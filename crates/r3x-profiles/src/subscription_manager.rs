use crate::formats::parse_import_payload;
use crate::headers::parse_subscription_headers;
use chrono::Utc;
use r3x_domain::{
    CorePreference, ProfileSource, R3xError, Subscription, SubscriptionImportSource,
    SubscriptionMetadata, SubscriptionStatus,
};
use r3x_security::{MAX_SUBSCRIPTION_BYTES, validate_remote_subscription_url};
use r3x_storage::R3xDatabase;
use reqwest::Client;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use uuid::Uuid;

static CRYPTO_INIT: OnceLock<()> = OnceLock::new();

fn ensure_rustls_provider() {
    CRYPTO_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub struct SubscriptionManager {
    client: Client,
    db: Arc<R3xDatabase>,
}

impl SubscriptionManager {
    pub fn new(db: Arc<R3xDatabase>) -> Result<Self, R3xError> {
        ensure_rustls_provider();
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("R3X/0.1.0")
            .build()
            .map_err(|e| R3xError::Network(format!("failed constructing HTTP client: {e}")))?;
        Ok(Self { client, db })
    }

    pub fn create_and_import_local(
        &self,
        name: String,
        source: SubscriptionImportSource,
        payload: &[u8],
    ) -> Result<Subscription, R3xError> {
        let now = Utc::now();
        let sub_id = Uuid::new_v4();
        let parsed = parse_import_payload(
            payload,
            ProfileSource::Subscription {
                subscription_id: sub_id,
            },
        )?;

        let sub = Subscription {
            id: sub_id,
            name,
            source,
            enabled: true,
            pinned: false,
            status: SubscriptionStatus::Active,
            metadata: SubscriptionMetadata::default(),
            core_preference: CorePreference::Auto,
            last_updated_at: Some(now),
            last_error: None,
            server_count: parsed.profiles.len(),
            created_at: now,
            updated_at: now,
        };
        self.db.upsert_subscription(&sub)?;
        self.db
            .replace_subscription_profiles(sub_id, &parsed.profiles)?;
        Ok(sub)
    }

    pub async fn add_remote_and_fetch(
        &self,
        name: Option<String>,
        raw_url: &str,
    ) -> Result<Subscription, R3xError> {
        let valid_url = validate_remote_subscription_url(raw_url)?;
        let now = Utc::now();
        let sub_id = Uuid::new_v4();
        let mut sub = Subscription {
            id: sub_id,
            name: name.unwrap_or_else(|| valid_url.host_str().unwrap_or("Subscription").to_owned()),
            source: SubscriptionImportSource::RemoteUrl {
                url: valid_url.to_string(),
            },
            enabled: true,
            pinned: false,
            status: SubscriptionStatus::Active,
            metadata: SubscriptionMetadata::default(),
            core_preference: CorePreference::Auto,
            last_updated_at: None,
            last_error: None,
            server_count: 0,
            created_at: now,
            updated_at: now,
        };
        self.db.upsert_subscription(&sub)?;

        match self.refresh_subscription(sub.id).await {
            Ok(updated) => Ok(updated),
            Err(err) => {
                sub.status = SubscriptionStatus::Error;
                sub.last_error = Some(err.to_string());
                let _ = self.db.upsert_subscription(&sub);
                Err(err)
            }
        }
    }

    pub async fn refresh_subscription(&self, id: Uuid) -> Result<Subscription, R3xError> {
        let mut sub = self
            .db
            .list_subscriptions()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| R3xError::Validation(format!("subscription {id} not found")))?;

        let url = match &sub.source {
            SubscriptionImportSource::RemoteUrl { url } => validate_remote_subscription_url(url)?,
            _ => {
                return Err(R3xError::Validation(
                    "local subscription cannot be refreshed over HTTP".to_owned(),
                ));
            }
        };

        let res = self.fetch_and_parse(id, url.as_str()).await;
        match res {
            Ok((parsed_headers, parsed_profiles)) => {
                let now = Utc::now();
                if let Some(title) = parsed_headers.title
                    && sub.name.trim().is_empty()
                {
                    sub.name = title;
                }
                sub.metadata = parsed_headers.metadata;
                sub.status = match sub.metadata.expire_at {
                    Some(exp) if exp < now => SubscriptionStatus::Expired,
                    Some(exp) if exp < now + chrono::Duration::days(7) => {
                        SubscriptionStatus::Expiring
                    }
                    _ => SubscriptionStatus::Active,
                };
                sub.last_updated_at = Some(now);
                sub.last_error = None;
                sub.server_count = parsed_profiles.len();
                sub.updated_at = now;

                self.db.upsert_subscription(&sub)?;
                self.db
                    .replace_subscription_profiles(id, &parsed_profiles)?;
                Ok(sub)
            }
            Err(err) => {
                // Never overwrite last working profiles on refresh error.
                sub.status = SubscriptionStatus::Error;
                sub.last_error = Some(err.to_string());
                sub.updated_at = Utc::now();
                let _ = self.db.upsert_subscription(&sub);
                Err(err)
            }
        }
    }

    async fn fetch_and_parse(
        &self,
        sub_id: Uuid,
        url: &str,
    ) -> Result<
        (
            crate::headers::ParsedSubscriptionHeaders,
            Vec<r3x_domain::Profile>,
        ),
        R3xError,
    > {
        let mut resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| R3xError::Network(format!("subscription request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(R3xError::Network(format!(
                "subscription server returned HTTP {}",
                resp.status()
            )));
        }

        if let Some(len) = resp.content_length()
            && len as usize > MAX_SUBSCRIPTION_BYTES
        {
            return Err(R3xError::Validation(format!(
                "subscription Content-Length {len} exceeds {MAX_SUBSCRIPTION_BYTES} byte limit"
            )));
        }

        let headers = parse_subscription_headers(resp.headers());
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| R3xError::Network(format!("failed reading subscription body: {e}")))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BYTES {
                return Err(R3xError::Validation(format!(
                    "subscription payload exceeded {MAX_SUBSCRIPTION_BYTES} byte limit"
                )));
            }
            body.extend_from_slice(&chunk);
        }

        let parsed = parse_import_payload(
            &body,
            ProfileSource::Subscription {
                subscription_id: sub_id,
            },
        )?;
        Ok((headers, parsed.profiles))
    }
}
