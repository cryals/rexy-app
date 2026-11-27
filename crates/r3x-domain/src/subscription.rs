use crate::core::CorePreference;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Expiring,
    Expired,
    Error,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubscriptionImportSource {
    RemoteUrl { url: String },
    LocalFile { filename: String },
    Clipboard,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionMetadata {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    /// `None` or `Some(0)` denotes an unlimited traffic plan without a percentage bar.
    pub total_bytes: Option<u64>,
    pub expire_at: Option<DateTime<Utc>>,
    pub update_interval_hours: u32,
    pub support_url: Option<String>,
    pub website_url: Option<String>,
    pub announcement: Option<String>,
}

impl SubscriptionMetadata {
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }

    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        matches!(self.total_bytes, None | Some(0))
    }

    #[must_use]
    pub fn usage_ratio(&self) -> Option<f64> {
        match self.total_bytes {
            Some(total) if total > 0 => Some((self.used_bytes() as f64 / total as f64).min(1.0)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub name: String,
    pub source: SubscriptionImportSource,
    pub enabled: bool,
    pub pinned: bool,
    pub status: SubscriptionStatus,
    pub metadata: SubscriptionMetadata,
    pub core_preference: CorePreference,
    pub last_updated_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub server_count: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
