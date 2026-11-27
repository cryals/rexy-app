use crate::uri::decode_base64_flexible;
use chrono::DateTime;
use r3x_domain::SubscriptionMetadata;
use r3x_security::validate_remote_subscription_url;
use reqwest::header::HeaderMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedSubscriptionHeaders {
    pub title: Option<String>,
    pub metadata: SubscriptionMetadata,
}

fn decode_maybe_base64(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(b64) = trimmed.strip_prefix("base64:")
        && let Ok(bytes) = decode_base64_flexible(b64)
        && let Ok(decoded) = String::from_utf8(bytes)
    {
        return sanitize_untrusted_text(&decoded, 256);
    }
    sanitize_untrusted_text(trimmed, 256)
}

fn sanitize_untrusted_text(input: &str, max_chars: usize) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[must_use]
pub fn parse_subscription_headers(headers: &HeaderMap) -> ParsedSubscriptionHeaders {
    let mut out = ParsedSubscriptionHeaders::default();
    out.metadata.update_interval_hours = 6;

    if let Some(title) = headers.get("profile-title").and_then(|v| v.to_str().ok()) {
        let clean = decode_maybe_base64(title);
        if !clean.is_empty() {
            out.title = Some(clean);
        }
    }

    if let Some(userinfo) = headers
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
    {
        for part in userinfo.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                let key = k.trim().to_ascii_lowercase();
                let val_u64 = v.trim().parse::<u64>().ok();
                match key.as_str() {
                    "upload" => {
                        if let Some(n) = val_u64 {
                            out.metadata.upload_bytes = n;
                        }
                    }
                    "download" => {
                        if let Some(n) = val_u64 {
                            out.metadata.download_bytes = n;
                        }
                    }
                    "total" => {
                        // Treat 0 as unlimited plan (None) so UI never shows fake percentages.
                        out.metadata.total_bytes = val_u64.filter(|n| *n > 0);
                    }
                    "expire" => {
                        if let Some(ts) = v.trim().parse::<i64>().ok().filter(|n| *n > 0) {
                            out.metadata.expire_at = DateTime::from_timestamp(ts, 0);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(interval) = headers
        .get("profile-update-interval")
        .and_then(|v| v.to_str().ok())
        && let Ok(hours) = interval.trim().parse::<u32>()
    {
        out.metadata.update_interval_hours = hours.clamp(1, 720);
    }

    if let Some(support) = headers.get("support-url").and_then(|v| v.to_str().ok())
        && validate_remote_subscription_url(support).is_ok()
    {
        out.metadata.support_url = Some(support.trim().to_owned());
    }

    if let Some(site) = headers
        .get("profile-web-page-url")
        .and_then(|v| v.to_str().ok())
        && validate_remote_subscription_url(site).is_ok()
    {
        out.metadata.website_url = Some(site.trim().to_owned());
    }

    if let Some(ann) = headers.get("announce").and_then(|v| v.to_str().ok()) {
        let clean = decode_maybe_base64(ann);
        if !clean.is_empty() {
            out.metadata.announcement = Some(clean);
        }
    }

    out
}
