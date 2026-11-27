use r3x_domain::R3xError;
use url::Url;

pub const MAX_SUBSCRIPTION_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_IPC_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROFILES_PER_SUBSCRIPTION: usize = 10_000;

pub fn validate_subscription_size(bytes: usize) -> Result<(), R3xError> {
    if bytes > MAX_SUBSCRIPTION_BYTES {
        return Err(R3xError::Validation(format!(
            "subscription payload size {bytes} bytes exceeds maximum {MAX_SUBSCRIPTION_BYTES} bytes"
        )));
    }
    Ok(())
}

pub fn validate_config_size(bytes: usize) -> Result<(), R3xError> {
    if bytes > MAX_CONFIG_BYTES {
        return Err(R3xError::Validation(format!(
            "configuration payload size {bytes} bytes exceeds maximum {MAX_CONFIG_BYTES} bytes"
        )));
    }
    Ok(())
}

pub fn validate_remote_subscription_url(raw: &str) -> Result<Url, R3xError> {
    let trimmed = raw.trim();
    if trimmed.len() > 4096 {
        return Err(R3xError::Validation(
            "subscription URL exceeds 4096 characters".to_owned(),
        ));
    }
    let parsed = Url::parse(trimmed)
        .map_err(|e| R3xError::Validation(format!("invalid subscription URL: {e}")))?;
    match parsed.scheme() {
        "https" | "http" => {}
        other => {
            return Err(R3xError::SecurityViolation(format!(
                "unsupported remote subscription URL scheme '{other}'; only http/https allowed"
            )));
        }
    }
    if parsed.host_str().is_none() {
        return Err(R3xError::Validation(
            "subscription URL missing host".to_owned(),
        ));
    }
    Ok(parsed)
}

#[must_use]
pub fn sanitize_filename(raw: &str) -> String {
    let mut filtered: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while filtered.contains("..") {
        filtered = filtered.replace("..", "_");
    }
    let trimmed = filtered.trim_matches('.');
    if trimmed.is_empty() {
        "unnamed".to_owned()
    } else {
        trimmed.chars().take(96).collect()
    }
}
