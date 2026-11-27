use r3x_domain::{DiagnosticReport, LogEntry};
use regex::Regex;
use std::sync::LazyLock;

static URI_CREDENTIAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://)([^/@\s]{1,256})@")
        .unwrap_or_else(|_| unreachable!("static regex must compile"))
});

static QUERY_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)([?&](?:token|key|auth|pass|password|secret|pbk|sid|shortId|obfs-password|sni_secret)=)([^&\s#]+)")
        .unwrap_or_else(|_| unreachable!("static regex must compile"))
});

static JSON_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)("(?:password|uuid|private[_-]?key|preshared[_-]?key|token|secret|auth|public[_-]?key|short[_-]?id|obfs-password|passphrase|authorization|credential)"\s*:\s*")([^"]*)(")"#)
        .unwrap_or_else(|_| unreachable!("static regex must compile"))
});

static KV_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^(\s*(?:PrivateKey|PresharedKey|Password|Secret|Token|Auth|Passphrase|obfs-password|Authorization)\s*[:=]\s*)(.+)$")
        .unwrap_or_else(|_| unreachable!("static regex must compile"))
});

static BEARER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}")
        .unwrap_or_else(|_| unreachable!("static regex must compile"))
});

pub struct Redactor;

impl Redactor {
    #[must_use]
    pub fn redact_str(input: &str) -> String {
        let step1 = URI_CREDENTIAL_RE.replace_all(input, "${1}[REDACTED]@");
        let step2 = QUERY_SECRET_RE.replace_all(&step1, "${1}[REDACTED]");
        let step3 = JSON_SECRET_RE.replace_all(&step2, "${1}[REDACTED]${3}");
        let step4 = KV_SECRET_RE.replace_all(&step3, "${1}[REDACTED]");
        let step5 = BEARER_RE.replace_all(&step4, "${1} [REDACTED]");
        step5.into_owned()
    }

    #[must_use]
    pub fn redact_log_entry(entry: &LogEntry) -> LogEntry {
        let mut cloned = entry.clone();
        cloned.message = Self::redact_str(&entry.message);
        cloned
    }

    #[must_use]
    pub fn redact_diagnostic_report(report: &DiagnosticReport) -> DiagnosticReport {
        let mut cloned = report.clone();
        for res in &mut cloned.results {
            res.summary = Self::redact_str(&res.summary);
            res.technical_details = Self::redact_str(&res.technical_details);
            for action in &mut res.suggested_actions {
                *action = Self::redact_str(action);
            }
        }
        cloned
    }
}
