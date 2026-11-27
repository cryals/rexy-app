use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Validation,
    StateTransition,
    Core,
    Network,
    Storage,
    Security,
    Ipc,
    Cancelled,
    Timeout,
    Platform,
    Io,
}

#[derive(Debug, Error)]
pub enum R3xError {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("invalid connection state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("required core '{0}' is not installed")]
    CoreNotInstalled(String),

    #[error("core '{core}' is incompatible: {reason}")]
    CoreIncompatible { core: String, reason: String },

    #[error("core process '{core}' failed: {reason}")]
    CoreProcessFailed { core: String, reason: String },

    #[error("network error: {0}")]
    Network(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("secure secret store unavailable: {0}")]
    SecretStoreUnavailable(String),

    #[error("security violation: {0}")]
    SecurityViolation(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("operation timed out after {0} ms")]
    Timeout(u64),

    #[error("unsupported on current platform: {0}")]
    UnsupportedPlatform(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl R3xError {
    #[must_use]
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::Validation(_) => ErrorCategory::Validation,
            Self::InvalidStateTransition { .. } => ErrorCategory::StateTransition,
            Self::CoreNotInstalled(_)
            | Self::CoreIncompatible { .. }
            | Self::CoreProcessFailed { .. } => ErrorCategory::Core,
            Self::Network(_) => ErrorCategory::Network,
            Self::Storage(_) | Self::SecretStoreUnavailable(_) => ErrorCategory::Storage,
            Self::SecurityViolation(_) => ErrorCategory::Security,
            Self::Ipc(_) => ErrorCategory::Ipc,
            Self::Cancelled => ErrorCategory::Cancelled,
            Self::Timeout(_) => ErrorCategory::Timeout,
            Self::UnsupportedPlatform(_) => ErrorCategory::Platform,
            Self::Io(_) => ErrorCategory::Io,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "E_VALIDATION",
            Self::InvalidStateTransition { .. } => "E_STATE_TRANSITION",
            Self::CoreNotInstalled(_) => "E_CORE_NOT_INSTALLED",
            Self::CoreIncompatible { .. } => "E_CORE_INCOMPATIBLE",
            Self::CoreProcessFailed { .. } => "E_CORE_FAILED",
            Self::Network(_) => "E_NETWORK",
            Self::Storage(_) => "E_STORAGE",
            Self::SecretStoreUnavailable(_) => "E_SECRET_STORE",
            Self::SecurityViolation(_) => "E_SECURITY",
            Self::Ipc(_) => "E_IPC",
            Self::Cancelled => "E_CANCELLED",
            Self::Timeout(_) => "E_TIMEOUT",
            Self::UnsupportedPlatform(_) => "E_UNSUPPORTED_PLATFORM",
            Self::Io(_) => "E_IO",
        }
    }

    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::Timeout(_) | Self::Cancelled | Self::CoreProcessFailed { .. }
        )
    }
}
