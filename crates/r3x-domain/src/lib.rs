pub mod connection;
pub mod core;
pub mod diagnostics;
pub mod dns;
pub mod error;
pub mod logging;
pub mod monitoring;
pub mod profile;
pub mod routing;
pub mod settings;
pub mod subscription;

pub use connection::{
    ActiveConnectionInfo, ConnectionHistoryEntry, ConnectionMode, ConnectionSession,
    ConnectionState,
};
pub use core::{
    CoreCapabilities, CoreId, CoreInstallState, CoreIntegrationType, CoreManifest, CorePreference,
    CpuArch, Platform, SupportStatus,
};
pub use diagnostics::{DiagnosticCheckId, DiagnosticReport, DiagnosticResult, DiagnosticStatus};
pub use dns::{DnsConfig, DnsLeakProtectionMode, DnsMode, DnsResolver};
pub use error::{ErrorCategory, R3xError};
pub use logging::{LogCategory, LogEntry, LogLevel};
pub use monitoring::{
    LatencySample, ResourceSample, RingBuffer, TelemetrySnapshot, TimeRange, TrafficSample,
};
pub use profile::{
    AmneziaWgObfuscation, AuthConfig, Endpoint, FlowType, Profile, ProfileOptions, ProfileSource,
    ProtocolConfig, ProtocolType, RealitySettings, RedactedSecret, SecurityConfig, TlsSettings,
    TransportConfig,
};
pub use routing::{RoutingRule, RuleAction, RuleMatcher, RuleSet};
pub use settings::{
    AccentConfig, AppSettings, InterfaceMode, Language, PerformanceProfile, ThemeMode, WindowState,
};
pub use subscription::{
    Subscription, SubscriptionImportSource, SubscriptionMetadata, SubscriptionStatus,
};
