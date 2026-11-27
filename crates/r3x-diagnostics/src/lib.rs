pub mod dns;
pub mod doctor;
pub mod monitoring;
pub mod routing;

pub use dns::{
    DnsManager, DnsProbeResult, check_dns_leaks, test_dns_resolver, validate_dns_config,
};
pub use doctor::{DiagnosticContext, NetworkDoctor, export_redacted_report};
pub use monitoring::{TelemetryHub, build_area_path, build_line_path, measure_tcp_latency};
pub use routing::{RoutingManager, default_rule_presets, preview_core_routing, validate_rule};
