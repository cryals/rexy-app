use crate::connection::ConnectionMode;
use crate::core::CorePreference;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    System,
    Light,
    Dark,
    Amoled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "hex", rename_all = "snake_case")]
pub enum AccentConfig {
    Default,
    Dynamic,
    CustomHex(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceProfile {
    Eco,
    Balanced,
    Performance,
}

impl PerformanceProfile {
    #[must_use]
    pub fn telemetry_interval_ms(self) -> u64 {
        match self {
            Self::Eco => 2000,
            Self::Balanced => 1000,
            Self::Performance => 400,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    System,
    En,
    Ru,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceMode {
    Simple,
    Advanced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowState {
    pub width: u32,
    pub height: u32,
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub maximized: bool,
    pub drawer_collapsed: bool,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 820,
            x: None,
            y: None,
            maximized: false,
            drawer_collapsed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme_mode: ThemeMode,
    pub accent: AccentConfig,
    pub reduced_motion: bool,
    pub language: Language,
    pub interface_mode: InterfaceMode,
    pub performance_profile: PerformanceProfile,
    pub preferred_connection_mode: ConnectionMode,
    pub global_core_preference: CorePreference,
    pub selected_profile_id: Option<Uuid>,
    pub auto_reconnect: bool,
    pub kill_switch: bool,
    pub auto_start_on_boot: bool,
    pub connect_on_launch: bool,
    pub minimize_to_tray: bool,
    pub mixed_port: u16,
    pub socks_port: u16,
    pub http_port: u16,
    pub allow_lan: bool,
    pub ipv6_enabled: bool,
    pub onboarding_completed: bool,
    pub window_state: WindowState,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme_mode: ThemeMode::Dark,
            accent: AccentConfig::Default,
            reduced_motion: false,
            language: Language::System,
            interface_mode: InterfaceMode::Advanced,
            performance_profile: PerformanceProfile::Balanced,
            preferred_connection_mode: ConnectionMode::Tun,
            global_core_preference: CorePreference::Auto,
            selected_profile_id: None,
            auto_reconnect: true,
            kill_switch: false,
            auto_start_on_boot: false,
            connect_on_launch: false,
            minimize_to_tray: true,
            mixed_port: 10808,
            socks_port: 10809,
            http_port: 10810,
            allow_lan: false,
            ipv6_enabled: false,
            onboarding_completed: false,
            window_state: WindowState::default(),
        }
    }
}
