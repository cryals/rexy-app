# R3X UI Screen & State Map

All 60+ views, modal workflows, tabs, and states specified for R3X map natively onto Slint components under `D:\Rexy\rexy-app\ui\`.

| Area | Screen / State | Slint Implementation | Navigation / Trigger |
|---|---|---|---|
| Onboarding | Welcome, Appearance & Language, Security & Capabilities, First Import | `ui/screens/onboarding_screen.slint` | Shown automatically when `onboarding_completed == false`, or `Settings -> Advanced -> Re-run Onboarding` |
| Home (`nav == 0`) | Disconnected, Connecting (`HeroState.busy`), Connected (scalloped morph + timer), Error (`ErrorStateView` with retry & diagnostics), Traffic chart (empty vs live SVG paths), Public IP, Core badge, Socket summary | `ui/screens/home_screen.slint`, `ui/components/connection_hero_button.slint`, `ui/components/traffic_chart.slint` | Primary nav item 0 |
| Quick Controls | Quick Connection Settings modal | `ui/layouts/app_shell.slint` (`active_modal == "quick_settings"`) | `Home -> Quick settings` |
| Subscriptions (`nav == 1`) | Feeds overview, Unlimited vs Metered cards (`LinearProgressIndicator`), 4-button connected toolbar, empty state, refresh status | `ui/screens/subscriptions_screen.slint` | Primary nav item 1 / Mobile bottom bar |
| Modals (Import) | Add Subscription Feed, Import URI/YAML/JSON/INI, Manual Profile Editor | `ui/layouts/app_shell.slint` (`ExpressiveModal`) | Action buttons on Subscriptions / Servers / Onboarding |
| Servers (`nav == 2`) | Server selector list, Country SVG flags (`R3xFlags`), Search, Favorites filter chip, Latency color tags, Delete/Star actions, Server Details pane, Export URI preview | `ui/screens/servers_screen.slint` | Primary nav item 2 / Home server card |
| Routing & DNS (`nav == 3`) | Subtab 0: Routing Rules + Presets + `add_rule` modal; Subtab 1: Rule Sets; Subtab 2: DNS (System/Custom/DoH/DoT/DoQ + Leak Guard + Live Probe); Subtab 3: Raw Config Viewer (Xray/sing-box/Mihomo) | `ui/screens/routing_screen.slint`, `ui/layouts/app_shell.slint` (`add_rule`) | Primary nav item 3 |
| Connections (`nav == 4`) | Subtab 0: Active Flows (`EmptyStateView` when idle); Subtab 1: Persisted Session History + Search + Clear | `ui/screens/connections_screen.slint` | Primary nav item 4 |
| Diagnostics (`nav == 5`) | Tab 0: Monitoring (1m/5m/15m/1h, Pause, SVG chart, real `sysinfo` UI+Core CPU/RAM); Tab 1: Network Doctor (all 16 real checks + Redacted Report modal); Tabs 2–5: Core, Subscription, App & Platform Logs | `ui/screens/diagnostics_screen.slint`, `ui/layouts/app_shell.slint` (`report_preview`) | Primary nav item 5 / Mobile bottom bar |
| Core Manager (`nav == 6`) | 14 Core manifest inventory, Install State pills, Limitations, Binary Paths, Re-verify Installed, Preferred Core / Reset Auto | `ui/screens/core_manager_screen.slint` | Primary nav item 6 |
| Settings (`nav == 7`) | Split-pane (Desktop) / Chip Strip (Mobile) covering all 8 categories: Appearance (System/Light/Dark/AMOLED, Custom Accent Hex, EN/RU, Advanced Mode, Reduced Motion), Connection & Network Ports, Privacy & Security, Performance & Battery (Eco/Balanced/Perf), Data & Encrypted `.r3xbak` Backup/Restore, Startup/Tray Behavior, Advanced Network Recovery, About & Third-Party Licenses | `ui/screens/settings_screen.slint` | Primary nav item 7 / Mobile bottom bar |
