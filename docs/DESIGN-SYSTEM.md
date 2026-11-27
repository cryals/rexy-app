# R3X Material 3 Expressive Design System

Built natively in Slint 1.19 atop `@material` (`material-1.1.0/`) without modifying the upstream template kit and without using WebView/HTML runtimes.

## 1. Visual Tokens (`ui/tokens/`)
- **Palette (`palette.slint`):**
  - **Dark Graphite:** Surface `#141317`, Containers `#1C1B1F` / `#201F23` / `#2B292D` / `#353438`, Primary Silver-Lavender `#CAC3DC`, On-Surface `#E3E2E7`.
  - **Warm Light:** Surface `#FCF8FD`, Containers `#F5F1F6` / `#EFEBF0` / `#E9E5EA` / `#E4E0E5`, Primary `#4A4459`.
  - **AMOLED Dark:** Pure `#000000` background/surface with elevated `#0C0C0E` / `#121215` / `#1B1A1E` / `#26252A` cards so hierarchy stays clear on OLED panels.
  - **Semantic Status Roles:** `success` (`#95D8AB` dark / `#1E6F3D` light), `warning` (`#F4BE76` dark / `#8C5400` light), `error` (`MaterialPalette.error`), `download` (`#8FD5C5`), `upload` (`#C2B9E3`).
  - **Custom Accent:** Configurable `#RRGGBB` hex persisted in SQLite and applied dynamically through `R3xThemeController` + `MaterialPalette.schemes`.
- **Shape & Spacing (`metrics.slint`):**
  - 4px base grid (`4 / 8 / 12 / 16 / 24 / 32px`).
  - Corner hierarchy: `28px` hero cards (`radius_hero`), `24px` metric cards (`radius_xl`), `16px` inputs (`radius_md`), `8px` inner segmented seams (`radius_inner`), `9999px` full pill buttons/chips (`radius_full`).
- **Motion & Accessibility:**
  - `R3xMetrics.reduced_motion` collapses durations (`dur_state_change`, `dur_surface_enter`, `dur_shape_morph`) cleanly to `0ms` when toggled.
  - Semantic status pills (`StatusPill`) always pair color with icon or status dot + readable label; color is never the sole carrier.
  - Interactive rows declare ARIA/AccessKit semantics (`accessible-role`, `accessible-item-selectable`, `accessible-item-selected`).

## 2. Expressive Components (`ui/components/`)
- **`ConnectionHeroButton`:** Morphs between a `32px` rounded squircle (disconnected) and a 12-lobe organic scalloped SVG path (connected) with animated transition when `reduced_motion == false`.
- **`ConnectedSegmentedGroup` / `ConnectedGroupButton`:** 4px internal gaps, pill outer ends (`radius_full`), `8px` inner seams, check indicator on active segment.
- **`StackedListItem`:** Rounded outer ends on `first`/`last`/`only`, `8px` inner corners between rows.
- **`TrafficAreaChart`:** SVG stroke + semi-transparent area fill rendered natively via Slint `Path`, falling back to explicit empty-state messaging (`No active tunnel session`) when idle.
- **`ExpressiveModal`, `R3xTextField`, `R3xFilterChip`, `R3xSwitchRow`:** Accessible form controls and scrim-protected modal overlays shared across desktop and mobile.
