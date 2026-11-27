# ADR 0003: Native Slint Material 3 Expressive UI Architecture

- **Status:** Accepted
- **Date:** 2026-11-28

## Context
The Stitch HTML references illustrate R3X's Material 3 Expressive aesthetic (graphite & silver-lavender palette, 12-lobe connection hero morph, connected button groups, stacked list corner radii, dual-series traffic charts). The product must be native Slint using the provided `material-1.1.0` kit, without WebView/Electron/HTML wrappers.

## Decision
1. Leave `material-1.1.0/` untouched and import standard Material components via `@material`.
2. Build an additive R3X Expressive UI layer in `ui/` (`tokens/`, `themes/`, `components/`, `layouts/`, `screens/`, `state/`) implementing the R3X palette (`System`, `Light`, `Dark`, `AMOLED`, custom accent), strict 4px grid, M3 Expressive typography scale, vector SVG icons/flags, and custom Expressive components (`ConnectionHeroButton`, `ConnectedSegmentedGroup`, `StackedListItem`, `TrafficAreaChart`, `StatusPill`).
3. Synchronize `MaterialPalette.schemes` and `Palette.color-scheme` dynamically via `R3xThemeController` so both `@material` widgets and custom R3X components share one unified theme.

## Consequences
- Zero duplication of stock Material widgets (`Switch`, `TextField`, `Dialog`, `ModalBottomSheet`, etc.).
- Adaptive desktop (`>= 1024px` drawer/rail + 5/7 grid) and mobile (`< 1024px` compact app bar + 80px bottom bar) shells share a single `R3xAppState` contract.
