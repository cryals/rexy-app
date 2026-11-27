# ADR 0002: Multi-Core Adapter Contract and Capability Negotiation

- **Status:** Accepted
- **Date:** 2026-11-28

## Context
R3X must support multiple proxy and VPN cores (Xray-core, sing-box, Mihomo, Hysteria 2, WireGuard, AmneziaWG, NaiveProxy, Mieru, OpenVPN, etc.) without hardcoding the engine to a single core binary or config schema.

## Decision
1. Define a unified async `CoreAdapter` trait in `r3x-engine` covering identity, capabilities, platform support, profile validation, config generation, lifecycle (`start`, `health_check`, `collect_stats`, `stop`, `cleanup`).
2. Implement `CoreSelector` with deterministic precedence: per-profile override -> per-subscription override -> global preference -> highest capability score (`Verified > Supported > Experimental`, universal cores preferred on tie).
3. Enforce a real readiness gate: `R3xEngine` enters `ConnectionState::Connected` only after `CoreAdapter::health_check()` returns ready (`process_alive && control_api_reachable && tunnel_ready`).

## Consequences
- Adding a new core requires implementing one isolated `CoreAdapter` without modifying UI or FSM logic.
- Users never see `Connected` merely because a child process started and immediately crashed.
