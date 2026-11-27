# R3X Architecture Overview

R3X uses a strict layered architecture separating UI presentation from engine orchestration, core adapters, persistence, and OS networking primitives.

```text
+-------------------------------------------------------------------+
|  Presentation Layer (Slint Native UI — ui/ + src/)                |
|  - Material 3 Expressive design system & adaptive layouts         |
|  - Communicates strictly via R3xAppState bindings & engine events |
+---------------------------------+---------------------------------+
                                  |
        +-------------------------+-------------------------+
        v                                                   v
+-------------------------+                       +-------------------+
| Direct Engine (Embedded)|                       | r3x-ipc (Local)   |
| (Desktop single/Android)|                       | Named Pipe / UDS  |
+------------+------------+                       +---------+---------+
             |                                              |
             +----------------------+-----------------------+
                                    v
+-------------------------------------------------------------------+
|  Application & Engine Layer (crates/r3x-engine)                   |
|  - 10-state typed Connection FSM + CancellationToken              |
|  - CoreSelector capability negotiation                            |
|  - Redacted LogHub + bounded EngineEvent broadcast                |
+--------+--------------------------+----------------------+--------+
         |                          |                      |
         v                          v                      v
+-----------------+       +------------------+    +-----------------+
| Core Adapters   |       | Storage & Sec    |    | Platform Layer  |
| Xray / sing-box |       | r3x-storage      |    | Win / Lin / And |
| Mihomo / WG ... |       | r3x-security     |    | TUN / Proxy/VPN |
+-----------------+       +------------------+    +-----------------+
         |
         v
+-------------------------------------------------------------------+
|  Domain Layer (crates/r3x-domain — zero UI/OS dependencies)       |
+-------------------------------------------------------------------+
```

## Key Invariants
1. **UI Isolation:** `.slint` files and `src/lib.rs` UI glue never spawn core processes, mutate system routes, or touch raw SQLite tables directly.
2. **Real Readiness:** `R3xEngine` transitions to `Connected` only after `CoreAdapter::health_check()` confirms process health, control API availability, and tunnel readiness.
3. **Android Compatibility:** Core crates (`r3x-domain`, `r3x-security`, `r3x-storage`, `r3x-engine`) compile cleanly without desktop-only dependencies (`keyring` desktop backends are strictly target-gated).
