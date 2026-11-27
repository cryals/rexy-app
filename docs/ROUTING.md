# Routing Rules & DNS Engine (`r3x-diagnostics`)

Visual rule orchestration and DNS validation live in `crates/r3x-diagnostics/src/routing.rs` and `dns.rs`.

## 1. Routing Pipeline (`RoutingManager`)

- **Matchers (`RuleMatcher`):** Domain, Domain Suffix, Domain Keyword, IP/CIDR (`ipnet` validated), GeoIP, GeoSite, Port / Port Range, Protocol, Process / Application Name, and Rule Set tags.
- **Actions (`RuleAction`):** `Proxy`, `Direct`, `Block`, or `Profile(Uuid)`.
- **Presets (`default_rule_presets`):** Pre-built starter policies (e.g., Bypass LAN & Private IPv4/IPv6 Ranges, Block Ads/Malware Domains, Proxy Global Default).
- **Live Core Translation Preview (`preview_core_routing`):** Renders real JSON/YAML routing snippets for `Xray-core`, `sing-box`, and `Mihomo` inside **Routing & DNS -> Raw Config Viewer** so advanced users can inspect exact generated rules before connecting.

## 2. DNS Configuration & Probes (`DnsManager`)

- **Modes (`DnsMode`):** `System`, `Custom` (plain UDP/TCP resolver), `DoH` (DNS-over-HTTPS), `DoT` (DNS-over-TLS), `DoQ` (DNS-over-QUIC).
- **Leak Protection (`DnsLeakProtectionMode`):** `StrictTunnel` (forces DNS via tunnel adapter in TUN mode), `Standard`, or `SystemPassthrough`.
- **Honest Verification (`test_dns_resolver`, `check_dns_leaks`):**
  - Validates upstream syntax and reachability via live socket/TCP probes.
  - Compares OS-configured DNS servers (`inspect_os_dns_servers`) against active tunnel expectation when connected, surfacing clear warnings if split/bypass resolvers could leak queries.
