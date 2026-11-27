use r3x_domain::{CoreId, R3xError, RoutingRule, RuleAction, RuleMatcher, RuleSet};
use r3x_storage::R3xDatabase;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

pub struct RoutingManager {
    db: Arc<R3xDatabase>,
}

impl RoutingManager {
    #[must_use]
    pub fn new(db: Arc<R3xDatabase>) -> Self {
        Self { db }
    }

    pub fn list_rules_sorted(&self) -> Result<Vec<RoutingRule>, R3xError> {
        let mut rules = self.db.list_routing_rules()?;
        rules.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(rules)
    }

    pub fn upsert_rule(&self, rule: &RoutingRule) -> Result<(), R3xError> {
        validate_rule(rule)?;
        self.db.upsert_routing_rule(rule)
    }

    pub fn delete_rule(&self, id: Uuid) -> Result<(), R3xError> {
        self.db.delete_routing_rule(id)
    }

    pub fn toggle_rule(&self, id: Uuid, enabled: bool) -> Result<(), R3xError> {
        let mut rules = self.db.list_routing_rules()?;
        let Some(rule) = rules.iter_mut().find(|r| r.id == id) else {
            return Err(R3xError::Validation(format!("routing rule {id} not found")));
        };
        rule.enabled = enabled;
        self.db.upsert_routing_rule(rule)
    }

    pub fn set_priority(&self, id: Uuid, priority: i32) -> Result<(), R3xError> {
        let mut rules = self.db.list_routing_rules()?;
        let Some(rule) = rules.iter_mut().find(|r| r.id == id) else {
            return Err(R3xError::Validation(format!("routing rule {id} not found")));
        };
        rule.priority = priority;
        self.db.upsert_routing_rule(rule)
    }

    pub fn list_rule_sets(&self) -> Result<Vec<RuleSet>, R3xError> {
        self.db.list_rule_sets()
    }

    pub fn upsert_rule_set(&self, rule_set: &RuleSet) -> Result<(), R3xError> {
        if rule_set.tag.trim().is_empty() {
            return Err(R3xError::Validation(
                "rule-set tag cannot be empty".to_owned(),
            ));
        }
        self.db.upsert_rule_set(rule_set)
    }

    pub fn delete_rule_set(&self, id: Uuid) -> Result<(), R3xError> {
        self.db.delete_rule_set(id)
    }

    pub fn install_default_presets(&self) -> Result<usize, R3xError> {
        let existing = self.db.list_routing_rules()?;
        let mut added = 0usize;
        for preset in default_rule_presets() {
            if !existing.iter().any(|r| r.name == preset.name) {
                self.upsert_rule(&preset)?;
                added += 1;
            }
        }
        Ok(added)
    }

    pub fn export_rules_json(&self) -> Result<String, R3xError> {
        let rules = self.list_rules_sorted()?;
        serde_json::to_string_pretty(&rules)
            .map_err(|e| R3xError::Storage(format!("export rules JSON: {e}")))
    }

    pub fn import_rules_json(&self, raw: &str) -> Result<usize, R3xError> {
        let rules: Vec<RoutingRule> = serde_json::from_str(raw)
            .map_err(|e| R3xError::Validation(format!("invalid rules JSON: {e}")))?;
        for rule in &rules {
            validate_rule(rule)?;
        }
        let count = rules.len();
        for rule in &rules {
            self.db.upsert_routing_rule(rule)?;
        }
        Ok(count)
    }
}

pub fn validate_rule(rule: &RoutingRule) -> Result<(), R3xError> {
    if rule.name.trim().is_empty() {
        return Err(R3xError::Validation(
            "routing rule name cannot be empty".to_owned(),
        ));
    }
    match &rule.matcher {
        RuleMatcher::Domain(v)
        | RuleMatcher::DomainSuffix(v)
        | RuleMatcher::DomainKeyword(v)
        | RuleMatcher::GeoIp(v)
        | RuleMatcher::GeoSite(v)
        | RuleMatcher::Application(v)
        | RuleMatcher::ProcessName(v)
        | RuleMatcher::Protocol(v)
        | RuleMatcher::RuleSet(v) => {
            if v.trim().is_empty() {
                return Err(R3xError::Validation(format!(
                    "rule '{}' matcher value cannot be empty",
                    rule.name
                )));
            }
        }
        RuleMatcher::Ip(ip) => {
            ip.trim().parse::<IpAddr>().map_err(|_| {
                R3xError::Validation(format!("rule '{}' has invalid IP '{ip}'", rule.name))
            })?;
        }
        RuleMatcher::Cidr(_) => {}
        RuleMatcher::Port(port) => {
            if *port == 0 {
                return Err(R3xError::Validation(format!(
                    "rule '{}' port must be between 1 and 65535",
                    rule.name
                )));
            }
        }
        RuleMatcher::PortRange { start, end } => {
            if *start == 0 || *start > *end {
                return Err(R3xError::Validation(format!(
                    "rule '{}' has invalid port range {start}-{end}",
                    rule.name
                )));
            }
        }
    }
    Ok(())
}

#[must_use]
pub fn default_rule_presets() -> Vec<RoutingRule> {
    vec![
        RoutingRule {
            id: Uuid::new_v4(),
            name: "Private LAN CIDR Direct".to_owned(),
            enabled: true,
            priority: 10,
            group: "Bypass".to_owned(),
            matcher: RuleMatcher::GeoIp("private".to_owned()),
            action: RuleAction::Direct,
        },
        RoutingRule {
            id: Uuid::new_v4(),
            name: "Loopback & Localhost Direct".to_owned(),
            enabled: true,
            priority: 20,
            group: "Bypass".to_owned(),
            matcher: RuleMatcher::Domain("localhost".to_owned()),
            action: RuleAction::Direct,
        },
        RoutingRule {
            id: Uuid::new_v4(),
            name: "Ad-block Telemetry & Trackers".to_owned(),
            enabled: false,
            priority: 30,
            group: "Privacy".to_owned(),
            matcher: RuleMatcher::GeoSite("category-ads-all".to_owned()),
            action: RuleAction::Block,
        },
    ]
}

fn action_tag(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Proxy | RuleAction::SelectedProfile(_) => "proxy",
        RuleAction::Direct => "direct",
        RuleAction::Block => "block",
    }
}

#[must_use]
pub fn preview_core_routing(core_id: CoreId, rules: &[RoutingRule]) -> Value {
    let mut enabled: Vec<&RoutingRule> = rules.iter().filter(|r| r.enabled).collect();
    enabled.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.name.cmp(&b.name))
    });

    match core_id {
        CoreId::Xray | CoreId::V2Fly => {
            let xray_rules: Vec<Value> = enabled
                .into_iter()
                .map(|r| {
                    let tag = action_tag(r.action);
                    match &r.matcher {
                        RuleMatcher::Domain(d) => {
                            json!({ "type": "field", "domain": [format!("full:{d}")], "outboundTag": tag })
                        }
                        RuleMatcher::DomainSuffix(s) => {
                            json!({ "type": "field", "domain": [format!("domain:{s}")], "outboundTag": tag })
                        }
                        RuleMatcher::DomainKeyword(k) => {
                            json!({ "type": "field", "domain": [k], "outboundTag": tag })
                        }
                        RuleMatcher::Ip(ip) => {
                            json!({ "type": "field", "ip": [ip], "outboundTag": tag })
                        }
                        RuleMatcher::Cidr(net) => {
                            json!({ "type": "field", "ip": [net.to_string()], "outboundTag": tag })
                        }
                        RuleMatcher::GeoIp(g) => {
                            json!({ "type": "field", "ip": [format!("geoip:{g}")], "outboundTag": tag })
                        }
                        RuleMatcher::GeoSite(g) | RuleMatcher::RuleSet(g) => {
                            json!({ "type": "field", "domain": [format!("geosite:{g}")], "outboundTag": tag })
                        }
                        RuleMatcher::Port(p) => {
                            json!({ "type": "field", "port": p.to_string(), "outboundTag": tag })
                        }
                        RuleMatcher::PortRange { start, end } => {
                            json!({ "type": "field", "port": format!("{start}-{end}"), "outboundTag": tag })
                        }
                        RuleMatcher::Protocol(proto) => {
                            json!({ "type": "field", "protocol": [proto], "outboundTag": tag })
                        }
                        RuleMatcher::Application(app) | RuleMatcher::ProcessName(app) => {
                            json!({ "type": "field", "domain": [format!("comment:app={app}")], "outboundTag": tag })
                        }
                    }
                })
                .collect();
            json!({ "domainStrategy": "IPIfNonMatch", "rules": xray_rules })
        }
        CoreId::SingBox => {
            let sb_rules: Vec<Value> = enabled
                .into_iter()
                .map(|r| {
                    let ob = action_tag(r.action);
                    match &r.matcher {
                        RuleMatcher::Domain(d) => json!({ "domain": [d], "outbound": ob }),
                        RuleMatcher::DomainSuffix(s) => {
                            json!({ "domain_suffix": [s], "outbound": ob })
                        }
                        RuleMatcher::DomainKeyword(k) => {
                            json!({ "domain_keyword": [k], "outbound": ob })
                        }
                        RuleMatcher::Ip(ip) => {
                            json!({ "ip_cidr": [format!("{ip}/32")], "outbound": ob })
                        }
                        RuleMatcher::Cidr(net) => {
                            json!({ "ip_cidr": [net.to_string()], "outbound": ob })
                        }
                        RuleMatcher::GeoIp(g) => {
                            json!({ "rule_set": [format!("geoip-{g}")], "outbound": ob })
                        }
                        RuleMatcher::GeoSite(g) => {
                            json!({ "rule_set": [format!("geosite-{g}")], "outbound": ob })
                        }
                        RuleMatcher::RuleSet(tag) => json!({ "rule_set": [tag], "outbound": ob }),
                        RuleMatcher::Port(p) => json!({ "port": [p], "outbound": ob }),
                        RuleMatcher::PortRange { start, end } => {
                            json!({ "port_range": [format!("{start}:{end}")], "outbound": ob })
                        }
                        RuleMatcher::Protocol(proto) => {
                            json!({ "protocol": [proto], "outbound": ob })
                        }
                        RuleMatcher::Application(app) | RuleMatcher::ProcessName(app) => {
                            json!({ "process_name": [app], "outbound": ob })
                        }
                    }
                })
                .collect();
            json!({ "auto_detect_interface": true, "rules": sb_rules, "final": "proxy" })
        }
        CoreId::Mihomo => {
            let mut mihomo_rules: Vec<String> = enabled
                .into_iter()
                .map(|r| {
                    let target = match r.action {
                        RuleAction::Proxy | RuleAction::SelectedProfile(_) => "PROXY",
                        RuleAction::Direct => "DIRECT",
                        RuleAction::Block => "REJECT",
                    };
                    match &r.matcher {
                        RuleMatcher::Domain(d) => format!("DOMAIN,{d},{target}"),
                        RuleMatcher::DomainSuffix(s) => format!("DOMAIN-SUFFIX,{s},{target}"),
                        RuleMatcher::DomainKeyword(k) => format!("DOMAIN-KEYWORD,{k},{target}"),
                        RuleMatcher::Ip(ip) => format!("IP-CIDR,{ip}/32,{target}"),
                        RuleMatcher::Cidr(net) => format!("IP-CIDR,{net},{target}"),
                        RuleMatcher::GeoIp(g) => {
                            format!("GEOIP,{},{target}", g.to_ascii_uppercase())
                        }
                        RuleMatcher::GeoSite(g) | RuleMatcher::RuleSet(g) => {
                            format!("GEOSITE,{g},{target}")
                        }
                        RuleMatcher::Port(p) => format!("DST-PORT,{p},{target}"),
                        RuleMatcher::PortRange { start, end } => {
                            format!("DST-PORT,{start}-{end},{target}")
                        }
                        RuleMatcher::Application(app) | RuleMatcher::ProcessName(app) => {
                            format!("PROCESS-NAME,{app},{target}")
                        }
                        RuleMatcher::Protocol(proto) => format!("NETWORK,{proto},{target}"),
                    }
                })
                .collect();
            mihomo_rules.push("MATCH,PROXY".to_owned());
            json!({ "rules": mihomo_rules })
        }
        other => json!({
            "core": other.display_name(),
            "rule_count": enabled.len(),
            "rules": enabled
        }),
    }
}
