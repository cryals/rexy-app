use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RuleMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    Ip(String),
    Cidr(IpNet),
    GeoIp(String),
    GeoSite(String),
    Application(String),
    ProcessName(String),
    Port(u16),
    PortRange { start: u16, end: u16 },
    Protocol(String),
    RuleSet(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "profile_id", rename_all = "snake_case")]
pub enum RuleAction {
    Proxy,
    Direct,
    Block,
    SelectedProfile(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub group: String,
    pub matcher: RuleMatcher,
    pub action: RuleAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub id: Uuid,
    pub tag: String,
    pub kind: String,
    pub source_url: Option<String>,
    pub local_path: Option<String>,
    pub enabled: bool,
    pub entry_count: usize,
}
