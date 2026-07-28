//! Top-level config schema - the full "desired state" of the box.

use crate::dhcp::DhcpScope;
use crate::dns::{DnsSettings, records::DnsRecord};
use crate::firewall::FirewallRule;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub firewall_rules: Vec<FirewallRule>,
    pub dhcp_scopes: Vec<DhcpScope>,
    pub dns_settings: Option<DnsSettings>,
    pub dns_records: Vec<DnsRecord>,
}
