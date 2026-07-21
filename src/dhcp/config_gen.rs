//! Generate a dnsmasq config file from our `DhcpScope` model.

use crate::dhcp::DhcpScope;
use crate::error::AppResult;

/// Render dnsmasq config text, e.g.:
///   interface=eth1
///   dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h
pub fn render(_scopes: &[DhcpScope]) -> String {
    todo!("render dnsmasq.conf content from scopes")
}

pub async fn write_config(_scopes: &[DhcpScope], _path: &str) -> AppResult<()> {
    todo!("render() then write to disk, e.g. /etc/netfence/dnsmasq.conf")
}
