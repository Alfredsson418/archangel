//! Read and expose active DHCP leases (dnsmasq writes these to a
//! lease file, typically /var/lib/misc/dnsmasq.leases).

use crate::error::AppResult;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Lease {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub expires_at: i64, // unix timestamp
}

pub async fn list(_lease_file_path: &str) -> AppResult<Vec<Lease>> {
    todo!("parse the dnsmasq lease file")
}
