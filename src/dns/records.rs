//! Local DNS overrides / host entries (e.g. "nas.home.arpa -> 192.168.1.20").

use crate::error::AppResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub hostname: String,
    pub ip_address: String,
}

pub async fn list() -> AppResult<Vec<DnsRecord>> {
    todo!("return local DNS records from the config store")
}

pub async fn create(_record: DnsRecord) -> AppResult<()> {
    todo!("persist a new local DNS record")
}
