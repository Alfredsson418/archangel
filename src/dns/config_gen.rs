//! Generate unbound.conf from our settings + local overrides.

use crate::dns::{DnsSettings, records::DnsRecord};
use crate::error::AppResult;

pub fn render(_settings: &DnsSettings, _records: &[DnsRecord]) -> String {
    todo!("render unbound.conf content")
}

pub async fn write_config(
    _settings: &DnsSettings,
    _records: &[DnsRecord],
    _path: &str,
) -> AppResult<()> {
    todo!("render() then write to disk")
}
