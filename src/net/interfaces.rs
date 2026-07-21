//! List and toggle network interfaces via netlink.

use crate::error::{AppError, AppResult};
use crate::net::NetManager;
use futures::stream::TryStreamExt;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags}; // note: LinkFlags, not LinkFlag
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub is_up: bool,
}

/// List all interfaces on the box (this is the code from the standalone
/// netlink-test example, moved in here and cleaned up).
pub async fn list(net: &NetManager) -> AppResult<Vec<Interface>> {
    let mut links = net.handle().link().get().execute();
    let mut result = Vec::new();

    while let Some(link) = links
        .try_next()
        .await
        .map_err(|e| AppError::Netlink(e.to_string()))?
    {
        let mut name = String::from("<unknown>");
        for attr in &link.attributes {
            if let LinkAttribute::IfName(n) = attr {
                name = n.clone();
            }
        }

        // IFF_UP flag check - link.header.flags is a bitfield.
        let is_up = link.header.flags.contains(LinkFlags::Up);

        result.push(Interface {
            index: link.header.index,
            name,
            is_up,
        });
    }

    Ok(result)
}

/// Bring an interface up or down by name. Requires CAP_NET_ADMIN.
pub async fn set_link_state(net: &NetManager, if_name: &str, up: bool) -> Result<(), AppError> {
    let mut links = net
        .handle()
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();

    let link = links
        .try_next()
        .await
        .map_err(|e| AppError::Netlink(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("interface '{if_name}' not found")))?;

    let builder = rtnetlink::LinkUnspec::new_with_index(link.header.index);
    let builder = if up { builder.up() } else { builder.down() };

    net.handle()
        .link()
        .set(builder.build())
        .execute()
        .await
        .map_err(|e: rtnetlink::Error| AppError::Netlink(e.to_string()))?;

    Ok(())
}
