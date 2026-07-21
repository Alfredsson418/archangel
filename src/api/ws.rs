//! WebSocket endpoint for live dashboard data (traffic, system stats).
//! Frontend connects once and gets pushed updates instead of polling.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use std::time::Duration;

pub async fn upgrade(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    loop {
        // TODO: replace with real stats::traffic::current() / stats::system::current()
        let payload = serde_json::json!({ "type": "heartbeat" });
        let send_result: Result<(), axum::Error> =
            socket.send(Message::Text(payload.to_string().into())).await;

        if send_result.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
