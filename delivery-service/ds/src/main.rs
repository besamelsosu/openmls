//! # The OpenMLS Delivery Service (DS).
//!
//! This is a minimal implementation of 2.3. Delivery Service in
//! [The MLS Architecture](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html).
//! It is used for end-to-end testing of OpenMLS and can be used by other
//! implementations. However it should never be used in any sort of production
//! environment.
//!
//! Because the infrastructure description doesn't give a lot of guidelines on
//! the design of the DS we take a couple of deliberate design decisions here:
//! * The DS does not know about groups.
//! * Clients have to send a list of clients (group members) along with each
//!   message for the DS to know where to send the message.
//! * The DS stores and delivers key packages.
//!
//! This is a very basic delivery service that allows to register clients and
//! send messages to MLS groups.
//! Note that there are a lot of limitations to this service:
//! * No persistence layer such that all information gets lost when the process
//!   shuts down.
//! * No authentication for clients.
//! * Key packages can't be updated, changed or deleted at the moment.
//! * Messages lost in transit are gone.
//!
//! **⚠️ DON'T EXPECT ANY SECURITY OR PRIVACY FROM THIS!**
//!
//! The server always listens on localhost and should be run behind a TLS server
//! if accessible on the public internet.
//!
//! The DS returns a list of messages queued for the client in all groups they
//! are part of.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use clap::Command;
use parking_lot::Mutex;
use tls_codec::{Deserialize, Serialize, TlsSliceU16};

use ds_lib::{
    messages::{
        PublishKeyPackagesRequest, RecvMessageRequest, RegisterClientRequest,
        RegisterClientSuccessResponse,
    },
    *,
};
use openmls::prelude::*;

#[cfg(test)]
mod test;

/// The DS state.
/// It holds a list of clients and their information.
#[derive(Default, Debug)]
pub struct DsData {
    // (ClientIdentity, ClientInfo)
    clients: Mutex<HashMap<Vec<u8>, ClientInfo>>,

    // (group_id, epoch)
    groups: Mutex<HashMap<Vec<u8>, u64>>,
}

macro_rules! unwrap_data {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };
}

/// Try to interpret `bytes` as UTF-8; fall back to `0x<hex>` if it isn't.
fn bytes_to_display(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => format!("0x{}", hex::encode(bytes)),
    }
}

// === API ===

/// Registering a new client takes a serialised `RegisterClientRequest` and
/// returns an authentication token on success.
/// An HTTP conflict (409) is returned if a client with this name exists
/// already.
async fn register_client(State(data): State<Arc<DsData>>, body: Bytes) -> Response {
    let req = match RegisterClientRequest::tls_deserialize(&mut &body[..]) {
        Ok(i) => i,
        Err(_) => {
            log::error!("Invalid payload for /clients/register\n{body:?}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    if req.key_packages.0.is_empty() {
        log::error!("Invalid payload for /clients/register: no key packages");
        return StatusCode::BAD_REQUEST.into_response();
    }

    let key_packages = req
        .key_packages
        .0
        .into_vec()
        .into_iter()
        .map(|(b, kp)| (b.into_vec(), kp))
        .collect();
    let new_client_info = ClientInfo::new(key_packages);

    log::debug!("Registering client: {:?}", new_client_info.id);

    let response = RegisterClientSuccessResponse {
        auth_token: new_client_info.auth_token.clone(),
    };

    let mut clients = data.clients.lock();
    if clients.contains_key(&new_client_info.id) {
        return StatusCode::CONFLICT.into_response();
    }
    let old = clients.insert(new_client_info.id.clone(), new_client_info);
    assert!(old.is_none());

    response.tls_serialize_detached().unwrap().into_response()
}

/// Resets the server state.
async fn reset(headers: HeaderMap, State(data): State<Arc<DsData>>) -> Response {
    if let Some(reset_key) = headers.get("reset-key") {
        if reset_key != "poc-reset-password" {
            return StatusCode::NETWORK_AUTHENTICATION_REQUIRED.into_response();
        }
    }
    log::debug!("Resetting server");
    let mut clients = data.clients.lock();
    let mut groups = data.groups.lock();
    clients.clear();
    groups.clear();
    StatusCode::OK.into_response()
}

/// Get the list of key packages for a given client `{id}`.
/// This returns a serialised vector of `ClientKeyPackages` (see the `ds-lib`
/// for details).
async fn get_key_packages(Path(path): Path<String>, State(data): State<Arc<DsData>>) -> Response {
    let clients = data.clients.lock();

    let id = match base64::engine::general_purpose::URL_SAFE.decode(path) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    log::debug!("Getting key packages for {id:?}");

    let client = match clients.get(&id) {
        Some(c) => c,
        None => return StatusCode::NO_CONTENT.into_response(),
    };
    unwrap_data!(client.key_packages.tls_serialize_detached()).into_response()
}

/// Publish key packages for a given client `{id}`.
async fn publish_key_packages(
    Path(path): Path<String>,
    State(data): State<Arc<DsData>>,
    body: Bytes,
) -> Response {
    let mut clients = data.clients.lock();

    let id = match base64::engine::general_purpose::URL_SAFE.decode(path) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let client = match clients.get(&id) {
        Some(c) => c,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Deserialize request
    let req = match PublishKeyPackagesRequest::tls_deserialize(&mut &body[..]) {
        Ok(i) => i,
        Err(_) => {
            log::error!("Invalid payload for /clients/key_packages/{id:?}\n{body:?}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Auth
    if client.auth_token != req.auth_token {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    log::debug!("Add key package for {id:?}");

    let client = match clients.get_mut(&id) {
        Some(client) => client,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    req.key_packages
        .0
        .into_vec()
        .into_iter()
        .for_each(|value| client.key_packages.0.push(value));

    StatusCode::OK.into_response()
}

/// Consume a key package for a given client `{id}`.
/// This returns a serialised `KeyPackage` (see the `ds-lib`
/// for details).
async fn consume_key_package(
    Path(path): Path<String>,
    State(data): State<Arc<DsData>>,
) -> Response {
    let mut clients = data.clients.lock();

    let id = match base64::engine::general_purpose::URL_SAFE.decode(path) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    log::debug!("Consuming key package for {id:?}");

    let key_package = match clients.get_mut(&id) {
        Some(c) => match c.consume_kp() {
            Ok(kp) => kp,
            Err(e) => {
                log::debug!("Error consuming key package: {e}");
                return StatusCode::NO_CONTENT.into_response();
            }
        },
        None => return StatusCode::NO_CONTENT.into_response(),
    };

    unwrap_data!(key_package.tls_serialize_detached()).into_response()
}

/// Send a welcome message to a client.
/// This takes a serialised `Welcome` message and stores the message for all
/// clients in the welcome message.
async fn send_welcome(State(data): State<Arc<DsData>>, body: Bytes) -> Response {
    let welcome_msg = unwrap_data!(MlsMessageIn::tls_deserialize(&mut &body[..]));
    let welcome = welcome_msg.clone().into_welcome().unwrap();
    log::debug!("Storing welcome message: {welcome_msg:?}");

    let mut clients = data.clients.lock();
    for secret in welcome.secrets().iter() {
        let key_package_hash = &secret.new_member();
        for client in clients.values_mut() {
            match client
                .reserved_key_pkg_hash
                .take(key_package_hash.as_slice())
            {
                Some(_kp_hash) => {
                    client.welcome_queue.push(welcome_msg);
                    return StatusCode::OK.into_response();
                }
                None => continue,
            };
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Send an MLS message to a set of clients (group).
/// This takes a serialised `GroupMessage` and stores the message for each
/// client in the recipient list.
/// If a handshake message is sent with an epoch smaller or equal to another
/// handshake message this DS has seen, a 409 is returned and the message is not
/// processed.
async fn msg_send(State(data): State<Arc<DsData>>, body: Bytes) -> Response {
    let group_msg = unwrap_data!(GroupMessage::tls_deserialize(&mut &body[..]));
    log::debug!("Storing group message: {group_msg:?}");

    let mut clients = data.clients.lock();
    let mut groups = data.groups.lock();

    let protocol_msg: ProtocolMessage = group_msg.msg.clone().try_into().unwrap();

    // Reject any handshake message that has an earlier epoch than the one we know
    // about.
    // XXX: There's no test for this block in here right now because it's pretty
    //      painful to test in the current setting. This should get tested through
    //      the client and maybe later with the MlsGroup API.
    if protocol_msg.is_handshake_message() {
        let epoch = protocol_msg.epoch().as_u64();
        let group_id = protocol_msg.group_id().as_slice();
        let is_commit = protocol_msg.content_type() == ContentType::Commit;

        match groups.get(group_id).copied() {
            Some(group_epoch) => {
                // Anything not targeting the epoch the DS currently has on
                // record is stale — a genuinely old retransmit, or a second
                // commit racing to close out an epoch someone else already
                // closed out first.
                if epoch != group_epoch {
                    return StatusCode::CONFLICT.into_response();
                }
                if is_commit {
                    // Accepting this commit finalizes N -> N+1. Record the
                    // *result*, not the epoch the message itself carries.
                    groups.insert(group_id.to_vec(), epoch + 1);
                }
            }
            None => {
                // Handle a commit as the very first message for a group_id
                // the same way: store the epoch it produces, not the one it
                // was built against, or a second same-epoch commit racing
                // right behind it would slip through this branch too.
                let stored_epoch = if is_commit { epoch + 1 } else { epoch };
                groups.insert(group_id.to_vec(), stored_epoch);
            }
        }
    }

    for recipient in group_msg.recipients.iter() {
        let client = match clients.get_mut(recipient.as_slice()) {
            Some(client) => client,
            None => return StatusCode::NOT_FOUND.into_response(),
        };
        client.msgs.push(group_msg.msg.clone());
    }
    StatusCode::OK.into_response()
}

/// Receive all messages stored for the client `{id}`.
/// This returns a serialised vector of `Message`s (see the `ds-lib` for
/// details) the DS has stored for the given client.
/// The messages are deleted on the DS when sent out.
async fn msg_recv(
    Path(path): Path<String>,
    State(data): State<Arc<DsData>>,
    body: Bytes,
) -> Response {
    let mut clients = data.clients.lock();

    let id = match base64::engine::general_purpose::URL_SAFE.decode(path) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let client = match clients.get_mut(&id) {
        Some(client) => client,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Auth
    // Deserialize request
    let req = match RecvMessageRequest::tls_deserialize(&mut &body[..]) {
        Ok(i) => i,
        Err(_) => {
            log::error!("Invalid payload for /clients/key_packages/{id:?}\n{body:?}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    if req.auth_token != client.auth_token {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    log::debug!("Getting messages for client {id:?}");

    let mut out: Vec<MlsMessageIn> = Vec::new();
    let mut welcomes: Vec<MlsMessageIn> = client.welcome_queue.drain(..).collect();
    out.append(&mut welcomes);
    let mut msgs: Vec<MlsMessageIn> = client.msgs.drain(..).collect();
    out.append(&mut msgs);

    match TlsSliceU16(&out).tls_serialize_detached() {
        Ok(out) => out.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn debug_dump(State(data): State<Arc<DsData>>) -> Response {
    let clients_lock = data.clients.lock();
    let groups_lock = data.groups.lock();

    let clients: Vec<serde_json::Value> = clients_lock
        .values()
        .map(|c| {
            serde_json::json!({
                "id": bytes_to_display(&c.id),
                "key_packages": c.key_packages.0.iter()
                    .map(|(hash, _)| hex::encode(hash.as_slice()))
                    .collect::<Vec<_>>(),
                "reserved_kp_hashes": c.reserved_key_pkg_hash.iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                "queued_msgs": c.msgs.len(),
                "queued_welcomes": c.welcome_queue.len(),
            })
        })
        .collect();

    let groups: Vec<serde_json::Value> = groups_lock
        .iter()
        .map(|(id, epoch)| {
            serde_json::json!({
                "group_id": hex::encode(id),
                "epoch": epoch,
            })
        })
        .collect();

    let dump = serde_json::json!({
        "client_count": clients.len(),
        "group_count": groups.len(),
        "clients": clients,
        "groups": groups,
    });

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        dump.to_string(),
    )
        .into_response()
}

/// Build the axum router for the DS.
fn app(data: Arc<DsData>) -> Router {
    Router::new()
        .route("/clients/register", post(register_client))
        .route(
            "/clients/key_packages/{id}",
            get(get_key_packages).post(publish_key_packages),
        )
        .route("/clients/key_package/{id}", get(consume_key_package))
        .route("/send/welcome", post(send_welcome))
        .route("/send/message", post(msg_send))
        .route("/recv/{id}", get(msg_recv))
        .route("/reset", get(reset))
        .route("/debug/dump", get(debug_dump))
        .with_state(data)
}

// === Main function driving the DS ===

#[tokio::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();

    // Configure App and command line arguments.
    let matches = Command::new("OpenMLS DS")
        .version("0.1.0")
        .author("OpenMLS Developers")
        .about("PoC MLS Delivery Service")
        .arg(
            clap::Arg::new("port")
                .short('p')
                .long("port")
                .value_name("port")
                .value_parser(clap::value_parser!(u16))
                .help("Sets a custom port number"),
        )
        .get_matches();

    // The data this app operates on.
    let data = Arc::new(DsData::default());

    // Set default port or use port provided on the command line.
    let port = *matches.get_one("port").unwrap_or(&8080u16);

    let ip = "127.0.0.1";
    let addr = format!("{ip}:{port}");
    log::info!("Listening on: {addr}");

    // Start the server.
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app(data)).await
}
