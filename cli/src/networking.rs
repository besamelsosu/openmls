use reqwest::{self, blocking::Client, blocking::Response, StatusCode};
use std::sync::OnceLock;
use url::Url;

use openmls::prelude::tls_codec::Serialize;

fn http_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(Client::new)
}

fn handle_response(response: Result<Response, reqwest::Error>) -> Result<Vec<u8>, String> {
    match response {
        Ok(r) => {
            if r.status() != StatusCode::OK {
                Err(format!("Error status code {:?}", r.status()))
            } else {
                r.bytes()
                    .map(|b| b.to_vec())
                    .map_err(|e| format!("Error retrieving bytes from response: {e:?}"))
            }
        }
        Err(e) => Err(format!("ERROR: {e:?}")),
    }
}

pub fn post(url: &Url, msg: &impl Serialize) -> Result<Vec<u8>, String> {
    let serialized_msg = msg
        .tls_serialize_detached()
        .map_err(|e| format!("TLS serialization error: {e:?}"))?;
    log::debug!("Post {url:?}");
    log::trace!("Payload: {serialized_msg:?}");

    let response = http_client()
        .post(url.to_string())
        .body(serialized_msg)
        .send();
    handle_response(response)
}

pub fn get(url: &Url) -> Result<Vec<u8>, String> {
    get_internal::<()>(url, None)
}

pub fn get_with_body(url: &Url, body: &impl Serialize) -> Result<Vec<u8>, String> {
    get_internal(url, Some(body))
}

fn get_internal<T: Serialize>(url: &Url, msg: Option<&T>) -> Result<Vec<u8>, String> {
    log::debug!("Get {url:?}");
    let mut request = http_client().get(url.to_string());
    if let Some(msg) = msg {
        let serialized_msg = msg
            .tls_serialize_detached()
            .map_err(|e| format!("TLS serialization error: {e:?}"))?;
        log::trace!("Payload: {serialized_msg:?}");
        request = request.body(serialized_msg);
    }
    handle_response(request.send())
}
