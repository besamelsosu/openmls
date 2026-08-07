use base64::Engine;
use tls_codec::{Deserialize, TlsVecU16};
use url::Url;

use crate::networking::{get_with_body, post_empty_unless_conflict};

use super::{
    networking::{get, post},
    user::User,
};

use ds_lib::{
    messages::{
        AuthToken, PublishKeyPackagesRequest, RecvMessageRequest, RegisterClientRequest,
        RegisterClientSuccessResponse,
    },
    *,
};
use openmls::prelude::*;

pub struct Backend {
    ds_url: Url,
}

impl Backend {
    /// Atomically reserve a group ID on the delivery service.
    pub fn reserve_group(&self, group_id: &[u8]) -> Result<bool, String> {
        let mut url = self.ds_url.clone();
        let encoded_id = base64::engine::general_purpose::URL_SAFE.encode(group_id);
        url.set_path(&format!("/groups/{encoded_id}"));
        post_empty_unless_conflict(&url)
    }

    /// Register a new client with the server.
    pub fn register_client(
        &self,
        key_packages: Vec<(Vec<u8>, KeyPackage)>,
    ) -> Result<AuthToken, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/register");

        let key_packages = ClientKeyPackages(
            key_packages
                .into_iter()
                .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
                .collect::<Vec<_>>()
                .into(),
        );
        let request = RegisterClientRequest { key_packages };
        let response_bytes = post(&url, &request)?;
        let response =
            RegisterClientSuccessResponse::tls_deserialize(&mut response_bytes.as_slice())
                .map_err(|e| format!("Error decoding server response: {e:?}"))?;

        Ok(response.auth_token)
    }

    /// Get and reserve a key package for a client.
    pub fn consume_key_package(&self, client_id: &[u8]) -> Result<KeyPackageIn, String> {
        let mut url = self.ds_url.clone();
        let encoded_id = base64::engine::general_purpose::URL_SAFE.encode(client_id);
        url.set_path(&format!("/clients/key_package/{encoded_id}"));

        let response = get(&url)?;
        KeyPackageIn::tls_deserialize(&mut response.as_slice())
            .map_err(|e| format!("Error decoding server response: {e:?}"))
    }

    /// Publish client additional key packages
    pub fn publish_key_packages(&self, user: &User, ckp: ClientKeyPackages) -> Result<(), String> {
        let Some(auth_token) = user.auth_token() else {
            return Err("Please register user before publishing key packages".to_string());
        };
        let mut url = self.ds_url.clone();
        let encoded_id =
            base64::engine::general_purpose::URL_SAFE.encode(user.identity.borrow().identity());
        url.set_path(&format!("/clients/key_packages/{encoded_id}"));

        let request = PublishKeyPackagesRequest {
            key_packages: ckp,
            auth_token: auth_token.clone(),
        };

        // The response should be empty.
        let _response = post(&url, &request)?;
        Ok(())
    }

    /// Send a welcome message.
    pub fn send_welcome(&self, welcome_msg: &MlsMessageOut) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/welcome");

        // The response should be empty.
        let _response = post(&url, welcome_msg)?;
        Ok(())
    }

    /// Send a group message.
    pub fn send_msg(&self, group_msg: &GroupMessage) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/message");

        // The response should be empty.
        let _response = post(&url, group_msg)?;
        Ok(())
    }

    /// Get a list of all new messages for the user.
    pub fn recv_msgs(&self, user: &User) -> Result<Vec<MlsMessageIn>, String> {
        let Some(auth_token) = user.auth_token() else {
            return Err("Please register user before publishing key packages".to_string());
        };
        let mut url = self.ds_url.clone();
        let encoded_id =
            base64::engine::general_purpose::URL_SAFE.encode(user.identity.borrow().identity());
        url.set_path(&format!("/recv/{encoded_id}"));

        let request = RecvMessageRequest {
            auth_token: auth_token.clone(),
        };

        let response = get_with_body(&url, &request)?;
        TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut response.as_slice())
            .map(|r| r.into())
            .map_err(|e| format!("Invalid message list: {e:?}"))
    }

    /// Reset the DS.
    pub fn reset_server(&self) {
        let mut url = self.ds_url.clone();
        url.set_path("reset");
        let _ = get(&url);
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            // There's a public DS at https://mls.franziskuskiefer.de
            ds_url: Url::parse("http://localhost:8080").unwrap(),
        }
    }
}
