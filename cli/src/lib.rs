//! Reusable API for the OpenMLS proof-of-concept client.
//!
//! The [`Client`] type exposes the operations used by the interactive CLI.  The
//! crate is also built as a `cdylib`; its C ABI is documented in [`ffi`].

mod admin_list_gce;
mod backend;
mod conversation;
mod identity;
mod networking;
mod openmls_rust_persistent_crypto;
mod serialize_any_hashmap;
mod user;

pub mod ffi;

pub use backend::Backend;
pub use conversation::ConversationMessage;
pub use user::User;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub groups: Vec<String>,
    pub key_package_count: usize,
}

#[derive(Debug, Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub message_count: usize,
}

/// A stateful OpenMLS client suitable for embedding in another application.
#[derive(Default)]
pub struct Client {
    user: Option<User>,
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: impl Into<String>) -> Result<(), String> {
        let mut user = User::new(name.into())?;
        user.add_key_package();
        user.add_key_package();
        user.register()?;
        self.user = Some(user);
        Ok(())
    }

    pub fn load(&mut self, name: impl Into<String>) -> Result<(), String> {
        self.user = Some(User::load(name.into())?);
        Ok(())
    }

    pub fn username(&self) -> Option<String> {
        self.user.as_ref().map(User::username)
    }

    pub fn group_names(&self) -> Result<Vec<String>, String> {
        Ok(self.user()?.group_names())
    }

    pub fn info(&self) -> Result<UserInfo, String> {
        let user = self.user()?;
        Ok(UserInfo {
            username: user.username(),
            groups: user.group_names(),
            key_package_count: user.key_packages().len(),
        })
    }

    pub fn group_info(&self, group: &str) -> Result<GroupInfo, String> {
        let user = self.user()?;
        Ok(GroupInfo {
            name: group.to_string(),
            members: user.group_member_names(group)?,
            admins: user.group_admin_names(group)?,
            message_count: user.group_message_count(group)?,
        })
    }

    pub fn resolve_group(&self, prefix: &str) -> Result<String, String> {
        self.user()?.resolve_group_prefix(prefix)
    }

    pub fn create_key_package(&mut self) -> Result<(), String> {
        self.user_mut()?.create_kp();
        Ok(())
    }

    pub fn create_group(&mut self) -> Result<String, String> {
        self.user_mut()?.create_group()
    }

    pub fn update(&mut self, group: Option<String>) -> Result<Vec<ConversationMessage>, String> {
        self.user_mut()?.update(group)
    }

    pub fn invite(
        &mut self,
        group: impl Into<String>,
        user: impl Into<String>,
    ) -> Result<(), String> {
        self.user_mut()?.invite(user.into(), group.into())
    }

    pub fn remove(
        &mut self,
        group: impl Into<String>,
        user: impl Into<String>,
    ) -> Result<(), String> {
        self.user_mut()?.remove(user.into(), group.into())
    }

    pub fn promote(
        &mut self,
        group: impl Into<String>,
        user: impl Into<String>,
    ) -> Result<(), String> {
        self.user_mut()?.promote(user.into(), group.into())
    }

    pub fn demote(
        &mut self,
        group: impl Into<String>,
        user: impl Into<String>,
    ) -> Result<(), String> {
        self.user_mut()?.demote(user.into(), group.into())
    }

    pub fn leave(&mut self, group: impl Into<String>) -> Result<(), String> {
        self.user_mut()?.leave(group.into())
    }

    pub fn self_update(&mut self, group: impl Into<String>) -> Result<(), String> {
        self.user_mut()?.self_update(group.into())
    }

    pub fn send(&mut self, group: impl Into<String>, message: &str) -> Result<(), String> {
        self.user_mut()?.send_msg(message, group.into())
    }

    pub fn read(
        &self,
        group: impl Into<String>,
    ) -> Result<Option<Vec<ConversationMessage>>, String> {
        self.user()?.read_msgs(group.into())
    }

    pub fn reset(&mut self) {
        backend::Backend::default().reset_server();
        self.user = None;
    }

    fn user(&self) -> Result<&User, String> {
        self.user
            .as_ref()
            .ok_or_else(|| "No client registered or loaded".to_string())
    }

    fn user_mut(&mut self) -> Result<&mut User, String> {
        self.user
            .as_mut()
            .ok_or_else(|| "No client registered or loaded".to_string())
    }
}
