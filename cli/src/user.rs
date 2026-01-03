use std::collections::HashMap;
use std::str;
use std::{cell::RefCell, collections::HashSet};

use ds_lib::messages::AuthToken;
use ds_lib::{ClientKeyPackages, GroupMessage};
use openmls::prelude::{tls_codec::*, *};
use openmls_traits::OpenMlsProvider;

use super::{
    backend::Backend, conversation::Conversation, conversation::ConversationMessage,
    identity::Identity, openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(PartialEq)]
pub enum PostUpdateActions {
    None,
    Remove,
}

pub struct Contact {
    id: Vec<u8>,
}

impl Contact {
    fn user_name(&self) -> String {
        String::from_utf8(self.id.clone()).unwrap()
    }
}

pub struct Group {
    group_name: String,
    conversation: Conversation,
    mls_group: RefCell<MlsGroup>,
}

pub struct User {
    pub(crate) contacts: HashMap<Vec<u8>, Contact>,
    pub(crate) groups: RefCell<HashMap<String, Group>>,
    group_list: HashSet<String>,
    pub(crate) identity: RefCell<Identity>,
    backend: Backend,
    provider: OpenMlsRustPersistentCrypto,
    autosave_enabled: bool,
    auth_token: Option<AuthToken>,
}

impl User {
    /// Create a new user with the given name and a fresh set of credentials.
    pub fn new(user_name: String) -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = std::env::temp_dir().join(format!("openmls_cli_{}.db", user_name));
        let provider = OpenMlsRustPersistentCrypto::new(db_path)?;

        let out = Self {
            groups: RefCell::new(HashMap::new()),
            group_list: HashSet::new(),
            contacts: HashMap::new(),
            identity: RefCell::new(Identity::new(CIPHERSUITE, &provider, user_name.as_bytes())),
            backend: Backend::default(),
            provider,
            autosave_enabled: true,
            auth_token: None,
        };
        Ok(out)
    }

    /// Load a user from SQLite database.
    pub fn load(user_name: String) -> Result<Self, Box<dyn std::error::Error>> {
        let db_path = std::env::temp_dir().join(format!("openmls_cli_{}.db", user_name));

        // Database and user must exist
        if !db_path.exists() {
            return Err(format!("User database not found for {}", user_name).into());
        }

        let provider = OpenMlsRustPersistentCrypto::new(db_path)?;

        // Load user application state from the database
        let (contacts, group_list, autosave_enabled, auth_token, identity_opt) =
            Self::load_user_state_from_db(&provider)?;

        let identity = match identity_opt {
            Some(i) => RefCell::new(i),
            None => RefCell::new(Identity::new(CIPHERSUITE, &provider, user_name.as_bytes())),
        };

        #[allow(unused_mut)]
        let mut user = Self {
            groups: RefCell::new(HashMap::new()),
            group_list,
            contacts,
            identity,
            backend: Backend::default(),
            provider,
            autosave_enabled,
            auth_token,
        };

        // Load all groups
        for group_name in &user.group_list.clone() {
            let mlsgroup = MlsGroup::load(
                user.provider.storage(),
                &GroupId::from_slice(group_name.as_bytes()),
            );
            match mlsgroup {
                Ok(Some(group)) => {
                    let grp = Group {
                        mls_group: RefCell::new(group),
                        group_name: group_name.clone(),
                        conversation: Conversation::default(),
                    };
                    user.groups.borrow_mut().insert(group_name.clone(), grp);
                }
                Ok(None) => {
                    log::warn!("Group {} not found in storage", group_name);
                }
                Err(e) => {
                    log::error!("Error loading group {}: {:?}", group_name, e);
                    return Err(format!("Failed to load group {}: {}", group_name, e).into());
                }
            }
        }

        Ok(user)
    }

    /// Load user state (contacts, groups, auth_token, identity) from SQLite database.
    fn load_user_state_from_db(
        provider: &OpenMlsRustPersistentCrypto,
    ) -> Result<
        (
            HashMap<Vec<u8>, Contact>,
            HashSet<String>,
            bool,
            Option<AuthToken>,
            Option<Identity>,
        ),
        Box<dyn std::error::Error>,
    > {
        let conn = rusqlite::Connection::open(provider.db_path())?;

        // Load contacts
        let mut contacts = HashMap::new();
        let mut stmt = conn.prepare("SELECT id FROM contacts")?;
        let contact_ids = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for contact_id in contact_ids {
            let id = contact_id?;
            contacts.insert(id.clone(), Contact { id });
        }

        // Load groups
        let mut groups = HashSet::new();
        let mut stmt = conn.prepare("SELECT name FROM groups")?;
        let group_names = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for group_name in group_names {
            groups.insert(group_name?);
        }

        // Load autosave flag
        let autosave_enabled = conn
            .query_row(
                "SELECT value FROM user_config WHERE key = 'autosave_enabled'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_else(|_| "false".to_string())
            == "true";

        // Load auth token
        let auth_token = conn
            .query_row(
                "SELECT value FROM user_config WHERE key = 'auth_token'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|token_json| serde_json::from_str(&token_json).ok());

        // Load identity if present
        let identity = conn
            .query_row(
                "SELECT value FROM user_config WHERE key = 'identity'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|ident_json| {
                let ident: Identity = serde_json::from_str(&ident_json).ok()?;
                // Ensure signer key material is stored in the provider storage
                if ident.signer.store(provider.storage()).is_err() {
                    log::warn!("Failed to store identity signer into storage");
                }
                Some(ident)
            });

        Ok((contacts, groups, autosave_enabled, auth_token, identity))
    }

    /// Save user state to SQLite database.
    pub fn save(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let conn = rusqlite::Connection::open(self.provider.db_path())?;

        // Clear and write contacts
        conn.execute("DELETE FROM contacts", [])?;
        for contact in self.contacts.values() {
            conn.execute(
                "INSERT OR REPLACE INTO contacts (id) VALUES (?1)",
                [&contact.id],
            )?;
        }

        // Clear and write groups
        conn.execute("DELETE FROM groups", [])?;
        for group_name in &self.group_list {
            conn.execute(
                "INSERT OR REPLACE INTO groups (name) VALUES (?1)",
                [group_name],
            )?;
        }

        // Write autosave flag
        let autosave_str = if self.autosave_enabled {
            "true"
        } else {
            "false"
        };
        conn.execute(
            "INSERT OR REPLACE INTO user_config (key, value) VALUES (?, ?)",
            ["autosave_enabled", autosave_str],
        )?;

        // Write auth token if present
        if let Some(ref token) = self.auth_token {
            let token_json = serde_json::to_string(token)?;
            conn.execute(
                "INSERT OR REPLACE INTO user_config (key, value) VALUES (?, ?)",
                ["auth_token", &token_json],
            )?;
        } else {
            // Delete auth token if not present
            conn.execute("DELETE FROM user_config WHERE key = 'auth_token'", [])?;
        }

        // Persist identity
        let ident_json = serde_json::to_string(&*self.identity.borrow())?;
        conn.execute(
            "INSERT OR REPLACE INTO user_config (key, value) VALUES (?, ?)",
            ["identity", &ident_json],
        )?;

        log::info!("User state saved to SQLite");
        Ok(())
    }

    pub fn enable_auto_save(&mut self) {
        self.autosave_enabled = true;
    }

    fn autosave(&mut self) {
        if self.autosave_enabled {
            if let Err(e) = self.save() {
                log::error!("Autosave error: {:?}", e);
            }
        }
    }

    /// Add a key package to the user identity and return the pair [key package
    /// hash ref , key package]
    pub fn add_key_package(&self) -> (Vec<u8>, KeyPackage) {
        let kp = self
            .identity
            .borrow_mut()
            .add_key_package(CIPHERSUITE, &self.provider);
        (
            kp.hash_ref(self.provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            kp,
        )
    }

    /// Get a member
    fn find_member_index(&self, name: String, group: &Group) -> Result<LeafNodeIndex, String> {
        let mls_group = group.mls_group.borrow();
        for Member {
            index,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            let credential = BasicCredential::try_from(credential).unwrap();
            if credential.identity() == name.as_bytes() {
                return Ok(index);
            }
        }
        Err("Unknown member".to_string())
    }

    /// Get the key packages fo this user.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackage)> {
        // clone first !
        let kpgs = self.identity.borrow().kp.clone();
        Vec::from_iter(kpgs)
    }

    pub fn register(&mut self) {
        match self.backend.register_client(self.key_packages()) {
            Ok(token) => {
                log::debug!("Created new user: {:?}", self.user_name());
                self.set_auth_token(token)
            }
            Err(e) => log::error!("Error creating user: {e:?}"),
        }
    }

    /// Get a list of clients in the group to send messages to.
    fn recipients(&self, group: &Group) -> Vec<Vec<u8>> {
        let mut recipients = Vec::new();

        let mls_group = group.mls_group.borrow();
        for Member {
            index: _,
            encryption_key: _,
            signature_key,
            credential,
        } in mls_group.members()
        {
            if self
                .identity
                .borrow()
                .credential_with_key
                .signature_key
                .as_slice()
                != signature_key.as_slice()
            {
                let credential = BasicCredential::try_from(credential).unwrap();
                log::debug!(
                    "Searching for contact {:?}",
                    str::from_utf8(credential.identity()).unwrap()
                );
                let contact = match self.contacts.get(credential.identity()) {
                    Some(c) => c.id.clone(),
                    None => panic!("There's a member in the group we don't know."),
                };
                recipients.push(contact);
            }
        }
        recipients
    }

    /// Return the last 100 messages sent to the group.
    pub fn read_msgs(
        &self,
        group_name: String,
    ) -> Result<Option<Vec<ConversationMessage>>, String> {
        let groups = self.groups.borrow();
        groups.get(&group_name).map_or_else(
            || Err("Unknown group".to_string()),
            |g| {
                Ok(g.conversation
                    .get(100)
                    .map(|messages: &[crate::conversation::ConversationMessage]| messages.to_vec()))
            },
        )
    }

    /// Create a new key package and publish it to the delivery server
    pub fn create_kp(&self) {
        let kp = self.add_key_package();
        let ckp = ClientKeyPackages(
            vec![kp]
                .into_iter()
                .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
                .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                .into(),
        );

        match self.backend.publish_key_packages(self, ckp) {
            Ok(()) => (),
            Err(e) => println!("Error sending new key package: {e:?}"),
        };
    }

    /// Send an application message to the group.
    pub fn send_msg(&self, msg: &str, group: String) -> Result<(), String> {
        let groups = self.groups.borrow();
        let group = match groups.get(&group) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let message_out = group
            .mls_group
            .borrow_mut()
            .create_message(
                &self.provider,
                &self.identity.borrow().signer,
                msg.as_bytes(),
            )
            .map_err(|e| format!("{e}"))?;

        let msg = GroupMessage::new(message_out.into(), &self.recipients(group));
        log::debug!(" >>> send: {msg:?}");
        match self.backend.send_msg(&msg) {
            Ok(()) => (),
            Err(e) => println!("Error sending group message: {e:?}"),
        }

        // XXX: Need to update the client's local view of the conversation to include
        // the message they sent.

        Ok(())
    }

    /// Update the user clients list.
    /// It updates the contacts with all the clients known by the server
    fn update_clients(&mut self) {
        match self.backend.list_clients() {
            Ok(mut v) => {
                for client_id in v.drain(..) {
                    log::debug!(
                        "update::Processing client for contact {:?}",
                        str::from_utf8(&client_id).unwrap()
                    );
                    if client_id != self.identity.borrow().identity()
                        && self
                            .contacts
                            .insert(
                                client_id.clone(),
                                Contact {
                                    id: client_id.clone(),
                                },
                            )
                            .is_some()
                    {
                        log::debug!(
                            "update::added client to contact {:?}",
                            str::from_utf8(&client_id).unwrap()
                        );
                        log::trace!("Updated client {}", "");
                    }
                }
            }
            Err(e) => log::debug!("update_clients::Error reading clients from DS: {e:?}"),
        }
        log::debug!("update::Processing clients done, contact list is:");
        for contact_id in self.contacts.keys() {
            log::debug!(
                "update::Parsing contact {:?}",
                str::from_utf8(contact_id).unwrap()
            );
        }
    }

    fn process_protocol_message(
        &mut self,
        group_name: Option<String>,
        message: ProtocolMessage,
    ) -> Result<
        (
            PostUpdateActions,
            Option<GroupId>,
            Option<ConversationMessage>,
        ),
        String,
    > {
        let processed_message: ProcessedMessage;
        let mut groups = self.groups.borrow_mut();

        let group = match groups.get_mut(str::from_utf8(message.group_id().as_slice()).unwrap()) {
            Some(g) => g,
            None => {
                log::error!(
                    "Error getting group {:?} for a message. Dropping message.",
                    message.group_id()
                );
                return Err("error".to_string());
            }
        };
        let mut mls_group = group.mls_group.borrow_mut();

        processed_message = match mls_group.process_message(&self.provider, message) {
            Ok(msg) => msg,
            Err(e) => {
                log::error!("Error processing unverified message: {e:?} -  Dropping message.");
                return Err("error".to_string());
            }
        };

        let processed_message_credential: Credential = processed_message.credential().clone();

        let message_out = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                let processed_message_credential =
                    BasicCredential::try_from(processed_message_credential.clone()).unwrap();
                let sender_name = match self.contacts.get(processed_message_credential.identity()) {
                    Some(c) => c.id.clone(),
                    None => {
                        // Contact list is not updated right now, get the identity from the
                        // mls_group member
                        let user_id = mls_group.members().find_map(|m| {
                                let m_credential = BasicCredential::try_from(m.credential.clone()).unwrap();
                                if m_credential.identity()
                                    == processed_message_credential.identity()
                                    && (self
                                        .identity
                                        .borrow()
                                        .credential_with_key
                                        .signature_key
                                        .as_slice()
                                        != m.signature_key.as_slice())
                                {
                                    log::debug!("update::Processing ApplicationMessage read sender name from credential identity for group {} ", group.group_name);
                                    Some(
                                        str::from_utf8(m_credential.identity()).unwrap().to_owned(),
                                    )
                                } else {
                                    None
                                }
                            });
                        user_id.unwrap_or("".to_owned()).as_bytes().to_vec()
                    }
                };
                let conversation_message = ConversationMessage::new(
                    String::from_utf8(application_message.into_bytes())
                        .unwrap()
                        .clone(),
                    String::from_utf8(sender_name).unwrap(),
                );
                group.conversation.add(conversation_message.clone());
                if group_name.is_none() || group_name.clone().unwrap() == group.group_name {
                    Some(conversation_message)
                } else {
                    None
                }
            }
            ProcessedMessageContent::ProposalMessage(_proposal_ptr) => {
                // intentionally left blank.
                None
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal_ptr) => {
                // intentionally left blank.
                None
            }
            ProcessedMessageContent::StagedCommitMessage(commit_ptr) => {
                let mut remove_proposal: bool = false;
                if commit_ptr.self_removed() {
                    remove_proposal = true;
                }
                match mls_group.merge_staged_commit(&self.provider, *commit_ptr) {
                    Ok(()) => {
                        if remove_proposal {
                            log::debug!(
                                "update::Processing StagedCommitMessage removing {} from group {} ",
                                self.user_name(),
                                group.group_name
                            );
                            return Ok((
                                PostUpdateActions::Remove,
                                Some(mls_group.group_id().clone()),
                                None,
                            ));
                        }
                    }
                    Err(e) => return Err(e.to_string()),
                }
                None
            }
        };
        Ok((PostUpdateActions::None, None, message_out))
    }

    /// Update the user. This involves:
    /// * retrieving all new messages from the server
    /// * update the contacts with all other clients known to the server
    pub fn update(
        &mut self,
        group_name: Option<String>,
    ) -> Result<Vec<ConversationMessage>, String> {
        log::debug!("Updating {} ...", self.user_name());

        let mut messages_out: Vec<ConversationMessage> = Vec::new();

        log::debug!("update::Processing messages for {} ", self.user_name());
        // Go through the list of messages and process or store them.
        for message in self.backend.recv_msgs(self)?.drain(..) {
            log::debug!("Reading message format {:#?} ...", message.wire_format());
            match message.extract() {
                MlsMessageBodyIn::Welcome(welcome) => {
                    // Join the group. (Later we should ask the user to
                    // approve first ...)
                    self.join_group(welcome)?;
                }
                MlsMessageBodyIn::PrivateMessage(message) => {
                    match self.process_protocol_message(group_name.clone(), message.into()) {
                        Ok((post_update_actions, group_id_option, message_out_option)) => {
                            if let Some(message_out) = message_out_option {
                                messages_out.push(message_out);
                            }
                            if post_update_actions == PostUpdateActions::Remove {
                                match group_id_option {
                                    Some(gid) => {
                                        let mut grps = self.groups.borrow_mut();
                                        grps.remove_entry(str::from_utf8(gid.as_slice()).unwrap());
                                        self.group_list
                                            .remove(str::from_utf8(gid.as_slice()).unwrap());
                                    }
                                    None => log::debug!(
                                        "update::Error post update remove must have a group id"
                                    ),
                                }
                            }
                        }
                        Err(_e) => {
                            continue;
                        }
                    };
                }
                MlsMessageBodyIn::PublicMessage(message) => {
                    if self
                        .process_protocol_message(group_name.clone(), message.into())
                        .is_err()
                    {
                        continue;
                    }
                }
                _ => panic!("Unsupported message type"),
            }
        }
        log::debug!("update::Processing messages done");

        self.update_clients();

        self.autosave();

        Ok(messages_out)
    }

    /// Create a group with the given name.
    pub fn create_group(&mut self, name: String) {
        log::debug!("{} creates group {}", self.user_name(), name);
        let group_id = name.as_bytes();

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let mls_group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.identity.borrow().signer,
            &group_config,
            GroupId::from_slice(group_id),
            self.identity.borrow().credential_with_key.clone(),
        )
        .expect("Failed to create MlsGroup");

        let group = Group {
            group_name: name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        if self.groups.borrow().contains_key(&name) {
            panic!("Group '{name}' existed already");
        }

        self.groups.borrow_mut().insert(name.clone(), group);
        self.group_list.insert(name);

        self.autosave();
    }

    /// Invite user with the given name to the group.
    pub fn invite(&mut self, name: String, group_name: String) -> Result<(), String> {
        // First we need to get the key package for {id} from the DS.
        let contact = match self.contacts.values().find(|c| c.user_name() == name) {
            Some(v) => v,
            None => return Err(format!("No contact with name {name} known.")),
        };

        // Reclaim a key package from the server
        let joiner_key_package = self.backend.consume_key_package(&contact.id).unwrap();

        // Build a proposal with this key package and do the MLS bits.
        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_name) {
            Some(g) => g,
            None => return Err(format!("No group with name {group_name} known.")),
        };

        let (out_messages, welcome, _group_info) = group
            .mls_group
            .borrow_mut()
            .add_members(
                &self.provider,
                &self.identity.borrow().signer,
                &[joiner_key_package.into()],
            )
            .map_err(|e| format!("Failed to add member to group - {e}"))?;

        /* First, send the MlsMessage commit to the group.
        This must be done before the member invitation is locally committed.
        It avoids the invited member to receive the commit message (which is in the previous group epoch).*/
        log::trace!("Sending commit");
        let group = groups.get_mut(&group_name).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);

        let msg = GroupMessage::new(out_messages.into(), &group_recipients);
        self.backend.send_msg(&msg)?;

        // Second, process the invitation on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        // Finally, send Welcome to the joiner.
        log::trace!("Sending welcome");
        self.backend
            .send_welcome(&welcome)
            .expect("Error sending Welcome message");

        drop(groups);

        self.autosave();

        Ok(())
    }

    /// Remove user with the given name from the group.
    pub fn remove(&mut self, name: String, group_name: String) -> Result<(), String> {
        // Get the group ID

        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_name) {
            Some(g) => g,
            None => return Err(format!("No group with name {group_name} known.")),
        };

        // Get the client leaf index

        let leaf_index = self.find_member_index(name, group)?;

        // Remove operation on the mls group
        let (remove_message, _welcome, _group_info) = group
            .mls_group
            .borrow_mut()
            .remove_members(
                &self.provider,
                &self.identity.borrow().signer,
                &[leaf_index],
            )
            .map_err(|e| format!("Failed to remove member from group - {e}"))?;

        // First, send the MlsMessage remove commit to the group.
        log::trace!("Sending commit");
        let group = groups.get_mut(&group_name).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);

        let msg = GroupMessage::new(remove_message.into(), &group_recipients);
        self.backend.send_msg(&msg)?;

        // Second, process the removal on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        drop(groups);

        self.autosave();

        Ok(())
    }

    /// Join a group with the provided welcome message.
    fn join_group(&mut self, welcome: Welcome) -> Result<(), String> {
        log::debug!("{} joining group ...", self.user_name());

        let mut ident = self.identity.borrow_mut();
        for secret in welcome.secrets().iter() {
            let key_package_hash = &secret.new_member();
            if ident.kp.contains_key(key_package_hash.as_slice()) {
                ident.kp.remove(key_package_hash.as_slice());
            }
        }
        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group =
            StagedWelcome::new_from_welcome(&self.provider, &group_config, welcome, None)
                .expect("Failed to create staged join")
                .into_group(&self.provider)
                .expect("Failed to create MlsGroup");

        let group_id = mls_group.group_id().to_vec();
        // XXX: Use Welcome's encrypted_group_info field to store group_name.
        let group_name = String::from_utf8(group_id.clone()).unwrap();

        let group = Group {
            group_name: group_name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        log::trace!("   {group_name}");

        match self.groups.borrow_mut().insert(group_name.clone(), group) {
            Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
            None => {
                self.group_list.insert(group_name);
                Ok(())
            }
        }
    }

    pub(crate) fn user_name(&self) -> String {
        self.identity.borrow().identity_as_string()
    }

    pub(super) fn set_auth_token(&mut self, token: AuthToken) {
        self.auth_token = Some(token);
    }

    pub(super) fn auth_token(&self) -> Option<&AuthToken> {
        self.auth_token.as_ref()
    }
}
