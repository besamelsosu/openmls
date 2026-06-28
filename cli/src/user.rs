use std::borrow::Borrow;
use std::collections::HashSet;
use std::{
    cell::{Ref, RefCell},
    collections::HashMap,
    str,
};

use ds_lib::messages::AuthToken;
use ds_lib::{ClientKeyPackages, GroupMessage};
use openmls::prelude::{tls_codec::*, *};
use openmls_traits::OpenMlsProvider;

use crate::admin_list_gce::{AdminListExtension, ADMIN_LIST_EXT_TYPE};

use super::{
    backend::Backend, conversation::Conversation, conversation::ConversationMessage,
    identity::Identity, openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto,
    serialize_any_hashmap,
};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Contact {
    id: Vec<u8>,
}

impl Contact {
    pub fn username(&self) -> String {
        String::from_utf8(self.id.clone()).unwrap()
    }
}

pub struct Group {
    group_name: String,
    conversation: Conversation,
    mls_group: RefCell<MlsGroup>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct User {
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    pub(crate) contacts: HashMap<Vec<u8>, Contact>,
    #[serde(skip)]
    pub(crate) groups: RefCell<HashMap<String, Group>>,
    group_list: HashSet<String>,
    pub(crate) identity: RefCell<Identity>,
    #[serde(skip)]
    backend: Backend,
    #[serde(skip)]
    provider: OpenMlsRustPersistentCrypto,
    autosave_enabled: bool,
    auth_token: Option<AuthToken>,
}

#[derive(PartialEq)]
pub enum PostUpdateActions {
    None,
    Remove,
}

fn check_credential_is_admin(
    extensions: &Extensions<GroupContext>,
    credential: &Credential,
) -> Result<(), String> {
    let mut has_admin_list = false;
    for ext in extensions.iter() {
        if let Ok(admin_list) = AdminListExtension::from_extension(ext) {
            has_admin_list = true;
            if admin_list.admins.contains(credential) {
                return Ok(());
            }
            break;
        }
    }
    if !has_admin_list {
        Err("Group context extension for admin list is missing".to_string())
    } else {
        Err("Sender is not in the admin list".to_string())
    }
}

impl User {
    /// Create a new user with the given name and a fresh set of credentials.
    pub fn new(username: String) -> Result<Self, String> {
        let crypto = OpenMlsRustPersistentCrypto::new(&username)?;
        let out = Self {
            groups: RefCell::new(HashMap::new()),
            group_list: HashSet::new(),
            contacts: HashMap::new(),
            identity: RefCell::new(Identity::new(CIPHERSUITE, &crypto, username.as_bytes())),
            backend: Backend::default(),
            provider: crypto,
            autosave_enabled: false,
            auth_token: None,
        };
        out.persist_metadata()?;
        Ok(out)
    }

    fn metadata_key(user_name: &str, field: &str) -> Vec<u8> {
        format!("user:{}:{}", user_name, field).into_bytes()
    }

    fn persist_metadata(&self) -> Result<(), String> {
        let user_name = self.username();

        // Convert HashMap<Vec<u8>, Contact> to Vec<(Vec<u8>, Contact)> for JSON serialization
        let contacts_vec: Vec<(Vec<u8>, Contact)> = self
            .contacts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let contacts_json = serde_json::to_string(&contacts_vec).map_err(|e| e.to_string())?;
        let group_list_json = serde_json::to_string(&self.group_list).map_err(|e| e.to_string())?;
        let auth_token_json = serde_json::to_string(&self.auth_token).map_err(|e| e.to_string())?;
        let identity_json =
            serde_json::to_string(&*self.identity.borrow()).map_err(|e| e.to_string())?;

        self.provider
            .write_value(
                Self::metadata_key(&user_name, "contacts"),
                contacts_json.into_bytes(),
            )
            .map_err(|e| e.to_string())?;
        self.provider
            .write_value(
                Self::metadata_key(&user_name, "group_list"),
                group_list_json.into_bytes(),
            )
            .map_err(|e| e.to_string())?;
        self.provider
            .write_value(
                Self::metadata_key(&user_name, "auth_token"),
                auth_token_json.into_bytes(),
            )
            .map_err(|e| e.to_string())?;
        self.provider
            .write_value(
                Self::metadata_key(&user_name, "identity"),
                identity_json.into_bytes(),
            )
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn load_metadata(
        user_name: &str,
        provider: &OpenMlsRustPersistentCrypto,
    ) -> Result<
        (
            HashMap<Vec<u8>, Contact>,
            HashSet<String>,
            Option<AuthToken>,
            Option<Identity>,
        ),
        String,
    > {
        let contacts_bytes = provider
            .read_value(Self::metadata_key(user_name, "contacts"))
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let group_list_bytes = provider
            .read_value(Self::metadata_key(user_name, "group_list"))
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let auth_token_bytes = provider
            .read_value(Self::metadata_key(user_name, "auth_token"))
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        let identity_bytes = provider
            .read_value(Self::metadata_key(user_name, "identity"))
            .map_err(|e| e.to_string())?
            .unwrap_or_default();

        let contacts: HashMap<Vec<u8>, Contact> = if contacts_bytes.is_empty() {
            HashMap::new()
        } else {
            let contacts_vec: Vec<(Vec<u8>, Contact)> =
                serde_json::from_slice(&contacts_bytes).map_err(|e| e.to_string())?;
            contacts_vec.into_iter().collect()
        };
        let group_list: HashSet<String> = if group_list_bytes.is_empty() {
            HashSet::new()
        } else {
            serde_json::from_slice(&group_list_bytes).map_err(|e| e.to_string())?
        };
        let auth_token: Option<AuthToken> = if auth_token_bytes.is_empty() {
            None
        } else {
            serde_json::from_slice(&auth_token_bytes).map_err(|e| e.to_string())?
        };
        let identity: Option<Identity> = if identity_bytes.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&identity_bytes).map_err(|e| e.to_string())?)
        };

        Ok((contacts, group_list, auth_token, identity))
    }

    pub fn load(user_name: String) -> Result<Self, String> {
        let provider = OpenMlsRustPersistentCrypto::new(&user_name)?;
        let (contacts, group_list, auth_token, identity) =
            Self::load_metadata(&user_name, &provider)?;

        let identity = match identity {
            Some(id) => id,
            None => return Err(format!("No saved identity found for user {}", user_name)),
        };

        let mut user = Self {
            groups: RefCell::new(HashMap::new()),
            group_list,
            contacts,
            identity: RefCell::new(identity),
            backend: Backend::default(),
            provider,
            autosave_enabled: false,
            auth_token,
        };

        let groups = user.groups.get_mut();
        for group_name in &user.group_list {
            let mlsgroup = MlsGroup::load(
                user.provider.storage(),
                &GroupId::from_slice(group_name.as_bytes()),
            );
            let grp = Group {
                mls_group: RefCell::new(mlsgroup.unwrap().unwrap()),
                group_name: group_name.clone(),
                conversation: Conversation::default(),
            };
            groups.insert(group_name.clone(), grp);
        }

        Ok(user)
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

    fn group(&self, group_name: &str) -> Result<Ref<'_, Group>, String> {
        let groups = self.groups.borrow();
        Ref::filter_map(groups, |groups| groups.get(group_name))
            .map_err(|_| format!("No group with name {group_name} known."))
    }

    pub fn group_names(&self) -> Vec<String> {
        let mut group_names: Vec<String> = self.group_list.iter().cloned().collect();
        group_names.sort();
        group_names
    }

    pub fn contact_names(&self) -> Vec<String> {
        let mut contact_names: Vec<String> = self
            .contacts
            .values()
            .map(|contact| contact.username())
            .collect();
        contact_names.sort();
        contact_names
    }

    pub fn group_member_names(&self, group_name: &str) -> Result<Vec<String>, String> {
        let group = self.group(group_name)?;
        let mls_group = group.mls_group.borrow();
        let mut member_names = Vec::new();
        for member in mls_group.members() {
            let credential = BasicCredential::try_from(member.credential).unwrap();
            member_names.push(String::from_utf8(credential.identity().to_vec()).unwrap());
        }
        member_names.sort();
        Ok(member_names)
    }

    pub fn group_message_count(&self, group_name: &str) -> Result<usize, String> {
        let group = self.group(group_name)?;
        Ok(group
            .conversation
            .get(usize::MAX)
            .map_or(0, |messages| messages.len()))
    }

    pub fn register(&mut self) -> Result<(), String> {
        match self.backend.register_client(self.key_packages()) {
            Ok(token) => {
                log::debug!("Created new user: {:?}", self.username());
                self.set_auth_token(token);
                self.persist_metadata()
            }
            Err(e) => {
                log::error!("Error creating user: {e:?}");
                Err(format!("Error creating user: {e:?}"))
            }
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
        for contact_id in self.contacts.borrow().keys() {
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
                let has_add_or_remove = commit_ptr.add_proposals().next().is_some()
                    || commit_ptr.remove_proposals().next().is_some();
                if has_add_or_remove {
                    check_credential_is_admin(
                        mls_group.extensions(),
                        &processed_message_credential,
                    )
                    .map_err(|e| format!("Authorization error: {e}"))?;
                }

                let mut remove_proposal: bool = false;
                if commit_ptr.self_removed() {
                    remove_proposal = true;
                }
                match mls_group.merge_staged_commit(&self.provider, *commit_ptr) {
                    Ok(()) => {
                        if remove_proposal {
                            log::debug!(
                                "update::Processing StagedCommitMessage removing {} from group {} ",
                                self.username(),
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
        log::debug!("Updating {} ...", self.username());

        let mut messages_out: Vec<ConversationMessage> = Vec::new();

        log::debug!("update::Processing messages for {} ", self.username());
        // Go through the list of messages and process or store them.
        for message in self.backend.recv_msgs(self)?.drain(..) {
            log::debug!("Reading message format {:#?} ...", message.wire_format());
            match message.extract() {
                MlsMessageBodyIn::Welcome(welcome) => {
                    if let Err(e) = self.join_group(welcome) {
                        log::error!("Error joining group: {e}");
                        continue;
                    }
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
                        Err(e) => {
                            log::error!("Error processing private message: {e}");
                            continue;
                        }
                    };
                }
                MlsMessageBodyIn::PublicMessage(message) => {
                    if let Err(e) =
                        self.process_protocol_message(group_name.clone(), message.into())
                    {
                        log::error!("Error processing public message: {e}");
                        continue;
                    }
                }
                _ => panic!("Unsupported message type"),
            }
        }
        log::debug!("update::Processing messages done");

        self.update_clients();

        self.persist_metadata()?;

        Ok(messages_out)
    }

    /// Create a group with the given name.
    pub fn create_group(&mut self, name: String) -> Result<(), String> {
        log::debug!("{} creates group {}", self.username(), name);
        let group_id = name.as_bytes();

        let creator_credential = self
            .identity
            .borrow()
            .credential_with_key
            .credential
            .clone();

        let admin_ext = crate::admin_list_gce::AdminListExtension::new(vec![creator_credential]);
        let openmls_ext = admin_ext.to_extension().map_err(|e| e.to_string())?;

        let extensions = openmls::extensions::Extensions::single(openmls_ext)
            .map_err(|e| format!("Invalid extension configuration: {:?}", e))?;

        let capabilities = Capabilities::builder()
            .extensions(vec![ExtensionType::Unknown(ADMIN_LIST_EXT_TYPE)])
            .build();

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(extensions) // Inject the unpacked extensions collection
            .capabilities(capabilities)
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
        self.persist_metadata()?;
        Ok(())
    }

    /// Invite user with the given name to the group.
    pub fn invite(&mut self, name: String, group_name: String) -> Result<(), String> {
        // First we need to get the key package for {id} from the DS.
        let contact = match self.contacts.values().find(|c| c.username() == name) {
            Some(v) => v,
            None => return Err(format!("No contact with name {name} known.")),
        };

        // Reclaim a key package from the server
        let joiner_key_package = self
            .backend
            .consume_key_package(&contact.id)
            .map_err(|e| format!("Failed to reclaim key package from server: {e}"))?;

        // Build a proposal with this key package and do the MLS bits.
        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_name) {
            Some(g) => g,
            None => return Err(format!("No group with name {group_name} known.")),
        };

        // Check authorization
        {
            let mls_group = group.mls_group.borrow();
            let self_credential = &self.identity.borrow().credential_with_key.credential;
            check_credential_is_admin(mls_group.extensions(), self_credential)
                .map_err(|e| format!("Authorization error: {e}"))?;
        }

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

        self.persist_metadata()?;

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

        // Check authorization
        {
            let mls_group = group.mls_group.borrow();
            let self_credential = &self.identity.borrow().credential_with_key.credential;
            check_credential_is_admin(mls_group.extensions(), self_credential)
                .map_err(|e| format!("Authorization error: {e}"))?;
        }

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

        self.persist_metadata()?;

        Ok(())
    }

    /// Join a group with the provided welcome message.
    fn join_group(&mut self, welcome: Welcome) -> Result<(), String> {
        log::debug!("{} joining group ...", self.username());

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
        let staged_welcome =
            StagedWelcome::new_from_welcome(&self.provider, &group_config, welcome, None)
                .map_err(|e| format!("Failed to create staged join: {:?}", e))?;

        let welcome_sender_leaf = staged_welcome.welcome_sender().map_err(|e| e.to_string())?;
        let welcome_sender_credential = welcome_sender_leaf.credential();

        check_credential_is_admin(
            staged_welcome.group_context().extensions(),
            welcome_sender_credential,
        )
        .map_err(|e| format!("Authorization error: {e}"))?;

        let mls_group = staged_welcome
            .into_group(&self.provider)
            .map_err(|e| format!("Failed to convert to MlsGroup: {:?}", e))?;

        let group_id = mls_group.group_id().to_vec();
        // XXX: Use Welcome's encrypted_group_info field to store group_name.
        let group_name = String::from_utf8(group_id.clone()).unwrap();

        let group = Group {
            group_name: group_name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        log::trace!("   {group_name}");

        self.group_list.insert(group_name.clone());

        match self.groups.borrow_mut().insert(group_name, group) {
            Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
            None => Ok(()),
        }
    }

    pub(crate) fn username(&self) -> String {
        self.identity.borrow().identity_as_string()
    }

    pub(super) fn set_auth_token(&mut self, token: AuthToken) {
        self.auth_token = Some(token);
    }

    pub(super) fn auth_token(&self) -> Option<&AuthToken> {
        self.auth_token.as_ref()
    }
}
