//! # OpenMLS Delivery Service Library
//!
//! This library provides structs and necessary implementations to interact with
//! the OpenMLS DS.
//!
//! The delivery service stores clients internally as `ClientInfo` values.

pub mod messages;

use std::collections::HashSet;

use messages::AuthToken;
use openmls::prelude::tls_codec::*;
use openmls::prelude::*;

/// Internal delivery-service state for a client.
#[derive(Debug)]
pub struct ClientInfo {
    pub id: Vec<u8>,
    pub key_packages: ClientKeyPackages,
    /// map of reserved key_packages [group_id, key_package_hash]
    pub reserved_key_pkg_hash: HashSet<Vec<u8>>,
    pub msgs: Vec<MlsMessageIn>,
    pub welcome_queue: Vec<MlsMessageIn>,
    pub auth_token: AuthToken,
}

/// The DS returns a list of key packages for a client as `ClientKeyPackages`.
/// This is a tuple struct holding a vector of `(Vec<u8>, KeyPackage)` tuples,
/// where the first value is the key package hash (output of `KeyPackage::hash`)
/// and the second value is the corresponding key package.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ClientKeyPackages(pub TlsVecU32<(TlsByteVecU8, KeyPackageIn)>);

impl ClientInfo {
    /// Create a new `ClientInfo` struct for a given client name and vector of
    /// key packages with corresponding hashes.
    pub fn new(mut key_packages: Vec<(Vec<u8>, KeyPackageIn)>) -> Self {
        let key_package: KeyPackage = KeyPackage::from(key_packages[0].1.clone());
        let id = key_package.leaf_node().credential().serialized_content();
        Self {
            id: id.into(),
            key_packages: ClientKeyPackages(
                key_packages
                    .drain(..)
                    .map(|(e1, e2)| (e1.into(), e2))
                    .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                    .into(),
            ),
            reserved_key_pkg_hash: HashSet::new(),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
            auth_token: AuthToken::random(),
        }
    }

    /// Acquire a key package from the client's key packages
    /// Mark the key package hash ref as "reserved key package"
    /// The reserved hash ref will be used in DS::send_welcome and removed once welcome is distributed
    pub fn consume_kp(&mut self) -> Result<KeyPackageIn, String> {
        match self.key_packages.0.pop() {
            Some(c) => {
                self.reserved_key_pkg_hash.insert(c.0.into_vec());
                Ok(c.1)
            }
            None => Err("No more keypackage available".to_string()),
        }
    }
}

/// An core group message.
/// This is an `MLSMessage` plus the list of recipients as a vector of client
/// names.
#[derive(Debug)]
pub struct GroupMessage {
    pub msg: MlsMessageIn,
    pub recipients: TlsVecU32<TlsByteVecU32>,
}

impl GroupMessage {
    /// Create a new `GroupMessage` taking an `MlsMessageIn` and slice of
    /// recipient names.
    pub fn new(msg: MlsMessageIn, recipients: &[Vec<u8>]) -> Self {
        Self {
            msg,
            recipients: recipients
                .iter()
                .map(|r| r.clone().into())
                .collect::<Vec<TlsByteVecU32>>()
                .into(),
        }
    }
}

impl tls_codec::Size for GroupMessage {
    fn tls_serialized_len(&self) -> usize {
        self.msg.tls_serialized_len() + self.recipients.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.msg.tls_serialize(writer)?;
        self.recipients.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for GroupMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let msg = MlsMessageIn::tls_deserialize(bytes)?;
        let recipients = TlsVecU32::<TlsByteVecU32>::tls_deserialize(bytes)?;
        Ok(Self { msg, recipients })
    }
}
