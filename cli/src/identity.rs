use std::collections::HashMap;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::admin_list_gce::ADMIN_LIST_EXT_TYPE;
use crate::user::KEY_PACKAGE_LIFETIME_SECONDS;

use super::{openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto, serialize_any_hashmap};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Identity {
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    pub(crate) kp: HashMap<Vec<u8>, KeyPackage>,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
}

impl Identity {
    fn build_key_package(
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
        signer: &SignatureKeyPair,
        credential_with_key: &CredentialWithKey,
    ) -> KeyPackageBundle {
        let capabilities = Capabilities::builder()
            .extensions(vec![ExtensionType::Unknown(ADMIN_LIST_EXT_TYPE)])
            .build();

        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECONDS))
            .build(ciphersuite, crypto, signer, credential_with_key.clone())
            .unwrap()
    }

    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
        username: &[u8],
    ) -> Self {
        let credential = BasicCredential::new(username.to_vec());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };
        signature_keys.store(crypto.storage()).unwrap();

        let key_package =
            Self::build_key_package(ciphersuite, crypto, &signature_keys, &credential_with_key);

        let hash_ref = key_package
            .key_package()
            .hash_ref(crypto.crypto())
            .unwrap()
            .as_slice()
            .to_vec();

        Self {
            kp: HashMap::from([(hash_ref, key_package.key_package().clone())]),
            credential_with_key,
            signer: signature_keys,
        }
    }

    /// Create an additional key package using the credential_with_key/signer bound to this identity
    pub fn add_key_package(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
    ) -> KeyPackage {
        let key_package =
            Self::build_key_package(ciphersuite, crypto, &self.signer, &self.credential_with_key);

        let hash_ref = key_package
            .key_package()
            .hash_ref(crypto.crypto())
            .unwrap()
            .as_slice()
            .to_vec();

        self.kp.insert(hash_ref, key_package.key_package().clone());
        key_package.key_package().clone()
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential_with_key.credential.serialized_content()
    }

    /// Get the plain identity as string.
    pub fn identity_as_string(&self) -> String {
        String::from_utf8_lossy(self.identity()).to_string()
    }
}
