use openmls::extensions::{Extension, UnknownExtension};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// Custom Extension Type ID for the Admin List.
/// Assigned from the MLS Private Use range (0xFF00 - 0xFFFF).
pub const ADMIN_LIST_EXT_TYPE: u16 = 0xFF01;

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AdminListExtension {
    /// A list of credentials belonging to group administrators.
    pub admins: Vec<Credential>,
}

impl AdminListExtension {
    /// Creates a new instance of the admin list extension.
    pub fn new(admins: Vec<Credential>) -> Self {
        Self { admins }
    }

    /// Converts this custom extension into an OpenMLS `Extension` enum variant.
    pub fn to_extension(&self) -> Result<Extension, tls_codec::Error> {
        let mut extension_data = Vec::new();
        self.tls_serialize(&mut extension_data)?;

        Ok(Extension::Unknown(
            ADMIN_LIST_EXT_TYPE,
            UnknownExtension(extension_data),
        ))
    }

    /// Parses an AdminListExtension from an OpenMLS `Extension`.
    pub fn from_extension(extension: &Extension) -> Result<Self, tls_codec::Error> {
        match extension {
            Extension::Unknown(ext_type, unknown_ext) if *ext_type == ADMIN_LIST_EXT_TYPE => {
                let mut slice = unknown_ext.0.as_slice();
                Self::tls_deserialize(&mut slice)
            }
            Extension::Unknown(_, _) => Err(tls_codec::Error::DecodingError(
                "Extension type mismatch for AdminListExtension".to_string(),
            )),
            _ => Err(tls_codec::Error::DecodingError(
                "Expected Unknown extension variant for custom AdminListExtension".to_string(),
            )),
        }
    }

    /// Finds and parses an `AdminListExtension` from `Extensions<GroupContext>`.
    pub fn find_in_extensions(extensions: &Extensions<GroupContext>) -> Result<Self, String> {
        extensions
            .iter()
            .find_map(|ext| Self::from_extension(ext).ok())
            .ok_or_else(|| "Group context extension for admin list is missing".to_string())
    }
}
