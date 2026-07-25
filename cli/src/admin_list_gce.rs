use openmls::extensions::{Extension, UnknownExtension};
use openmls::prelude::Credential;
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use openmls::prelude::*;

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

        // FIX: Pass the raw `Vec<u8>` directly into `UnknownExtension`.
        // No intermediate `VLBytes` casting required!
        Ok(Extension::Unknown(
            ADMIN_LIST_EXT_TYPE,
            UnknownExtension(extension_data),
        ))
    }

    /// Parses an AdminListExtension from an OpenMLS `Extension`.
    pub fn from_extension(extension: &Extension) -> Result<Self, tls_codec::Error> {
        match extension {
            Extension::Unknown(ext_type, unknown_ext) => {
                if *ext_type == ADMIN_LIST_EXT_TYPE {
                    // Since `unknown_ext.0` is a raw `Vec<u8>`, `.as_slice()`
                    // cleanly gives us the `&[u8]` required for the deserializer.
                    let mut slice = unknown_ext.0.as_slice();
                    Self::tls_deserialize(&mut slice)
                } else {
                    Err(tls_codec::Error::DecodingError(
                        "Extension type mismatch for AdminListExtension".to_string(),
                    ))
                }
            }
            _ => Err(tls_codec::Error::DecodingError(
                "Expected Unknown extension variant for custom AdminListExtension".to_string(),
            )),
        }
    }

    /// Finds and parses an `AdminListExtension` from `Extensions<GroupContext>`.
    pub fn find_in_extensions(extensions: &Extensions<GroupContext>) -> Result<Self, String> {
        for ext in extensions.iter() {
            if let Ok(admin_list) = Self::from_extension(ext) {
                return Ok(admin_list);
            }
        }
        Err("Group context extension for admin list is missing".to_string())
    }
}
