//! # OpenMLS SQLite Storage Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS, backed by SQLite for persistent storage.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::Serialize;
use std::cell::RefCell;
use std::path::PathBuf;

/// JSON codec for SQLite storage
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    /// Storage provider backed by SQLite, wrapped in RefCell for interior mutability
    storage: RefCell<SqliteStorageProvider<JsonCodec, Connection>>,
    /// Database path for reference
    db_path: PathBuf,
}

impl OpenMlsRustPersistentCrypto {
    /// Create a new instance with the given database path.
    /// If the database doesn't exist, it will be created.
    pub fn new(db_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let connection = Connection::open(&db_path)?;
        let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);

        // Run migrations to initialize the database schema
        storage.run_migrations()?;

        Ok(Self {
            crypto: RustCrypto::default(),
            storage: RefCell::new(storage),
            db_path,
        })
    }

    /// Get the database path
    pub fn db_path(&self) -> &PathBuf {
        &self.db_path
    }
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        // SafeBorrow allows us to provide a reference to the storage provider
        // without exposing the RefCell's borrow_mut capability through this interface
        unsafe {
            // SAFETY: The RefCell is never borrowed mutably through the OpenMlsProvider interface,
            // and the underlying storage is only accessed through read-only operations.
            // The borrow_mut() is only called in User::save() where we have exclusive access.
            &*(self.storage.as_ptr() as *const SqliteStorageProvider<JsonCodec, Connection>)
        }
    }
}
