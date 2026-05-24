//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsProvider`] trait to use with
//! OpenMLS.

use std::{env, path::PathBuf};

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use std::sync::Arc;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Arc<Connection>>,
    connection: Arc<Connection>,
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Arc<Connection>>;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

impl Default for OpenMlsRustPersistentCrypto {
    fn default() -> Self {
        let mut connection = Connection::open_in_memory().expect("sqlite connection failed");
        {
            let mut storage: SqliteStorageProvider<JsonCodec, &mut Connection> =
                SqliteStorageProvider::new(&mut connection);
            storage.run_migrations().expect("sqlite migrations failed");
        }

        let connection = Arc::new(connection);
        let storage = SqliteStorageProvider::new(connection.clone());

        Self {
            crypto: RustCrypto::default(),
            storage,
            connection,
        }
    }
}

impl OpenMlsRustPersistentCrypto {
    fn db_path(user_name: &str) -> PathBuf {
        env::temp_dir()
            .join("openmls")
            .join(format!("cli_{}.db", user_name))
    }

    pub fn new(user_name: &str) -> Result<Self, String> {
        let db_path = Self::db_path(user_name);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut connection = Connection::open(db_path).map_err(|e| e.to_string())?;

        {
            let mut storage: SqliteStorageProvider<JsonCodec, &mut Connection> =
                SqliteStorageProvider::new(&mut connection);
            storage.run_migrations().map_err(|e| e.to_string())?;
        }

        // Ensure metadata table exists
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS openmls_metadata (key BLOB PRIMARY KEY, value BLOB)",
                [],
            )
            .map_err(|e| e.to_string())?;

        let connection = Arc::new(connection);
        let storage = SqliteStorageProvider::new(connection.clone());

        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
            connection,
        })
    }

    pub fn write_value(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO openmls_metadata (key, value) VALUES (?1, ?2)",
                rusqlite::params![&key, &value],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn read_value(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let mut stmt = self
            .connection
            .prepare("SELECT value FROM openmls_metadata WHERE key = ?1")
            .map_err(|e| e.to_string())?;
        let result = stmt
            .query_row(rusqlite::params![&key], |row| row.get::<usize, Vec<u8>>(0))
            .optional()
            .map_err(|e| e.to_string())?;
        Ok(result)
    }
}
