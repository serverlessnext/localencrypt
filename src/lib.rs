pub(crate) mod common;
pub(crate) mod crypto;
pub(crate) mod storage;
pub(crate) mod utils;
mod user;
mod configurations;

use std::collections::HashMap;
use wasm_bindgen::prelude::*;

pub use common::{ObjectKey, SecureStringError, SecureStringResult};
pub use configurations::LocalStorage;
use storage::SecureStorage;


#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct LocalEncryptJs {
    local_encrypt: LocalEncrypt,
}

#[wasm_bindgen]
impl LocalEncryptJs {
    pub fn new(username: String, password: String) -> js_sys::Promise {
        _ = console_log::init_with_level(log::Level::Debug);
        let future = async move {

            let storage_backend = StorageBackend::initiate_with_local_storage(&username, Some(&password)).await?;
            let local_encrypt = LocalEncrypt::builder()
                .with_backend(storage_backend)
                .build();

            log::debug!("LocalEncryptJs::new: {:?}", local_encrypt);
            Ok(JsValue::from_str("Initialized"))
        };
        wasm_bindgen_futures::future_to_promise(future)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct ItemMetaData {
    id: String,
    tags: Option<HashMap<String, String>>,
}

impl ItemMetaData {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            tags: None,
        }
    }

    pub fn new_with_tags(id: &str, tags: HashMap<String, String>) -> Self {
        Self {
            id: id.to_string(),
            tags: Some(tags),
        }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn tags(&self) -> Option<HashMap<String, String>> {
        self.tags.clone()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum BrowserStorage {
    LocalStorage(LocalStorage),
}


#[derive(Clone, PartialEq, Debug)]
pub enum StorageBackend {
    Browser(BrowserStorage),
    Memory,
}

impl BrowserStorage {
    pub fn local_storage(&self) -> Option<LocalStorage> {
        match self {
            BrowserStorage::LocalStorage(local_storage) => Some(local_storage.clone()),
        }
    }
}


impl StorageBackend {
    pub async fn initiate_with_local_storage(username: &str, password: Option<&str>) -> SecureStringResult<Self> {
        let local_storage = match password {
            Some(password) => {
                LocalStorage::initiate_with_password(username, password).await?
            }
            None => {
                LocalStorage::initiate_with_no_password(username).await?
            },
        };

        Ok(Self::Browser(BrowserStorage::LocalStorage(local_storage)))
    }


    pub async fn hard_reset(&self) -> SecureStringResult<()> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                local_storage.hard_reset().await
            },
            _ => Err(SecureStringError::Unimplemented),
        }
    }

    pub async fn validate_password(&self) -> SecureStringResult<bool> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                local_storage.validate_password().await
            },
            _ => Err(SecureStringError::Unimplemented),
        }
    }

    pub async fn change_password(&self, old_password: &str, new_password: &str) -> SecureStringResult<()> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                local_storage.change_password(old_password, new_password).await
            },
            _ => Err(SecureStringError::Unimplemented),
        }
    }

}

#[derive(Clone, PartialEq, Debug)]
pub struct LocalEncrypt {
    backend: StorageBackend,
}


impl LocalEncrypt {
    pub fn builder() -> LocalEncryptBuilder {
        LocalEncryptBuilder::new()
    }

    pub fn new() -> Self {
        Self {
            backend: StorageBackend::Memory,
        }
    }

    pub fn backend(&self) -> &StorageBackend {
        &self.backend
    }
}


pub struct LocalEncryptBuilder {
    backend: StorageBackend,
}

impl LocalEncryptBuilder {
    pub fn new() -> Self {
        Self {
            backend: StorageBackend::Memory,
        }
    }

    pub fn with_backend(mut self, backend: StorageBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn build(self) -> LocalEncrypt {
        LocalEncrypt {
            backend: self.backend,
        }
    }
}


#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;
    use crate::common::Credentials;

    wasm_bindgen_test_configure!(run_in_browser);


    #[wasm_bindgen_test]
    async fn test_builder_memory_backend() {
        // Using builder to set up LocalEncrypt with memory backend
        let local_encrypt = LocalEncrypt::builder().build();
        match local_encrypt.backend() {
            StorageBackend::Memory => {}, // expected case
            _ => panic!("Invalid backend"),
        };
    }

    #[wasm_bindgen_test]
    async fn test_builder_local_storage_backend() {
        // Using builder to set up LocalEncrypt with localStorage backend
        let username = "username";
        let password = "password";
        let credentials = Credentials::new(username, password);
        let local_storage = LocalStorage::new(credentials).await.expect("Failed to create local storage backend");
        let local_encrypt = LocalEncrypt::builder().with_backend(StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage))).build();

        match local_encrypt.backend() {
            StorageBackend::Browser(BrowserStorage::LocalStorage(_)) => {}, // expected case
            _ => panic!("Invalid backend"),
        };
    }

    #[wasm_bindgen_test]
    async fn test_new_memory_backend() {
        // Using new method to set up LocalEncrypt with memory backend
        let local_encrypt = LocalEncrypt::new();
        match local_encrypt.backend() {
            StorageBackend::Memory => {}, // expected case
            _ => panic!("Invalid backend"),
        };
    }

    #[wasm_bindgen_test]
    async fn test_local_encrypt_equality() {
        let local_encrypt1 = LocalEncrypt::new();
        let local_encrypt2 = LocalEncrypt::new();
        assert_eq!(local_encrypt1, local_encrypt2);

        let credentials = Credentials::new("username", "password");
        let local_storage = LocalStorage::new(credentials).await.expect("Failed to create local storage backend");
        let local_encrypt3 = LocalEncrypt::builder().with_backend(StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage))).build();
        assert_ne!(local_encrypt1, local_encrypt3);
    }

    #[wasm_bindgen_test]
    async fn test_credentials_new() {
        let username = "username";
        let password = "password";
        let credentials = Credentials::new(username, password);
        assert_eq!(credentials.username(), username);
        assert_eq!(credentials.password(), password);
    }

    #[wasm_bindgen_test]
    async fn test_credentials_debug() {
        let username = "username";
        let password = "secretpassword";
        let credentials = Credentials::new(username, password);
        let debug_str = format!("{:?}", credentials);
        assert!(debug_str.contains("username"));
        assert!(debug_str.contains("********"));
        assert!(!debug_str.contains(password));
    }

    #[wasm_bindgen_test]
    async fn test_initiate_with_local_storage() {
        // Case with password
        let username = "username";
        let password = "password";
        let result = StorageBackend::initiate_with_local_storage(username, Some(password)).await;
        assert!(result.is_ok());

        // Case without password
        let username = "username";
        let result = StorageBackend::initiate_with_local_storage(username, None).await;
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    async fn test_hard_reset() {
        // Case with Browser backend
        let username = "username";
        let password = "password";
        let backend = StorageBackend::initiate_with_local_storage(username, Some(password)).await.expect("Failed to initiate local storage backend");
        let result = backend.hard_reset().await;
        assert!(result.is_ok());

        // Case with Memory backend
        let backend = StorageBackend::Memory;
        let result = backend.hard_reset().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SecureStringError::Unimplemented);
    }


}
