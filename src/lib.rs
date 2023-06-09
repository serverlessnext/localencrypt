pub(crate) mod common;
pub(crate) mod crypto;
pub(crate) mod storage;
pub(crate) mod utils;
mod user;
mod configurations;

use std::collections::HashMap;
use wasm_bindgen::prelude::*;

pub use common::{ObjectKey, SecureStringError, SecureStringResult};
pub use configurations::DocumentStore;
use storage::SecureStorage;
use user::User;

#[derive(Clone, PartialEq, Debug)]
pub struct DocumentMetaData {
    id: String,
    tags: Option<HashMap<String, String>>,
}

impl DocumentMetaData {
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
pub enum StorageBackend {
    DocumentStore(DocumentStore),
    Memory,
}


#[derive(Clone, PartialEq)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

use std::fmt::{Debug, Formatter};
impl Debug for Credentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"********")
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct LocalEncrypt {
    credentials: Credentials,
    backend: StorageBackend,
}


impl LocalEncrypt {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            credentials: Credentials::new(username, password),
            backend: StorageBackend::Memory,
        }
    }

    pub fn backend(&self) -> &StorageBackend {
        &self.backend
    }

    pub async fn new_with_document_store(username: &str, password: &str) -> SecureStringResult<Self> {
        let credentials = Credentials::new(username, password);
        let document_store = DocumentStore::new(&credentials).await?;
        Ok (Self {
            credentials,
            backend: StorageBackend::DocumentStore(document_store),
        })
    }

    pub async fn user_exists(username: &str) -> bool {
        User::exists(username).await
    }

    pub async fn validate_password(
        &self,
    ) -> Result<bool, SecureStringError> {
        User::validate_password(&self.credentials.username, &self.credentials.password).await
    }

    pub async fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> SecureStringResult<()> {
        let username = self.credentials.username.as_str();
        User::change_password(username, old_password, new_password).await
    }

    pub async fn reset(&self) -> SecureStringResult<()> {
        let username = self.credentials.username.as_str();
        User::reset(username).await
    }

}

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
            let le = LocalEncrypt::new_with_document_store(&username, &password).await;
            log::debug!("LocalEncryptJs::new: {:?}", le);
            Ok(JsValue::from_str("Initialized"))
        };
        wasm_bindgen_futures::future_to_promise(future)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);


    #[wasm_bindgen_test]
    async fn test_create_or_validate() {
        let username = "test_string_vault_create_or_validate";
        let password = "password_for_create_or_validate";

        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        local_encrypt.unwrap().reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_change_password() {
        let username = "test_string_vault_change_password";
        let old_password = "password_for_change_password";
        let new_password = "new_password_for_change_password";

        let local_encrypt = LocalEncrypt::new(username, old_password);
        let change_password_result =
            local_encrypt.change_password(old_password, new_password).await;
        assert!(change_password_result.is_ok(), "Failed to change password");

        local_encrypt.reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_user_exists() {
        let username = "test_string_vault_exists";
        let password = "password_for_exists";

        // Assert Vault doesn't exist initially
        assert_eq!(LocalEncrypt::user_exists(username).await, false);

        // Create the Vault
        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        let local_encrypt = local_encrypt.unwrap();

        // Assert Vault now exists
        assert_eq!(LocalEncrypt::user_exists(username).await, true);

        // Reset the Vault
        local_encrypt.reset().await.unwrap();

        // Assert Vault doesn't exist now
        assert_eq!(LocalEncrypt::user_exists(username).await, false);
        local_encrypt.reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_validate_password() {
        let username = "test_string_vault_validate_password";
        let password = "password_for_validate_password";

        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        let local_encrypt = local_encrypt.unwrap();
        let validate_password_result = local_encrypt.validate_password().await;
        assert!(
            validate_password_result.is_ok() && validate_password_result.unwrap(),
            "Failed to validate password"
        );
        local_encrypt.reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_list_configurations() {
        let username = "test_string_vault_list_configurations";
        let password = "password_for_list";

        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        let local_encrypt = local_encrypt.unwrap();
        let backend = local_encrypt.backend();

        let mut document_store = match backend {
            StorageBackend::DocumentStore(document_store) => document_store,
            _ => panic!("Invalid backend"),
        }.clone();

        let mut config = HashMap::new();
        config.insert("some random value".to_string(), "test_config".to_string());

        // ensure unique id
        let form_id = format!("{}-{}", username, password);
        let meta_data = DocumentMetaData::new(&form_id);

        let config_bytes = serde_json::to_vec(&config).unwrap();
        let save_result = document_store.save(meta_data, &config_bytes).await;
        assert!(
            save_result.is_ok(),
            "Failed to save secure configuration: {:?}",
            save_result.err().unwrap()
        );

        let list_result = document_store.list().await;
        assert!(
            list_result.is_ok(),
            "Failed to list configurations: {:?}",
            list_result.err().unwrap()
        );

        let listed_configurations = list_result.unwrap();
        assert!(listed_configurations
            .iter()
            .any(|form_data| form_data.id() == form_id));
        local_encrypt.reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_add_and_delete_configuration() {
        let username = "test_string_vault_add_delete";
        let password = "password_for_add_delete";

        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        let local_encrypt = local_encrypt.unwrap();
        let backend = local_encrypt.backend();

        let mut document_store = match backend {
            StorageBackend::DocumentStore(document_store) => document_store,
            _ => panic!("Invalid backend"),
        }.clone();

        // ensure unique id
        let form_id = format!("{}-{}", username, password);

        let meta_data = DocumentMetaData::new(&form_id);

        // Add a configuration with a given name
        let add_result = document_store.add(meta_data).await;
        assert!(
            add_result.is_ok(),
            "Failed to add configuration: {:?}",
            add_result.err().unwrap()
        );

        // Delete the configuration
        let delete_result = document_store.delete(&form_id).await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete configuration: {:?}",
            delete_result.err().unwrap()
        );

        // Try to delete again, it should fail since the configuration no longer exists
        let delete_again_result = document_store.delete(&form_id).await;
        assert!(
            delete_again_result.is_err(),
            "Successfully deleted non-existent configuration"
        );
        local_encrypt.reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_save_and_load_configuration() {
        let username = "test_local_encrypt_save_load";
        let password = "password_for_save_load";

        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        let local_encrypt = local_encrypt.unwrap();
        let backend = local_encrypt.backend();

        let mut document_store = match backend {
            StorageBackend::DocumentStore(document_store) => document_store,
            _ => panic!("Invalid backend"),
        }.clone();

        let mut config = HashMap::new();
        config.insert("some random value".to_string(), "test_config".to_string());

        // ensure unique id
        let form_id = format!("{}-{}", username, password);
        let meta_data = DocumentMetaData::new(&form_id);

        let config_bytes = serde_json::to_vec(&config).unwrap();
        let save_result = document_store.save(meta_data.clone(), &config_bytes).await;
        assert!(
            save_result.is_ok(),
            "Failed to save secure configuration: {:?}",
            save_result.err().unwrap()
        );

        let load_result = document_store.load(&form_id).await;
        assert!(
            load_result.is_ok(),
            "Failed to load secure configuration: {:?}",
            load_result.err().unwrap()
        );

        let loaded_config_bytes_option = load_result.unwrap();
        assert!(
            loaded_config_bytes_option.is_some(),
            "Loaded secure configuration did not exist"
        );

        let loaded_config_bytes = loaded_config_bytes_option.unwrap();
        let loaded_config: HashMap<String, String> =
            serde_json::from_slice(&loaded_config_bytes).unwrap();
        assert_eq!(
            loaded_config, config,
            "Loaded secure configuration did not match saved configuration"
        );
        local_encrypt.reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_delete_configuration() {
        let username = "test_string_vault_delete";
        let password = "password_for_delete";

        let local_encrypt = LocalEncrypt::new_with_document_store(username, password).await;
        assert!(
            local_encrypt.is_ok(),
            "Failed to create document store with error: {:?}",
            local_encrypt
        );
        let local_encrypt = local_encrypt.unwrap();
        let backend = local_encrypt.backend();

        let mut document_store = match backend {
            StorageBackend::DocumentStore(document_store) => document_store,
            _ => panic!("Invalid backend"),
        }.clone();

        let mut config = HashMap::new();
        config.insert("some random value".to_string(), "test_config".to_string());

        // ensure unique id
        let form_id = format!("{}-{}", username, password);
        let meta_data = DocumentMetaData::new(&form_id);

        let config_bytes = serde_json::to_vec(&config).unwrap();
        let save_result = document_store.save(meta_data.clone(), &config_bytes).await;
        assert!(
            save_result.is_ok(),
            "Failed to save data: {:?}",
            save_result.err().unwrap()
        );

        let delete_result = document_store.delete(&form_id).await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete data: {:?}",
            delete_result.err().unwrap()
        );

        let load_result = document_store.load(&form_id).await;
        assert!(
            load_result.is_err(),
            "Successfully loaded data after deletion"
        );
        local_encrypt.reset().await.unwrap();
    }
}
