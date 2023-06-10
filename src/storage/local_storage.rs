use std::collections::HashMap;

use log::info;
use serde_json;

use crate::common::Credentials;
use crate::crypto::{derive_crypto_key, hash_username};
use crate::utils::generate_password_base64;
use crate::{ItemMetaData, ObjectKey, SecureStorage, SecureStringError, SecureStringResult};

use super::local_storage_user::LocalStorageUser;

const PASSWORD_FIELD: &str = "__PASSWD__";

#[derive(Clone, PartialEq, Debug)]
pub struct LocalStorage {
    credentials: Credentials,
    storage: Option<SecureStorage>,
}

impl LocalStorage {
    pub async fn new(credentials: Credentials) -> SecureStringResult<Self> {
        let password = credentials.password();

        let storage = if password.is_empty() {
            None
        } else {
            let username = credentials.username();
            let user = LocalStorageUser::create_or_validate(&username, &password).await?;
            Some(user.secure_storage().clone())
        };
        Ok(Self {
            credentials,
            storage,
        })
    }

    pub fn get_username(&self) -> SecureStringResult<String> {
        Ok(self.credentials.username().to_string())
    }

    pub async fn user_exists(username: &str) -> bool {
        let hashed_username = hash_username(username);
        let object_key = ObjectKey::new(&hashed_username, "self").unwrap();
        SecureStorage::exists(object_key).await
    }

    pub async fn soft_reset(&self) -> SecureStringResult<()> {
        // TODO: soft reset should try to backup old master account
        // for now we just hard reset
        self.hard_reset().await?;
        Ok(())
    }

    pub async fn hard_reset(&self) -> SecureStringResult<()> {
        let username = self.credentials.username();
        let hashed_username = hash_username(&username);
        let object_key = ObjectKey::new(&hashed_username, "self")?;

        let secure_storage = SecureStorage::for_deletion(object_key);
        secure_storage.delete().await?;

        Ok(())
    }

    pub async fn validate_password(&self) -> SecureStringResult<bool> {
        // Check if storage is initialized
        if self.storage.is_none() {
            return Err(SecureStringError::StorageNotInitialized);
        }

        // Attempt to load the stored data using the current password
        match self.storage.as_ref().unwrap().load().await {
            // If data loading is successful, it implies the password is valid
            Ok(_) => Ok(true),
            // If a DecryptError occurs, the password is invalid
            Err(SecureStringError::DecryptError(_)) => Ok(false),
            // Any other error is propagated
            Err(err) => Err(err),
        }
    }

    pub async fn change_password(
        &mut self,
        new_password: &str,
    ) -> SecureStringResult<()> {

        // copy existing items -- this will be gone after soft_reset
        let items = self.get_items().await?;
        let username = self.credentials.username();

        // cleanup current user
        self.soft_reset().await?;

        // create user with same username, but new password
        let user = LocalStorageUser::create_or_validate(&username, new_password).await?;
        self.storage = Some(user.secure_storage().clone());

        // put back original items with the new password
        self.put_items(&items).await?;
        Ok(())
    }

    pub async fn initiate_with_password(
        username: &str,
        password: &str,
    ) -> SecureStringResult<Self> {
        let credentials = Credentials::new(username, password);
        Self::new(credentials).await
    }

    pub async fn initiate_with_no_password(username: &str) -> SecureStringResult<Self> {
        let password = "";
        let credentials = Credentials::new(username, &password);
        Self::new(credentials).await
    }

    pub async fn list_items(&self) -> SecureStringResult<Vec<ItemMetaData>> {
        let items = self.get_items().await?;

        let items_as_meta = items
            .into_iter()
            .map(|(id, tags)| {
                let mut new_tags = tags.clone();
                new_tags.retain(|k, _| !k.starts_with("__") && !k.ends_with("__"));
                ItemMetaData::new_with_tags(&id, new_tags)
            })
            .collect();

        Ok(items_as_meta)
    }

    pub async fn add_item(&mut self, item_meta: ItemMetaData) -> SecureStringResult<()> {
        let mut items = self.get_items().await?;

        let item_id = item_meta.id();

        if items.contains_key(&item_id) {
            return Err(SecureStringError::FormAlreadyExists);
        }

        let item_meta_stored = self.populate_meta_stored(&item_meta, None);

        items.insert(item_id, item_meta_stored);

        self.put_items(&items).await
    }

    pub async fn delete_item(&mut self, item_id: &str) -> SecureStringResult<()> {
        let mut items = self.get_items().await?;

        if items.remove(item_id).is_none() {
            return Err(SecureStringError::PasswordNotFound(format!(
                "Configuration for {} not found",
                item_id
            )));
        }

        self.put_items(&items).await
    }

    pub async fn save_content(
        &mut self,
        item_meta: ItemMetaData,
        content: &[u8],
    ) -> SecureStringResult<()> {
        let item_id = item_meta.id();
        info!("Saving configuration for {}", item_id);

        let password = generate_password_base64()?;
        let derived_key = derive_crypto_key(&password, &item_id).await?;

        let object_key = ObjectKey::new("", &item_id)?;
        let secure_storage_form = SecureStorage::new(object_key, derived_key);
        secure_storage_form.save(content).await?;

        let mut items = self.get_items().await?;
        let item_meta_stored = self.populate_meta_stored(&item_meta, Some(password));

        items.insert(item_id, item_meta_stored);

        self.put_items(&items).await
    }

    pub async fn load_content(&self, item_id: &str) -> Result<Option<Vec<u8>>, SecureStringError> {
        let items = self.get_items().await?;

        if let Some(meta) = items.get(item_id) {
            if let Some(password) = meta.get(PASSWORD_FIELD) {
                let object_key = ObjectKey::new("", &item_id)?;
                let derived_key = derive_crypto_key(&password, &item_id).await?;
                let secure_storage_form = SecureStorage::new(object_key, derived_key);

                secure_storage_form.load().await.map(Some)
            } else {
                // item found, but no content saved yet
                Ok(None)
            }
        } else {
            // item not found
            Err(SecureStringError::NoLocalStorageData)
        }
    }

    async fn get_items(&self) -> SecureStringResult<HashMap<String, HashMap<String, String>>> {
        if self.storage.is_none() {
            return Err(SecureStringError::StorageNotInitialized);
        }

        match self.storage.as_ref().unwrap().load().await {
            Ok(passwords_json) => serde_json::from_slice(&passwords_json).map_err(|err| {
                SecureStringError::SerdeError(format!("Failed to parse forms_db: {:?}", err))
            }),
            Err(SecureStringError::NoLocalStorageData) => Ok(HashMap::new()),
            Err(err) => Err(err),
        }
    }

    async fn put_items(
        &mut self,
        items: &HashMap<String, HashMap<String, String>>,
    ) -> SecureStringResult<()> {
        if self.storage.is_none() {
            return Err(SecureStringError::StorageNotInitialized);
        }
        let items_vec = serde_json::to_vec(items).map_err(|err| {
            SecureStringError::SerdeError(format!("Failed to serialize forms_db: {:?}", err))
        })?;
        self.storage.as_ref().unwrap().save(&items_vec).await
    }

    fn populate_meta_stored(
        &self,
        item_meta: &ItemMetaData,
        password: Option<String>,
    ) -> HashMap<String, String> {
        let mut item_meta_stored = HashMap::new();

        if let Some(pwd) = password {
            item_meta_stored.insert(PASSWORD_FIELD.to_string(), pwd);
        }

        if let Some(tags) = item_meta.tags() {
            item_meta_stored.extend(tags);
        }

        item_meta_stored
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_list_items() {
        let credentials = Credentials::new("test_user_list_items", "password_for_list_items");

        let local_storage = LocalStorage::new(credentials.clone()).await;
        assert!(local_storage.is_ok());
        let local_storage = local_storage.unwrap();

        let result = local_storage.list_items().await;
        assert!(
            result.is_ok(),
            "Failed to list documents: {:?}",
            result.err().unwrap()
        );

        let document_map = result.unwrap();
        assert_eq!(document_map.len(), 0);
        local_storage.hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_save_and_load_content() {
        let credentials = Credentials::new("test_user_save_load", "password_for_save_load");

        let local_storage = LocalStorage::new(credentials.clone()).await;
        assert!(local_storage.is_ok());
        let mut local_storage = local_storage.unwrap();

        let mut config = HashMap::new();
        config.insert("__NAME__".to_string(), "test_config".to_string());

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username(), credentials.password());
        let meta_data = ItemMetaData::new(&form_id);
        let config_bytes = serde_json::to_vec(&config).unwrap();

        let save_result = local_storage
            .save_content(meta_data.clone(), &config_bytes)
            .await;
        assert!(
            save_result.is_ok(),
            "Failed to save document: {:?}",
            save_result.err().unwrap()
        );

        let load_result = local_storage.load_content(&form_id).await;
        assert!(
            load_result.is_ok(),
            "Failed to load document: {:?}",
            load_result.err().unwrap()
        );

        let loaded_config_bytes_option = load_result.unwrap();
        assert!(
            loaded_config_bytes_option.is_some(),
            "Loaded document did not exist"
        );

        let loaded_config_bytes = loaded_config_bytes_option.unwrap();
        let loaded_config: HashMap<String, String> =
            serde_json::from_slice(&loaded_config_bytes).unwrap();
        assert_eq!(
            loaded_config, config,
            "Loaded document did not match saved document"
        );
        local_storage.hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_add_and_delete_items() {
        let credentials = Credentials::new(
            "test_user_add_and_delete_items",
            "password_for_add_and_delete",
        );

        let local_storage = LocalStorage::new(credentials.clone()).await;
        assert!(local_storage.is_ok());
        let mut local_storage = local_storage.unwrap();

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username(), credentials.password());
        let meta_data = ItemMetaData::new(&form_id);

        // Test adding a document
        let add_result = local_storage.add_item(meta_data.clone()).await;
        assert!(
            add_result.is_ok(),
            "Failed to add document: {:?}",
            add_result.err().unwrap()
        );

        let load_result = local_storage.load_content(&form_id).await;
        assert!(load_result.is_ok(), "Load failed after add");

        let loaded_data = load_result.unwrap();
        assert!(loaded_data.is_none(), "Data present after add");

        // Test deleting a document
        let delete_result = local_storage.delete_item(&form_id).await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete document: {:?}",
            delete_result.err().unwrap()
        );

        let load_result_after_delete = local_storage.load_content(&form_id).await;
        assert!(
            matches!(
                load_result_after_delete,
                Err(SecureStringError::NoLocalStorageData)
            ),
            "Successfully loaded document after delete"
        );
        local_storage.hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_delete_non_existent_item() {
        let credentials = Credentials::new(
            "test_user_delete_non_existent_item",
            "password_for_delete_non_existent",
        );

        let local_storage = LocalStorage::new(credentials.clone()).await;
        assert!(local_storage.is_ok());
        let mut local_storage = local_storage.unwrap();

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username(), credentials.password());
        let delete_result = local_storage.delete_item(&form_id).await;
        assert!(
            delete_result.is_err(),
            "Successfully deleted a non-existent document"
        );

        local_storage.hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_load_non_existent_item() {
        let credentials = Credentials::new(
            "test_user_load_non_existent_item",
            "password_for_load_non_existent",
        );

        let local_storage = LocalStorage::new(credentials.clone()).await;
        assert!(local_storage.is_ok());
        let local_storage = local_storage.unwrap();

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username(), credentials.password());
        let load_result = local_storage.load_content(&form_id).await;
        assert!(
            load_result.is_err(),
            "Successfully loaded a non-existent document"
        );
        local_storage.hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_populate_meta_stored() {
        let credentials = Credentials::new(
            "test_user_populate_meta_stored",
            "password_for_populate_meta_stored",
        );

        let local_storage = LocalStorage::new(credentials.clone()).await;
        assert!(local_storage.is_ok());
        let local_storage = local_storage.unwrap();

        let mut tags = HashMap::new();
        tags.insert("tag1".to_string(), "value1".to_string());
        tags.insert("tag2".to_string(), "value2".to_string());

        let item_meta = ItemMetaData::new_with_tags("test_populate_meta_stored", tags);

        let item_meta_stored =
            local_storage.populate_meta_stored(&item_meta, Some("password".to_string()));

        assert_eq!(
            item_meta_stored.get(PASSWORD_FIELD),
            Some(&"password".to_string())
        );
        assert_eq!(item_meta_stored.get("tag1"), Some(&"value1".to_string()));
        assert_eq!(item_meta_stored.get("tag2"), Some(&"value2".to_string()));
        local_storage.hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_validate_password() {
        let correct_password = "correct_password";
        let incorrect_password = "incorrect_password";

        // Initialization with correct password
        let local_storage =
            LocalStorage::initiate_with_password("test_user", correct_password).await;
        assert!(
            local_storage.is_ok(),
            "Failed to initialize with correct password"
        );

        // Attempting initialization with incorrect password
        let result = LocalStorage::initiate_with_password("test_user", incorrect_password).await;
        assert!(
            matches!(result, Err(SecureStringError::DecryptError(_))),
            "Unexpected error type returned"
        );

        // Clean up
        local_storage.unwrap().hard_reset().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_change_password() {
        let old_password = "old_password";
        let new_password = "new_password";
        let username = "test_user_change_password_local_storage";

        let item_id = "test_item_id";
        let item_meta = ItemMetaData::new(item_id);
        let test_content = b"test_content";

        // Initialization with old password
        let local_storage = LocalStorage::initiate_with_password(username, old_password).await;
        assert!(local_storage.is_ok(), "Failed to initialize with old password");
        let mut local_storage = local_storage.unwrap();

        // Add an item
        let save_result = local_storage.save_content(item_meta.clone(), test_content).await;
        assert!(save_result.is_ok(), "Failed to save content before changing password");

        // Change password to new password
        let change_password_result = local_storage.change_password(new_password).await;
        assert!(change_password_result.is_ok(), "Failed to change password");

        // Ensure we can't load with old password
        let result = LocalStorage::initiate_with_password(username, old_password).await;
        assert!(
            matches!(result, Err(SecureStringError::DecryptError(_))),
            "Unexpectedly succeeded in loading with old password"
        );

        // Ensure we can load with new password
        let result = LocalStorage::initiate_with_password(username, new_password).await;
        assert!(
            result.is_ok(),
            "Failed to load with new password"
        );
        let new_local_storage = result.unwrap();

        // Ensure our item still exists with new password
        let load_result = new_local_storage.load_content(item_id).await;
        assert!(
            load_result.is_ok() && load_result.unwrap() == Some(test_content.to_vec()),
            "Failed to load content or content was incorrect after changing password"
        );

        // Clean up
        local_storage.hard_reset().await.unwrap();
    }
}
