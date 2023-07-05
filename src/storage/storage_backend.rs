use super::LocalStorage;
use crate::{SecureStringError, SecureStringResult};

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
    pub async fn initiate_with_local_storage(
        environment: Option<&str>,
        username: &str,
        password: Option<&str>,
    ) -> SecureStringResult<Self> {
        let local_storage = match password {
            Some(password) => {
                LocalStorage::initiate_with_password(environment, username, password).await?
            }
            None => LocalStorage::initiate_with_no_password(environment, username).await?,
        };

        Ok(Self::Browser(BrowserStorage::LocalStorage(local_storage)))
    }

    pub async fn hard_reset(&self) -> SecureStringResult<()> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                local_storage.hard_reset().await
            }
            _ => Err(SecureStringError::Unimplemented),
        }
    }

    pub async fn validate_password(&self) -> SecureStringResult<bool> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                local_storage.validate_password().await
            }
            _ => Err(SecureStringError::Unimplemented),
        }
    }

    pub async fn change_password(
        &self,
        environment: Option<&str>,
        old_password: &str,
        new_password: &str,
    ) -> SecureStringResult<()> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                // get the username from the existing local_storage
                let username = local_storage
                    .get_username()
                    .expect("Failed to get username");

                // create a new LocalStorage instance with the old password
                let mut old_local_storage =
                    LocalStorage::initiate_with_password(environment, &username, old_password)
                        .await?;

                // perform the change password operation
                old_local_storage.change_password(new_password).await?;
                Ok(())
            }
            _ => Err(SecureStringError::Unimplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;
    use crate::ItemMetaData;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_initiate_with_local_storage() {
        // Case with password
        let username = "test_initiate_with_local_storage";
        let password = "password";
        let result =
            StorageBackend::initiate_with_local_storage(None, username, Some(password)).await;
        assert!(result.is_ok());

        // Case without password
        let username = "username";
        let result = StorageBackend::initiate_with_local_storage(None, username, None).await;
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    async fn test_hard_reset() {
        // Case with Browser backend
        let username = "test_hard_reset";
        let password = "password";
        let backend = StorageBackend::initiate_with_local_storage(None, username, Some(password))
            .await
            .expect("Failed to initiate local storage backend");
        let result = backend.hard_reset().await;
        assert!(result.is_ok());

        // Case with Memory backend
        let backend = StorageBackend::Memory;
        let result = backend.hard_reset().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SecureStringError::Unimplemented);
    }

    #[wasm_bindgen_test]
    async fn test_validate_password() {
        // Case with Browser backend
        let username = "test_validate_password";
        let password = "password";
        let backend = StorageBackend::initiate_with_local_storage(None, username, Some(password))
            .await
            .expect("Failed to initiate local storage backend");
        let result = backend.validate_password().await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // assuming the password is correct

        // Case with Memory backend
        let backend = StorageBackend::Memory;
        let result = backend.validate_password().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SecureStringError::Unimplemented);
    }

    #[wasm_bindgen_test]
    async fn test_change_password_local_storage() {
        // Case with Browser backend
        let username = "test_change_password_local_storage";
        let password = "old_password";
        let new_password = "new_password";
        let mut backend =
            StorageBackend::initiate_with_local_storage(None, username, Some(password))
                .await
                .expect("Failed to initiate local storage backend");

        // Get LocalStorage and add some items to it
        match &mut backend {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                // Add some items to local_storage
                let item_meta = ItemMetaData::new_with_tags(
                    "item1",
                    vec![
                        ("tag1".to_string(), "value1".to_string()),
                        ("tag2".to_string(), "value2".to_string()),
                    ]
                    .into_iter()
                    .collect(),
                );
                let content = b"Content of the item";
                local_storage
                    .save_content(item_meta, content)
                    .await
                    .expect("Failed to add item");
            }
            _ => panic!("Expected browser local storage backend"),
        }

        // Change password
        let result = backend.change_password(None, password, new_password).await;
        assert!(result.is_ok());

        // Validate should fail on old backend
        let result = backend.validate_password().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // password should no longer be correct

        // Get backend with new password
        let new_backend =
            StorageBackend::initiate_with_local_storage(None, username, Some(new_password))
                .await
                .expect("Failed to initiate local storage backend");

        // Get LocalStorage and check that the items are still there
        match new_backend {
            StorageBackend::Browser(BrowserStorage::LocalStorage(new_local_storage)) => {
                // Check that the items are still there
                let items = new_local_storage
                    .list_items()
                    .await
                    .expect("Failed to list items");
                assert_eq!(items.len(), 1); // one item was added
                assert_eq!(items[0].id(), "item1");
                assert_eq!(
                    items[0].tags(),
                    Some(
                        vec![
                            ("tag1".to_string(), "value1".to_string()),
                            ("tag2".to_string(), "value2".to_string())
                        ]
                        .into_iter()
                        .collect()
                    )
                );

                // Check the content of the item
                let content = new_local_storage
                    .load_content("item1")
                    .await
                    .expect("Failed to load content");
                assert_eq!(content.as_ref().unwrap().as_slice(), b"Content of the item");
            }
            _ => panic!("Expected browser local storage backend"),
        }
    }
}
