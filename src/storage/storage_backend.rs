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
        username: &str,
        password: Option<&str>,
    ) -> SecureStringResult<Self> {
        let local_storage = match password {
            Some(password) => LocalStorage::initiate_with_password(username, password).await?,
            None => LocalStorage::initiate_with_no_password(username).await?,
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
        old_password: &str,
        new_password: &str,
    ) -> SecureStringResult<()> {
        match self {
            StorageBackend::Browser(BrowserStorage::LocalStorage(local_storage)) => {
                local_storage
                    .change_password(old_password, new_password)
                    .await
            }
            _ => Err(SecureStringError::Unimplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

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
        let backend = StorageBackend::initiate_with_local_storage(username, Some(password))
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
        let username = "username";
        let password = "password";
        let backend = StorageBackend::initiate_with_local_storage(username, Some(password))
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
    async fn test_change_password() {
        // Case with Browser backend
        let username = "username";
        let password = "password";
        let new_password = "new_password";
        let backend = StorageBackend::initiate_with_local_storage(username, Some(password))
            .await
            .expect("Failed to initiate local storage backend");
        let result = backend.change_password(password, new_password).await;
        assert!(result.is_ok());

        // Validate the new password
        let result = backend.validate_password().await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Case with Memory backend
        let backend = StorageBackend::Memory;
        let result = backend.change_password(password, new_password).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SecureStringError::Unimplemented);

        // TODO: Test with wrong old password
        // actual passchange not yet implemented
    }
}
