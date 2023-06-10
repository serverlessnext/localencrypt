use crate::StorageBackend;

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
    use crate::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_builder_memory_backend() {
        // Using builder to set up LocalEncrypt with memory backend
        let local_encrypt = LocalEncrypt::builder().build();
        match local_encrypt.backend() {
            StorageBackend::Memory => {} // expected case
            _ => panic!("Invalid backend"),
        };
    }

    #[wasm_bindgen_test]
    async fn test_builder_local_storage_backend() {
        // Using builder to set up LocalEncrypt with localStorage backend
        let username = "username";
        let password = "password";
        let credentials = Credentials::new(username, password);
        let local_storage = LocalStorage::new(credentials)
            .await
            .expect("Failed to create local storage backend");
        let local_encrypt = LocalEncrypt::builder()
            .with_backend(StorageBackend::Browser(BrowserStorage::LocalStorage(
                local_storage,
            )))
            .build();

        match local_encrypt.backend() {
            StorageBackend::Browser(BrowserStorage::LocalStorage(_)) => {} // expected case
            _ => panic!("Invalid backend"),
        };
    }

    #[wasm_bindgen_test]
    async fn test_new_memory_backend() {
        // Using new method to set up LocalEncrypt with memory backend
        let local_encrypt = LocalEncrypt::new();
        match local_encrypt.backend() {
            StorageBackend::Memory => {} // expected case
            _ => panic!("Invalid backend"),
        };
    }

    #[wasm_bindgen_test]
    async fn test_local_encrypt_equality() {
        let local_encrypt1 = LocalEncrypt::new();
        let local_encrypt2 = LocalEncrypt::new();
        assert_eq!(local_encrypt1, local_encrypt2);

        let credentials = Credentials::new("username", "password");
        let local_storage = LocalStorage::new(credentials)
            .await
            .expect("Failed to create local storage backend");
        let local_encrypt3 = LocalEncrypt::builder()
            .with_backend(StorageBackend::Browser(BrowserStorage::LocalStorage(
                local_storage,
            )))
            .build();
        assert_ne!(local_encrypt1, local_encrypt3);
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
}
