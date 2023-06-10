use crate::crypto::{derive_key_from_password, hash_username};
use crate::{ObjectKey, SecureStorage, SecureStringError, SecureStringResult};

#[derive(Clone, PartialEq, Debug)]
pub struct LocalStorageUser {
    secure_storage: SecureStorage,
}

impl LocalStorageUser {
    pub async fn create_or_validate(username: &str, password: &str) -> SecureStringResult<Self> {
        if !LocalStorageUser::exists(username).await {
            return LocalStorageUser::create(username, password).await;
        }

        let user = LocalStorageUser::new(username, password).await?;

        // Try to load the passwords to validate the password
        match user.secure_storage.load().await {
            Ok(_) => Ok(user),
            Err(err) => match err {
                SecureStringError::NoLocalStorageData => {
                    // user is not yet created
                    Ok(user)
                }
                SecureStringError::DecryptError(_) => {
                    // user exists but password is wrong
                    Err(err)
                }
                _ => Err(err), // Propagate any other errors
            },
        }
    }

    async fn new(username: &str, password: &str) -> SecureStringResult<Self> {
        let hashed_username = hash_username(username);

        let object_key_user = ObjectKey::new("USER", &hashed_username)?;
        let crypto_key = derive_key_from_password(&object_key_user, password).await?;

        let object_key_crypto = ObjectKey::new(&object_key_user.id(), "self")?;
        Ok(Self {
            secure_storage: SecureStorage::new(object_key_crypto, crypto_key),
        })
    }

    pub fn secure_storage(&self) -> &SecureStorage {
        &self.secure_storage
    }

    async fn exists(username: &str) -> bool {
        let hashed_username = hash_username(username);
        let object_key = ObjectKey::new(&hashed_username, "self").unwrap();
        SecureStorage::exists(object_key).await
    }

    async fn create(username: &str, password: &str) -> SecureStringResult<Self> {
        // this will ensure existing config is deleted
        LocalStorageUser::reset(username).await?;
        let user = LocalStorageUser::new(username, password).await?;
        user.secure_storage.empty().await?;
        Ok(user)
    }

    async fn reset(username: &str) -> SecureStringResult<()> {
        let hashed_username = hash_username(username);
        let object_key = ObjectKey::new(&hashed_username, "self")?;

        let secure_storage = SecureStorage::for_deletion(object_key);
        secure_storage.delete().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_new() {
        let username = "username";
        let password = "password";

        let user_result = LocalStorageUser::new(username, password).await;
        assert!(user_result.is_ok());

        let user = user_result.unwrap();
        assert_eq!(
            user.secure_storage.object_key().tag(),
            hash_username(username)
        );
        assert_eq!(user.secure_storage.object_key().id(), "self");
    }

    #[wasm_bindgen_test]
    async fn test_create_or_validate_new_user() {
        let username = "new_username";
        let password = "new_password";

        // Resetting a non-existing user should not return an error
        assert!(LocalStorageUser::reset(username).await.is_ok());

        let user_result = LocalStorageUser::create_or_validate(username, password).await;
        assert!(user_result.is_ok());

        let user = user_result.unwrap();
        assert_eq!(
            user.secure_storage.object_key().tag(),
            hash_username(username)
        );
        assert_eq!(user.secure_storage.object_key().id(), "self");
    }

    #[wasm_bindgen_test]
    async fn test_create_or_validate_existing_user_wrong_password() {
        let username = "existing_username";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        // Create the user
        LocalStorageUser::create(username, password).await.unwrap();

        // Now try to validate the user with wrong password
        let user_result = LocalStorageUser::create_or_validate(username, wrong_password).await;
        assert!(user_result.is_err());
        assert_eq!(
            user_result.unwrap_err(),
            SecureStringError::DecryptError("Please ensure the password is correct.".to_owned())
        );
    }

    #[wasm_bindgen_test]
    async fn test_create_or_validate_existing_user_correct_password() {
        let username = "existing_username_2";
        let password = "correct_password_2";

        // Create the user
        LocalStorageUser::create(username, password).await.unwrap();

        // Now try to validate the user with correct password
        let user_result = LocalStorageUser::create_or_validate(username, password).await;
        assert!(user_result.is_ok());

        let user = user_result.unwrap();
        assert_eq!(
            user.secure_storage.object_key().tag(),
            hash_username(username)
        );
        assert_eq!(user.secure_storage.object_key().id(), "self");
    }

    #[wasm_bindgen_test]
    async fn test_exists() {
        let username = "username_for_exists_test";
        let password = "password_for_exists_test";

        // Assert user doesn't exist initially
        assert_eq!(LocalStorageUser::exists(username).await, false);

        // Create the user
        LocalStorageUser::create(username, password).await.unwrap();

        // Assert user now exists
        assert_eq!(LocalStorageUser::exists(username).await, true);
    }

    #[wasm_bindgen_test]
    async fn test_reset() {
        let username = "username_for_reset_test";
        let password = "password_for_reset_test";

        // Create the user
        LocalStorageUser::create(username, password).await.unwrap();

        // Assert user now exists
        assert_eq!(LocalStorageUser::exists(username).await, true);

        // Reset the user
        LocalStorageUser::reset(username).await.unwrap();

        // Assert user doesn't exist now
        assert_eq!(LocalStorageUser::exists(username).await, false);
    }
}
