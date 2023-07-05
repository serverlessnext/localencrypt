use crate::common::Credentials;
use crate::crypto::{derive_key_from_password, hash_username};
use crate::{ObjectKey, SecureStorage, SecureStringError, SecureStringResult};

#[derive(Clone, PartialEq, Debug)]
pub struct LocalStorageUser {
    secure_storage: SecureStorage,
}

impl LocalStorageUser {
    pub async fn create_or_validate(credentials: &Credentials) -> SecureStringResult<Self> {
        let environment = credentials.environment();
        let username = credentials.username();
        if !LocalStorageUser::exists(&environment, &username).await {
            return LocalStorageUser::create(credentials).await;
        }

        let user = LocalStorageUser::new(credentials).await?;

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

    async fn new(credentials: &Credentials) -> SecureStringResult<Self> {
        let environment = credentials.environment();
        let username = credentials.username();
        let password = credentials.password();
        let hashed_username = hash_username(&username);

        let object_key_user = ObjectKey::new(&environment, "USER", &hashed_username)?;
        let crypto_key = derive_key_from_password(&object_key_user, &password).await?;

        let object_key_crypto = ObjectKey::new(&environment, &object_key_user.id(), "self")?;
        Ok(Self {
            secure_storage: SecureStorage::new(object_key_crypto, crypto_key),
        })
    }

    pub fn secure_storage(&self) -> &SecureStorage {
        &self.secure_storage
    }

    async fn exists(environment: &str, username: &str) -> bool {
        let hashed_username = hash_username(username);
        let object_key = ObjectKey::new(environment, &hashed_username, "self").unwrap();
        SecureStorage::exists(object_key).await
    }

    async fn create(credentials: &Credentials) -> SecureStringResult<Self> {
        // this will ensure existing config is deleted
        let environment = credentials.environment();
        let username = credentials.username();
        LocalStorageUser::reset(&environment, &username).await?;
        let user = LocalStorageUser::new(credentials).await?;
        user.secure_storage.empty().await?;
        Ok(user)
    }

    async fn reset(environment: &str, username: &str) -> SecureStringResult<()> {
        let hashed_username = hash_username(username);
        let object_key = ObjectKey::new(environment, &hashed_username, "self")?;

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
        let credentials = Credentials::new(None, username, password);

        let user_result = LocalStorageUser::new(&credentials).await;
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
        let environment = "debug";
        let username = "new_username";
        let password = "new_password";
        let credentials = Credentials::new(Some(environment), username.clone(), password.clone());

        // Resetting a non-existing user should not return an error
        assert!(LocalStorageUser::reset(environment, username).await.is_ok());

        let user_result = LocalStorageUser::create_or_validate(&credentials).await;
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
        let environment = "debug";
        let username = "existing_username";
        let password = "correct_password";
        let credentials = Credentials::new(Some(environment), username.clone(), password.clone());
        let wrong_credentials =
            Credentials::new(Some(environment), username.clone(), "wrong_password");

        // Create the user
        LocalStorageUser::create(&credentials).await.unwrap();

        // Now try to validate the user with wrong password
        let user_result = LocalStorageUser::create_or_validate(&wrong_credentials).await;
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
        let credentials = Credentials::new(None, username.clone(), password.clone());

        // Create the user
        LocalStorageUser::create(&credentials).await.unwrap();

        // Now try to validate the user with correct password
        let user_result = LocalStorageUser::create_or_validate(&credentials).await;
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
        let environment = "debug";
        let username = "username_for_exists_test";
        let password = "password_for_exists_test";
        let credentials = Credentials::new(Some(environment), username, password);

        // Assert user doesn't exist initially
        assert_eq!(LocalStorageUser::exists(environment, username).await, false);

        // Create the user
        LocalStorageUser::create(&credentials).await.unwrap();

        // Assert user now exists
        assert_eq!(LocalStorageUser::exists(environment, username).await, true);
    }

    #[wasm_bindgen_test]
    async fn test_reset() {
        let environment = "debug";
        let username = "username_for_reset_test";
        let password = "password_for_reset_test";
        let credentials = Credentials::new(Some(environment), username.clone(), password.clone());

        // Create the user
        LocalStorageUser::create(&credentials).await.unwrap();

        // Assert user now exists
        assert_eq!(LocalStorageUser::exists(environment, username).await, true);

        // Reset the user
        LocalStorageUser::reset(environment, username)
            .await
            .unwrap();

        // Assert user doesn't exist now
        assert_eq!(LocalStorageUser::exists(environment, username).await, false);
    }
}
