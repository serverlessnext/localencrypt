use std::collections::HashMap;

use log::info;
use serde_json;

use crate::crypto::derive_crypto_key;
use crate::utils::generate_password_base64;
use crate::{User, DocumentMetaData, ObjectKey, SecureStorage, SecureStringError, SecureStringResult, Credentials};

#[derive(Clone, PartialEq, Debug)]
pub struct DocumentStore {
    secure_storage: SecureStorage,
}

impl DocumentStore {
    pub async fn new(credentials: &Credentials) -> SecureStringResult<Self> {
        let username = credentials.username.as_str();
        let password = credentials.password.as_str();
        let user = User::create_or_validate(username, password).await?;
        let secure_storage = user.secure_storage().clone();
        Ok(Self { secure_storage })
    }

    async fn load_forms_db(&self) -> SecureStringResult<HashMap<String, HashMap<String, String>>> {
        let passwords_json_result = self.secure_storage.load().await;

        match passwords_json_result {
            Ok(passwords_json) => match serde_json::from_slice(&passwords_json) {
                Ok(map) => Ok(map),
                Err(err) => Err(SecureStringError::SerdeError(format!(
                    "Failed to parse forms_db: {:?}",
                    err
                ))),
            },
            Err(SecureStringError::NoLocalStorageData) => Ok(HashMap::new()),
            Err(err) => Err(err), // Propagate any other errors
        }
    }

    async fn save_forms_db(
        &mut self,
        forms_db: &HashMap<String, HashMap<String, String>>,
    ) -> SecureStringResult<()> {
        let forms_db_vec = serde_json::to_vec(forms_db).map_err(|err| {
            SecureStringError::SerdeError(format!("Failed to serialize forms_db: {:?}", err))
        })?;
        self.secure_storage.save(&forms_db_vec).await
    }

    pub async fn list(&self) -> SecureStringResult<Vec<DocumentMetaData>> {
        let forms_db = self.load_forms_db().await?;

        let configurations = forms_db
            .into_iter()
            .map(|(id, tags)| DocumentMetaData::new_with_tags(&id, tags))
            .collect();

        Ok(configurations)
    }

    pub async fn save(
        &mut self,
        meta_data: DocumentMetaData,
        document_content: &[u8],
    ) -> SecureStringResult<()> {
        let form_id = meta_data.id();
        info!("Saving configuration for {}", form_id);

        let password = generate_password_base64()?;
        let derived_key = derive_crypto_key(&password, &form_id).await?;

        let object_key = ObjectKey::new("", &form_id)?;
        let secure_storage_form = SecureStorage::new(object_key, derived_key);
        secure_storage_form.save(document_content).await?;

        let mut forms_db = self.load_forms_db().await?;
        let mut form_config = HashMap::new();

        form_config.insert("__PASSWD__".to_string(), password);

        if let Some(tags) = meta_data.tags() {
            form_config.extend(tags);
        }
        forms_db.insert(form_id, form_config);

        self.save_forms_db(&forms_db).await
    }

    pub async fn load(&self, form_id: &str) -> Result<Option<Vec<u8>>, SecureStringError> {
        let forms_db = self.load_forms_db().await?;

        if let Some(meta) = forms_db.get(form_id) {
            if let Some(password) = meta.get("__PASSWD__") {
                let object_key = ObjectKey::new("", &form_id).unwrap();
                let derived_key = derive_crypto_key(&password, &form_id).await?;
                let secure_storage_form = SecureStorage::new(object_key, derived_key);

                secure_storage_form.load().await.map(Some)
            } else {
                // No document content stored yet
                Ok(None)
            }
        } else {
            // No entry found in forms_db for the given form_id
            Err(SecureStringError::NoLocalStorageData)
        }
    }

    pub async fn add(&mut self, meta_data: DocumentMetaData) -> SecureStringResult<()> {
        let mut forms_db = self.load_forms_db().await?;

        let form_id = meta_data.id();

        // Check if the form_id already exists
        if forms_db.contains_key(&form_id) {
            return Err(SecureStringError::FormAlreadyExists);
        }

        // Create a new form configuration
        let mut form_config = HashMap::new();

        if let Some(tags) = meta_data.tags() {
            form_config.extend(tags);
        }

        // Add new form configuration to forms_db
        forms_db.insert(form_id.to_string(), form_config);

        self.save_forms_db(&forms_db).await
    }

    pub async fn delete(&mut self, form_id: &str) -> SecureStringResult<()> {
        let mut forms_db = self.load_forms_db().await?;

        if forms_db.remove(form_id).is_none() {
            return Err(SecureStringError::PasswordNotFound(format!(
                "Configuration for {} not found",
                form_id
            )));
        }

        self.save_forms_db(&forms_db).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use wasm_bindgen_test::*;

    use super::*;
    use crate::User;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_list() {
        let credentials = Credentials {
            username: "test_document_store_test_list".to_string(),
            password: "password_for_list".to_string(),
        };

        let document_store = DocumentStore::new(&credentials).await;
        assert!(document_store.is_ok());
        let document_store = document_store.unwrap();

        let result = document_store.list().await;
        assert!(
            result.is_ok(),
            "Failed to list documents: {:?}",
            result.err().unwrap()
        );

        let document_map = result.unwrap();
        assert_eq!(document_map.len(), 0);
        User::reset(&credentials.username).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_save_and_load() {
        let credentials = Credentials {
            username: "test_document_store_test_save_and_load".to_string(),
            password: "password_for_save_load".to_string(),
        };

        let document_store = DocumentStore::new(&credentials).await;
        assert!(document_store.is_ok());
        let mut document_store = document_store.unwrap();

        let mut config = HashMap::new();
        config.insert("__NAME__".to_string(), "test_config".to_string());

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username, credentials.password);
        let meta_data = DocumentMetaData::new(&form_id);
        let config_bytes = serde_json::to_vec(&config).unwrap();

        let save_result = document_store.save(meta_data.clone(), &config_bytes).await;
        assert!(
            save_result.is_ok(),
            "Failed to save document: {:?}",
            save_result.err().unwrap()
        );

        let load_result = document_store.load(&form_id).await;
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
        User::reset(&credentials.username).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_add_and_delete() {
        let credentials = Credentials {
            username: "test_document_store_test_add_and_delete".to_string(),
            password: "password_for_add_and_delete".to_string(),
        };

        let document_store = DocumentStore::new(&credentials).await;
        assert!(document_store.is_ok());
        let mut document_store = document_store.unwrap();

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username, credentials.password);
        let meta_data = DocumentMetaData::new(&form_id);

        // Test adding a document
        let add_result = document_store.add(meta_data.clone()).await;
        assert!(
            add_result.is_ok(),
            "Failed to add document: {:?}",
            add_result.err().unwrap()
        );

        let load_result = document_store.load(&form_id).await;
        assert!(load_result.is_ok(), "Load failed after add");

        let loaded_data = load_result.unwrap();
        assert!(loaded_data.is_none(), "Data present after add");

        // Test deleting a document
        let delete_result = document_store.delete(&form_id).await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete document: {:?}",
            delete_result.err().unwrap()
        );

        let load_result_after_delete = document_store.load(&form_id).await;
        assert!(
            matches!(
                load_result_after_delete,
                Err(SecureStringError::NoLocalStorageData)
            ),
            "Successfully loaded document after delete"
        );
        User::reset(&credentials.username).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_delete_non_existent() {
        let credentials = Credentials {
            username: "test_document_store_test_delete_non_existent".to_string(),
            password: "password_for_delete_non_existent".to_string(),
        };

        let document_store = DocumentStore::new(&credentials).await;
        assert!(document_store.is_ok());
        let mut document_store = document_store.unwrap();

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username, credentials.password);
        let delete_result = document_store.delete(&form_id).await;
        assert!(
            delete_result.is_err(),
            "Successfully deleted a non-existent document"
        );

        User::reset(&credentials.username).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn test_load_non_existent() {
        let credentials = Credentials {
            username: "test_document_store_test_load_non_existent".to_string(),
            password: "password_for_load_non_existent".to_string(),
        };

        let document_store = DocumentStore::new(&credentials).await;
        assert!(document_store.is_ok());
        let document_store = document_store.unwrap();

        // ensure unique id
        let form_id = format!("{}-{}", credentials.username, credentials.password);
        let load_result = document_store.load(&form_id).await;
        assert!(
            load_result.is_err(),
            "Successfully loaded a non-existent document"
        );
        User::reset(&credentials.username).await.unwrap();
    }
}
