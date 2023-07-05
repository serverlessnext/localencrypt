use crate::SecureStringError;

const DEFAULT_ENVIRONMENT: &str = "LocalEncrypt";

#[derive(Clone, PartialEq, Debug)]
pub struct ObjectKey {
    environment: String,
    tag: String,
    id: String,
}

impl ObjectKey {
    pub fn new(environment: &str, tag: &str, id: &str) -> Result<Self, SecureStringError> {
        if id.is_empty() {
            return Err(SecureStringError::InvalidArgument(String::from(
                "Tag and ID must not be empty",
            )));
        }

        Ok(Self {
            environment: environment.to_string(),
            tag: tag.to_string(),
            id: id.to_string(),
        })
    }

    pub fn environment(&self) -> String {
        self.environment.clone()
    }

    pub fn tag(&self) -> String {
        self.tag.clone()
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    fn test_object_key_new() {
        let object_key = ObjectKey::new("debug", "test", "test_id").unwrap();
        assert_eq!(object_key.tag(), "test");
        assert_eq!(object_key.id(), "test_id");
    }

    #[wasm_bindgen_test]
    async fn test_invalid_object_key_creation() {
        // Check that ObjectKey::new returns an error when given an empty id
        let object_key_empty_id = ObjectKey::new("debug", "test_tag", "");
        assert!(
            object_key_empty_id.is_err(),
            "Successfully created ObjectKey with empty id"
        );
    }

    #[wasm_bindgen_test]
    fn test_object_key_new_empty_tag_and_id() {
        let object_key = ObjectKey::new("debug", "", "");
        assert!(
            object_key.is_err(),
            "Successfully created ObjectKey with empty tag and id"
        );
        match object_key {
            Err(SecureStringError::InvalidArgument(msg)) => {
                assert_eq!(msg, "Tag and ID must not be empty");
            }
            _ => {
                panic!("Unexpected result from ObjectKey::new with empty tag and id");
            }
        }
    }

    #[wasm_bindgen_test]
    fn test_object_key_new_error_message() {
        let object_key = ObjectKey::new("debug", "test", "");
        assert!(
            object_key.is_err(),
            "Successfully created ObjectKey with empty id"
        );
        match object_key {
            Err(SecureStringError::InvalidArgument(msg)) => {
                assert_eq!(msg, "Tag and ID must not be empty");
            }
            _ => {
                panic!("Unexpected result from ObjectKey::new with empty id");
            }
        }
    }
}
