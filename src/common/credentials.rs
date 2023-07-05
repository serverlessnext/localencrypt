const DEFAULT_ENVIRONMENT: &str = "LocalEncrypt";

#[derive(Clone, PartialEq)]
pub struct Credentials {
    environment: String,
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(environment: Option<&str>, username: &str, password: &str) -> Self {
        Self {
            environment: environment.unwrap_or(DEFAULT_ENVIRONMENT).to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub fn environment(&self) -> String {
        self.environment.clone()
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> String {
        // TODO: lets make this hashbased
        self.password.clone()
    }
}

use std::fmt::{Debug, Formatter};
impl Debug for Credentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("environment", &self.environment)
            .field("username", &self.username)
            .field("password", &"********")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_credentials_new() {
        let username = "username";
        let password = "password";
        let credentials = Credentials::new(None, username, password);
        assert_eq!(credentials.username(), username);
        assert_eq!(credentials.password(), password);
    }

    #[wasm_bindgen_test]
    async fn test_credentials_debug() {
        let username = "username";
        let password = "secretpassword";
        let credentials = Credentials::new(None, username, password);
        let debug_str = format!("{:?}", credentials);
        assert!(debug_str.contains("username"));
        assert!(debug_str.contains("********"));
        assert!(!debug_str.contains(password));
    }
}
