
#[derive(Clone, PartialEq)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
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
            .field("username", &self.username)
            .field("password", &"********")
            .finish()
    }
}

