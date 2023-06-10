use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug)]
pub struct ItemMetaData {
    id: String,
    tags: Option<HashMap<String, String>>,
}

impl ItemMetaData {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            tags: None,
        }
    }

    pub fn new_with_tags(id: &str, tags: HashMap<String, String>) -> Self {
        Self {
            id: id.to_string(),
            tags: Some(tags),
        }
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn tags(&self) -> Option<HashMap<String, String>> {
        self.tags.clone()
    }
}
