use wasm_bindgen::prelude::*;

use crate::{LocalEncrypt, StorageBackend};

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct LocalEncryptJs {
    local_encrypt: LocalEncrypt,
}

#[wasm_bindgen]
impl LocalEncryptJs {
    pub fn new(username: String, password: String) -> js_sys::Promise {
        _ = console_log::init_with_level(log::Level::Debug);
        let future = async move {
            let storage_backend =
                StorageBackend::initiate_with_local_storage(&username, Some(&password)).await?;
            let local_encrypt = LocalEncrypt::builder()
                .with_backend(storage_backend)
                .build();

            log::debug!("LocalEncryptJs::new: {:?}", local_encrypt);
            Ok(JsValue::from_str("Initialized"))
        };
        wasm_bindgen_futures::future_to_promise(future)
    }
}
