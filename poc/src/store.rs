use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use p256::ecdsa::SigningKey;
pub type CredId = [u8; 16];
#[derive(Clone)]
pub struct Entry {
    pub rp_id: String,
    pub key: SigningKey,
    pub auth_data_prefix: Vec<u8>,
}
static DB: Lazy<Mutex<HashMap<Vec<u8>, Entry>>> = Lazy::new(|| Mutex::new(HashMap::new()));
pub fn insert(cred_id: CredId, entry: Entry) {
    DB.lock().unwrap().insert(cred_id.to_vec(), entry);
}
pub fn get(cred_id: &[u8]) -> Option<Entry> {
    DB.lock().unwrap().get(cred_id).cloned()
}
pub fn first() -> Option<(Vec<u8>, Entry)> {
    DB.lock().unwrap().iter().next().map(|(k, v)| (k.clone(), v.clone()))
}