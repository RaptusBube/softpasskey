use rand::rngs::OsRng;
use p256::ecdsa::SigningKey;
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub fn generate_key_cose() -> (SigningKey, Value) {
    let sk = SigningKey::random(&mut OsRng);
    let pub_bytes = sk.verifying_key().to_encoded_point(false);
    let x = pub_bytes.x().unwrap();
    let y = pub_bytes.y().unwrap();
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(1), Value::Integer(2));
    map.insert(Value::Integer(3), Value::Integer(-7));
    map.insert(Value::Integer(-1), Value::Integer(1));
    map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
    map.insert(Value::Integer(-3), Value::Bytes(y.to_vec()));
    let cose_map = Value::Map(map);
    (sk, cose_map)
}
pub fn build_auth_data(rp_id: &str, cred_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    let rp_hash = hasher.finalize();
    out.extend_from_slice(&rp_hash);
    out.extend_from_slice(&[0x41]);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&[0u8; 16]);
    let cred_len: u16 = cred_id.len() as u16;
    out.extend_from_slice(&cred_len.to_be_bytes());
    out.extend_from_slice(cred_id);
    out.extend_from_slice(cose_key);
    out
}
pub fn cose_from_signing_key(sk: &SigningKey) -> Value {
    let pub_bytes = sk.verifying_key().to_encoded_point(false);
    let x = pub_bytes.x().unwrap();
    let y = pub_bytes.y().unwrap();
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(1), Value::Integer(2));
    map.insert(Value::Integer(3), Value::Integer(-7));
    map.insert(Value::Integer(-1), Value::Integer(1));
    map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
    map.insert(Value::Integer(-3), Value::Bytes(y.to_vec()));
    Value::Map(map)
}