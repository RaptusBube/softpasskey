use std::collections::BTreeMap;
use rand::RngCore;
use serde_cbor::Value;
use p256::ecdsa::{signature::Signer, Signature};
use crate::{ctap::{generate_key_cose, build_auth_data}, store::{insert, first, Entry}, CTAP2_ERR_UNSUPPORTED_OPTION};
pub fn handle_cbor_msg(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![vec![CTAP2_ERR_UNSUPPORTED_OPTION]];
    }
    let subcmd = data[0];
    let cbor_slice = &data[1..];
    match subcmd {
        0x01 => make_credential(cbor_slice),
        0x02 => get_assertion(cbor_slice),
        _ => vec![vec![CTAP2_ERR_UNSUPPORTED_OPTION]],
    }
}
fn make_credential(cbor_slice: &[u8]) -> Vec<Vec<u8>> {
    let value = match serde_cbor::from_slice::<Value>(cbor_slice) {
        Ok(v) => v,
        Err(_) => return vec![vec![CTAP2_ERR_UNSUPPORTED_OPTION]],
    };
    let rp_id = if let Value::Map(map) = &value {
        if let Some(Value::Map(rp_map)) = map.get(&Value::Integer(2)) {
            if let Some(Value::Text(id)) = rp_map.get(&Value::Text("id".into())) {
                id.clone()
            } else { return vec![vec![CTAP2_ERR_UNSUPPORTED_OPTION]] }
        } else { return vec![vec![CTAP2_ERR_UNSUPPORTED_OPTION]] }
    } else { return vec![vec![CTAP2_ERR_UNSUPPORTED_OPTION]] };
    let (sk, cose_pub) = generate_key_cose();
    let cose_pub_bytes = serde_cbor::to_vec(&cose_pub).unwrap();
    let mut cred_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cred_id);
    let auth_data = build_auth_data(&rp_id, &cred_id, &cose_pub_bytes);
    let mut a_map = BTreeMap::new();
    a_map.insert(Value::Text("fmt".into()), Value::Text("none".into()));
    a_map.insert(Value::Text("authData".into()), Value::Bytes(auth_data.clone()));
    a_map.insert(Value::Text("attStmt".into()), Value::Map(BTreeMap::new()));
    let att_obj = Value::Map(a_map);
    let mut att_bytes = serde_cbor::to_vec(&att_obj).unwrap();
    insert(cred_id, Entry { rp_id, key: sk, auth_data_prefix: auth_data });
    let mut payload = Vec::with_capacity(1 + att_bytes.len());
    payload.push(0x00);
    payload.append(&mut att_bytes);
    vec![payload]
}
fn get_assertion(cbor_slice: &[u8]) -> Vec<Vec<u8>> {
    let value = match serde_cbor::from_slice::<Value>(cbor_slice) {
        Ok(v) => v,
        Err(_) => return vec![vec![0x2E]],
    };
    let client_hash = if let Value::Map(map) = &value {
        if let Some(Value::Bytes(ch)) = map.get(&Value::Integer(1)) { ch.clone() } else { return vec![vec![0x2E]] }
    } else { return vec![vec![0x2E]] };
    let (cred_id_vec, entry) = match first() { Some(t) => t, None => return vec![vec![0x2E]] };
    let mut auth_data = entry.auth_data_prefix.clone();
    auth_data[32] = 0x01;
    let mut msg = Vec::new();
    msg.extend_from_slice(&auth_data);
    msg.extend_from_slice(&client_hash);
    let signature: Signature = entry.key.sign(&msg);
    let mut resp_map = BTreeMap::new();
    resp_map.insert(Value::Text("credential".into()), Value::Map({
        let mut cm = BTreeMap::new();
        cm.insert(Value::Text("id".into()), Value::Bytes(cred_id_vec.clone()));
        cm.insert(Value::Text("type".into()), Value::Text("public-key".into()));
        cm
    }));
    resp_map.insert(Value::Text("authData".into()), Value::Bytes(auth_data));
    resp_map.insert(Value::Text("signature".into()), Value::Bytes(signature.to_der().as_bytes().to_vec()));
    let mut cbor_bytes = serde_cbor::to_vec(&Value::Map(resp_map)).unwrap();
    let mut payload = Vec::with_capacity(1 + cbor_bytes.len());
    payload.push(0x00);
    payload.append(&mut cbor_bytes);
    vec![payload]
}