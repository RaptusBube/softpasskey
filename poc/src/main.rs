use anyhow::Context;
use rand::Rng;
use std::io::{self, BufRead, Write};
use serde_cbor::Value;
mod ctap;
use ctap::{generate_key_cose, build_auth_data, cose_from_signing_key};
use rand::RngCore;
use std::collections::BTreeMap;
mod store;
use store::{insert, Entry};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use clap::Parser;
use std::path::PathBuf;
use p256::pkcs8::DecodePrivateKey;
mod browser;
pub const REPORT_LEN: usize = 64;
pub const CID_BROADCAST: u32 = 0xFFFF_FFFF;
pub const CMD_INIT: u8 = 0x86;
pub const CMD_CBOR: u8 = 0x90;
const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    browser: bool,
    #[arg(long, default_value_t = 9222)]
    port: u16,
    #[arg(long)]
    rp: Option<String>,
    #[arg(long)]
    usb: bool,
    #[arg(long, value_name = "PEM")]
    key: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    launch_chrome: bool,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let sk: p256::ecdsa::SigningKey = if let Some(path) = args.key.as_ref() {
        let pem = std::fs::read_to_string(path).with_context(|| format!("unable to read key at {}", path.display()))?;
        p256::ecdsa::SigningKey::from_pkcs8_pem(&pem).map_err(|e| anyhow::anyhow!("invalid key: {}", e))?
    } else {
        p256::ecdsa::SigningKey::random(&mut rand::thread_rng())
    };
    if args.browser {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        return rt.block_on(browser::run_browser_mode(args.port, args.rp.clone(), sk, args.launch_chrome));
    }
    if args.usb {
        #[cfg(windows)]
        {
            return run_usb();
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("USB mode supported only on Windows for now");
        }
    }
    run_pipe_with_key(Some(sk))
}
fn run_usb() -> anyhow::Result<()> {
    anyhow::bail!("USB mode not yet implemented – VHF kernel stub in progress")
}
fn run_pipe_with_key(user_key: Option<p256::ecdsa::SigningKey>) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let assigned_cid: u32 = rng.gen();
    eprintln!(
        "[softpasskey] started – waiting for 64-byte HID frames on stdin (hex encoded)"
    );
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let frame_bytes = hex::decode(&line.trim())
            .with_context(|| format!("expected hex, got '{}…'", &line[..line.len().min(16)]))?;
        let frame_bytes = if frame_bytes.len() < REPORT_LEN {
            let mut tmp = frame_bytes;
            tmp.resize(REPORT_LEN, 0);
            tmp
        } else if frame_bytes.len() == REPORT_LEN {
            frame_bytes
        } else {
            eprintln!("skipping frame with len {} (must be 64)", frame_bytes.len());
            continue;
        };
        let cid = u32::from_be_bytes([frame_bytes[0], frame_bytes[1], frame_bytes[2], frame_bytes[3]]);
        let cmd = frame_bytes[4];
        let is_init_cmd = cmd == CMD_INIT | 0x80;
        if cid == CID_BROADCAST && is_init_cmd {
            let payload_len = u16::from_be_bytes([frame_bytes[5], frame_bytes[6]]) as usize;
            if payload_len != 8 {
                eprintln!("INIT payload len unexpected: {}", payload_len);
                continue;
            }
            let nonce: [u8; 8] = frame_bytes[7..15].try_into().unwrap();
            let mut payload = Vec::with_capacity(17);
            payload.extend_from_slice(&nonce);
            payload.extend_from_slice(&assigned_cid.to_be_bytes());
            payload.extend_from_slice(&[2, 0, 0, 0, 0x05]);
            let mut resp = Vec::with_capacity(REPORT_LEN);
            resp.extend_from_slice(&assigned_cid.to_be_bytes());
            resp.push(CMD_INIT | 0x80);
            resp.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            resp.extend_from_slice(&payload);
            resp.resize(REPORT_LEN, 0);
            println!("{}", hex::encode_upper(resp));
            io::stdout().flush().ok();
        } else if cid == assigned_cid && cmd == CMD_CBOR | 0x80 {
            let total_len = u16::from_be_bytes([frame_bytes[5], frame_bytes[6]]) as usize;
            if total_len + 7 > frame_bytes.len() {
                eprintln!("payload truncated: expected {}, have {}", total_len, frame_bytes.len()-7);
            }
            if total_len == 0 {
                eprintln!("[softpasskey] empty CBOR payload");
                continue;
            }
            let subcmd = frame_bytes[7];
            let cbor_slice = &frame_bytes[8..8 + (total_len - 1).min(REPORT_LEN-8)];
            if subcmd != 0x01 {
                eprintln!("[softpasskey] unsupported subcommand 0x{:02x}", subcmd);
            }
            let cbor_val = serde_cbor::from_slice::<Value>(cbor_slice).unwrap_or(Value::Null);
            let rp_id_opt: Option<String> = if let Value::Map(ref map) = cbor_val {
                if let Some(Value::Map(rp_map)) = map.get(&Value::Integer(2)) {
                    if let Some(Value::Text(rp_id)) = rp_map.get(&Value::Text("id".into())) {
                        Some(rp_id.clone())
                    } else { None }
                } else { None }
            } else { None };
            let payload: Vec<u8>;
            payload = if subcmd == 0x01 {
                if let Some(rp_id) = rp_id_opt {
                    let (sk, cose_pub) = if let Some(ref k) = user_key {
                        (k.clone(), cose_from_signing_key(k))
                    } else {
                        generate_key_cose()
                    };
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
                    let mut p = Vec::with_capacity(1 + att_bytes.len());
                    p.push(0x00);
                    p.append(&mut att_bytes);
                    insert(cred_id, Entry { rp_id, key: sk, auth_data_prefix: auth_data });
                    p
                } else {
                    vec![CTAP2_ERR_UNSUPPORTED_OPTION]
                }
            } else if subcmd == 0x02 {
                if let Value::Map(ref m) = cbor_val {
                    if let Some(Value::Bytes(client_hash)) = m.get(&Value::Integer(1)) {
                        if let Some((cred_id_vec, entry)) = store::first() {
                            let mut auth_data = entry.auth_data_prefix.clone();
                            auth_data[32] = 0x01;
                            let mut msg = Vec::new();
                            msg.extend_from_slice(&auth_data);
                            msg.extend_from_slice(client_hash);
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
                            let mut p = Vec::with_capacity(1 + cbor_bytes.len());
                            p.push(0x00);
                            p.append(&mut cbor_bytes);
                            p
                        } else {
                            vec![0x2E]
                        }
                    } else {
                        vec![0x2E]
                    }
                } else {
                    vec![0x2E]
                }
            } else {
                vec![CTAP2_ERR_UNSUPPORTED_OPTION]
            };
            let frames = build_frames(assigned_cid, CMD_CBOR | 0x80, &payload);
            for f in frames {
                println!("{}", hex::encode_upper(f));
            }
            io::stdout().flush().ok();
        } else {
            eprintln!("[warn] unhandled frame (cid {:08x}, cmd 0x{:02x})", cid, cmd);
        }
    }
    Ok(())
}
pub fn build_frames(cid: u32, cmd_byte: u8, data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let total_len = data.len();
    let mut first = Vec::with_capacity(REPORT_LEN);
    first.extend_from_slice(&cid.to_be_bytes());
    first.push(cmd_byte);
    first.extend_from_slice(&(total_len as u16).to_be_bytes());
    let chunk_len = total_len.min(57);
    first.extend_from_slice(&data[..chunk_len]);
    first.resize(REPORT_LEN, 0);
    out.push(first);
    offset += chunk_len;
    let mut seq: u8 = 0;
    while offset < total_len {
        let mut frame = Vec::with_capacity(REPORT_LEN);
        frame.extend_from_slice(&cid.to_be_bytes());
        frame.push(seq);
        seq = seq.wrapping_add(1);
        let remaining = total_len - offset;
        let chunk = &data[offset..offset + remaining.min(59)];
        frame.extend_from_slice(chunk);
        frame.resize(REPORT_LEN, 0);
        out.push(frame);
        offset += chunk.len();
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_frame_building() {
        let cid = 0x01020304;
        let cmd = 0x90 | 0x80;
        let data = vec![0u8; 120];
        let frames = build_frames(cid, cmd, &data);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].len(), REPORT_LEN);
        assert_eq!(frames[1].len(), REPORT_LEN);
    }
}