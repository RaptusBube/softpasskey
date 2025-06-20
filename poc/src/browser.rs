use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use anyhow::Context;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio::net::TcpStream;
use std::process::{Command, Child};
use std::path::PathBuf;
use tempfile::TempDir;
use std::time::{Duration, Instant};
type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn cdp_send(ws: &mut Ws, next_id: &mut u32, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let id = *next_id;
    *next_id += 1;
    let msg = json!({"id": id, "method": method, "params": params});
    ws.send(Message::Text(msg.to_string())).await?;
    while let Some(m) = ws.next().await {
        let txt = m?.into_text()?;
        let v: serde_json::Value = serde_json::from_str(&txt)?;
        if v.get("id") == Some(&json!(id)) {
            if v.get("error").is_some() {
                return Err(anyhow::anyhow!("CDP error: {}", v["error"]));
            }
            return Ok(v["result"].clone());
        }
    }
    anyhow::bail!("cdp socket closed");
}
pub async fn run_browser_mode(port: u16, rp_opt: Option<String>, sk: SigningKey, spawn: bool) -> anyhow::Result<()> {
    let _chrome_tmp;
    let mut _child: Option<Child> = None;
    if spawn {
        let chrome_path = locate_chrome()?;
        _chrome_tmp = TempDir::new()?;
        let user_dir = _chrome_tmp.path().to_path_buf();
        let mut cmd = Command::new(chrome_path);
        cmd.arg(format!("--remote-debugging-port={}", port))
           .arg(format!("--user-data-dir={}", user_dir.display()))
           .arg("--disable-background-networking")
           .arg("--disable-component-extensions-with-background-pages")
           .arg("--mute-audio")
           .arg("--no-first-run")
           .arg("--disable-fre");
        _child = Some(cmd.spawn()?);
        wait_cdp(port, Duration::from_secs(10))?;
    }
    let ws_url = fetch_ws_url(port)?;
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await?;
    let mut next_id = 1u32;
    cdp_send(&mut ws, &mut next_id, "WebAuthn.enable", json!({"enableUI": true})).await?;
    let res = cdp_send(&mut ws,&mut next_id, "WebAuthn.addVirtualAuthenticator",
        json!({"options": {"protocol":"ctap2","transport":"usb","hasResidentKey":true,"hasUserVerification":true}})).await?;
    let auth_id = res.get("authenticatorId").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("CDP addVirtualAuthenticator missing authenticatorId: {:?}", res))?.to_owned();
    let _ = cdp_send(&mut ws, &mut next_id, "WebAuthn.setAutomaticPresenceSimulation", json!({"authenticatorId": auth_id, "enabled": true})).await;
    let _ = cdp_send(&mut ws, &mut next_id, "WebAuthn.setUserVerified", json!({"authenticatorId": auth_id, "isUserVerified": true})).await;
    if let Some(rp) = rp_opt {
        inject_credential(&mut ws, &mut next_id, &auth_id, &rp, &sk).await?;
        println!("[softpasskey] injected deterministic credential for rp '{}'.", rp);
    }
    println!("[softpasskey] virtual authenticator ready – keep this process running.");
    while let Some(msg) = ws.next().await {
        let txt = msg?.into_text()?;
        println!("[cdp] {}", txt);
    }
    Ok(())
}
fn fetch_ws_url(port: u16) -> anyhow::Result<String> {
    let list_url = format!("http://127.0.0.1:{}/json", port);
    if let Ok(res) = ureq::get(&list_url).call() {
        if let Ok(arr) = res.into_json::<serde_json::Value>() {
            if let Some(arr) = arr.as_array() {
                if let Some(first) = arr.iter().find(|v| v["type"]=="page") {
                    if let Some(ws) = first["webSocketDebuggerUrl"].as_str() {
                        return Ok(ws.to_owned());
                    }
                }
            }
        }
    }
    let url = format!("http://127.0.0.1:{}/json/version", port);
    let resp: serde_json::Value = ureq::get(&url).call().context("fetch /json/version")?.into_json()?;
    Ok(resp["webSocketDebuggerUrl"].as_str().unwrap().to_owned())
}
async fn inject_credential(ws: &mut Ws, next_id: &mut u32, auth_id: &str, rp: &str, sk: &SigningKey) -> anyhow::Result<()> {
    let id = *next_id; *next_id += 1;
    let pkcs8 = sk.to_pkcs8_der().map_err(|e| anyhow::anyhow!("pkcs8 encode: {}", e))?.as_bytes().to_vec();
    let cred_id: [u8;16] = rand::random();
    let msg = json!({
        "id": id,
        "method": "WebAuthn.addCredential",
        "params": {
            "authenticatorId": auth_id,
            "credential": {
                "credentialId": b64.encode(cred_id),
                "rpId": rp,
                "privateKey": b64.encode(pkcs8),
                "signCount": 0,
                "isResidentCredential": true,
                "userHandle": b64.encode(&[0x01,0x02])
            }
        }
    });
    ws.send(Message::Text(msg.to_string())).await?;
    while let Some(m) = ws.next().await {
        let txt = m?.into_text()?;
        let v: serde_json::Value = serde_json::from_str(&txt)?;
        if v.get("id") == Some(&json!(id)) { break; }
    }
    Ok(())
}
fn wait_cdp(port: u16, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        if let Ok(_) = ureq::get(&format!("http://127.0.0.1:{}/json/version", port)).call() {
            return Ok(())
        }
        if start.elapsed() > timeout {
            anyhow::bail!("chrome did not open debugging port {}", port);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn locate_chrome() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            r"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        ];
        for p in &candidates {
            let pb = PathBuf::from(p);
            if pb.exists() {return Ok(pb)}
        }
    }
    anyhow::bail!("could not find chrome executable; supply manually and run browser first")
}