//! `pdfcraft-cli seal-worker`: the e-sign sealing service, driven over raw HTTP on loopback.
//!
//! Each test starts its own worker on `127.0.0.1:0` with the test chain (`crates/sign/tests/data/chain.p12`)
//! and reads the port it bound from `--port-file`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use pdfcraft_engine::Session;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_pdfcraft-cli");
const SECRET: &str = "worker-test-secret-0123456789abcdef";
const OWNER_REFUSAL: &str = "This PDF is already signed; a new signature would break it";

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn hmac(text: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
    m.update(text.as_bytes());
    hex(&m.finalize().into_bytes())
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(v.as_str().expect("base64 text")).expect("base64")
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() as i64
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh nonce: 32 lowercase hex.
fn nonce() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    sha(format!("{}-{n}-{nanos}", std::process::id()).as_bytes())[..32].to_string()
}

/// A directory of its own for one worker.
fn workdir(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-worker-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// The key, its password and the HMAC secret in `dir`, each readable by this user only.
fn secrets(dir: &Path, password: &str) {
    let p12 = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/sign/tests/data/chain.p12")).expect("chain.p12");
    std::fs::write(dir.join("seal.p12"), p12).expect("key");
    std::fs::write(dir.join("seal_password"), format!("{password}\n")).expect("password");
    std::fs::write(dir.join("seal_hmac"), format!("{SECRET}\n")).expect("secret");
    #[cfg(unix)]
    for f in ["seal.p12", "seal_password", "seal_hmac"] {
        chmod(&dir.join(f), 0o600);
    }
}

fn command(dir: &Path, extra: &[&str]) -> Command {
    let mut c = Command::new(BIN);
    c.arg("seal-worker").arg("--listen").arg("127.0.0.1:0");
    c.arg("--key-file").arg(dir.join("seal.p12"));
    c.arg("--key-password-file").arg(dir.join("seal_password"));
    c.arg("--secret-file").arg(dir.join("seal_hmac"));
    c.arg("--port-file").arg(dir.join("port"));
    c.args(extra);
    c.stdin(Stdio::null()).stdout(Stdio::null());
    c.stderr(std::fs::File::create(dir.join("stderr.log")).expect("log"));
    c
}

struct Worker {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON reply")
    }
}

/// What a request sent, for the reply MAC and the log check.
struct Sent {
    mac: String,
    nonce: String,
}

fn start_in(dir: &Path, extra: &[&str]) -> Worker {
    let child = command(dir, extra).spawn().expect("starts");
    let mut worker = Worker { child, port: 0, dir: dir.to_path_buf() };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(port) = std::fs::read_to_string(dir.join("port")).ok().and_then(|p| p.trim().parse().ok()) {
            worker.port = port;
            return worker;
        }
        if let Ok(Some(status)) = worker.child.try_wait() {
            panic!("the worker exited ({status}): {}", std::fs::read_to_string(dir.join("stderr.log")).unwrap_or_default());
        }
        assert!(Instant::now() < deadline, "the worker did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn start(name: &str, extra: &[&str]) -> Worker {
    let dir = workdir(name);
    secrets(&dir, "test");
    start_in(&dir, extra)
}

impl Worker {
    /// Send raw bytes; the whole reply (the worker closes the connection).
    fn raw(&self, request: &[u8]) -> Reply {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).expect("connects");
        s.set_read_timeout(Some(Duration::from_secs(120))).expect("timeout");
        s.write_all(request).expect("sends");
        let mut out = Vec::new();
        s.read_to_end(&mut out).expect("reads");
        let end = out.windows(4).position(|w| w == b"\r\n\r\n").expect("a reply head") + 4;
        let head = String::from_utf8_lossy(&out[..end]).to_string();
        let mut lines = head.split("\r\n");
        let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|c| c.parse().ok()).expect("status");
        let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
        Reply { status, headers, body: out[end..].to_vec() }
    }

    /// A request with the given time and nonce, signed with `secret`'s MAC unless `mac` is given.
    fn send(&self, method: &str, path: &str, body: &[u8], time: i64, nonce: &str, mac: Option<&str>) -> (Reply, Sent) {
        let good = hmac(&format!("{method}\n{path}\n{}\n{time}\n{nonce}", sha(body)));
        let mac = mac.map(str::to_string).unwrap_or(good);
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: seal\r\nX-Craft-Seal-Time: {time}\r\nX-Craft-Seal-Nonce: {nonce}\r\nX-Craft-Seal-Mac: {mac}\r\n"
        );
        if method == "POST" {
            req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(body);
        (self.raw(&bytes), Sent { mac, nonce: nonce.to_string() })
    }

    fn get(&self, path: &str) -> Reply {
        self.send("GET", path, b"", now(), &nonce(), None).0
    }

    fn post(&self, path: &str, body: &Value) -> Reply {
        self.send("POST", path, serde_json::to_string(body).expect("json").as_bytes(), now(), &nonce(), None).0
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.dir.join("stderr.log")).unwrap_or_default()
    }
}

fn blank() -> Vec<u8> {
    Session::new().with_clock(|| 1_700_000_000).create_blank(612.0, 792.0, 1).expect("blank").to_vec()
}

const RID: u64 = 7;

fn prepare_body(pdf: &[u8]) -> Value {
    json!({
        "pdf": b64(pdf),
        "request_id": RID,
        "header": {
            "title": "Contract", "requester_uid": "alice", "requester_name": "Alice Doe",
            "created_utc": "2026-11-24T08:00:00Z", "instance": "workspace.treeo.id", "organisation": "PT Solusi Hutan Digital",
        },
        "signers": [
            { "position": 1, "uid": "bob", "display_name": "Bob Brown", "placement": null },
            { "position": 2, "uid": "carol", "display_name": "Carol Chan", "placement": { "page": 0, "rect": [100, 100, 280, 140] } },
        ],
        "date": "2026-11-24T08:00:00Z",
    })
}

fn seal_body(pdf: &[u8], position: u32, last: bool, tsa_url: Option<&str>, graphic: Value) -> Value {
    let (uid, name) = if position == 1 { ("bob", "Bob Brown") } else { ("carol", "Carol Chan") };
    json!({
        "pdf": b64(pdf),
        "request_id": RID,
        "signer": { "position": position, "uid": uid, "display_name": name },
        "graphic": graphic,
        "row_text": format!("{name} ({uid}) signed"),
        "date": format!("2026-11-24T09:0{position}:00Z"),
        "tsa_url": tsa_url,
        "final": if last {
            json!({ "completed_text": "Completed; 2 signers", "date": "2026-11-24T09:05:00Z",
                "instance": "cloud.example.org", "organisation": "Example Org" })
        } else {
            Value::Null
        },
    })
}

fn prepared(w: &Worker) -> Vec<u8> {
    let r = w.post("/v1/prepare", &prepare_body(&blank()));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    unb64(&r.json()["pdf"])
}

#[test]
fn health_reports_subject_fingerprint_and_expiry() {
    let w = start("health", &[]);
    let r = w.get("/v1/health");
    assert_eq!(r.status, 200);
    let h = r.json();
    assert_eq!(h["ok"], true);
    let p12 = std::fs::read(w.dir.join("seal.p12")).expect("key");
    let id = pdfcraft_engine::sign::pkcs12::open(&p12, "test").expect("opens");
    assert_eq!(h["cert"]["sha256"], sha(&id.certificate.raw));
    assert_eq!(h["cert"]["subject"], id.certificate.subject.display());
    assert_eq!(h["cert"]["issuer"], id.certificate.issuer.display());
    let t = id.certificate.not_after;
    let not_after = h["cert"]["not_after"].as_str().expect("text");
    assert!(not_after.starts_with(&format!("{:04}-{:02}-{:02}T", t.year, t.month, t.day)) && not_after.ends_with('Z'), "{not_after}");
    let chain = h["cert"]["chain_pem"].as_array().expect("chain");
    let leaf = pdfcraft_engine::sign::x509::load_certificates(chain[0].as_str().expect("pem").as_bytes()).expect("pem");
    assert_eq!(leaf[0], id.certificate, "the chain starts with the sealing certificate");
    let root = pdfcraft_engine::sign::x509::load_certificates(h["root_pem"].as_str().expect("root").as_bytes()).expect("pem");
    assert!(root[0].is_self_signed(), "the root is a self-signed CA certificate");
    assert_eq!(chain.last(), Some(&h["root_pem"]), "the chain ends at the root");
}

#[test]
fn bad_mac_is_401() {
    let w = start("badmac", &[]);
    let (r, _) = w.send("GET", "/v1/health", b"", now(), &nonce(), Some(&"0".repeat(64)));
    assert_eq!(r.status, 401);
    // The MAC of another body does not do either.
    let other = hmac(&format!("GET\n/v1/health\n{}\n{}\n{}", sha(b"x"), now(), "a".repeat(32)));
    let (r, _) = w.send("GET", "/v1/health", b"", now(), &"a".repeat(32), Some(&other));
    assert_eq!(r.status, 401);
    assert_eq!(w.get("/v1/health").status, 200, "the right MAC passes");
}

#[test]
fn stale_time_is_401() {
    let w = start("stale", &[]);
    assert_eq!(w.send("GET", "/v1/health", b"", now() - 90, &nonce(), None).0.status, 401);
    assert_eq!(w.send("GET", "/v1/health", b"", now() + 90, &nonce(), None).0.status, 401);
    assert_eq!(w.send("GET", "/v1/health", b"", now() - 30, &nonce(), None).0.status, 200, "well inside the 60 s window");
}

#[test]
fn reused_nonce_is_401() {
    let w = start("nonce", &[]);
    let n = nonce();
    assert_eq!(w.send("GET", "/v1/health", b"", now(), &n, None).0.status, 200);
    assert_eq!(w.send("GET", "/v1/health", b"", now(), &n, None).0.status, 401);
}

#[test]
fn reply_mac_matches_request_mac_and_body() {
    let w = start("replymac", &[]);
    let (r, sent) = w.send("GET", "/v1/health", b"", now(), &nonce(), None);
    let want = hmac(&format!("reply\n{}\n{}", sent.mac, sha(&r.body)));
    assert_eq!(r.header("X-Craft-Seal-Reply"), Some(want.as_str()));
    // A refusal carries one too, over its own body.
    let body = br#"{"pdf":"not base64!"}"#;
    let (r, sent) = w.send("POST", "/v1/inspect", body, now(), &nonce(), None);
    assert_eq!(r.status, 400);
    assert_eq!(r.header("X-Craft-Seal-Reply"), Some(hmac(&format!("reply\n{}\n{}", sent.mac, sha(&r.body))).as_str()));
    assert_ne!(r.json(), json!({}), "never an empty object");
}

#[test]
fn oversize_body_is_413() {
    let w = start("oversize", &[]);
    let n = nonce();
    let mac = "0".repeat(64);
    let head = format!(
        "POST /v1/inspect HTTP/1.1\r\nHost: seal\r\nX-Craft-Seal-Time: {}\r\nX-Craft-Seal-Nonce: {n}\r\nX-Craft-Seal-Mac: {mac}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        now(),
        96 * 1024 * 1024 + 1
    );
    let r = w.raw(head.as_bytes());
    assert_eq!(r.status, 413, "refused from the length alone, before the body");
    assert_eq!(r.header("X-Craft-Seal-Reply"), Some(hmac(&format!("reply\n{mac}\n{}", sha(&r.body))).as_str()));
}

#[test]
fn prepare_then_seal_round_trip_valid() {
    let w = start("roundtrip", &[]);
    let base = prepared(&w);
    let r = w.post("/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "name" })));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let first = r.json();
    let one = unb64(&first["pdf"]);
    assert!(one.starts_with(&base), "an incremental update");
    assert_eq!(first["sha256"], sha(&one));
    assert_eq!(first["after_signer_sha256"], first["sha256"], "no final seal: one revision");
    assert_eq!(first["timestamped"], false, "tsa_url null: B-B");

    let strokes = json!({ "kind": "strokes", "strokes": [[[0.1, 0.2], [0.5, 0.6], [0.9, 0.3]]] });
    let r = w.post("/v1/seal", &seal_body(&one, 2, true, None, strokes));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let last = r.json();
    let two = unb64(&last["pdf"]);
    assert!(two.starts_with(&one));
    assert_eq!(last["sha256"], sha(&two));
    assert_ne!(last["after_signer_sha256"], last["sha256"], "the final seal is a revision of its own");
    let signed: Vec<&Value> = last["signatures"].as_array().expect("list").iter().filter(|s| s["signed"] == true).collect();
    assert_eq!(signed.len(), 3, "two signers and the seal");
    assert!(signed.iter().all(|s| s["status"] == "valid" && s["modification"] != "disallowed"), "{signed:?}");

    // inspect checks against the same root, so it says the same.
    let r = w.post("/v1/inspect", &json!({ "pdf": b64(&two) }));
    assert_eq!(r.status, 200);
    let i = r.json();
    assert_eq!(i["sha256"], last["sha256"]);
    assert_eq!(i["signatures"], last["signatures"]);
    assert_eq!(i["signed"], true);
    let health = w.get("/v1/health").json();
    assert_eq!(i["root_pem"], health["root_pem"]);
}

#[test]
fn already_signed_is_422_with_owner_wording() {
    let w = start("signed", &[]);
    let signed = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/sign/tests/data/openssl-signed.pdf")).expect("fixture");
    let r = w.post("/v1/prepare", &prepare_body(&signed));
    assert_eq!(r.status, 422);
    assert_eq!(r.json(), json!({ "error": "already_signed", "message": OWNER_REFUSAL }));
}

#[test]
fn graphic_over_caps_is_400() {
    let w = start("caps", &[]);
    let base = prepared(&w);
    let stroke = json!([[0.1, 0.1], [0.2, 0.2]]);
    let too_many = json!({ "kind": "strokes", "strokes": vec![stroke; 65] });
    let r = w.post("/v1/seal", &seal_body(&base, 1, false, None, too_many));
    assert_eq!(r.status, 400);
    let e = r.json();
    assert_eq!(e["error"], "graphic_too_large");
    assert!(e.get("pdf").is_none(), "nothing written");
    let nan = w.post("/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "strokes", "strokes": [[[0.1, "NaN"]]] })));
    assert_eq!(nan.status, 400, "{}", String::from_utf8_lossy(&nan.body));
}

#[test]
fn tsa_unreachable_is_503_and_writes_nothing() {
    let w = start("tsadown", &[]);
    let base = prepared(&w);
    let r = w.post("/v1/seal", &seal_body(&base, 1, false, Some("https://127.0.0.1:9/tsr"), json!({ "kind": "name" })));
    assert_eq!(r.status, 503);
    let e = r.json();
    assert_eq!(e["error"], "tsa_unavailable");
    assert_eq!(e["message"], "The timestamp service did not answer; nothing was signed. Try again.");
    assert!(e.get("pdf").is_none());
    // The same bytes can be sealed afterwards: the field was not used up.
    assert_eq!(w.post("/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "name" }))).status, 200);
}

#[test]
fn dev_tsa_marks_timestamped() {
    let w = start("devtsa", &["--insecure-dev-tsa"]);
    let base = prepared(&w);
    let r = w.post("/v1/seal", &seal_body(&base, 1, false, Some("https://freetsa.org/tsr"), json!({ "kind": "name" })));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["timestamped"], true);
    let plain = w.post("/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "name" })));
    assert_eq!(plain.json()["timestamped"], false, "tsa_url null stays B-B");
}

#[test]
fn http_tsa_refused_without_allow_http_tsa() {
    // Readable secrets are another switch: they never allow http:// (N9, P5 nit).
    for extra in [&[][..], &["--allow-readable-secrets"][..]] {
        let w = start("httptsa", extra);
        let base = prepared(&w);
        let r = w.post("/v1/seal", &seal_body(&base, 1, false, Some("http://127.0.0.1:9/tsr"), json!({ "kind": "name" })));
        assert_eq!(r.status, 400, "{extra:?}");
        assert_eq!(r.json()["error"], "bad_tsa_url");
    }
    // A worker allowed http:// takes it, and finds nobody there.
    let dev = start("httptsa-dev", &["--allow-http-tsa"]);
    let base = prepared(&dev);
    let r = dev.post("/v1/seal", &seal_body(&base, 1, false, Some("http://127.0.0.1:9/tsr"), json!({ "kind": "name" })));
    assert_eq!(r.status, 503);
    assert_eq!(r.json()["error"], "tsa_unavailable");
}

/// Start a worker in `dir` and wait for it to exit; its stderr. Fails if it starts listening.
fn refused_start(dir: &Path, why: &str) -> String {
    let mut child = command(dir, &[]).spawn().expect("spawns");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().expect("waits") {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{why}: the worker started");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success(), "{why}");
    assert!(!dir.join("port").exists(), "{why}: it never listened");
    std::fs::read_to_string(dir.join("stderr.log")).unwrap_or_default()
}

/// A key, password or secret file that group or others can read or change stops the start
/// (P5 review m10: write bits too; N9: group-read 0640 and 0440 too), unless --allow-readable-secrets.
#[cfg(unix)]
#[test]
fn world_readable_key_refuses_to_start() {
    for file in ["seal.p12", "seal_password", "seal_hmac"] {
        for mode in [0o644, 0o604, 0o620, 0o602, 0o640, 0o440, 0o660] {
            let dir = workdir("readable");
            secrets(&dir, "test");
            chmod(&dir.join(file), mode);
            let why = format!("{file} {mode:o}");
            assert!(refused_start(&dir, &why).contains("group or others"), "{why}: says why");
        }
        // --allow-readable-secrets lets it start; --allow-http-tsa does not.
        let dir = workdir("readable-dev");
        secrets(&dir, "test");
        chmod(&dir.join(file), 0o644);
        assert!(refused_start_with(&dir, &["--allow-http-tsa"], "http only").contains("group or others"));
        let w = start_in(&dir, &["--allow-readable-secrets"]);
        assert_eq!(w.get("/v1/health").status, 200);
        // 0400 (read-only for the owner, as the stacks mount them) is fine without any switch.
        let dir = workdir("readonly");
        secrets(&dir, "test");
        chmod(&dir.join(file), 0o400);
        assert_eq!(start_in(&dir, &[]).get("/v1/health").status, 200, "{file} 0400");
    }
}

/// Start a worker in `dir` with `extra`, and wait for it to exit; its stderr.
fn refused_start_with(dir: &Path, extra: &[&str], why: &str) -> String {
    let mut child = command(dir, extra).spawn().expect("spawns");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().expect("waits") {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{why}: the worker started");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success(), "{why}");
    std::fs::read_to_string(dir.join("stderr.log")).unwrap_or_default()
}

/// N9: the switches that mixed two jobs, and the names the worker made up, are gone (ruling I1).
#[test]
fn removed_options_refuse_to_start() {
    for extra in [&["--insecure-dev"][..], &["--instance", "x"][..], &["--organisation", "y"][..]] {
        let dir = workdir("removed");
        secrets(&dir, "test");
        assert!(refused_start_with(&dir, extra, &format!("{extra:?}")).contains("unknown option"), "{extra:?}");
    }
}

/// Ruling I1: the final seal names the instance and organisation the request sends; without them it is refused.
#[test]
fn a_final_seal_without_instance_or_organisation_is_400() {
    let w = start("final-names", &[]);
    let base = prepared(&w);
    let one = unb64(&w.post("/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "name" }))).json()["pdf"]);
    for missing in ["instance", "organisation"] {
        let mut body = seal_body(&one, 2, true, None, json!({ "kind": "name" }));
        body["final"].as_object_mut().expect("final").remove(missing);
        let r = w.post("/v1/seal", &body);
        assert_eq!(r.status, 400, "{missing}: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["error"], "bad_json");
        assert!(r.json()["message"].as_str().unwrap_or_default().contains(missing));
        body["final"][missing] = json!("");
        assert_eq!(w.post("/v1/seal", &body).status, 400, "{missing} empty");
    }
    let r = w.post("/v1/seal", &seal_body(&one, 2, true, None, json!({ "kind": "name" })));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(!w.stderr().contains("worker's own names"));
}

/// The dev timestamp authority answers whatever address the request names, http:// too (the e2e stack).
#[test]
fn dev_tsa_takes_an_http_address() {
    let w = start("devtsa-http", &["--insecure-dev-tsa"]);
    let base = prepared(&w);
    let r = w.post("/v1/seal", &seal_body(&base, 1, false, Some("http://dev-tsa.invalid/tsr"), json!({ "kind": "name" })));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["timestamped"], true);
}

/// n6: leading and trailing whitespace is trimmed from the secret file, as PHP trims CRAFT_SEAL_SECRET.
#[test]
fn the_secret_is_trimmed_at_both_ends() {
    let dir = workdir("secret-trim");
    secrets(&dir, "test");
    std::fs::write(dir.join("seal_hmac"), format!(" \t{SECRET}\r\n")).expect("secret");
    #[cfg(unix)]
    chmod(&dir.join("seal_hmac"), 0o600);
    assert_eq!(start_in(&dir, &[]).get("/v1/health").status, 200, "the MAC of the trimmed secret");
}

/// P5 review m12: a Content-Length with a sign is malformed; one too long for memory is too large.
#[test]
fn content_length_digits() {
    let w = start("content-length", &[]);
    let head = |len: &str| format!("POST /v1/inspect HTTP/1.1\r\nHost: seal\r\nContent-Length: {len}\r\n\r\n");
    for bad in ["+5", "-5", "5 5", "0x5", " "] {
        let r = w.raw(head(bad).as_bytes());
        assert_eq!(r.status, 400, "{bad:?}");
        assert_eq!(r.json()["error"], "bad_request");
    }
    let r = w.raw(head(&"9".repeat(25)).as_bytes());
    assert_eq!(r.status, 413, "25 digits");
    assert_eq!(r.json()["error"], "too_large");
}

/// P5 review m6: a client that sends `Expect: 100-continue` (Guzzle over 1 MB) gets `100 Continue`
/// at once, before it sends the body, and then its answer.
#[test]
fn expect_100_continue_is_answered() {
    let w = start("expect", &[]);
    let body = serde_json::to_vec(&json!({ "pdf": b64(&blank()) })).expect("json");
    let (time, n) = (now(), nonce());
    let mac = hmac(&format!("POST\n/v1/inspect\n{}\n{time}\n{n}", sha(&body)));
    let head = format!(
        "POST /v1/inspect HTTP/1.1\r\nHost: seal\r\nX-Craft-Seal-Time: {time}\r\nX-Craft-Seal-Nonce: {n}\r\nX-Craft-Seal-Mac: {mac}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        body.len()
    );
    let mut s = TcpStream::connect(("127.0.0.1", w.port)).expect("connects");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    s.write_all(head.as_bytes()).expect("sends the head");
    let started = Instant::now();
    let want = b"HTTP/1.1 100 Continue\r\n\r\n";
    let mut got = vec![0u8; want.len()];
    s.read_exact(&mut got).expect("100 Continue before the body");
    assert_eq!(&got[..], &want[..]);
    assert!(started.elapsed() < Duration::from_secs(2));
    s.write_all(&body).expect("sends the body");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("reads");
    assert!(out.starts_with(b"HTTP/1.1 200 "), "{}", String::from_utf8_lossy(&out[..out.len().min(200)]));
}

#[test]
fn a_short_secret_refuses_to_start() {
    let dir = workdir("short-secret");
    secrets(&dir, "test");
    std::fs::write(dir.join("seal_hmac"), "x".repeat(31)).expect("secret");
    #[cfg(unix)]
    chmod(&dir.join("seal_hmac"), 0o600);
    let err = refused_start(&dir, "a 31-byte secret");
    assert!(err.contains("shorter than"));
    // n6: sign-setup does not make the secret; it reads CRAFT_SEAL_SECRET.
    assert!(err.contains("same value as CRAFT_SEAL_SECRET"), "{err}");
    assert!(!err.contains("sign-setup made"), "{err}");
}

#[test]
fn seal_calls_past_the_rate_limit_are_429() {
    let w = start("ratelimit", &[]);
    // Malformed seal calls are cheap, and the limit counts every authenticated seal call. On a busy
    // machine the 10 s window can slide while the calls are made; then the first 429 comes later,
    // never earlier (N9: robust under load).
    let started = Instant::now();
    let mut statuses = Vec::new();
    while statuses.len() < 200 && statuses.last() != Some(&429) {
        statuses.push(w.post("/v1/seal", &json!({})).status);
    }
    let first = statuses.iter().position(|s| *s == 429).expect("a 429 comes");
    assert!(statuses[..first].iter().all(|s| *s == 400), "{statuses:?}");
    assert!(first >= 30, "never before the 31st call: {statuses:?}");
    if started.elapsed() < Duration::from_secs(9) {
        assert_eq!(first, 30, "one past the limit, when the calls fit in the window");
    }
    assert_eq!(w.get("/v1/health").status, 200, "other calls are not limited");
}

#[test]
fn a_chunked_body_is_411() {
    let w = start("chunked", &[]);
    let r = w.raw(b"POST /v1/inspect HTTP/1.1\r\nHost: seal\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert_eq!(r.status, 411);
    assert_eq!(r.json()["error"], "bad_request");
}

#[test]
fn an_oversize_head_is_431() {
    let w = start("bighead", &[]);
    let r = w.raw(format!("GET /v1/health HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(20_000)).as_bytes());
    assert_eq!(r.status, 431);
}

#[test]
fn a_request_that_stops_arriving_is_dropped() {
    let w = start("slow", &[]);
    let mut s = TcpStream::connect(("127.0.0.1", w.port)).expect("connects");
    s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: se").expect("sends half a head");
    s.set_read_timeout(Some(Duration::from_secs(90))).expect("timeout");
    let mut out = Vec::new();
    let read = s.read_to_end(&mut out);
    assert!(read.is_ok(), "the worker closed the connection (not our own timeout): {read:?}");
    assert!(out.is_empty(), "with no answer");
    assert_eq!(w.get("/v1/health").status, 200, "and serves the next");
}

#[test]
fn a_ninth_connection_waits_for_a_free_slot() {
    let w = start("cap", &[]);
    // Eight connections that never finish their request hold every slot.
    let holders: Vec<TcpStream> = (0..8)
        .map(|_| {
            let mut s = TcpStream::connect(("127.0.0.1", w.port)).expect("connects");
            s.write_all(b"GET /v1/health HTTP/1.1\r\n").expect("sends");
            s
        })
        .collect();
    let mut ninth = TcpStream::connect(("127.0.0.1", w.port)).expect("connects (backlog)");
    let n = nonce();
    let t = now();
    let mac = hmac(&format!("GET\n/v1/health\n{}\n{t}\n{n}", sha(b"")));
    let req =
        format!("GET /v1/health HTTP/1.1\r\nHost: seal\r\nX-Craft-Seal-Time: {t}\r\nX-Craft-Seal-Nonce: {n}\r\nX-Craft-Seal-Mac: {mac}\r\n\r\n");
    ninth.write_all(req.as_bytes()).expect("sends");
    ninth.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let mut buf = [0u8; 64];
    assert!(ninth.read(&mut buf).is_err(), "no answer while eight connections are open");
    drop(holders);
    ninth.set_read_timeout(Some(Duration::from_secs(30))).expect("timeout");
    let mut out = Vec::new();
    ninth.read_to_end(&mut out).expect("answered once a slot is free");
    assert!(out.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&out));
}

#[test]
fn a_placement_rect_with_a_non_number_is_refused() {
    let w = start("rect", &[]);
    let mut body = prepare_body(&blank());
    body["signers"][1]["placement"]["rect"] = json!([100, "x", 100, 280, 140]);
    let r = w.post("/v1/prepare", &body);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["error"], "bad_json");
}

/// A hostile PDF nested very deep is refused or read; it never takes the worker down.
#[test]
fn a_deeply_nested_pdf_does_not_take_the_worker_down() {
    let w = start("deep", &[]);
    let depth = 50_000;
    let body = format!("<< /Type /Catalog /Pages 2 0 R /X {}{} >>", "[".repeat(depth), "]".repeat(depth));
    let objs = [body, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(), "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>".to_string()];
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = pdf.len();
    pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for o in offsets {
        pdf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    for path in ["/v1/inspect", "/v1/prepare"] {
        let mut body = prepare_body(&pdf);
        body["pdf"] = json!(b64(&pdf));
        let r = w.post(path, &body);
        assert!([200, 422].contains(&r.status), "{path}: {}", r.status);
    }
    assert_eq!(w.get("/v1/health").status, 200, "still up");
}

#[test]
fn key_not_loaded_is_503() {
    let dir = workdir("nokey");
    secrets(&dir, "not-the-password");
    let w = start_in(&dir, &[]);
    let h = w.get("/v1/health");
    assert_eq!(h.status, 200);
    assert_eq!(h.json()["ok"], false);
    // Prepare does not need the key; sealing does.
    let base = prepared(&w);
    let r = w.post("/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "name" })));
    assert_eq!(r.status, 503);
    assert_eq!(r.json()["error"], "key_not_loaded");
}

#[test]
fn logs_never_contain_pdf_or_mac() {
    let w = start("logs", &[]);
    let mut sent = Vec::new();
    let mut call = |method: &str, path: &str, body: &Value| {
        let bytes = if method == "GET" { Vec::new() } else { serde_json::to_vec(body).expect("json") };
        let (r, s) = w.send(method, path, &bytes, now(), &nonce(), None);
        sent.push(s);
        r
    };
    let p = call("POST", "/v1/prepare", &prepare_body(&blank()));
    let base = unb64(&p.json()["pdf"]);
    call("POST", "/v1/inspect", &json!({ "pdf": b64(&base) }));
    call("POST", "/v1/seal", &seal_body(&base, 1, false, None, json!({ "kind": "name" })));
    call("GET", "/v1/health", &Value::Null);
    let (_, bad) = w.send("GET", "/v1/health", b"", now(), &nonce(), Some(&"f".repeat(64)));
    sent.push(bad);
    let log = w.stderr();
    assert!(log.lines().filter(|l| l.contains("/v1/")).count() >= 5, "one line per call:\n{log}");
    let mut run = 0usize;
    for c in log.chars() {
        run = if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') { run + 1 } else { 0 };
        assert!(run <= 64, "a base64-like run of more than 64 characters in the log:\n{log}");
    }
    for s in &sent {
        assert!(!log.contains(&s.mac), "a request MAC in the log");
        assert!(!log.contains(&s.nonce), "a nonce in the log");
    }
    assert!(!log.contains(SECRET));
}
