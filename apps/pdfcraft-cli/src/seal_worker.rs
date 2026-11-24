//! `pdfcraft-cli seal-worker`: the e-sign sealing service (PAdES B-T approval signatures and the
//! locking final seal, made with the instance's key).
//!
//! A small HTTP/1.1 server on `std::net`: at most [`MAX_CONNECTIONS`] connections at a time, one
//! request per connection, bodies by `Content-Length` only (at most [`MAX_BODY`]), and
//! [`READ_TIMEOUT`] to read a whole request. Every request is authenticated by its MAC
//! ([`auth`]) and every reply carries a reply MAC. The routes are in [`routes`].
//!
//! The key is loaded once at start and its password wiped after. A key that does not load leaves
//! the server up: health says `ok: false` and every seal is refused with 503 `key_not_loaded`.
//!
//! The worker logs one line per call to stderr: method, endpoint, status, request id, digests
//! and the certificate's fingerprint. Never document bytes, MACs, nonces or secrets.

mod auth;
mod routes;
mod tsa;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use pdfcraft_sign::{Certificate, DigitalId};
use zeroize::{Zeroize, Zeroizing};

use crate::CliError;

/// At most this many connections are served at once; more wait to be accepted.
pub const MAX_CONNECTIONS: usize = 8;
/// The largest request body (a PDF of at most 64 MiB, base64, plus the rest of the JSON).
pub const MAX_BODY: usize = 96 * 1024 * 1024;
/// A whole request must arrive within this time.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest request head (request line and headers).
const MAX_HEAD: usize = 16 * 1024;
/// At most this many seal calls in [`SEAL_WINDOW`]; more get 429.
const MAX_SEALS: usize = 30;
const SEAL_WINDOW: Duration = Duration::from_secs(10);

/// The least HMAC secret taken, in bytes (`occ craft_office:sign-setup` makes longer ones).
const MIN_SECRET: usize = 32;
/// Each connection's thread stack: a deeply nested hostile PDF must not overflow it, since a
/// stack overflow aborts the whole worker where a panic does not.
const CONNECTION_STACK: usize = 8 << 20;

/// The loaded sealing identity and what health reports about it.
pub(crate) struct Key {
    pub id: DigitalId,
    pub root: Certificate,
    pub root_pem: String,
    pub chain_pem: Vec<String>,
    pub cert_sha256: String,
}

/// What every connection shares.
pub(crate) struct Worker {
    secret: Zeroizing<Vec<u8>>,
    pub key: Option<Key>,
    pub dev_tsa: Option<tsa::DevTsa>,
    /// `--allow-http-tsa`: http:// timestamp services are taken (development only).
    pub allow_http_tsa: bool,
    nonces: Mutex<auth::NonceCache>,
    seals: Mutex<auth::RateLimit>,
}

impl Worker {
    /// Count one seal call; false when the rate limit is reached.
    pub fn allow_seal(&self, now: Instant) -> bool {
        self.seals.lock().map(|mut r| r.allow(now)).unwrap_or(false)
    }
}

struct Options {
    listen: String,
    key_file: PathBuf,
    key_password_file: PathBuf,
    secret_file: PathBuf,
    allow_readable_secrets: bool,
    allow_http_tsa: bool,
    insecure_dev_tsa: bool,
    port_file: Option<PathBuf>,
}

fn options(args: &[String]) -> Result<Options, CliError> {
    let (mut listen, mut key_file, mut key_password_file, mut secret_file, mut port_file) = (None, None, None, None, None);
    let (mut allow_readable_secrets, mut allow_http_tsa, mut insecure_dev_tsa) = (false, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| CliError::from(format!("seal-worker: {a} needs a value")));
        match a.as_str() {
            "--listen" => listen = Some(value()?),
            "--key-file" => key_file = Some(PathBuf::from(value()?)),
            "--key-password-file" => key_password_file = Some(PathBuf::from(value()?)),
            "--secret-file" => secret_file = Some(PathBuf::from(value()?)),
            "--port-file" => port_file = Some(PathBuf::from(value()?)),
            // Two development switches, one job each (N9): secret files group or others can read,
            // and http:// timestamp services. The instance and organisation come with each final
            // seal (ruling I1); the worker has none of its own.
            "--allow-readable-secrets" => allow_readable_secrets = true,
            "--allow-http-tsa" => allow_http_tsa = true,
            "--insecure-dev-tsa" => insecure_dev_tsa = true,
            other => return Err(format!("seal-worker: unknown option '{other}'; see pdfcraft-cli --help").into()),
        }
    }
    let need = |v: Option<PathBuf>, name: &str| v.ok_or_else(|| CliError::from(format!("seal-worker: {name} is required")));
    Ok(Options {
        listen: listen.ok_or_else(|| CliError::from("seal-worker: --listen is required"))?,
        key_file: need(key_file, "--key-file")?,
        key_password_file: need(key_password_file, "--key-password-file")?,
        secret_file: need(secret_file, "--secret-file")?,
        allow_readable_secrets,
        allow_http_tsa,
        insecure_dev_tsa,
        port_file,
    })
}

pub(crate) fn log(line: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr().lock(), "seal-worker: {line}");
}

/// Refuse a secret file that group or others may read or change, unless `allow_readable`.
#[cfg(unix)]
fn private(path: &Path, allow_readable: bool) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else { return Ok(()) };
    if meta.permissions().mode() & 0o066 != 0 && !allow_readable {
        return Err(format!(
            "seal-worker: {} can be read or changed by group or others; make it this user's only (chmod 400 or 600), or pass --allow-readable-secrets",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn private(_path: &Path, _allow_readable: bool) -> Result<(), CliError> {
    Ok(())
}

/// Lowercase hex SHA-256 of a certificate's DER.
fn cert_sha256(c: &Certificate) -> String {
    auth::sha256_hex(&c.raw)
}

/// The secret file's bytes without the whitespace PHP's `trim()` removes from CRAFT_SEAL_SECRET
/// (space, tab, line breaks, NUL, vertical tab), at both ends, so both sides MAC with the same key (n6).
fn trim_secret(secret: &mut Zeroizing<Vec<u8>>) {
    let blank = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\0' | 0x0b);
    while secret.last().is_some_and(blank) {
        secret.pop();
    }
    let lead = secret.iter().take_while(|b| blank(b)).count();
    if lead > 0 {
        secret.drain(..lead);
    }
}

/// Open the PKCS #12 file with the password file's contents (one trailing line break dropped);
/// the password is wiped once `open` is done. Why it failed, in words that hold no secret.
fn load_key(key_file: &Path, password_file: &Path) -> Result<Key, &'static str> {
    let p12 = Zeroizing::new(std::fs::read(key_file).map_err(|_| "the key file cannot be read")?);
    let mut raw = Zeroizing::new(std::fs::read(password_file).map_err(|_| "the key password file cannot be read")?);
    while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        raw.pop();
    }
    let mut password = String::from_utf8(raw.to_vec()).map_err(|e| {
        let mut bytes = e.into_bytes();
        bytes.zeroize();
        "the key password is not UTF-8 text"
    })?;
    let opened = pdfcraft_sign::pkcs12::open(&p12, &password);
    password.zeroize();
    let id = opened.map_err(|e| match e {
        pdfcraft_sign::SignError::WrongPassword => "the key password is wrong",
        _ => "the key file is not a PKCS #12 file this worker can use",
    })?;
    let chain: Vec<Certificate> = pdfcraft_sign::x509::build_chain(&id.certificate, &id.chain, None).into_iter().cloned().collect();
    // The same anchor the engine checks a seal against (P5 review m8).
    let root = pdfcraft_engine::esign::trust_root(&id);
    Ok(Key {
        root_pem: pdfcraft_sign::x509::to_pem(&root),
        chain_pem: chain.iter().map(pdfcraft_sign::x509::to_pem).collect(),
        cert_sha256: cert_sha256(&id.certificate),
        root,
        id,
    })
}

/// `pdfcraft-cli seal-worker …`: load the key and secret, listen, and serve until killed.
pub fn run(args: &[String]) -> Result<(), CliError> {
    let o = options(args)?;
    // A panic's message can quote its input; only where it happened is logged. The call that
    // panicked is answered by `connection`.
    std::panic::set_hook(Box::new(|info| {
        let at = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        log(format_args!("a call failed inside the worker (panic at {at}); its message is not logged"));
    }));
    for path in [&o.secret_file, &o.key_file, &o.key_password_file] {
        private(path, o.allow_readable_secrets)?;
    }
    let mut secret = Zeroizing::new(std::fs::read(&o.secret_file).map_err(|_| CliError::from("seal-worker: the secret file cannot be read"))?);
    trim_secret(&mut secret);
    if secret.len() < MIN_SECRET {
        return Err(format!(
            "seal-worker: the secret is shorter than {MIN_SECRET} bytes; use the same value as CRAFT_SEAL_SECRET (at least {MIN_SECRET} bytes)"
        )
        .into());
    }
    let key = match load_key(&o.key_file, &o.key_password_file) {
        Ok(k) => {
            log(format_args!("key loaded; cert sha256:{}", k.cert_sha256));
            Some(k)
        }
        Err(why) => {
            log(format_args!("the seal key was not loaded ({why}); health reports ok: false and every seal answers 503 key_not_loaded"));
            None
        }
    };
    let dev_tsa = if o.insecure_dev_tsa {
        log(format_args!("INSECURE: --insecure-dev-tsa: every timestamp comes from an in-process test authority nobody trusts"));
        Some(tsa::DevTsa::new().map_err(|_| CliError::from("seal-worker: the test timestamp authority could not make its key"))?)
    } else {
        None
    };
    if o.allow_readable_secrets {
        log(format_args!("INSECURE: --allow-readable-secrets: secret files group or others can read are taken"));
    }
    if o.allow_http_tsa {
        log(format_args!("INSECURE: --allow-http-tsa: http:// timestamp services are taken"));
    }
    let listener = TcpListener::bind(&o.listen).map_err(|e| CliError::from(format!("seal-worker: cannot listen on {}: {e}", o.listen)))?;
    let addr = listener.local_addr().map_err(|e| CliError::from(format!("seal-worker: {e}")))?;
    if let Some(path) = &o.port_file {
        // Written whole, then renamed, so a reader never sees half a number.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, addr.port().to_string())
            .and_then(|()| std::fs::rename(&tmp, path))
            .map_err(|e| CliError::from(format!("seal-worker: cannot write the port file: {e}")))?;
    }
    log(format_args!("listening on {addr}"));
    let worker = Arc::new(Worker {
        secret,
        key,
        dev_tsa,
        allow_http_tsa: o.allow_http_tsa,
        nonces: Mutex::new(auth::NonceCache::default()),
        seals: Mutex::new(auth::RateLimit::new(MAX_SEALS, SEAL_WINDOW)),
    });
    serve(&listener, &worker);
    Ok(())
}

/// Connections being served, and a signal when one ends.
type Slots = Arc<(Mutex<usize>, Condvar)>;

/// Frees a connection slot when the connection's thread ends, however it ends.
struct Slot(Slots);

impl Drop for Slot {
    fn drop(&mut self) {
        let (count, freed) = &*self.0;
        if let Ok(mut n) = count.lock() {
            *n = n.saturating_sub(1);
        }
        freed.notify_one();
    }
}

fn serve(listener: &TcpListener, worker: &Arc<Worker>) {
    let slots: Slots = Arc::new((Mutex::new(0), Condvar::new()));
    loop {
        // Wait for a free slot before accepting, so extra clients wait in the backlog.
        {
            let (count, freed) = &*slots;
            let Ok(mut n) = count.lock() else { return };
            while *n >= MAX_CONNECTIONS {
                n = match freed.wait(n) {
                    Ok(n) => n,
                    Err(_) => return,
                };
            }
            *n += 1;
        }
        let slot = Slot(slots.clone());
        let Ok((stream, _)) = listener.accept() else { continue };
        let worker = worker.clone();
        let spawned = std::thread::Builder::new().name("seal-worker-conn".into()).stack_size(CONNECTION_STACK).spawn(move || {
            let _slot = slot;
            connection(stream, &worker);
        });
        if spawned.is_err() {
            log(format_args!("could not start a thread for a connection"));
        }
    }
}

/// One parsed request.
struct Request {
    method: String,
    path: String,
    time: Option<String>,
    nonce: Option<String>,
    mac: Option<String>,
    body: Vec<u8>,
}

/// Why a request could not be read: answered with this status and code, or dropped.
enum ReadError {
    Answer(u16, &'static str, &'static str),
    Drop,
}

/// Read from `stream` into `buf` before `deadline`.
fn read_some(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<usize, ReadError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(ReadError::Drop);
    }
    stream.set_read_timeout(Some(left)).map_err(|_| ReadError::Drop)?;
    match stream.read(buf) {
        Ok(0) | Err(_) => Err(ReadError::Drop),
        Ok(n) => Ok(n),
    }
}

/// Read one request (head, then a `Content-Length` body), all within [`READ_TIMEOUT`]. The
/// request MAC header, when one was given, comes back with an error too, for the reply MAC.
fn read_request(stream: &mut TcpStream) -> Result<Request, (ReadError, Option<String>)> {
    let deadline = Instant::now() + READ_TIMEOUT;
    let mut head = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let too_large = || (ReadError::Answer(431, "bad_request", "The request headers are too large."), None);
    let end = loop {
        // A whole head that arrived in one read is measured too, not only one still coming.
        if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            if i + 4 > MAX_HEAD {
                return Err(too_large());
            }
            break i + 4;
        }
        if head.len() > MAX_HEAD {
            return Err(too_large());
        }
        let n = read_some(stream, &mut chunk, deadline).map_err(|e| (e, None))?;
        head.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    let bad = |m| (ReadError::Answer(400, "bad_request", m), None);
    match req.parse(head.get(..end).unwrap_or_default()) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(bad("The request is not HTTP/1.1.")),
    }
    let header = |name: &str| -> Vec<String> {
        req.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).map(|h| String::from_utf8_lossy(h.value).trim().to_string()).collect()
    };
    let single = |name: &str| header(name).into_iter().next();
    let mac = single("x-craft-seal-mac");
    let fail = |status, code, message| (ReadError::Answer(status, code, message), mac.clone());
    if !header("transfer-encoding").is_empty() {
        return Err(fail(411, "bad_request", "Only bodies with a Content-Length are accepted."));
    }
    let lengths = header("content-length");
    let length = match lengths.as_slice() {
        [] => 0,
        [one] if !one.is_empty() && one.bytes().all(|c| c.is_ascii_digit()) => {
            // Digits too many for memory are too large, not malformed.
            one.parse::<usize>().unwrap_or(usize::MAX)
        }
        [_] => return Err(fail(400, "bad_request", "The Content-Length is not a number.")),
        _ => return Err(fail(400, "bad_request", "The request has more than one Content-Length.")),
    };
    if length > MAX_BODY {
        return Err(fail(413, "too_large", "The request is larger than 96 MiB; a PDF of at most 64 MiB can be signed."));
    }
    let method = req.method.unwrap_or_default().to_string();
    let path = req.path.unwrap_or_default().split('?').next().unwrap_or_default().to_string();
    let mut body = Vec::with_capacity(length.min(1024 * 1024));
    body.extend_from_slice(head.get(end..).unwrap_or_default());
    // A client that waits for it (Guzzle and curl over 1 MB) gets `100 Continue` once the length is
    // known to be acceptable, instead of waiting a second for nothing (P5 review m6).
    if body.len() < length && header("expect").iter().any(|v| v.eq_ignore_ascii_case("100-continue")) {
        let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
        if stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").and_then(|()| stream.flush()).is_err() {
            return Err((ReadError::Drop, mac.clone()));
        }
    }
    while body.len() < length {
        let n = read_some(stream, &mut chunk, deadline).map_err(|e| (e, mac.clone()))?;
        body.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    if body.len() != length {
        return Err(fail(400, "bad_request", "The body is longer than its Content-Length."));
    }
    Ok(Request { method, path, time: single("x-craft-seal-time"), nonce: single("x-craft-seal-nonce"), mac: mac.clone(), body })
}

/// Write the reply, with its MAC over `request_mac` (the request's header, as given).
fn respond(stream: &mut TcpStream, worker: &Worker, request_mac: &str, status: u16, body: &serde_json::Value) {
    let text = serde_json::to_string(body).unwrap_or_else(|_| String::from(r#"{"error":"internal","message":"The reply could not be written."}"#));
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let mac = auth::reply_mac(&worker.secret, request_mac, text.as_bytes());
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Craft-Seal-Reply: {mac}\r\nConnection: close\r\n\r\n",
        text.len()
    );
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(text.as_bytes())).and_then(|()| stream.flush());
}

/// The endpoint as it may be logged: only names this worker serves, never what a client sent.
fn loggable(path: &str) -> &'static str {
    match path {
        "/v1/health" => "/v1/health",
        "/v1/inspect" => "/v1/inspect",
        "/v1/prepare" => "/v1/prepare",
        "/v1/seal" => "/v1/seal",
        "/v1/audit-pdf" => "/v1/audit-pdf",
        _ => "(other)",
    }
}

fn loggable_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        _ => "(other)",
    }
}

fn connection(mut stream: TcpStream, worker: &Worker) {
    let started = Instant::now();
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err((ReadError::Drop, _)) => return,
        Err((ReadError::Answer(status, code, message), mac)) => {
            respond(&mut stream, worker, mac.as_deref().unwrap_or_default(), status, &serde_json::json!({ "error": code, "message": message }));
            log(format_args!("- - {status} code {code}"));
            // Let the client finish sending before the socket closes, so it reads the answer.
            let _ = stream.shutdown(Shutdown::Write);
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut sink = [0u8; 65536];
            while read_some(&mut stream, &mut sink, deadline).is_ok() {}
            return;
        }
    };
    let presented = auth::Presented {
        method: &req.method,
        path: &req.path,
        body: &req.body,
        time: req.time.as_deref(),
        nonce: req.nonce.as_deref(),
        mac: req.mac.as_deref(),
    };
    let now_unix = tsa::now_secs();
    let authentic =
        worker.nonces.lock().map(|mut cache| auth::verify(&worker.secret, &presented, now_unix, &mut cache, Instant::now())).unwrap_or(false);
    let reply = if authentic {
        // A panic in a library is this call's failure, not the worker's.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| routes::dispatch(worker, &req.method, &req.path, &req.body)))
            .unwrap_or_else(|_| routes::refusal(422, "validation_failed", "The PDF could not be processed."))
    } else {
        routes::refusal(401, "unauthorized", "The request could not be authenticated (clock, nonce or MAC).")
    };
    respond(&mut stream, worker, req.mac.as_deref().unwrap_or_default(), reply.status, &reply.body);
    let dash = || "-".to_string();
    let cert = worker.key.as_ref().map(|k| format!("sha256:{}", k.cert_sha256)).unwrap_or_else(dash);
    log(format_args!(
        "{} {} {} request {} in {} out {} cert {} code {} {}ms",
        loggable_method(&req.method),
        loggable(&req.path),
        reply.status,
        reply.request_id.map(|r| r.to_string()).unwrap_or_else(dash),
        reply.sha256_in.map(|s| format!("sha256:{s}")).unwrap_or_else(dash),
        reply.sha256_out.map(|s| format!("sha256:{s}")).unwrap_or_else(dash),
        cert,
        reply.code.unwrap_or("-"),
        started.elapsed().as_millis(),
    ));
}
