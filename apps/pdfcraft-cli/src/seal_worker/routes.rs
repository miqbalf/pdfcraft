//! The seal worker's five endpoints. Each takes the authenticated request body and gives a
//! status and a JSON reply; PDFs travel base64 in `"pdf"`. A refusal is
//! `{ "error": "<code>", "message": "<English sentence>" }`, and never carries the inner text of
//! a library error.

use std::collections::BTreeMap;
use std::time::Instant;

use base64::Engine as _;
use pdfcraft_engine::esign::{
    self, AuditHeader, EsignError, FinalSeal, Placement, SignatureSummary, SignerSeal, SignerSlot, graphic_from_json, inspect_trusting,
};
use serde_json::{Map, Value, json};

use super::tsa::{self, HttpTsa};
use super::{Key, Worker};

/// The largest PDF taken (the request body may be up to 96 MiB: base64 plus the rest).
pub const MAX_PDF_BYTES: usize = 64 * 1024 * 1024;

/// What a route answered, and what its log line names.
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub request_id: Option<u64>,
    /// SHA-256 of the PDF given, and of the PDF returned.
    pub sha256_in: Option<String>,
    pub sha256_out: Option<String>,
    pub code: Option<&'static str>,
}

impl Reply {
    fn ok(body: Value) -> Self {
        Reply { status: 200, body, request_id: None, sha256_in: None, sha256_out: None, code: None }
    }
}

/// A refusal: `status` with `{ "error": code, "message": message }`.
pub fn refusal(status: u16, code: &'static str, message: &str) -> Reply {
    Reply { status, body: json!({ "error": code, "message": message }), request_id: None, sha256_in: None, sha256_out: None, code: Some(code) }
}

/// An engine refusal on the wire: a mark the signer must change is 400, a timestamp authority
/// that did not answer is 503 (try again), anything else about the PDF is 422.
fn refused(e: &EsignError) -> Reply {
    let code = e.code();
    let status = match code {
        "bad_graphic" | "graphic_too_large" => 400,
        "tsa_unavailable" => 503,
        _ => 422,
    };
    // `Display` only: the `Debug` form of a signing error holds library text.
    refusal(status, code, &e.to_string())
}

fn bad_json(message: &str) -> Reply {
    refusal(400, "bad_json", message)
}

type Field<T> = Result<T, Reply>;

fn object(v: &Value, what: &str) -> Field<Map<String, Value>> {
    v.as_object().cloned().ok_or_else(|| bad_json(&format!("{what} is not a JSON object.")))
}

fn string(o: &Map<String, Value>, key: &str) -> Field<String> {
    o.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| bad_json(&format!("The field \"{key}\" is missing or not text.")))
}

fn uint(o: &Map<String, Value>, key: &str) -> Field<u64> {
    o.get(key).and_then(Value::as_u64).ok_or_else(|| bad_json(&format!("The field \"{key}\" is missing or not a whole number.")))
}

fn position(o: &Map<String, Value>) -> Field<u32> {
    uint(o, "position").and_then(|n| u32::try_from(n).map_err(|_| bad_json("The field \"position\" is too large.")))
}

/// The PDF in `o["pdf"]`, decoded from the parsed body in place (no copy of the base64 text; P5 review m4).
fn pdf(o: &Map<String, Value>) -> Field<Vec<u8>> {
    let text = o.get("pdf").and_then(Value::as_str).ok_or_else(|| bad_json("The field \"pdf\" is missing or not text."))?;
    // Base64 of the cap, rounded up: anything longer cannot decode to an allowed PDF.
    if text.len() > MAX_PDF_BYTES.div_ceil(3) * 4 {
        return Err(refusal(413, "too_large", "This PDF is larger than 64 MiB and cannot be signed."));
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(text.as_bytes()).map_err(|_| bad_json("The field \"pdf\" is not base64."))?;
    if bytes.len() > MAX_PDF_BYTES {
        return Err(refusal(413, "too_large", "This PDF is larger than 64 MiB and cannot be signed."));
    }
    Ok(bytes)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn summaries(list: &[SignatureSummary]) -> Value {
    Value::Array(
        list.iter()
            .map(|s| {
                json!({
                    "field": s.field, "signed": s.signed, "status": s.status, "modification": s.modification,
                    "signer": s.signer, "date": s.date,
                })
            })
            .collect(),
    )
}

/// Run `route` on the parsed body object; a body that is not a JSON object is `bad_json`.
fn with_object(body: &[u8], route: impl FnOnce(&Map<String, Value>) -> Reply) -> Reply {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(o)) => route(&o),
        _ => bad_json("The request body is not a JSON object."),
    }
}

/// The route for `method` and `path`, with the request `body` already authenticated.
pub fn dispatch(worker: &Worker, method: &str, path: &str, body: &[u8]) -> Reply {
    match (method, path) {
        ("GET", "/v1/health") => health(worker),
        ("POST", "/v1/inspect") => with_object(body, |o| inspect(worker, o)),
        ("POST", "/v1/prepare") => with_object(body, prepare),
        ("POST", "/v1/seal") => {
            if worker.key.is_some() && !worker.allow_seal(Instant::now()) {
                return refusal(429, "rate_limited", "Too many signatures at once. Try again in a few seconds.");
            }
            with_object(body, |o| seal(worker, o))
        }
        ("POST", "/v1/audit-pdf") => with_object(body, audit_pdf),
        (_, "/v1/health" | "/v1/inspect" | "/v1/prepare" | "/v1/seal" | "/v1/audit-pdf") => {
            refusal(405, "method_not_allowed", "This method is not allowed here.")
        }
        _ => refusal(404, "not_found", "There is no such endpoint."),
    }
}

/// `GET /v1/health`: the sealing certificate, or `ok: false` when the key did not load.
fn health(worker: &Worker) -> Reply {
    let version = pdfcraft_engine::build_info::version();
    let Some(key) = &worker.key else {
        return Reply::ok(json!({
            "ok": false, "version": version, "error": "key_not_loaded",
            "message": "The seal key could not be loaded, so nothing can be signed.",
        }));
    };
    let cert = &key.id.certificate;
    let t = cert.not_after;
    Reply::ok(json!({
        "ok": true,
        "version": version,
        "cert": {
            "subject": cert.subject.display(),
            "issuer": cert.issuer.display(),
            "sha256": key.cert_sha256,
            "not_after": format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year, t.month, t.day, t.hour, t.minute, t.second),
            "chain_pem": key.chain_pem,
        },
        "root_pem": key.root_pem,
    }))
}

/// `POST /v1/inspect`: the PDF's state, its signatures checked against the seal's own root, so
/// the request's signatures read `valid` as in the seal's reply.
fn inspect(worker: &Worker, o: &Map<String, Value>) -> Reply {
    let bytes = match pdf(o) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let trust = worker.key.as_ref().map(|k| vec![k.root.clone()]).unwrap_or_default();
    match inspect_trusting(&bytes, &trust) {
        Ok(i) => {
            let mut r = Reply::ok(json!({
                "sha256": i.sha256, "pages": i.pages, "signed": i.signed, "needs_password": i.needs_password,
                "signatures": summaries(&i.signatures),
                "root_pem": worker.key.as_ref().map(|k| k.root_pem.clone()),
            }));
            r.sha256_in = Some(i.sha256);
            r
        }
        Err(e) => refused(&e),
    }
}

fn header(o: &Map<String, Value>, request_id: u64) -> Field<AuditHeader> {
    let h = object(o.get("header").unwrap_or(&Value::Null), "The field \"header\"")?;
    Ok(AuditHeader {
        request_id,
        title: string(&h, "title")?,
        requester_uid: string(&h, "requester_uid")?,
        requester_name: string(&h, "requester_name")?,
        created_utc: string(&h, "created_utc")?,
        instance: string(&h, "instance")?,
        organisation: string(&h, "organisation")?,
    })
}

fn placement(v: Option<&Value>) -> Field<Option<Placement>> {
    let Some(v) = v.filter(|v| !v.is_null()) else { return Ok(None) };
    let p = object(v, "A signer's placement")?;
    let page = uint(&p, "page").and_then(|n| usize::try_from(n).map_err(|_| bad_json("A placement's page is too large.")))?;
    // Every element a number: one that is not refuses the rect, it is never skipped.
    let rect: Option<Vec<f64>> = p.get("rect").and_then(Value::as_array).and_then(|a| a.iter().map(Value::as_f64).collect());
    let rect = rect.and_then(|r| <[f64; 4]>::try_from(r).ok()).ok_or_else(|| bad_json("A placement's rect is not four numbers."))?;
    Ok(Some(Placement { page, rect }))
}

fn slots(o: &Map<String, Value>) -> Field<Vec<SignerSlot>> {
    let list = o.get("signers").and_then(Value::as_array).ok_or_else(|| bad_json("The field \"signers\" is missing or not a list."))?;
    // The engine caps the count; this only keeps a hostile list from being copied first.
    if list.len() > esign::MAX_SIGNERS {
        return Err(refusal(422, "validation_failed", &format!("A signature request can have at most {} signers.", esign::MAX_SIGNERS)));
    }
    list.iter()
        .map(|s| {
            let s = object(s, "A signer")?;
            Ok(SignerSlot {
                position: position(&s)?,
                uid: string(&s, "uid")?,
                display_name: string(&s, "display_name")?,
                placement: placement(s.get("placement"))?,
            })
        })
        .collect()
}

/// `POST /v1/prepare`: every signer's field, the audit page and the seal field, in one revision.
fn prepare(o: &Map<String, Value>) -> Reply {
    let parsed = (|| -> Field<_> { Ok((pdf(o)?, uint(o, "request_id")?, slots(o)?, string(o, "date")?)) })();
    let (bytes, rid, signers, date) = match parsed {
        Ok(p) => p,
        Err(r) => return r,
    };
    let sha_in = super::auth::sha256_hex(&bytes);
    let h = match header(o, rid) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let mut r = match esign::prepare(&bytes, &h, &signers, &date) {
        Ok(p) => {
            let fields: BTreeMap<String, String> = p.fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            let mut r = Reply::ok(json!({ "pdf": b64(&p.bytes), "sha256": p.sha256, "fields": fields, "seal_field": p.seal_field }));
            r.sha256_out = Some(p.sha256);
            r
        }
        Err(e) => refused(&e),
    };
    r.request_id = Some(rid);
    r.sha256_in = Some(sha_in);
    r
}

/// The parsed `/v1/seal` body.
struct SealCall {
    pdf: Vec<u8>,
    request_id: u64,
    position: u32,
    uid: String,
    display_name: String,
    graphic: Value,
    row_text: String,
    date: String,
    tsa_url: Option<String>,
    final_seal: Option<FinalCall>,
}

struct FinalCall {
    completed_text: String,
    date: String,
    instance: String,
    organisation: String,
}

fn seal_call(o: &Map<String, Value>) -> Field<SealCall> {
    let signer = object(o.get("signer").unwrap_or(&Value::Null), "The field \"signer\"")?;
    let tsa_url = match o.get("tsa_url") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(refusal(400, "bad_tsa_url", "The timestamp service address is not text.")),
    };
    let final_seal = match o.get("final") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let f = object(v, "The field \"final\"")?;
            // Ruling I1: the host names them with every final seal; the worker has no names of its own.
            let named = |k: &str| {
                f.get(k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| bad_json(&format!("The field \"final.{k}\" is missing or empty.")))
            };
            Some(FinalCall {
                completed_text: string(&f, "completed_text")?,
                date: string(&f, "date")?,
                instance: named("instance")?,
                organisation: named("organisation")?,
            })
        }
    };
    Ok(SealCall {
        pdf: pdf(o)?,
        request_id: uint(o, "request_id")?,
        position: position(&signer)?,
        uid: string(&signer, "uid")?,
        display_name: string(&signer, "display_name")?,
        graphic: o.get("graphic").cloned().unwrap_or(Value::Null),
        row_text: string(o, "row_text")?,
        date: string(o, "date")?,
        tsa_url,
        final_seal,
    })
}

/// `POST /v1/seal`: the signer's approval signature and, with `final`, the locking final seal.
/// Nothing is kept here: a refusal returns no PDF, and the caller's file is as it was.
fn seal(worker: &Worker, o: &Map<String, Value>) -> Reply {
    let Some(key) = &worker.key else {
        return refusal(
            503,
            "key_not_loaded",
            "The seal key is not loaded, so nothing can be signed. Ask an administrator to check the seal service.",
        );
    };
    let call = match seal_call(o) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut r = seal_with(worker, key, &call);
    r.request_id = Some(call.request_id);
    r.sha256_in = Some(super::auth::sha256_hex(&call.pdf));
    r
}

fn seal_with(worker: &Worker, key: &Key, call: &SealCall) -> Reply {
    let graphic = match graphic_from_json(&call.graphic, &call.display_name) {
        Ok(g) => g,
        Err(e) => return refused(&e),
    };
    let http;
    let authority: Option<&dyn pdfcraft_sign::TimestampAuthority> = match (&call.tsa_url, &worker.dev_tsa) {
        (None, _) => None,
        // The in-process test authority answers whatever address is set (the e2e stack's is http://).
        (Some(_), Some(dev)) => Some(dev),
        (Some(url), None) if !tsa::url_allowed(url, worker.allow_http_tsa) => {
            return refusal(
                400,
                "bad_tsa_url",
                "The timestamp service address must be an https:// URL with a host (http:// only on a development worker).",
            );
        }
        (Some(url), None) => {
            http = HttpTsa::new(url, tsa::TIMEOUT);
            Some(&http)
        }
    };
    let signer = SignerSeal {
        request_id: call.request_id,
        position: call.position,
        uid: &call.uid,
        display_name: &call.display_name,
        graphic: &graphic,
        row_text: &call.row_text,
        date: &call.date,
    };
    let fin = call.final_seal.as_ref().map(|f| FinalSeal {
        completed_text: &f.completed_text,
        date: &f.date,
        instance: &f.instance,
        organisation: &f.organisation,
    });
    match esign::seal(&call.pdf, &key.id, &signer, fin.as_ref(), authority) {
        Ok(s) => {
            let mut r = Reply::ok(json!({
                "pdf": b64(&s.bytes),
                "sha256": s.sha256,
                "after_signer_sha256": s.after_signer_sha256,
                "cert_sha256": s.cert_sha256,
                "byterange_sha256": s.byterange_sha256,
                "timestamped": s.timestamped,
                "signatures": summaries(&s.signatures),
            }));
            r.sha256_out = Some(s.sha256);
            r
        }
        Err(e) => refused(&e),
    }
}

/// `POST /v1/audit-pdf`: the printable audit trail.
fn audit_pdf(o: &Map<String, Value>) -> Reply {
    let Some(trail) = o.get("trail").filter(|t| t.is_object()) else {
        return bad_json("The field \"trail\" is missing or not a JSON object.");
    };
    match esign::audit_document(trail) {
        Ok(pdf) => {
            let mut r = Reply::ok(json!({ "pdf": b64(&pdf) }));
            r.sha256_out = Some(super::auth::sha256_hex(&pdf));
            r
        }
        Err(e) => refused(&e),
    }
}
