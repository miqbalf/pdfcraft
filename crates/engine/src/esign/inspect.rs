//! What the seal worker reports about a PDF before anything is done to it: its digest, its
//! pages, whether it is signed or needs a password, and its signature fields.
//!
//! Inspecting never refuses a signed or encrypted PDF: those are answers, not errors. Only bytes
//! that are not a PDF at all are refused.

use std::cell::Cell;
use std::sync::Arc;

use pdfcraft_render::OpenError;
use pdfcraft_sign::{DigestAlg, Modification, SignatureInfo, Status};

use super::EsignError;
use crate::{DocId, Session};

/// A PDF as the seal worker sees it (`POST /v1/inspect`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// Lowercase hex SHA-256 of the bytes given.
    pub sha256: String,
    /// 0 when the PDF needs a password to open.
    pub pages: usize,
    /// At least one signature field holds a signature.
    pub signed: bool,
    pub needs_password: bool,
    pub signatures: Vec<SignatureSummary>,
}

/// One signature field and its verdict, as the wire carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureSummary {
    pub field: String,
    pub signed: bool,
    /// `unsigned`, `valid`, `unknown` or `invalid` (with no trusted certificates, a sound
    /// signature is `unknown`).
    pub status: String,
    /// `none`, `allowed` or `disallowed`: what later revisions did, as the signature permits.
    pub modification: String,
    pub signer: Option<String>,
    /// The signature's `/M`, as written.
    pub date: Option<String>,
}

impl From<&SignatureInfo> for SignatureSummary {
    fn from(s: &SignatureInfo) -> Self {
        let status = match (s.signed, s.status) {
            (false, _) => "unsigned",
            (true, Status::Valid) => "valid",
            (true, Status::Unknown) => "unknown",
            (true, Status::Invalid) => "invalid",
        };
        let modification = match s.modification {
            Modification::None => "none",
            Modification::Allowed(_) => "allowed",
            Modification::Disallowed(_) => "disallowed",
        };
        SignatureSummary {
            field: s.field.clone(),
            signed: s.signed,
            status: status.into(),
            modification: modification.into(),
            signer: s.signer.clone(),
            date: s.date.clone(),
        }
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    DigestAlg::Sha256.digest(&[bytes]).iter().map(|b| format!("{b:02x}")).collect()
}

thread_local! {
    /// The time an e-sign session's clock reads (seconds since the epoch, UTC), so that what a
    /// step writes depends on its inputs only. A session's clock is a plain function, so the
    /// value it reads lives here; each step sets it before it opens its session, on its thread.
    static NOW: Cell<i64> = const { Cell::new(0) };
}

fn fixed_now() -> i64 {
    NOW.with(Cell::get)
}

fn utc() -> i64 {
    0
}

/// What opening a PDF for an e-sign step gave.
pub(super) enum Opened {
    Doc(Session, DocId),
    NeedsPassword,
}

/// Open `bytes` in a session of their own whose clock reads `now` (UTC), with the document's
/// scripts off: the PDF is untrusted, and nothing here needs them.
pub(super) fn open(bytes: &[u8], now: i64) -> Result<Opened, EsignError> {
    NOW.with(|c| c.set(now));
    let mut session = Session::new().with_wall_clock(fixed_now, utc);
    session.set_javascript(false);
    match session.open("document.pdf", None, Arc::new(bytes.to_vec()), None) {
        Ok(id) => Ok(Opened::Doc(session, id)),
        Err(OpenError::NeedsPassword | OpenError::WrongPassword) => Ok(Opened::NeedsPassword),
        Err(OpenError::Invalid(_) | OpenError::Unsupported(_)) => Err(EsignError::NotPdf("This file is not a PDF that can be read.".into())),
    }
}

/// Report on `bytes`. A signed or encrypted PDF is reported, never refused.
pub fn inspect(bytes: &[u8]) -> Result<Inspection, EsignError> {
    let sha256 = sha256_hex(bytes);
    let (session, id) = match open(bytes, 0)? {
        Opened::Doc(session, id) => (session, id),
        Opened::NeedsPassword => {
            return Ok(Inspection { sha256, pages: 0, signed: false, needs_password: true, signatures: Vec::new() });
        }
    };
    let doc = session.get(id).ok_or_else(|| EsignError::NotPdf("This file is not a PDF that can be read.".into()))?;
    Ok(Inspection {
        sha256,
        pages: doc.info.pages.len(),
        signed: doc.is_signed(),
        needs_password: false,
        signatures: doc.signatures.iter().map(SignatureSummary::from).collect(),
    })
}
