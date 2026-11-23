//! What the seal worker reports about a PDF before anything is done to it: its digest, its
//! pages, whether it is signed or needs a password, and its signature fields.
//!
//! Inspecting never refuses a signed or encrypted PDF: those are answers, not errors. Only bytes
//! that are not a PDF at all are refused.

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
    /// The signature's `/M` in UTC, `YYYY-MM-DDTHH:MM:SSZ` like every date on the wire; none
    /// when it is missing or not a date.
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
            date: s.date.as_deref().and_then(iso_utc),
        }
    }
}

/// A PDF date (`D:20261123090000+07'00'`) as `YYYY-MM-DDTHH:MM:SSZ`, in UTC.
fn iso_utc(pdf_date: &str) -> Option<String> {
    let t = pdfcraft_sign::Time::from_pdf(pdf_date)?;
    (t.year <= 9999).then(|| format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year, t.month, t.day, t.hour, t.minute, t.second))
}

/// Lowercase hex SHA-256 of `bytes`.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    DigestAlg::Sha256.digest(&[bytes]).iter().map(|b| format!("{b:02x}")).collect()
}

/// What opening a PDF for an e-sign step gave.
pub(super) enum Opened {
    Doc(Session, DocId),
    NeedsPassword,
}

/// A session whose clock reads `now` (UTC) for it alone, with document scripts off: the PDFs
/// are untrusted, and nothing here needs them. What it writes depends on its inputs only
/// ([`Session::with_fixed_time`]), however many such sessions a thread holds.
pub(super) fn session_at(now: i64) -> Session {
    let mut session = Session::new().with_fixed_time(now);
    session.set_javascript(false);
    session
}

/// Open `bytes` in a session of their own whose clock reads `now` ([`session_at`]).
pub(super) fn open(bytes: &[u8], now: i64) -> Result<Opened, EsignError> {
    let mut session = session_at(now);
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
