//! Prepare a PDF for a signature request (`POST /v1/prepare`): one incremental revision that
//! adds every signer's signature field, the audit page with its read-only rows and Completed
//! line, and the final seal's field. Nothing is signed here; a signed PDF is refused, because a
//! new revision with pages would break its signatures (owner answer 3).

use std::collections::{BTreeMap, BTreeSet};

use super::EsignError;
use super::audit_page::{audit_edits, page_size};
use super::inspect::{Opened, open, sha256_hex};
use crate::{Edit, EditError};

/// Who asked for the signatures, and where: the audit page's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditHeader {
    pub request_id: u64,
    pub title: String,
    pub requester_uid: String,
    pub requester_name: String,
    /// ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ`; shown as given.
    pub created_utc: String,
    pub instance: String,
    pub organisation: String,
}

/// Where a signer's field goes: a 0-based page and a rectangle in that page's user space.
#[derive(Clone, Debug, PartialEq)]
pub struct Placement {
    pub page: usize,
    pub rect: [f64; 4],
}

/// One signer of the request. Without a placement the signer's field is on the audit page.
#[derive(Clone, Debug, PartialEq)]
pub struct SignerSlot {
    pub position: u32,
    pub uid: String,
    pub display_name: String,
    pub placement: Option<Placement>,
}

/// The prepared file: the input bytes plus one revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`.
    pub sha256: String,
    /// Each signer's position and their signature field's name.
    pub fields: BTreeMap<u32, String>,
    pub seal_field: String,
}

/// A signer's signature field: `CraftOffice.R<id>.S<position>`.
pub fn signer_field(request_id: u64, position: u32) -> String {
    format!("CraftOffice.R{request_id}.S{position}")
}

/// A signer's audit row, a read-only text field: `CraftOffice.R<id>.Row<position>`.
pub fn row_field(request_id: u64, position: u32) -> String {
    format!("CraftOffice.R{request_id}.Row{position}")
}

/// The audit page's Completed line: `CraftOffice.R<id>.Completed`.
pub fn completed_field(request_id: u64) -> String {
    format!("CraftOffice.R{request_id}.Completed")
}

/// The final seal's signature field: `CraftOffice.R<id>.Seal`.
pub fn seal_field(request_id: u64) -> String {
    format!("CraftOffice.R{request_id}.Seal")
}

/// Seconds since the epoch of a wire date (`YYYY-MM-DDTHH:MM:SSZ`, UTC).
pub(super) fn parse_date(date: &str) -> Result<i64, EsignError> {
    chrono::NaiveDateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%SZ")
        .map(|t| t.and_utc().timestamp())
        .map_err(|_| EsignError::Validation("The date is not a UTC time of the form YYYY-MM-DDTHH:MM:SSZ.".into()))
}

/// Why the prepare edits were refused, in a sentence the requester can act on. The inner text
/// never reaches the wire.
fn refusal(e: EditError) -> EsignError {
    match e {
        EditError::NotPermitted(_) => {
            EsignError::Validation("This PDF's security settings do not allow changes; remove its owner password first.".into())
        }
        // The one form error prepare's fields can meet once places and sizes are checked: a name
        // taken by a field of the PDF (`add_field` refuses it as invalid).
        EditError::Form(pdfcraft_forms::FormError::Invalid(_)) => {
            EsignError::Validation("This PDF has form fields whose names clash with the signature fields.".into())
        }
        other => other.into(),
    }
}

/// The most signers one request may have (the audit page's own cap).
pub const MAX_SIGNERS: usize = 500;

/// Why `cos` must not get a signature request although no field of it is signed: its catalog
/// names a signature elsewhere (usage rights, `/Perms /UR3`; a certification, `/Perms /DocMDP`),
/// which a new revision would break, or it is an XFA form, where viewers that lay out the XFA
/// would not show the new fields.
fn signed_elsewhere_or_xfa(cos: &pdfcraft_cos::Document) -> Option<EsignError> {
    let catalog = cos.root().map(|r| cos.get(r))?;
    let catalog = catalog.as_dict()?;
    if let Some(perms) = catalog.get(b"Perms").map(|p| cos.resolve(p))
        && perms.as_dict().is_some_and(|p| [&b"UR3"[..], b"UR", b"DocMDP"].iter().any(|k| p.get(k).is_some()))
    {
        return Some(EsignError::AlreadySigned);
    }
    let form = catalog.get(b"AcroForm").map(|f| cos.resolve(f))?;
    form.as_dict().is_some_and(|f| f.get(b"XFA").is_some()).then(|| {
        EsignError::Validation(
            "This PDF is an XFA form; signature fields added to it would not show in every viewer, so it cannot be sent for signatures.".into(),
        )
    })
}

/// A place may lie this far outside its page's visible area (rounding in the browser).
const EDGE: f64 = 0.5;

/// Add the request's fields and audit page to `bytes`. `date` (ISO 8601 UTC) is the time the
/// revision records, so the same inputs give the same bytes.
pub fn prepare(bytes: &[u8], header: &AuditHeader, signers: &[SignerSlot], date: &str) -> Result<Prepared, EsignError> {
    let now = parse_date(date)?;
    if signers.is_empty() {
        return Err(EsignError::Validation("A signature request needs at least one signer.".into()));
    }
    if signers.len() > MAX_SIGNERS {
        return Err(EsignError::Validation(format!("A signature request can have at most {MAX_SIGNERS} signers.")));
    }
    let mut seen = BTreeSet::new();
    if !signers.iter().all(|s| seen.insert(s.position)) {
        return Err(EsignError::Validation("Two signers have the same position.".into()));
    }
    let (mut session, id) = match open(bytes, now)? {
        Opened::Doc(session, id) => (session, id),
        Opened::NeedsPassword => return Err(EsignError::NeedsPassword),
    };
    let doc = session.get(id).ok_or_else(|| EsignError::NotPdf("This file is not a PDF that can be read.".into()))?;
    if doc.is_signed() {
        return Err(EsignError::AlreadySigned);
    }
    let editor = doc.editor.as_ref().ok_or_else(|| EsignError::Validation("This PDF can be read but not changed.".into()))?;
    if let Some(refused) = signed_elsewhere_or_xfa(&editor.cos) {
        return Err(refused);
    }
    let rid = header.request_id;
    // Every field of this request is under `CraftOffice.R<id>.`: a file prepared before is refused.
    let prefix = format!("CraftOffice.R{rid}.");
    if pdfcraft_forms::fields(&editor.cos).iter().any(|f| f.name.starts_with(&prefix)) {
        return Err(EsignError::Validation("This PDF already has the fields of this signature request.".into()));
    }

    let pages = &doc.info.pages;
    for s in signers {
        let Some(at) = &s.placement else { continue };
        let n = at.page + 1;
        let page = pages
            .get(at.page)
            .ok_or_else(|| EsignError::NoField(format!("Signer {}'s place is on page {n}, but the PDF has {} pages.", s.position, pages.len())))?;
        let [cx0, cy0, cx1, cy1] = page.crop.map(f64::from);
        let r = at.rect;
        let (x0, y0, x1, y1) = (r[0].min(r[2]), r[1].min(r[3]), r[0].max(r[2]), r[1].max(r[3]));
        let inside = r.iter().all(|v| v.is_finite())
            && x0 >= cx0.min(cx1) - EDGE
            && y0 >= cy0.min(cy1) - EDGE
            && x1 <= cx0.max(cx1) + EDGE
            && y1 <= cy0.max(cy1) + EDGE;
        if !inside {
            return Err(EsignError::NoField(format!("Signer {}'s place is not inside page {n}.", s.position)));
        }
        if x1 - x0 < pdfcraft_forms::MIN_FIELD_SIDE || y1 - y0 < pdfcraft_forms::MIN_FIELD_SIDE {
            return Err(EsignError::NoField(format!("Signer {}'s place on page {n} is too small for a signature.", s.position)));
        }
    }

    let size = page_size(pages.last().map(|p| (f64::from(p.width), f64::from(p.height))));
    let edits = audit_edits(pages.len(), size, header, signers);
    session.apply(id, Edit::Batch { label: "Prepare signature request".into(), edits }).map_err(refusal)?;
    let out = session.save_bytes(id)?;
    // A file opened through a repair (a rebuilt cross-reference table, a missing page tree) is
    // written out whole: the input would survive only as a repaired copy, and every later
    // signature's claim that it covers the bytes the signer saw would rest on that copy.
    if !out.starts_with(bytes) {
        return Err(EsignError::Validation("This PDF is damaged; open it in PdfCraft and save it again before asking for signatures.".into()));
    }
    Ok(Prepared {
        sha256: sha256_hex(&out),
        bytes: out.to_vec(),
        fields: signers.iter().map(|s| (s.position, signer_field(rid, s.position))).collect(),
        seal_field: seal_field(rid),
    })
}
