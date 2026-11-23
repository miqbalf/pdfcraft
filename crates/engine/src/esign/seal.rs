//! Seal a signer's signature (`POST /v1/seal`) and, after the last signer, the final seal that
//! locks the document.
//!
//! Each signer gets one revision: their audit row filled in and an approval signature on their
//! field, made with the instance's digital ID and showing their mark. After the last signer a
//! second revision fills the Completed line, makes every form field but the signature fields
//! read-only (ISO 32000-2 §12.7.4.1, field flag ReadOnly, bit 1) and signs the seal field with a lock on the whole
//! document (`/Lock << /Action /All /P 1 >>` and a FieldMDP reference, P1's lock). Every
//! revision is appended to the bytes given, and checked before it is returned.

use std::sync::Arc;

use super::EsignError;
use super::inspect::{Opened, SignatureSummary, open, sha256_hex};
use super::prepare::{completed_field, parse_date, row_field, seal_field, signer_field};
use crate::{DocId, Edit, EditError, FieldProps, FieldValue, Session, SignOptions};
use pdfcraft_sign::{FieldLock, Modification, Status};

/// One signer's seal: who signs which request, with what mark, and the audit row's text (drawn
/// as given; the host puts the audit chain's count and head MAC in it).
pub struct SignerSeal<'a> {
    pub request_id: u64,
    pub position: u32,
    pub uid: &'a str,
    pub display_name: &'a str,
    pub graphic: &'a pdfcraft_sign::Graphic,
    pub row_text: &'a str,
    /// ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ`: the signing time the revision records.
    pub date: &'a str,
}

/// The final seal, added after the last signer's revision.
pub struct FinalSeal<'a> {
    /// The audit page's Completed line, drawn as given.
    pub completed_text: &'a str,
    /// ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ`.
    pub date: &'a str,
    pub instance: &'a str,
    pub organisation: &'a str,
}

/// The sealed file and what the host records about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`.
    pub sha256: String,
    /// The SHA-256 after the signer's revision: `sha256` when there is no final seal.
    pub after_signer_sha256: String,
    /// SHA-256 of the sealing certificate (DER), lowercase hex.
    pub cert_sha256: String,
    /// SHA-256 of the bytes the last signature's `/ByteRange` covers.
    pub byterange_sha256: String,
    /// Every signature this seal made carries an RFC 3161 timestamp.
    pub timestamped: bool,
    pub signatures: Vec<SignatureSummary>,
}

/// The reason a signer's approval signature carries.
fn signer_reason(display_name: &str, uid: &str) -> String {
    format!("Signed by {display_name} ({uid}) via Craft Office")
}

/// The reason the final seal carries.
fn seal_reason(instance: &str, organisation: &str) -> String {
    format!("Sealed by {instance} for {organisation}: all signers signed")
}

/// Fill a read-only text field through the edit path: unlock, fill, lock again, in one batch, so
/// the revision changes only its value and appearance (a form fill earlier signatures permit).
fn fill_read_only(name: &str, text: &str) -> [Edit; 3] {
    let read_only =
        |on: bool| Edit::SetFieldProps { name: name.into(), props: Box::new(FieldProps { read_only: Some(on), ..FieldProps::default() }) };
    [read_only(false), Edit::SetFieldValue { name: name.into(), value: FieldValue::Text(text.into()) }, read_only(true)]
}

/// Why the seal's edits were refused, in a sentence the signer can read. The inner text never
/// reaches the wire.
fn refusal(e: EditError) -> EsignError {
    match e {
        EditError::NotPermitted(_) => {
            EsignError::Validation("This PDF's security settings do not allow changes; remove its owner password first.".into())
        }
        other => other.into(),
    }
}

/// Open `bytes` at `now` for a seal revision; the field `field` must be an unsigned signature
/// field and `row` (if any) a field of the form.
fn open_for(bytes: &[u8], now: i64, field: &str, row: Option<&str>) -> Result<(Session, DocId), EsignError> {
    let (session, id) = match open(bytes, now)? {
        Opened::Doc(session, id) => (session, id),
        Opened::NeedsPassword => return Err(EsignError::NeedsPassword),
    };
    let doc = session.get(id).ok_or_else(|| EsignError::NotPdf("This file is not a PDF that can be read.".into()))?;
    match doc.signatures.iter().find(|s| s.field == field) {
        None => return Err(EsignError::NoField(format!("This PDF has no signature field {field}."))),
        Some(s) if s.signed => return Err(EsignError::NoField(format!("The signature field {field} is already signed."))),
        Some(_) => {}
    }
    let editor = doc.editor.as_ref().ok_or_else(|| EsignError::Validation("This PDF can be read but not changed.".into()))?;
    if let Some(row) = row
        && !pdfcraft_forms::fields(&editor.cos).iter().any(|f| f.name == row)
    {
        return Err(EsignError::NoField(format!("This PDF has no audit row {row}.")));
    }
    Ok((session, id))
}

/// Apply `edits` and sign `opts.field` in one revision appended to the opened bytes.
fn sign_revision(
    mut session: Session,
    doc: DocId,
    edits: Vec<Edit>,
    id: &pdfcraft_sign::DigitalId,
    mut opts: SignOptions,
    tsa: Option<&dyn pdfcraft_sign::TimestampAuthority>,
) -> Result<Vec<u8>, EsignError> {
    session.apply(doc, Edit::Batch { label: "Seal signature request".into(), edits }).map_err(refusal)?;
    opts.date = session.signing_date();
    let cos = session.signing_copy(doc)?;
    let signed = match tsa {
        Some(tsa) => pdfcraft_sign::sign_with_timestamp(&cos, id, &opts, tsa)?,
        None => pdfcraft_sign::sign(&cos, id, &opts)?,
    };
    drop(cos);
    let signed = Arc::new(signed);
    session.check_save(doc, &signed)?;
    Ok(Arc::try_unwrap(signed).unwrap_or_else(|a| a.to_vec()))
}

/// Check every signature of `bytes` as any validator would: each must be sound (`Valid`, or
/// `Unknown` because the instance's root is not trusted here) and nothing after it may be a
/// change it does not permit. Returns the signatures as the wire reports them, and whether the
/// signature on `field` carries a timestamp.
fn checked(bytes: &[u8], now: i64, field: &str) -> Result<(Vec<SignatureSummary>, bool), EsignError> {
    let failed = || EsignError::Validation("The sealed PDF did not pass its own signature check, so it was not kept.".into());
    let (session, id) = match open(bytes, now)? {
        Opened::Doc(session, id) => (session, id),
        Opened::NeedsPassword => return Err(failed()),
    };
    let doc = session.get(id).ok_or_else(failed)?;
    let signed: Vec<_> = doc.signatures.iter().filter(|s| s.signed).collect();
    for s in &signed {
        let fine = matches!(s.status, Status::Valid | Status::Unknown) && !matches!(s.modification, Modification::Disallowed(_));
        if !fine {
            return Err(failed());
        }
    }
    let timestamped = signed.iter().any(|s| s.field == field && s.timestamp);
    Ok((doc.signatures.iter().map(SignatureSummary::from).collect(), timestamped))
}

/// SHA-256 of the bytes `field`'s signature covers (its `/ByteRange`).
fn byterange_sha256(bytes: &[u8], field: &str) -> Result<String, EsignError> {
    let failed = || EsignError::Validation("The sealed PDF did not pass its own signature check, so it was not kept.".into());
    let cos = pdfcraft_cos::Document::open(Arc::new(bytes.to_vec())).map_err(|_| failed())?;
    let f = pdfcraft_forms::fields(&cos).into_iter().find(|f| f.name == field).ok_or_else(failed)?;
    let dict = cos.get(f.obj);
    let value = dict.as_dict().and_then(|d| d.get(b"V")).map(|v| cos.resolve(v)).ok_or_else(failed)?;
    let range = value.as_dict().and_then(|v| v.get(b"ByteRange")).map(|r| cos.resolve(r)).ok_or_else(failed)?;
    let numbers: Vec<usize> =
        range.as_array().map(|a| a.iter().filter_map(|n| n.as_int().and_then(|n| usize::try_from(n).ok())).collect()).unwrap_or_default();
    let mut parts: Vec<&[u8]> = Vec::new();
    for pair in numbers.chunks(2) {
        let [start, len] = pair else { return Err(failed()) };
        parts.push(bytes.get(*start..start.saturating_add(*len)).ok_or_else(failed)?);
    }
    if parts.is_empty() {
        return Err(failed());
    }
    Ok(pdfcraft_sign::DigestAlg::Sha256.digest(&parts).iter().map(|b| format!("{b:02x}")).collect())
}

/// Seal `signer`'s signature into `bytes`, and when `last` is given, the final seal after it.
/// With `tsa` every signature made here carries an RFC 3161 timestamp (PAdES B-T); a timestamp
/// that cannot be had fails the seal, and nothing is returned. The output starts with `bytes`.
pub fn seal(
    bytes: &[u8],
    id: &pdfcraft_sign::DigitalId,
    signer: &SignerSeal<'_>,
    last: Option<&FinalSeal<'_>>,
    tsa: Option<&dyn pdfcraft_sign::TimestampAuthority>,
) -> Result<Sealed, EsignError> {
    let now = parse_date(signer.date)?;
    let final_now = last.map(|f| parse_date(f.date)).transpose()?;
    let rid = signer.request_id;

    // Revision A: the signer's row and their approval signature.
    let field = signer_field(rid, signer.position);
    let row = row_field(rid, signer.position);
    let (session, doc) = open_for(bytes, now, &field, Some(&row))?;
    let opts = SignOptions {
        field: Some(field.clone()),
        reason: Some(signer_reason(signer.display_name, signer.uid)),
        graphic: Some(signer.graphic.clone()),
        ..SignOptions::default()
    };
    let after_signer = sign_revision(session, doc, fill_read_only(&row, signer.row_text).into(), id, opts, tsa)?;
    let (mut signatures, mut timestamped) = checked(&after_signer, now, &field)?;
    let mut out = after_signer.clone();
    let mut last_field = field;

    // Revision B: the Completed line, every field read-only, and the locking final seal.
    if let (Some(f), Some(final_now)) = (last, final_now) {
        let seal = seal_field(rid);
        let completed = completed_field(rid);
        let (session, doc) = open_for(&after_signer, final_now, &seal, Some(&completed))?;
        let mut edits: Vec<Edit> = fill_read_only(&completed, f.completed_text).into();
        let cos = session
            .get(doc)
            .and_then(|d| d.editor.as_ref())
            .map(|e| &e.cos)
            .ok_or_else(|| EsignError::Validation("This PDF can be read but not changed.".into()))?;
        // Every terminal field but the seal's own; Completed is locked again by its fill. A
        // signature field is left alone: a signed one cannot take another value, the seal's lock
        // covers it, and setting its flags redraws its look, which the signatures before would
        // count as a change of page content.
        let names: std::collections::BTreeSet<String> = pdfcraft_forms::fields(cos)
            .into_iter()
            .filter(|x| x.name != seal && x.name != completed && x.kind != pdfcraft_forms::FieldKind::Signature && !x.read_only())
            .map(|x| x.name)
            .collect();
        edits.extend(
            names
                .into_iter()
                .map(|name| Edit::SetFieldProps { name, props: Box::new(FieldProps { read_only: Some(true), ..FieldProps::default() }) }),
        );
        let opts = SignOptions {
            field: Some(seal.clone()),
            reason: Some(seal_reason(f.instance, f.organisation)),
            lock: Some(FieldLock::whole_document()),
            ..SignOptions::default()
        };
        out = sign_revision(session, doc, edits, id, opts, tsa)?;
        let (all, sealed_stamped) = checked(&out, final_now, &seal)?;
        signatures = all;
        timestamped &= sealed_stamped;
        last_field = seal;
    }

    if !out.starts_with(bytes) || !out.starts_with(&after_signer) {
        return Err(EsignError::Validation("The sealed PDF did not keep the bytes it was given, so it was not kept.".into()));
    }
    Ok(Sealed {
        sha256: sha256_hex(&out),
        after_signer_sha256: sha256_hex(&after_signer),
        cert_sha256: sha256_hex(&id.certificate.raw),
        byterange_sha256: byterange_sha256(&out, &last_field)?,
        timestamped,
        signatures,
        bytes: out,
    })
}
