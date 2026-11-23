//! Seal a signer's signature (`POST /v1/seal`) and, after the last signer, the final seal that
//! locks the document.
//!
//! Each signer gets one revision: their audit row filled in and an approval signature on their
//! field, made with the instance's digital ID and showing their mark. After the last signer a
//! second revision fills the Completed line, makes every form field but the signed signature fields
//! read-only (ISO 32000-2 §12.7.4.1, field flag ReadOnly, bit 1) and signs the seal field with a lock on the whole
//! document (`/Lock << /Action /All /P 1 >>` and a FieldMDP reference, P1's lock). Every
//! revision is appended to the bytes given, and checked before it is returned.

use std::cell::Cell;
use std::sync::Arc;

use super::EsignError;
use super::inspect::{Opened, SignatureSummary, open, session_at, sha256_hex};
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
    /// Every signature field and its verdict, checked against the sealing identity's root: the
    /// seal's own signatures read `valid` here, where `inspect`, trusting nothing, says `unknown`.
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

/// A timestamp authority that notes when the call to it fails, so that an authority that does
/// not answer is told apart from a PDF the signer refuses. A token that comes back but does not
/// check stays a signing error.
struct Noting<'a> {
    inner: &'a dyn pdfcraft_sign::TimestampAuthority,
    failed: Cell<bool>,
}

impl pdfcraft_sign::TimestampAuthority for Noting<'_> {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, pdfcraft_sign::SignError> {
        let answer = self.inner.timestamp(request);
        if answer.is_err() {
            self.failed.set(true);
        }
        answer
    }
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
        Some(tsa) => {
            let noting = Noting { inner: tsa, failed: Cell::new(false) };
            match pdfcraft_sign::sign_with_timestamp(&cos, id, &opts, &noting) {
                Ok(signed) => signed,
                Err(_) if noting.failed.get() => return Err(EsignError::TsaUnavailable),
                Err(e) => return Err(e.into()),
            }
        }
        None => pdfcraft_sign::sign(&cos, id, &opts)?,
    };
    drop(cos);
    let signed = Arc::new(signed);
    session.check_save(doc, &signed)?;
    Ok(Arc::try_unwrap(signed).unwrap_or_else(|a| a.to_vec()))
}

/// Check every signature of `bytes` as any validator would, trusting the root of the sealing
/// identity `trust`: the signatures this call made (`made`, the last one the newest) must exist,
/// be signed and be `Valid`; earlier ones must be sound (`Valid`, or `Unknown` when another
/// certificate made them, before a key rotation); and nothing after any of them may be a change
/// it does not permit. Returns the signatures as the wire reports them, and whether every one of
/// `made` carries a timestamp.
fn checked(bytes: &[u8], now: i64, trust: &[pdfcraft_sign::Certificate], made: &[&str]) -> Result<(Vec<SignatureSummary>, bool), EsignError> {
    let failed = || EsignError::Validation("The sealed PDF did not pass its own signature check, so it was not kept.".into());
    let mut session = session_at(now);
    session.set_trusted_certificates(trust.to_vec());
    let id = match session.open("document.pdf", None, Arc::new(bytes.to_vec()), None) {
        Ok(id) => id,
        Err(_) => return Err(failed()),
    };
    let doc = session.get(id).ok_or_else(failed)?;
    let signed: Vec<_> = doc.signatures.iter().filter(|s| s.signed).collect();
    for s in &signed {
        let ours = made.contains(&s.field.as_str());
        let sound = if ours { matches!(s.status, Status::Valid) } else { matches!(s.status, Status::Valid | Status::Unknown) };
        if !sound || matches!(s.modification, Modification::Disallowed(_)) {
            return Err(failed());
        }
    }
    let mut timestamped = true;
    for field in made {
        let s = signed.iter().find(|s| s.field == *field).ok_or_else(failed)?;
        timestamped &= s.timestamp;
    }
    Ok((doc.signatures.iter().map(SignatureSummary::from).collect(), timestamped))
}

/// The certificate the seal's signatures are checked against: the root of the identity's chain,
/// or its own certificate when it has none.
fn root_of(id: &pdfcraft_sign::DigitalId) -> Vec<pdfcraft_sign::Certificate> {
    vec![id.chain.last().cloned().unwrap_or_else(|| id.certificate.clone())]
}

/// SHA-256 of the bytes `field`'s signature covers (its `/ByteRange`).
fn byterange_sha256(bytes: &[u8], field: &str) -> Result<String, EsignError> {
    let failed = || EsignError::Validation("The sealed PDF did not pass its own signature check, so it was not kept.".into());
    let cos = pdfcraft_cos::Document::open(Arc::new(bytes.to_vec())).map_err(|_| failed())?;
    let f = pdfcraft_forms::fields(&cos).into_iter().find(|f| f.name == field).ok_or_else(failed)?;
    let dict = cos.get(f.obj);
    let value = dict.as_dict().and_then(|d| d.get(b"V")).map(|v| cos.resolve(v)).ok_or_else(failed)?;
    let range = value.as_dict().and_then(|v| v.get(b"ByteRange")).map(|r| cos.resolve(r)).ok_or_else(failed)?;
    // Exactly four non-negative integers, as every signature here writes it: two ranges.
    let numbers: Option<Vec<usize>> = range.as_array().and_then(|a| a.iter().map(|n| n.as_int().and_then(|n| usize::try_from(n).ok())).collect());
    let Some([a, b, c, d]) = numbers.as_deref().and_then(|n| <[usize; 4]>::try_from(n).ok()) else { return Err(failed()) };
    let first = bytes.get(a..a.saturating_add(b)).ok_or_else(failed)?;
    let second = bytes.get(c..c.saturating_add(d)).ok_or_else(failed)?;
    let parts = [first, second];
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
    if final_now.is_some_and(|t| t < now) {
        return Err(EsignError::Validation("The final seal's date is earlier than the last signature's.".into()));
    }
    let trust = root_of(id);
    let rid = signer.request_id;

    // Revision A: the signer's row and their approval signature.
    let field = signer_field(rid, signer.position);
    let row = row_field(rid, signer.position);
    let (session, doc) = open_for(bytes, now, &field, Some(&row))?;
    // The final seal locks the document: a signer whose field is still empty could never sign.
    // Checked before anything is signed, so a refused call costs no signature.
    if last.is_some() {
        let signer_prefix = format!("CraftOffice.R{rid}.S");
        let waiting = session.get(doc).is_some_and(|d| {
            d.signatures.iter().any(|s| {
                let is_signer = s.field.strip_prefix(&signer_prefix).is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()));
                is_signer && s.field != field && !s.signed
            })
        });
        if waiting {
            return Err(EsignError::Validation("Not every signer has signed yet, so the document was not sealed.".into()));
        }
    }
    let opts = SignOptions {
        field: Some(field.clone()),
        reason: Some(signer_reason(signer.display_name, signer.uid)),
        graphic: Some(signer.graphic.clone()),
        ..SignOptions::default()
    };
    let after_signer = sign_revision(session, doc, fill_read_only(&row, signer.row_text).into(), id, opts, tsa)?;
    let (mut signatures, mut timestamped) = checked(&after_signer, now, &trust, &[&field])?;
    let mut out = after_signer.clone();
    let mut last_field = field;

    // Revision B: the Completed line, every field read-only, and the locking final seal.
    if let (Some(f), Some(final_now)) = (last, final_now) {
        let seal = seal_field(rid);
        let completed = completed_field(rid);
        let (session, doc) = open_for(&after_signer, final_now, &seal, Some(&completed))?;
        let mut edits: Vec<Edit> = fill_read_only(&completed, f.completed_text).into();
        let opened = session.get(doc).ok_or_else(|| EsignError::Validation("This PDF can be read but not changed.".into()))?;
        let cos = opened.editor.as_ref().map(|e| &e.cos).ok_or_else(|| EsignError::Validation("This PDF can be read but not changed.".into()))?;
        let signed: std::collections::BTreeSet<&str> = opened.signatures.iter().filter(|s| s.signed).map(|s| s.field.as_str()).collect();
        // Every terminal field but the seal's own; Completed is locked again by its fill. A
        // signed signature field is left alone: it cannot take another value, the seal's lock
        // covers it, and setting its flags redraws its look, which the signatures before would
        // count as a change of page content. An unsigned one (the source PDF's own) is made
        // read-only, so a viewer that ignores the lock does not offer it (P4 review m3).
        let names: std::collections::BTreeSet<String> = pdfcraft_forms::fields(cos)
            .into_iter()
            .filter(|x| x.name != seal && x.name != completed && !x.read_only())
            .filter(|x| x.kind != pdfcraft_forms::FieldKind::Signature || !signed.contains(x.name.as_str()))
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
        (signatures, timestamped) = checked(&out, final_now, &trust, &[&last_field, &seal])?;
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
