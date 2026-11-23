//! Locking the document after signing (ISO 32000-2 §12.7.5.5, the signature field lock
//! dictionary with its `/P`; §12.8.1 signature references, §12.8.2.4 FieldMDP): the signature
//! that locks writes the lock and a FieldMDP reference and leaves the catalog's `/Perms` alone
//! (only the first signature may certify, §12.8.2.2), and the validator judges every later
//! revision by the lock's `/P`, as it would a certification's.

use std::sync::Arc;

use pdfcraft_cos::{Dict, Document, ObjRef, Object, PdfString, SaveOptions, write_incremental};
use pdfcraft_sign::dss::{self, Evidence};
use pdfcraft_sign::{FieldLock, LockAction, Modification, SignOptions, SignatureInfo, Status, Time, TrustStore, pkcs12, signatures};

use crate::pdf::{TestTsa, tsa_id};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn open(b: &[u8]) -> Document {
    Document::open(Arc::new(b.to_vec())).unwrap()
}

/// A classic-xref PDF of `objs`, numbered from 1, with object 1 as the catalog.
fn write_pdf(objs: &[&str]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

const PAGE: u32 = 3;
const NOTE: u32 = 7;

/// A one-page form with three empty signature fields, "S1", "S2" and "Seal", and a text field
/// "note".
fn form() -> Vec<u8> {
    form_with_seal("")
}

/// [`form`] with `extra` entries in the "Seal" field.
fn form_with_seal(extra: &str) -> Vec<u8> {
    let seal = format!("<< /Type /Annot /Subtype /Widget /FT /Sig /T (Seal) {extra} /Rect [20 80 280 120] /P 3 0 R /F 4 >>");
    write_pdf(&[
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 5 0 R 6 0 R 7 0 R] >> >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Annots [4 0 R 5 0 R 6 0 R 7 0 R] >>",
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (S1) /Rect [20 20 140 60] /P 3 0 R /F 4 >>",
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (S2) /Rect [160 20 280 60] /P 3 0 R /F 4 >>",
        &seal,
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (note) /V (hello) /Rect [20 200 280 220] /P 3 0 R /F 4 >>",
    ])
}

fn id() -> pkcs12::DigitalId {
    pkcs12::open(&data("rsa-aes.p12"), "test").unwrap()
}

/// The trust that makes signatures by [`id`] Valid.
fn trust() -> TrustStore {
    TrustStore { certs: vec![id().certificate.clone()] }
}

fn opts(field: Option<&str>, lock: Option<FieldLock>) -> SignOptions {
    SignOptions { field: field.map(Into::into), date: "D:20261123120000Z".into(), lock, ..SignOptions::default() }
}

fn sign(bytes: &[u8], field: Option<&str>, lock: Option<FieldLock>) -> Vec<u8> {
    pdfcraft_sign::sign(&open(bytes), &id(), &opts(field, lock)).unwrap()
}

fn info(bytes: &[u8], trust: &TrustStore, field: &str) -> SignatureInfo {
    signatures(&open(bytes), bytes, trust).into_iter().find(|s| s.field == field).unwrap()
}

/// The form field named `name` among the catalog's `/AcroForm /Fields`.
fn field(doc: &Document, name: &str) -> Dict {
    let root = doc.root().unwrap();
    let catalog = doc.get(root).as_dict().cloned().unwrap();
    let form = doc.resolve(catalog.get(b"AcroForm").unwrap()).as_dict().cloned().unwrap();
    let fields = doc.resolve(form.get(b"Fields").unwrap()).as_array().cloned().unwrap();
    fields
        .iter()
        .filter_map(|f| doc.resolve(f).as_dict().cloned())
        .find(|f| f.get(b"T").and_then(Object::as_string).map(PdfString::to_text).as_deref() == Some(name))
        .unwrap()
}

fn resolved_dict(doc: &Document, d: &Dict, key: &[u8]) -> Option<Dict> {
    d.get(key).and_then(|o| doc.resolve(o).as_dict().cloned())
}

fn edit_after(signed: &[u8], f: impl FnOnce(&mut Document)) -> Vec<u8> {
    let mut doc = open(signed);
    f(&mut doc);
    write_incremental(&doc, &SaveOptions { object_streams: false, ..SaveOptions::default() }).unwrap()
}

fn r(num: u32) -> ObjRef {
    ObjRef { num, generation: 0 }
}

fn is_disallowed(m: &Modification) -> bool {
    matches!(m, Modification::Disallowed(_))
}

/// The field's `/Lock` and the signature's FieldMDP reference say "all fields, no changes", and
/// the catalog has no `/Perms`.
fn assert_whole_document_lock(bytes: &[u8], name: &str) {
    let doc = open(bytes);
    let f = field(&doc, name);
    let lock = resolved_dict(&doc, &f, b"Lock").expect("the signed field has a /Lock");
    assert_eq!(lock.name(b"Type"), Some(&b"SigFieldLock"[..]));
    assert_eq!(lock.name(b"Action"), Some(&b"All"[..]));
    assert_eq!(lock.int(b"P"), Some(1));
    let v = resolved_dict(&doc, &f, b"V").expect("the field is signed");
    let refs = doc.resolve(v.get(b"Reference").expect("the signature has a /Reference")).as_array().cloned().unwrap();
    let field_mdp: Vec<Dict> =
        refs.iter().filter_map(|r| doc.resolve(r).as_dict().cloned()).filter(|r| r.name(b"TransformMethod") == Some(&b"FieldMDP"[..])).collect();
    assert_eq!(field_mdp.len(), 1, "one FieldMDP reference");
    assert_eq!(field_mdp[0].name(b"Type"), Some(&b"SigRef"[..]));
    let params = resolved_dict(&doc, &field_mdp[0], b"TransformParams").unwrap();
    assert_eq!(params.name(b"Action"), Some(&b"All"[..]));
    // `/Data`, required for FieldMDP (ISO 32000 signature reference dictionary): the object the
    // modification analysis starts from, the catalog.
    assert_eq!(field_mdp[0].get(b"Data").and_then(Object::as_ref), doc.root(), "FieldMDP /Data is the catalog");
    let catalog = doc.get(doc.root().unwrap()).as_dict().cloned().unwrap();
    assert!(catalog.get(b"Perms").is_none(), "a lock is not a certification");
}

#[test]
fn whole_document_lock_writes_lock_dict_and_fieldmdp_reference() {
    let input = form();
    let sealed = sign(&input, Some("Seal"), Some(FieldLock::whole_document()));
    assert!(sealed.starts_with(&input), "an incremental revision");
    assert_whole_document_lock(&sealed, "Seal");
    let s = info(&sealed, &trust(), "Seal");
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    assert_eq!(s.modification, Modification::None);
    assert_eq!(s.certify, None, "not a certification");
    assert_eq!(s.locks_document, Some(1));
}

#[test]
fn lock_p1_makes_a_later_form_fill_disallowed() {
    let sealed = sign(&form(), Some("Seal"), Some(FieldLock::whole_document()));
    let filled = edit_after(&sealed, |d| d.update_dict(r(NOTE), |n| n.set(b"V".to_vec(), PdfString::text("changed"))).unwrap());
    let s = info(&filled, &trust(), "Seal");
    assert!(is_disallowed(&s.modification), "{:?}", s.modification);
    assert_eq!(s.status, Status::Invalid);
    assert_eq!(s.locks_document, Some(1));
}

#[test]
fn lock_p1_makes_a_later_comment_disallowed() {
    // A comment touches no field, so only the lock's /P, not its field list, forbids it; the same
    // comment after an approval signature without a lock is permitted.
    let open_approval = comment(&sign(&form(), Some("Seal"), None));
    let s = info(&open_approval, &trust(), "Seal");
    assert!(!is_disallowed(&s.modification), "{:?}", s.modification);
    assert_eq!(s.locks_document, None);
    let locked = comment(&sign(&form(), Some("Seal"), Some(FieldLock::whole_document())));
    let s = info(&locked, &trust(), "Seal");
    assert!(is_disallowed(&s.modification), "{:?}", s.modification);
    assert_eq!(s.status, Status::Invalid);
}

#[test]
fn lock_p1_allows_a_later_document_timestamp_and_dss() {
    let id = id();
    let sealed = sign(&form(), Some("Seal"), Some(FieldLock::whole_document()));
    let tsa = TestTsa { id: tsa_id(), time: Time { year: 2026, month: 11, day: 23, hour: 13, minute: 0, second: 0 } };
    let trust = TrustStore { certs: vec![id.certificate.clone(), tsa.id.certificate.clone()] };
    let stamped = pdfcraft_sign::timestamp_document(&open(&sealed), &tsa, "D:20261123130000Z").unwrap();
    let s = info(&stamped, &trust, "Seal");
    assert!(matches!(s.modification, Modification::Allowed(_) | Modification::None), "{:?}", s.modification);
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    let ltv = dss::embed(&open(&stamped), &Evidence { certs: vec![id.certificate.raw.clone()], ocsps: Vec::new(), crls: Vec::new() }).unwrap();
    let s = info(&ltv, &trust, "Seal");
    assert!(matches!(s.modification, Modification::Allowed(_) | Modification::None), "{:?}", s.modification);
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    assert_eq!(s.locks_document, Some(1));
}

#[test]
fn earlier_unlocked_approvals_stay_valid_after_a_locked_seal() {
    let one = sign(&form(), Some("S1"), None);
    let two = sign(&one, Some("S2"), None);
    let sealed = sign(&two, Some("Seal"), Some(FieldLock::whole_document()));
    // For the poppler `pdfsig` oracle.
    std::fs::write(format!("{}/lock_after_signing_three_signatures.pdf", env!("CARGO_TARGET_TMPDIR")), &sealed).unwrap();
    for trust in [trust(), TrustStore::default()] {
        let all = signatures(&open(&sealed), &sealed, &trust);
        assert_eq!(all.iter().filter(|s| s.signed).count(), 3);
        for name in ["S1", "S2", "Seal"] {
            let s = all.iter().find(|s| s.field == name).unwrap();
            let expected = if trust.certs.is_empty() { Status::Unknown } else { Status::Valid };
            assert_eq!(s.status, expected, "{name}: {:?}", s.details);
            assert!(!is_disallowed(&s.modification), "{name}: {:?}", s.modification);
        }
    }
    assert_eq!(info(&sealed, &trust(), "S1").locks_document, None, "an approval does not lock");
    assert_eq!(info(&sealed, &trust(), "Seal").locks_document, Some(1));
}

#[test]
fn lock_on_a_new_invisible_field_is_written() {
    let input = form();
    let sealed = pdfcraft_sign::sign(
        &open(&input),
        &id(),
        &SignOptions { new_field_name: Some("Locked".into()), ..opts(None, Some(FieldLock::whole_document())) },
    )
    .unwrap();
    assert!(sealed.starts_with(&input), "an incremental revision");
    assert_whole_document_lock(&sealed, "Locked");
    let s = info(&sealed, &trust(), "Locked");
    assert!(!s.visible);
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    assert_eq!(s.locks_document, Some(1));
    // And it locks: a later form fill breaks it.
    let filled = edit_after(&sealed, |d| d.update_dict(r(NOTE), |n| n.set(b"V".to_vec(), PdfString::text("changed"))).unwrap());
    assert!(is_disallowed(&info(&filled, &trust(), "Locked").modification));
}

/// A text annotation added to the page after `signed`: a comment, which touches no field.
fn comment(signed: &[u8]) -> Vec<u8> {
    edit_after(signed, |d| {
        let mut a = Dict::new();
        a.set(b"Type".to_vec(), Object::name("Annot"));
        a.set(b"Subtype".to_vec(), Object::name("Text"));
        a.set(b"Rect".to_vec(), Object::Array([200, 250, 220, 270].iter().map(|x| Object::Int(*x)).collect()));
        a.set(b"Contents".to_vec(), PdfString::text("a comment"));
        let note = d.add(Object::Dict(a));
        d.update_dict(r(PAGE), |p| {
            if let Some(Object::Array(a)) = p.get_mut(b"Annots") {
                a.push(Object::Ref(note));
            }
        })
        .unwrap();
    })
}

#[test]
fn a_lock_whose_p_is_not_a_level_is_unchecked_not_open() {
    // A form author's lock with a `/P` outside 1..=3. Read as no `/P`, it would let a later
    // comment pass; it can't be read, so the signature is not Valid once anything changes.
    let input = form_with_seal("/Lock << /Type /SigFieldLock /Action /All /P 7 >>");
    let sealed = sign(&input, Some("Seal"), None);
    let s = info(&sealed, &trust(), "Seal");
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    assert_eq!(s.locks_document, None);
    let s = info(&comment(&sealed), &trust(), "Seal");
    assert_eq!(s.status, Status::Unknown, "{:?}", s.details);
}

#[test]
fn a_certification_that_also_locks_keeps_both_references() {
    let sealed =
        pdfcraft_sign::sign(&open(&form()), &id(), &SignOptions { certify: Some(3), ..opts(Some("Seal"), Some(FieldLock::whole_document())) })
            .unwrap();
    let doc = open(&sealed);
    let v = resolved_dict(&doc, &field(&doc, "Seal"), b"V").unwrap();
    let refs = doc.resolve(v.get(b"Reference").unwrap()).as_array().cloned().unwrap();
    let mut methods: Vec<Vec<u8>> =
        refs.iter().filter_map(|r| doc.resolve(r).as_dict().and_then(|d| d.name(b"TransformMethod").map(<[u8]>::to_vec))).collect();
    methods.sort();
    assert_eq!(methods, vec![b"DocMDP".to_vec(), b"FieldMDP".to_vec()]);
    let s = info(&sealed, &trust(), "Seal");
    assert_eq!((s.certify, s.locks_document), (Some(3), Some(1)));
    // The stricter of the two judges later changes: a comment, which P 3 alone permits, is not.
    assert!(is_disallowed(&info(&comment(&sealed), &trust(), "Seal").modification));
}

/// The one FieldMDP signature reference in the value of field `name`.
fn field_mdp(doc: &Document, name: &str) -> Dict {
    let v = resolved_dict(doc, &field(doc, name), b"V").unwrap();
    let refs = doc.resolve(v.get(b"Reference").unwrap()).as_array().cloned().unwrap();
    let mut found: Vec<Dict> =
        refs.iter().filter_map(|r| doc.resolve(r).as_dict().cloned()).filter(|r| r.name(b"TransformMethod") == Some(&b"FieldMDP"[..])).collect();
    assert_eq!(found.len(), 1);
    found.remove(0)
}

/// The names in `/Fields` of lock or transform parameters `d`.
fn listed(doc: &Document, d: &Dict) -> Vec<String> {
    let a = doc.resolve(d.get(b"Fields").unwrap()).as_array().cloned().unwrap();
    a.iter().map(|n| doc.resolve(n).as_string().map(PdfString::to_text).unwrap()).collect()
}

/// `signed` with the text field "note" filled in a later revision.
fn fill_note(signed: &[u8]) -> Vec<u8> {
    edit_after(signed, |d| d.update_dict(r(NOTE), |n| n.set(b"V".to_vec(), PdfString::text("changed"))).unwrap())
}

fn try_sign(bytes: &[u8], o: &SignOptions) -> Result<Vec<u8>, pdfcraft_sign::SignError> {
    pdfcraft_sign::sign(&open(bytes), &id(), o)
}

#[test]
fn a_later_approval_signature_after_a_p1_lock_is_disallowed() {
    // The guarantee the final seal exists for: nobody signs after it.
    let sealed = sign(&form(), Some("Seal"), Some(FieldLock::whole_document()));
    let later = sign(&sealed, Some("S1"), None);
    let s = info(&later, &trust(), "Seal");
    assert!(is_disallowed(&s.modification), "{:?}", s.modification);
    assert_eq!(s.status, Status::Invalid);
    assert_eq!(info(&later, &trust(), "S1").status, Status::Valid, "the later signature itself is intact");
}

#[test]
fn include_and_exclude_locks_name_their_fields() {
    for (action, word, fill_breaks) in
        [(LockAction::Include(vec!["note".into()]), &b"Include"[..], true), (LockAction::Exclude(vec!["note".into()]), &b"Exclude"[..], false)]
    {
        let sealed = sign(&form(), Some("Seal"), Some(FieldLock { action, permissions: None }));
        let doc = open(&sealed);
        let lock = resolved_dict(&doc, &field(&doc, "Seal"), b"Lock").unwrap();
        assert_eq!(lock.name(b"Action"), Some(word));
        assert_eq!(listed(&doc, &lock), ["note"]);
        assert!(lock.get(b"P").is_none(), "no /P without permissions");
        let reference = field_mdp(&doc, "Seal");
        let params = resolved_dict(&doc, &reference, b"TransformParams").unwrap();
        assert_eq!(params.name(b"Action"), Some(word));
        assert_eq!(listed(&doc, &params), ["note"]);
        assert_eq!(info(&sealed, &trust(), "Seal").locks_document, None);
        // Filling "note" breaks an Include lock that names it, not an Exclude lock that spares it.
        let s = info(&fill_note(&sealed), &trust(), "Seal");
        assert_eq!(is_disallowed(&s.modification), fill_breaks, "{word:?}: {:?}", s.modification);
    }
}

#[test]
fn p2_and_p3_locks_set_the_level_later_changes_are_judged_by() {
    let lock = |p| Some(FieldLock { action: LockAction::Include(vec!["note".into()]), permissions: Some(p) });
    // P 2: another signature is permitted, a comment is not.
    let p2 = sign(&form(), Some("Seal"), lock(2));
    assert_eq!(info(&p2, &trust(), "Seal").locks_document, Some(2));
    let s = info(&sign(&p2, Some("S1"), None), &trust(), "Seal");
    assert!(!is_disallowed(&s.modification), "{:?}", s.modification);
    assert!(is_disallowed(&info(&comment(&p2), &trust(), "Seal").modification));
    // P 3: a comment is permitted too.
    let p3 = sign(&form(), Some("Seal"), lock(3));
    assert_eq!(info(&p3, &trust(), "Seal").locks_document, Some(3));
    let s = info(&comment(&p3), &trust(), "Seal");
    assert!(!is_disallowed(&s.modification), "{:?}", s.modification);
    // The level never frees a field the lock names.
    assert!(is_disallowed(&info(&fill_note(&p3), &trust(), "Seal").modification));
}

#[test]
fn a_callers_lock_never_weakens_the_form_authors_lock() {
    let authored = form_with_seal("/Lock << /Type /SigFieldLock /Action /All /P 1 >>");
    let weaker = [
        FieldLock { action: LockAction::Include(vec!["note".into()]), permissions: Some(1) },
        FieldLock { action: LockAction::All, permissions: Some(2) },
        FieldLock { action: LockAction::All, permissions: None },
    ];
    for lock in weaker {
        assert!(try_sign(&authored, &opts(Some("Seal"), Some(lock.clone()))).is_err(), "{lock:?}");
    }
    // As strict: signed, the lock as strict as before.
    let sealed = sign(&authored, Some("Seal"), Some(FieldLock::whole_document()));
    assert_whole_document_lock(&sealed, "Seal");
    // No lock asked for: the author's stays and applies.
    let plain = sign(&authored, Some("Seal"), None);
    assert_eq!(info(&plain, &trust(), "Seal").locks_document, Some(1));
    // Stricter than the author's: the caller's is written.
    let authored = form_with_seal("/Lock << /Type /SigFieldLock /Action /Include /Fields [(note)] /P 2 >>");
    let sealed = sign(&authored, Some("Seal"), Some(FieldLock::whole_document()));
    assert_whole_document_lock(&sealed, "Seal");
}

#[test]
fn a_lock_never_grants_more_than_the_certification_in_force() {
    let looser = || Some(FieldLock { action: LockAction::All, permissions: Some(3) });
    let certified = try_sign(&form(), &SignOptions { certify: Some(2), ..opts(Some("S1"), None) }).unwrap();
    assert!(try_sign(&certified, &opts(Some("Seal"), looser())).is_err(), "P 3 after a P 2 certification");
    let sealed = sign(&certified, Some("Seal"), Some(FieldLock::whole_document()));
    assert_eq!(info(&sealed, &trust(), "S1").status, Status::Valid, "a lock is a signature P 2 permits");
    // Both in one signature.
    assert!(try_sign(&form(), &SignOptions { certify: Some(2), ..opts(Some("Seal"), looser()) }).is_err());
    // Out-of-range levels are refused, for a certification as for a lock.
    for p in [0, 4] {
        assert!(try_sign(&form(), &SignOptions { certify: Some(p), ..opts(Some("Seal"), None) }).is_err(), "certify {p}");
        let lock = Some(FieldLock { action: LockAction::All, permissions: Some(p) });
        assert!(try_sign(&form(), &opts(Some("Seal"), lock)).is_err(), "lock {p}");
    }
}

#[test]
fn a_null_lock_level_is_no_level() {
    // ISO 32000-2 §7.3.7: a key whose value is null is absent.
    let sealed = sign(&form_with_seal("/Lock << /Type /SigFieldLock /Action /Include /Fields [(note)] /P null >>"), Some("Seal"), None);
    let s = info(&comment(&sealed), &trust(), "Seal");
    assert_eq!(s.locks_document, None);
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
}

#[test]
fn a_dss_from_an_older_pdfcraft_keeps_a_p1_certification_valid() {
    let id = id();
    let certified = try_sign(&form(), &SignOptions { certify: Some(1), ..opts(Some("Seal"), None) }).unwrap();
    let ltv = dss::embed(&open(&certified), &Evidence { certs: vec![id.certificate.raw.clone()], ocsps: Vec::new(), crls: Vec::new() }).unwrap();
    let s = info(&ltv, &trust(), "Seal");
    assert!(matches!(s.modification, Modification::Allowed(_)), "{:?}", s.modification);
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    // Older builds also wrote `/Filter /Adobe.PPKLite` into the store, an entry nothing reads.
    let older = edit_after(&ltv, |d| {
        let root = d.root().unwrap();
        let store = d.get(root).as_dict().and_then(|c| c.get(b"DSS").and_then(Object::as_ref)).unwrap();
        d.update_dict(store, |x| x.set(b"Filter".to_vec(), Object::name("Adobe.PPKLite"))).unwrap();
    });
    let s = info(&older, &trust(), "Seal");
    assert!(matches!(s.modification, Modification::Allowed(_)), "{:?}", s.modification);
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
}
