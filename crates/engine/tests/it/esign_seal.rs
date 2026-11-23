//! E-sign seal and the locking final seal (`pdfcraft_engine::esign::seal`).

use std::sync::Arc;

use pdfcraft_cos::{PdfString, SaveOptions, write_incremental};
use pdfcraft_engine::esign::{
    AuditHeader, EsignError, FinalSeal, Placement, SignerSeal, SignerSlot, completed_field, graphic_from_json, inspect, inspect_trusting, prepare,
    row_field, seal, seal_field, signer_field,
};
use pdfcraft_engine::sign::der;
use pdfcraft_engine::sign::timestamp::{TimestampIssuance, TimestampSigner, parse_request, respond};
use pdfcraft_engine::sign::{Certificate, DigitalId, Graphic, Name, PrivateKey, SignError, Time, TimestampAuthority, pkcs12};
use pdfcraft_engine::{Edit, FieldValue, FormFieldKind, NewAnnotation, NewField, NoteIcon, Session, Shape, Style};
use serde_json::json;

const RID: u64 = 42;
const PREPARED_AT: &str = "2026-11-23T09:00:00Z";
const DATES: [&str; 3] = ["2026-11-23T10:00:00Z", "2026-11-23T11:00:00Z", "2026-11-23T12:00:00Z"];
const FINAL_AT: &str = "2026-11-23T12:00:00Z";
const HEAD_MAC: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const COMPLETED: &str = "Completed 2026-11-23T12:00:00Z; 3 signers; sealed by workspace.treeo.id; chain 7 events, head MAC 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn blank(pages: usize) -> Vec<u8> {
    Session::new().with_clock(|| 1_700_000_000).create_blank(612.0, 792.0, pages).expect("blank").to_vec()
}

fn header() -> AuditHeader {
    AuditHeader {
        request_id: RID,
        title: "Supply contract".into(),
        requester_uid: "alice".into(),
        requester_name: "Alice Doe".into(),
        created_utc: "2026-11-23T08:00:00Z".into(),
        instance: "workspace.treeo.id".into(),
        organisation: "PT Solusi Hutan Digital".into(),
    }
}

const SIGNERS: [(&str, &str); 3] = [("bob", "Bob Brown"), ("carol", "Carol Chan"), ("dan", "Dan Dewi")];

/// A one-page PDF prepared for three signers: Bob and Dan sign on the audit page, Carol on page 1.
fn prepared() -> Vec<u8> {
    let slots: Vec<SignerSlot> = SIGNERS
        .iter()
        .enumerate()
        .map(|(i, (uid, name))| SignerSlot {
            position: i as u32 + 1,
            uid: (*uid).into(),
            display_name: (*name).into(),
            placement: (i == 1).then_some(Placement { page: 0, rect: [100.0, 100.0, 280.0, 140.0] }),
        })
        .collect();
    prepare(&form(), &header(), &slots, PREPARED_AT).expect("prepares").bytes
}

/// A one-page PDF with a form field of its own, filled before the request.
fn form() -> Vec<u8> {
    let mut s = Session::new().with_clock(|| 1_700_000_000);
    let id = s.open("x.pdf", None, Arc::new(blank(1)), None).expect("opens");
    let add = Edit::AddField { page: 0, rect: [100.0, 600.0, 300.0, 630.0], kind: NewField::Text { multiline: false }, name: Some("Vendor".into()) };
    s.apply(id, add).expect("adds");
    s.apply(id, Edit::SetFieldValue { name: "Vendor".into(), value: FieldValue::Text("PT Contoh".into()) }).expect("fills");
    s.save_bytes(id).expect("saves").to_vec()
}

fn id() -> DigitalId {
    let p12 = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/chain.p12")).expect("chain.p12");
    pkcs12::open(&p12, "test").expect("p12")
}

fn mark(name: &str) -> Graphic {
    graphic_from_json(&json!({ "kind": "name" }), name).expect("mark")
}

fn row_text(position: usize) -> String {
    format!("Signed 2026-11-23 by signer {position}; chain {} events, head MAC {HEAD_MAC}", position + 3)
}

fn final_seal() -> FinalSeal<'static> {
    FinalSeal { completed_text: COMPLETED, date: FINAL_AT, instance: "workspace.treeo.id", organisation: "PT Solusi Hutan Digital" }
}

/// Seal signer `position` (1-based) into `bytes`.
fn seal_one(bytes: &[u8], position: usize, last: bool, tsa: Option<&dyn TimestampAuthority>) -> Result<pdfcraft_engine::esign::Sealed, EsignError> {
    let (uid, name) = SIGNERS[position - 1];
    let graphic = mark(name);
    let text = row_text(position);
    let signer = SignerSeal {
        request_id: RID,
        position: position as u32,
        uid,
        display_name: name,
        graphic: &graphic,
        row_text: &text,
        date: DATES[position - 1],
    };
    let fin = final_seal();
    seal(bytes, &id(), &signer, last.then_some(&fin), tsa)
}

/// The three signers in turn, the final seal with the third. Every step's input and output.
fn all_three(tsa: Option<&dyn TimestampAuthority>) -> Vec<(Vec<u8>, pdfcraft_engine::esign::Sealed)> {
    let mut steps = Vec::new();
    let mut bytes = prepared();
    for p in 1..=3 {
        let out = seal_one(&bytes, p, p == 3, tsa).expect("seals");
        let next = out.bytes.clone();
        steps.push((bytes, out));
        bytes = next;
    }
    steps
}

fn infos(bytes: &[u8]) -> Vec<pdfcraft_engine::SignatureInfo> {
    let cos = pdfcraft_cos::Document::open(Arc::new(bytes.to_vec())).expect("reopens");
    pdfcraft_engine::sign::signatures(&cos, bytes, &pdfcraft_engine::TrustStore::default())
}

fn fields(bytes: &[u8]) -> Vec<pdfcraft_engine::FormField> {
    let cos = pdfcraft_cos::Document::open(Arc::new(bytes.to_vec())).expect("reopens");
    pdfcraft_forms::fields(&cos)
}

/// A deterministic RFC 3161 authority: a self-signed P-256 identity whose only (critical) extended
/// key usage is time stamping, answering at a fixed time. Nothing leaves the process.
struct TestTsa {
    id: DigitalId,
}

impl TestTsa {
    fn new() -> Self {
        let key = PrivateKey::generate_p256().expect("key");
        let name = Name::build("Test TSA", "", "PdfCraft Tests", "", "US");
        let alg = key.preferred_digest();
        let sig_alg = key.signature_algorithm(alg);
        let from = Time { year: 2026, month: 10, day: 2, hour: 0, minute: 0, second: 0 };
        let until = Time { year: 2036, ..from };
        let eku = der::seq(&[&der::oid("2.5.29.37"), &der::boolean(true), &der::octets(&der::seq(&[&der::oid("1.3.6.1.5.5.7.3.8")]))]);
        let tbs = der::seq(&[
            &der::explicit(0, &der::int(2)),
            &der::uint(&[0x31]),
            &sig_alg,
            &name.raw,
            &der::seq(&[&from.encode(), &until.encode()]),
            &name.raw,
            &key.public_key().spki(),
            &der::explicit(3, &der::seq(&[&eku])),
        ]);
        let signature = key.sign(alg, &tbs).expect("signs");
        let certificate = Certificate::parse(&der::seq(&[&tbs, &sig_alg, &der::bit_string(&signature)])).expect("certificate");
        TestTsa { id: DigitalId { key, certificate, chain: Vec::new(), friendly_name: None } }
    }
}

impl TimestampAuthority for TestTsa {
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, SignError> {
        let q = parse_request(request)?;
        respond(
            TimestampSigner {
                key: &self.id.key,
                certificate: &self.id.certificate,
                chain: &self.id.chain,
                digest: pdfcraft_engine::sign::DigestAlg::Sha256,
            },
            TimestampIssuance {
                query: &q,
                policy: "1.2.3.4",
                generation_time: Time { year: 2026, month: 11, day: 23, hour: 12, minute: 0, second: 5 },
                serial: 7,
            },
        )
    }
}

struct DownTsa;

impl TimestampAuthority for DownTsa {
    fn timestamp(&self, _request: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::Pdf("the authority did not answer".into()))
    }
}

#[test]
fn three_signers_in_turn_then_final_seal_all_valid() {
    let steps = all_three(None);
    let last = &steps[2].1;
    let report = inspect(&last.bytes).expect("inspects");
    let signed: Vec<_> = report.signatures.iter().filter(|s| s.signed).collect();
    assert_eq!(signed.len(), 4, "three signers and the seal: {signed:?}");
    for s in &signed {
        assert!(s.status == "valid" || s.status == "unknown", "{s:?}");
    }
    for p in 1..=3 {
        let s = signed.iter().find(|s| s.field == signer_field(RID, p)).expect("signer's signature");
        assert_eq!(s.modification, "allowed", "a later row fill, signature and seal are permitted: {s:?}");
    }
    let s = signed.iter().find(|s| s.field == seal_field(RID)).expect("the seal");
    assert_eq!(s.modification, "none", "the seal covers the whole file");
    // The seal checks against its own root (the instance CA), so its own signatures are valid;
    // inspect, trusting nothing, sees them as unknown. Everything else is the same.
    assert_eq!(last.signatures.len(), report.signatures.len());
    for (ours, seen) in last.signatures.iter().zip(&report.signatures) {
        assert_eq!((&ours.field, ours.signed, &ours.modification), (&seen.field, seen.signed, &seen.modification));
        if ours.signed {
            assert_eq!(ours.status, "valid", "the seal's own signatures verify against its root: {ours:?}");
            assert_eq!(seen.status, "unknown");
        }
    }
    // What the later revisions are, in the validator's own words: form fill and signatures only,
    // plus the document's modification date that every edited revision updates.
    for i in infos(&last.bytes).iter().filter(|i| i.signed && i.field != seal_field(RID)) {
        let pdfcraft_engine::sign::Modification::Allowed(kinds) = &i.modification else { panic!("{}: {:?}", i.field, i.modification) };
        for k in kinds {
            use pdfcraft_engine::sign::kind::{FORM_FILL, METADATA, SIGNATURE};
            assert!([FORM_FILL, SIGNATURE, METADATA].contains(k), "{}: {kinds:?}", i.field);
        }
    }
    let first = &steps[0].1;
    assert_eq!(first.after_signer_sha256, first.sha256, "no final seal: one revision");
    assert_ne!(last.after_signer_sha256, last.sha256, "the final seal is a second revision");
    let cert = pdfcraft_engine::sign::DigestAlg::Sha256.digest(&[&id().certificate.raw]);
    assert_eq!(last.cert_sha256, cert.iter().map(|b| format!("{b:02x}")).collect::<String>());
    assert!(!last.timestamped);
}

#[test]
fn every_output_starts_with_its_input() {
    for (input, out) in all_three(None) {
        assert!(out.bytes.len() > input.len());
        assert!(out.bytes.starts_with(&input), "an incremental update of the bytes given");
    }
}

#[test]
fn the_byte_range_digest_is_of_what_the_last_signature_covers() {
    let steps = all_three(None);
    let last = &steps[2].1;
    let seal_info = infos(&last.bytes).into_iter().find(|i| i.field == seal_field(RID)).expect("seal");
    // The seal is the last revision: it covers everything but its own /Contents.
    assert_eq!(seal_info.signed_len, last.bytes.len());
    assert_ne!(last.byterange_sha256, last.sha256, "the /Contents hole is left out");
    let middle = &steps[1].1;
    assert_ne!(middle.byterange_sha256, last.byterange_sha256);
}

#[test]
fn final_seal_locks() {
    let steps = all_three(None);
    let sealed = steps[2].1.bytes.clone();
    // A later revision fills the Completed line again, as a tamperer could with any tool.
    let mut cos = pdfcraft_cos::Document::open(Arc::new(sealed.clone())).expect("reopens");
    let completed = pdfcraft_forms::fields(&cos).into_iter().find(|f| f.name == completed_field(RID)).expect("Completed");
    cos.update_dict(completed.obj, |d| d.set(b"V".to_vec(), PdfString::text("Completed by nobody"))).expect("edits");
    let tampered = write_incremental(&cos, &SaveOptions { object_streams: false, ..SaveOptions::default() }).expect("writes");
    assert!(tampered.starts_with(&sealed));
    let report = inspect(&tampered).expect("inspects");
    let s = report.signatures.iter().find(|s| s.field == seal_field(RID)).expect("the seal");
    assert_eq!(s.modification, "disallowed", "nothing may change after the final seal: {s:?}");
    let seal_info = infos(&sealed).into_iter().find(|i| i.field == seal_field(RID)).expect("seal");
    assert_eq!(seal_info.locks_document, Some(1), "P1's whole-document lock");

    // The lock's /P 1 judges every change, not only the fields FieldMDP names: a comment and a
    // page added afterwards are refused too.
    let edited = |edit: Edit| {
        let mut s = Session::new().with_clock(|| 1_795_500_000);
        let id = s.open("x.pdf", None, Arc::new(sealed.clone()), None).expect("opens");
        s.apply(id, edit).expect("edits");
        let out = s.save_bytes(id).expect("saves").to_vec();
        assert!(out.starts_with(&sealed), "saved incrementally");
        out
    };
    let shape = Shape::Note { at: [100.0, 700.0], icon: NoteIcon::Comment };
    let style = Style::default_for(&shape);
    let commented = edited(Edit::AddAnnotation(NewAnnotation { page: 0, style, shape, contents: "Later".into(), author: "Eve".into() }));
    let paged = edited(Edit::InsertBlankPage { at: 1, width: 612.0, height: 792.0 });
    for (what, bytes) in [("a comment", commented), ("a page", paged)] {
        let report = inspect(&bytes).expect("inspects");
        let s = report.signatures.iter().find(|s| s.field == seal_field(RID)).expect("the seal");
        assert_eq!(s.modification, "disallowed", "{what} after the final seal: {s:?}");
    }
}

#[test]
fn fields_are_read_only_after_final_seal() {
    let steps = all_three(None);
    let before = fields(&steps[1].1.bytes);
    assert!(before.iter().any(|f| f.name == "Vendor" && !f.read_only()), "before the final seal the PDF's own field can be filled");
    for f in fields(&steps[2].1.bytes) {
        // Signature fields are signed (or the seal itself); the seal's lock covers them.
        if f.kind == FormFieldKind::Signature {
            continue;
        }
        assert!(f.read_only(), "{} is read-only after the final seal", f.name);
    }
}

#[test]
fn with_tsa_each_signature_is_timestamped() {
    let tsa = TestTsa::new();
    let steps = all_three(Some(&tsa));
    let last = &steps[2].1;
    let signed: Vec<_> = infos(&last.bytes).into_iter().filter(|i| i.signed).collect();
    assert_eq!(signed.len(), 4);
    for i in &signed {
        assert!(i.timestamp, "{} carries a timestamp", i.field);
    }
    assert!(steps.iter().all(|(_, s)| s.timestamped));
}

#[test]
fn tsa_error_fails_without_output() {
    let err = seal_one(&prepared(), 1, false, Some(&DownTsa)).expect_err("no timestamp, no seal");
    assert!(matches!(err, EsignError::TsaUnavailable), "{err:?}");
    assert_eq!(err.code(), "tsa_unavailable", "the worker answers 503, so the host retries");
    assert_eq!(err.to_string(), "The timestamp service did not answer; nothing was signed. Try again.", "no inner text on the wire");
    // The final seal's timestamp failing fails the whole call too.
    let two = all_three(None)[1].1.bytes.clone();
    let err = seal_one(&two, 3, true, Some(&DownTsa)).expect_err("refused");
    assert!(matches!(err, EsignError::TsaUnavailable), "{err:?}");
}

/// The final seal locks the document, so it is refused while a signer's field is still empty:
/// sealed early, that signer could never sign.
#[test]
fn final_seal_refuses_while_a_signer_has_not_signed() {
    let err = seal_one(&prepared(), 1, true, None).expect_err("two signers have not signed");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("Not every signer has signed"), "{err}");
    // With the other two signed, the same call on the third goes through (all_three).
    let two = all_three(None)[1].1.bytes.clone();
    assert!(seal_one(&two, 3, true, None).is_ok());
}

#[test]
fn a_final_seal_dated_before_the_signer_is_refused() {
    let two = all_three(None)[1].1.bytes.clone();
    let (uid, name) = SIGNERS[2];
    let graphic = mark(name);
    let text = row_text(3);
    let signer = SignerSeal { request_id: RID, position: 3, uid, display_name: name, graphic: &graphic, row_text: &text, date: DATES[2] };
    let early = FinalSeal { date: "2026-11-23T11:59:59Z", ..final_seal() };
    let err = seal(&two, &id(), &signer, Some(&early), None).expect_err("the seal would predate the approval it closes");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
}

#[test]
fn same_key_same_date_same_bytes() {
    let a = all_three(None);
    let b = all_three(None);
    for ((_, x), (_, y)) in a.iter().zip(&b) {
        assert!(x.bytes == y.bytes, "the same inputs seal to the same bytes");
        assert_eq!(x, y);
    }
}

#[test]
fn row_and_completed_text_are_on_the_audit_page() {
    let steps = all_three(None);
    let last = &steps[2].1.bytes;
    let audit_page = {
        let mut s = Session::new();
        let id = s.open("x.pdf", None, Arc::new(last.clone()), None).expect("opens");
        s.get(id).expect("doc").info.pages.len() - 1
    };
    let all = fields(last);
    let mut expect: Vec<(String, String)> = (1..=3).map(|p| (row_field(RID, p as u32), row_text(p))).collect();
    expect.push((completed_field(RID), COMPLETED.to_string()));
    for (name, text) in expect {
        let f = all.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(f.value, vec![text.clone()], "{name} holds the host's text verbatim");
        assert!(text.contains(HEAD_MAC));
        let w = f.widgets.first().expect("a widget");
        assert_eq!(w.page, Some(audit_page), "{name} is on the audit page");
        let cos = pdfcraft_cos::Document::open(Arc::new(last.clone())).expect("reopens");
        let ap = cos.get(w.obj).as_dict().and_then(|d| d.get(b"AP").cloned());
        assert!(ap.is_some(), "{name} is drawn, not only stored");
    }
}

#[test]
fn parallel_seal_on_newer_bytes_keeps_earlier_signature_valid() {
    let base = prepared();
    // Bob and Carol both opened `base`; Bob's seal lands first, Carol's is made on Bob's output.
    let bob = seal_one(&base, 1, false, None).expect("bob");
    let carol = seal_one(&bob.bytes, 2, false, None).expect("carol on the newer bytes");
    assert!(carol.bytes.starts_with(&bob.bytes) && carol.bytes.starts_with(&base));
    let report = inspect(&carol.bytes).expect("inspects");
    for p in [1, 2] {
        let s = report.signatures.iter().find(|s| s.field == signer_field(RID, p)).expect("signature");
        assert!(s.signed && (s.status == "valid" || s.status == "unknown"), "{s:?}");
        assert_ne!(s.modification, "disallowed", "{s:?}");
    }
}

#[test]
fn refuses_seal_when_signer_field_already_signed() {
    let once = seal_one(&prepared(), 1, false, None).expect("seals");
    let err = seal_one(&once.bytes, 1, false, None).expect_err("signed twice");
    assert!(matches!(err, EsignError::NoField(_)), "{err:?}");
    assert_eq!(err.code(), "no_field");
}

#[test]
fn writes_oracle_file() {
    let steps = all_three(None);
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("esign-final.pdf");
    std::fs::write(&path, &steps[2].1.bytes).expect("writes");
    assert_eq!(infos(&steps[2].1.bytes).iter().filter(|i| i.signed).count(), 4);
}

/// The fixed time is the session's own (P3 review M4): two sessions on one thread keep their own
/// times, and an edit that makes ids (a note's `/NM`) gives the same bytes for the same inputs.
#[test]
fn a_fixed_time_is_per_session_and_its_edits_are_byte_deterministic() {
    let early = Session::new().with_fixed_time(1_795_000_000);
    let late = Session::new().with_fixed_time(1_795_999_999);
    assert_eq!((early.now_secs(), late.now_secs()), (1_795_000_000, 1_795_999_999));
    let noted = |t: i64| {
        let mut s = Session::new().with_fixed_time(t);
        let id = s.open("x.pdf", None, Arc::new(blank(1)), None).expect("opens");
        let shape = Shape::Note { at: [100.0, 700.0], icon: NoteIcon::Comment };
        let style = Style::default_for(&shape);
        s.apply(id, Edit::AddAnnotation(NewAnnotation { page: 0, style, shape, contents: "Note".into(), author: "Ada".into() })).expect("notes");
        s.save_bytes(id).expect("saves").to_vec()
    };
    let one = noted(1_795_000_000);
    std::thread::sleep(std::time::Duration::from_millis(30));
    assert!(one == noted(1_795_000_000), "the same time and edit give the same bytes");
    assert!(one != noted(1_795_000_001), "the time is in the file");
}

#[test]
fn a_bad_date_is_refused() {
    let graphic = mark("Bob Brown");
    let signer =
        SignerSeal { request_id: RID, position: 1, uid: "bob", display_name: "Bob Brown", graphic: &graphic, row_text: "x", date: "23/11/2026" };
    let err = seal(&prepared(), &id(), &signer, None, None).expect_err("refused");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
}

/// With the seal's root trusted, as the worker does (P4 review concern 1), `inspect` agrees with
/// the seal: the request's signatures read valid, not unknown.
#[test]
fn inspect_trusting_the_seal_root_agrees_with_the_seal() {
    let steps = all_three(None);
    let last = &steps[2].1;
    let id = id();
    let root = id.chain.last().cloned().unwrap_or_else(|| id.certificate.clone());
    let report = inspect_trusting(&last.bytes, &[root]).expect("inspects");
    assert_eq!(report.signatures, last.signatures, "the same verdicts as the seal's own check");
    assert!(report.signatures.iter().filter(|s| s.signed).all(|s| s.status == "valid"), "{:?}", report.signatures);
    assert_eq!(report.sha256, inspect(&last.bytes).expect("inspects").sha256);
}

/// A PDF with a signature field of its own, left unsigned, prepared for the three signers.
fn prepared_with_own_signature_field() -> Vec<u8> {
    let mut s = Session::new().with_clock(|| 1_700_000_000);
    let id = s.open("x.pdf", None, Arc::new(form()), None).expect("opens");
    let add = Edit::AddField { page: 0, rect: [320.0, 600.0, 500.0, 650.0], kind: NewField::Signature, name: Some("Witness".into()) };
    s.apply(id, add).expect("adds");
    let source = s.save_bytes(id).expect("saves").to_vec();
    let slots: Vec<SignerSlot> = SIGNERS
        .iter()
        .enumerate()
        .map(|(i, (uid, name))| SignerSlot { position: i as u32 + 1, uid: (*uid).into(), display_name: (*name).into(), placement: None })
        .collect();
    prepare(&source, &header(), &slots, PREPARED_AT).expect("prepares").bytes
}

/// P4 review m3: after the final seal, a viewer that ignores the seal's lock still offers no
/// field to sign, the source PDF's own unsigned signature fields included; every signature stays
/// sound.
#[test]
fn the_source_pdf_s_unsigned_signature_fields_are_read_only_after_final_seal() {
    let mut bytes = prepared_with_own_signature_field();
    let own = |b: &[u8]| fields(b).into_iter().find(|f| f.name == "Witness").expect("the PDF's own signature field");
    assert!(!own(&bytes).read_only(), "before the request ends it can be signed");
    let mut last = None;
    for p in 1..=3 {
        let out = seal_one(&bytes, p, p == 3, None).expect("seals");
        bytes = out.bytes.clone();
        last = Some(out);
    }
    assert!(own(&bytes).read_only(), "read-only after the final seal");
    let last = last.expect("sealed");
    for s in last.signatures.iter().filter(|s| s.signed) {
        assert_eq!(s.status, "valid", "{s:?}");
        assert_ne!(s.modification, "disallowed", "{s:?}");
    }
    assert!(last.signatures.iter().any(|s| s.field == "Witness" && !s.signed), "still listed, still unsigned");
}
