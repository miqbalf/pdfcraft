//! E-sign inspect, prepare and the audit page (`pdfcraft_engine::esign`).

use std::sync::Arc;

use pdfcraft_engine::esign::{
    AuditHeader, EsignError, Placement, SignerSlot, audit_document, completed_field, inspect, prepare, row_field, seal_field, signer_field,
};
use pdfcraft_engine::export::Exporter;
use pdfcraft_engine::sign::pkcs12;
use pdfcraft_engine::{Edit, Protection, Session, SignOptions};
use serde_json::json;

const DATE: &str = "2026-11-23T09:00:00Z";
const CREATED: &str = "2026-11-23T08:00:00Z";

fn blank(pages: usize) -> Vec<u8> {
    Session::new().with_clock(|| 1_700_000_000).create_blank(612.0, 792.0, pages).expect("blank").to_vec()
}

fn header() -> AuditHeader {
    AuditHeader {
        request_id: 42,
        title: "Supply contract".into(),
        requester_uid: "alice".into(),
        requester_name: "Alice Doe".into(),
        created_utc: CREATED.into(),
        instance: "workspace.treeo.id".into(),
        organisation: "PT Solusi Hutan Digital".into(),
    }
}

fn slot(position: u32, uid: &str, name: &str, placement: Option<Placement>) -> SignerSlot {
    SignerSlot { position, uid: uid.into(), display_name: name.into(), placement }
}

/// Bob signs on the audit page; Carol has a place on the first page.
fn slots() -> Vec<SignerSlot> {
    vec![slot(1, "bob", "Bob Brown", None), slot(2, "carol", "Carol Chan", Some(Placement { page: 0, rect: [100.0, 100.0, 280.0, 140.0] }))]
}

fn cos(bytes: &[u8]) -> pdfcraft_cos::Document {
    pdfcraft_cos::Document::open(Arc::new(bytes.to_vec())).expect("reopens")
}

fn page_count(bytes: &[u8]) -> usize {
    let mut s = Session::new();
    let id = s.open("x.pdf", None, Arc::new(bytes.to_vec()), None).expect("opens");
    s.get(id).expect("doc").info.pages.len()
}

fn text_of_pages(bytes: &[u8], pages: std::ops::Range<usize>) -> String {
    let mut s = Session::new();
    let id = s.open("x.pdf", None, Arc::new(bytes.to_vec()), None).expect("opens");
    let mut ex = Exporter::new(s.get(id).expect("doc"));
    pages.map(|p| ex.text(p).expect("text")).collect::<Vec<_>>().join("\n")
}

fn signed_blank() -> Vec<u8> {
    let p12 = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/chain.p12")).expect("chain.p12");
    let id = pkcs12::open(&p12, "test").expect("p12");
    let opts = SignOptions { new_field_name: Some("Approval".into()), date: "D:20261123090000Z".into(), ..SignOptions::default() };
    pdfcraft_engine::sign::sign(&cos(&blank(1)), &id, &opts).expect("signs")
}

fn password_blank() -> Vec<u8> {
    let mut s = Session::new().with_clock(|| 1_700_000_000);
    let id = s.open("x.pdf", None, Arc::new(blank(1)), None).expect("opens");
    let p = Protection { open_password: Some("secret".into()), ..Protection::default() };
    s.apply(id, Edit::Protect(p)).expect("protects");
    s.save_bytes(id).expect("saves").to_vec()
}

#[test]
fn prepare_output_starts_with_input_bytes() {
    let input = blank(2);
    let out = prepare(&input, &header(), &slots(), DATE).expect("prepares");
    assert!(out.bytes.len() > input.len());
    assert!(out.bytes.starts_with(&input), "an incremental update of the input");
    assert_eq!(out.sha256, inspect(&out.bytes).expect("inspects").sha256, "the digest of the bytes returned");
}

#[test]
fn prepare_adds_one_page_and_all_named_fields() {
    let input = blank(2);
    let out = prepare(&input, &header(), &slots(), DATE).expect("prepares");
    let pages = page_count(&out.bytes);
    assert_eq!(pages, page_count(&input) + 1, "one audit page");
    let audit = pages - 1;

    let expected: std::collections::BTreeMap<u32, String> = [(1, signer_field(42, 1)), (2, signer_field(42, 2))].into_iter().collect();
    assert_eq!(out.fields, expected);
    assert_eq!(out.seal_field, seal_field(42));

    let fields = pdfcraft_forms::fields(&cos(&out.bytes));
    let find = |name: &str| fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name}: {:?}", names(&fields)));
    let sig = |name: &str| {
        let f = find(name);
        assert_eq!(f.kind, pdfcraft_forms::FieldKind::Signature, "{name} is a signature field");
        assert_eq!(f.widgets.len(), 1, "{name}");
        (f.widgets[0].page, f.widgets[0].rect)
    };
    // Bob has no place: his field is on the audit page. Carol's is where the requester put it.
    assert_eq!(sig(&signer_field(42, 1)).0, Some(audit));
    let (page, rect) = sig(&signer_field(42, 2));
    assert_eq!(page, Some(0));
    for (got, want) in rect.iter().zip([100.0, 100.0, 280.0, 140.0]) {
        assert!((got - want).abs() < 1e-6, "{rect:?}");
    }
    // The seal: visible, 180 x 40, in the bottom part of the audit page.
    let (page, r) = sig(&seal_field(42));
    assert_eq!(page, Some(audit));
    assert!(((r[2] - r[0]) - 180.0).abs() < 1e-6 && ((r[3] - r[1]) - 40.0).abs() < 1e-6, "{r:?}");
    assert!(r[3] < 792.0 / 4.0, "at the page bottom: {r:?}");
    // The audit rows and the Completed line: read-only text on the audit page, empty.
    for name in [row_field(42, 1), row_field(42, 2), completed_field(42)] {
        let f = find(&name);
        assert_eq!(f.kind, pdfcraft_forms::FieldKind::Text, "{name}");
        assert!(f.flags & 1 == 1, "{name} is read-only");
        assert!(f.value.iter().all(String::is_empty), "{name} starts empty");
        assert_eq!(f.widgets[0].page, Some(audit), "{name}");
    }
    assert!(find(&row_field(42, 1)).flags & pdfcraft_forms::flags::MULTILINE != 0, "rows are multiline");
    // Kept for a look with an outside renderer.
    std::fs::write(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("esign_prepared.pdf"), &out.bytes).expect("writes");
}

fn names(fields: &[pdfcraft_forms::Field]) -> Vec<&str> {
    fields.iter().map(|f| f.name.as_str()).collect()
}

#[test]
fn prepare_refuses_already_signed_input() {
    let err = prepare(&signed_blank(), &header(), &slots(), DATE).expect_err("refused");
    assert!(matches!(err, EsignError::AlreadySigned), "{err:?}");
    assert_eq!(err.to_string(), "This PDF is already signed; a new signature would break it");
    assert_eq!(err.code(), "already_signed");
}

#[test]
fn prepare_refuses_user_password_input() {
    let err = prepare(&password_blank(), &header(), &slots(), DATE).expect_err("refused");
    assert!(matches!(err, EsignError::NeedsPassword), "{err:?}");
}

#[test]
fn prepare_refuses_placement_off_page() {
    let input = blank(2);
    let off = |placement: Placement| {
        let signers = vec![slot(1, "bob", "Bob Brown", Some(placement))];
        prepare(&input, &header(), &signers, DATE).expect_err("refused")
    };
    // A page past the end, and a place that leaves the page's edge.
    for (placement, page) in
        [(Placement { page: 5, rect: [100.0, 100.0, 280.0, 140.0] }, "page 6"), (Placement { page: 1, rect: [500.0, 100.0, 680.0, 140.0] }, "page 2")]
    {
        let err = off(placement);
        assert!(matches!(err, EsignError::NoField(_)), "{err:?}");
        assert!(err.to_string().contains(page), "names {page}: {err}");
    }
}

#[test]
fn inspect_reports_signed_and_needs_password_without_failing() {
    let plain = blank(3);
    let i = inspect(&plain).expect("inspects");
    assert!(!i.signed && !i.needs_password && i.signatures.is_empty());
    assert_eq!(i.pages, 3);

    let signed = signed_blank();
    let i = inspect(&signed).expect("a signed PDF is reported, not refused");
    assert!(i.signed && !i.needs_password);
    let s = i.signatures.iter().find(|s| s.field == "Approval").expect("the signature is listed");
    assert!(s.signed && s.signer.is_some() && s.date.is_some());
    assert_ne!(s.status, "unsigned");
    assert_ne!(i.sha256, inspect(&plain).expect("inspects").sha256);

    let locked = inspect(&password_blank()).expect("an encrypted PDF is reported, not refused");
    assert!(locked.needs_password && !locked.signed);

    // The prepared file lists its empty signature fields as unsigned.
    let prepared = prepare(&plain, &header(), &slots(), DATE).expect("prepares");
    let i = inspect(&prepared.bytes).expect("inspects");
    assert!(!i.signed);
    for name in [signer_field(42, 1), signer_field(42, 2), seal_field(42)] {
        let s = i.signatures.iter().find(|s| s.field == name).unwrap_or_else(|| panic!("{name} listed"));
        assert!(!s.signed && s.status == "unsigned" && s.signer.is_none(), "{s:?}");
    }

    assert!(matches!(inspect(b"not a pdf"), Err(EsignError::NotPdf(_))));
}

#[test]
fn audit_page_text_lists_every_signer() {
    let input = blank(1);
    let out = prepare(&input, &header(), &slots(), DATE).expect("prepares");
    let text = text_of_pages(&out.bytes, 1..2);
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for want in [
        "Signature record: Supply contract",
        "Request 42",
        "requested by Alice Doe (alice) on 2026-11-23T08:00:00Z",
        "Sealed by workspace.treeo.id for PT Solusi Hutan Digital.",
        "The SHA-256 of this final file is in the Nextcloud audit trail, not on this page.",
        "Bob Brown (bob)",
        "Carol Chan (carol)",
    ] {
        assert!(flat.contains(want), "{want:?} in {flat:?}");
    }
    assert!(!flat.contains("Z UTC"), "the date is shown as given: {flat:?}");
    assert!(!text_of_pages(&out.bytes, 0..1).contains("Signature record"), "the input page is untouched");
}

#[test]
fn audit_document_is_a_valid_pdf_with_every_event_line() {
    let kinds = ["created", "prepared", "notified", "viewed", "signed", "reminded"];
    let events: Vec<_> = (1..=90)
        .map(|seq| {
            json!({
                "seq": seq,
                "kind": kinds[seq % kinds.len()],
                "actor_uid": "bob",
                "at": 1_795_420_800_000_i64 + seq as i64 * 1000,
                "ip": "10.0.0.7",
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
                "sha256_before": format!("{:064x}", seq),
                "sha256_after": format!("{:064x}", seq + 1),
                "mac": format!("mac{seq:04}{}", "ab".repeat(30)),
            })
        })
        .collect();
    let trail = json!({
        "request": { "id": 42, "title": "Supply contract", "requester_uid": "alice", "status": "completed", "created_utc": CREATED },
        "signers": [
            { "position": 1, "uid": "bob", "display_name": "Bob Brown", "status": "signed", "signed_at": "2026-11-23T09:00:00Z" },
            { "position": 2, "uid": "carol", "display_name": "Carol Chan", "status": "signed" }
        ],
        "events": events,
        "chain": { "ok": true, "count": 90, "head_mac": "f".repeat(64) },
        "final_sha256": "e".repeat(64),
    });
    let pdf = audit_document(&trail).expect("prints");
    assert!(pdf.starts_with(b"%PDF-"));
    let pages = page_count(&pdf);
    assert!(pages > 1, "90 events need more than one page");
    let flat = text_of_pages(&pdf, 0..pages).split_whitespace().collect::<Vec<_>>().join(" ");
    for seq in 1..=90 {
        let mac = format!("mac{seq:04}{}", "ab".repeat(30));
        let kind = kinds[seq % kinds.len()];
        assert!(flat.contains(&format!("#{seq} ")), "event {seq} listed");
        assert!(flat.contains(&mac), "event {seq}'s mac");
        assert!(flat.contains(&format!("{:064x}", seq + 1)), "event {seq}'s digest after");
        assert!(flat.contains(kind));
    }
    for want in ["Supply contract", "Bob Brown (bob)", "Carol Chan (carol)", &"f".repeat(64), &"e".repeat(64)] {
        assert!(flat.contains(want), "{want:?}");
    }

    assert!(audit_document(&json!("not a trail")).is_err(), "a trail is a JSON object");
}

#[test]
fn same_inputs_same_bytes() {
    let input = blank(1);
    let a = prepare(&input, &header(), &slots(), DATE).expect("prepares");
    let b = prepare(&input, &header(), &slots(), DATE).expect("prepares");
    assert_eq!(a.bytes, b.bytes);
    assert_eq!(a.sha256, b.sha256);
    let later = prepare(&input, &header(), &slots(), "2026-11-24T09:00:00Z").expect("prepares");
    assert_ne!(a.bytes, later.bytes, "the date is what changes the output");
}
