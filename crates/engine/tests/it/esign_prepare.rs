//! E-sign inspect, prepare and the audit page (`pdfcraft_engine::esign`).

use std::sync::Arc;

use pdfcraft_engine::esign::{
    AuditHeader, EsignError, MAX_SIGNERS, Placement, SignerSlot, audit_document, completed_field, inspect, prepare, row_field, seal_field,
    signer_field,
};
use pdfcraft_engine::export::Exporter;
use pdfcraft_engine::sign::pkcs12;
use pdfcraft_engine::{Changes, Edit, NewField, Protection, Session, SignOptions};
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

/// A PDF whose `startxref` points nowhere: it opens only through a rebuilt cross-reference
/// table, which a save writes out in full.
fn damaged_blank() -> Vec<u8> {
    let bytes = blank(1);
    let at = bytes.windows(9).rposition(|w| w == b"startxref").expect("startxref");
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(b"startxref\n7\n%%EOF\n");
    out
}

#[test]
fn prepare_refuses_input_it_cannot_keep_byte_for_byte() {
    let damaged = damaged_blank();
    // The fixture is pinned: the engine itself cannot keep it byte for byte, so prepare's guard
    // is what the test reaches.
    let mut s = Session::new().with_clock(|| 1_700_000_000);
    let id = s.open("x.pdf", None, Arc::new(damaged.clone()), None).expect("opens");
    s.apply(id, Edit::SetInfo { key: "Title".into(), value: "x".into() }).expect("edits");
    assert!(!s.save_bytes(id).expect("saves").starts_with(&damaged), "the fixture forces a rewrite");
    let e = prepare(&damaged, &header(), &slots(), DATE).expect_err("refused");
    assert!(matches!(e, EsignError::Validation(_)), "{e:?}");
    assert!(e.to_string().contains("damaged"), "{e}");
}

/// `blank(1)` with `edit` applied to its catalog, as another program would have written it.
fn with_catalog(edit: impl FnOnce(&mut pdfcraft_cos::Document, &mut pdfcraft_cos::Dict)) -> Vec<u8> {
    let bytes = blank(1);
    let mut doc = cos(&bytes);
    let root = doc.root().expect("catalog");
    let mut catalog = doc.get(root).as_dict().cloned().expect("dict");
    edit(&mut doc, &mut catalog);
    doc.set(root, pdfcraft_cos::Object::Dict(catalog));
    pdfcraft_cos::write_incremental(&doc, &pdfcraft_cos::SaveOptions { object_streams: false, ..pdfcraft_cos::SaveOptions::default() })
        .expect("writes")
}

fn sig_dict() -> pdfcraft_cos::Object {
    let mut d = pdfcraft_cos::Dict::new();
    d.set(b"Type".to_vec(), pdfcraft_cos::Object::name("Sig"));
    pdfcraft_cos::Object::Dict(d)
}

#[test]
fn prepare_refuses_usage_rights_certified_and_xfa_documents() {
    // Usage rights and a certification are signatures made elsewhere, even with no signed field.
    for key in ["UR3", "DocMDP"] {
        let pdf = with_catalog(|doc, c| {
            let sig = doc.add(sig_dict());
            let mut perms = pdfcraft_cos::Dict::new();
            perms.set(key.as_bytes().to_vec(), pdfcraft_cos::Object::Ref(sig));
            c.set(b"Perms".to_vec(), pdfcraft_cos::Object::Dict(perms));
        });
        let err = prepare(&pdf, &header(), &slots(), DATE).expect_err(key);
        assert!(matches!(err, EsignError::AlreadySigned), "{key}: {err:?}");
        assert_eq!(err.to_string(), "This PDF is already signed; a new signature would break it");
    }
    // A hybrid XFA form: viewers that lay out the XFA would not show the new fields.
    let pdf = with_catalog(|doc, c| {
        let body =
            b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><template xmlns=\"http://www.xfa.org/schema/xfa-template/3.3/\"/></xdp:xdp>".to_vec();
        let mut sd = pdfcraft_cos::Dict::new();
        sd.set(b"Length".to_vec(), pdfcraft_cos::Object::Int(body.len() as i64));
        let xfa = doc.add(pdfcraft_cos::Object::Stream(pdfcraft_cos::Stream::from_raw(sd, body)));
        let mut form = pdfcraft_cos::Dict::new();
        form.set(b"Fields".to_vec(), pdfcraft_cos::Object::Array(Vec::new()));
        form.set(b"XFA".to_vec(), pdfcraft_cos::Object::Ref(xfa));
        c.set(b"AcroForm".to_vec(), pdfcraft_cos::Object::Dict(form));
    });
    let err = prepare(&pdf, &header(), &slots(), DATE).expect_err("xfa");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("XFA"), "{err}");
}

#[test]
fn prepare_caps_the_signers() {
    let many = |n: u32| (1..=n).map(|p| slot(p, "u", "U", None)).collect::<Vec<_>>();
    let at_cap = prepare(&blank(1), &header(), &many(MAX_SIGNERS as u32), DATE).expect("exactly the cap is accepted");
    assert_eq!(at_cap.fields.len(), MAX_SIGNERS);
    let err = prepare(&blank(1), &header(), &many(MAX_SIGNERS as u32 + 1), DATE).expect_err("over the cap");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
    assert!(err.to_string().contains(&MAX_SIGNERS.to_string()), "{err}");
}

#[test]
fn prepare_says_why_an_owner_password_or_a_name_clash_refuses() {
    // An owner password that allows no changes (no open password).
    let mut s = Session::new().with_clock(|| 1_700_000_000);
    let id = s.open("x.pdf", None, Arc::new(blank(1)), None).expect("opens");
    let p = Protection { permissions_password: Some("owner".into()), changes: Changes::None, ..Protection::default() };
    s.apply(id, Edit::Protect(p)).expect("protects");
    let locked = s.save_bytes(id).expect("saves").to_vec();
    let err = prepare(&locked, &header(), &slots(), DATE).expect_err("refused");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("security settings"), "{err}");

    // A terminal field named like the request's parent.
    let mut s = Session::new().with_clock(|| 1_700_000_000);
    let id = s.open("x.pdf", None, Arc::new(blank(1)), None).expect("opens");
    let edit =
        Edit::AddField { page: 0, rect: [50.0, 50.0, 200.0, 80.0], kind: NewField::Text { multiline: false }, name: Some("CraftOffice".into()) };
    s.apply(id, edit).expect("adds");
    let clashing = s.save_bytes(id).expect("saves").to_vec();
    let err = prepare(&clashing, &header(), &slots(), DATE).expect_err("refused");
    assert!(matches!(err, EsignError::Validation(_)), "{err:?}");
    assert!(err.to_string().contains("clash"), "{err}");
}

fn event(seq: usize) -> serde_json::Value {
    json!({ "seq": seq, "kind": "viewed", "actor_uid": "bob", "at": 1_795_420_800_000_i64 + seq as i64, "mac": format!("{seq:064x}") })
}

#[test]
fn audit_document_caps_every_list_and_object() {
    let trail = |events: usize, signers: usize, signatures: usize| {
        json!({
            "request": { "id": 42, "title": "Supply contract", "created_utc": CREATED },
            "signers": (1..=signers).map(|p| json!({ "position": p, "uid": "u", "display_name": "U" })).collect::<Vec<_>>(),
            "signatures": (1..=signatures).map(|i| json!({ "field": format!("S{i}"), "status": "unknown" })).collect::<Vec<_>>(),
            "events": (1..=events).map(event).collect::<Vec<_>>(),
        })
    };
    let started = std::time::Instant::now();
    let pdf = audit_document(&trail(5_000, 3, 3)).expect("5,000 events print");
    eprintln!("audit_document: 5,000 events, {} pages, {} bytes, {:?}", page_count(&pdf), pdf.len(), started.elapsed());
    for (t, what) in [(trail(5_001, 3, 3), "events"), (trail(1, 501, 3), "signers"), (trail(1, 3, 501), "signatures")] {
        let err = audit_document(&t).expect_err(what);
        assert!(matches!(err, EsignError::Validation(_)), "{what}: {err:?}");
    }
    assert!(audit_document(&trail(1, 500, 500)).is_ok(), "500 signers and signatures print");
    let mut wide = trail(1, 1, 1);
    let keys: serde_json::Map<String, serde_json::Value> = (0..65).map(|k| (format!("k{k:02}"), json!(k))).collect();
    wide["request"] = serde_json::Value::Object(keys.clone());
    assert!(matches!(audit_document(&wide), Err(EsignError::Validation(_))), "65 keys in one object");
    let mut fits = keys;
    fits.remove("k64");
    wide["request"] = serde_json::Value::Object(fits);
    assert!(audit_document(&wide).is_ok(), "64 keys print");
}

/// The file's `/Info` date `key`, as its 14 digits (`YYYYMMDDHHmmSS`).
fn info_date(pdf: &[u8], key: &str) -> Option<String> {
    let v = pdfcraft_organize::info(&cos(pdf), key)?;
    Some(v.trim_start_matches("D:").chars().take(14).collect())
}

#[test]
fn audit_document_is_deterministic_and_created_no_later_than_modified() {
    let trail = json!({ "request": { "id": 42, "title": "T", "created_utc": CREATED }, "events": [event(1)] });
    let a = audit_document(&trail).expect("prints");
    let created = info_date(&a, "CreationDate").expect("a creation date");
    let modified = info_date(&a, "ModDate").expect("a modification date");
    assert!(created <= modified, "{created} after {modified}");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert_eq!(a, audit_document(&trail).expect("prints"), "the same trail prints the same bytes");
}

#[test]
fn a_cut_event_line_is_marked_and_keeps_its_mac() {
    let mac = "c0ffee".repeat(10);
    // Keys that sort before `mac`, each short enough to print, together far past the line's cut.
    let mut e = json!({ "seq": 7, "kind": "signed", "actor_uid": "bob", "at": 1_795_420_800_000_i64, "mac": mac.clone() });
    for k in 0..8 {
        e[format!("a{k}")] = json!("y".repeat(250));
    }
    let pdf = audit_document(&json!({ "request": { "title": "T" }, "events": [e] })).expect("prints");
    let flat = text_of_pages(&pdf, 0..page_count(&pdf)).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains(&mac), "the MAC survives the cut");
    assert!(flat.contains('\u{2026}'), "the cut is marked");
}

#[test]
fn signature_dates_are_iso_utc() {
    let i = inspect(&signed_blank()).expect("inspects");
    let date = i.signatures.iter().find_map(|s| s.date.clone()).expect("a date");
    let parsed = chrono::NaiveDateTime::parse_from_str(&date, "%Y-%m-%dT%H:%M:%SZ");
    assert!(parsed.is_ok(), "{date}");
}

#[test]
fn characters_the_fonts_cannot_draw_print_as_code_points() {
    let mut h = header();
    h.requester_name = "Nguy\u{1ec5}n".into();
    let out = prepare(&blank(1), &h, &slots(), DATE).expect("prepares");
    let text = text_of_pages(&out.bytes, 1..2);
    assert!(text.contains("Nguy[U+1EC5]n"), "{text}");
}
