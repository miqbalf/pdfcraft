//! Tests for sign mode and request mode (`sign_request.rs`).

use std::cell::RefCell;
use std::rc::Rc;

use egui::{Pos2, vec2};
use serde_json::Value;

use super::*;
use crate::{HostSign, PdfCraftApp, SignHostEvent};

/// One page with the signer's empty field S1, another signer's field S2, and a text field Note.
const SIGN_PAGE: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 5 0 R 6 0 R] >> >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Annots [4 0 R 5 0 R 6 0 R] >> endobj
4 0 obj << /Type /Annot /Subtype /Widget /FT /Sig /T (CraftOffice.R7.S1) /Rect [20 110 140 180] /P 3 0 R /F 4 >> endobj
5 0 obj << /Type /Annot /Subtype /Widget /FT /Sig /T (CraftOffice.R7.S2) /Rect [160 110 280 180] /P 3 0 R /F 4 >> endobj
6 0 obj << /Type /Annot /Subtype /Widget /FT /Tx /T (Note) /Rect [20 20 280 60] /P 3 0 R /F 4 >> endobj
trailer << /Root 1 0 R >>
%%EOF";

/// One page turned a quarter (`/Rotate 90`): 300 wide and 200 tall in user space, shown 200 wide
/// and 300 tall.
const ROTATED_PAGE: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Rotate 90 >> endobj
trailer << /Root 1 0 R >>
%%EOF";

const MINE: &str = "CraftOffice.R7.S1";
const THEIRS: &str = "CraftOffice.R7.S2";

fn sign_mode() -> SignHostEvent {
    SignHostEvent::SignMode {
        request_id: 7,
        field: MINE.into(),
        page: 0,
        others: vec![THEIRS.into()],
        banner: "Alice asks you to sign Contract.pdf: 1 field".into(),
        trust_roots: Vec::new(),
    }
}

/// The messages the app posted to the host.
type Posted = Rc<RefCell<Vec<Value>>>;

/// An app with `bytes` open as the host's document and its posts recorded.
fn app_with(bytes: &[u8]) -> (PdfCraftApp, Posted) {
    let mut app = PdfCraftApp::new();
    app.open_bytes("contract.pdf", None, bytes.to_vec()).expect("opens");
    app.host_doc = app.active_ids().map(|(_, id)| id);
    let posted: Posted = Rc::default();
    let sink = posted.clone();
    app.host_sign_post = Some(Box::new(move |v: Value| {
        sink.borrow_mut().push(v);
        Ok(())
    }));
    (app, posted)
}

fn in_sign_mode(bytes: &[u8]) -> (PdfCraftApp, Posted) {
    let (mut app, posted) = app_with(bytes);
    app.host_sign.push(sign_mode());
    app.process_host_sign();
    (app, posted)
}

fn annotations(app: &PdfCraftApp) -> usize {
    let (_, id) = app.active_ids().expect("a document");
    app.session.get(id).expect("open").info.annotations.len()
}

/// A typed note at the page's foot: an edit that works on the plain document.
fn note() -> pdfcraft_engine::Edit {
    crate::fill_sign::typed(0, [30.0, 100.0], "changed", 10.0, 0, "Bob")
}

#[test]
fn sign_mode_makes_the_document_read_only() {
    let (mut plain, _) = app_with(SIGN_PAGE);
    let before = annotations(&plain);
    assert!(plain.apply_edit(note()), "the plain document takes the edit");
    assert!(annotations(&plain) > before);
    assert!(plain.execute("page.rotate"), "and a page command");

    let (mut app, _) = in_sign_mode(SIGN_PAGE);
    let (_, id) = app.active_ids().expect("a document");
    assert!(app.esign_locked(id));
    let before = annotations(&app);
    let generation = app.session.get(id).expect("open").edit_generation();
    assert!(!app.apply_edit(note()), "an edit is refused");
    for command in ["page.rotate", "page.delete", "sign.fill.signature", "sign.digital", "form.add.text", "page.organize", "a11y.autotag"] {
        assert!(!app.execute(command), "{command} is refused in sign mode");
    }
    assert_eq!(annotations(&app), before);
    assert_eq!(app.session.get(id).expect("open").edit_generation(), generation, "the document is unchanged");
    assert!(app.execute("view.fit_one_page"), "reading commands still work");
}

/// The real shell with the signer's document open, in sign mode, after the first frames.
fn shell() -> egui_kittest::Harness<'static, PdfCraftApp> {
    let mut h = egui_kittest::Harness::builder().with_size(vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = PdfCraftApp::new();
        app.set_option("language", "en").expect("language");
        app.open_bytes("contract.pdf", None, SIGN_PAGE.to_vec()).expect("opens");
        app.host_doc = app.active_ids().map(|(_, id)| id);
        app.set_option("left", "closed").expect("left");
        app.set_option("panel", "none").expect("panel");
        app.host_sign.push(sign_mode());
        app
    });
    h.run_steps(6);
    h
}

fn field_centre(h: &egui_kittest::Harness<'static, PdfCraftApp>, name: &str) -> Pos2 {
    let app = h.state();
    let view = &app.views[0];
    let doc = app.session.get(view.id).expect("open");
    let f = doc.form.iter().find(|f| f.name == name).expect("field");
    crate::forms_ui::field_screen_rect(view, &doc.info, f, 0).expect("on screen").center()
}

fn click_at(h: &mut egui_kittest::Harness<'static, PdfCraftApp>, at: Pos2) {
    h.drag_at(at);
    h.run_steps(1);
    h.drop_at(at);
    h.run_steps(3);
}

#[test]
fn click_on_own_field_opens_picker_others_do_nothing() {
    let mut h = shell();
    let (theirs, note) = (field_centre(&h, THEIRS), field_centre(&h, "Note"));
    click_at(&mut h, theirs);
    assert_eq!(h.state().dialog, None, "another signer's field opens nothing");
    assert!(h.state().sign_draft.is_none(), "nor the digital signature dialog");
    click_at(&mut h, note);
    assert!(h.state().views[0].forms.focus.is_none(), "a text field doesn't open for typing");
    assert_eq!(h.state().dialog, None);

    let mine = field_centre(&h, MINE);
    click_at(&mut h, mine);
    assert_eq!(h.state().dialog, Some(crate::Dialog::Signature), "the signer's own field opens the Fill & Sign picker");
    assert!(h.state().sign_draft.is_none(), "not the digital signature dialog");
    assert!(h.state().esign.picking(), "the picker is for the request's field");
}

#[test]
fn typed_pick_posts_typed_text_not_outlines() {
    let (mut app, posted) = in_sign_mode(SIGN_PAGE);
    assert!(app.sign_field_clicked(MINE));
    app.signature_draft.drawing = false;
    app.signature_draft.image_mode = false;
    app.signature_draft.text = "Ada Lovelace".into();
    app.signature_pad_applied();
    let posted = posted.borrow();
    assert_eq!(posted.len(), 1, "one message: {posted:?}");
    let m = &posted[0];
    assert_eq!(m["type"], "pdfcraft:sign-mark");
    assert_eq!(m["requestId"], 7);
    assert_eq!(m["field"], MINE);
    assert_eq!(m["graphic"], serde_json::json!({ "kind": "typed", "text": "Ada Lovelace" }));
    assert!(!m.to_string().contains("outlines"), "never outlines: {m}");
    assert!(!app.esign.picking(), "the picker is done");
}

#[test]
fn drawn_pick_posts_strokes_json_that_parses_with_graphic_from_json() {
    let (mut app, posted) = in_sign_mode(SIGN_PAGE);
    assert!(app.sign_field_clicked(MINE));
    let drawn = vec![vec![[0.1, 0.1], [0.3, 0.2], [0.5, 0.12]], vec![[0.6, 0.05], [0.8, 0.15]]];
    app.signature_draft.drawing = true;
    app.signature_draft.image_mode = false;
    app.signature_draft.strokes = drawn.clone();
    app.signature_pad_applied();
    let posted = posted.borrow();
    assert_eq!(posted.len(), 1);
    let graphic = &posted[0]["graphic"];
    match pdfcraft_engine::esign::graphic_from_json(graphic, "Bob") {
        Ok(pdfcraft_engine::sign::Graphic::Strokes(strokes)) => {
            assert_eq!(strokes.len(), drawn.len(), "every stroke arrives");
            for (got, sent) in strokes.iter().zip(&drawn) {
                assert_eq!(got.len(), sent.len(), "with every point");
            }
        }
        other => panic!("not strokes: {other:?}"),
    }
}

fn in_request_mode(bytes: &[u8]) -> (PdfCraftApp, Posted) {
    let (mut app, posted) = app_with(bytes);
    app.host_sign.push(SignHostEvent::RequestMode { signers: vec![(1, "Ann Example".into()), (2, "Bob Example".into())] });
    app.process_host_sign();
    (app, posted)
}

#[test]
fn request_mode_allows_one_box_per_signer() {
    let (mut app, posted) = in_request_mode(SIGN_PAGE);
    let (_, id) = app.active_ids().expect("a document");
    assert!(app.esign_locked(id), "the document is not edited while placing boxes");
    let a = [20.0, 20.0, 120.0, 60.0];
    let b = [150.0, 20.0, 250.0, 60.0];
    assert_eq!(app.place_signer_box(0, a), Ok(1), "the first signer's box");
    assert_eq!(app.place_signer_box(0, b), Ok(2), "then the second's");
    assert!(app.place_signer_box(0, a).is_err(), "every signer has a box: no third");
    assert_eq!(app.esign.boxes().len(), 2);
    app.remove_signer_box(1);
    assert_eq!(app.place_signer_box(0, b), Ok(1), "a removed box can be drawn again");
    assert!(app.send_placements());
    let posted = posted.borrow();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0]["type"], "pdfcraft:sign-placements");
    let mut positions: Vec<u64> = posted[0]["placements"].as_array().expect("a list").iter().filter_map(|p| p["position"].as_u64()).collect();
    positions.sort_unstable();
    assert_eq!(positions, vec![1, 2], "one box per signer");
}

#[test]
fn placements_are_pdf_user_space_on_rotated_pages() {
    let (mut app, posted) = in_request_mode(ROTATED_PAGE);
    let (_, id) = app.active_ids().expect("a document");
    let page = app.session.get(id).expect("open").info.pages[0].clone();
    // A box drawn on the page as shown (y down, 200 wide and 300 tall): 100 across, 40 down.
    let shown = [20.0_f32, 40.0, 120.0, 80.0];
    let user = view_box_to_user(&page, shown);
    let [x0, y0, x1, y1] = user;
    assert!(x0 < x1 && y0 < y1, "normalised: {user:?}");
    assert!(x0 >= 0.0 && y0 >= 0.0 && x1 <= 300.0 && y1 <= 200.0, "inside the media box: {user:?}");
    assert!(((x1 - x0) - 40.0).abs() < 0.01 && ((y1 - y0) - 100.0).abs() < 0.01, "the sides swap on a quarter turn: {user:?}");
    // Its corners shown again are the corners drawn.
    let mut back: Vec<[f32; 2]> = [[x0, y0], [x1, y1], [x0, y1], [x1, y0]].iter().map(|[x, y]| page.user_to_view(*x as f32, *y as f32)).collect();
    back.sort_by(|a, b| a[0].total_cmp(&b[0]).then(a[1].total_cmp(&b[1])));
    let near = |p: [f32; 2], q: [f32; 2]| (p[0] - q[0]).abs() < 0.01 && (p[1] - q[1]).abs() < 0.01;
    assert!(near(back[0], [shown[0], shown[1]]) && near(back[3], [shown[2], shown[3]]), "{back:?}");

    assert_eq!(app.place_signer_box(0, user), Ok(1));
    assert!(app.send_placements());
    let sent = &posted.borrow()[0]["placements"][0];
    assert_eq!(sent["page"], 0);
    let rect: Vec<f64> = sent["rect"].as_array().expect("rect").iter().filter_map(Value::as_f64).collect();
    assert_eq!(rect, user.to_vec(), "sent as placed, in user space");
}

#[test]
fn request_command_hidden_without_host_sign() {
    let (mut app, posted) = app_with(SIGN_PAGE);
    assert!(!app.host_command_registered(REQUEST_COMMAND));
    assert!(app.host_commands().is_empty(), "nothing to list in the palette");
    assert!(!app.execute(REQUEST_COMMAND), "not a command here");
    assert!(posted.borrow().is_empty());

    app.host_sign = HostSign::default();
    app.host_sign.set_offered(true);
    assert!(app.host_command_registered(REQUEST_COMMAND));
    assert!(app.host_commands().iter().any(|c| c.id == REQUEST_COMMAND));
    assert!(app.execute(REQUEST_COMMAND));
    let posted = posted.borrow();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0]["type"], "pdfcraft:sign-request");
}

/// Two pages; the signer's field is on the second.
const FIELD_ON_PAGE_TWO: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] >> >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >> endobj
4 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Annots [5 0 R] >> endobj
5 0 obj << /Type /Annot /Subtype /Widget /FT /Sig /T (CraftOffice.R7.S1) /Rect [20 110 140 180] /P 4 0 R /F 4 >> endobj
trailer << /Root 1 0 R >>
%%EOF";

/// The host's `page` is 0 when the signer has no placement of his own; the field's own page in
/// the form wins over it.
#[test]
fn sign_mode_opens_at_the_page_of_the_signers_field() {
    let (app, _) = in_sign_mode(FIELD_ON_PAGE_TWO);
    let (i, _) = app.active_ids().expect("a document");
    assert_eq!(app.views[i].current, 1, "the page the field is on, not the host's page 0");
}
