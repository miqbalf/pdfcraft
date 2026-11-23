//! Sign mode and request mode for a Nextcloud signature request (the `pdfcraft:sign-*` host
//! messages, which the web shell hears and posts in `apps/pdfcraft-web/src/sign_host.rs`).
//!
//! - **Sign mode** (`pdfcraft:sign-mode`): the host's document is read-only. A banner shows the
//!   host's text, the signer's field has an accent outline and the other signers' fields are
//!   greyed. A click on his field opens the Fill & Sign picker (Draw, Type, an image); Done posts
//!   `pdfcraft:sign-mark { requestId, field, graphic }`. PdfCraft never signs here: the host's
//!   seal worker does. A typed mark travels as its text, never as outlines.
//! - **Request mode** (`pdfcraft:sign-request-mode`): one box per listed signer, drawn on the page
//!   as Prepare Form draws a field and labelled with the signer's name. Send posts
//!   `pdfcraft:sign-placements` with each box in PDF user space.
//! - **Request signatures…** (`sign.request`) exists only while the host offers requests
//!   (`sign: true` in `pdfcraft:host`); it posts `pdfcraft:sign-request`.

use egui::{Color32, CornerRadius, Pos2, Rect, Sense, Stroke};
use pdfcraft_engine::DocId;
use pdfcraft_engine::commands::{CommandSpec, Needs};
use serde_json::{Value, json};

use crate::fill_sign::SavedSig;
use crate::theme::Tokens;
use crate::{PdfCraftApp, SignHostEvent};

/// The command that asks the host to start a signature request.
pub const REQUEST_COMMAND: &str = "sign.request";

/// Commands that exist only while the host offers them. Each needs an open document.
const HOST_COMMANDS: [HostCommand; 1] = [HostCommand { id: REQUEST_COMMAND, label: "Request signatures…", icon: "signature" }];

/// The label under which the host's certificates are trusted, for this session only.
pub const HOST_TRUST_LABEL: &str = "this Nextcloud";

/// The size of a box placed with a click rather than a drag (points), as Prepare Form places a
/// signature field.
const CLICK_BOX: (f64, f64) = (180.0, 36.0);

/// The signer's own request, while the host's document is open for it.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SignMode {
    request_id: u64,
    field: String,
    page: usize,
    others: Vec<String>,
    banner: String,
    /// The document it applies to, once one is open.
    doc: Option<DocId>,
    /// The Fill & Sign picker is open for the field.
    picking: bool,
}

/// One signer's box in request mode, in PDF user space on 0-based `page`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SignerBox {
    pub position: u32,
    pub page: usize,
    pub rect: [f64; 4],
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct RequestMode {
    signers: Vec<(u32, String)>,
    boxes: Vec<SignerBox>,
    doc: Option<DocId>,
    /// A box being drawn: its page and the screen point the drag began at.
    drawing: Option<(usize, Pos2)>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Mode {
    Sign(SignMode),
    Request(RequestMode),
}

/// Sign mode or request mode, and the certificates the host asked to trust.
#[derive(Clone, Debug, Default)]
pub struct Esign {
    mode: Option<Mode>,
    /// The host's roots added to the trust store (DER), which are never saved with the settings.
    pub(crate) host_roots: Vec<Vec<u8>>,
}

impl Esign {
    /// The signature picker is open for the signer's field.
    pub fn picking(&self) -> bool {
        matches!(&self.mode, Some(Mode::Sign(s)) if s.picking)
    }

    /// The boxes placed in request mode.
    pub fn boxes(&self) -> &[SignerBox] {
        match &self.mode {
            Some(Mode::Request(r)) => &r.boxes,
            _ => &[],
        }
    }

    /// Whether document `id` is open for a signature request, and so read-only.
    pub(crate) fn locks(&self, id: DocId) -> bool {
        self.doc() == Some(id)
    }

    fn doc(&self) -> Option<DocId> {
        match &self.mode {
            Some(Mode::Sign(s)) => s.doc,
            Some(Mode::Request(r)) => r.doc,
            None => None,
        }
    }

    /// Whether `der` is a certificate the host asked to trust.
    pub(crate) fn host_trusted(&self, der: &[u8]) -> bool {
        self.host_roots.iter().any(|r| r == der)
    }
}

/// A box drawn on a page as shown (view space: points, y down, the page's `/Rotate` applied) in
/// PDF user space, normalised.
pub fn view_box_to_user(page: &pdfcraft_render::PageInfo, shown: [f32; 4]) -> [f64; 4] {
    let a = page.view_to_user(shown[0], shown[1]);
    let b = page.view_to_user(shown[2], shown[3]);
    let (a, b) = ([f64::from(a[0]), f64::from(a[1])], [f64::from(b[0]), f64::from(b[1])]);
    [a[0].min(b[0]), a[1].min(b[1]), a[0].max(b[0]), a[1].max(b[1])]
}

/// The `graphic` JSON of a mark picked in the Fill & Sign picker. A typed mark is its text (the
/// host's worker draws it, up to the same 100 characters the server takes); drawn strokes and
/// images go as their JSON form, within its caps.
pub fn mark_json(saved: &SavedSig) -> Result<Value, String> {
    let graphic = match saved {
        SavedSig::Typed(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Err(tl!("Type your name first.").to_string());
            }
            if text.chars().count() > pdfcraft_engine::esign::MAX_TYPED_CHARS {
                return Err(crate::i18n::fmt(
                    tl!("A typed signature can have at most {n} characters."),
                    &[("n", &pdfcraft_engine::esign::MAX_TYPED_CHARS.to_string())],
                ));
            }
            return Ok(json!({ "kind": "typed", "text": text }));
        }
        // A bare click leaves an empty stroke behind; it is not part of the mark.
        SavedSig::Drawn(strokes) => SavedSig::Drawn(strokes.iter().filter(|s| !s.is_empty()).cloned().collect()).graphic(),
        SavedSig::Image(_) => saved.graphic(),
    };
    let graphic = graphic.ok_or_else(|| tl!("This signature can't be drawn.").to_string())?;
    pdfcraft_engine::esign::graphic_to_json(&graphic).map_err(|e| e.to_string())
}

/// A command the host offers, for the palette: its id, label and icon.
#[derive(Clone, Copy, Debug)]
pub struct HostCommand {
    pub id: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
}

impl PdfCraftApp {
    /// The host's messages since the last frame, and sign or request mode bound to the host's
    /// document once it is open. Run each frame.
    pub fn process_host_sign(&mut self) {
        // The picker closed some other way (Escape, a click outside it).
        if self.dialog != Some(crate::Dialog::Signature) {
            self.sign_pick_cancelled();
        }
        for event in self.host_sign.take_events() {
            match event {
                SignHostEvent::SignMode { request_id, field, page, others, banner, trust_roots } => {
                    self.trust_host_roots(&trust_roots);
                    self.esign.mode = Some(Mode::Sign(SignMode { request_id, field, page, others, banner, doc: None, picking: false }));
                }
                SignHostEvent::RequestMode { signers } => {
                    self.esign.mode = Some(Mode::Request(RequestMode { signers, ..Default::default() }));
                }
            }
        }
        // Only the host's document: wait while it has opened none yet.
        let open = |app: &Self, id: DocId| app.views.iter().any(|v| v.id == id);
        if let Some(doc) = self.esign.doc()
            && !open(self, doc)
        {
            // The document closed: the request ends with it.
            self.esign.mode = None;
            return;
        }
        if self.esign.mode.is_none() || self.esign.doc().is_some() {
            return;
        }
        let Some(doc) = self.host_doc.filter(|d| open(self, *d)) else { return };
        match &mut self.esign.mode {
            Some(Mode::Sign(s)) => {
                s.doc = Some(doc);
                // The field's own page in the form: the host says page 0 when the signer has no
                // placement of his own, so its `page` is only the fallback.
                let field = self.session.get(doc).and_then(|d| d.form.iter().find(|f| f.name == s.field));
                let page = field.and_then(|f| f.widgets.iter().find_map(|w| w.page)).unwrap_or(s.page);
                let missing = field.is_none().then(|| s.field.clone());
                if let Some(v) = self.views.iter_mut().find(|v| v.id == doc) {
                    v.go_to_page(page);
                }
                if let Some(name) = missing {
                    self.notify_fmt(
                        "Your signature field {field} isn't in this document. Close it and use Sign with my name in Nextcloud.",
                        &[("field", &name)],
                    );
                }
            }
            Some(Mode::Request(r)) => r.doc = Some(doc),
            None => {}
        }
        // Nothing to edit with: put any tool down.
        self.quick_tool = crate::QuickTool::Select;
    }

    /// Add the host's roots to the trust store as "this Nextcloud", for this session only.
    fn trust_host_roots(&mut self, pems: &[String]) {
        let mut certs = self.session.trusted_certificates().to_vec();
        let mut added = false;
        for pem in pems {
            let Ok(found) = pdfcraft_engine::sign::x509::load_certificates(pem.as_bytes()) else {
                log::warn!("PdfCraft: a trust root from the host is not a certificate; ignored");
                continue;
            };
            for cert in found {
                if !certs.iter().any(|c| c.raw == cert.raw) {
                    self.esign.host_roots.push(cert.raw.clone());
                    certs.push(cert);
                    added = true;
                }
            }
        }
        if added {
            self.apply_trusted_certificates(certs);
        }
    }

    /// Whether document `id` is open for a signature request (sign or request mode), and so
    /// read-only.
    pub fn esign_locked(&self, id: DocId) -> bool {
        self.esign.locks(id)
    }

    /// Whether the active document is read-only for a signature request.
    pub(crate) fn esign_locks_active(&self) -> bool {
        self.active_ids().is_some_and(|(_, id)| self.esign_locked(id))
    }

    /// Whether `spec` may run while the active document is open for a signature request: reading,
    /// finding, copying, printing and the file's own commands, never an edit.
    pub(crate) fn esign_allows(&self, spec: &CommandSpec) -> bool {
        if !self.esign_locks_active() {
            return true;
        }
        match spec.needs {
            Needs::Nothing => !spec.id.starts_with("sign.") && !spec.id.starts_with("form."),
            Needs::Copying | Needs::Printing | Needs::TwoPageView => true,
            Needs::Document => {
                const READING: [&str; 9] = [
                    "view.",
                    "file.",
                    "edit.find",
                    "edit.advanced_search",
                    "edit.column_select",
                    "comment.copy",
                    "comment.list",
                    "sign.panel",
                    "sign.validate",
                ];
                READING.iter().any(|p| spec.id.starts_with(p)) || spec.id == "page.copy"
            }
            _ => false,
        }
    }

    /// The signer clicked `field`: his own opens the Fill & Sign picker for it; any other does
    /// nothing. Returns whether the picker opened.
    pub fn sign_field_clicked(&mut self, field: &str) -> bool {
        let Some(Mode::Sign(s)) = &mut self.esign.mode else { return false };
        if s.field != field || self.dialog.is_some() {
            return false;
        }
        s.picking = true;
        self.signature_draft = match &self.signature {
            Some(saved) => crate::fill_sign::SigDraft::from_saved(false, saved),
            None => crate::fill_sign::SigDraft::new(false, &self.comment_prefs.author),
        };
        self.signature_draft.editing = false;
        self.signature_draft.for_request = true;
        self.dialog = Some(crate::Dialog::Signature);
        true
    }

    /// The picker was closed without a mark.
    pub(crate) fn sign_pick_cancelled(&mut self) {
        if let Some(Mode::Sign(s)) = &mut self.esign.mode {
            s.picking = false;
        }
    }

    /// The signature pad's Apply (Done in sign mode): in sign mode the mark goes to the host;
    /// otherwise it becomes the saved signature or initials and its tool is picked. Returns
    /// whether the dialog may close: a mark refused at the caps keeps it open, with the drawing,
    /// and the reason in `signature_draft.error`.
    pub fn signature_pad_applied(&mut self) -> bool {
        if self.esign.picking() {
            let Some(saved) = self.signature_draft.saved() else { return true };
            match mark_json(&saved) {
                Ok(graphic) => {
                    self.signature_draft = Default::default();
                    self.dialog = None;
                    self.sign_pick_cancelled();
                    self.post_mark(graphic);
                }
                Err(why) => {
                    self.signature_draft.error = Some(crate::i18n::fmt(tl!("Couldn't use this signature: {e}"), &[("e", &why)]));
                    return false;
                }
            }
            return true;
        }
        let d = std::mem::take(&mut self.signature_draft);
        let tool = if d.initials {
            self.initials = d.saved();
            crate::fill_sign::FillTool::Initials
        } else {
            self.signature = d.saved();
            crate::fill_sign::FillTool::Signature
        };
        self.fill_tool = tool;
        self.quick_tool = crate::QuickTool::Fill(tool);
        self.toast = None;
        true
    }

    fn post_mark(&mut self, graphic: Value) {
        let Some(Mode::Sign(s)) = &self.esign.mode else { return };
        let message = json!({ "type": "pdfcraft:sign-mark", "requestId": s.request_id, "field": s.field, "graphic": graphic });
        self.post_to_host(message);
    }

    fn post_to_host(&mut self, message: Value) -> bool {
        match self.host_sign_post.as_ref().map(|post| post(message)) {
            Some(Ok(())) => true,
            Some(Err(e)) => {
                log::warn!("PdfCraft: a message to Nextcloud did not go: {e}");
                self.notify_tr("Couldn't reach Nextcloud. Reload the page and try again.");
                false
            }
            None => {
                self.notify_tr("No Nextcloud connected");
                false
            }
        }
    }

    /// Place the next signer's box at `rect` (PDF user space) on 0-based `page`. Returns that
    /// signer's position, or why not: every listed signer has one box at most.
    pub fn place_signer_box(&mut self, page: usize, rect: [f64; 4]) -> Result<u32, String> {
        let Some(Mode::Request(r)) = &mut self.esign.mode else { return Err(tl!("No signature request is being prepared.").to_string()) };
        if !rect.iter().all(|v| v.is_finite()) || rect[0] >= rect[2] || rect[1] >= rect[3] {
            return Err(tl!("Draw the box on the page.").to_string());
        }
        let Some(position) = r.signers.iter().map(|(p, _)| *p).find(|p| !r.boxes.iter().any(|b| b.position == *p)) else {
            return Err(tl!("Every signer has a box. Remove one to draw it again.").to_string());
        };
        r.boxes.push(SignerBox { position, page, rect });
        Ok(position)
    }

    /// Take away the box of the signer at `position`.
    pub fn remove_signer_box(&mut self, position: u32) {
        if let Some(Mode::Request(r)) = &mut self.esign.mode {
            r.boxes.retain(|b| b.position != position);
        }
    }

    /// Stop placing boxes: request mode ends and the document can be edited again.
    pub fn stop_request_mode(&mut self) {
        if matches!(self.esign.mode, Some(Mode::Request(_))) {
            self.esign.mode = None;
        }
    }

    /// The Signatures panel's Sign on `field`, in the document of view `index`.
    pub(crate) fn signatures_panel_sign(&mut self, index: usize, field: String) {
        let Some(view) = self.views.get(index) else { return };
        let (page, id) = (view.current, view.id);
        if self.esign_locked(id) {
            // In sign mode only the signer's own field takes a mark, through the picker.
            self.sign_field_clicked(&field);
            return;
        }
        self.start_signing(page, None, Some(field), None);
    }

    /// Send: post the boxes to the host (`pdfcraft:sign-placements`). Returns whether it went.
    pub fn send_placements(&mut self) -> bool {
        let Some(Mode::Request(r)) = &self.esign.mode else { return false };
        if r.boxes.is_empty() {
            self.notify_tr("Draw a box for at least one signer first.");
            return false;
        }
        let placements: Vec<Value> = r.boxes.iter().map(|b| json!({ "position": b.position, "page": b.page, "rect": b.rect })).collect();
        let sent = self.post_to_host(json!({ "type": "pdfcraft:sign-placements", "placements": placements }));
        if sent {
            // The places went: the request is the host's now, and the document is hers again.
            self.esign.mode = None;
        }
        sent
    }

    /// The commands the host offers now, for the palette and the control channel.
    pub fn host_commands(&self) -> Vec<HostCommand> {
        if self.host_sign_post.is_none() || !self.host_sign.offered() {
            return Vec::new();
        }
        HOST_COMMANDS.to_vec()
    }

    /// Whether `id` is a command the host offers now.
    pub fn host_command_registered(&self, id: &str) -> bool {
        self.host_commands().iter().any(|c| c.id == id)
    }

    /// Run a command the host offers. `None` when `id` is not one.
    pub(crate) fn run_host_command(&mut self, id: &str) -> Option<bool> {
        HOST_COMMANDS.iter().find(|c| c.id == id)?;
        if !self.host_command_registered(id) {
            return Some(false);
        }
        if self.active_ids().is_none() {
            self.notify_tr("Open a document first");
            return Some(false);
        }
        Some(self.post_to_host(json!({ "type": "pdfcraft:sign-request" })))
    }
}

/// The banner above the page in sign or request mode (with request mode's signers and Send).
pub(crate) fn banner(app: &mut PdfCraftApp, index: usize, ui: &mut egui::Ui) {
    let Some(view) = app.views.get(index) else { return };
    if !app.esign_locked(view.id) {
        return;
    }
    let t = Tokens::get(ui.ctx());
    let mut send = false;
    let mut stop = false;
    let mut remove = None;
    egui::Frame::NONE.fill(t.accent_soft).inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        match &app.esign.mode {
            Some(Mode::Sign(s)) => {
                ui.add(egui::Label::new(egui::RichText::new(&s.banner).color(t.text).font(crate::theme::semibold(13.0))).wrap());
            }
            Some(Mode::Request(r)) => {
                let next = r.signers.iter().find(|(p, _)| !r.boxes.iter().any(|b| b.position == *p));
                let prompt = match next {
                    Some((_, name)) => crate::i18n::fmt(tl!("Draw the box where {name} signs"), &[("name", name)]),
                    None => tl!("Every signer has a box. Send the places to Nextcloud.").to_string(),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(prompt).color(t.text).font(crate::theme::semibold(13.0)));
                    for (position, name) in &r.signers {
                        if r.boxes.iter().any(|b| b.position == *position) {
                            let label = crate::i18n::fmt(tl!("Remove {name}'s box"), &[("name", name)]);
                            if ui.button(label).clicked() {
                                remove = Some(*position);
                            }
                        }
                    }
                    if ui.button(tl!("Stop placing")).clicked() {
                        stop = true;
                    }
                    let any = !r.boxes.is_empty();
                    if ui.add_enabled_ui(any, |ui| crate::widgets::pill_button(ui, tl!("Send"), true)).inner.clicked() && any {
                        send = true;
                    }
                });
            }
            None => {}
        }
    });
    if let Some(position) = remove {
        app.remove_signer_box(position);
    }
    if send {
        app.send_placements();
    }
    if stop {
        app.stop_request_mode();
    }
}

/// The outlines over the pages in sign mode (the signer's field takes the click that opens the
/// picker; the others take clicks and do nothing), and request mode's boxes and the drag that
/// draws them. Drawn after the page view, over it.
pub fn overlay(app: &mut PdfCraftApp, index: usize, ui: &mut egui::Ui) {
    let Some(view) = app.views.get(index) else { return };
    let id = view.id;
    if !app.esign_locked(id) {
        return;
    }
    let Some(doc) = app.session.get(id) else { return };
    let clip = view.viewport_rect();
    if !clip.is_positive() {
        return;
    }
    let t = Tokens::get(ui.ctx());
    let painter = ui.painter_at(clip);
    let modal = app.modal_open();
    let sense = if modal { Sense::hover() } else { Sense::click() };
    match &app.esign.mode {
        Some(Mode::Sign(s)) => {
            let mut clicked = None;
            let fields = std::iter::once((s.field.as_str(), true)).chain(s.others.iter().map(|o| (o.as_str(), false)));
            for (name, mine) in fields {
                let Some(f) = doc.form.iter().find(|f| f.name == name) else { continue };
                for wi in 0..f.widgets.len() {
                    let Some(rect) = crate::forms_ui::field_screen_rect(view, &doc.info, f, wi) else { continue };
                    let shown = rect.intersect(clip);
                    if !shown.is_positive() {
                        continue;
                    }
                    if mine {
                        painter.rect_filled(rect, CornerRadius::same(3), t.accent_soft.gamma_multiply(0.5));
                        painter.rect_stroke(rect.expand(2.0), CornerRadius::same(4), Stroke::new(2.5, t.accent), egui::StrokeKind::Outside);
                    } else {
                        painter.rect_filled(rect, CornerRadius::same(3), Color32::from_gray(128).gamma_multiply(0.45));
                        painter.rect_stroke(rect, CornerRadius::same(3), Stroke::new(1.0, t.text_faint), egui::StrokeKind::Inside);
                    }
                    let resp = ui.interact(shown, egui::Id::unique(("esign-field", name, wi)), sense);
                    let label = if mine {
                        crate::i18n::fmt(tl!("Sign here: {field}"), &[("field", name)])
                    } else {
                        crate::i18n::fmt(tl!("Another signer's field: {field}"), &[("field", name)])
                    };
                    resp.widget_info(|| egui::WidgetInfo::labeled(if mine { egui::Role::Button } else { egui::Role::Label }, mine, label.clone()));
                    let resp = if mine { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp };
                    if mine && resp.clicked() {
                        clicked = Some(name.to_string());
                    }
                }
            }
            if let Some(name) = clicked {
                app.sign_field_clicked(&name);
            }
        }
        Some(Mode::Request(r)) => {
            let xforms = view.page_xforms();
            // The boxes placed, each labelled with its signer's name.
            for b in &r.boxes {
                let Some((_, xf)) = xforms.iter().find(|(p, _)| *p == b.page) else { continue };
                let rect = xf.user_rect(&doc.info, b.page, b.rect.map(|v| v as f32));
                let name = r.signers.iter().find(|(p, _)| *p == b.position).map(|(_, n)| n.as_str()).unwrap_or_default();
                painter.rect_filled(rect, CornerRadius::same(3), t.accent_soft.gamma_multiply(0.6));
                painter.rect_stroke(rect, CornerRadius::same(3), Stroke::new(2.0, t.accent), egui::StrokeKind::Inside);
                painter.text(rect.left_top() + egui::vec2(4.0, 3.0), egui::Align2::LEFT_TOP, name, egui::FontId::proportional(12.0), t.accent_text);
                let shown = rect.intersect(clip);
                if shown.is_positive() {
                    let label = crate::i18n::fmt(tl!("Signature box for {name}"), &[("name", name)]);
                    ui.interact(shown, egui::Id::unique(("esign-box", b.position)), Sense::hover())
                        .widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, label.clone()));
                }
            }
            let can_draw = r.signers.iter().any(|(p, _)| !r.boxes.iter().any(|b| b.position == *p));
            if !can_draw || modal {
                return;
            }
            let resp =
                ui.interact(clip, egui::Id::unique(("esign-draw", index)), Sense::click_and_drag()).on_hover_cursor(egui::CursorIcon::Crosshair);
            let at = resp.interact_pointer_pos();
            let page_at = |p: Pos2| xforms.iter().find(|(_, xf)| xf.rect.contains(p)).map(|(i, xf)| (*i, *xf));
            let mut drawing = r.drawing;
            let mut placed = None;
            if resp.drag_started_by(egui::PointerButton::Primary)
                && let Some(p) = at
                && let Some((page, _)) = page_at(p)
            {
                drawing = Some((page, p));
            }
            if let Some((page, from)) = drawing
                && let Some((_, xf)) = xforms.iter().find(|(i, _)| *i == page)
            {
                let to = at.unwrap_or(from).clamp(xf.rect.min, xf.rect.max);
                let rect = Rect::from_two_pos(from, to);
                painter.rect_stroke(rect, CornerRadius::same(2), Stroke::new(1.5, t.accent), egui::StrokeKind::Inside);
                if resp.drag_stopped() {
                    drawing = None;
                    if rect.width() >= 4.0 && rect.height() >= 4.0 && page < doc.info.pages.len() {
                        placed = Some((page, crate::prepare::user_rect(xf, &doc.info, page, rect)));
                    }
                }
            } else if resp.clicked()
                && let Some(p) = at
                && let Some((page, xf)) = page_at(p)
                && let Some(info) = doc.info.pages.get(page)
            {
                // A click places the default size with its top-left corner at the pointer.
                let (x, y) = xf.screen_to_view(p);
                let (w, h) = (CLICK_BOX.0.min(f64::from(xf.pw)) as f32, CLICK_BOX.1.min(f64::from(xf.ph)) as f32);
                let (x, y) = (x.min(xf.pw - w).max(0.0), y.min(xf.ph - h).max(0.0));
                placed = Some((page, view_box_to_user(info, [x, y, x + w, y + h])));
            }
            if let Some(Mode::Request(r)) = &mut app.esign.mode {
                r.drawing = drawing;
            }
            if let Some((page, rect)) = placed
                && let Err(why) = app.place_signer_box(page, rect)
            {
                app.notify(why);
            }
        }
        None => {}
    }
}

#[cfg(test)]
#[path = "sign_request_tests.rs"]
mod tests;
