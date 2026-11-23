//! Export a PDF ▸ Image (PNG, JPEG, TIFF) and Text (Acrobat's Export a PDF tool, first formats).
//!
//! On the desktop the export runs on a worker thread and reports progress in the notice bar;
//! on the web it runs in place and downloads the files.

use std::sync::{Arc, Mutex};

use egui::{Align, Layout};
use pdfcraft_engine::export::{ExportSource, Exporter, ImageFormat, all_images_stem, page_image_name};

use crate::marks_ui::PageRange;
use crate::theme::{self, Tokens};
use crate::{PdfCraftApp, widgets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportKind {
    Image,
    Text,
    /// Export all images: the images pages use, as files.
    AllImages,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExportDraft {
    pub dpi: f64,
    pub range: PageRange,
    pub format: ImageFormat,
    /// Export all images ▸ skip images with fewer pixels than this on their shorter side.
    pub min_side: u32,
}

impl Default for ExportDraft {
    fn default() -> Self {
        Self { dpi: 150.0, range: PageRange::default(), format: ImageFormat::Png, min_side: 0 }
    }
}

/// Progress of a background export: (done, total, final message once finished).
pub type ExportStatus = Arc<Mutex<Option<(usize, usize, Option<String>)>>>;

pub(crate) fn body(ui: &mut egui::Ui, app: &mut PdfCraftApp, t: &Tokens, kind: ExportKind) -> (bool, bool) {
    let count = app.active_ids().and_then(|(_, id)| app.session.get(id)).map(|d| d.info.pages.len()).unwrap_or(0);
    let d = &mut app.export_draft;
    ui.label(
        egui::RichText::new(match kind {
            ExportKind::Image => tl!("Export to Image"),
            ExportKind::Text => tl!("Export to Text"),
            ExportKind::AllImages => tl!("Export All Images"),
        })
        .font(theme::semibold(18.0)),
    );
    ui.add_space(8.0);
    if kind == ExportKind::Image {
        ui.horizontal(|ui| {
            ui.label(tl!("Resolution"));
            craft_ui::ComboBox::from_id_salt("export-dpi")
                .selected_text(crate::i18n::fmt(tl!("{dpi} pixels/inch"), &[("dpi", &d.dpi.to_string())]))
                .show_ui(ui, |ui| {
                    for dpi in [72.0, 96.0, 150.0, 300.0, 600.0] {
                        ui.selectable_value(&mut d.dpi, dpi, crate::i18n::fmt(tl!("{dpi} pixels/inch"), &[("dpi", &dpi.to_string())]));
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label(tl!("Format"));
            let mut quality = match d.format {
                ImageFormat::Jpeg { quality } => quality,
                _ => 85,
            };
            craft_ui::ComboBox::from_id_salt("export-format").selected_text(d.format.label()).show_ui(ui, |ui| {
                for f in [ImageFormat::Png, ImageFormat::Jpeg { quality }, ImageFormat::Tiff] {
                    let on = std::mem::discriminant(&d.format) == std::mem::discriminant(&f);
                    if ui.selectable_label(on, f.label()).clicked() {
                        d.format = f;
                    }
                }
            });
            if let ImageFormat::Jpeg { .. } = d.format {
                ui.label(tl!("Quality"));
                if ui.add(egui::Slider::new(&mut quality, 10..=100)).changed() {
                    d.format = ImageFormat::Jpeg { quality };
                }
            }
        });
        ui.label(
            egui::RichText::new(crate::i18n::fmt(tl!("One {f} file per page, named after the document."), &[("f", d.format.label())]))
                .small()
                .color(t.text_faint),
        );
    } else if kind == ExportKind::AllImages {
        ui.horizontal(|ui| {
            ui.label(tl!("Exclude images smaller than"));
            let label = move |n: u32| {
                if n == 0 { tl!("No limit").to_string() } else { crate::i18n::trn(crate::i18n::current(), u64::from(n), "{n} pixel", "{n} pixels") }
            };
            craft_ui::ComboBox::from_id_salt("export-min").selected_text(label(d.min_side)).show_ui(ui, |ui| {
                for n in [0, 16, 32, 64, 128, 256] {
                    ui.selectable_value(&mut d.min_side, n, label(n));
                }
            });
        });
        ui.label(
            egui::RichText::new(tl!("Each image once, named after the document and page. JPEG images are saved unchanged; others as PNG."))
                .small()
                .color(t.text_faint),
        );
    } else {
        ui.label(egui::RichText::new(tl!("Plain text in reading order; pages are separated by form feeds.")).small().color(t.text_faint));
    }
    ui.add_space(6.0);
    ui.label(egui::RichText::new(tl!("Pages")).font(theme::semibold(12.5)));
    d.range.ui(ui, count);
    ui.add_space(12.0);
    let (mut apply, mut cancel) = (false, false);
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        let ok = !d.range.pages(count).is_empty();
        if ui.add_enabled_ui(ok, |ui| widgets::pill_button(ui, tl!("Export"), true)).inner.clicked() {
            apply = true;
        }
        if widgets::pill_button(ui, tl!("Cancel"), false).clicked() {
            cancel = true;
        }
    });
    (apply, cancel)
}

/// Write the files (`name`, bytes) produced for `pages`, reporting progress.
struct ExportTask<'a> {
    src: ExportSource,
    kind: ExportKind,
    dpi: f64,
    format: ImageFormat,
    min_side: u32,
    pages: Vec<usize>,
    /// The document's name: the files are named after it ([`SAVE_AS`](crate::editing::SAVE_AS)).
    doc_name: String,
    /// The text file's name, when the user chose it (the desktop's save dialog).
    text_name: Option<String>,
    status: &'a ExportStatus,
    lang: crate::i18n::Lang,
}

fn run(task: ExportTask<'_>, mut sink: impl FnMut(&str, Vec<u8>) -> Result<(), String>) -> String {
    let ExportTask { src, kind, dpi, format, min_side, pages, doc_name, text_name, status, lang } = task;
    let list = crate::editing::SAVE_AS;
    let fallback = crate::editing::save_as::FALLBACK;
    // May run on a worker thread: messages are drawn in the UI's language.
    crate::i18n::set_current(lang);
    let total = pages.len();
    let set = |done: usize, msg: Option<String>| {
        if let Ok(mut s) = status.lock() {
            *s = Some((done, total, msg));
        }
    };
    if kind == ExportKind::AllImages {
        set(0, None);
        let out = match pdfcraft_engine::export::extract_images(&src, &pages, min_side) {
            Ok(o) => o,
            Err(e) => return crate::i18n::fmt(tl!("Export stopped: {e}"), &[("e", &e.to_string())]),
        };
        // The engine numbers the images by page; the stem is the copy's name without its extension.
        let stem = match all_images_stem(&doc_name) {
            Ok(s) => s,
            Err(e) => return crate::i18n::fmt(tl!("Export stopped: {e}"), &[("e", &e)]),
        };
        for (k, img) in out.images.iter().enumerate() {
            if let Err(e) = sink(&pdfcraft_engine::export::image_file_name(&stem, img, k + 1, src.pages), img.data.clone()) {
                return crate::i18n::fmt(tl!("Export stopped: {e}"), &[("e", &e.to_string())]);
            }
        }
        let n = out.images.len();
        let mut msg = if n == 1 {
            crate::i18n::fmt(tl!("Exported 1 image"), &[])
        } else {
            crate::i18n::fmt(tl!("Exported {n} images"), &[("n", &n.to_string())])
        };
        if !out.skipped.is_empty() {
            msg.push_str(&crate::i18n::fmt(
                tl!(" ({s} not exported: {first})"),
                &[("s", &out.skipped.len().to_string()), ("first", &out.skipped[0].2)],
            ));
        }
        return msg;
    }
    let mut ex = Exporter::from_source(src);
    match kind {
        // Handled above.
        ExportKind::AllImages => String::new(),
        ExportKind::Image => {
            set(0, None);
            // Pages are drawn several at once and handed over in order: the progress counts the
            // pages written so far.
            let mut done = 0;
            let result = ex.images(&pages, dpi, format, |p, img| {
                sink(&page_image_name(&doc_name, p, format)?, img)?;
                done += 1;
                set(done, None);
                Ok(())
            });
            if let Err(e) = result {
                return crate::i18n::fmt(tl!("Export stopped: {e}"), &[("e", &e.to_string())]);
            }
            let mut msg = if total == 1 {
                crate::i18n::fmt(tl!("Exported 1 image"), &[])
            } else {
                crate::i18n::fmt(tl!("Exported {n} images"), &[("n", &total.to_string())])
            };
            // Pages too large for the renderer at the chosen resolution are drawn at the most it
            // allows: say so, rather than leave a smaller image unexplained.
            let lowered: Vec<f64> = pages.iter().map(|p| ex.dpi_used(*p, dpi)).filter(|used| *used < dpi.clamp(18.0, 1200.0) - 0.5).collect();
            if let Some(lowest) = lowered.iter().copied().reduce(f64::min) {
                msg.push_str(&crate::i18n::fmt(
                    tl!(" ({n} at {dpi} dpi, the largest size they can be drawn at)"),
                    &[("n", &lowered.len().to_string()), ("dpi", &format!("{}", lowest.floor()))],
                ));
            }
            msg
        }
        ExportKind::Text => {
            set(0, None);
            let name = match text_name {
                Some(n) => Ok(n),
                None => list.file_name(&doc_name, fallback, "text").map_err(|e| e.to_string()),
            };
            match name.and_then(|name| ex.text_of(&pages).and_then(|text| sink(&name, text.into_bytes()))) {
                Ok(()) => {
                    if total == 1 {
                        crate::i18n::fmt(tl!("Exported the text of 1 page"), &[])
                    } else {
                        crate::i18n::fmt(tl!("Exported the text of {n} pages"), &[("n", &total.to_string())])
                    }
                }
                Err(e) => crate::i18n::fmt(tl!("Export stopped: {e}"), &[("e", &e.to_string())]),
            }
        }
    }
}

/// The type a file exported as `name` downloads as: from the extension it was written with.
fn file_mime(name: &str) -> &'static str {
    craft_share::export::mime_for_ext(name.rsplit_once('.').map_or("", |(_, ext)| ext))
}

/// Files an export would write over, held until the user answers [`Dialog::ReplaceFiles`]
/// (crate::Dialog::ReplaceFiles): `existing` of them are there already, and `write` writes them
/// all.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct PendingReplace {
    pub(crate) existing: usize,
    write: Box<dyn FnOnce(&mut PdfCraftApp) + Send>,
}

/// Where a background export leaves a [`PendingReplace`] for the UI thread to ask about.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type ReplaceSlot = Arc<Mutex<Option<PendingReplace>>>;

/// The [`SAVE_AS`](crate::editing::SAVE_AS) format of an Export dialog kind.
fn format_id(kind: ExportKind) -> &'static str {
    match kind {
        ExportKind::Image => "image",
        ExportKind::Text => "text",
        ExportKind::AllImages => "all_images",
    }
}

impl PdfCraftApp {
    /// Start exporting the active document with the dialog's settings, delivered as the Save As
    /// plan for its format says: downloads on the web, files on the desktop. A desktop export
    /// never writes over an existing file unasked: it asks once how many would be replaced, and
    /// writes nothing on No or when it cannot ask.
    pub(crate) fn start_export(&mut self, kind: ExportKind) {
        // What's typed in a form field is part of the document (#166).
        if !self.commit_form_typing() {
            return;
        }
        let Some((_, id)) = self.active_ids() else { return };
        if !self.may_copy(id) {
            return;
        }
        let Some(doc) = self.session.get(id) else { return };
        let src = doc.export_source();
        let doc_name = doc.name.clone();
        #[cfg(not(target_arch = "wasm32"))]
        let doc_path = doc.path.clone();
        let pages = self.export_draft.range.pages(src.pages);
        let dpi = self.export_draft.dpi;
        let format = self.export_draft.format;
        let min_side = self.export_draft.min_side;
        let status: ExportStatus = Arc::new(Mutex::new(Some((0, pages.len(), None))));
        let plan = match self.copy_plan(&doc_name, format_id(kind)) {
            Ok(p) => p,
            Err(e) => return self.notify_error(e),
        };
        match plan.delivery {
            // One download per file, each typed as what it is (PNG, JPEG, TIFF or text).
            craft_share::export::Delivery::Download => {
                let lang = crate::i18n::current();
                let task = ExportTask { src, kind, dpi, format, min_side, pages, doc_name, text_name: None, status: &status, lang };
                let msg = run(task, |name, bytes| self.download_copy(name, file_mime(name), &bytes));
                if let Ok(mut s) = status.lock() {
                    *s = Some((0, 0, Some(msg)));
                }
                self.export_status = Some(status);
            }
            #[cfg(target_arch = "wasm32")]
            craft_share::export::Delivery::SaveDialog => {}
            #[cfg(not(target_arch = "wasm32"))]
            craft_share::export::Delivery::SaveDialog => {
                // The names known before the export runs (pages as images, the text file); the
                // extracted images' names are known once they are extracted.
                let known: Vec<String> = match kind {
                    ExportKind::Image => pages.iter().filter_map(|&p| page_image_name(&doc_name, p, format).ok()).collect(),
                    ExportKind::Text => vec![plan.file_name.clone()],
                    ExportKind::AllImages => Vec::new(),
                };
                let slot = self.replace_slot.clone();
                let start = move |app: &mut Self, dir: std::path::PathBuf, inline: bool, text_name: Option<String>| {
                    let st = status.clone();
                    let shown = dir.display().to_string();
                    let lang = crate::i18n::current();
                    let done = move |msg: &str| crate::i18n::fmt(tl!("{msg} to {dir}"), &[("msg", msg), ("dir", &shown)]);
                    // A name the save dialog confirmed was asked about there.
                    let existing = if text_name.is_some() { 0 } else { known.iter().filter(|n| dir.join(n).exists()).count() };
                    let go = move |app: &mut Self| {
                        let finish = st.clone();
                        let work = move || {
                            let write = |dir: &std::path::Path, name: &str, bytes: &[u8]| {
                                crate::editing::write_atomically(&dir.join(name).to_string_lossy(), bytes).map_err(|e| format!("{name}: {e}"))
                            };
                            let task = ExportTask { src, kind, dpi, format, min_side, pages, doc_name, text_name, status: &st, lang };
                            let msg = if kind == ExportKind::AllImages {
                                // Extracted images are in memory already: hold them until it is
                                // known that none is there, or the user said to replace them.
                                let mut files: Vec<(String, Vec<u8>)> = Vec::new();
                                let msg = run(task, |name, bytes| {
                                    files.push((name.to_string(), bytes));
                                    Ok(())
                                });
                                let existing = files.iter().filter(|(n, _)| dir.join(n).exists()).count();
                                let write_all = move |dir: &std::path::Path, files: Vec<(String, Vec<u8>)>| -> Result<(), String> {
                                    files.iter().try_for_each(|(n, b)| write(dir, n, b))
                                };
                                let stopped = |e: String| crate::i18n::fmt(tl!("Export stopped: {e}"), &[("e", &e)]);
                                if existing == 0 {
                                    match write_all(&dir, files) {
                                        Ok(()) => done(&msg),
                                        Err(e) => stopped(e),
                                    }
                                } else {
                                    let write: Box<dyn FnOnce(&mut PdfCraftApp) + Send> = Box::new(move |app| match write_all(&dir, files) {
                                        Ok(()) => app.notify(done(&msg)),
                                        Err(e) => app.notify(stopped(e)),
                                    });
                                    if let Ok(mut s) = slot.lock() {
                                        *s = Some(PendingReplace { existing, write });
                                    }
                                    // Nothing to say yet: the question follows.
                                    String::new()
                                }
                            } else {
                                done(&run(task, |name, bytes| write(&dir, name, &bytes)))
                            };
                            if let Ok(mut s) = finish.lock() {
                                let (done, total) = s.as_ref().map_or((0, 0), |(d, t, _)| (*d, *t));
                                *s = Some((done.max(total), total, Some(msg)));
                            }
                        };
                        if inline {
                            work(); // tests and automation: synchronous
                        } else {
                            std::thread::Builder::new().name("pdfcraft-export".into()).spawn(work).ok();
                        }
                        app.export_status = Some(status);
                    };
                    if existing > 0 {
                        app.ask_replace(PendingReplace { existing, write: Box::new(go) });
                    } else {
                        go(app);
                    }
                };
                match self.export_dir_override.clone() {
                    Some(d) => start(self, d.into(), true, None),
                    // One text file: the save dialog asks for its name, as for every other copy.
                    None if kind == ExportKind::Text => {
                        self.pick_copy_path(&plan, doc_path.as_deref(), tl!("Export"), move |app, path| {
                            let path = std::path::PathBuf::from(path);
                            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                            let dir = path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
                            start(app, dir, false, name);
                        });
                    }
                    None => {
                        let dialog = rfd::AsyncFileDialog::new().set_title(tl!("Choose a folder for the exported files").to_string());
                        self.ask_one(crate::pickers::Ask::Folder(dialog), None, move |app, dir| start(app, dir, false, None));
                    }
                }
            }
        }
    }

    /// Ask whether to replace the files `p` would write over. With no window to ask in, nothing
    /// is written.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn ask_replace(&mut self, p: PendingReplace) {
        if self.ctx.is_none() {
            let n = p.existing.to_string();
            self.notify_fmt("{n} of the files to export already exist in that folder. Nothing was exported.", &[("n", &n)]);
            return;
        }
        self.pending_replace = Some(p);
        self.dialog = Some(crate::Dialog::ReplaceFiles);
    }

    /// The answer to [`Dialog::ReplaceFiles`](crate::Dialog::ReplaceFiles): write the files over
    /// the existing ones, or nothing.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn answer_replace(&mut self, replace: bool) {
        let Some(p) = self.pending_replace.take() else { return };
        if replace {
            (p.write)(self);
        } else {
            self.notify_tr("Nothing was exported.");
        }
    }

    /// Show export progress, and the result once it is done.
    pub(crate) fn poll_export(&mut self) {
        // An export that found files it would replace asks first.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(p) = self.replace_slot.lock().ok().and_then(|mut s| s.take()) {
            self.ask_replace(p);
        }
        let Some(st) = self.export_status.clone() else { return };
        let snapshot = st.lock().ok().and_then(|s| s.clone());
        match snapshot {
            Some((_, _, Some(msg))) => {
                self.export_status = None;
                if !msg.is_empty() {
                    self.notify(msg);
                }
            }
            Some((done, total, None)) if total > 1 => {
                let m = crate::i18n::fmt(tl!("Exporting… {d} of {t}"), &[("d", &done.to_string()), ("t", &total.to_string())]);
                self.notify(m);
            }
            _ => {}
        }
        if let Some(ctx) = &self.ctx {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{all_images_stem, file_mime, page_image_name};
    use pdfcraft_engine::export::ImageFormat;

    /// Extracted images are named after the document without the image extension it kept, in
    /// any case (S5 review M4).
    #[test]
    fn extracted_images_are_named_after_the_document_without_its_extension() {
        for doc in ["x.pdf", "x.PNG", "x.jpg"] {
            assert_eq!(all_images_stem(doc).unwrap(), "x", "{doc}");
        }
    }

    /// With no window to ask in, an export that would replace a file writes nothing (I2).
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn with_no_way_to_ask_an_export_replaces_nothing() {
        let dir = std::env::temp_dir().join(format!("pdfcraft-export-headless-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("doc-2.png"), b"mine").unwrap();
        let mut app = crate::PdfCraftApp::new();
        let bytes = app.session.create_blank(200.0, 300.0, 2).unwrap();
        app.open_bytes("doc.pdf", None, bytes.to_vec()).unwrap();
        app.export_dir_override = Some(dir.to_string_lossy().into_owned());
        app.start_export(super::ExportKind::Image);
        app.poll_export();
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "nothing written: {names:?}");
        assert_eq!(std::fs::read(dir.join("doc-2.png")).unwrap(), b"mine");
        assert!(app.toast.as_ref().is_some_and(|t| t.0.contains("1 of the files")), "{:?}", app.toast);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The extension, and so the download's type, follow the encoder, not the name's extension
    /// nor the list's default (PNG).
    #[test]
    fn page_images_are_named_and_typed_by_the_encoder_used() {
        let jpeg = ImageFormat::Jpeg { quality: 80 };
        for doc in ["x.pdf", "x.jpg", "x.PNG"] {
            let name = page_image_name(doc, 0, jpeg).unwrap();
            assert!(name.starts_with('x') && name.ends_with(".jpg"), "{doc}: {name}");
            assert_eq!(file_mime(&name), "image/jpeg");
            let png = page_image_name(doc, 2, ImageFormat::Png).unwrap();
            assert!(png.ends_with(".png") && png.contains('3'), "{doc}: {png}");
            assert_eq!(file_mime(&png), "image/png");
            let tif = page_image_name(doc, 0, ImageFormat::Tiff).unwrap();
            assert_eq!(file_mime(&tif), "image/tiff", "{tif}");
        }
        assert_ne!(page_image_name("x.pdf", 0, jpeg).unwrap(), page_image_name("x.pdf", 1, jpeg).unwrap(), "one file per page");
    }
}
