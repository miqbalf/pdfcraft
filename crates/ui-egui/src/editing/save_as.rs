//! Save As = Export: every format PdfCraft writes is in one list, [`SAVE_AS`], and every Save As
//! and Export entry point (File menu, Cmd/Ctrl+Shift+S, command search, the control channel, a
//! form's SaveAs button or `execMenuItem`) goes through [`PdfCraftApp::save_as_copy`].
//!
//! A Save As is always a copy: the document keeps its file, name, unsaved changes and saved
//! state. On the web the copy downloads (also inside a hosting page: Save As never goes to the
//! host); on the desktop the save dialog asks where. Plain Save is not here (`save.rs`).

use craft_share::export::{Delivery, Runtime, SaveAsPlan};
use pdfcraft_engine::compare::OfficeFormat;

use crate::PdfCraftApp;
use crate::export_ui::ExportKind;

/// Every format PdfCraft writes (the engine's list, shared with automation).
pub use pdfcraft_engine::export::SAVE_AS;

/// What writes a desktop copy once the save dialog has answered (the path chosen).
#[cfg(not(target_arch = "wasm32"))]
type WriteCopy = Box<dyn FnOnce(&mut PdfCraftApp, String) + Send>;

/// The name a document gets when it has none to name a copy after.
pub(crate) use pdfcraft_engine::export::COPY_FALLBACK as FALLBACK;

/// What writes a format of [`SAVE_AS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Writer {
    /// The document itself, as PDF.
    Pdf,
    /// The engine's office export.
    Office(OfficeFormat),
    /// The Export dialog (options first, then the files).
    Dialog(ExportKind),
}

impl Writer {
    /// The writer of the format `id` in [`SAVE_AS`].
    pub(crate) fn of(id: &str) -> Option<Self> {
        Some(match id {
            "pdf" => Writer::Pdf,
            "docx" => Writer::Office(OfficeFormat::Docx),
            "pptx" => Writer::Office(OfficeFormat::Pptx),
            "rtf" => Writer::Office(OfficeFormat::Rtf),
            "html" => Writer::Office(OfficeFormat::Html),
            "text" => Writer::Dialog(ExportKind::Text),
            "image" => Writer::Dialog(ExportKind::Image),
            "all_images" => Writer::Dialog(ExportKind::AllImages),
            _ => return None,
        })
    }

    /// The [`SAVE_AS`] id of this writer.
    #[cfg(test)]
    fn id(self) -> &'static str {
        match self {
            Writer::Pdf => "pdf",
            Writer::Office(OfficeFormat::Docx) => "docx",
            Writer::Office(OfficeFormat::Pptx) => "pptx",
            Writer::Office(OfficeFormat::Rtf) => "rtf",
            Writer::Office(OfficeFormat::Html | OfficeFormat::HtmlSimple) => "html",
            // Written by automation only (`doc_export`); not offered in the app.
            Writer::Office(OfficeFormat::Markdown) => "md",
            Writer::Dialog(ExportKind::Text) => "text",
            Writer::Dialog(ExportKind::Image) => "image",
            Writer::Dialog(ExportKind::AllImages) => "all_images",
        }
    }
}

/// The command each [`SAVE_AS`] format is run by (File menu, shortcut, command search).
pub(crate) fn command_format(command: &str) -> Option<&'static str> {
    Some(match command {
        "file.save_as" => "pdf",
        "export.docx" => "docx",
        "export.pptx" => "pptx",
        "export.rtf" => "rtf",
        "export.html" => "html",
        "export.text" => "text",
        "export.image" => "image",
        "export.all_images" => "all_images",
        _ => return None,
    })
}

impl PdfCraftApp {
    /// Where a Save As copy goes in this build: the desktop's save dialog, or a browser download
    /// (hosted or not). [`Self::save_as_runtime`] stands in for it in tests and automation.
    pub(crate) fn copy_runtime(&self) -> Runtime {
        if let Some(r) = self.save_as_runtime {
            return r;
        }
        #[cfg(target_arch = "wasm32")]
        {
            Runtime::web(self.host_save.is_some())
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Runtime::Desktop
        }
    }

    /// How to name and deliver a copy of document `name` as format `id`.
    pub(crate) fn copy_plan(&self, name: &str, id: &str) -> Result<SaveAsPlan, String> {
        SAVE_AS.plan(self.copy_runtime(), name, FALLBACK, id).map_err(|e| e.to_string())
    }

    /// Save As / Export the active document as format `id` of [`SAVE_AS`]: the one function every
    /// Save As and Export entry point calls. Returns `false` when nothing could start.
    pub fn save_as_copy(&mut self, id: &str) -> bool {
        match self.active {
            Some(index) => self.save_as_copy_in(index, id),
            None => false,
        }
    }

    /// [`Self::save_as_copy`] for the document in tab `index` (a form script's SaveAs runs on its
    /// own document, which need not be the active one).
    pub(crate) fn save_as_copy_in(&mut self, index: usize, id: &str) -> bool {
        let Some(writer) = Writer::of(id) else {
            self.notify_error(craft_share::export::ExportError::UnknownFormat(id.to_string()));
            return false;
        };
        match writer {
            Writer::Pdf => self.save_then(index, super::SaveTarget::Copy, |_| {}),
            Writer::Office(format) => {
                let Some(doc) = self.views.get(index).map(|v| v.id) else { return false };
                self.export_office(doc, format, id);
                true
            }
            // The options come first; the dialog's Export delivers (`start_export`), for the
            // active document.
            Writer::Dialog(kind) if Some(index) == self.active => {
                self.dialog = Some(crate::Dialog::Export(kind));
                true
            }
            Writer::Dialog(_) => false,
        }
    }

    /// Hand a planned web copy to the browser: `craft_web_host::web::download`, framed or not,
    /// never the hosting page. A native build only gets here when [`Self::save_as_runtime`] says
    /// web (tests and automation): it keeps the copy in [`Self::downloads`].
    pub(crate) fn download_copy(&mut self, name: &str, mime: &str, bytes: &[u8]) -> Result<(), String> {
        #[cfg(target_arch = "wasm32")]
        {
            craft_web_host::web::download(name, mime, bytes)
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.downloads.push((name.to_string(), mime.to_string(), bytes.to_vec()));
            Ok(())
        }
    }

    /// Write the engine's office export (`format`, [`SAVE_AS`] id `id`) of document `doc` as a
    /// copy: downloaded on the web, where the user chooses on the desktop.
    pub(crate) fn export_office(&mut self, doc: pdfcraft_engine::DocId, format: OfficeFormat, id: &str) {
        // What's typed in a form field is part of the document (#166).
        if !self.commit_typing_in(doc) || !self.may_copy(doc) {
            return;
        }
        let Some(d) = self.session.get(doc) else { return };
        let (name, folder) = (d.name.clone(), d.path.clone());
        let plan = match self.copy_plan(&name, id) {
            Ok(p) => p,
            Err(e) => return self.notify_error(e),
        };
        let bytes = d.export_office(format);
        match plan.delivery {
            Delivery::Download => {
                if let Err(e) = self.download_copy(&plan.file_name, plan.format.mime, &bytes) {
                    self.notify_fmt("Couldn't download {name}: {e}", &[("name", &plan.file_name), ("e", &e)]);
                }
            }
            Delivery::SaveDialog => {
                #[cfg(not(target_arch = "wasm32"))]
                self.pick_copy_path(&plan, folder.as_deref(), tl!("Export"), move |app, path| {
                    match crate::editing::write_atomically(&path, &bytes) {
                        Ok(()) => app.notify_fmt("Exported to {path}", &[("path", &path)]),
                        Err(e) => app.notify_fmt("Couldn't write {name}: {e}", &[("name", &path), ("e", &e.to_string())]),
                    }
                });
                #[cfg(target_arch = "wasm32")]
                let _ = (folder, bytes);
            }
        }
    }

    /// The desktop half of a copy: the save dialog, suggesting `plan`'s name in the folder of
    /// `doc_path`, then `write` with the path chosen. The chosen name gets the format's extension
    /// ([`ExportList::picked_path`]); when that names a file that already exists, which the
    /// dialog did not confirm, it asks again with that name, so the dialog asks about replacing
    /// it. [`Self::save_override`] answers instead of the dialog (tests and automation) and is
    /// written as given.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn pick_copy_path(
        &mut self,
        plan: &SaveAsPlan,
        doc_path: Option<&str>,
        title: &str,
        write: impl FnOnce(&mut Self, String) + Send + 'static,
    ) {
        if let Some(p) = self.save_override.clone() {
            return write(self, p);
        }
        self.ask_copy_path(plan.format, plan.file_name.clone(), doc_path.map(str::to_string), title.to_string(), true, Box::new(write));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn ask_copy_path(
        &mut self,
        format: craft_share::export::ExportFormat,
        file_name: String,
        folder: Option<String>,
        title: String,
        again: bool,
        write: WriteCopy,
    ) {
        use crate::file_filter::AddFilterAnyCase as _;
        let dialog = rfd::AsyncFileDialog::new()
            .set_title(title.clone())
            .add_filter_any_case(format.ext.to_uppercase(), &[format.ext])
            .set_file_name(file_name.clone());
        let dialog = super::in_document_folder(dialog, folder.as_deref());
        self.ask_one(crate::pickers::Ask::Save(dialog), None, move |app, dest| {
            let picked = match SAVE_AS.picked_path(&dest.to_string_lossy(), format.id) {
                Ok(p) => p,
                Err(e) => return app.notify_error(e),
            };
            if picked.renamed && std::path::Path::new(&picked.path).exists() {
                if again {
                    // The dialog confirmed another name: ask again with this one, so it asks
                    // whether to replace the file.
                    let name = std::path::Path::new(&picked.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or(file_name);
                    let folder = std::path::Path::new(&picked.path).parent().map(|p| p.join("x").to_string_lossy().into_owned());
                    return app.ask_copy_path(format, name, folder, title, false, write);
                }
                let e = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
                return app.notify_fmt("Couldn't save {name}: {e}", &[("name", &picked.path), ("e", &e.to_string())]);
            }
            write(app, picked.path);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use craft_share::export::{Delivery, Runtime};

    #[test]
    fn the_list_is_valid() {
        assert_eq!(SAVE_AS.check(), Ok(()));
    }

    /// Every writer the app offers has its format in the list, and the list has nothing else.
    #[test]
    fn the_list_covers_every_writer_the_app_offers() {
        let offered = [
            Writer::Pdf,
            Writer::Office(OfficeFormat::Docx),
            Writer::Office(OfficeFormat::Pptx),
            Writer::Office(OfficeFormat::Rtf),
            Writer::Office(OfficeFormat::Html),
            Writer::Dialog(ExportKind::Text),
            Writer::Dialog(ExportKind::Image),
            Writer::Dialog(ExportKind::AllImages),
        ];
        let mut from_writers: Vec<&str> = offered.iter().map(|w| w.id()).collect();
        let mut listed: Vec<&str> = SAVE_AS.formats().iter().map(|f| f.id).collect();
        from_writers.sort_unstable();
        listed.sort_unstable();
        assert_eq!(from_writers, listed);
        for f in SAVE_AS.formats() {
            let w = Writer::of(f.id).expect("every listed format has a writer");
            assert_eq!(w.id(), f.id);
            if let Writer::Office(o) = w {
                assert_eq!(o.extension(), f.ext, "{}: the list names the extension the engine writes", f.id);
            }
        }
        // Every Save As / Export command of the menus routes to a listed format.
        for spec in pdfcraft_engine::commands::COMMANDS.iter().filter(|c| c.id == "file.save_as" || c.id.starts_with("export.")) {
            let id = command_format(spec.id).unwrap_or_else(|| panic!("{} has no Save As format", spec.id));
            assert!(SAVE_AS.get(id).is_some(), "{}", spec.id);
            assert_eq!(SAVE_AS.get(id).map(|f| f.label), Some(spec.label), "{}: the list uses the command's label", spec.id);
        }
    }

    #[test]
    fn the_web_downloads_a_copy_named_after_the_document_hosted_or_not() {
        for runtime in [Runtime::Web, Runtime::WebHosted] {
            let pdf = SAVE_AS.plan(runtime, "report.pdf", FALLBACK, "pdf").unwrap();
            assert_eq!((pdf.delivery, pdf.file_name.as_str(), pdf.format.mime), (Delivery::Download, "report.pdf", "application/pdf"));
            let docx = SAVE_AS.plan(runtime, "report.pdf", FALLBACK, "docx").unwrap();
            assert_eq!(docx.delivery, Delivery::Download);
            assert_eq!(docx.file_name, "report.docx");
            assert!(docx.format.mime.contains("wordprocessingml"));
        }
        let desktop = SAVE_AS.plan(Runtime::Desktop, "/home/a/report.pdf", FALLBACK, "rtf").unwrap();
        assert_eq!((desktop.delivery, desktop.file_name.as_str()), (Delivery::SaveDialog, "report.rtf"));
    }
}
