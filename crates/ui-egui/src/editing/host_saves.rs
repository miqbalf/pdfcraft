//! Saves to a host page that stores them and answers each (`?host=parent`, the host's `saves`).
//!
//! The bytes go out with an id; the document counts as saved only when the host's `saved` for
//! that id arrives, and a `save-failed` leaves it unsaved with the host's reason. What was to run
//! after the save (close the tab, quit) waits for the answer too. The host may store the file
//! under another name (a conflict copy, Save As): that is the document's name from then on.

use std::sync::Arc;

use super::PdfCraftApp;
use crate::HostAnswer;

/// A save the host has not answered yet.
pub(crate) struct PendingHostSave {
    id: String,
    doc: pdfcraft_engine::DocId,
    bytes: Arc<Vec<u8>>,
    /// The document's edit generation when the bytes were taken: a later one means more was done
    /// since, which the stored file lacks.
    generation: u64,
    after: Box<dyn FnOnce(&mut PdfCraftApp) + Send>,
}

impl PdfCraftApp {
    /// A new id for a save about to be handed to the host.
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn next_host_save_id(&mut self) -> String {
        self.host_save_seq += 1;
        format!("save-{}", self.host_save_seq)
    }

    /// The bytes of `doc` went to the host as save `id`: wait for its answer, then run `after`.
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn hold_for_host(&mut self, id: String, doc: pdfcraft_engine::DocId, bytes: Arc<Vec<u8>>, after: Box<dyn FnOnce(&mut Self) + Send>) {
        let generation = self.session.get(doc).map_or(0, |d| d.edit_generation());
        self.pending_host_saves.push(PendingHostSave { id, doc, bytes, generation, after });
    }

    /// Read what the host answered since the last frame. An answer for a save that is not waiting
    /// (unknown, repeated, its document closed) changes nothing.
    pub(crate) fn poll_host_saves(&mut self) {
        for answer in self.host_saves.take_answers() {
            let (HostAnswer::Saved { id, .. } | HostAnswer::Failed { id, .. }) = &answer;
            let Some(at) = self.pending_host_saves.iter().position(|p| p.id == *id) else { continue };
            let pending = self.pending_host_saves.remove(at);
            match answer {
                HostAnswer::Failed { error, .. } => self.notify_fmt("Couldn't save to Nextcloud: {error}", &[("error", &error)]),
                HostAnswer::Saved { name, .. } => self.host_stored(pending, name),
            }
        }
    }

    fn host_stored(&mut self, pending: PendingHostSave, name: Option<String>) {
        let Some(doc) = self.session.get(pending.doc) else { return };
        if doc.edit_generation() != pending.generation {
            // Stored, but without what was done since: still unsaved, and the next save sends all.
            self.notify_fmt("Saved to Nextcloud, but changes made since are not saved yet", &[]);
            return;
        }
        if self.session.mark_saved(pending.doc, pending.bytes, name).is_ok() {
            self.placed_signatures.remove(&pending.doc);
        }
        if let Some(doc) = self.session.get(pending.doc)
            && let Some(view) = self.views.iter_mut().find(|v| v.id == pending.doc)
        {
            view.document_changed(&doc.info);
            view.redactions_downloaded = view.redactions_applied;
        }
        (pending.after)(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pdfcraft_engine::{Edit, FieldValue};

    fn app() -> PdfCraftApp {
        let mut app = PdfCraftApp::new();
        app.open_bytes("form.pdf", None, include_bytes!("../../tests/data/form.pdf").to_vec()).unwrap();
        app
    }

    fn edit(app: &mut PdfCraftApp, text: &str) {
        assert!(app.apply_edit(Edit::SetFieldValue { name: "name".into(), value: FieldValue::Text(text.into()) }));
    }

    /// Hand the shown document to a pretend host as save `id`, after an edit; the app waits.
    fn sent(app: &mut PdfCraftApp) -> String {
        let id = app.views[0].id;
        edit(app, "First");
        let bytes = app.session.save_bytes(id).unwrap();
        let save = app.next_host_save_id();
        app.hold_for_host(save.clone(), id, bytes, Box::new(|app| app.notify_fmt("after ran", &[])));
        save
    }

    fn dirty(app: &PdfCraftApp) -> bool {
        app.session.get(app.views[0].id).is_some_and(|d| d.dirty)
    }

    #[test]
    fn the_document_is_saved_only_when_the_host_says_so_and_takes_its_name() {
        let mut app = app();
        let save = sent(&mut app);
        app.poll_host_saves();
        assert!(dirty(&app), "handing the bytes over is not saving them");
        app.host_saves.answer(HostAnswer::Saved { id: save, name: Some("form (conflict).pdf".into()) });
        app.poll_host_saves();
        assert!(!dirty(&app));
        assert_eq!(app.session.get(app.views[0].id).map(|d| d.name.clone()).as_deref(), Some("form (conflict).pdf"));
        assert_eq!(app.toast.as_ref().map(|t| t.0.as_str()), Some("after ran"), "what waited for the save runs");
    }

    #[test]
    fn a_refused_save_stays_unsaved_says_why_and_runs_nothing_after() {
        let mut app = app();
        let save = sent(&mut app);
        app.host_saves.answer(HostAnswer::Failed { id: save, error: "the file is locked".into() });
        app.poll_host_saves();
        assert!(dirty(&app));
        assert_eq!(app.toast.as_ref().map(|t| t.0.as_str()), Some("Couldn't save to Nextcloud: the file is locked"));
    }

    #[test]
    fn an_answer_counts_once_and_only_for_its_own_save() {
        let mut app = app();
        let save = sent(&mut app);
        app.host_saves.answer(HostAnswer::Saved { id: "save-99".into(), name: None });
        app.poll_host_saves();
        assert!(dirty(&app), "an unknown id changes nothing");
        app.host_saves.answer(HostAnswer::Saved { id: save.clone(), name: None });
        app.poll_host_saves();
        assert!(!dirty(&app));
        edit(&mut app, "Second");
        app.host_saves.answer(HostAnswer::Saved { id: save, name: None });
        app.poll_host_saves();
        assert!(dirty(&app), "a repeated answer does not save a later edit");
    }

    #[test]
    fn work_done_while_the_host_stores_the_save_stays_unsaved() {
        let mut app = app();
        let save = sent(&mut app);
        edit(&mut app, "Later");
        app.host_saves.answer(HostAnswer::Saved { id: save, name: None });
        app.poll_host_saves();
        assert!(dirty(&app), "the stored file lacks the later edit");
    }
}
