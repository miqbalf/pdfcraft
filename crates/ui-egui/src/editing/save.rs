use super::{PdfCraftApp, StagingName, staging_suffixes};
#[cfg(not(target_arch = "wasm32"))]
use crate::file_filter::AddFilterAnyCase as _;

/// A save held back by [`Dialog::OverwriteChanged`](crate::Dialog::OverwriteChanged): the file
/// on disk is another version than the document came from (#2166).
#[cfg(not(target_arch = "wasm32"))]
pub struct PendingOverwrite {
    pub id: pdfcraft_engine::DocId,
    pub dest: String,
    target: SaveTarget,
    /// What was to run once the document is written (close its tab, quit).
    after: Box<dyn FnOnce(&mut PdfCraftApp) + Send>,
}

/// A save held back by [`Dialog::LockSignatures`](crate::Dialog::LockSignatures) (#2149).
pub struct PendingLock {
    pub id: pdfcraft_engine::DocId,
    target: SaveTarget,
    /// What was to run once the document is written (close its tab, quit).
    after: Box<dyn FnOnce(&mut PdfCraftApp) + Send>,
}

impl PendingLock {
    /// The question is for a Save As copy (its answer locks the copy only).
    pub(crate) fn is_copy(&self) -> bool {
        self.target == SaveTarget::Copy
    }
}

/// Where Save writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveTarget {
    /// The file's own path; asks for one if the document has none (e.g. opened from bytes).
    InPlace,
    /// Always ask for a new location, and make that file the document's (a new document, or one
    /// whose redactions must not go over its file).
    As,
    /// Save As: a PDF copy, downloaded on the web and written where the user chooses on the
    /// desktop. The document keeps its file, name, unsaved changes and saved state
    /// ([`PdfCraftApp::save_as_copy`]).
    Copy,
}

impl PdfCraftApp {
    /// Save the active document. Returns `true` if it was written.
    pub fn save_active(&mut self, target: SaveTarget) -> bool {
        match self.active {
            Some(i) => self.save_view(i, target),
            None => false,
        }
    }

    /// Save the document shown in tab `index`. Returns `true` if it was written now. When it has
    /// to ask where (a new document, or Save As) it returns `false` and saves on a later frame,
    /// once the user has chosen.
    pub fn save_view(&mut self, index: usize, target: SaveTarget) -> bool {
        self.save_then(index, target, |_| {})
    }

    /// [`Self::save_view`], then `after` once the document is written: now, or on a later frame
    /// when the user had to choose where. `after` never runs when the save fails or is cancelled.
    pub(crate) fn save_then(&mut self, index: usize, target: SaveTarget, after: impl FnOnce(&mut Self) + Send + 'static) -> bool {
        // What's typed in a field is part of what's saved (#166).
        if let Some(id) = self.views.get(index).map(|v| v.id)
            && !self.commit_typing_in(id)
        {
            return false;
        }
        let Some(id) = self.views.get(index).map(|v| v.id) else { return false };
        // A signature just placed with Fill & Sign is a removable comment unless it is flattened:
        // ask once whether to lock it into the page (#2149). Only while a Fill & Sign mark is still
        // there (undo may have taken it away), and never on a digitally signed document: locking
        // changes page content in an update, which validators report as a change after signing.
        let still_marked = self.session.get(id).is_some_and(|d| d.info.annotations.iter().any(|a| a.fill_sign));
        let signed = self.session.get(id).is_some_and(|d| d.is_signed());
        let answered = self.lock_answered.take() == Some(id);
        if self.ask_to_lock_signatures
            && !self.flatten_fill_sign_on_save
            && self.placed_signatures.contains(&id)
            && still_marked
            && !signed
            && !answered
        {
            self.pending_lock = Some(PendingLock { id, target, after: Box::new(after) });
            self.dialog = Some(crate::Dialog::LockSignatures);
            return false;
        }
        let Some(doc) = self.session.get(id) else { return false };
        let (name, path) = (doc.name.clone(), doc.path.clone());
        // After Apply redactions, Save asks where and proposes the name with `_Redacted`.
        // In the web build a delivered step stays counted, so only the steps applied since the
        // last delivery make Save ask where.
        let redacted = self.views.get(index).is_some_and(|v| v.redactions_applied > 0);
        let not_delivered = self.views.get(index).is_some_and(|v| v.redactions_applied > v.redactions_downloaded);
        let name = if redacted { pdfcraft_engine::redacted_file_name(&name) } else { name };
        // Undo past a saved Apply redactions brings back content that the file on disk has
        // redacted: ask where instead of writing it over that file. In the web build a delivered
        // step stays counted in `redactions_applied`, so fewer steps than were delivered means one
        // was undone.
        let unredacted = self.views.get(index).is_some_and(restores_saved_redactions);
        // The restored content is not a redacted copy: propose the name without `_Redacted`, so
        // the dialog's default is not the redacted file.
        let name = if unredacted && !redacted { unredacted_file_name(&name) } else { name };
        // A copy leaves the document as it is, so it need not become another file.
        let target = if target != SaveTarget::Copy && (not_delivered || unredacted) { SaveTarget::As } else { target };
        if target == SaveTarget::Copy {
            return self.save_copy(id, &name, path.as_deref(), Box::new(after));
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let doc_path = path.clone();
            let destination = match (target, path, &self.save_override) {
                (_, _, Some(p)) => p.clone(),
                // An email attachment's temporary copy is no place to keep work: ask, as for a new
                // document (`is_mail_temp_copy`).
                // Neither is a path read back from a recovery sidecar until a save confirms it:
                // anyone who can write the recovery folder can name any file there (#3923).
                (SaveTarget::InPlace, Some(p), _) if !is_mail_temp_copy(&p) && !self.recovered_paths.contains(&id) => p,
                _ => {
                    let name = if name.to_ascii_lowercase().ends_with(".pdf") { name } else { format!("{name}.pdf") };
                    let dialog = rfd::AsyncFileDialog::new().add_filter_any_case("PDF", &["pdf"]).set_file_name(name);
                    let dialog = in_document_folder(dialog, doc_path.as_deref());
                    // The bytes are taken once the user has chosen, so edits made meanwhile are saved too.
                    self.ask_one(crate::pickers::Ask::Save(dialog), None, move |app, dest| {
                        // An Apply redactions or an Undo of one while the dialog was open makes the
                        // name it proposed wrong: ask again with the name for the current content.
                        let asked = (redacted, unredacted);
                        let changed = |v: &crate::DocView| v.id == id && (v.redactions_applied > 0, restores_saved_redactions(v)) != asked;
                        if let Some(index) = app.views.iter().position(changed) {
                            app.save_then(index, SaveTarget::As, after);
                            return;
                        }
                        app.save_doc_to_then(id, &dest.to_string_lossy(), target, Box::new(after));
                    });
                    return false;
                }
            };
            self.save_doc_to_then(id, &destination, target, Box::new(after))
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = path;
            if !self.flatten_fill_sign_for_save(id) {
                return false;
            }
            self.run_document_actions(id, pdfcraft_engine::js::DocumentScriptEvent::WillSave);
            let bytes = match self.session.save_bytes(id) {
                Ok(b) => b,
                Err(e) => {
                    self.notify_fmt("Couldn't save {name}: {e}", &[("name", &name), ("e", &e.to_string())]);
                    return false;
                }
            };
            // An embedding page that asked for saves (`?host=parent`) gets the bytes; otherwise
            // the browser downloads them.
            let to_host = self.host_save.is_some();
            // A host that answers each save gets an id; the document counts as saved when it says so.
            let confirmed = to_host && self.host_saves.confirms();
            let save_id = confirmed.then(|| self.next_host_save_id());
            // Plain Save only: a Save As is a copy (`save_copy`) and never reaches the host.
            let delivered = match &self.host_save {
                Some(save) => save(&name, &bytes, matches!(target, SaveTarget::As), save_id.as_deref()),
                None => download(&name, &bytes),
            };
            if let (Ok(()), Some(save_id)) = (&delivered, save_id) {
                self.hold_for_host(save_id, id, bytes, Box::new(after));
                return false;
            }
            match delivered {
                Ok(()) => {
                    // As the native save does: what was saved isn't asked about again (#2149).
                    if self.session.mark_saved(id, bytes, None).is_ok() {
                        self.placed_signatures.remove(&id);
                    }
                    if let Some(doc) = self.session.get(id)
                        && let Some(view) = self.views.get_mut(index)
                    {
                        view.document_changed(&doc.info);
                        // `redactions_applied` stays set: the document keeps its name here, so
                        // later downloads are named after the redacted copy too.
                        view.redactions_downloaded = view.redactions_applied;
                    }
                    // The host reports where the file went (and any failure) itself.
                    if !to_host {
                        self.notify_fmt("Downloaded {name}", &[("name", &name)]);
                    }
                    after(self);
                    true
                }
                Err(e) if to_host => {
                    self.notify_fmt("Couldn't save {name}: {e}", &[("name", &name), ("e", &e)]);
                    false
                }
                Err(e) => {
                    self.notify_fmt("Couldn't download {name}: {e}", &[("name", &name), ("e", &e.to_string())]);
                    false
                }
            }
        }
    }

    /// Save As: deliver a PDF copy of document `id` (named after `name`, stored at `doc_path`)
    /// as [`Self::copy_plan`] says, then `after`. Never touches the document's file, name, dirty
    /// flag or saved state, and never goes to a hosting page.
    fn save_copy(&mut self, id: pdfcraft_engine::DocId, name: &str, doc_path: Option<&str>, after: Box<dyn FnOnce(&mut Self) + Send>) -> bool {
        // Lock the copy's Fill & Sign marks when the preference says so, or when this Save As was
        // answered with Lock.
        let answered = self.copy_lock.take().is_some_and(|(doc, lock)| doc == id && lock);
        let lock = self.flatten_fill_sign_on_save || answered;
        let plan = match self.copy_plan(name, "pdf") {
            Ok(p) => p,
            Err(e) => {
                self.notify_error(e);
                return false;
            }
        };
        match plan.delivery {
            craft_share::export::Delivery::Download => {
                let Some(bytes) = self.copy_bytes(id, lock) else { return false };
                match self.download_copy(&plan.file_name, plan.format.mime, &bytes) {
                    Ok(()) => {
                        self.notify_fmt("Downloaded {name}", &[("name", &plan.file_name)]);
                        after(self);
                        true
                    }
                    Err(e) => {
                        self.notify_fmt("Couldn't download {name}: {e}", &[("name", &plan.file_name), ("e", &e)]);
                        false
                    }
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            craft_share::export::Delivery::SaveDialog => {
                let written = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let w = written.clone();
                // The bytes are taken once the user has chosen, so edits made meanwhile are in the copy.
                self.pick_copy_path(&plan, doc_path, tl!("Save as…"), move |app, dest| {
                    if app.write_copy(id, &dest, lock, after) {
                        w.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                });
                written.load(std::sync::atomic::Ordering::SeqCst)
            }
            #[cfg(target_arch = "wasm32")]
            craft_share::export::Delivery::SaveDialog => {
                let _ = doc_path;
                false
            }
        }
    }

    /// The bytes of a copy of document `id`, ready to deliver. What is typed is committed first
    /// (it is part of the document). The rest happens on a throwaway session opened from the
    /// document's bytes, never on the open document: its WillSave actions run there, and its
    /// Fill & Sign marks are locked there when `lock`. A copy is a clean file without earlier
    /// revisions (#2165) unless the document is signed (its signatures must keep covering it) or
    /// read-only. `None`, having said why, when it cannot be made.
    fn copy_bytes(&mut self, id: pdfcraft_engine::DocId, lock: bool) -> Option<Vec<u8>> {
        if !self.commit_typing_in(id) {
            return None;
        }
        let Some(d) = self.session.get(id) else {
            self.notify_tr("The document was closed before it could be saved.");
            return None;
        };
        let (name, password) = (d.name.clone(), d.password.clone());
        let signed = d.is_signed();
        let full = d.read_only_reason.is_none() && !signed;
        // Locking changes page content in an update, which validators report as a change after
        // signing: never on a digitally signed document, as for a save.
        let lock = lock && !signed && d.info.annotations.iter().any(|a| a.fill_sign);
        let failed =
            |app: &mut Self, e: &dyn std::fmt::Display| app.notify_fmt("Couldn't save {name}: {e}", &[("name", &name), ("e", &e.to_string())]);
        let bytes = match self.session.save_bytes(id).and_then(|b| self.session.check_save(id, &b).map(|()| b)) {
            Ok(b) => b,
            Err(e) => {
                failed(self, &e);
                return None;
            }
        };
        let mut copy = pdfcraft_engine::Session::new();
        copy.set_javascript(self.session.javascript());
        let doc = match copy.open(name.clone(), None, bytes.clone(), password.as_deref()) {
            Ok(doc) => doc,
            // No throwaway to run scripts or lock in: the document's own bytes, unless locking
            // was asked for, which the copy must not silently lack.
            Err(e) if lock => {
                failed(self, &e);
                return None;
            }
            Err(_) => return Some(bytes.to_vec()),
        };
        // A script's alerts and requests have no window here; what it changes is in the copy.
        let _ = copy.run_document_actions(doc, pdfcraft_engine::js::DocumentScriptEvent::WillSave);
        if lock && let Err(e) = copy.apply(doc, pdfcraft_engine::Edit::FlattenFillSign) {
            failed(self, &e);
            return None;
        }
        let out = if full { copy.save_full_bytes(doc) } else { copy.save_bytes(doc) };
        match out {
            Ok(b) => Some(b.to_vec()),
            Err(e) => {
                failed(self, &e);
                None
            }
        }
    }

    /// Write a PDF copy of document `id` to `dest` (Fill & Sign marks locked in it when `lock`),
    /// then `after`. The copy is not the document's file: its path, name, dirty flag and saved
    /// state stay. Save As never writes over the document's own file: that is Save. Returns
    /// `true` if written.
    #[cfg(not(target_arch = "wasm32"))]
    fn write_copy(&mut self, id: pdfcraft_engine::DocId, dest: &str, lock: bool, after: Box<dyn FnOnce(&mut Self) + Send>) -> bool {
        if self.session.get(id).and_then(|d| d.path.as_deref()).is_some_and(|p| crate::same_file(p, dest)) {
            self.notify_tr("Save As makes a copy. To save this file, use Save.");
            return false;
        }
        let Some(bytes) = self.copy_bytes(id, lock) else { return false };
        if let Err(e) = write_atomically(dest, &bytes) {
            self.notify_fmt("Couldn't save {name}: {e}", &[("name", dest), ("e", &e.to_string())]);
            return false;
        }
        self.notify_fmt("Saved {name}", &[("name", &short_name(dest))]);
        after(self);
        true
    }

    /// [`Self::save_doc_to`], then `after`. When `dest` is the document's own file and it is
    /// another version on disk than the one the document came from (something else wrote it
    /// since the open or the last save, #2166), it asks first: the save waits in
    /// `pending_overwrite` behind [`Dialog::OverwriteChanged`](crate::Dialog::OverwriteChanged).
    /// Returns `true` if written now.
    #[cfg(not(target_arch = "wasm32"))]
    fn save_doc_to_then(&mut self, id: pdfcraft_engine::DocId, dest: &str, target: SaveTarget, after: Box<dyn FnOnce(&mut Self) + Send>) -> bool {
        let own = self.session.get(id).and_then(|d| d.path.as_deref()).is_some_and(|p| crate::same_file(p, dest));
        if own && self.watch.disk_differs(id, dest, self.session.get(id).map(|d| d.saved_bytes())) {
            self.pending_overwrite = Some(PendingOverwrite { id, dest: dest.to_string(), target, after });
            self.dialog = Some(crate::Dialog::OverwriteChanged);
            return false;
        }
        let saved = self.save_doc_to(id, dest, target);
        if saved {
            after(self);
        }
        saved
    }

    /// The dialog's Save anyway: write over the changed file.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn overwrite_changed_file(&mut self) {
        let Some(p) = self.pending_overwrite.take() else { return };
        if self.save_doc_to(p.id, &p.dest, p.target) {
            (p.after)(self);
        }
    }

    /// The dialog's Save as…: leave the file on disk as it is and ask where to put this version.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn save_changed_file_elsewhere(&mut self) {
        let Some(p) = self.pending_overwrite.take() else { return };
        if let Some(index) = self.views.iter().position(|v| v.id == p.id) {
            self.save_then(index, SaveTarget::As, p.after);
        }
    }

    /// The Lock signatures dialog answered (#2149): lock the document's Fill & Sign marks into
    /// its pages first when `lock`, then save as was asked. With `remember`, the answer becomes
    /// the preference (flatten on every save, or never ask again). Nothing changes when locking
    /// fails: the document still counts as holding a placed signature, so the next save asks
    /// again, and the answer isn't remembered. The placed-signature mark stays until the save
    /// succeeds, so a save that fails or is cancelled asks again too.
    pub(crate) fn answer_lock_signatures(&mut self, lock: bool, remember: bool) {
        let Some(p) = self.pending_lock.take() else { return };
        // Save As: the answer is for this copy only. The document and the preference stay as
        // they are (`save_copy` locks the marks in the copy's bytes).
        if p.target == SaveTarget::Copy {
            self.lock_answered = Some(p.id);
            self.copy_lock = Some((p.id, lock));
            if let Some(index) = self.views.iter().position(|v| v.id == p.id) {
                self.save_then(index, p.target, p.after);
            }
            // `save_copy` takes the answer. Cancel, error or no window leaves it: drop it here.
            self.copy_lock = None;
            return;
        }
        if lock && !self.flatten_fill_sign_on_save && !self.flatten_fill_sign_in(p.id) {
            return;
        }
        self.lock_answered = Some(p.id);
        if remember {
            if lock {
                self.flatten_fill_sign_on_save = true;
            } else {
                self.ask_to_lock_signatures = false;
            }
        }
        if let Some(index) = self.views.iter().position(|v| v.id == p.id) {
            self.save_then(index, p.target, p.after);
        }
    }

    /// Lock now, on the notice shown after a signature is placed (#2149): lock document `id`'s
    /// Fill & Sign marks into its pages, as the save-time question's Lock does but without
    /// saving. Undoable. The next save doesn't ask, as no Fill & Sign mark is left to lock; the
    /// placed-signature mark itself stays, so undoing the lock brings back both the notice and the
    /// save-time question. Never on a digitally signed document.
    pub(crate) fn lock_signatures_now(&mut self, id: pdfcraft_engine::DocId) {
        if self.session.get(id).is_none_or(|d| d.is_signed()) {
            return;
        }
        if self.flatten_fill_sign_in(id) {
            self.notify_tr("Signature locked into the page.");
        }
    }

    /// Lock document `id`'s Fill & Sign marks into its pages (an undoable edit). Returns false,
    /// having told the user why, when that fails.
    fn flatten_fill_sign_in(&mut self, id: pdfcraft_engine::DocId) -> bool {
        let before = self.session.get(id).map(|d| d.edit_generation());
        if let Err(e) = self.session.apply(id, pdfcraft_engine::Edit::FlattenFillSign) {
            self.notify_error(e);
            return false;
        }
        if before != self.session.get(id).map(|d| d.edit_generation())
            && let Some(doc) = self.session.get(id)
            && let Some(view) = self.views.iter_mut().find(|v| v.id == id)
        {
            view.document_changed(&doc.info);
            // The marks left the comments: a selected one is gone, and its (page, index) could
            // now name another comment.
            view.comments.selected = None;
        }
        true
    }

    /// Write document `id` to `dest` and make it the document's file. Returns `true` if written.
    #[cfg(not(target_arch = "wasm32"))]
    fn save_doc_to(&mut self, id: pdfcraft_engine::DocId, dest: &str, target: SaveTarget) -> bool {
        // Save As answers on a later frame: commit what was typed meanwhile, too (#166), even
        // if another tab is active by then.
        if !self.commit_typing_in(id) || !self.flatten_fill_sign_for_save(id) {
            return false;
        }
        let recovered = self.recovered_paths.contains(&id);
        let Some((name, full)) = self.session.get(id).map(|d| {
            // Save As to another file and a recovered document are clean copies, without earlier
            // revisions that may retain deleted pages or replaced text (#2165, #3923). A signed
            // document stays incremental so its signatures keep covering the file.
            let full = (target == SaveTarget::As || recovered)
                && !d.path.as_deref().is_some_and(|p| crate::same_file(p, dest))
                && d.read_only_reason.is_none()
                && !d.is_signed();
            (d.name.clone(), full)
        }) else {
            self.notify_tr("The document was closed before it could be saved.");
            return false;
        };
        self.run_document_actions(id, pdfcraft_engine::js::DocumentScriptEvent::WillSave);
        let bytes = if full { self.session.save_full_bytes(id) } else { self.session.save_bytes(id) };
        let bytes = match bytes.and_then(|b| self.session.check_save(id, &b).map(|()| b)) {
            Ok(b) => b,
            Err(e) => {
                self.notify_fmt("Couldn't save {name}: {e}", &[("name", &name), ("e", &e.to_string())]);
                return false;
            }
        };
        if let Err(e) = write_atomically(dest, &bytes) {
            self.notify_fmt("Couldn't save {name}: {e}", &[("name", dest), ("e", &e.to_string())]);
            return false;
        }
        // Our own write is not a change on disk to reload (#431).
        self.watch.known_now(id, dest);
        match self.session.mark_saved(id, bytes, Some(dest.to_string())) {
            Ok(()) => {
                self.forget_recovery(id);
                self.placed_signatures.remove(&id);
                // The tab in use: `sync_views` brings any other tab of the document up to date.
                if let Some(doc) = self.session.get(id)
                    && let Some(view) = self.asking_tab(id).and_then(|i| self.views.get_mut(i))
                {
                    view.document_changed(&doc.info);
                }
                // Saving over a version that changed on disk keeps this one: nothing to ask.
                for view in self.views.iter_mut().filter(|v| v.id == id) {
                    view.disk_changed = false;
                    view.redactions_applied = 0;
                    view.redactions_undone_after_save = 0;
                    view.saved_redactions_cut_off = false;
                }
                self.notify_fmt("Saved {name}", &[("name", &short_name(dest))]);
                #[cfg(target_os = "macos")]
                crate::macos_association::repair(std::path::Path::new(dest));
                true
            }
            Err(e) => {
                self.notify_fmt("Saved, but reopening failed: {e}", &[("e", &e.to_string())]);
                false
            }
        }
    }
}

/// Whether `path` is the temporary copy an email client opened an attachment from, so that Save
/// asks where to keep the document instead of writing to it.
///
/// Outlook opens an attachment from its own cache: `INetCache\Content.Outlook\<random>\` for
/// classic Outlook (`Temporary Internet Files\Content.Outlook\` on older Windows), and the
/// `Packages\Microsoft.OutlookForWindows_<id>` package folder for the new Outlook. The patterns
/// follow those layouts, so an ordinary folder that merely shares a name doesn't match. Saving there either fails,
/// because Outlook can still hold the file, or appears to work while the edits stay out of the
/// email and are deleted with the cache. Apple Mail opens one from `Mail Downloads/<UUID>/` in
/// its sandbox container, where other apps can't write, so saving there fails (#2751). Matched on
/// either separator and in any case, so it can be tested on every platform.
pub(crate) fn is_mail_temp_copy(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    // Outlook's cache holds `<marker><random folder>/<file>`: exactly one folder, then the file.
    let in_outlook_cache = |marker: &str| {
        p.split_once(marker)
            .is_some_and(|(_, rest)| matches!(rest.split('/').collect::<Vec<_>>()[..], [dir, file] if !dir.is_empty() && !file.is_empty()))
    };
    in_outlook_cache("/inetcache/content.outlook/")
        || in_outlook_cache("/temporary internet files/content.outlook/")
        || p.contains("/packages/microsoft.outlookforwindows_")
        || p.contains("/library/containers/com.apple.mail/data/library/mail downloads/")
}

/// Whether `view` holds content that a saved or delivered Apply redactions removed: a saved step
/// is undone, cannot be redone, or (in the web build) fewer steps are in effect than were
/// delivered.
fn restores_saved_redactions(view: &crate::DocView) -> bool {
    view.redactions_undone_after_save > 0 || view.saved_redactions_cut_off || view.redactions_applied < view.redactions_downloaded
}

/// `name` without the `_Redacted` that [`pdfcraft_engine::redacted_file_name`] adds before the
/// extension ("contract_Redacted.pdf" gives "contract.pdf"). Any other name is returned as it is.
pub(crate) fn unredacted_file_name(name: &str) -> String {
    let cut = name.len().saturating_sub(4);
    let (stem, ext) = match (name.get(..cut), name.get(cut..)) {
        (Some(stem), Some(ext)) if ext.eq_ignore_ascii_case(".pdf") => (stem, ext),
        _ => (name, ""),
    };
    match stem.strip_suffix("_Redacted") {
        Some(base) if !base.is_empty() => format!("{base}{ext}"),
        _ => name.to_string(),
    }
}

/// The folder a Save As style dialog should open in for a document stored at `path`: the
/// document's own folder, as Acrobat and Foxit do, instead of whichever folder the system picks.
/// `None` (keep the system's choice) for a new document, a path with no parent, or an email
/// attachment's temporary copy (`is_mail_temp_copy`), which is no place to keep work. Also right
/// for UNC paths on Windows (`\\server\share\dir\f.pdf` gives `\\server\share\dir`).
pub(crate) fn save_dialog_folder(path: Option<&str>) -> Option<std::path::PathBuf> {
    let path = path.filter(|p| !is_mail_temp_copy(p))?;
    let parent = std::path::Path::new(path).parent()?;
    (!parent.as_os_str().is_empty()).then(|| parent.to_path_buf())
}

/// `dialog` opened in the folder of the document stored at `path` ([`save_dialog_folder`]).
pub(crate) fn in_document_folder(dialog: rfd::AsyncFileDialog, path: Option<&str>) -> rfd::AsyncFileDialog {
    match save_dialog_folder(path) {
        Some(dir) => dialog.set_directory(dir),
        None => dialog,
    }
}

/// Write via a temporary file in the same directory and rename over the target, so a crash or
/// full disk never leaves a half-written PDF where the original was.
pub fn write_atomically(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    write_atomically_with(path, bytes, staging_suffixes())
}

/// [`write_atomically`], trying the staging names that `suffixes` give.
pub(super) fn write_atomically_with(path: &str, bytes: &[u8], suffixes: impl IntoIterator<Item = u64>) -> std::io::Result<()> {
    write_atomically_syncing(path, bytes, suffixes, std::fs::File::sync_all)
}

/// [`write_atomically_with`], flushing the staging file with `sync_all` (the standard library's
/// in the app, a failing one in tests). The writer itself is the platform crate's, shared with
/// the tools and the CLI (#2166); the desktop app keeps its staging-name form.
pub(super) fn write_atomically_syncing(
    path: &str,
    bytes: &[u8],
    suffixes: impl IntoIterator<Item = u64>,
    sync_all: impl FnOnce(&std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    pdfcraft_platform::staging::write_atomically_with(std::path::Path::new(path), bytes, StagingName::TagThenSuffix, suffixes, sync_all)
}

#[cfg(not(target_arch = "wasm32"))]
fn short_name(path: &str) -> String {
    std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string())
}

/// The MIME type a download of `name` is offered as, from its extension.
#[doc(hidden)]
pub fn download_mime_type(name: &str) -> &'static str {
    let ext = std::path::Path::new(name).extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "tif" | "tiff" => "image/tiff",
        "svg" => "image/svg+xml",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "json" => "application/json",
        "xfdf" => "application/vnd.adobe.xfdf",
        "fdf" => "application/vnd.fdf",
        "rtf" => "application/rtf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
}

/// Offer bytes as a browser download: the shared download every web copy goes through
/// (`craft_web_host::web::download`), typed by the name's extension.
#[cfg(target_arch = "wasm32")]
pub(crate) fn download(name: &str, bytes: &[u8]) -> Result<(), String> {
    craft_web_host::web::download(name, download_mime_type(name), bytes)
}
