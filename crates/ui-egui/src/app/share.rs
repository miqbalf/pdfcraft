//! Share (`file.share`): Nextcloud's own sharing for the open file, and nothing else. Where it goes
//! is `craft-share`'s [`ShareRoute`], shared by the Craft apps; it never exports, mails or opens a
//! dialog of ours. The toolbar button, the File menu, command search and the control channel all
//! run `file.share`, which ends in [`PdfCraftApp::share_active`].

use craft_share::{ShareAction, ShareRoute};

use super::*;

impl PdfCraftApp {
    /// Where Share goes for the active document.
    ///
    /// - Web, framed by a page that shares files itself ([`Self::host_share`], the Nextcloud app)
    ///   and showing the file that page opened: the page.
    /// - Desktop, a file in a folder the Nextcloud desktop client syncs: that file on its server.
    /// - Anything else (no document, a plain web build, a document the page did not open, a file
    ///   outside every synced folder): [`ShareRoute::None`].
    pub fn share_route(&self) -> ShareRoute {
        let Some((_, id)) = self.active_ids() else { return ShareRoute::None };
        if self.host_share.is_some() && self.host_shares.offered() && self.host_doc == Some(id) {
            return ShareRoute::NextcloudWebHost;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(path) = self.session.get(id).and_then(|d| d.path.as_deref())
            && let Some((asked, route)) = self.desktop_shares.get(&id)
            && asked == path
        {
            return route.clone();
        }
        ShareRoute::None
    }

    /// A document named `name` was just added as `id`: when it is a file the host handed over, it
    /// becomes the host's document. Only one document is: while the first is open, a later host
    /// file opens without Share, and the user is told.
    pub(crate) fn host_opened(&mut self, name: &str, id: DocId) {
        let Some(at) = self.host_opening.iter().position(|n| n == name) else { return };
        self.host_opening.remove(at);
        let first_open = self.host_doc.filter(|doc| self.views.iter().any(|v| v.id == *doc));
        match first_open {
            Some(first) if first != id => {
                let first = self.session.get(first).map(|d| d.name.clone()).unwrap_or_default();
                self.notify_fmt("Share works only for {name}, the first file opened from Nextcloud", &[("name", &first)]);
            }
            _ => self.host_doc = Some(id),
        }
    }

    /// The host's file named `name` was handed to the opener. Unless it waits for its password,
    /// it is either a document now or was refused: either way no later document takes its place.
    pub(crate) fn host_open_settled(&mut self, name: &str) {
        if self.password_prompt.as_ref().is_some_and(|p| p.name == name) {
            return;
        }
        if let Some(at) = self.host_opening.iter().position(|n| n == name) {
            self.host_opening.remove(at);
        }
    }

    /// Ask [`Self::share_lookup`] where the active document's file is shared, when it is a
    /// document or a path it has not been asked about (opened, saved under another path, switched
    /// to). Each frame runs this; it reads the Nextcloud client's config only on such a change.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn refresh_share_route(&mut self) {
        let Some((_, id)) = self.active_ids() else { return };
        let Some(path) = self.session.get(id).and_then(|d| d.path.as_deref()) else { return };
        if self.desktop_shares.get(&id).is_some_and(|(asked, _)| asked == path) {
            return;
        }
        let path = path.to_string();
        let route = (self.share_lookup)(std::path::Path::new(&path));
        self.desktop_shares.insert(id, (path, route));
    }

    /// Share the active document: the one function every Share entry point runs.
    pub fn share_active(&mut self) {
        // A command run with no frame in between (the control channel, tests) still sees the
        // current document.
        #[cfg(not(target_arch = "wasm32"))]
        self.refresh_share_route();
        match self.share_route().action() {
            ShareAction::PostToHost => {
                if let Some(Err(e)) = self.host_share.as_ref().map(|share| share()) {
                    self.notify_fmt("Couldn't share: {e}", &[("e", &e)]);
                }
            }
            ShareAction::OpenUrl(url) => self.open_url(&url),
            ShareAction::Notice(_) => self.notify(no_nextcloud()),
        }
    }
}

/// [`craft_share::NO_NEXTCLOUD`] in the interface language (the literal keeps it in the catalogs'
/// string scan; a test checks it is the crate's text).
pub(crate) fn no_nextcloud() -> String {
    tl!("No Nextcloud connected").to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_message_is_the_shared_one() {
        crate::i18n::set_current(crate::i18n::Lang::EN);
        assert_eq!(super::no_nextcloud(), craft_share::NO_NEXTCLOUD);
    }
}
