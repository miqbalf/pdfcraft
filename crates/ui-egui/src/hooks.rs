/// Files delivered asynchronously: (name, bytes).
pub type Inbox = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

/// Files that failed to arrive asynchronously (a browser `?file=` URL that couldn't be fetched):
/// `(name, error)`, reported to the user on the next frame (#173).
pub type FailedInbox = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// A request the operating system sends the running app, outside its window: on macOS, Finder
/// double-clicks, Open With and drops on the Dock icon arrive as Apple events, not arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsEvent {
    /// Open these files.
    Open(Vec<String>),
    /// Add these files to Combine files and show it (`pdfcraft --combine`, File Explorer's
    /// "Combine files in PdfCraft", #585).
    Combine(Vec<String>),
    /// Quit (the Dock's Quit, logging out), asking about unsaved changes first.
    Quit,
}

/// Returns the [`OsEvent`]s that arrived since it was last called (set by the desktop app).
pub type OsEventsFn = Box<dyn FnMut() -> Vec<OsEvent>>;

/// Hands a saved PDF to the page embedding PdfCraft (web): `(name, bytes, save_as, id)`. `save_as`
/// is `true` for Save As. `id` is set when the host stores saves and answers each one
/// ([`HostSaves::confirms`]): it names the save its `saved` or `save-failed` answers. Set by the
/// web app when a host page (such as a Nextcloud app) asked for saves; without it the browser
/// downloads the file.
pub type HostSaveFn = Box<dyn Fn(&str, &[u8], bool, Option<&str>) -> Result<(), String>>;

/// What a host answered to a save that carried an id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAnswer {
    /// Stored; `name` is set when the host kept it under another name (a conflict copy, Save As).
    Saved { id: String, name: Option<String> },
    /// Not stored.
    Failed { id: String, error: String },
}

#[derive(Default)]
struct HostSavesState {
    confirms: bool,
    answers: Vec<HostAnswer>,
}

/// What the host page tells the app about saves, shared between the web shell's listener and the
/// app (a cheap clone): whether it stores saves (the host's `saves`), and its answers, which the
/// app reads each frame.
#[derive(Clone, Default)]
pub struct HostSaves(std::sync::Arc<std::sync::Mutex<HostSavesState>>);

impl HostSaves {
    fn with<R>(&self, f: impl FnOnce(&mut HostSavesState) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// The host said it stores saves and answers each.
    pub fn set_confirms(&self) {
        self.with(|s| s.confirms = true);
    }

    pub fn confirms(&self) -> bool {
        self.with(|s| s.confirms)
    }

    pub fn answer(&self, answer: HostAnswer) {
        self.with(|s| s.answers.push(answer));
    }

    pub(crate) fn take_answers(&self) -> Vec<HostAnswer> {
        self.with(|s| std::mem::take(&mut s.answers))
    }
}

/// Told every frame whether any tab has unsaved work, or an OCR review is not yet accepted or
/// rejected, so a host page can warn before leaving.
pub type HostDirtyFn = Box<dyn FnMut(bool)>;

/// Asks the page embedding PdfCraft to share the file it opened (web, `pdfcraft:share`): the page
/// opens Nextcloud's own sharing for it. Set by the web app when a host page is connected.
pub type HostShareFn = Box<dyn Fn() -> Result<(), String>>;

#[derive(Default)]
struct HostSharesState {
    offered: bool,
    opened: Option<String>,
}

/// What the host page tells the app about sharing, shared between the web shell's listener and the
/// app (a cheap clone): whether it shares files itself (the host's `share`), and the name of the
/// file it opened in the frame, the one file it can share.
#[derive(Clone, Default)]
pub struct HostShares(std::sync::Arc<std::sync::Mutex<HostSharesState>>);

impl HostShares {
    fn with<R>(&self, f: impl FnOnce(&mut HostSharesState) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// The host said it shares files itself (Nextcloud).
    pub fn set_offered(&self) {
        self.with(|s| s.offered = true);
    }

    /// The host opened the file named `name` in the frame.
    pub fn set_opened(&self, name: &str) {
        self.with(|s| s.opened = Some(name.to_string()));
    }

    /// The host shares files and `name` is the file it opened.
    pub fn shares(&self, name: &str) -> bool {
        self.with(|s| s.offered && s.opened.as_deref() == Some(name))
    }
}
