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

/// Hands a saved PDF to the page embedding PdfCraft (web): `(name, bytes, save_as, id)`. Plain
/// Save only: Save As is a copy that downloads and never comes here. `save_as` is `true` when
/// the Save must make a new file (a redacted document, or one whose saved redactions were undone). `id` is set when the host stores saves and answers each one
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
    queued: Vec<String>,
}

/// What the host page tells the app about sharing, shared between the web shell's listener and the
/// app (a cheap clone): whether it shares files itself (the host's `share`), and the names of the
/// files it handed over to open, which the app ties to the documents they become.
#[derive(Clone, Default)]
pub struct HostShares(std::sync::Arc<std::sync::Mutex<HostSharesState>>);

impl HostShares {
    fn with<R>(&self, f: impl FnOnce(&mut HostSharesState) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// The host said whether it shares files itself (Nextcloud): its latest `share`.
    pub fn set_offered(&self, offered: bool) {
        self.with(|s| s.offered = offered);
    }

    pub fn offered(&self) -> bool {
        self.with(|s| s.offered)
    }

    /// The host queued the file named `name` to open in the frame.
    pub fn queued(&self, name: &str) {
        self.with(|s| s.queued.push(name.to_string()));
    }

    /// Whether `name` is a file the host queued; it is no longer queued afterwards.
    pub(crate) fn take_queued(&self, name: &str) -> bool {
        self.with(|s| match s.queued.iter().position(|q| q == name) {
            Some(at) => {
                s.queued.remove(at);
                true
            }
            None => false,
        })
    }
}

/// What the host page asks of PdfCraft for a Nextcloud signature request (web,
/// `pdfcraft:sign-mode` and `pdfcraft:sign-request-mode`). The web shell checks and bounds each
/// message before it becomes one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignHostEvent {
    /// Sign mode: the document is read-only, `field` (on 0-based `page`) is the signer's,
    /// `others` are the other signers' fields, `banner` is shown above the page, and
    /// `trust_roots` (PEM) are trusted as "this Nextcloud" for this session.
    SignMode { request_id: u64, field: String, page: usize, others: Vec<String>, banner: String, trust_roots: Vec<String> },
    /// Request mode: one box per listed signer, `(position, name)`.
    RequestMode { signers: Vec<(u32, String)> },
}

#[derive(Default)]
struct HostSignState {
    offered: bool,
    events: Vec<SignHostEvent>,
}

/// What the host page tells the app about signature requests, shared between the web shell's
/// listener and the app (a cheap clone): whether it offers them (`sign` in `pdfcraft:host`), and
/// the sign-mode and request-mode messages, which the app reads each frame.
#[derive(Clone, Default)]
pub struct HostSign(std::sync::Arc<std::sync::Mutex<HostSignState>>);

impl HostSign {
    fn with<R>(&self, f: impl FnOnce(&mut HostSignState) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// The host said whether it offers signature requests: its latest `sign`.
    pub fn set_offered(&self, offered: bool) {
        self.with(|s| s.offered = offered);
    }

    pub fn offered(&self) -> bool {
        self.with(|s| s.offered)
    }

    /// A message from the host, for the app's next frame.
    pub fn push(&self, event: SignHostEvent) {
        self.with(|s| s.events.push(event));
    }

    /// The messages that arrived since the last call.
    pub fn take_events(&self) -> Vec<SignHostEvent> {
        self.with(|s| std::mem::take(&mut s.events))
    }
}

/// Posts one app → host message (`pdfcraft:sign-mark`, `-placements` or `-request`), its `type`
/// included, to the same-origin page embedding PdfCraft. Set by the web app when a host page is
/// connected.
pub type HostSignFn = Box<dyn Fn(serde_json::Value) -> Result<(), String>>;
