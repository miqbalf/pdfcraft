//! Share (`file.share`) opens Nextcloud's own sharing for the open file and does nothing else:
//! the hosting Nextcloud page on the web, the file's Nextcloud in the browser on the desktop, and
//! "No Nextcloud connected" anywhere else. Every entry point runs the same command.

use std::cell::Cell;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use craft_share::ShareRoute;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use pdfcraft_ui_egui::PdfCraftApp;
use pdfcraft_ui_egui::control::ControlClient;
use serde_json::json;

const NO_NEXTCLOUD: &str = "No Nextcloud connected";

fn fixture() -> Vec<u8> {
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 300] >>".to_string(),
        "<< /Type /Page /Parent 2 0 R >>".to_string(),
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

/// A fake Nextcloud desktop client config: files under `/synced/` are in a synced folder.
fn synced_lookup(path: &Path) -> ShareRoute {
    match path.strip_prefix("/synced") {
        Ok(rest) => ShareRoute::NextcloudDesktop {
            server: "https://cloud.example.test".into(),
            user: "alice".into(),
            remote_path: format!("/{}", rest.to_string_lossy()),
        },
        Err(_) => ShareRoute::None,
    }
}

/// What a Share left behind: the host page asked, a URL opened, a save or download made.
#[derive(Clone, Default)]
struct Probe {
    host_shares: Rc<Cell<usize>>,
    host_saves: Rc<Cell<usize>>,
}

impl Probe {
    /// The web shell's wiring for a Nextcloud page that shares files.
    fn connect(&self, app: &mut PdfCraftApp, share: bool) {
        let shares = self.host_shares.clone();
        app.host_share = Some(Box::new(move || {
            shares.set(shares.get() + 1);
            Ok(())
        }));
        let saves = self.host_saves.clone();
        app.host_save = Some(Box::new(move |_, _, _, _| {
            saves.set(saves.get() + 1);
            Ok(())
        }));
        app.host_shares.set_offered(share);
    }

    /// A page that shares files, and the host's `open` of `name` (queued as the web shell does).
    fn host(&self, app: &mut PdfCraftApp, name: &str) {
        self.connect(app, true);
        host_open(app, name);
    }
}

/// The host's `open`: the web shell queues the bytes in the startup inbox and tells the app the name.
fn host_open(app: &mut PdfCraftApp, name: &str) {
    app.host_shares.queued(name);
    app.startup_inbox.lock().unwrap().push((name.to_string(), fixture()));
}

fn harness(setup: impl FnOnce(&mut PdfCraftApp) + 'static) -> (Harness<'static, PdfCraftApp>, ControlClient) {
    let slot: Arc<Mutex<Option<ControlClient>>> = Arc::default();
    let s = slot.clone();
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |cc| {
        let mut app = PdfCraftApp::new();
        app.set_option("language", "en").unwrap();
        *s.lock().unwrap() = Some(app.attach_control(&cc.egui_ctx));
        app.share_lookup = synced_lookup;
        setup(&mut app);
        app
    });
    h.run_steps(4);
    let client = slot.lock().unwrap().take().unwrap();
    (h, client)
}

fn toast(h: &Harness<'static, PdfCraftApp>) -> Option<String> {
    h.state().toast.as_ref().map(|t| t.0.clone())
}

/// Every way in: the toolbar button, the File menu, command search, the control channel.
fn entry_points() -> [&'static str; 4] {
    ["button", "menu", "palette", "control"]
}

fn share_via(h: &mut Harness<'static, PdfCraftApp>, c: &ControlClient, how: &str) {
    match how {
        "button" => {
            h.get_by_label("Share").click();
            h.run_steps(2);
        }
        "menu" => {
            let ctx = h.ctx.clone();
            h.state_mut().run_menu_command(&ctx, &craft_menu::CommandRef::new("file.share"));
            h.run_steps(2);
        }
        "palette" => {
            h.state_mut().set_option("palette", "share").unwrap();
            h.run_steps(3);
            assert!(h.query_all_by_label("Share").count() >= 2, "command search lists Share beside the button");
            h.key_press(egui::Key::Enter);
            h.run_steps(3);
        }
        "control" => {
            let rx = c.send("ui.command", json!({"id": "file.share"}));
            let mut reply = None;
            let answered = crate::support::step_until(h, |_| {
                reply = rx.try_recv().ok();
                reply.is_some()
            });
            assert!(answered && reply.is_some_and(|r| r.is_ok()), "the control channel runs file.share");
        }
        _ => unreachable!(),
    }
}

#[test]
fn every_entry_point_asks_the_hosting_page_to_share() {
    for how in entry_points() {
        let probe = Probe::default();
        let p = probe.clone();
        let (mut h, c) = harness(move |app| p.host(app, "report.pdf"));
        assert_eq!(h.state().views.len(), 1, "the host's file opened");
        share_via(&mut h, &c, how);
        assert_eq!(probe.host_shares.get(), 1, "{how}: the page is asked to share once");
        assert_eq!(probe.host_saves.get(), 0, "{how}: nothing is saved or exported");
        assert_eq!(h.state().last_opened_url, None, "{how}: no browser tab");
        assert_ne!(toast(&h).as_deref(), Some(NO_NEXTCLOUD), "{how}");
    }
}

#[test]
fn every_entry_point_opens_sharing_for_a_synced_desktop_file() {
    let expected = craft_share::sharing_url("https://cloud.example.test", "/Reports/q3.pdf");
    for how in entry_points() {
        let (mut h, c) = harness(|app| app.open_bytes("q3.pdf", Some("/synced/Reports/q3.pdf".into()), fixture()).unwrap());
        share_via(&mut h, &c, how);
        assert_eq!(h.state().last_opened_url.as_deref(), Some(expected.as_str()), "{how}: the file's sharing opens in the browser");
        assert!(h.state().dialog.is_none(), "{how}: no dialog of ours");
    }
}

#[test]
fn every_entry_point_says_no_nextcloud_for_an_unsynced_file() {
    for how in entry_points() {
        let (mut h, c) = harness(|app| app.open_bytes("local.pdf", Some("/home/alice/local.pdf".into()), fixture()).unwrap());
        share_via(&mut h, &c, how);
        assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD), "{how}");
        assert_eq!(h.state().last_opened_url, None, "{how}: no browser tab");
        assert!(h.state().dialog.is_none(), "{how}: no export or save dialog");
    }
}

/// The plain web build: no hosting page, no file path.
#[test]
fn without_nextcloud_share_only_says_so_and_exports_nothing() {
    let dir = std::env::temp_dir().join(format!("pdfcraft-share-none-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out.pdf");
    let o = out.clone();
    let (mut h, c) = harness(move |app| {
        app.save_override = Some(o.to_string_lossy().into_owned());
        app.pick_override = Some(Vec::new());
        app.open_bytes("web.pdf", None, fixture()).unwrap();
    });
    let before = h.state().session.get(h.state().views[0].id).unwrap().saved_bytes().to_vec();
    share_via(&mut h, &c, "control");
    assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD));
    assert!(!out.exists(), "nothing is written");
    assert!(h.state().dialog.is_none() && h.state().last_opened_url.is_none());
    let doc = h.state().session.get(h.state().views[0].id).unwrap();
    assert_eq!(doc.saved_bytes().as_slice(), before.as_slice(), "the document is not saved");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn with_no_document_share_says_no_nextcloud() {
    let (mut h, c) = harness(|_| {});
    share_via(&mut h, &c, "control");
    assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD));
}

/// The page shares the one file it opened: another document in the frame is not that file.
#[test]
fn the_hosting_page_shares_only_the_file_it_opened() {
    let probe = Probe::default();
    let p = probe.clone();
    let (mut h, c) = harness(move |app| p.host(app, "report.pdf"));
    h.state_mut().open_bytes("other.pdf", None, fixture()).unwrap();
    h.run_steps(2);
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 0, "the page is not asked to share another file");
    assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD));
    // Back on the file the page opened, Share asks the page.
    h.state_mut().active = Some(0);
    h.run_steps(2);
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 1);
}

/// A local file with the same name as the host's is still another document.
#[test]
fn a_local_file_of_the_same_name_is_not_the_hosts() {
    let probe = Probe::default();
    let p = probe.clone();
    let (mut h, c) = harness(move |app| p.host(app, "report.pdf"));
    h.state_mut().open_bytes("report.pdf", None, fixture()).unwrap();
    h.run_steps(2);
    assert_eq!(h.state().views.len(), 2);
    assert_eq!(h.state().active, Some(1), "the local copy is in front");
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 0, "the page is not asked to share the local copy");
    assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD));
    h.state_mut().active = Some(0);
    h.run_steps(2);
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 1, "the host's own document still shares");
}

/// The host stores a save under another name (Save As, a conflict copy): still the host's file.
#[test]
fn the_hosts_document_keeps_share_after_a_rename() {
    let probe = Probe::default();
    let p = probe.clone();
    let (mut h, c) = harness(move |app| p.host(app, "report.pdf"));
    let id = h.state().views[0].id;
    let bytes = h.state().session.get(id).unwrap().saved_bytes();
    h.state_mut().session.mark_saved(id, bytes, Some("report (copy).pdf".into())).unwrap();
    h.run_steps(2);
    assert_ne!(h.state().session.get(id).unwrap().name, "report.pdf", "the document was renamed");
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 1);
}

/// A second file from the host while the first is open does not take Share over silently.
#[test]
fn a_second_host_file_does_not_take_share_over() {
    let probe = Probe::default();
    let p = probe.clone();
    let (mut h, c) = harness(move |app| p.host(app, "first.pdf"));
    host_open(h.state_mut(), "second.pdf");
    h.run_steps(3);
    assert_eq!(h.state().views.len(), 2, "the second file opens");
    let said = toast(&h).unwrap_or_default();
    assert!(said.contains("first.pdf"), "the user is told which file Share is for: {said}");
    h.state_mut().active = Some(1);
    h.run_steps(2);
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 0, "the second file is not shared");
    h.state_mut().active = Some(0);
    h.run_steps(2);
    share_via(&mut h, &c, "control");
    assert_eq!(probe.host_shares.get(), 1, "the first still is");
}

/// The page could not be asked: the user is told, and nothing else happens.
#[test]
fn a_failed_host_request_is_reported() {
    let (mut h, c) = harness(|app| {
        Probe::default().host(app, "report.pdf");
        app.host_share = Some(Box::new(|| Err("the page is gone".into())));
    });
    share_via(&mut h, &c, "control");
    let said = toast(&h).unwrap_or_default();
    assert!(said.contains("the page is gone") && said != NO_NEXTCLOUD, "{said}");
    assert_eq!(h.state().last_opened_url, None);
}

/// A page that does not share files (it never said `share: true`, or took it back) gets no request.
#[test]
fn a_page_that_does_not_share_gets_nothing() {
    for share in [false, true] {
        let probe = Probe::default();
        let p = probe.clone();
        let (mut h, c) = harness(move |app| p.host(app, "report.pdf"));
        // `share: false` from the start, or `share: true` then `share: false`.
        h.state().host_shares.set_offered(share);
        h.state().host_shares.set_offered(false);
        share_via(&mut h, &c, "control");
        assert_eq!(probe.host_shares.get(), 0);
        assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD));
    }
}

/// Save As to a path in a synced folder: Share follows the document's new file.
#[test]
fn share_follows_a_save_to_another_path() {
    let (mut h, c) = harness(|app| app.open_bytes("local.pdf", Some("/home/alice/local.pdf".into()), fixture()).unwrap());
    share_via(&mut h, &c, "control");
    assert_eq!(toast(&h).as_deref(), Some(NO_NEXTCLOUD));
    let id = h.state().views[0].id;
    let bytes = h.state().session.get(id).unwrap().saved_bytes();
    h.state_mut().session.mark_saved(id, bytes, Some("/synced/Moved/local.pdf".into())).unwrap();
    h.run_steps(2);
    share_via(&mut h, &c, "control");
    let expected = craft_share::sharing_url("https://cloud.example.test", "/Moved/local.pdf");
    assert_eq!(h.state().last_opened_url.as_deref(), Some(expected.as_str()));
}

/// The app's own default reads no Nextcloud config: only the desktop app sets the real lookup.
#[test]
fn without_the_desktop_lookup_no_file_is_synced() {
    let mut app = PdfCraftApp::new();
    app.set_option("language", "en").unwrap();
    app.open_bytes("q3.pdf", Some("/synced/Reports/q3.pdf".into()), fixture()).unwrap();
    app.execute("file.share");
    assert_eq!(app.toast.as_ref().map(|t| t.0.as_str()), Some(NO_NEXTCLOUD));
    assert_eq!(app.last_opened_url, None);
}

static LOOKUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn counted_lookup(path: &Path) -> ShareRoute {
    LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    synced_lookup(path)
}

/// The desktop client's config is read when a document is opened or switched to, not every frame.
#[test]
fn the_desktop_lookup_runs_on_open_and_switch_not_every_frame() {
    use std::sync::atomic::Ordering::SeqCst;
    let (mut h, c) = harness(|app| {
        app.share_lookup = counted_lookup;
        app.open_bytes("a.pdf", Some("/synced/a.pdf".into()), fixture()).unwrap();
        app.open_bytes("b.pdf", Some("/synced/b.pdf".into()), fixture()).unwrap();
    });
    let after_open = LOOKUPS.load(SeqCst);
    assert!(after_open >= 1, "the shown document was looked up");
    h.run_steps(10);
    assert_eq!(LOOKUPS.load(SeqCst), after_open, "frames alone ask nothing");
    share_via(&mut h, &c, "control");
    share_via(&mut h, &c, "control");
    assert_eq!(LOOKUPS.load(SeqCst), after_open, "Share uses the known answer");
    h.state_mut().active = Some(0);
    h.run_steps(3);
    assert_eq!(LOOKUPS.load(SeqCst), after_open + 1, "switching to the other document asks once");
    let expected = craft_share::sharing_url("https://cloud.example.test", "/a.pdf");
    share_via(&mut h, &c, "control");
    assert_eq!(h.state().last_opened_url.as_deref(), Some(expected.as_str()));
}
