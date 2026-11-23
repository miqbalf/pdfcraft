//! Save As = Export: every Save As and Export entry point makes a copy through one function
//! (`save_as_copy`). The copy downloads on the web, hosted or not, and never goes to the hosting
//! page; on the desktop it is written where the user chooses. The document keeps its file, name
//! and unsaved changes.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use craft_share::export::Runtime;
use egui::{Key, Modifiers};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use pdfcraft_ui_egui::PdfCraftApp;
use pdfcraft_ui_egui::control::ControlClient;
use serde_json::json;

fn fixture(pages: usize) -> Vec<u8> {
    let mut objs: Vec<String> = vec!["<< /Type /Catalog /Pages 2 0 R >>".into()];
    let kids: Vec<String> = (0..pages).map(|i| format!("{} 0 R", 4 + 2 * i)).collect();
    objs.push(format!("<< /Type /Pages /Kids [{}] /Count {pages} /MediaBox [0 0 200 300] >>", kids.join(" ")));
    objs.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into());
    for i in 0..pages {
        objs.push(format!("<< /Type /Page /Parent 2 0 R /Contents {} 0 R /Resources << /Font << /F1 3 0 R >> >> >>", 5 + 2 * i));
        let body = format!("BT /F1 24 Tf 20 150 Td (Page {}) Tj ET", i + 1);
        objs.push(format!("<< /Length {} >>\nstream\n{body}\nendstream", body.len()));
    }
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

fn scratch(name: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("pdfcraft-save-as-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A harness with the control channel, `setup` run on the app before the first frame.
fn harness(setup: impl FnOnce(&mut PdfCraftApp) + 'static) -> (Harness<'static, PdfCraftApp>, ControlClient) {
    let slot: Arc<Mutex<Option<ControlClient>>> = Arc::default();
    let s = slot.clone();
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |cc| {
        let mut app = PdfCraftApp::new();
        app.set_option("language", "en").unwrap();
        *s.lock().unwrap() = Some(app.attach_control(&cc.egui_ctx));
        setup(&mut app);
        app
    });
    h.run_steps(4);
    let client = slot.lock().unwrap().take().unwrap();
    (h, client)
}

/// The document's (path, name, dirty).
fn doc_state(h: &Harness<'static, PdfCraftApp>) -> (Option<String>, String, bool) {
    let s = h.state();
    let d = s.session.get(s.views[0].id).unwrap();
    (d.path.clone(), d.name.clone(), d.dirty)
}

fn toast(h: &Harness<'static, PdfCraftApp>) -> String {
    h.state().toast.as_ref().map(|t| t.0.clone()).unwrap_or_default()
}

/// Run the Save As or Export `command` the way `how` says.
fn run_via(h: &mut Harness<'static, PdfCraftApp>, c: &ControlClient, command: &str, how: &str) {
    match how {
        "menu" => {
            let ctx = h.ctx.clone();
            h.state_mut().run_menu_command(&ctx, &craft_menu::CommandRef::new(command));
        }
        "shortcut" => {
            assert_eq!(command, "file.save_as", "only Save As has a shortcut");
            h.key_press_modifiers(Modifiers::COMMAND | Modifiers::SHIFT, Key::S);
        }
        "palette" => assert!(h.state_mut().execute(command), "command search runs {command}"),
        "control" => {
            let rx = c.send("ui.command", json!({ "id": command }));
            let mut reply = None;
            let answered = crate::support::step_until(h, |_| {
                reply = rx.try_recv().ok();
                reply.is_some()
            });
            assert!(answered && reply.is_some_and(|r| r.is_ok()), "the control channel runs {command}");
        }
        "script" => {
            assert_eq!(command, "file.save_as", "a script's SaveAs is Save As");
            let id = h.state().views[0].id;
            h.state_mut().run_button_script(id, "", "app.execMenuItem('SaveAs');");
        }
        _ => unreachable!(),
    }
}

/// An edited document stored at `dir/orig.pdf`, whose copies go to `out` (the dialog's answer).
fn edited_file(dir: &std::path::Path, out: &std::path::Path) -> (Harness<'static, PdfCraftApp>, ControlClient, Vec<u8>) {
    let orig = dir.join("orig.pdf");
    let bytes = fixture(3);
    std::fs::write(&orig, &bytes).unwrap();
    let (o, d) = (orig.to_string_lossy().into_owned(), out.to_string_lossy().into_owned());
    let (mut h, c) = harness(move |app| {
        app.open_bytes("orig.pdf", Some(o), bytes).unwrap();
        app.pick_override = Some(vec![d]);
    });
    h.state_mut().apply_edit(pdfcraft_engine::Edit::DeletePages { pages: vec![0] });
    h.run_steps(2);
    (h, c, std::fs::read(&orig).unwrap())
}

#[test]
fn every_save_as_entry_point_writes_a_copy_and_keeps_the_document() {
    for how in ["menu", "shortcut", "palette", "control", "script"] {
        let dir = scratch(how);
        let out = dir.join("copy.pdf");
        let (mut h, c, original) = edited_file(&dir, &out);
        let before = doc_state(&h);
        assert!(before.2, "edited");
        run_via(&mut h, &c, "file.save_as", how);
        assert!(crate::support::step_until(&mut h, |_| out.exists()), "{how}: the copy is written");
        h.run_steps(2);
        let copy = std::fs::read(&out).unwrap();
        let mut s = pdfcraft_engine::Session::new();
        let id = s.open("copy.pdf", None, Arc::new(copy), None).expect("the copy opens");
        assert_eq!(s.get(id).unwrap().info.pages.len(), 2, "{how}: the copy has the edit");
        assert_eq!(doc_state(&h), before, "{how}: the document keeps its file, name and unsaved changes");
        assert_eq!(std::fs::read(dir.join("orig.pdf")).unwrap(), original, "{how}: its file is untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn every_export_entry_point_writes_a_copy_named_after_the_document() {
    for (command, ext) in [("export.docx", "docx"), ("export.pptx", "pptx"), ("export.rtf", "rtf"), ("export.html", "html")] {
        for how in ["menu", "palette", "control"] {
            let dir = scratch(ext);
            // The dialog's answer without an extension: the format's is added.
            let (mut h, c, original) = edited_file(&dir, &dir.join("exported"));
            let before = doc_state(&h);
            run_via(&mut h, &c, command, how);
            let out = dir.join(format!("exported.{ext}"));
            assert!(crate::support::step_until(&mut h, |_| out.exists()), "{command} via {how}: written as {}", out.display());
            assert!(!std::fs::read(&out).unwrap().is_empty());
            assert_eq!(doc_state(&h), before, "{command} via {how}: the document is unchanged");
            assert_eq!(std::fs::read(dir.join("orig.pdf")).unwrap(), original);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[test]
fn a_picked_name_without_its_extension_never_replaces_an_existing_file_unasked() {
    let dir = scratch("renamed");
    let taken = dir.join("copy.pdf");
    std::fs::write(&taken, b"keep me").unwrap();
    // The dialog confirmed "copy"; the copy would be "copy.pdf", which exists. It asks again, and
    // the answer (the same name here) still does not overwrite it.
    let (mut h, c, _) = edited_file(&dir, &dir.join("copy"));
    run_via(&mut h, &c, "file.save_as", "palette");
    assert!(crate::support::step_until(&mut h, |h| !toast(h).is_empty()), "it says why nothing was written");
    h.run_steps(4);
    assert_eq!(std::fs::read(&taken).unwrap(), b"keep me", "the existing file is untouched");
    assert!(toast(&h).contains("copy.pdf"), "{}", toast(&h));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The web shell's wiring for a Nextcloud page that stores saves.
fn hosted(app: &mut PdfCraftApp, saves: &Rc<Cell<usize>>) {
    let s = saves.clone();
    app.host_save = Some(Box::new(move |_, _, _, _| {
        s.set(s.get() + 1);
        Ok(())
    }));
    app.host_saves.set_confirms();
}

#[test]
fn on_the_web_save_as_and_export_download_a_copy_and_never_go_to_the_host() {
    for runtime in [Runtime::Web, Runtime::WebHosted] {
        let saves = Rc::new(Cell::new(0));
        let s = saves.clone();
        let (mut h, c) = harness(move |app| {
            app.save_as_runtime = Some(runtime);
            if runtime == Runtime::WebHosted {
                hosted(app, &s);
            }
            app.open_bytes("report.pdf", None, fixture(2)).unwrap();
        });
        h.state_mut().apply_edit(pdfcraft_engine::Edit::RotatePages { pages: vec![0], degrees: 90 });
        h.run_steps(2);
        let before = doc_state(&h);
        for how in ["menu", "shortcut", "palette", "control"] {
            h.state_mut().downloads.clear();
            run_via(&mut h, &c, "file.save_as", how);
            assert!(crate::support::step_until(&mut h, |h| !h.state().downloads.is_empty()), "{runtime:?} {how}: a download");
            let (name, mime, bytes) = h.state().downloads[0].clone();
            assert_eq!((name.as_str(), mime.as_str()), ("report.pdf", "application/pdf"), "{runtime:?} {how}");
            assert!(bytes.starts_with(b"%PDF"));
            // Live or hosted, Save As always yields the copy: no refusal, only the download.
            assert_eq!(toast(&h), "Downloaded report.pdf", "{runtime:?} {how}");
        }
        h.state_mut().downloads.clear();
        run_via(&mut h, &c, "export.docx", "menu");
        h.run_steps(2);
        let (name, mime, _) = h.state().downloads.first().cloned().expect("the export downloads");
        assert_eq!(name, "report.docx");
        assert!(mime.contains("wordprocessingml"), "{mime}");
        assert_eq!(saves.get(), 0, "{runtime:?}: nothing is posted to the host");
        assert_eq!(doc_state(&h), before, "{runtime:?}: still edited, under its own name");
    }
}

#[test]
fn page_images_are_jpeg_named_and_written_as_jpeg() {
    let dir = scratch("jpeg");
    let d = dir.to_string_lossy().into_owned();
    let (mut h, _c) = harness(move |app| {
        app.open_bytes("scan.pdf", None, fixture(2)).unwrap();
        app.export_dir_override = Some(d);
    });
    assert!(h.state_mut().execute("export.image"));
    h.state_mut().export_draft.format = pdfcraft_engine::export::ImageFormat::Jpeg { quality: 80 };
    h.run_steps(2);
    h.get_by_label("Export").click();
    h.run_steps(4);
    let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    for name in names {
        assert!(name.starts_with("scan") && name.ends_with(".jpg"), "{name}");
        assert!(std::fs::read(dir.join(&name)).unwrap().starts_with(&[0xFF, 0xD8]), "{name} holds JPEG bytes");
        assert_eq!(craft_share::export::mime_for_ext("jpg"), "image/jpeg");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
