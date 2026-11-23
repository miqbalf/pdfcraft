//! The Nextcloud signature-request messages (`pdfcraft:sign-*`), on a `message` listener of their
//! own: `craft-web-host`'s message list is closed (plan Ruling R9). Only the same-origin parent
//! is heard and answered, as `craft-web-host`'s Parent transport does.
//!
//! - Host → app: `pdfcraft:sign-mode { requestId, field, page, others, banner, trustRoots }` and
//!   `pdfcraft:sign-request-mode { signers: [{ position, name }] }`, and `sign` read from the raw
//!   `pdfcraft:host` (`craft_web_host::Message::Host` has no such field).
//! - App → host: `pdfcraft:sign-mark`, `pdfcraft:sign-placements` and `pdfcraft:sign-request`,
//!   posted by the app through [`pdfcraft_ui_egui::HostSignFn`].
//!
//! The parsing below is wasm-free, so it is tested natively. Every message is untrusted: each
//! field is checked and bounded, and a message with a missing or malformed field is dropped.

use pdfcraft_ui_egui::SignHostEvent;
use serde_json::Value;

/// The host's message types this listener reads.
pub const HEARD: [&str; 3] = ["pdfcraft:host", "pdfcraft:sign-mode", "pdfcraft:sign-request-mode"];

/// The app's message types it posts.
pub const POSTED: [&str; 3] = ["pdfcraft:sign-mark", "pdfcraft:sign-placements", "pdfcraft:sign-request"];

/// Field names and signer names: at most this many characters.
const MAX_NAME: usize = 255;
/// The banner: at most this many characters.
const MAX_BANNER: usize = 1_000;
/// At most this many other signers' fields, or signers.
const MAX_SIGNERS: usize = 64;
/// At most this many trust roots, each at most this many bytes of PEM.
const MAX_ROOTS: usize = 8;
const MAX_ROOT_PEM: usize = 16 * 1024;
/// The highest page index accepted.
const MAX_PAGE: u64 = 100_000;

/// What a heard message says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Heard {
    /// `pdfcraft:host`: whether the host offers signature requests.
    Offered(bool),
    Event(SignHostEvent),
}

/// Whether a `message` event is from the framing parent on this origin.
pub fn accepts(event_origin: &str, own_origin: &str, from_parent: bool) -> bool {
    from_parent && !own_origin.is_empty() && event_origin == own_origin
}

/// The message `data` of type `kind` means, or `None` for another type or a malformed message.
pub fn read(kind: &str, data: &Value) -> Option<Heard> {
    match kind {
        // `host_flag`: only a real `true` offers.
        "pdfcraft:host" => Some(Heard::Offered(data.get("sign").and_then(Value::as_bool) == Some(true))),
        "pdfcraft:sign-mode" => {
            let request_id = data.get("requestId")?.as_u64()?;
            let field = name(data.get("field")?)?;
            let page = data.get("page")?.as_u64().filter(|p| *p <= MAX_PAGE)?;
            let others = match data.get("others") {
                None | Some(Value::Null) => Vec::new(),
                Some(list) => list.as_array().filter(|l| l.len() <= MAX_SIGNERS)?.iter().map(name).collect::<Option<Vec<_>>>()?,
            };
            let banner = data.get("banner").and_then(Value::as_str).map(clean)?;
            if banner.chars().count() > MAX_BANNER {
                return None;
            }
            let trust_roots = match data.get("trustRoots") {
                None | Some(Value::Null) => Vec::new(),
                Some(list) => list
                    .as_array()
                    .filter(|l| l.len() <= MAX_ROOTS)?
                    .iter()
                    .map(|r| r.as_str().filter(|s| s.len() <= MAX_ROOT_PEM).map(str::to_string))
                    .collect::<Option<Vec<_>>>()?,
            };
            Some(Heard::Event(SignHostEvent::SignMode { request_id, field, page: usize::try_from(page).ok()?, others, banner, trust_roots }))
        }
        "pdfcraft:sign-request-mode" => {
            let list = data.get("signers")?.as_array().filter(|l| !l.is_empty() && l.len() <= MAX_SIGNERS)?;
            let mut signers = Vec::with_capacity(list.len());
            for s in list {
                let position = u32::try_from(s.get("position")?.as_u64()?).ok()?;
                if signers.iter().any(|(p, _)| *p == position) {
                    return None;
                }
                signers.push((position, name(s.get("name")?)?));
            }
            Some(Heard::Event(SignHostEvent::RequestMode { signers }))
        }
        _ => None,
    }
}

/// A field or signer name: a non-blank string of at most [`MAX_NAME`] characters.
fn name(v: &Value) -> Option<String> {
    let s = clean(v.as_str()?);
    (!s.is_empty() && s.chars().count() <= MAX_NAME).then_some(s)
}

/// Text without control characters, trimmed.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string()
}

/// Whether the app may post `message`: one of [`POSTED`], by its `type`.
pub fn may_post(message: &Value) -> bool {
    message.get("type").and_then(Value::as_str).is_some_and(|t| POSTED.contains(&t))
}

#[cfg(target_arch = "wasm32")]
pub use web::SignHost;

#[cfg(target_arch = "wasm32")]
mod web {
    use eframe::wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use pdfcraft_ui_egui::{HostSign, HostSignFn};

    use super::{HEARD, Heard, accepts, may_post, read};

    /// The listener and poster for the same-origin parent.
    pub struct SignHost {
        window: web_sys::Window,
        parent: web_sys::Window,
        origin: String,
    }

    impl SignHost {
        /// `None` unless the page is `?host=parent` in a frame whose parent is on this origin.
        pub fn connect() -> Option<Self> {
            let window = web_sys::window()?;
            let search = window.location().search().ok()?;
            if web_sys::UrlSearchParams::new_with_str(&search).ok()?.get("host").as_deref() != Some("parent") {
                return None;
            }
            let parent = window.parent().ok().flatten()?;
            if js_sys::Object::is(&parent, &window) {
                return None;
            }
            let origin = window.location().origin().ok()?;
            // Reading another origin's location throws, which is `None` too.
            if parent.location().origin().ok()? != origin {
                return None;
            }
            Some(Self { window, parent, origin })
        }

        /// Hear the host's messages into `sign` and wake the app.
        pub fn listen(&self, sign: HostSign, ctx: egui::Context) {
            let (parent, origin) = (self.parent.clone(), self.origin.clone());
            let on_message = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
                let from_parent = event.source().is_some_and(|s| js_sys::Object::is(&s, &parent));
                if !accepts(&event.origin(), &origin, from_parent) {
                    return;
                }
                let data = event.data();
                // Only our types are read further: another message may hold a whole file.
                let Some(kind) = js_sys::Reflect::get(&data, &JsValue::from_str("type")).ok().and_then(|t| t.as_string()) else { return };
                if !HEARD.contains(&kind.as_str()) {
                    return;
                }
                let Some(json) = js_sys::JSON::stringify(&data).ok().and_then(|s| s.as_string()) else { return };
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else { return };
                match read(&kind, &value) {
                    Some(Heard::Offered(offered)) => sign.set_offered(offered),
                    Some(Heard::Event(e)) => sign.push(e),
                    None => {
                        web_sys::console::warn_1(&format!("PdfCraft: {kind} was not understood; ignored").into());
                        return;
                    }
                }
                ctx.request_repaint();
            });
            if self.window.add_event_listener_with_callback("message", on_message.as_ref().unchecked_ref()).is_ok() {
                on_message.forget();
            }
        }

        /// Posts one app → host message to the parent, on this origin only.
        pub fn post_fn(&self) -> HostSignFn {
            let (parent, origin) = (self.parent.clone(), self.origin.clone());
            Box::new(move |message: serde_json::Value| {
                if !may_post(&message) {
                    return Err("not a signature request message".into());
                }
                let value = js_sys::JSON::parse(&message.to_string()).map_err(|e| format!("{e:?}"))?;
                parent.post_message(&value, &origin).map_err(|e| e.as_string().unwrap_or_else(|| format!("{e:?}")))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sign_mode() -> Value {
        json!({ "type": "pdfcraft:sign-mode", "requestId": 7, "field": "CraftOffice.R7.S1", "page": 2,
                "others": ["CraftOffice.R7.S2"], "banner": "Alice asks you to sign Contract.pdf: 1 field", "trustRoots": [] })
    }

    #[test]
    fn sign_host_ignores_other_origins_and_unknown_types() {
        let here = "https://cloud.example";
        assert!(accepts(here, here, true), "the same-origin parent is heard");
        assert!(!accepts("https://evil.example", here, true), "another origin is not");
        assert!(!accepts(here, here, false), "nor another window on this origin");
        assert!(!accepts("", "", true), "nor an opaque origin");

        assert!(matches!(read("pdfcraft:sign-mode", &sign_mode()), Some(Heard::Event(SignHostEvent::SignMode { request_id: 7, page: 2, .. }))));
        for kind in ["pdfcraft:sign-unknown", "pdfcraft:open", "pdfcraft:sign-mark", "other:sign-mode", ""] {
            assert_eq!(read(kind, &sign_mode()), None, "{kind} is not heard");
        }
        for kind in POSTED {
            assert!(!HEARD.contains(&kind), "the app's own messages are never heard back");
        }

        malformed_sign_mode_is_dropped();
        request_mode_and_host_flag_are_checked();
    }

    /// Malformed sign-mode messages are dropped whole.
    fn malformed_sign_mode_is_dropped() {
        let broken = |key: &str, value: Value| {
            let mut m = sign_mode();
            m[key] = value;
            read("pdfcraft:sign-mode", &m)
        };
        assert_eq!(broken("requestId", json!(-1)), None);
        assert_eq!(broken("requestId", json!(1.5)), None);
        assert_eq!(broken("requestId", json!("7")), None);
        assert_eq!(broken("field", json!("")), None);
        assert_eq!(broken("field", json!("x".repeat(MAX_NAME + 1))), None);
        assert_eq!(broken("page", json!(MAX_PAGE + 1)), None);
        assert_eq!(broken("others", json!(vec!["f"; MAX_SIGNERS + 1])), None);
        assert_eq!(broken("others", json!([3])), None);
        assert_eq!(broken("banner", json!(null)), None);
        assert_eq!(broken("trustRoots", json!(vec!["pem"; MAX_ROOTS + 1])), None);
        assert_eq!(broken("trustRoots", json!(["x".repeat(MAX_ROOT_PEM + 1)])), None);
    }

    /// Request mode: signers with distinct positions and names; `sign` only when really true.
    fn request_mode_and_host_flag_are_checked() {
        let request = |signers: Value| read("pdfcraft:sign-request-mode", &json!({ "signers": signers }));
        assert!(
            matches!(request(json!([{ "position": 1, "name": "Ann" }, { "position": 2, "name": "Bob" }])), Some(Heard::Event(SignHostEvent::RequestMode { signers })) if signers.len() == 2)
        );
        assert_eq!(request(json!([])), None, "no signers");
        assert_eq!(request(json!([{ "position": 1, "name": "Ann" }, { "position": 1, "name": "Bob" }])), None, "one position twice");
        assert_eq!(request(json!([{ "position": -1, "name": "Ann" }])), None);
        assert_eq!(request(json!([{ "position": 1 }])), None);

        // `sign` in pdfcraft:host: only a real true offers.
        assert_eq!(read("pdfcraft:host", &json!({ "sign": true })), Some(Heard::Offered(true)));
        assert_eq!(read("pdfcraft:host", &json!({ "sign": "yes" })), Some(Heard::Offered(false)));
        assert_eq!(read("pdfcraft:host", &json!({ "saves": true })), Some(Heard::Offered(false)));

        assert!(may_post(&json!({ "type": "pdfcraft:sign-mark" })));
        assert!(!may_post(&json!({ "type": "pdfcraft:save" })), "only the sign messages go out this way");
        assert!(!may_post(&json!({})));
    }
}
