//! The audit page a signature request appends at prepare (plan ruling R2), and the standalone
//! printable copy of a request's audit trail (`POST /v1/audit-pdf`).
//!
//! Both are built only from existing edits: blank pages, added text and form fields, so they
//! go through the same `Edit` and `Session` path as every other change (rule 14). Text drawn
//! here is untrusted (titles, names, user agents): it is cut to a length and drawn in the
//! standard fonts, with what they cannot show written as its code point (`[U+1EC5]`).

use pdfcraft_edit::added::text_rect;
use serde_json::{Map, Value};

use super::EsignError;
use super::inspect::{Opened, open, session_at};
use super::prepare::{AuditHeader, SignerSlot, completed_field, row_field, seal_field, signer_field};
use crate::{AddedText, Edit, FieldProps, FontFamily, NewField};

/// The page margin, in points.
const MARGIN: f64 = 54.0;
/// US Letter, the audit page's size when the last page is too small (or too large) to copy.
const LETTER: (f64, f64) = (612.0, 792.0);
/// A last page smaller than this on either side is not copied: the blocks would not fit.
const MIN_SIDE: f64 = 420.0;
/// A last page larger than this on either side is not copied either (a poster or a drawing).
const MAX_SIDE: f64 = 2_000.0;
/// The seal's field and a signer's field on the audit page: 180 x 40 points.
const SIG_W: f64 = 180.0;
const SIG_H: f64 = 40.0;
/// Room kept at the bottom of every audit page for the Completed line and the seal.
const FOOTER: f64 = 108.0;
/// Longest text taken from the request for one line (characters).
const MAX_LINE: usize = 300;
/// At most this many events in a printed trail.
const MAX_EVENTS: usize = 5_000;
/// At most this many signers, and as many signatures, in a printed trail: a request's own cap.
const MAX_LIST: usize = super::prepare::MAX_SIGNERS;
/// At most this many keys in the trail and in any one of its objects.
const MAX_KEYS: usize = 64;
/// The keys of an event that follow its head, before anything else, so a cut never hides them.
const EVENT_FIRST: [&str; 3] = ["mac", "sha256_before", "sha256_after"];

/// `s` as the standard fonts draw it: control characters become spaces, a character outside
/// WinAnsiEncoding is written as its code point (`[U+1EC5]`), so a name stays unambiguous, and
/// text past `max` characters is cut, the cut marked with an ellipsis.
pub(super) fn clean(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i == max {
            out.push('\u{2026}');
            break;
        }
        if c.is_control() {
            out.push(' ');
        } else if pdfcraft_fonts::win_ansi_encodable(c) {
            out.push(c);
        } else {
            out.push_str(&format!("[U+{:04X}]", u32::from(c)));
        }
    }
    out
}

/// The audit page's size: the last page's (as shown), unless that is too small or too large.
pub(super) fn page_size(last: Option<(f64, f64)>) -> (f64, f64) {
    match last {
        Some((w, h)) if (MIN_SIDE..=MAX_SIDE).contains(&w) && (MIN_SIDE..=MAX_SIDE).contains(&h) => (w, h),
        _ => LETTER,
    }
}

fn styled(text: String, size: f64, bold: bool) -> AddedText {
    AddedText { text, size, bold, family: FontFamily::Helvetica, ..AddedText::default() }
}

/// Lays text out top to bottom over pages of one size, opening a page when the next item would
/// run into the bottom room. Consecutive paragraphs of one style on one page share an item.
struct Pages {
    size: (f64, f64),
    /// Room kept free at each page's bottom, above the margin.
    footer: f64,
    page: usize,
    /// The top of the free space on `page`.
    y: f64,
    edits: Vec<Edit>,
    /// The item being filled: its style, its text and its top.
    run: Option<(AddedText, f64)>,
    /// Drawn at the top of each page this opens.
    continued: Option<String>,
}

impl Pages {
    /// Start at the top of `page`, adding it first when `insert` is set.
    fn new(page: usize, size: (f64, f64), footer: f64, insert: bool) -> Self {
        let mut edits = Vec::new();
        if insert {
            edits.push(Edit::InsertBlankPage { at: page, width: size.0, height: size.1 });
        }
        Pages { size, footer, page, y: size.1 - MARGIN, edits, run: None, continued: None }
    }

    fn width(&self) -> f64 {
        self.size.0 - 2.0 * MARGIN
    }

    fn height_of(&self, t: &AddedText) -> f64 {
        let mut t = t.clone();
        t.rect = [MARGIN, 0.0, MARGIN + self.width(), 1.0];
        let r = text_rect(&t);
        r[3] - r[1]
    }

    fn flush(&mut self) {
        if let Some((mut t, top)) = self.run.take() {
            let h = self.height_of(&t);
            t.rect = [MARGIN, top - h, MARGIN + self.width(), top];
            self.edits.push(Edit::AddText { page: self.page, text: t });
        }
    }

    /// Make sure `h` points fit above the bottom room, on a new page if need be.
    fn room(&mut self, h: f64) {
        if self.y - h >= MARGIN + self.footer {
            return;
        }
        self.flush();
        self.page += 1;
        self.edits.push(Edit::InsertBlankPage { at: self.page, width: self.size.0, height: self.size.1 });
        self.y = self.size.1 - MARGIN;
        if let Some(c) = self.continued.clone() {
            self.text(c, 10.0, true, 8.0);
        }
    }

    /// A paragraph, then `gap` points of space.
    fn text(&mut self, text: String, size: f64, bold: bool, gap: f64) {
        if text.trim().is_empty() {
            return;
        }
        let t = styled(text, size, bold);
        let h = self.height_of(&t);
        let joins = matches!(&self.run, Some((r, _)) if r.size == size && r.bold == bold);
        if !joins || self.y - h < MARGIN + self.footer {
            self.flush();
            self.room(h);
            self.run = Some((styled(String::new(), size, bold), self.y));
        }
        if let Some((r, _)) = self.run.as_mut() {
            if !r.text.is_empty() {
                r.text.push('\n');
            }
            r.text.push_str(&t.text);
        }
        self.y -= h;
        if gap > 0.0 {
            // A gap ends the item, so the next paragraph starts below it.
            self.flush();
            self.y -= gap;
        }
    }

    fn field(&mut self, page: usize, rect: [f64; 4], kind: NewField, name: String) {
        self.edits.push(Edit::AddField { page, rect, kind, name: Some(name) });
    }
}

fn read_only(name: String) -> Edit {
    Edit::SetFieldProps { name, props: Box::new(FieldProps { read_only: Some(true), ..FieldProps::default() }) }
}

/// The edits that append the audit page (or pages, for many signers) after the document's
/// `pages` pages: the header, a block per signer with its empty read-only row and, when the
/// signer has no place of their own, their signature field; then the Completed line and the
/// seal at the bottom of the last audit page. Signers with a place get their field there.
pub(super) fn audit_edits(pages: usize, size: (f64, f64), header: &AuditHeader, signers: &[SignerSlot]) -> Vec<Edit> {
    let id = header.request_id;
    let title = clean(&header.title, MAX_LINE);
    let mut p = Pages::new(pages, size, FOOTER, true);
    p.text(format!("Signature record: {title}"), 14.0, true, 6.0);
    p.text(
        format!(
            "Request {id} \u{b7} requested by {} ({}) on {}",
            clean(&header.requester_name, MAX_LINE),
            clean(&header.requester_uid, MAX_LINE),
            clean(&header.created_utc, 40)
        ),
        10.0,
        false,
        4.0,
    );
    p.text(
        format!(
            "Sealed by {} for {}. Each signature below is an approval signature with the instance certificate; the final seal locks the \
             document. The SHA-256 of this final file is in the Nextcloud audit trail, not on this page.",
            clean(&header.instance, MAX_LINE),
            clean(&header.organisation, MAX_LINE)
        ),
        9.0,
        false,
        14.0,
    );
    p.continued = Some(format!("Signature record: {title} (continued)"));

    let (x0, x1) = (MARGIN, size.0 - MARGIN);
    let mut rows = Vec::new();
    for s in signers {
        let line = format!("{}. {} ({})", s.position, clean(&s.display_name, MAX_LINE), clean(&s.uid, MAX_LINE));
        let name_h = p.height_of(&styled(line.clone(), 10.0, true));
        p.room(name_h + 4.0 + SIG_H);
        p.text(line, 10.0, true, 4.0);
        let top = p.y;
        let row_right = if s.placement.is_none() { x1 - SIG_W - 10.0 } else { x1 };
        let row = row_field(id, s.position);
        p.field(p.page, [x0, top - SIG_H, row_right, top], NewField::Text { multiline: true }, row.clone());
        rows.push(row);
        match &s.placement {
            None => p.field(p.page, [x1 - SIG_W, top - SIG_H, x1, top], NewField::Signature, signer_field(id, s.position)),
            Some(at) => p.field(at.page, at.rect, NewField::Signature, signer_field(id, s.position)),
        }
        p.y = top - SIG_H - 12.0;
    }
    p.flush();

    // The bottom of the last audit page: the Completed line, then the seal.
    let last = p.page;
    let label = |text: &str, top: f64, right: f64| {
        let mut t = styled(text.into(), 9.0, true);
        t.rect = [x0, top - 11.0, right, top];
        Edit::AddText { page: last, text: t }
    };
    p.edits.push(label("Completed", MARGIN + 100.0, x1));
    p.field(last, [x0, MARGIN + 56.0, x1, MARGIN + 86.0], NewField::Text { multiline: true }, completed_field(id));
    p.edits.push(label("Final seal", MARGIN + SIG_H / 2.0 + 5.0, x1 - SIG_W - 10.0));
    p.field(last, [x1 - SIG_W, MARGIN, x1, MARGIN + SIG_H], NewField::Signature, seal_field(id));
    rows.push(completed_field(id));
    p.edits.extend(rows.into_iter().map(read_only));
    p.edits
}

/// A value of the trail as text: strings as they are, `at` milliseconds as a UTC time, other
/// values as compact JSON.
fn shown(key: &str, v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        Value::Number(n) if key == "at" => match n.as_i64().and_then(chrono::DateTime::from_timestamp_millis) {
            Some(t) => t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            None => n.to_string(),
        },
        other => other.to_string(),
    }
}

fn field(o: &Map<String, Value>, key: &str) -> String {
    o.get(key).map(|v| shown(key, v)).unwrap_or_else(|| "-".into())
}

/// `o`'s entries other than `skip`, as `key value` parts joined by middle dots. Long values
/// (PEM blocks) are left to the JSON export.
fn rest(o: &Map<String, Value>, skip: &[&str]) -> String {
    o.iter()
        .filter(|(k, _)| !skip.contains(&k.as_str()) && k.as_str() != "token_hash")
        .map(|(k, v)| {
            let s = shown(k, v);
            if s.chars().count() > MAX_LINE { format!("{k} (in the JSON export)") } else { format!("{k} {s}") }
        })
        .collect::<Vec<_>>()
        .join(" \u{b7} ")
}

/// A printable PDF of a request's audit trail (the JSON export of N8): the request, its
/// signers, one line per event with its MAC, the chain check, the certificate, the signatures
/// of the current file and the final digest. Keys it does not know are printed as they are.
pub fn audit_document(trail: &Value) -> Result<Vec<u8>, EsignError> {
    let bad = |why: &str| EsignError::Validation(why.into());
    let t = trail.as_object().ok_or_else(|| bad("The audit trail is not a JSON object."))?;
    let empty = Map::new();
    let obj = |k: &str| t.get(k).and_then(Value::as_object).unwrap_or(&empty);
    let list = |k: &str| t.get(k).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let events = list("events");
    for (key, cap, why) in [
        ("events", MAX_EVENTS, "The audit trail has too many events to print."),
        ("signers", MAX_LIST, "The audit trail has too many signers to print."),
        ("signatures", MAX_LIST, "The audit trail has too many signatures to print."),
    ] {
        if list(key).len() > cap {
            return Err(bad(why));
        }
    }
    let objects = ["request", "chain", "certificate"].map(obj);
    let entries = ["events", "signers", "signatures"].into_iter().flat_map(list).filter_map(Value::as_object);
    if t.len() > MAX_KEYS || objects.into_iter().chain(entries).any(|o| o.len() > MAX_KEYS) {
        return Err(bad("An entry of the audit trail has too many fields to print."));
    }
    let request = obj("request");
    // Both of the file's dates are the export's time (else the request's): the same trail
    // prints the same bytes, and the file is never modified before it was created.
    let stamp = t.get("exported_at").and_then(Value::as_str).into_iter();
    let mut created = stamp.chain(["created_utc", "created_at", "created"].iter().filter_map(|k| request.get(*k).and_then(Value::as_str)));
    let now = created.find_map(|c| super::prepare::parse_date(c).ok()).unwrap_or(0);

    let blank = session_at(now).create_blank(LETTER.0, LETTER.1, 1)?;
    let (mut session, id) = match open(&blank, now)? {
        Opened::Doc(s, id) => (s, id),
        Opened::NeedsPassword => return Err(EsignError::NeedsPassword),
    };
    let line = |s: String| clean(&s, 4 * MAX_LINE);
    let title = clean(&field(request, "title"), MAX_LINE);
    let mut p = Pages::new(0, LETTER, 0.0, false);
    p.continued = Some(format!("Audit trail: {title} (continued)"));
    p.text(format!("Audit trail: {title}"), 14.0, true, 6.0);
    p.text(line(rest(request, &["title"])), 9.0, false, 10.0);

    p.text("Signers".into(), 11.0, true, 4.0);
    for s in list("signers").iter().filter_map(Value::as_object) {
        let head = format!("{}. {} ({})", field(s, "position"), field(s, "display_name"), field(s, "uid"));
        let more = rest(s, &["position", "display_name", "uid"]);
        p.text(line(if more.is_empty() { head } else { format!("{head} \u{b7} {more}") }), 9.0, false, 0.0);
    }
    p.y -= 8.0;

    p.text("Events".into(), 11.0, true, 4.0);
    for e in events.iter().filter_map(Value::as_object) {
        let head = format!("#{} {} {} by {}", field(e, "seq"), field(e, "at"), field(e, "kind"), field(e, "actor_uid"));
        let first = EVENT_FIRST.iter().filter_map(|k| e.get(*k).map(|v| format!("{k} {}", shown(k, v))));
        let more = rest(e, &["seq", "at", "kind", "actor_uid", "mac", "sha256_before", "sha256_after"]);
        let parts: Vec<String> = std::iter::once(head).chain(first).chain((!more.is_empty()).then_some(more)).collect();
        // No gap: consecutive events share one text item per page, so thousands of events stay
        // a few hundred edits.
        p.text(line(parts.join(" \u{b7} ")), 7.0, false, 0.0);
    }
    p.y -= 8.0;

    p.text("Chain check".into(), 11.0, true, 4.0);
    p.text(line(rest(obj("chain"), &[])), 9.0, false, 8.0);
    p.text("Seal certificate".into(), 11.0, true, 4.0);
    p.text(line(rest(obj("certificate"), &[])), 9.0, false, 8.0);
    p.text("Signatures in the current file".into(), 11.0, true, 4.0);
    for s in list("signatures").iter().filter_map(Value::as_object) {
        p.text(line(format!("{} \u{b7} {}", field(s, "field"), rest(s, &["field"]))), 9.0, false, 0.0);
    }
    p.y -= 8.0;
    p.text(line(format!("Final SHA-256: {}", t.get("final_sha256").map(|v| shown("", v)).unwrap_or_else(|| "-".into()))), 9.0, false, 0.0);
    p.flush();

    // The blank page's save stamped only `/ModDate`; the creation date is the same fixed time.
    p.edits.insert(0, Edit::SetInfo { key: "CreationDate".into(), value: pdfcraft_cos::pdf_date(now) });
    session.apply(id, Edit::Batch { label: "Print audit trail".into(), edits: p.edits })?;
    Ok(session.save_full_bytes(id)?.to_vec())
}
