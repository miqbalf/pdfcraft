//! The `graphic` JSON a signer's mark travels in, and its caps.
//!
//! ```text
//! { "kind": "strokes", "strokes": [[[x, y], …], …] }   y up, the drawing pad is 1 wide
//! { "kind": "typed",   "text": "…" }                   drawn in the script font
//! { "kind": "name" }                                   the signer's display name, drawn as typed
//! { "kind": "image",   "png": "<base64>" }
//! ```
//!
//! The input is untrusted: every cap is checked before the data is used, and a refusal says in a
//! sentence what was too big.

use std::sync::Arc;

use base64::Engine as _;
use craft_image_codecs::{ChannelLayout, CodecError, DecodeOptions, EncodeOptions, Format, Image, Limits};
use pdfcraft_sign::Graphic;
use serde_json::{Map, Value, json};

use super::EsignError;

/// At most this many strokes in a drawn mark.
pub const MAX_STROKES: usize = 64;
/// At most this many points in one stroke.
pub const MAX_STROKE_POINTS: usize = 2_000;
/// At most this many bytes in a PNG mark.
pub const MAX_PNG_BYTES: usize = 512 * 1024;
/// At most this many pixels on a PNG mark's width or height.
pub const MAX_PNG_SIDE: u32 = 1024;
/// At most this many characters in a typed mark.
pub const MAX_TYPED_CHARS: usize = 100;

/// A stroke coordinate stays within this distance of the origin. The drawing pad is 1 wide, so
/// this is a thousand pads: far more than any real mark, far less than what `draw` refuses.
const MAX_COORD: f64 = 1_000.0;

/// `n` when it is a finite number inside the box a mark may use.
fn coord(n: f64) -> Option<f64> {
    (n.is_finite() && n.abs() <= MAX_COORD).then_some(n)
}

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn bad(why: impl Into<String>) -> EsignError {
    EsignError::BadGraphic(why.into())
}

fn too_large(why: impl Into<String>) -> EsignError {
    EsignError::GraphicTooLarge(why.into())
}

/// The mark in `v` as a signature graphic. `display_name` is what `{ "kind": "name" }` draws:
/// the payload never chooses that text.
pub fn graphic_from_json(v: &Value, display_name: &str) -> Result<Graphic, EsignError> {
    let obj = v.as_object().ok_or_else(|| bad("The signature mark is not a JSON object."))?;
    match obj.get("kind").and_then(Value::as_str) {
        Some("strokes") => strokes(obj),
        Some("typed") => {
            let text = obj.get("text").and_then(Value::as_str).ok_or_else(|| bad("The typed signature has no text."))?;
            typed(text)
        }
        // The name is the server's, never the signer's: an over-long one is cut, not refused.
        Some("name") => typed(&display_name.chars().take(MAX_TYPED_CHARS).collect::<String>()),
        Some("image") => image(obj),
        Some(other) => Err(bad(format!("The signature mark kind \"{}\" is not supported.", other.chars().take(40).collect::<String>()))),
        None => Err(bad("The signature mark has no kind.")),
    }
}

fn typed(text: &str) -> Result<Graphic, EsignError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(bad("The typed signature is empty."));
    }
    if text.chars().count() > MAX_TYPED_CHARS {
        return Err(too_large(format!("The typed signature has more than {MAX_TYPED_CHARS} characters.")));
    }
    crate::fill_sign::typed_signature_graphic(text).ok_or_else(|| bad("The typed signature has no letters that can be drawn."))
}

fn strokes(obj: &Map<String, Value>) -> Result<Graphic, EsignError> {
    let list = obj.get("strokes").and_then(Value::as_array).ok_or_else(|| bad("The drawn signature has no strokes."))?;
    if list.len() > MAX_STROKES {
        return Err(too_large(format!("The drawn signature has more than {MAX_STROKES} strokes.")));
    }
    // Caps first, so an oversized mark is refused before any of it is read.
    if list.iter().any(|s| s.as_array().is_some_and(|p| p.len() > MAX_STROKE_POINTS)) {
        return Err(too_large(format!("A stroke of the drawn signature has more than {MAX_STROKE_POINTS} points.")));
    }
    let mut out = Vec::with_capacity(list.len());
    for s in list {
        let points = s.as_array().ok_or_else(|| bad("A stroke of the drawn signature is not a list of points."))?;
        let mut stroke = Vec::with_capacity(points.len());
        for p in points {
            let xy = p.as_array().filter(|a| a.len() == 2).ok_or_else(|| bad("A point of the drawn signature is not an [x, y] pair."))?;
            let coord = |i: usize| xy.get(i).and_then(Value::as_f64).and_then(coord);
            let (Some(x), Some(y)) = (coord(0), coord(1)) else {
                return Err(bad("A point of the drawn signature is not a finite number within ±1000."));
            };
            stroke.push([x, y]);
        }
        out.push(stroke);
    }
    if out.iter().all(Vec::is_empty) {
        return Err(bad("The drawn signature has no points."));
    }
    Ok(Graphic::Strokes(out))
}

fn limits() -> Limits {
    let side = u64::from(MAX_PNG_SIDE);
    Limits { max_width: MAX_PNG_SIDE, max_height: MAX_PNG_SIDE, max_pixels: side * side, max_alloc: side * side * 8 }
}

fn image(obj: &Map<String, Value>) -> Result<Graphic, EsignError> {
    let text = obj.get("png").and_then(Value::as_str).ok_or_else(|| bad("The image signature has no PNG data."))?;
    // Refuse by the encoded length first: base64 is 4 characters per 3 bytes.
    if text.len() > MAX_PNG_BYTES.div_ceil(3) * 4 + 4 {
        return Err(too_large(format!("The signature image is larger than {} KiB.", MAX_PNG_BYTES / 1024)));
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(text.trim()).map_err(|_| bad("The signature image is not valid base64."))?;
    if bytes.len() > MAX_PNG_BYTES {
        return Err(too_large(format!("The signature image is larger than {} KiB.", MAX_PNG_BYTES / 1024)));
    }
    if !bytes.starts_with(&PNG_SIGNATURE) {
        return Err(bad("The signature image is not a PNG."));
    }
    if !ends_at_iend(&bytes) {
        return Err(bad("The signature image has data after the end of the PNG."));
    }
    // The header first, so a side over the cap is named as such and the decoder's own limits
    // (memory) only ever speak about memory.
    let (w, h) = craft_image_codecs::probe_size(&bytes).map_err(|_| bad("The signature image is not a readable PNG."))?;
    if w > MAX_PNG_SIDE || h > MAX_PNG_SIDE {
        return Err(too_large(format!("The signature image is larger than {MAX_PNG_SIDE} pixels on a side.")));
    }
    let opts = DecodeOptions { keep_orientation: true, limits: limits() };
    let img = craft_image_codecs::decode_as_with(Format::Png, &bytes, &opts).map_err(|e| match e {
        CodecError::LimitExceeded(_) => too_large("The signature image needs too much memory to open."),
        _ => bad("The signature image is not a readable PNG."),
    })?;
    let (width, height) = (img.width(), img.height());
    if width == 0 || height == 0 || width > MAX_PNG_SIDE || height > MAX_PNG_SIDE {
        return Err(too_large(format!("The signature image is larger than {MAX_PNG_SIDE} pixels on a side.")));
    }
    Ok(Graphic::Image { width, height, rgba: Arc::new(img.to_rgba8()) })
}

/// Whether the chunks of the PNG in `b` run to an `IEND` that is the last thing in the file: a
/// PNG with a payload behind it (a polyglot) is refused.
fn ends_at_iend(b: &[u8]) -> bool {
    let mut at = PNG_SIGNATURE.len();
    while let Some(head) = b.get(at..at + 8) {
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let Some(end) = at.checked_add(12).and_then(|n| n.checked_add(len)) else { return false };
        if end > b.len() {
            return false;
        }
        if &head[4..8] == b"IEND" {
            return end == b.len();
        }
        at = end;
    }
    false
}

/// The JSON form of `g`: strokes and images only. Outlines (a typed mark already drawn) have no
/// JSON form, so they are refused; send `typed` or `name` instead.
pub fn graphic_to_json(g: &Graphic) -> Result<Value, EsignError> {
    match g {
        Graphic::Strokes(strokes) => {
            if strokes.len() > MAX_STROKES {
                return Err(too_large(format!("The drawn signature has more than {MAX_STROKES} strokes.")));
            }
            if strokes.iter().any(|s| s.len() > MAX_STROKE_POINTS) {
                return Err(too_large(format!("A stroke of the drawn signature has more than {MAX_STROKE_POINTS} points.")));
            }
            let mut out = Vec::with_capacity(strokes.len());
            for s in strokes {
                let mut points = Vec::with_capacity(s.len());
                for [x, y] in s {
                    // `from_f64` is `None` for NaN and infinity.
                    let (Some(x), Some(y)) = (serde_json::Number::from_f64(*x), serde_json::Number::from_f64(*y)) else {
                        return Err(bad("A point of the drawn signature is not a finite number."));
                    };
                    points.push(json!([x, y]));
                }
                out.push(Value::Array(points));
            }
            Ok(json!({ "kind": "strokes", "strokes": out }))
        }
        Graphic::Image { width, height, rgba } => {
            if *width > MAX_PNG_SIDE || *height > MAX_PNG_SIDE {
                return Err(too_large(format!("The signature image is larger than {MAX_PNG_SIDE} pixels on a side.")));
            }
            let img = Image::from_u8(*width, *height, ChannelLayout::Rgba, rgba.as_ref().clone())
                .map_err(|_| bad("The signature image's pixels don't match its size."))?;
            let png = craft_image_codecs::encode(&img, Format::Png, &EncodeOptions::default())
                .map_err(|_| bad("The signature image could not be written as a PNG."))?;
            if png.len() > MAX_PNG_BYTES {
                return Err(too_large(format!("The signature image is larger than {} KiB.", MAX_PNG_BYTES / 1024)));
            }
            Ok(json!({ "kind": "image", "png": base64::engine::general_purpose::STANDARD.encode(png) }))
        }
        Graphic::Outlines(_) => Err(bad("A typed signature already drawn has no JSON form; send its text instead.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coord_refuses_non_finite_and_out_of_box_numbers() {
        for n in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1_000.5, -1_000.5, 1e308, -1e308] {
            assert_eq!(coord(n), None, "{n}");
        }
        for n in [0.0, -0.0, 0.5, 1_000.0, -1_000.0] {
            assert_eq!(coord(n), Some(n));
        }
    }
}
