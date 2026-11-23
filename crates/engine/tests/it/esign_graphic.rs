//! The `Graphic` JSON form of an e-sign mark and its caps (`pdfcraft_engine::esign`).

use base64::Engine as _;
use craft_image_codecs::{ChannelLayout, EncodeOptions, Format, Image};
use pdfcraft_engine::esign::{
    EsignError, MAX_PNG_BYTES, MAX_PNG_SIDE, MAX_STROKE_POINTS, MAX_STROKES, MAX_TYPED_CHARS, graphic_from_json, graphic_to_json,
};
use pdfcraft_engine::typed_signature_graphic;
use pdfcraft_sign::Graphic;
use serde_json::{Value, json};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A PNG of `w` x `h` pixels; `noise` makes it incompressible.
fn png(w: u32, h: u32, noise: bool) -> Vec<u8> {
    let mut x = 0x9e37_79b9_u32;
    let data: Vec<u8> = (0..w * h * 4)
        .map(|i| {
            if noise {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 8) as u8
            } else {
                (i % 251) as u8
            }
        })
        .collect();
    let img = Image::from_u8(w, h, ChannelLayout::Rgba, data).expect("image");
    craft_image_codecs::encode(&img, Format::Png, &EncodeOptions::default()).expect("encode")
}

/// A 16-bit RGBA PNG of `w` x `h` pixels.
fn png16(w: u32, h: u32) -> Vec<u8> {
    let data: Vec<u16> = (0..w * h * 4).map(|i| ((i / 4 % 1024) * 64) as u16).collect();
    let img = Image::from_u16(w, h, ChannelLayout::Rgba, &data).expect("image");
    craft_image_codecs::encode(&img, Format::Png, &EncodeOptions::default()).expect("encode")
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// `png` with a `tEXt` chunk before its `IEND`, so the whole file is exactly `size` bytes.
fn png_of_size(png: &[u8], size: usize) -> Vec<u8> {
    let iend = png.len() - 12;
    let data_len = size - png.len() - 12;
    let mut data = b"k\0".to_vec();
    data.resize(data_len, b'a');
    let mut chunk = Vec::new();
    chunk.extend_from_slice(b"tEXt");
    chunk.extend_from_slice(&data);
    let mut out = png[..iend].to_vec();
    out.extend_from_slice(&(data_len as u32).to_be_bytes());
    out.extend_from_slice(&chunk);
    out.extend_from_slice(&crc32(&chunk).to_be_bytes());
    out.extend_from_slice(&png[iend..]);
    assert_eq!(out.len(), size);
    out
}

fn image_json(bytes: &[u8]) -> Value {
    json!({ "kind": "image", "png": b64(bytes) })
}

fn strokes_json(strokes: usize, points: usize) -> Value {
    let stroke: Vec<Value> = (0..points).map(|i| json!([i as f64 / 4000.0, 0.25])).collect();
    json!({ "kind": "strokes", "strokes": vec![Value::Array(stroke); strokes] })
}

fn too_large(r: Result<Graphic, EsignError>) -> bool {
    matches!(r, Err(EsignError::GraphicTooLarge(_)))
}

fn bad(r: Result<Graphic, EsignError>) -> bool {
    matches!(r, Err(EsignError::BadGraphic(_)))
}

#[test]
fn strokes_round_trip() {
    let strokes = vec![vec![[0.1, 0.2], [0.3, 0.4], [0.5, 0.25]], vec![[0.6, 0.1]]];
    let g = Graphic::Strokes(strokes);
    let json = graphic_to_json(&g).expect("to json");
    assert_eq!(json["kind"], "strokes");
    assert_eq!(graphic_from_json(&json, "Alice").expect("from json"), g);
}

#[test]
fn image_round_trips_through_png() {
    let bytes = png(40, 20, false);
    let g = graphic_from_json(&image_json(&bytes), "Alice").expect("from json");
    assert!(matches!(g, Graphic::Image { width: 40, height: 20, .. }));
    let json = graphic_to_json(&g).expect("to json");
    assert_eq!(graphic_from_json(&json, "Alice").expect("again"), g);
}

#[test]
fn typed_draws_the_text() {
    let g = graphic_from_json(&json!({ "kind": "typed", "text": "Alice Example" }), "Someone Else").expect("typed");
    assert_eq!(Some(g), typed_signature_graphic("Alice Example"));
}

#[test]
fn name_draws_the_display_name_not_the_payload() {
    let g = graphic_from_json(&json!({ "kind": "name", "text": "Mallory", "name": "Mallory" }), "Alice Example").expect("name");
    assert_eq!(Some(g.clone()), typed_signature_graphic("Alice Example"));
    assert_ne!(Some(g), typed_signature_graphic("Mallory"));
}

#[test]
fn outlines_have_no_json_form() {
    let g = typed_signature_graphic("Alice").expect("outlines");
    assert!(matches!(graphic_to_json(&g), Err(EsignError::BadGraphic(_))));
}

#[test]
fn caps_are_inclusive_and_refuse_one_past() {
    assert_eq!((MAX_STROKES, MAX_STROKE_POINTS, MAX_PNG_BYTES, MAX_PNG_SIDE, MAX_TYPED_CHARS), (64, 2_000, 512 * 1024, 1024, 100));

    // Strokes.
    assert!(graphic_from_json(&strokes_json(MAX_STROKES, MAX_STROKE_POINTS), "A").is_ok());
    assert!(too_large(graphic_from_json(&strokes_json(MAX_STROKES + 1, 1), "A")));
    assert!(too_large(graphic_from_json(&strokes_json(1, MAX_STROKE_POINTS + 1), "A")));

    // Typed text.
    let typed = |n: usize| json!({ "kind": "typed", "text": "a".repeat(n) });
    assert!(graphic_from_json(&typed(MAX_TYPED_CHARS), "A").is_ok());
    assert!(too_large(graphic_from_json(&typed(MAX_TYPED_CHARS + 1), "A")));
    // Characters, not bytes.
    assert!(graphic_from_json(&json!({ "kind": "typed", "text": "é".repeat(MAX_TYPED_CHARS) }), "A").is_ok());

    // PNG sides.
    assert!(graphic_from_json(&image_json(&png(MAX_PNG_SIDE, 1, false)), "A").is_ok());
    assert!(graphic_from_json(&image_json(&png(1, MAX_PNG_SIDE, false)), "A").is_ok());
    assert!(too_large(graphic_from_json(&image_json(&png(MAX_PNG_SIDE + 1, 1, false)), "A")));
    assert!(too_large(graphic_from_json(&image_json(&png(1, MAX_PNG_SIDE + 1, false)), "A")));

    // PNG bytes: a real PNG with a text chunk, so the file is exactly the size.
    let base = png(300, 300, true);
    assert!(base.len() < MAX_PNG_BYTES, "the fixture PNG is {} bytes", base.len());
    assert!(graphic_from_json(&image_json(&png_of_size(&base, MAX_PNG_BYTES)), "A").is_ok());
    assert!(too_large(graphic_from_json(&image_json(&png_of_size(&base, MAX_PNG_BYTES + 1)), "A")));
    // The memory cap is no side cap: a full 1024 x 1024 picture opens, 8-bit and 16-bit.
    for (what, bytes) in [("8-bit", png(MAX_PNG_SIDE, MAX_PNG_SIDE, false)), ("16-bit", png16(MAX_PNG_SIDE, MAX_PNG_SIDE))] {
        assert!(bytes.len() <= MAX_PNG_BYTES, "{what} fixture is {} bytes", bytes.len());
        assert!(graphic_from_json(&image_json(&bytes), "A").is_ok(), "{what}");
    }
    // A genuinely large noisy picture.
    assert!(too_large(graphic_from_json(&image_json(&png(400, 400, true)), "A")));
}

#[test]
fn nan_or_infinite_points_are_bad_graphic() {
    // JSON has no NaN, but a number can be missing, null or a string, and `json!` turns a NaN into null.
    for bad_point in [
        json!([f64::NAN, 0.5]),
        json!([f64::INFINITY, 0.5]),
        json!([0.5, null]),
        json!(["NaN", 0.5]),
        json!([0.5]),
        json!([0.5, 0.5, 0.5]),
        json!("x"),
    ] {
        let v = json!({ "kind": "strokes", "strokes": [[[0.1, 0.1], bad_point]] });
        assert!(bad(graphic_from_json(&v, "A")), "{v}");
    }
    // A number outside f64 does not even parse.
    assert!(serde_json::from_str::<Value>(r#"{"kind":"strokes","strokes":[[[1e999,0]]]}"#).is_err());
    // And a non-finite point is refused on the way out.
    assert!(matches!(graphic_to_json(&Graphic::Strokes(vec![vec![[f64::NAN, 0.0]]])), Err(EsignError::BadGraphic(_))));
    assert!(matches!(graphic_to_json(&Graphic::Strokes(vec![vec![[f64::INFINITY, 0.0]]])), Err(EsignError::BadGraphic(_))));
}

#[test]
fn jpeg_bytes_in_png_are_bad_graphic() {
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0];
    jpeg.resize(200, 0);
    assert!(bad(graphic_from_json(&image_json(&jpeg), "A")));
    // A PNG header with nothing behind it.
    assert!(bad(graphic_from_json(&image_json(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0]), "A")));
    // Not base64, not a string, missing.
    assert!(bad(graphic_from_json(&json!({ "kind": "image", "png": "***not base64***" }), "A")));
    assert!(bad(graphic_from_json(&json!({ "kind": "image", "png": 7 }), "A")));
    assert!(bad(graphic_from_json(&json!({ "kind": "image" }), "A")));
}

#[test]
fn unknown_kind_is_bad_graphic() {
    for v in [
        json!({ "kind": "scribble" }),
        json!({ "kind": "outlines", "contours": [] }),
        json!({ "kind": 3 }),
        json!({}),
        json!([]),
        json!(null),
        json!("strokes"),
        json!({ "kind": "typed" }),
        json!({ "kind": "typed", "text": "   " }),
        json!({ "kind": "strokes", "strokes": [] }),
        json!({ "kind": "strokes" }),
    ] {
        assert!(bad(graphic_from_json(&v, "A")), "{v}");
    }
    assert!(bad(graphic_from_json(&json!({ "kind": "name" }), "")));
}

#[test]
fn wire_codes() {
    let codes = [
        (EsignError::BadGraphic(String::new()), "bad_graphic"),
        (EsignError::GraphicTooLarge(String::new()), "graphic_too_large"),
        (EsignError::AlreadySigned, "already_signed"),
        (EsignError::NeedsPassword, "needs_password"),
        (EsignError::NotPdf(String::new()), "not_pdf"),
        (EsignError::NoField(String::new()), "no_field"),
        (EsignError::Validation(String::new()), "validation_failed"),
    ];
    for (e, code) in codes {
        assert_eq!(e.code(), code);
    }
    assert_eq!(EsignError::AlreadySigned.to_string(), "This PDF is already signed; a new signature would break it");
}

#[test]
fn bytes_after_iend_are_bad_graphic() {
    let mut polyglot = png(8, 8, false);
    assert!(graphic_from_json(&image_json(&polyglot), "A").is_ok());
    polyglot.extend_from_slice(b"PK\x03\x04 payload");
    assert!(bad(graphic_from_json(&image_json(&polyglot), "A")));
    let mut cut = png(8, 8, false);
    cut.truncate(cut.len() - 4);
    assert!(bad(graphic_from_json(&image_json(&cut), "A")));
}

#[test]
fn coordinates_outside_the_box_are_bad_graphic_not_a_signing_error() {
    for v in [1_000.5, -1_000.5, 1e308, -1e308, 1e6] {
        let j = json!({ "kind": "strokes", "strokes": [[[0.0, 0.0], [v, 0.0]]] });
        assert!(bad(graphic_from_json(&j, "A")), "{v}");
        let j = json!({ "kind": "strokes", "strokes": [[[0.0, v]]] });
        assert!(bad(graphic_from_json(&j, "A")), "{v}");
    }
    let edge = json!({ "kind": "strokes", "strokes": [[[-1000.0, 1000.0], [1000.0, -1000.0]]] });
    assert!(graphic_from_json(&edge, "A").is_ok());
}

#[test]
fn json_text_round_trips_every_double_exactly() {
    let mut x = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let strokes: Vec<Vec<[f64; 2]>> = (0..40)
        .map(|_| {
            (0..50)
                .map(|_| {
                    // Full-mantissa doubles over the allowed box, and some tiny and subnormal ones.
                    let a = (next() as f64 / u64::MAX as f64) * 2_000.0 - 1_000.0;
                    let b = f64::from_bits(next() & 0x800f_ffff_ffff_ffff | (next() % 0x3ff) << 52);
                    [a, if b.is_finite() { b } else { 0.0 }]
                })
                .collect()
        })
        .collect();
    let g = Graphic::Strokes(strokes);
    let text = serde_json::to_string(&graphic_to_json(&g).expect("to json")).expect("text");
    let parsed: Value = serde_json::from_str(&text).expect("parse");
    assert_eq!(graphic_from_json(&parsed, "A").expect("from json"), g);
}

#[test]
fn a_long_display_name_is_cut_not_refused() {
    let long = "é".repeat(MAX_TYPED_CHARS + 50);
    let g = graphic_from_json(&json!({ "kind": "name" }), &long).expect("name");
    assert_eq!(Some(g), typed_signature_graphic(&"é".repeat(MAX_TYPED_CHARS)));
}

#[test]
fn sign_and_edit_errors_keep_their_text_off_the_wire() {
    let secret = "/home/someone/secret-path";
    let e = EsignError::from(pdfcraft_sign::SignError::Pdf(secret.into()));
    assert!(!e.to_string().contains(secret));
    let e = EsignError::from(pdfcraft_engine::EditError::Print(secret.into()));
    assert!(!e.to_string().contains(secret));
}
