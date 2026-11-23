//! E-sign: platform-sealed signature requests. This module holds what the seal worker and the
//! host share: the error type with its wire codes, and the JSON form of a signer's mark.

mod graphic;

pub use graphic::{MAX_PNG_BYTES, MAX_PNG_SIDE, MAX_STROKE_POINTS, MAX_STROKES, MAX_TYPED_CHARS, graphic_from_json, graphic_to_json};

/// Why an e-sign step was refused. Each variant has a stable wire code ([`EsignError::code`]);
/// the `Display` text is an English sentence a signer can read.
#[derive(Debug, thiserror::Error)]
pub enum EsignError {
    #[error("{0}")]
    BadGraphic(String),
    #[error("{0}")]
    GraphicTooLarge(String),
    #[error("This PDF is already signed; a new signature would break it")]
    AlreadySigned,
    #[error("This PDF needs a password to open")]
    NeedsPassword,
    #[error("{0}")]
    NotPdf(String),
    #[error("{0}")]
    NoField(String),
    #[error("{0}")]
    Validation(String),
    #[error(transparent)]
    Sign(#[from] pdfcraft_sign::SignError),
    #[error(transparent)]
    Edit(#[from] crate::EditError),
}

impl EsignError {
    /// The code the seal worker puts in `{ "error": … }`. A signing or editing failure inside a
    /// step is the worker refusing the PDF it was given, so it shares `validation_failed`.
    pub fn code(&self) -> &'static str {
        match self {
            EsignError::BadGraphic(_) => "bad_graphic",
            EsignError::GraphicTooLarge(_) => "graphic_too_large",
            EsignError::AlreadySigned => "already_signed",
            EsignError::NeedsPassword => "needs_password",
            EsignError::NotPdf(_) => "not_pdf",
            EsignError::NoField(_) => "no_field",
            EsignError::Validation(_) | EsignError::Sign(_) | EsignError::Edit(_) => "validation_failed",
        }
    }
}
