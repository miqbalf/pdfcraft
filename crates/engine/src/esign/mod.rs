//! E-sign: platform-sealed signature requests. This module holds what the seal worker and the
//! host share: the error type with its wire codes, the JSON form of a signer's mark, the
//! inspection of a PDF, the prepare step that adds the request's fields and audit page, and the
//! seal that signs each signer's field and, after the last, locks the document.

mod audit_page;
mod graphic;
mod inspect;
mod prepare;
mod seal;

pub use audit_page::audit_document;
pub use graphic::{MAX_PNG_BYTES, MAX_PNG_SIDE, MAX_STROKE_POINTS, MAX_STROKES, MAX_TYPED_CHARS, graphic_from_json, graphic_to_json};
pub use inspect::{Inspection, SignatureSummary, inspect};
pub use prepare::{AuditHeader, MAX_SIGNERS, Placement, Prepared, SignerSlot, completed_field, prepare, row_field, seal_field, signer_field};
pub use seal::{FinalSeal, Sealed, SignerSeal, seal};

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
    /// The timestamp authority could not be reached or refused to answer; nothing was signed, and
    /// the same call may succeed later.
    #[error("The timestamp service did not answer; nothing was signed. Try again.")]
    TsaUnavailable,
    // A fixed sentence: the inner text can hold paths or library detail, so it stays off the wire.
    #[error("The PDF could not be signed.")]
    Sign(#[from] pdfcraft_sign::SignError),
    #[error("The PDF could not be edited.")]
    Edit(#[from] crate::EditError),
}

impl EsignError {
    /// The code the seal worker puts in `{ "error": … }`. A signing or editing failure inside a
    /// step is the worker refusing the PDF it was given, so it shares `validation_failed`; an
    /// unreachable timestamp authority is `tsa_unavailable` (503: try again).
    pub fn code(&self) -> &'static str {
        match self {
            EsignError::BadGraphic(_) => "bad_graphic",
            EsignError::GraphicTooLarge(_) => "graphic_too_large",
            EsignError::AlreadySigned => "already_signed",
            EsignError::NeedsPassword => "needs_password",
            EsignError::NotPdf(_) => "not_pdf",
            EsignError::NoField(_) => "no_field",
            EsignError::TsaUnavailable => "tsa_unavailable",
            EsignError::Validation(_) | EsignError::Sign(_) | EsignError::Edit(_) => "validation_failed",
        }
    }
}
