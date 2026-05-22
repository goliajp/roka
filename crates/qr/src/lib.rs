#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! Zero-dependency QR code encoder + decoder with built-in PNG/PBM image I/O.
//!
//! `roka-qr` covers [ISO/IEC 18004] from end to end: byte / alphanumeric /
//! numeric mode encoding, all four error-correction levels (L/M/Q/H), all 40
//! versions, and decoding back from a PNG or PBM image without ever pulling in
//! an external crate.
//!
//! # Quick start
//!
//! Encode a string into a QR code and write it as PNG:
//!
//! ```
//! use roka_qr::{Encoder, EcLevel};
//!
//! let code = Encoder::new(b"https://example.com").ec_level(EcLevel::M).build()?;
//! let bitmap = code.render().scale(8).quiet_zone(4).build();
//! let png_bytes = bitmap.to_png();
//! # Ok::<(), roka_qr::Error>(())
//! ```
//!
//! Decode a QR code from PNG bytes:
//!
//! ```no_run
//! use roka_qr::Reader;
//!
//! let png_bytes: Vec<u8> = std::fs::read("qr.png").unwrap();
//! let code = Reader::from_png(&png_bytes)?;
//! let payload: &[u8] = code.payload();
//! # Ok::<(), roka_qr::Error>(())
//! ```
//!
//! # Highlights
//!
//! - **Zero external crate dependencies** — `std` only.
//! - **Encode and decode in one crate** — fills a gap on crates.io.
//! - **Self-contained image I/O** — PNG (encode + decode via built-in DEFLATE
//!   inflate) and PBM P1/P4.
//! - **Round-trip tested** against `qrencode` and `zbarimg`.
//! - **No `unsafe`**.
//!
//! [ISO/IEC 18004]: https://www.iso.org/standard/62021.html

// ───── internal modules (codec building blocks) ─────
mod bch;
mod decode;
mod deflate;
mod deflate_encode;
mod encode;
mod galois;
mod mask;
mod matrix;
mod pbm;
mod png;
mod reed_solomon;
mod render;
mod sampler;
mod tables;

// ───── public API ─────

pub use bch::EcLevel;
pub use tables::Version;

/// Errors produced by `roka-qr`.
///
/// All fallible operations in this crate return [`Result<T, Error>`]. Variants
/// are intentionally coarse — most callers only need to distinguish "the input
/// was malformed" from "the QR was readable but couldn't be recovered".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Payload is larger than what fits in QR version 40 at the chosen EC level.
    DataTooLarge,
    /// Image bytes are not a valid PNG / PBM / supported format.
    InvalidImage(&'static str),
    /// The QR code was found in the image, but its data could not be recovered
    /// (too many errors, or unsupported encoding mode).
    Corrupted(&'static str),
    /// The QR uses a feature this crate does not implement (e.g. kanji mode).
    Unsupported(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::DataTooLarge => f.write_str("data too large for QR (max version 40)"),
            Error::InvalidImage(msg) => write!(f, "invalid image: {msg}"),
            Error::Corrupted(msg) => write!(f, "corrupted QR code: {msg}"),
            Error::Unsupported(msg) => write!(f, "unsupported feature: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Builder for QR code generation.
///
/// # Example
///
/// ```
/// use roka_qr::{Encoder, EcLevel};
///
/// let code = Encoder::new(b"hello")
///     .ec_level(EcLevel::M)
///     .build()?;
/// assert_eq!(code.version().0, 1);
/// # Ok::<(), roka_qr::Error>(())
/// ```
pub struct Encoder<'a> {
    data: &'a [u8],
    ec_level: EcLevel,
}

impl<'a> Encoder<'a> {
    /// Start building a QR code for the given payload bytes.
    ///
    /// Byte mode is used; any 8-bit data is accepted (UTF-8 strings, otpauth
    /// URIs, arbitrary binary, etc.).
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            ec_level: EcLevel::M,
        }
    }

    /// Set the error-correction level (default `EcLevel::M`).
    pub fn ec_level(mut self, level: EcLevel) -> Self {
        self.ec_level = level;
        self
    }

    /// Encode and return a [`Code`].
    ///
    /// The smallest version that fits the data at the chosen EC level is
    /// selected automatically.
    pub fn build(self) -> Result<Code, Error> {
        let (matrix, version, mask) =
            encode::encode(self.data, self.ec_level).map_err(|_| Error::DataTooLarge)?;
        Ok(Code {
            matrix,
            version,
            ec_level: self.ec_level,
            mask,
            payload: None,
        })
    }
}

/// An encoded or decoded QR code.
///
/// Holds the full module matrix plus metadata (version, EC level, mask number).
/// Convert to a renderable image with [`Code::render`].
///
/// `payload` is populated by [`Reader`]; for codes returned from [`Encoder`]
/// the input bytes are not retained — refer to the original value instead.
#[derive(Clone)]
pub struct Code {
    matrix: matrix::Matrix,
    version: Version,
    ec_level: EcLevel,
    mask: u8,
    payload: Option<Vec<u8>>,
}

impl Code {
    /// QR version (1–40).
    pub fn version(&self) -> Version {
        self.version
    }

    /// Error-correction level used.
    pub fn ec_level(&self) -> EcLevel {
        self.ec_level
    }

    /// Mask pattern (0–7) selected by the encoder or recovered from format info.
    pub fn mask(&self) -> u8 {
        self.mask
    }

    /// Side length of the module matrix in modules. Equals `17 + 4 * version.0`.
    pub fn size(&self) -> usize {
        self.matrix.size
    }

    /// Read a single module. `true` = dark.
    pub fn module(&self, row: usize, col: usize) -> bool {
        self.matrix.get(row, col)
    }

    /// Recovered payload bytes (only meaningful for decoded codes).
    ///
    /// For codes returned by [`Encoder::build`] this is empty — the encoder does
    /// not retain the input.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_deref().unwrap_or(&[])
    }

    /// Start building a [`Bitmap`] from this code.
    pub fn render(&self) -> RenderBuilder<'_> {
        RenderBuilder {
            code: self,
            scale: 4,
            quiet_zone: 4,
        }
    }
}

/// Builder returned by [`Code::render`].
pub struct RenderBuilder<'a> {
    code: &'a Code,
    scale: usize,
    quiet_zone: usize,
}

impl<'a> RenderBuilder<'a> {
    /// Scale factor in pixels per module (default 4).
    pub fn scale(mut self, scale: usize) -> Self {
        self.scale = scale.max(1);
        self
    }

    /// Quiet-zone width in modules (default 4, the QR standard recommendation).
    pub fn quiet_zone(mut self, quiet: usize) -> Self {
        self.quiet_zone = quiet;
        self
    }

    /// Render the bitmap.
    pub fn build(self) -> Bitmap {
        let bm = render::render_to_bitmap(&self.code.matrix, self.scale, self.quiet_zone);
        Bitmap { inner: bm }
    }
}

/// A binary bitmap — `true` = dark pixel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    inner: pbm::Bitmap,
}

impl Bitmap {
    /// Image width in pixels.
    pub fn width(&self) -> usize {
        self.inner.width
    }

    /// Image height in pixels.
    pub fn height(&self) -> usize {
        self.inner.height
    }

    /// Pixel at (x, y); `true` = dark.
    pub fn pixel(&self, x: usize, y: usize) -> bool {
        self.inner.get(x, y)
    }

    /// Encode as PNG (8-bit grayscale).
    pub fn to_png(&self) -> Vec<u8> {
        png::encode_grayscale(&self.inner)
    }

    /// Encode as PBM P1 ASCII text.
    pub fn to_pbm(&self) -> String {
        pbm::write_p1(&self.inner)
    }
}

/// Decode a QR code from various input formats.
pub struct Reader;

impl Reader {
    /// Decode from PNG bytes.
    pub fn from_png(data: &[u8]) -> Result<Code, Error> {
        let bm = png::decode(data).map_err(Error::InvalidImage)?;
        Self::from_bitmap_internal(bm)
    }

    /// Decode from PBM bytes (P1 ASCII or P4 binary, auto-detected).
    pub fn from_pbm(data: &[u8]) -> Result<Code, Error> {
        let bm = pbm::read(data).map_err(Error::InvalidImage)?;
        Self::from_bitmap_internal(bm)
    }

    /// Decode from image bytes, auto-detecting PNG vs PBM via magic bytes.
    pub fn from_image_bytes(data: &[u8]) -> Result<Code, Error> {
        if data.len() >= 8 && &data[..8] == b"\x89PNG\r\n\x1A\n" {
            Self::from_png(data)
        } else {
            Self::from_pbm(data)
        }
    }

    fn from_bitmap_internal(bm: pbm::Bitmap) -> Result<Code, Error> {
        let matrix = sampler::matrix_from_bitmap(&bm).map_err(Error::Corrupted)?;
        let version = decode::version_from_size(matrix.size).map_err(Error::Corrupted)?;
        let (ec_level, mask) = decode::read_format_info(&matrix).map_err(Error::Corrupted)?;
        let payload = decode::decode(&matrix).map_err(Error::Corrupted)?;
        Ok(Code {
            matrix,
            version,
            ec_level,
            mask,
            payload: Some(payload),
        })
    }
}
