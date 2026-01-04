//!
#![allow(dead_code, unused_imports, unused_variables)]
//! Cipher-Mesh: GentlyOS Cryptanalysis Toolkit
//!
//! Cipher identification, encoding/decoding, frequency analysis.
//! Based on dcode.fr tools + custom implementations.
//!
//! # Modules
//! - `identifier` - Auto-detect cipher/encoding/hash types
//! - `encodings` - Base64, Hex, Binary, Morse, ROT13, etc.
//! - `ciphers` - Caesar, Vigenère, Atbash, Affine, etc.
//! - `analysis` - Frequency analysis, IoC, Chi-squared
//! - `hashes` - MD5, SHA-1, SHA-256, SHA-512
//! - `cracker` - John the Ripper style password cracking
//! - `rainbow` - Rainbow table generation and lookup

pub mod identifier;
pub mod encodings;
pub mod ciphers;
pub mod analysis;
pub mod hashes;
pub mod cracker;
pub mod rainbow;

pub use identifier::{CipherIdentifier, CipherMatch, Confidence};
pub use encodings::Encoding;
pub use ciphers::Cipher;
pub use analysis::FrequencyAnalysis;
pub use hashes::{Hashes, HashIdentifier};
pub use cracker::{Cracker, HashType, Rule, Wordlist, BruteForce};
pub use rainbow::{RainbowTable, RainbowHashType, TableGenerator, OnlineLookup};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown cipher type")]
    UnknownCipher,

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    #[error("IO error: {0}")]
    IoError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// All supported cipher/encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherType {
    // Modern Crypto
    MD5,
    SHA1,
    SHA256,
    SHA512,
    BCrypt,

    // Encodings
    Base64,
    Base32,
    Base58,
    Hex,
    Binary,
    Ascii85,
    ROT13,
    ROT47,

    // Classic Ciphers
    Caesar,
    Vigenere,
    Atbash,
    Affine,
    Playfair,
    RailFence,
    Columnar,

    // Substitution
    Morse,
    Bacon,
    Polybius,
    Pigpen,

    // XOR
    XOR,

    // Unknown
    Unknown,
}

impl CipherType {
    pub fn name(&self) -> &'static str {
        match self {
            CipherType::MD5 => "MD5 Hash",
            CipherType::SHA1 => "SHA-1 Hash",
            CipherType::SHA256 => "SHA-256 Hash",
            CipherType::SHA512 => "SHA-512 Hash",
            CipherType::BCrypt => "BCrypt Hash",
            CipherType::Base64 => "Base64 Encoding",
            CipherType::Base32 => "Base32 Encoding",
            CipherType::Base58 => "Base58 Encoding",
            CipherType::Hex => "Hexadecimal",
            CipherType::Binary => "Binary",
            CipherType::Ascii85 => "ASCII85 Encoding",
            CipherType::ROT13 => "ROT13 Cipher",
            CipherType::ROT47 => "ROT47 Cipher",
            CipherType::Caesar => "Caesar Cipher",
            CipherType::Vigenere => "Vigenère Cipher",
            CipherType::Atbash => "Atbash Cipher",
            CipherType::Affine => "Affine Cipher",
            CipherType::Playfair => "Playfair Cipher",
            CipherType::RailFence => "Rail Fence Cipher",
            CipherType::Columnar => "Columnar Transposition",
            CipherType::Morse => "Morse Code",
            CipherType::Bacon => "Bacon Cipher",
            CipherType::Polybius => "Polybius Square",
            CipherType::Pigpen => "Pigpen Cipher",
            CipherType::XOR => "XOR Cipher",
            CipherType::Unknown => "Unknown",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            CipherType::MD5 | CipherType::SHA1 | CipherType::SHA256 |
            CipherType::SHA512 | CipherType::BCrypt => "Hash",

            CipherType::Base64 | CipherType::Base32 | CipherType::Base58 |
            CipherType::Hex | CipherType::Binary | CipherType::Ascii85 => "Encoding",

            CipherType::ROT13 | CipherType::ROT47 | CipherType::Caesar |
            CipherType::Atbash | CipherType::Affine => "Substitution",

            CipherType::Vigenere | CipherType::Playfair => "Polyalphabetic",

            CipherType::RailFence | CipherType::Columnar => "Transposition",

            CipherType::Morse | CipherType::Bacon | CipherType::Polybius |
            CipherType::Pigpen => "Symbol",

            CipherType::XOR => "Modern",

            CipherType::Unknown => "Unknown",
        }
    }
}
