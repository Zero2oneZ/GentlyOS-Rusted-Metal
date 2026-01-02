//! Base64 Encoder

use super::Encoder;
use crate::Result;
use ::base64::Engine;

pub struct Base64Encoder;

impl Base64Encoder {
    pub fn new() -> Self {
        Self
    }
}

impl Encoder for Base64Encoder {
    fn name(&self) -> &str {
        "base64"
    }

    fn encode(&self, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(::base64::engine::general_purpose::STANDARD.encode(payload).into_bytes())
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let s = std::str::from_utf8(encoded)
            .map_err(|e| crate::Error::PayloadFailed(e.to_string()))?;
        ::base64::engine::general_purpose::STANDARD.decode(s)
            .map_err(|e| crate::Error::PayloadFailed(e.to_string()))
    }

    fn decoder_stub(&self) -> Vec<u8> {
        // PowerShell base64 decode stub
        b"powershell -e ".to_vec()
    }
}
