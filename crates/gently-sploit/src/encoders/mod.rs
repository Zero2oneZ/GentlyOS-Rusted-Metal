//! Payload Encoders

pub mod xor;
pub mod base64;

use crate::Result;

pub trait Encoder: Send + Sync {
    fn name(&self) -> &str;
    fn encode(&self, payload: &[u8]) -> Result<Vec<u8>>;
    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>>;
    fn decoder_stub(&self) -> Vec<u8>;
}

/// Encoder chain - apply multiple encoders
pub struct EncoderChain {
    encoders: Vec<Box<dyn Encoder>>,
}

impl EncoderChain {
    pub fn new() -> Self {
        Self { encoders: Vec::new() }
    }

    pub fn add(&mut self, encoder: Box<dyn Encoder>) {
        self.encoders.push(encoder);
    }

    pub fn encode(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut result = payload.to_vec();
        for encoder in &self.encoders {
            result = encoder.encode(&result)?;
        }
        Ok(result)
    }
}
