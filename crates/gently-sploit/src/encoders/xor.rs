//! XOR Encoder

use super::Encoder;
use crate::Result;

pub struct XorEncoder {
    key: Vec<u8>,
}

impl XorEncoder {
    pub fn new() -> Self {
        Self { key: vec![0x41, 0x42, 0x43, 0x44] } // Default key
    }

    pub fn with_key(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl Encoder for XorEncoder {
    fn name(&self) -> &str {
        "xor"
    }

    fn encode(&self, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(payload.iter()
            .zip(self.key.iter().cycle())
            .map(|(a, b)| a ^ b)
            .collect())
    }

    fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        self.encode(encoded) // XOR is symmetric
    }

    fn decoder_stub(&self) -> Vec<u8> {
        // x86 XOR decoder stub
        vec![
            0xeb, 0x09,             // jmp short getpc
            0x5e,                   // pop esi
            0x31, 0xc9,             // xor ecx, ecx
            0xb1, 0x00,             // mov cl, <len>
            // decode:
            0x80, 0x36, 0x00,       // xor byte [esi], <key>
            0x46,                   // inc esi
            0xe2, 0xfa,             // loop decode
            0xeb, 0x05,             // jmp payload
            // getpc:
            0xe8, 0xf2, 0xff, 0xff, 0xff, // call getpc-5
        ]
    }
}
