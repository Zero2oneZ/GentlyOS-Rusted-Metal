//! Encoding/Decoding operations
//!
//! Base64, Base32, Base58, Hex, Binary, ASCII85, ROT13, ROT47

use crate::{Error, Result};

pub struct Encoding;

impl Encoding {
    // ═══════════════════════════════════════════════════════════
    // BASE64
    // ═══════════════════════════════════════════════════════════

    pub fn base64_encode(input: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, input)
    }

    pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input)
            .map_err(|e| Error::DecodingFailed(format!("Base64: {}", e)))
    }

    // ═══════════════════════════════════════════════════════════
    // HEX
    // ═══════════════════════════════════════════════════════════

    pub fn hex_encode(input: &[u8]) -> String {
        hex::encode(input)
    }

    pub fn hex_decode(input: &str) -> Result<Vec<u8>> {
        hex::decode(input)
            .map_err(|e| Error::DecodingFailed(format!("Hex: {}", e)))
    }

    // ═══════════════════════════════════════════════════════════
    // BINARY
    // ═══════════════════════════════════════════════════════════

    pub fn binary_encode(input: &[u8]) -> String {
        input.iter()
            .map(|b| format!("{:08b}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn binary_decode(input: &str) -> Result<Vec<u8>> {
        input
            .split_whitespace()
            .map(|s| {
                u8::from_str_radix(s, 2)
                    .map_err(|e| Error::DecodingFailed(format!("Binary: {}", e)))
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════
    // BASE58 (Bitcoin)
    // ═══════════════════════════════════════════════════════════

    pub fn base58_encode(input: &[u8]) -> String {
        bs58::encode(input).into_string()
    }

    pub fn base58_decode(input: &str) -> Result<Vec<u8>> {
        bs58::decode(input)
            .into_vec()
            .map_err(|e| Error::DecodingFailed(format!("Base58: {}", e)))
    }

    // ═══════════════════════════════════════════════════════════
    // ROT13
    // ═══════════════════════════════════════════════════════════

    pub fn rot13(input: &str) -> String {
        input.chars().map(|c| {
            match c {
                'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
                'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
                _ => c,
            }
        }).collect()
    }

    // ═══════════════════════════════════════════════════════════
    // ROT47
    // ═══════════════════════════════════════════════════════════

    pub fn rot47(input: &str) -> String {
        input.chars().map(|c| {
            let code = c as u8;
            if code >= 33 && code <= 126 {
                (((code - 33 + 47) % 94) + 33) as char
            } else {
                c
            }
        }).collect()
    }

    // ═══════════════════════════════════════════════════════════
    // MORSE CODE
    // ═══════════════════════════════════════════════════════════

    pub fn morse_encode(input: &str) -> String {
        input.to_uppercase().chars().map(|c| {
            match c {
                'A' => ".-", 'B' => "-...", 'C' => "-.-.", 'D' => "-..",
                'E' => ".", 'F' => "..-.", 'G' => "--.", 'H' => "....",
                'I' => "..", 'J' => ".---", 'K' => "-.-", 'L' => ".-..",
                'M' => "--", 'N' => "-.", 'O' => "---", 'P' => ".--.",
                'Q' => "--.-", 'R' => ".-.", 'S' => "...", 'T' => "-",
                'U' => "..-", 'V' => "...-", 'W' => ".--", 'X' => "-..-",
                'Y' => "-.--", 'Z' => "--..",
                '0' => "-----", '1' => ".----", '2' => "..---",
                '3' => "...--", '4' => "....-", '5' => ".....",
                '6' => "-....", '7' => "--...", '8' => "---..",
                '9' => "----.",
                ' ' => "/",
                _ => "",
            }
        }).collect::<Vec<_>>().join(" ")
    }

    pub fn morse_decode(input: &str) -> Result<String> {
        input
            .split(" / ")
            .map(|word| {
                word.split_whitespace()
                    .map(|code| {
                        match code {
                            ".-" => Ok('A'), "-..." => Ok('B'), "-.-." => Ok('C'),
                            "-.." => Ok('D'), "." => Ok('E'), "..-." => Ok('F'),
                            "--." => Ok('G'), "...." => Ok('H'), ".." => Ok('I'),
                            ".---" => Ok('J'), "-.-" => Ok('K'), ".-.." => Ok('L'),
                            "--" => Ok('M'), "-." => Ok('N'), "---" => Ok('O'),
                            ".--." => Ok('P'), "--.-" => Ok('Q'), ".-." => Ok('R'),
                            "..." => Ok('S'), "-" => Ok('T'), "..-" => Ok('U'),
                            "...-" => Ok('V'), ".--" => Ok('W'), "-..-" => Ok('X'),
                            "-.--" => Ok('Y'), "--.." => Ok('Z'),
                            "-----" => Ok('0'), ".----" => Ok('1'), "..---" => Ok('2'),
                            "...--" => Ok('3'), "....-" => Ok('4'), "....." => Ok('5'),
                            "-...." => Ok('6'), "--..." => Ok('7'), "---.." => Ok('8'),
                            "----." => Ok('9'),
                            "/" => Ok(' '),
                            _ => Err(Error::DecodingFailed(format!("Unknown morse: {}", code))),
                        }
                    })
                    .collect::<Result<String>>()
            })
            .collect::<Result<Vec<_>>>()
            .map(|words| words.join(" "))
    }

    // ═══════════════════════════════════════════════════════════
    // URL ENCODING
    // ═══════════════════════════════════════════════════════════

    pub fn url_encode(input: &str) -> String {
        input.chars().map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        }).collect()
    }

    pub fn url_decode(input: &str) -> Result<String> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    } else {
                        return Err(Error::DecodingFailed(format!("Invalid URL encoding: %{}", hex)));
                    }
                }
            } else if c == '+' {
                result.push(' ');
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64() {
        let original = b"Hello World";
        let encoded = Encoding::base64_encode(original);
        assert_eq!(encoded, "SGVsbG8gV29ybGQ=");

        let decoded = Encoding::base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_rot13() {
        assert_eq!(Encoding::rot13("Hello"), "Uryyb");
        assert_eq!(Encoding::rot13("Uryyb"), "Hello");
    }

    #[test]
    fn test_morse() {
        let encoded = Encoding::morse_encode("SOS");
        assert_eq!(encoded, "... --- ...");

        let decoded = Encoding::morse_decode("... --- ...").unwrap();
        assert_eq!(decoded, "SOS");
    }

    #[test]
    fn test_binary() {
        let encoded = Encoding::binary_encode(b"Hi");
        assert_eq!(encoded, "01001000 01101001");

        let decoded = Encoding::binary_decode(&encoded).unwrap();
        assert_eq!(decoded, b"Hi");
    }
}
