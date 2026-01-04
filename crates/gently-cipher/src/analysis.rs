//! Cryptanalysis Tools
//!
//! Frequency analysis, Index of Coincidence, bigrams/trigrams

use std::collections::HashMap;

/// Frequency analysis for cryptanalysis
pub struct FrequencyAnalysis {
    pub frequencies: HashMap<char, usize>,
    pub total_chars: usize,
    pub bigrams: HashMap<String, usize>,
    pub trigrams: HashMap<String, usize>,
}

impl FrequencyAnalysis {
    /// Analyze text for frequency patterns
    pub fn analyze(text: &str) -> Self {
        let mut frequencies: HashMap<char, usize> = HashMap::new();
        let mut bigrams: HashMap<String, usize> = HashMap::new();
        let mut trigrams: HashMap<String, usize> = HashMap::new();
        let mut total_chars = 0;

        let chars: Vec<char> = text.to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect();

        // Single character frequency
        for &c in &chars {
            *frequencies.entry(c).or_insert(0) += 1;
            total_chars += 1;
        }

        // Bigrams
        for window in chars.windows(2) {
            let bigram: String = window.iter().collect();
            *bigrams.entry(bigram).or_insert(0) += 1;
        }

        // Trigrams
        for window in chars.windows(3) {
            let trigram: String = window.iter().collect();
            *trigrams.entry(trigram).or_insert(0) += 1;
        }

        Self {
            frequencies,
            total_chars,
            bigrams,
            trigrams,
        }
    }

    /// Get frequency as percentage
    pub fn frequency_percent(&self, c: char) -> f64 {
        let count = *self.frequencies.get(&c.to_ascii_uppercase()).unwrap_or(&0);
        if self.total_chars > 0 {
            (count as f64 / self.total_chars as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Calculate Index of Coincidence
    /// English text ≈ 0.067, random ≈ 0.038
    pub fn index_of_coincidence(&self) -> f64 {
        if self.total_chars < 2 {
            return 0.0;
        }

        let sum: usize = self.frequencies.values()
            .map(|&n| n * (n - 1))
            .sum();

        let n = self.total_chars;
        sum as f64 / (n * (n - 1)) as f64
    }

    /// Get top N most frequent characters
    pub fn top_chars(&self, n: usize) -> Vec<(char, usize)> {
        let mut sorted: Vec<_> = self.frequencies.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(n).map(|(&c, &n)| (c, n)).collect()
    }

    /// Get top N bigrams
    pub fn top_bigrams(&self, n: usize) -> Vec<(String, usize)> {
        let mut sorted: Vec<_> = self.bigrams.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(n).map(|(s, &n)| (s.clone(), n)).collect()
    }

    /// Get top N trigrams
    pub fn top_trigrams(&self, n: usize) -> Vec<(String, usize)> {
        let mut sorted: Vec<_> = self.trigrams.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        sorted.into_iter().take(n).map(|(s, &n)| (s.clone(), n)).collect()
    }

    /// Chi-squared test against English frequencies
    pub fn chi_squared_english(&self) -> f64 {
        let english_freq: [f64; 26] = [
            0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002,
            0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091,
            0.028, 0.010, 0.024, 0.002, 0.020, 0.001,
        ];

        let mut chi_sq = 0.0;
        for (i, &expected) in english_freq.iter().enumerate() {
            let c = (b'A' + i as u8) as char;
            let observed = *self.frequencies.get(&c).unwrap_or(&0) as f64 / self.total_chars as f64;
            if expected > 0.0 {
                chi_sq += (observed - expected).powi(2) / expected;
            }
        }
        chi_sq
    }

    /// Estimate Vigenère key length using Kasiski examination
    pub fn kasiski_examination(&self, text: &str) -> Vec<usize> {
        let chars: Vec<char> = text.to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect();

        let mut distances: HashMap<String, Vec<usize>> = HashMap::new();

        // Find repeated trigrams
        for i in 0..chars.len().saturating_sub(2) {
            let trigram: String = chars[i..i+3].iter().collect();
            distances.entry(trigram).or_default().push(i);
        }

        // Calculate GCDs of distances
        let mut gcds: HashMap<usize, usize> = HashMap::new();
        for positions in distances.values().filter(|p| p.len() > 1) {
            for window in positions.windows(2) {
                let dist = window[1] - window[0];
                for divisor in 2..=dist.min(20) {
                    if dist % divisor == 0 {
                        *gcds.entry(divisor).or_insert(0) += 1;
                    }
                }
            }
        }

        // Sort by frequency
        let mut sorted: Vec<_> = gcds.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.into_iter().take(5).map(|(k, _)| k).collect()
    }

    /// Render as ASCII frequency chart
    pub fn render_ascii(&self) -> String {
        let mut lines = Vec::new();
        lines.push("FREQUENCY ANALYSIS".to_string());
        lines.push("═".repeat(40));

        let max_count = *self.frequencies.values().max().unwrap_or(&1);
        let scale = 30.0 / max_count as f64;

        for c in 'A'..='Z' {
            let count = *self.frequencies.get(&c).unwrap_or(&0);
            let bar_len = (count as f64 * scale) as usize;
            let bar = "█".repeat(bar_len);
            let pct = self.frequency_percent(c);
            lines.push(format!("{}: {:5.2}% |{}", c, pct, bar));
        }

        lines.push(String::new());
        lines.push(format!("Index of Coincidence: {:.4}", self.index_of_coincidence()));
        lines.push(format!("Chi-squared (English): {:.4}", self.chi_squared_english()));

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_analysis() {
        let analysis = FrequencyAnalysis::analyze("HELLO WORLD");
        assert_eq!(analysis.total_chars, 10);
        assert_eq!(*analysis.frequencies.get(&'L').unwrap_or(&0), 3);
    }

    #[test]
    fn test_ioc_english() {
        // Natural English text should have IoC around 0.067
        // Use a sentence with more repetition than a pangram
        let english = "TO BE OR NOT TO BE THAT IS THE QUESTION WHETHER TIS NOBLER";
        let analysis = FrequencyAnalysis::analyze(english);
        let ioc = analysis.index_of_coincidence();
        assert!(ioc > 0.05 && ioc < 0.10, "IoC was {}", ioc);
    }

    #[test]
    fn test_top_chars() {
        let analysis = FrequencyAnalysis::analyze("AAABBC");
        let top = analysis.top_chars(2);
        assert_eq!(top[0].0, 'A');
        assert_eq!(top[1].0, 'B');
    }
}
