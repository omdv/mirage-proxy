use base64::{engine::general_purpose, Engine as _};
use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub start: usize,
    pub end: usize,
    pub matched_text: String,
    pub pattern_name: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum EntropyMode {
    Lenient,
    Balanced,
    Strict,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub enable_context_filter: bool,
    pub entropy_mode: EntropyMode,
    pub enable_obfuscation_analysis: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enable_context_filter: true,
            entropy_mode: EntropyMode::Balanced,
            enable_obfuscation_analysis: true,
        }
    }
}

static PASSWORD_IN_JSON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[\"']password[\"']\s*:\s*[\"']([^\"']{8,})[\"']"#).unwrap()
});
static PASSWORD_IN_YAML: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*password\s*:\s*(.+)$").unwrap());
static PASSWORD_ENV_VAR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(password|passwd|pwd)\b[\"']?\s*[:=]\s*[\"']?([^\s\"']{8,})[\"']?"#)
        .unwrap()
});
static GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(api[_\s\-]?key|secret|token|auth[_\s\-]?token|access[_\s\-]?token)\b[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9\-._~+/]{16,})[\"']?"#,
    )
    .unwrap()
});

static BASE64_CANDIDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}\b").unwrap());
static HEX_CANDIDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{32,}\b").unwrap());
static URL_ENCODED_CANDIDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"[\"']([^\"']*%[0-9A-Fa-f]{2}[^\"']*)[\"']"#).unwrap());
static CHAR_ARRAY_CANDIDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\[(?:\s*\d+\s*,){9,}\s*\d+\s*\]").unwrap());

pub fn scan_text(path: &str, content: &str) -> Vec<SecretFinding> {
    scan_text_with_config(path, content, &ScanConfig::default())
}

pub fn scan_text_with_config(path: &str, content: &str, config: &ScanConfig) -> Vec<SecretFinding> {
    if config.enable_context_filter && should_skip_path(path) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut offset = 0usize;

    for line in content.split_inclusive('\n') {
        let clean_line = line.strip_suffix('\n').unwrap_or(line);

        scan_line_pattern(
            &mut findings,
            clean_line,
            offset,
            "Password in JSON",
            &PASSWORD_IN_JSON,
            config,
        );
        scan_line_pattern(
            &mut findings,
            clean_line,
            offset,
            "Password in YAML",
            &PASSWORD_IN_YAML,
            config,
        );
        scan_line_pattern(
            &mut findings,
            clean_line,
            offset,
            "Password Environment Variable",
            &PASSWORD_ENV_VAR,
            config,
        );
        scan_line_pattern(
            &mut findings,
            clean_line,
            offset,
            "Generic Secret",
            &GENERIC_SECRET,
            config,
        );

        if config.enable_obfuscation_analysis {
            analyze_obfuscated_line(&mut findings, clean_line, offset, config);
        }

        offset += line.len();
    }

    findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    findings.dedup_by(|a, b| a.start == b.start && a.end == b.end);
    findings
}

fn scan_line_pattern(
    findings: &mut Vec<SecretFinding>,
    line: &str,
    line_offset: usize,
    pattern_name: &str,
    regex: &Regex,
    config: &ScanConfig,
) {
    for m in regex.find_iter(line) {
        let matched = m.as_str();

        if config.enable_context_filter && should_skip_line(line, matched) {
            continue;
        }

        let entropy = shannon_entropy(matched);
        if !include_by_entropy(pattern_name, matched, line, entropy, config.entropy_mode) {
            continue;
        }

        findings.push(SecretFinding {
            start: line_offset + m.start(),
            end: line_offset + m.end(),
            matched_text: matched.to_string(),
            pattern_name: pattern_name.to_string(),
        });
    }
}

fn analyze_obfuscated_line(
    findings: &mut Vec<SecretFinding>,
    line: &str,
    line_offset: usize,
    config: &ScanConfig,
) {
    for m in BASE64_CANDIDATE.find_iter(line) {
        let encoded = m.as_str();
        if !is_suspicious_base64(encoded, line) {
            continue;
        }

        if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                if decoded_looks_secret(&decoded_str, line) {
                    if config.enable_context_filter && should_skip_line(line, encoded) {
                        continue;
                    }

                    findings.push(SecretFinding {
                        start: line_offset + m.start(),
                        end: line_offset + m.end(),
                        matched_text: encoded.to_string(),
                        pattern_name: "Base64 Encoded Secret".to_string(),
                    });
                }
            }
        }
    }

    for m in HEX_CANDIDATE.find_iter(line) {
        let encoded = m.as_str();
        if !is_suspicious_hex(encoded, line) {
            continue;
        }

        if let Ok(decoded) = hex::decode(encoded) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                if decoded_looks_secret(&decoded_str, line) {
                    if config.enable_context_filter && should_skip_line(line, encoded) {
                        continue;
                    }

                    findings.push(SecretFinding {
                        start: line_offset + m.start(),
                        end: line_offset + m.end(),
                        matched_text: encoded.to_string(),
                        pattern_name: "Hex Encoded Secret".to_string(),
                    });
                }
            }
        }
    }

    for cap in URL_ENCODED_CANDIDATE.captures_iter(line) {
        let Some(url_match) = cap.get(1) else {
            continue;
        };
        let encoded = url_match.as_str();
        let decoded = encoded
            .replace("%3A", ":")
            .replace("%2F", "/")
            .replace("%40", "@")
            .replace("%3F", "?")
            .replace("%3D", "=")
            .replace("%26", "&");

        if decoded != encoded && decoded_looks_secret(&decoded, line) {
            if config.enable_context_filter && should_skip_line(line, encoded) {
                continue;
            }
            findings.push(SecretFinding {
                start: line_offset + url_match.start(),
                end: line_offset + url_match.end(),
                matched_text: encoded.to_string(),
                pattern_name: "URL Encoded Secret".to_string(),
            });
        }
    }

    for m in CHAR_ARRAY_CANDIDATE.find_iter(line) {
        let arr = m.as_str();
        let numbers: Vec<u8> = arr
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .filter_map(|s| s.trim().parse::<u8>().ok())
            .collect();

        if numbers.len() > 8 {
            if let Ok(decoded) = String::from_utf8(numbers) {
                if decoded_looks_secret(&decoded, line) {
                    if config.enable_context_filter && should_skip_line(line, arr) {
                        continue;
                    }
                    findings.push(SecretFinding {
                        start: line_offset + m.start(),
                        end: line_offset + m.end(),
                        matched_text: arr.to_string(),
                        pattern_name: "Character Array Encoded Secret".to_string(),
                    });
                }
            }
        }
    }
}

fn include_by_entropy(
    pattern_name: &str,
    matched_text: &str,
    line: &str,
    entropy: f64,
    mode: EntropyMode,
) -> bool {
    let base_threshold = match pattern_name {
        "Password in JSON" | "Password in YAML" | "Password Environment Variable" => {
            if looks_like_real_password(matched_text, line) {
                1.5
            } else {
                4.0
            }
        }
        "Generic Secret" => 3.0,
        _ => 3.0,
    };

    let adjustment = match mode {
        EntropyMode::Lenient => -0.5,
        EntropyMode::Balanced => 0.0,
        EntropyMode::Strict => 0.5,
    };

    entropy >= (base_threshold + adjustment)
        || has_strong_context_indicators(matched_text, line)
}

fn looks_like_real_password(password: &str, line: &str) -> bool {
    let p = password.to_lowercase();
    let line_lower = line.to_lowercase();

    let test_indicators = [
        "test",
        "dummy",
        "fake",
        "example",
        "sample",
        "placeholder",
        "password123",
        "secret123",
        "changeme",
        "default",
        "admin",
    ];
    if test_indicators
        .iter()
        .any(|i| p.contains(i) || line_lower.contains(i))
    {
        return false;
    }

    let has_numbers = password.chars().any(char::is_numeric);
    let has_special = password.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace());
    let has_mixed_case =
        password.chars().any(char::is_uppercase) && password.chars().any(char::is_lowercase);

    password.len() >= 8 && (has_numbers || has_special || has_mixed_case || has_strong_context_indicators(password, line))
}

fn has_strong_context_indicators(_matched_text: &str, line: &str) -> bool {
    let lower = line.to_lowercase();
    let positive = [
        "production",
        "prod",
        "live",
        "staging",
        "config",
        "env",
        "secret",
        "private",
        "credential",
        "auth",
        "api",
        "token",
        "password",
        "database",
    ];
    let negative = [
        "test",
        "spec",
        "example",
        "sample",
        "dummy",
        "fake",
        "placeholder",
        "mock",
        "fixture",
        "demo",
    ];

    if negative.iter().any(|i| lower.contains(i)) {
        return false;
    }

    positive.iter().any(|i| lower.contains(i))
}

fn should_skip_path(path: &str) -> bool {
    let p = path.to_lowercase();
    ["/test/", "/tests/", "/example/", "/examples/", "/docs/", "/spec/"]
        .iter()
        .any(|part| p.contains(part))
}

fn should_skip_line(line: &str, matched_text: &str) -> bool {
    let lower = line.to_lowercase();
    let matched = matched_text.to_lowercase();

    let test_keywords = [
        "test", "spec", "mock", "fake", "dummy", "example", "sample", "placeholder", "fixture", "stub", "demo",
    ];

    if test_keywords.iter().any(|k| lower.contains(k)) {
        return true;
    }

    ["password123", "secret123", "changeme", "default_", "example_", "sample_"]
        .iter()
        .any(|p| matched == *p || matched.starts_with(p))
}

fn is_suspicious_base64(b64: &str, line: &str) -> bool {
    let context = [
        "api", "key", "secret", "token", "password", "pass", "auth", "credential", "config", "env", "prod", "production",
    ];
    let lower = line.to_lowercase();
    let has_context = context.iter().any(|k| lower.contains(k));
    has_context && b64.len() >= 16 && b64.len() % 4 == 0
}

fn is_suspicious_hex(hex_str: &str, line: &str) -> bool {
    let context = [
        "api", "key", "secret", "token", "password", "pass", "auth", "credential", "config", "env", "prod", "production",
    ];
    let lower = line.to_lowercase();
    let has_context = context.iter().any(|k| lower.contains(k));
    has_context && hex_str.len() >= 32 && hex_str.len() % 2 == 0
}

fn decoded_looks_secret(decoded: &str, line: &str) -> bool {
    let value = decoded.trim();
    if value.len() < 8 || !value.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
        return false;
    }

    let prefixes = [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "AIza", "xox", "AKIA", "ASIA", "dop_v1_", "glpat-", "eyJ",
    ];
    if prefixes.iter().any(|p| value.starts_with(p)) {
        return true;
    }

    let lower_line = line.to_lowercase();
    let context = ["password", "secret", "token", "api", "key", "auth", "credential", "bearer"];
    if context.iter().any(|k| lower_line.contains(k)) {
        return true;
    }

    value.contains("://") && value.contains('@')
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut counts = std::collections::HashMap::<u8, usize>::new();
    for b in s.as_bytes() {
        *counts.entry(*b).or_insert(0) += 1;
    }

    counts.values().fold(0.0, |acc, count| {
        let p = *count as f64 / len;
        acc - p * p.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::scan_text;

    #[test]
    fn detects_password_assignment() {
        let text = "password: my_very_long_pass";
        let findings = scan_text("/tmp/prod.env", text);
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_base64_in_secret_context() {
        let text = "password: bXlfdmVyeV9sb25nX3Bhc3MK";
        let findings = scan_text("/tmp/prod.yaml", text);
        assert!(findings.iter().any(|f| f.pattern_name.contains("Base64") || f.pattern_name.contains("Password")));
    }
}
