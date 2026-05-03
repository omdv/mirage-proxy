use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const NONCE_LEN: usize = 12;
pub const AUDIT_KEY_LEN: usize = 32;
const AUDIT_ENC_PREFIX: &str = "enc:";
const TRAIL_MAX_FIELD_CHARS: usize = 800;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacementRecord {
    pub original: String,
    pub replaced: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub local_url: String,
    pub remote_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub has_replacements: bool,
    #[serde(default)]
    pub replacements: Vec<ReplacementRecord>,
}

pub struct AuditLog {
    path: PathBuf,
    encrypted: bool,
    cipher: Option<Aes256Gcm>,
    max_size_bytes: u64,
    rotate_keep: usize,
    max_age_days: u64,
    writes_since_trim: Mutex<u32>,
    file: Mutex<Option<std::fs::File>>,
}

impl AuditLog {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        _log_values: bool,
        encrypted: bool,
        key: Option<[u8; AUDIT_KEY_LEN]>,
        max_size_mb: u64,
        rotate_keep: usize,
        max_age_days: u64,
    ) -> Result<Self, String> {
        let file = OpenOptions::new().create(true).append(true).open(&path).ok();

        let cipher = if encrypted {
            let key = key.ok_or_else(|| {
                "Audit encryption enabled but no key provided. Use --vault-key or MIRAGE_VAULT_KEY."
                    .to_string()
            })?;
            Some(Aes256Gcm::new_from_slice(&key).map_err(|e| format!("invalid audit key: {}", e))?)
        } else {
            None
        };

        Ok(Self {
            path,
            encrypted,
            cipher,
            max_size_bytes: max_size_mb.saturating_mul(1024 * 1024),
            rotate_keep,
            max_age_days,
            writes_since_trim: Mutex::new(0),
            file: Mutex::new(file),
        })
    }

    pub fn is_encrypted_line(line: &str) -> bool {
        line.starts_with(AUDIT_ENC_PREFIX)
    }

    fn encrypt_line(&self, plaintext: &str) -> Result<String, String> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| "audit cipher missing".to_string())?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("encrypt audit line: {}", e))?;

        let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        Ok(format!(
            "{}{}",
            AUDIT_ENC_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(payload)
        ))
    }

    pub fn decrypt_audit_line(line: &str, key: &[u8; AUDIT_KEY_LEN]) -> Result<String, String> {
        let payload_b64 = line
            .strip_prefix(AUDIT_ENC_PREFIX)
            .ok_or_else(|| "line is not encrypted".to_string())?;

        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|e| format!("base64 decode: {}", e))?;

        if payload.len() < NONCE_LEN {
            return Err("encrypted audit line too short".to_string());
        }

        let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "decryption failed (wrong key?)".to_string())?;

        String::from_utf8(plaintext).map_err(|e| format!("utf8 decode: {}", e))
    }

    fn trim_if_needed(&self) {
        let mut writes = match self.writes_since_trim.lock() {
            Ok(v) => v,
            Err(_) => return,
        };
        *writes += 1;
        if *writes < 100 {
            return;
        }
        *writes = 0;

        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return,
        };

        if self.max_size_bytes > 0 && meta.len() > self.max_size_bytes {
            let _ = self.rotate_files();
        }

        self.prune_old_rotations();
    }

    fn rotate_files(&self) -> Result<(), String> {
        if self.rotate_keep == 0 {
            let _ = std::fs::write(&self.path, b"");
            return Ok(());
        }

        if let Ok(mut guard) = self.file.lock() {
            *guard = None;
        }

        for i in (1..=self.rotate_keep).rev() {
            let src = if i == 1 {
                self.path.clone()
            } else {
                PathBuf::from(format!("{}.{}", self.path.display(), i - 1))
            };
            let dst = PathBuf::from(format!("{}.{}", self.path.display(), i));
            if src.exists() {
                let _ = std::fs::rename(&src, &dst);
            }
        }

        if let Ok(mut guard) = self.file.lock() {
            *guard = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }

        Ok(())
    }

    fn prune_old_rotations(&self) {
        if self.max_age_days == 0 {
            return;
        }

        let max_age = std::time::Duration::from_secs(self.max_age_days.saturating_mul(24 * 3600));
        let now = std::time::SystemTime::now();

        for i in 1..=self.rotate_keep.max(1) {
            let p = PathBuf::from(format!("{}.{}", self.path.display(), i));
            if !p.exists() {
                continue;
            }
            if let Ok(meta) = std::fs::metadata(&p) {
                if let Ok(modified) = meta.modified() {
                    if let Ok(age) = now.duration_since(modified) {
                        if age > max_age {
                            let _ = std::fs::remove_file(&p);
                        }
                    }
                }
            }
        }
    }

    fn write_entry(&self, entry: &AuditEntry) {
        if let Ok(json) = serde_json::to_string(entry) {
            let line = if self.encrypted {
                match self.encrypt_line(&json) {
                    Ok(v) => v,
                    Err(_) => return,
                }
            } else {
                json
            };

            if let Ok(mut guard) = self.file.lock() {
                if let Some(ref mut f) = *guard {
                    let _ = writeln!(f, "{}", line);
                }
            }

            self.trim_if_needed();
        }
    }

    pub fn log_call(
        &self,
        local_url: &str,
        remote_url: &str,
        session_id: Option<&str>,
        model: Option<&str>,
        replacements: Vec<ReplacementRecord>,
    ) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            local_url: truncate_chars(local_url, TRAIL_MAX_FIELD_CHARS),
            remote_url: truncate_chars(remote_url, TRAIL_MAX_FIELD_CHARS),
            session_id: session_id.map(|v| truncate_chars(v, TRAIL_MAX_FIELD_CHARS)),
            model: model.map(|v| truncate_chars(v, TRAIL_MAX_FIELD_CHARS)),
            has_replacements: !replacements.is_empty(),
            replacements: replacements
                .into_iter()
                .map(|r| ReplacementRecord {
                    original: truncate_chars(&r.original, TRAIL_MAX_FIELD_CHARS),
                    replaced: truncate_chars(&r.replaced, TRAIL_MAX_FIELD_CHARS),
                })
                .collect(),
        };

        self.write_entry(&entry);
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let head_len = max_chars / 2;
    let tail_len = max_chars - head_len;
    let head: String = s.chars().take(head_len).collect();
    let tail: String = s
        .chars()
        .rev()
        .take(tail_len)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{} …[snip]… {}", head, tail)
}
