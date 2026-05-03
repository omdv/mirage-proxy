use mirage_proxy::audit::{AuditEntry, AuditLog, ReplacementRecord};
use std::fs;
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mirage-audit-test-{}-{}.jsonl",
        name,
        uuid::Uuid::new_v4()
    ));
    p
}

#[test]
fn log_call_with_replacements() {
    let path = temp_path("call");
    let log = AuditLog::new(path.clone(), true, false, None, 10, 1, 1).unwrap();

    log.log_call(
        "http://localhost:8687/openrouter/api/v1/chat/completions",
        "https://openrouter.ai/api/v1/chat/completions",
        Some("session-1"),
        Some("openai/gpt-4o-mini"),
        vec![ReplacementRecord {
            original: "alice@example.com".to_string(),
            replaced: "bob@example.com".to_string(),
        }],
    );

    let content = fs::read_to_string(&path).unwrap();
    let line = content.lines().next().unwrap();
    let entry: AuditEntry = serde_json::from_str(line).unwrap();

    assert_eq!(entry.local_url, "http://localhost:8687/openrouter/api/v1/chat/completions");
    assert_eq!(entry.remote_url, "https://openrouter.ai/api/v1/chat/completions");
    assert_eq!(entry.model.as_deref(), Some("openai/gpt-4o-mini"));
    assert!(entry.has_replacements);
    assert_eq!(entry.replacements.len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn log_call_without_replacements() {
    let path = temp_path("call-empty");
    let log = AuditLog::new(path.clone(), true, false, None, 10, 1, 1).unwrap();

    log.log_call(
        "http://localhost:8687/openai/v1/chat/completions",
        "https://api.openai.com/v1/chat/completions",
        None,
        None,
        vec![],
    );

    let content = fs::read_to_string(&path).unwrap();
    let line = content.lines().next().unwrap();
    let entry: AuditEntry = serde_json::from_str(line).unwrap();

    assert!(!entry.has_replacements);
    assert!(entry.replacements.is_empty());

    let _ = fs::remove_file(path);
}
