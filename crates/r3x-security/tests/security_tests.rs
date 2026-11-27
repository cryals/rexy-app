use proptest::prelude::*;
use r3x_domain::{DiagnosticCheckId, DiagnosticReport, DiagnosticResult, DiagnosticStatus};
use r3x_security::{
    ArchiveLimits, Redactor, compute_sha256_bytes, decrypt_backup, encrypt_backup,
    extract_zip_safely, generate_ipc_token, sanitize_filename, validate_remote_subscription_url,
    verify_ipc_token, verify_sha256_file,
};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;

#[test]
fn redacts_uris_json_ini_and_diagnostics() {
    let raw = r#"connecting vless://11111111-2222-3333-4444-555555555555@example.com:443?pbk=secretPubKey&sid=abcd#Node {"password":"mySecretPassword","token":"tok123"} PrivateKey = myWgPrivKey Authorization: Bearer abcdef123456"#;
    let redacted = Redactor::redact_str(raw);
    assert!(!redacted.contains("11111111-2222-3333-4444-555555555555"));
    assert!(!redacted.contains("secretPubKey"));
    assert!(!redacted.contains("mySecretPassword"));
    assert!(!redacted.contains("tok123"));
    assert!(!redacted.contains("abcdef123456"));
    assert!(redacted.contains("[REDACTED]"));

    let report = DiagnosticReport {
        generated_at: chrono::Utc::now(),
        platform: "windows".to_owned(),
        app_version: "0.1.0".to_owned(),
        results: vec![DiagnosticResult {
            check_id: DiagnosticCheckId::TlsConnectivity,
            status: DiagnosticStatus::Failed,
            summary: "failed for trojan://topsecret@host:443".to_owned(),
            technical_details: r#"{"password":"hunter2"}"#.to_owned(),
            suggested_actions: vec![],
            related_settings_section: None,
            duration_ms: Some(12),
        }],
    };
    let clean = Redactor::redact_diagnostic_report(&report);
    assert!(!clean.results[0].summary.contains("topsecret"));
    assert!(!clean.results[0].technical_details.contains("hunter2"));
}

#[test]
fn rejects_zip_path_traversal_and_size_bombs() {
    let dir = tempdir().expect("tempdir");
    let zip_path = dir.path().join("evil.zip");
    {
        let f = File::create(&zip_path).expect("create zip");
        let mut zw = zip::ZipWriter::new(f);
        zw.start_file("../escape.txt", SimpleFileOptions::default())
            .expect("start file");
        zw.write_all(b"evil").expect("write");
        zw.finish().expect("finish");
    }
    let out = dir.path().join("out");
    let res = extract_zip_safely(&zip_path, &out, ArchiveLimits::default());
    assert!(res.is_err());
    assert!(!dir.path().join("escape.txt").exists());

    // Size bomb limit enforcement
    let bomb_zip = dir.path().join("bomb.zip");
    {
        let f = File::create(&bomb_zip).expect("create bomb zip");
        let mut zw = zip::ZipWriter::new(f);
        zw.start_file("big.bin", SimpleFileOptions::default())
            .expect("start");
        zw.write_all(&[b'A'; 4096]).expect("write");
        zw.finish().expect("finish");
    }
    let small_limits = ArchiveLimits {
        max_file_count: 10,
        max_total_bytes: 1024,
        max_single_file_bytes: 1024,
    };
    assert!(extract_zip_safely(&bomb_zip, &dir.path().join("out2"), small_limits).is_err());
}

#[test]
fn sha256_integrity_and_encrypted_backup_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("core.bin");
    std::fs::write(&file_path, b"r3x-verified-binary").expect("write");
    let expected = compute_sha256_bytes(b"r3x-verified-binary");
    assert!(verify_sha256_file(&file_path, &expected).is_ok());
    assert!(verify_sha256_file(&file_path, &"0".repeat(64)).is_err());

    let env = encrypt_backup(b"sensitive-backup-json", "StrongPass123!").expect("encrypt");
    let plain = decrypt_backup(&env, "StrongPass123!").expect("decrypt");
    assert_eq!(plain, b"sensitive-backup-json");
    assert!(decrypt_backup(&env, "WrongPass123!").is_err());

    let tok = generate_ipc_token();
    assert!(verify_ipc_token(&tok, &tok));
    assert!(!verify_ipc_token(&tok, "bad-token"));
}

#[test]
fn subscription_url_validation_blocks_dangerous_schemes() {
    assert!(validate_remote_subscription_url("https://example.com/sub").is_ok());
    assert!(validate_remote_subscription_url("file:///etc/passwd").is_err());
    assert!(validate_remote_subscription_url("javascript:alert(1)").is_err());
}

proptest! {
    #[test]
    fn sanitize_filename_never_produces_traversal(s in ".*") {
        let safe = sanitize_filename(&s);
        prop_assert!(!safe.is_empty());
        prop_assert!(!safe.contains(".."));
        prop_assert!(!safe.contains('/'));
        prop_assert!(!safe.contains('\\'));
        prop_assert!(Path::new(&safe).components().count() == 1);
    }
}
