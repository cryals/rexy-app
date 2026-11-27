use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn cli_version_cores_and_profile_import_validate_json() {
    let dir = tempdir().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_r3x");

    let ver_out = Command::new(exe)
        .env("R3X_DATA_DIR", dir.path())
        .args(["--json", "version"])
        .output()
        .expect("run r3x version");
    assert!(ver_out.status.success());
    let ver_json: Value = serde_json::from_slice(&ver_out.stdout).expect("valid version JSON");
    assert_eq!(ver_json["name"], "R3X");

    let cores_out = Command::new(exe)
        .env("R3X_DATA_DIR", dir.path())
        .args(["--json", "cores", "list"])
        .output()
        .expect("run r3x cores list");
    assert!(cores_out.status.success());
    let cores_json: Value = serde_json::from_slice(&cores_out.stdout).expect("valid cores JSON");
    assert_eq!(cores_json.as_array().map(Vec::len), Some(14));

    let info_out = Command::new(exe)
        .env("R3X_DATA_DIR", dir.path())
        .args(["--json", "cores", "info", "xray"])
        .output()
        .expect("run r3x cores info");
    assert!(info_out.status.success());
    let info_json: Value = serde_json::from_slice(&info_out.stdout).expect("valid core info");
    assert_eq!(info_json["id"], "xray");

    let uri = "vless://11111111-1111-1111-1111-111111111111@198.51.100.5:443#CLITestNode";
    let val_out = Command::new(exe)
        .env("R3X_DATA_DIR", dir.path())
        .args(["--json", "profiles", "validate", uri])
        .output()
        .expect("validate uri");
    assert!(val_out.status.success());

    let imp_out = Command::new(exe)
        .env("R3X_DATA_DIR", dir.path())
        .args(["--json", "profiles", "import", uri])
        .output()
        .expect("import uri");
    assert!(imp_out.status.success());

    let list_out = Command::new(exe)
        .env("R3X_DATA_DIR", dir.path())
        .args(["--json", "profiles", "list"])
        .output()
        .expect("list profiles");
    assert!(list_out.status.success());
    let list_json: Value = serde_json::from_slice(&list_out.stdout).expect("list json");
    assert_eq!(list_json.as_array().map(Vec::len), Some(1));
}
