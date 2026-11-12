//! `write_all_mode` restores mode 0600 when the process umask would not.

use std::os::unix::fs::PermissionsExt;

#[test]
fn write_all_mode_restores_0600_under_umask_0377() {
    if std::env::var("AV_UMASK_PROBE").ok().as_deref() == Some("1") {
        let path = std::env::var("AV_UMASK_PATH").expect("AV_UMASK_PATH");
        av_cli::files::write_file_exclusive(
            std::path::Path::new(&path),
            "not-a-real-secret\n",
            false,
            0o600,
        )
        .expect("write");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("secret");
    let exe = std::env::current_exe().unwrap();
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"umask 0377; exec "$0" "$@""#)
        .arg(&exe)
        .arg("--exact")
        .arg("write_all_mode_restores_0600_under_umask_0377")
        .env("AV_UMASK_PROBE", "1")
        .env("AV_UMASK_PATH", &dest)
        .env_remove("AV_RUN_DIR")
        .status()
        .unwrap();
    assert!(status.success(), "child exited {status}");
    let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode is {mode:o}");
}
