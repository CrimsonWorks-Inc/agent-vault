//! The daemon leaves no core file: startup sets RLIMIT_CORE to 0/0 before
//! it reads its environment, so a daemon started by hand is covered as well
//! as one under the service units (which set LimitCORE=0 themselves).

#[test]
fn startup_sets_the_core_file_limit_to_zero() {
    assert!(
        std::env::var_os("AV_VAULT_DIR").is_none(),
        "this test relies on startup stopping at the missing vault dir"
    );
    let before = av_daemon::peercred::core_limit().unwrap();
    assert_ne!(
        before.1, 0,
        "the test process starts with a core limit to lower"
    );
    let exit = av_daemon::run_from_env();
    assert!(
        matches!(exit, av_core::errors::Exit::Usage),
        "stopped early"
    );
    assert_eq!(av_daemon::peercred::core_limit().unwrap(), (0, 0));
}
