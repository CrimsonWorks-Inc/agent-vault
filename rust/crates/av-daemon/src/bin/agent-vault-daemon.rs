//! `agent-vault-daemon`: the service entry point launchd and systemd start as
//! the `_agentvault` user. Ports `bin/agent-vault-daemon.js`; all of the work
//! is in [`av_daemon::run_from_env`].

fn main() {
    std::process::exit(av_daemon::run_from_env().code());
}
