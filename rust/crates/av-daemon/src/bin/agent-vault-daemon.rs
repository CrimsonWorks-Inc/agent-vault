//! `agent-vault-daemon`: the service entry point launchd and systemd start as
//! the `_agentvault` user. Ports `bin/agent-vault-daemon.js`; all of the work
//! is in [`av_daemon::run_from_env`].

fn main() {
    // launchd and systemd start it with no arguments; these are for people.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("agent-vault-daemon {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "agent-vault-daemon {}: the service the installer starts as the service user.\n\
             It takes no arguments; its settings come from the environment the\n\
             launchd plist or systemd unit sets. Run `agent-vault daemon` to run\n\
             one yourself, and `agent-vault -h` for every command.",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    std::process::exit(av_daemon::run_from_env().code());
}
