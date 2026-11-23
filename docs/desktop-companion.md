# Desktop companion: design note

Status: prototype, version 0.2, on branch `desktop-companion`. macOS first; the code compiles for Windows and Linux, but only macOS has been run.

## Why

Using the vault day to day means remembering commands and a URL: `agent-vault ui`, find the request, approve it, check what is still open, revoke what is finished. People forget, sessions stay open longer than they should, and requests sit waiting because nobody noticed them. Someone who is not at home in a terminal does not get that far: they have to install the vault, set a passphrase and find a `localhost` page first.

The companion is meant to be the one thing such a person installs. It sits in the menu bar (the system tray on Windows), finds the vault or offers to set it up, shows what is open, says when something needs them, and puts the everyday actions one click away.

The original spec asked for a native shell rather than a web page, to stay off the browser-automation surface. The companion is a step back toward that, without moving any trust into it.

## The rule that shapes the design

**The companion is a doorbell, a signpost and a set of brakes. It never grants anything.**

It runs as the user's account, which is the same account every local agent runs as. Anything the companion can do without a human present, an agent can do too: by talking to the same socket, by running the same CLI, or by driving the companion's own menu with accessibility automation. So the companion is given no power the CLI does not already give an unproven caller, and every action that widens access still goes through the daemon's existing presence gate (the passphrase, or the WebAuthn signature the web UI collects).

## What it does

| Area | Behaviour | Proof needed |
|---|---|---|
| First run | Says where the icon is and what it found; if no vault is installed, offers to set one up | — |
| Set up the vault | Opens Terminal on the official installer, then `passphrase set` | Mac password and a new passphrase, typed in Terminal |
| Setup checklist | Lists what is left: passphrase, Touch ID approvals, a first key, connecting an agent | Depends on the step |
| Status | Version, locked or unlocked | — |
| Waiting | Count beside the icon; one row per pending request (kind and age only); a notification | — |
| Review a request | Opens the web UI on that request (`#approvals/<id>`) | WebAuthn, in the UI |
| Sessions | Each open session: its keys, when it ends, and one sentence on what agents may do | — |
| Start a session | Opens the web UI on the new-session form, blank or from a template | WebAuthn, in the UI |
| Revoke a session | `session revoke <sid>`, after a confirmation dialog | None (narrows access) |
| Keys | Each stored key: service, last health check, whether a session is using it, whether it is stopped | — |
| Add a key | Opens the web UI's Credentials page | WebAuthn, in the UI |
| Check keys | `cred test --all`: the vault calls each key's own service once | None (the daemon does not gate it) |
| Stop a key | `cred quarantine <slug>`, after a confirmation dialog | None (narrows access) |
| Allow a stopped key again | Opens the web UI's Containment page | WebAuthn, in the UI |
| Connect an agent | `mcp install --agent <id> --scope user`: writes the vault into that agent's own config | None (grants no access; the agent still needs a session) |
| Move keys to another computer | Opens Terminal on `backup export` or `backup restore`, with a fixed file on the Desktop | Passphrase and a recovery passphrase, typed in Terminal |
| Open the vault / unlock | Opens the web UI | WebAuthn or passphrase, in the UI |
| Lock, Panic | `lock`; `panic` after a confirmation dialog | None (narrows access) |
| Notifications | A request waiting; a session ending within ten minutes; a session ended; the vault locked; the daemon unreachable or back; a key failing its check or being stopped | — |
| Settings | Notifications on or off; start at login | — |

### What it deliberately does not do

- **No approve, deny, session create, template save, credential add or release, or unlock.** Each widens access or decides on a held request, so each needs presence. The companion opens the page or the Terminal command where the human proves it. A unit test holds the companion's own commands to an allowlist.
- **No passphrase handling.** The companion never asks for, sees or stores the vault passphrase, the Mac password or a recovery passphrase. Those are typed into Terminal or the web UI.
- **No agent-written text.** A pending item's `claim` (the agent's stated reason) could be crafted to mislead ("routine refresh, approve"). The companion shows only the kind and the age of each request, and notifications say only that something happened. Session labels, key names and template names are shown, cleaned of control and bidirectional characters and shortened.
- **No secrets.** The companion never receives a credential, a placeholder or a session token; the CLI's JSON output contains none.
- **No network listener, and no network use of its own.** It talks only to the local CLI.

## How it talks to the vault

Through the CLI's `--json` output rather than linking the daemon's crates. The JSON envelope is the public interface the CLI already maintains, the companion stays a thin client that can be reviewed in one sitting, and it never holds control-socket code of its own.

**Which CLI.** Only the root-owned install (`/var/db/agent-vault/app/bin/agent-vault` on macOS, `/usr/libexec/agent-vault/app/bin/agent-vault` on Linux), and only when the file and its folder are owned by root and not writable by group or others. The companion never looks the CLI up on `PATH`: an agent can put a fake `agent-vault` earlier on `PATH`, and a companion that ran it would show whatever the fake chose. The install is looked up again on every refresh, so a vault set up while the companion runs is found without a restart.

**Commands used.** Read: `status`, `session list`, `approvals`, `template list`, `cred list`, `doctor`, `mcp install --print`. Change: `session revoke`, `cred quarantine`, `cred test --all`, `mcp install`, `lock`, `panic`. Streams: `watch --no-notify`, `ui --no-open`.

**Values on a command line.** Ids, key names and template names from the vault are passed on only if they are plain (`[A-Za-z0-9_][A-Za-z0-9_.-]*`), so none can be read as a flag. Agent ids come from a fixed list.

**Terminal commands.** Four fixed strings, compiled in, with nothing from the vault, an agent or the menu in them. They reach Terminal as an AppleScript string through `osascript`, never through a script file another process could rewrite first. macOS asks once whether the companion may control Terminal.

**Refresh.** On every `watch` event, and every 15 seconds as a backstop.

**The UI link.** `agent-vault ui --json --no-open` prints the single-use URL and keeps serving. The companion checks that the URL is `http://localhost:<port>/?t=…`, then checks with `lsof` that every listener on that port, IPv4 and IPv6, is the UI process it just started. Only then does it append the page fragment and open the link. Opening another page stops the previous UI process first, since each link works only once. If a UI the user started in a terminal already holds the port, the companion says so instead of picking another port: Touch ID confirmations are trusted only on the default origin.

**A clean environment.** Every process the companion starts gets a fixed environment (`HOME`, `USER`, `LOGNAME`, `LANG`, `TMPDIR` and a system-only `PATH`). Anything else could steer the CLI; `AGENT_VAULT_DIR`, for one, points it at a different control socket.

**Lifecycle.** Quit, and a terminate signal (logout, `kill`), stop the companion's `watch` and `ui` processes. Stream output is read in lines capped at 64 KiB.

## Moving a vault between computers, and why there is no login yet

Each computer has its own vault, and the keys have to reach each one. Today the companion offers the path the vault already has: `backup export` writes an encrypted file (under a recovery passphrase the user chooses, after fresh proof of presence), the user carries it across (AirDrop, a USB stick), and `backup restore` on the other computer brings the keys in. Sessions and approvals are not carried; every agent needs a new session there.

A sign-in that keeps vaults in step automatically is a different thing, and it belongs in the daemon, not the companion:

- **The companion cannot do it.** It cannot read the vault; only the daemon can. A sync the companion performed would mean handing it the keys, which is the one thing the design forbids.
- **It changes the vault's promise.** Today no credential leaves the machine except in a backup the human asked for. A sync service is a place those credentials go, so it needs its own threat model.
- **A login alone must not unlock anything.** If signing in (with GitHub, Apple or an email) were enough to fetch the keys, then that account, or the server, would be worth exactly as much as every key in the vault. The stored data has to be encrypted on the device under a secret the server never holds: a recovery passphrase, or a key held by the user's other devices.

A design that fits: each device has its own key pair; the vault's contents are encrypted on the device before upload; a new device joins when an existing device approves it (with presence) or when the user enters the recovery passphrase; the server stores ciphertext and device public keys only. The login then identifies the account and its storage, and is not the secret. That is a daemon feature with a server behind it, and worth its own design note and review before any code.

## Known gaps

- **The UI server's IPv6 bind (a daemon issue, not the companion's).** `UiServer::start` binds `127.0.0.1:<port>` and then tries `[::1]:<port>`, ignoring failure. If another program already holds `[::1]:7412`, a browser that resolves `localhost` to IPv6 first sends the single-use link to that program. This affects plain `agent-vault ui` as well. The companion refuses to open a link while any other process listens on the port, but a program that binds between that check and the browser's connection would still win. The fix belongs in the daemon: fail when `[::1]` is unavailable because the port is taken, and continue only when IPv6 is absent altogether.
- **The link is visible in the opener's arguments.** Like `agent-vault ui` itself, the companion passes the single-use URL to `open` (or `xdg-open`) as an argument, which another process of the same user can read for that moment. The link's single use turns theft into a visible failure (the user's own browser is refused), but does not prevent it.
- **Setting up from the companion trusts the same things as `curl | sh`.** The install command is the one the README gives. As the README says of any first install, it should run when no agent is active on the machine: the installer unpacks into a folder the user owns before the privileged step.
- **The backup file sits on the Desktop until the user deletes it.** It is encrypted under the recovery passphrase, and the vault refuses to overwrite an existing file or follow a symlink there. The companion reminds the user to delete it but does not do so.
- **Typed secrets can be phished.** A passphrase typed into Terminal can be captured by a look-alike window, exactly as with the CLI alone. The companion does not add this risk and cannot remove it.
- **Borrowed touch.** The platform's Touch ID dialog says who is asking, not what for. The companion makes approving easier to reach, so an agent that triggers a request at the moment the user expected a different one has one more chance of borrowing a touch. The web UI's operation display and the audit log remain the defence.
- **Menu automation.** An agent with macOS accessibility permission could click the companion's menu. Every command it would reach is one the agent could already run.
- **Not signed.** Without an Apple Developer ID signature and notarization, macOS blocks a downloaded copy of the app, and may suppress its notifications. The badge beside the icon works regardless. Signing needs the project's Apple credentials as repository secrets.
- **Windows.** The vault does not run on Windows yet, so on Windows the companion says so. A Windows companion becomes useful when the daemon does.
- **Native Touch ID in the menu** would need the daemon to accept a second kind of presence proof (for example, a Secure Enclave key enrolled through the companion). That is a daemon change with its own review.

## Building

See `desktop/README.md`.
