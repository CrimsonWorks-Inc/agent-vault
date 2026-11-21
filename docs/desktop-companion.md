# Desktop companion: design note

Status: prototype on branch `desktop-companion`. macOS first; the code compiles for Windows and Linux, but only macOS has been run.

## Why

Using the vault day to day means remembering commands and a URL: `agent-vault ui`, find the request, approve it, check what is still open, revoke what is finished. People forget, sessions stay open longer than they should, and requests sit waiting because nobody noticed them. A small icon in the menu bar (the system tray on Windows) can carry that load: it shows what is open, says when something is waiting, and puts the safe actions one click away.

The original spec asked for a native shell rather than a web page, to stay off the browser-automation surface. The companion is a step back toward that, without moving any trust into it.

## The rule that shapes the design

**The companion is a doorbell and a set of brakes. It never grants anything.**

It runs as the user's account, which is the same account every local agent runs as. Anything the companion can do without a human present, an agent can do too: by talking to the same socket, by running the same CLI, or by driving the companion's own menu with accessibility automation. So the companion is given no power the CLI does not already give an unproven caller, and every action that widens access still goes through the daemon's existing presence gate (passphrase, or the WebAuthn signature the web UI collects).

## What it does

| Area | Behaviour | Proof needed |
|---|---|---|
| Status | Version, locked or unlocked, shown at the top of the menu | — |
| Waiting | Count beside the icon; one menu row per pending request (kind and age only); a notification when a new one arrives | — |
| Review a request | Opens the web UI straight on that request (`#approvals/<id>`); the approval happens there, with Touch ID | WebAuthn, in the UI |
| Start a session from a template | Opens the web UI on the new-session form for that template (`#sessions/new:<name>`) | WebAuthn, in the UI |
| Open the vault / unlock | Opens the web UI (overview, or settings for unlock) | WebAuthn or passphrase, in the UI |
| Revoke a session | `agent-vault session revoke <sid>`, after a confirmation dialog | None (narrows access) |
| Panic | `agent-vault panic`, after a confirmation dialog | None (narrows access) |
| Lock | `agent-vault lock` | None (narrows access) |

### What it deliberately does not do

- **No approve, deny, session create, template save, credential add or unlock.** Each of these widens access or decides on a held request, so each needs presence. The companion opens the page where the human proves it instead. A unit test asserts that no menu action of these kinds exists.
- **No agent-written text.** A pending item's `claim` (the agent's stated reason) is written by the agent and could be crafted to mislead ("routine refresh, approve"). The companion shows only the kind and the age of each request, and notifications say only that something is waiting. This matches the daemon's own notification rule (`notify --detail minimal`). Session labels and template names are shown, but cleaned of control and bidirectional characters and shortened.
- **No secrets.** The companion never receives a credential, a placeholder or a session token; the CLI's JSON output contains none.
- **No network listener.** It talks only to the local CLI.

## How it talks to the vault

Through the CLI's `--json` output rather than linking the daemon's crates. The JSON envelope is the public interface the CLI already maintains, the companion stays a thin client that can be reviewed in one sitting, and it never holds control-socket code of its own.

**Which CLI.** Only the root-owned install (`/var/db/agent-vault/app/bin/agent-vault` on macOS, `/usr/libexec/agent-vault/app/bin/agent-vault` on Linux), and only when the file and its folder are owned by root and not writable by group or others. The companion never looks the CLI up on `PATH`: an agent can put a fake `agent-vault` earlier on `PATH`, and a companion that ran it would show whatever the fake chose.

**Commands used:** `status`, `session list`, `approvals`, `template list` (read); `session revoke`, `panic`, `lock` (narrowing); `watch --no-notify` (a stream that wakes the companion the moment a request arrives); `ui --no-open` (to get a fresh single-use link, which the companion opens with the system browser).

**Refresh.** On every `watch` event, and every 15 seconds as a backstop. Each refresh runs four short CLI calls with a 20-second timeout.

**The UI link.** `agent-vault ui --json --no-open` prints the single-use URL and keeps serving. The companion checks that the URL is `http://localhost:<port>/?t=…`, then checks with `lsof` that every listener on that port, IPv4 and IPv6, is the UI process it just started. Only then does it append the page fragment and open the link. Opening another page stops the previous UI process first, since each link works only once. If a UI the user started in a terminal already holds the port, the companion says so instead of picking another port: Touch ID confirmations are trusted only on the default origin.

**A clean environment.** Every process the companion starts gets a fixed environment (`HOME`, `USER`, `LOGNAME`, `LANG`, `TMPDIR` and a system-only `PATH`). Anything else could steer the CLI; `AGENT_VAULT_DIR`, for one, points it at a different control socket.

**Lifecycle.** Quit, and a terminate signal (logout, `kill`), stop the companion's `watch` and `ui` processes. Stream output is read in lines capped at 64 KiB.

## Known gaps

- **The UI server's IPv6 bind (a daemon issue, not the companion's).** `UiServer::start` binds `127.0.0.1:<port>` and then tries `[::1]:<port>`, ignoring failure. If another program already holds `[::1]:7412`, a browser that resolves `localhost` to IPv6 first sends the single-use link to that program. This affects plain `agent-vault ui` as well. The companion refuses to open a link while any other process listens on the port, but a program that binds between that check and the browser's connection would still win. The fix belongs in the daemon: fail when `[::1]` is unavailable because the port is taken, and continue only when IPv6 is absent altogether.
- **The link is visible in the opener's arguments.** Like `agent-vault ui` itself, the companion passes the single-use URL to `open` (or `xdg-open`) as an argument, which another process of the same user can read for that moment. The link's single use turns theft into a visible failure (the user's own browser is refused), but does not prevent it.
- **Borrowed touch.** The platform's Touch ID dialog says who is asking, not what for. The companion makes approving easier to reach, so an agent that triggers a request at the moment the user expected a different one has one more chance of borrowing a touch. The web UI's operation display and the audit log remain the defence; the companion adds nothing there.
- **Menu automation.** An agent with macOS accessibility permission could click the companion's menu. Every action it would reach only narrows access, which is the point of the rule above.
- **Notifications from an unsigned build** may be suppressed by macOS until the app is signed. The badge beside the icon works regardless.
- **Windows.** The vault does not run on Windows yet, so on Windows the companion shows that no vault is installed. A Windows companion becomes useful when the daemon does; approving a vault on another machine would need a network surface the vault deliberately does not have.
- **Native Touch ID in the menu** would need the daemon to accept a second kind of presence proof (for example, a Secure Enclave key enrolled through the companion). That is a daemon change with its own review, not part of this prototype.

## Building

See `desktop/README.md`.
