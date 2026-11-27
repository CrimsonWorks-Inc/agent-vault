# Desktop companion: design note

Status: version 0.4, a native macOS app in Swift (`desktop/`). It replaces the 0.3 prototype, which was built with Tauri; the rules below carried over unchanged, and so did their tests. macOS only.

## Why

Using the vault day to day means remembering commands and a URL: `agent-vault ui`, find the request, approve it, check what is still open, revoke what is finished. People forget, sessions stay open longer than they should, and requests sit waiting because nobody noticed them. Someone who is not at home in a terminal does not get that far: they have to install the vault, set a passphrase and find a `localhost` page first.

The companion is meant to be the one thing such a person installs. It lives in the notch at the top of the screen (in the menu bar, on a screen without one), finds the vault or offers to set it up, shows what is open, says when something needs them, and puts the everyday actions one click away.

The original spec asked for a native shell rather than a web page, to stay off the browser-automation surface. The companion is a step back toward that, without moving any trust into it.

## The rule that shapes the design

**The companion is a doorbell, a signpost and a set of brakes. It never grants anything.**

It runs as the user's account, which is the same account every local agent runs as. Anything the companion can do without a human present, an agent can do too: by talking to the same socket, by running the same CLI, or by driving the companion itself with accessibility automation. So the companion is given no power the CLI does not already give an unproven caller, and every action that widens access still goes through the daemon's existing presence gate.

That gate has three doors, and the companion only ever shows the user to one of them:

- **The island itself, with Touch ID**, once it is set up: a signature from a key in the Mac's Secure Enclave, over a challenge the daemon minted for that exact request, which the daemon verifies (see "Touch ID in the island" below).
- **The web UI**, where a change is confirmed with Touch ID (a WebAuthn signature the daemon verifies).
- **Terminal**, on the vault's own command, where a change is confirmed with the passphrase.

When Touch ID in the island is set up, the island uses it. Until it is, the island's forms (start a session, add a key, replace a value) open on a "Set up Touch ID" step, and each button that would leave the island offers the same: one Terminal window, the passphrase once (after unlocking the vault, if it is locked), and from then on these stay in the island. Otherwise the user chooses between the other two with one setting, "Without Touch ID, approve in Terminal with my passphrase". It is off by default, so the web UI is used. A Mac with no fingerprint reader in reach (a closed laptop on a dock, a desktop without a Touch ID keyboard, a browser that will not use the reader) is fully usable with it on.

The companion does not guess which the user should use, because it cannot tell: the CLI does not report whether Touch ID approvals are enrolled. (`doctor`'s "passphrase + authenticator" refers to Touch ID *unlock*, a separate setting.) A `doctor` line for approval enrollment would let the companion pick the right door on its own.

Every item that opens Terminal says so, and the route is part of the item: a click goes where the label said, whatever has changed since the list was drawn.

## Where it lives

On a Mac with a notch, the companion is an island around it, in the manner of the iPhone's Dynamic Island:

- **Closed**, it is the notch with an ear on each side: the vault's mark on the left, and on the right whatever needs the user (the number of requests waiting, a lock, a session ending within ten minutes, a warning) or a small green dot when nothing does. When a request arrives, the right ear says so in words for a few seconds.
- **Open**, it drops down from the notch into the same list the menu bar menu shows, in the same order and with the same labels: a test holds the island to every item of that list. Pointing at the notch opens it, and moving away closes it; a click keeps it open until a click elsewhere or Escape. Submenus (a session, a key, Start a session, Settings) open as native menus.
- **It never takes the keyboard on a hover.** The island is a non-activating panel: the app the user is typing in keeps focus unless the island is clicked.
- **On a screen without a notch** (an external display with the lid closed, an older Mac), the companion is a menu bar icon instead, and switches back when the screen changes.

## What it does

| Area | Behaviour | Proof needed |
|---|---|---|
| First run | Says where the companion is and what it found; if no vault is installed, offers to set one up | — |
| Set up the vault | Opens Terminal on the official installer, then `passphrase set` | Mac password and a new passphrase, typed in Terminal |
| Setup checklist | Lists what is left: passphrase, a first key, connecting an agent | Depends on the step |
| Status | Version, locked or unlocked | — |
| Waiting | Count beside the notch (or the menu bar icon); one row per pending request (kind and age only); a notification | — |
| Review a request | Island: what the vault recorded about it (never the agent's reason), then Approve or Deny with Touch ID. Web UI: opens that request (`#approvals/<id>`). Terminal: `approvals --show <id>`, then a typed `yes` or `no` runs `approve` or `deny` | Touch ID in the island, WebAuthn in the UI, or the passphrase in Terminal |
| Sessions | Each open session: its keys, when it ends, and one sentence on what agents may do | — |
| Start a session | Island: a template's keys and limits, or chosen keys for 1, 8 or 24 hours, read only or with each write waiting for approval, then Start with Touch ID. Web UI: the new-session form, blank or from a template. Terminal: `template show <name>`, then a typed yes runs `session create --template`; or the `session create` wizard | Touch ID in the island, WebAuthn in the UI, or the passphrase in Terminal |
| Revoke a session | `session revoke <sid>`, after a confirmation dialog | None (narrows access) |
| Keys | Each stored key: service, last health check, whether a session is using it, whether it is stopped | — |
| Add a key, replace a key's value | Island: a form with a secure field for the value, then Touch ID. Web UI: the Credentials page. Terminal: `cred add`, `cred rotate <slug>` | Touch ID in the island, WebAuthn in the UI, or the passphrase in Terminal |
| Check keys | `cred test --all`: the vault calls each key's own service once | None (the daemon does not gate it) |
| Stop a key | `cred quarantine <slug>`, after a confirmation dialog | None (narrows access) |
| Allow a stopped key again | Island: Allow it again, with Touch ID. Web UI: the Containment page. Terminal: a typed yes runs `cred release <slug>` | Touch ID in the island, WebAuthn in the UI, or the passphrase in Terminal |
| Connect an agent | `mcp install --agent <id> --scope user`: writes the vault into that agent's own config | None (grants no access; the agent still needs a session) |
| Move keys to another computer | Opens Terminal on `backup export` or `backup restore`, with a fixed file on the Desktop | Passphrase and a recovery passphrase, typed in Terminal |
| Open the vault | Opens the web UI | — |
| Unlock | Island: Touch ID, where Touch ID unlock is on; otherwise the passphrase, typed in the island and sent to `unlock` on stdin (then an offer to turn on Touch ID unlock). Menu bar: Touch ID where it is on, else the web UI's Settings or Terminal's `unlock` | Touch ID unlock (the island's or the browser's), or the passphrase |
| Lock, Panic | `lock`; `panic` after a confirmation dialog | None (narrows access) |
| Notifications | A request waiting; a session ending within ten minutes; a session ended; the vault locked; the daemon unreachable or back; a key failing its check or being stopped | — |
| Settings | Notifications on or off; start at login; approve in Terminal with the passphrase; set up Touch ID approvals (opens the web UI) | — |

### What it deliberately does not do

- **It never approves, denies, starts a session, or adds, replaces or re-allows a key on a click.** Each widens access or decides on a held request, so each needs presence. With Touch ID in the island, the command runs only with a signature the human's fingerprint released, over the daemon's challenge for that request; without it, the companion opens the page or the Terminal window where the human proves it. Either way the vault's own gate decides. It never saves a template, and unlocks only with the passphrase the human typed in the island or the secret the Secure Enclave released after a fingerprint. A unit test holds the commands the companion runs without proof to an allowlist.
- **No passphrase handling.** The companion never asks for, sees or stores the vault passphrase, the Mac password or a recovery passphrase. Those are typed into Terminal or the web UI.
- **No agent-written text.** A pending item's `claim` (the agent's stated reason) could be crafted to mislead ("routine refresh, approve"). The companion shows only the kind and the age of each request, and notifications say only that something happened. Session labels, key names and template names are shown, cleaned of control and bidirectional characters and shortened.
- **No secrets, except one in passing.** The companion never receives a credential, a placeholder or a session token; the CLI's JSON output contains none. When the user adds a key or replaces a key's value in the island, they type it into a secure field, and the companion passes it to the CLI on stdin, never in an argument; it is not shown, kept or logged. (The daemon binds it into the signed operation by digest only.)
- **No network listener, and no network use of its own.** It talks only to the local CLI.

## Touch ID in the island

Approving with a fingerprint in the island needs proof the daemon can check, and the WebAuthn credential the web UI uses belongs to the browser and the vault page's origin. So the daemon accepts a second kind of proof, with its own review and tests:

- **The key.** The companion makes a P-256 key in the Secure Enclave with access control `biometryCurrentSet`: it signs only after Touch ID, with the fingers enrolled when it was made. The private key never leaves the Secure Enclave. What the companion keeps (in its Application Support folder, mode 0600) is an encrypted handle only this Mac's Secure Enclave can use.
- **Enrolment.** `agent-vault companion enroll <public key>` stores the public key with the vault, under an id derived from it. It needs the passphrase to exist (as an authenticator does, so whoever enrols first cannot lock others out) and fresh presence: the passphrase, typed in Terminal, which the companion opens on that command. A confirmation window does not count. `companion remove` also needs fresh presence, which the key itself can give.
- **A challenge for one request.** For each change, the companion runs the very command it would run with `--companion-challenge`. The CLI builds the request as usual, but instead of sending it asks the daemon (`POST /v1/presence/companion/challenge`) for a challenge bound to the operation the daemon derives from that request, as it would on receipt; in this mode the CLI sends nothing that changes anything. The challenge is single-use, lasts a minute, and answers only a companion proof.
- **Checking before asking.** The companion checks that the operation the daemon bound is the change the user chose (the right kind, on the right request, key or template, with a key's value bound by digest; for a session made in the island, the whole operation, so no limit the user did not choose is signed), and only then asks for Touch ID. macOS's prompt says what for: "…is trying to approve the agent's request shown in the island."
- **The proof.** The companion signs `agent-vault companion presence v1\n` followed by the challenge, and runs the command again with `--presence-stdin`: the challenge id and signature on stdin's first line (exactly those two fields; never a passphrase), and a key's value, if any, on the next. The daemon verifies the signature against the enrolled key and the operation against the challenge before it widens anything, and audits `presence.verified` with factor `companion-secure-enclave`, or `presence.denied` with the reason. A signature never opens a confirmation window.
- **What it is not.** The presence key never opens a locked vault, is not a recovery factor, and is not in backups: the key cannot leave this Mac. Opening the vault is the unlock key's job (below).

### Touch ID unlock

Unlocking needs the vault key itself, which a signature cannot give. So Touch ID unlock is a second Secure Enclave key, for key agreement, and a wrap of the vault key of its own (class `companion-prf`), beside the passphrase's and the browser's:

- **The secret.** When it is turned on, the companion makes a P-256 key-agreement key in the Secure Enclave (`biometryCurrentSet`), and a software key whose private half is used once and thrown away. The agreement between the two, through HKDF-SHA256 (salt `agent-vault companion unlock v1`) to 32 bytes, is the unlock secret. Only this Mac's Secure Enclave, after Touch ID, can repeat it; the companion keeps the enclave key's handle and the other public key (mode 0600), neither of which gives the secret.
- **Turning it on.** Needs the vault unlocked, the passphrase (its recovery), and Touch ID in the island already set up: `companion enable-unlock` sends the secret as `prf_secret` with fresh presence, which the companion gives by signing the daemon's challenge. The challenge binds the secret by SHA-256 (`prf_secret_sha256`), and the companion signs only when the operation is exactly that digest. The vault wraps its key under the secret for the enrolled companion key only, and audits `presence.factor_added` with class `companion-prf`.
- **Unlocking.** After Touch ID, `unlock --companion` sends the secret (on stdin) to `/v1/unlock` as `prf_secret`. The class is in each wrap's associated data, so the island's secret never opens the browser's wrap, nor the reverse.
- **It goes with the key.** Replacing the companion key with another, or removing it, removes the unlock wrap in the same transaction (`presence.factor_removed`, class `companion-prf`). The passphrase cannot be removed while it is on: like the browser's, it never exists without the passphrase to recover with.
- **The schema.** The `vmk_wraps` table's class check gains `companion-prf` (schema version 3). A vault opened by 0.5.2 cannot then be opened by an older release.

### A key an agent proposed

An agent can propose a credential over MCP (`vault_propose_credential`) with everything but the key. The island shows it as "An agent wants you to add a key" and finishes it in two steps:

1. **The host.** Every host the key could be sent to, as the vault listed them (the credential's host ceiling), one per line. Nothing else can be typed until the user says that is the right host. A host the island would have to clean before showing it is not shown as one to confirm, and such a proposal cannot be finished here.
2. **The key.** Typed in a secure field and sent to `agent-vault approve <id>` on stdin, after the proof, like a new key's value. The companion signs only when the operation is exactly `cred_proposal.approve` for that proposal, with exactly the hosts it showed and the key bound by digest (`value_sha256`), and nothing else along. Deny signs `cred_proposal.deny` for that proposal.

Without Touch ID in the island, the button opens Terminal, where `agent-vault approve` asks about the host again before it asks for the key. The agent's reason is never shown in the island, as for any request.

## How it talks to the vault

Through the CLI's `--json` output rather than linking the daemon's crates. The JSON envelope is the public interface the CLI already maintains, the companion stays a thin client that can be reviewed in one sitting, and it never holds control-socket code of its own.

**Which CLI.** Only the root-owned install (`/var/db/agent-vault/app/bin/agent-vault` on macOS, `/usr/libexec/agent-vault/app/bin/agent-vault` on Linux), and only when the file and its folder are owned by root and not writable by group or others. The companion never looks the CLI up on `PATH`: an agent can put a fake `agent-vault` earlier on `PATH`, and a companion that ran it would show whatever the fake chose. The install is looked up again on every refresh, so a vault set up while the companion runs is found without a restart.

**Commands used.** Read: `status`, `session list`, `approvals`, `template list`, `cred list`, `doctor`, `mcp install --print`. Change: `session revoke`, `cred quarantine`, `cred test --all`, `mcp install`, `lock`, `panic`. Streams: `watch --no-notify`, `ui --no-open`.

**Values on a command line.** Ids, key names and template names from the vault are passed on only if they are plain (`[A-Za-z0-9_][A-Za-z0-9_.-]*`), so none can be read as a flag. Agent ids come from a fixed list.

**Terminal commands.** Each is a fixed string, compiled in. The only parts that vary are a request id, a key name or a template name, and those are inserted only when plain (see above); nothing an agent wrote reaches a command.

Terminal starts the user's own shell, whichever that is, with whatever its profile sets up. So that shell is handed exactly one thing: `/usr/bin/env -i … /bin/sh -c '<script>'`. It expands `$HOME`, `$USER` and `$TERM` and nothing else; the script inside the single quotes is read only by `/bin/sh`, in an emptied environment, the same way on every Mac. The scripts contain no single quote, backslash or backtick, and every program runs by absolute path. The command reaches Terminal as an AppleScript string the companion runs itself (`NSAppleScript`), never through a script file another process could rewrite first and never in another process's arguments; a test has AppleScript read each one back unchanged. macOS asks once whether the companion may control Terminal.

**The typed answer.** After a passphrase is typed, the daemon does not ask for it again for a few minutes. A Terminal command that approved a request the moment it ran would, inside that window, approve on a single menu click. So the commands that decide or grant in one step (`approve`, `deny`, `session create --template`, `cred release`) first show what is being decided and wait for a typed answer. The line is read as typed (`IFS= read -r`) and compared exactly: only `yes` approves and only `no` denies. A near miss, padding, an unreadable input or a closed window decides nothing, and nothing is asked at all if the request or template could not be shown. Tests run these commands in sh, bash and zsh with each kind of answer.

`cred add`, `cred rotate`, the `session create` wizard and `unlock` are not gated this way: each needs the human to type something of its own before anything changes.

**Refresh.** On every `watch` event, and every 15 seconds as a backstop.

**The UI link.** `agent-vault ui --json --no-open` prints the single-use URL and keeps serving. The companion checks that the URL is `http://localhost:<port>/?t=…`, then checks with `lsof` that every listener on that port, IPv4 and IPv6, is the UI process it just started. Only then does it append the page fragment and open the link, through LaunchServices (`NSWorkspace`), so the link is never in another process's arguments. Opening another page stops the previous UI process first, since each link works only once. If a UI the user started in a terminal already holds the port, the companion says so instead of picking another port: Touch ID confirmations are trusted only on the default origin.

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
- **The link passes through the companion's pipe.** `agent-vault ui` prints the single-use URL to the companion, which hands it to the browser through LaunchServices, so no process's arguments hold it (the 0.3 prototype passed it to `open`). Plain `agent-vault ui` in a terminal still passes it to `open`.
- **Setting up from the companion trusts the same things as `curl | sh`.** The install command is the one the README gives. As the README says of any first install, it should run when no agent is active on the machine: the installer unpacks into a folder the user owns before the privileged step.
- **The backup file sits on the Desktop until the user deletes it.** It is encrypted under the recovery passphrase, and the vault refuses to overwrite an existing file or follow a symlink there. The companion reminds the user to delete it but does not do so.
- **Typed secrets can be phished.** A passphrase typed into Terminal can be captured by a look-alike window, exactly as with the CLI alone. The companion does not add this risk and cannot remove it.
- **Terminal runs the user's shell first.** `env -i` keeps the shell's exported variables away from the vault's commands, but a shell profile an agent has rewritten can still interfere with the window itself. That is true of every use of the CLI, and it is why Touch ID approvals, where they work, are the stronger of the two doors.
- **Inside the presence window the passphrase is not asked for again.** The typed answer keeps a click from deciding anything, but it is a guard against accidents, not proof of a human: anything that can type into the user's Terminal can already run the vault's commands.
- **Terminal shows the summary, not every detail.** A request is shown as `approvals --show` prints it, which for a session request is a one-line summary of what is asked. The web UI shows the full proposal, and the Terminal text says so.
- **A template is shown, then used by name.** Between `template show` and `session create --template`, the template could be saved again. Saving one needs presence, so only something already inside the presence window could do it, and that something could start a session directly. `session create` prints the template version it used.
- **`unlock` on a vault with no passphrase asks nothing.** That is the vault's behaviour; the checklist puts "Set your passphrase" first for that reason.
- **Borrowed touch.** The platform's Touch ID dialog says who is asking, not what for. The companion makes approving easier to reach, so an agent that triggers a request at the moment the user expected a different one has one more chance of borrowing a touch. The web UI's operation display and the audit log remain the defence.
- **Automation.** An agent with macOS accessibility permission could click the island or the menu. Every command it would reach is one the agent could already run.
- **Not signed for download.** The CI build is signed ad hoc. Without an Apple Developer ID signature and notarization, macOS blocks a copy downloaded by a browser or the Homebrew cask, and may suppress its notifications; the island works regardless. `agent-vault companion install` installs a checked copy that macOS opens (see *Installing*). A local `scripts/bundle.sh` build signs with the developer's own Apple Development certificate. Signing for download needs the project's Apple credentials as repository secrets.
- **macOS only.** The 0.3 prototype compiled for Linux and Windows but had only been run on macOS; the native app is macOS only. A Linux tray companion would be its own small app over the same CLI rules.
- **The key's handle is a file the user's account can read.** Using it still takes the enrolled fingerprint, but a process running as the user could ask the Secure Enclave to sign with it, for a challenge of its own, and hope the user touches the sensor: the borrowed-touch risk of any platform authenticator. macOS's prompt names the process that asks, so a prompt that does not say "agent-vault companion" should be refused. Keeping the key in the data-protection keychain under the companion's own access group would stop other processes from using it at all; that needs a provisioning profile, so it waits for Developer ID signing.
- **Touch ID in the island needs a vault that knows it.** An older installed vault has no `companion` command; the island says so and uses the web UI or Terminal.

## Installing

```bash
agent-vault companion install    # this CLI's version of the app, checked, then opened
agent-vault companion upgrade    # after upgrading the CLI: replace the app, reopen it
agent-vault companion open       # open the installed app
```

`install` and `upgrade` download the `.dmg` from the GitHub release the CLI belongs to, so the app and the CLI are the same version. They take it with the system's curl (`/usr/bin/curl`, HTTPS only, ignoring `~/.curlrc`) and check it before anything is replaced:

- **The checksum.** The `.dmg` must match the one line of the release's `SHA256SUMS` that names it. A name listed twice, or a digest of another shape, is refused.
- **Build provenance**, when the GitHub CLI is installed: `gh attestation verify` must say the release workflow built it. Without `gh` this step is skipped, and the command says so.
- **The app itself**, copied out of the read-only mounted `.dmg`: its bundle id is the companion's, its version is the CLI's, and its code signature verifies.

Only then does the new copy replace the installed one, in one rename beside it, so a failure at any step leaves the installed app as it was. A companion running from that copy is asked to quit first (SIGTERM, which it handles by quitting cleanly) and is opened again afterwards. `upgrade` never replaces a newer app with an older one.

The app goes over the installed copy if there is one, in `/Applications` or `~/Applications`. Otherwise it goes in `/Applications` if this account can write there (an administrator's can), and in `~/Applications` if not. Nothing runs as root.

**Why this opens without macOS's warning.** Gatekeeper checks an app on its first launch only if it carries the quarantine mark that browsers, and Homebrew's cask, put on what they download. curl puts none on the `.dmg`, so the copy installed here opens like an app built on this Mac. The checks above are what vouch for it instead, the same ones `install.sh` makes for the CLI's archive. A copy that does carry the mark (say, the cask's) is replaced by `install` or `upgrade` even at the same version, since macOS will not open it until the app is notarized; see *Known gaps*.

## Building

See `desktop/README.md`.
