# agent-vault companion

A menu bar icon (system tray on Windows and Linux) for agent-vault, meant to be the one thing a person installs.

- **Finds your vault, or sets it up.** On first run it says what it found. If agent-vault is not installed, one click opens Terminal on the official installer.
- **Shows what agents can use.** Open sessions with their keys and when they end; every stored key with its health.
- **Tells you when you are needed.** A count beside the icon and a notification when an agent is waiting, when a session is about to end, when the vault locks, or when a key stops working.
- **Puts the everyday actions one click away.** Review a request, start a session, add a key, connect an agent, stop a key, revoke a session, lock, panic.

Anything that gives an agent more access opens the vault's own page for it, where you approve with Touch ID as usual. The companion never approves anything itself and never sees your passphrase or your keys. Why, and what it does and does not do: [`docs/desktop-companion.md`](../docs/desktop-companion.md).

## Requirements

- macOS 12 or later. The code builds for Windows and Linux, but only macOS has been run.
- To build: Rust (`brew install rust`, or rustup) and Node.js 18+.

agent-vault itself does not have to be installed first; the companion offers to set it up.

## Build and run

```sh
cd desktop
npm install
npm run build
open "src-tauri/target/release/bundle/macos/agent-vault companion.app"
```

The icon appears in the menu bar; there is no Dock icon. Quit it from its own menu.

To keep it, drag the app into Applications, then turn on **Settings → Start at login** in its menu.

For development, `npm run dev` runs it without bundling, and `npm test` runs the unit tests.

## Moving your keys to another computer

Each computer has its own vault. In the menu, **Move keys to another computer → Save my keys to an encrypted file…** writes `agent-vault-backup.json` to your Desktop, protected by a recovery passphrase you choose. Carry the file to the other computer's Desktop, choose **Bring in keys from that file…** there, then delete the file on both.

## Icons

`src-tauri/icons/tray-template.png` is the menu bar icon (black on transparent, so macOS tints it for light and dark menu bars). The app icons are generated from the vault logo with `npm run icons`.
