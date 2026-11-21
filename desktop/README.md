# agent-vault companion

A menu bar icon (system tray on Windows and Linux) for agent-vault. It shows whether the vault is locked, what sessions are open and for how long, and puts a count beside the icon when an agent is waiting for your approval.

Clicking a waiting request, a template or "Open the vault" opens the vault's own web UI on that page, where you approve with Touch ID as usual. Revoking a session, panic and lock work straight from the menu, because they only take access away.

The companion never approves anything itself. Why, and what it does and does not do: [`docs/desktop-companion.md`](../docs/desktop-companion.md).

## Requirements

- agent-vault installed with `agent-vault setup` (the companion only runs the root-owned install)
- Rust (`brew install rust`, or rustup) and Node.js 18+
- macOS 12 or later. The code builds for Windows and Linux, but only macOS has been run.

## Build and run

```sh
cd desktop
npm install
npm run build
open "src-tauri/target/release/bundle/macos/agent-vault companion.app"
```

The icon appears in the menu bar; there is no Dock icon. Quit it from its own menu.

To keep it, drag the app into Applications. To start it at login, add it under System Settings → General → Login Items.

For development, `npm run dev` runs it without bundling, and `npm test` runs the unit tests.

## Icons

`src-tauri/icons/tray-template.png` is the menu bar icon (black on transparent, so macOS tints it for light and dark menu bars). The app icons are generated from the vault logo with `npm run icons`.
