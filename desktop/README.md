# agent-vault companion

A native macOS app for agent-vault that lives in the notch at the top of the screen, meant to be the one thing a person installs.

- **Lives on the island.** Closed, it is the notch with the vault's mark beside it and, on the other side, whatever needs you: the number of requests waiting, a lock, a session about to end, or a warning. Point at the notch and it opens into the full list; click it to keep it open. On a screen without a notch (an external display with the lid closed, an older Mac), it is a menu bar icon instead, with the same list as its menu.
- **Finds your vault, or sets it up.** On first run it says what it found. If agent-vault is not installed, one click opens Terminal on the official installer.
- **Shows what agents can use.** Open sessions with their keys and when they end; every stored key with its health.
- **Tells you when you are needed.** The island says so beside the notch, and a notification tells you when an agent is waiting, when a session is about to end, when the vault locks, or when a key stops working.
- **Puts the everyday actions one click away.** Review a request, start a session, add a key, connect an agent, stop a key, revoke a session, lock, panic.

Anything that gives an agent more access is confirmed by you. With **Settings → Set up Touch ID in the island** (the gear beside the notch), that is right in the island, with your fingerprint: approve or deny a request, start a session from a template, add a key or replace its value, allow a stopped key again. Setting it up makes a key in your Mac's Secure Enclave and asks for your passphrase once, in Terminal. Without it, the island sends you to the vault's own page (Touch ID in the browser) or, with **Settings → Without Touch ID, approve in Terminal with my passphrase**, to a Terminal window. It never approves anything on a click and never sees your passphrase. Why, and what it does and does not do: [`docs/desktop-companion.md`](../docs/desktop-companion.md).

## Requirements

- macOS 13 or later.
- To build: Xcode 16 or later (Swift 6). `UNIVERSAL=1` needs the full Xcode, not just the command line tools.

agent-vault itself does not have to be installed first; the companion offers to set it up.

## Build and run

```sh
cd desktop
scripts/bundle.sh
open "build/agent-vault companion.app"
```

The script signs the app with your Apple Development certificate when you have one, so macOS remembers its permissions (Terminal automation, notifications) across rebuilds, and ad hoc otherwise. `UNIVERSAL=1` builds for Apple silicon and Intel; `DMG=1` also writes `build/agent-vault-companion.dmg`.

To keep it, drag the app into Applications, then turn on **Settings → Start at login**.

`swift test` runs the tests. `swift build` and `swift run` work for quick checks, but notifications and Start at login need the bundled app.

To try the other placement on one Mac: `defaults write com.iolitelabs.agentvault.companion placement menu-bar` (or `island`, for the island on a screen without a notch), then restart the companion. `defaults delete com.iolitelabs.agentvault.companion placement` goes back to choosing by screen.

## Layout

```
Sources/CompanionCore/   what is shown and what is run: pure Foundation, all tested
  Model.swift            parsing the CLI's JSON, actions and their routes, Terminal commands, the list
  Notices.swift          what deserves a notification
  CLI.swift              finding and running the root-owned CLI, the UI link checks
  IslandLayout.swift     where each item of the list sits on the island
Sources/Companion/       the app
  Companion.swift        refreshing, the watch stream, clicks, dialogs
  Island.swift           the panel around the notch: placement, size, hover and click
  IslandView.swift       the island's SwiftUI views
  StatusMenu.swift       the menu bar fallback, and native menus for the island's submenus
  System.swift           settings, Start at login, Terminal, notifications
Tests/CompanionCoreTests/
```

## Moving your keys to another computer

Each computer has its own vault. In the companion, **Move keys to another computer → Save my keys to an encrypted file…** writes `agent-vault-backup.json` to your Desktop, protected by a recovery passphrase you choose. Carry the file to the other computer's Desktop, choose **Bring in keys from that file…** there, then delete the file on both.

## Icons

`Resources/TrayTemplate.png` is the vault's mark, used beside the notch and as the menu bar icon (black on transparent, so macOS tints it). `Resources/AppIcon.icns` is generated from `icons-src/app-icon.svg`.
