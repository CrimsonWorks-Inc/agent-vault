Install or upgrade:

```sh
curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh | sh
```

or with Homebrew: `brew install crimsonworks-inc/tap/agent-vault`, then `agent-vault setup`.

The companion app (it lives in the notch, or the menu bar): `agent-vault companion install` once the CLI is installed, and `agent-vault companion upgrade` after upgrading it. The CLI fetches this release's `.dmg`, checks it, installs it and opens it, and macOS opens that copy without asking. The cask (`brew install --cask crimsonworks-inc/tap/agent-vault-companion`) and the `.dmg` below work too, but macOS blocks a downloaded copy until the app is notarized.

Each archive is listed in `SHA256SUMS` and has build provenance from this repository's release workflow:

```sh
gh attestation verify agent-vault-<version>-<target>.tar.gz --repo CrimsonWorks-Inc/agent-vault
```

What changed: see [CHANGELOG.md](https://github.com/CrimsonWorks-Inc/agent-vault/blob/main/CHANGELOG.md).
