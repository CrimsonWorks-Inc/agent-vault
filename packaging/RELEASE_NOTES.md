Install or upgrade:

```sh
curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh | sh
```

or with Homebrew: `brew install crimsonworks/tap/agent-vault`, then `agent-vault setup`.

Each archive is listed in `SHA256SUMS` and has build provenance from this repository's release workflow:

```sh
gh attestation verify agent-vault-<version>-<target>.tar.gz --repo CrimsonWorks-Inc/agent-vault
```

What changed: see [CHANGELOG.md](https://github.com/CrimsonWorks-Inc/agent-vault/blob/main/CHANGELOG.md).
