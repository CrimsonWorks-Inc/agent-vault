#!/bin/sh
# Install agent-vault from a GitHub release.
#
#   curl -fsSL https://github.com/CrimsonWorks-Inc/agent-vault/releases/latest/download/install.sh | sh
#
# It downloads the archive for this machine, checks it against the release's
# SHA256SUMS (and, when the GitHub CLI is installed, against the build
# provenance GitHub recorded for it), unpacks it under your home directory,
# and runs `agent-vault setup`, which shows exactly what the one privileged
# step will do and asks before it runs sudo. Nothing here runs as root.
#
# Settings (environment):
#   AGENT_VAULT_VERSION   a release tag such as v0.3.0 (default: the latest)
#   AGENT_VAULT_HOME      where releases are unpacked (default: ~/.local/share/agent-vault)
#   AGENT_VAULT_BIN_DIR   where `agent-vault` and `av` links go (default: ~/.local/bin)
#   AGENT_VAULT_NO_SETUP  set to 1 to unpack only, and run setup yourself

set -eu

REPO="CrimsonWorks-Inc/agent-vault"
HOME_DIR="${AGENT_VAULT_HOME:-$HOME/.local/share/agent-vault}"
BIN_DIR="${AGENT_VAULT_BIN_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'agent-vault install: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run this as yourself, not root; setup asks for sudo for the one step that needs it"

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-gnu ;;
  *) die "unsupported OS: $(uname -s) (macOS and Linux only)" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch=aarch64 ;;
  x86_64|amd64) arch=x86_64 ;;
  *) die "unsupported CPU: $(uname -m)" ;;
esac
target="$arch-$os"

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
  fetch_stdout() { curl -fsSL --proto '=https' --tlsv1.2 "$1"; }
else
  die "curl is required"
fi

tag="${AGENT_VAULT_VERSION:-}"
if [ -z "$tag" ]; then
  tag="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$tag" ] || die "could not find the latest release"
fi
version="${tag#v}"
name="agent-vault-$version-$target"
base="https://github.com/$REPO/releases/download/$tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "agent-vault $version for $target"
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" || die "no release archive for $target in $tag"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "the release has no SHA256SUMS"

expected="$(grep " $name.tar.gz\$" "$tmp/SHA256SUMS" | cut -d ' ' -f 1)"
[ -n "$expected" ] || die "SHA256SUMS does not list $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$name.tar.gz" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d ' ' -f 1)"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $name.tar.gz: refusing to install"
say "  checksum ok"

if command -v gh >/dev/null 2>&1; then
  if gh attestation verify "$tmp/$name.tar.gz" --repo "$REPO" >/dev/null 2>&1; then
    say "  build provenance ok (built by $REPO's release workflow)"
  else
    die "gh attestation verify failed for $name.tar.gz: refusing to install"
  fi
else
  say "  (install the GitHub CLI, gh, to also verify where this archive was built)"
fi

mkdir -p "$HOME_DIR"
dest="$HOME_DIR/$version"
rm -rf "$dest.partial"
mkdir -p "$dest.partial"
tar -xzf "$tmp/$name.tar.gz" -C "$dest.partial" --strip-components 1
rm -rf "$dest"
mv "$dest.partial" "$dest"
say "  unpacked to $dest"

if [ "${AGENT_VAULT_NO_SETUP:-}" = "1" ]; then
  say ""
  say "Next: $dest/bin/agent-vault setup"
  exit 0
fi

case "$(uname -s)" in
  Darwin) system_root="/var/db/agent-vault" ;;
  *) system_root="/usr/libexec/agent-vault" ;;
esac
if [ -f "$system_root/state.json" ]; then
  # Already installed: the root-owned installer copies the new binaries in.
  # `upgrade` prints the exact command; nothing here runs sudo for you.
  say ""
  "$dest/bin/agent-vault" upgrade --print-only
  say "Run that command to switch the service to $version."
  exit 0
fi

if [ -r /dev/tty ]; then
  "$dest/bin/agent-vault" setup < /dev/tty || die "setup did not finish; run it again with: $dest/bin/agent-vault setup"
else
  say ""
  say "Next (needs a terminal): $dest/bin/agent-vault setup"
  exit 0
fi

# Put `agent-vault` and `av` on PATH. Prefer the root-owned copy the install
# made: an agent running as you cannot replace it.
installed="$system_root/app/bin/agent-vault"
[ -x "$installed" ] || installed="$dest/bin/agent-vault"
mkdir -p "$BIN_DIR"
ln -sf "$installed" "$BIN_DIR/agent-vault"
ln -sf "$installed" "$BIN_DIR/av"
say ""
say "agent-vault and av now run $installed"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "Add $BIN_DIR to your PATH to use them." ;;
esac
