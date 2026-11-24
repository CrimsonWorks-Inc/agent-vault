#!/usr/bin/env python3
"""Print the Homebrew cask for the companion app of one release.

    python3 packaging/homebrew/render_cask.py 0.5.0 SHA256SUMS > agent-vault-companion.rb

The release workflow runs this and pushes the result to the tap
(CrimsonWorks-Inc/homebrew-tap, as Casks/agent-vault-companion.rb) when
HOMEBREW_TAP_TOKEN is set. A cask, not a formula: only a cask puts an app in
/Applications. It depends on the agent-vault formula, so installing the app
installs the CLI too.
"""
import sys

REPO = "CrimsonWorks-Inc/agent-vault"


def main() -> None:
    version, sums_path = sys.argv[1], sys.argv[2]
    sums = {}
    for line in open(sums_path):
        digest, name = line.split()
        sums[name.lstrip("*")] = digest
    name = f"agent-vault-companion-{version}.dmg"
    if name not in sums:
        sys.exit(f"SHA256SUMS has no {name}")
    print(f'''cask "agent-vault-companion" do
  version "{version}"
  sha256 "{sums[name]}"

  url "https://github.com/{REPO}/releases/download/v#{{version}}/agent-vault-companion-#{{version}}.dmg"
  name "agent-vault companion"
  desc "Island and menu bar companion for agent-vault"
  homepage "https://github.com/{REPO}"

  depends_on macos: ">= :ventura"
  depends_on formula: "crimsonworks-inc/tap/agent-vault"

  app "agent-vault companion.app"

  zap trash: [
    "~/Library/Application Support/agent-vault companion",
    "~/Library/Preferences/com.iolitelabs.agentvault.companion.plist",
  ]

  caveats <<~EOS
    The companion lives in the notch at the top of the screen (or the menu
    bar, on a screen without one). If agent-vault is not set up yet, run
    `agent-vault setup` once, or let the companion offer it.

    The app is not notarized yet, so macOS will not open this copy. Replace
    it with a checked copy that opens (after each upgrade, too):

      agent-vault companion install

    Upgrading later, the app and the vault together:

      brew upgrade && agent-vault upgrade && agent-vault companion upgrade
  EOS
end''')


if __name__ == "__main__":
    main()
