#!/usr/bin/env python3
"""Print the Homebrew formula for one release.

    python3 packaging/homebrew/render.py 0.3.0 SHA256SUMS > agent-vault.rb

The release workflow runs this and pushes the result to the tap
(CrimsonWorks-Inc/homebrew-tap) when HOMEBREW_TAP_TOKEN is set.
"""
import sys

REPO = "CrimsonWorks-Inc/agent-vault"
TARGETS = {
    ("macos", "arm"): "aarch64-apple-darwin",
    ("macos", "intel"): "x86_64-apple-darwin",
    ("linux", "arm"): "aarch64-unknown-linux-gnu",
    ("linux", "intel"): "x86_64-unknown-linux-gnu",
}


def main() -> None:
    version, sums_path = sys.argv[1], sys.argv[2]
    sums = {}
    for line in open(sums_path):
        digest, name = line.split()
        sums[name.lstrip("*")] = digest

    def block(os_name: str, cpu: str) -> str:
        name = f"agent-vault-{version}-{TARGETS[(os_name, cpu)]}.tar.gz"
        if name not in sums:
            sys.exit(f"SHA256SUMS has no {name}")
        url = f"https://github.com/{REPO}/releases/download/v{version}/{name}"
        return f'''    on_{cpu} do
      url "{url}"
      sha256 "{sums[name]}"
    end'''

    print(f'''class AgentVault < Formula
  desc "Zero-trust local credential proxy for LLM agents"
  homepage "https://github.com/{REPO}"
  version "{version}"
  license "Apache-2.0"

  on_macos do
{block("macos", "arm")}
{block("macos", "intel")}
  end

  on_linux do
{block("linux", "arm")}
{block("linux", "intel")}
  end

  def install
    bin.install "bin/agent-vault", "bin/agent-vault-daemon", "bin/agent-vault-setup"
    bin.install_symlink "agent-vault" => "av"
  end

  def caveats
    <<~EOS
      agent-vault keeps its vault under a separate system user, so an agent
      running as you cannot read it. One privileged step sets that up; it
      shows the plan and asks before running sudo:

        agent-vault setup

      Upgrading later (after brew upgrade):

        agent-vault upgrade
    EOS
  end

  test do
    assert_match "agent-vault", shell_output("#{{bin}}/agent-vault help")
  end
end''')


if __name__ == "__main__":
    main()
