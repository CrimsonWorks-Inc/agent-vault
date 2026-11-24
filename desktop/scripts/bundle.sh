#!/usr/bin/env bash
# Builds "build/agent-vault companion.app" and signs it.
#
#   UNIVERSAL=1   build for Apple silicon and Intel (needs Xcode, not just the
#                 command line tools)
#   DMG=1         also write build/agent-vault-companion.dmg
#   SIGN_IDENTITY a codesigning identity; by default the first Apple Development
#                 certificate, or ad hoc when there is none
#   VERSION       the version to stamp into the app (a release's tag)
#   TIMESTAMP=1   a secure timestamp on the signature, which notarization needs
#   DMG_NAME      the .dmg's file name (default agent-vault-companion.dmg)
#
# Signing with a stable identity keeps macOS's answers (Automation for
# Terminal, notifications) across rebuilds; an ad hoc signature makes macOS
# ask again after each build.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH_FLAGS=()
if [[ "${UNIVERSAL:-0}" == 1 ]]; then
  ARCH_FLAGS=(--arch arm64 --arch x86_64)
fi
swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"}
BIN="$(swift build -c release ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} --show-bin-path)/agent-vault-companion"

APP="build/agent-vault companion.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/agent-vault-companion"
cp Resources/Info.plist "$APP/Contents/Info.plist"
if [[ -n "${VERSION:-}" ]]; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" -c "Set :CFBundleVersion $VERSION" "$APP/Contents/Info.plist"
fi
cp Resources/AppIcon.icns Resources/TrayTemplate.png "$APP/Contents/Resources/"

IDENTITY="${SIGN_IDENTITY:-$(security find-identity -v -p codesigning 2>/dev/null | awk -F'"' '/Apple Development/ {print $2; exit}')}"
if [[ -z "$IDENTITY" ]]; then
  echo "No Apple Development identity found; signing ad hoc."
  IDENTITY="-"
fi
STAMP=()
if [[ "${TIMESTAMP:-0}" == 1 ]]; then
  STAMP=(--timestamp)
fi
codesign --force --options runtime ${STAMP[@]+"${STAMP[@]}"} --entitlements Resources/Companion.entitlements --sign "$IDENTITY" "$APP"
codesign --verify --strict "$APP"
echo "Built $APP (signed with: $IDENTITY)"

if [[ "${DMG:-0}" == 1 ]]; then
  DMG_PATH="build/${DMG_NAME:-agent-vault-companion.dmg}"
  rm -f "$DMG_PATH"
  STAGE="$(mktemp -d)"
  cp -R "$APP" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"
  hdiutil create -quiet -volname "agent-vault companion" -srcfolder "$STAGE" -ov -format UDZO "$DMG_PATH"
  rm -rf "$STAGE"
  echo "Built $DMG_PATH"
fi
