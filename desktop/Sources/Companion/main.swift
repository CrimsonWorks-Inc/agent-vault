// agent-vault companion: lives around the notch (or in the menu bar on a
// screen without one), shows what the vault has open, says when something
// needs the user, and puts the everyday actions one click away. It never
// grants access itself: anything that widens what an agent may do opens the
// vault's own web UI or a Terminal window, where the human proves presence.
// See docs/desktop-companion.md.

import AppKit

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// No Dock icon and no app menu: the island (or the menu bar icon) is the app.
app.setActivationPolicy(.accessory)
app.run()
