// Safe display of text the page did not write (contract U7).
//
// React already escapes markup, so the danger left is characters that change
// what the eye reads without being markup: bidi embeddings, overrides and
// isolates ("fix\u202elive" reads as "fixevil"), C0/C1 controls, and the line
// and paragraph separators. The rules are the CLI's, character for character,
// so a reason reads the same in a terminal and on this page:
//
//   cleanText -> src/cli/control-commands.js cleanText: removes C0 controls
//                except tab and newline, DEL, C1, bidi and U+2028/2029.
//   cleanLine -> src/daemon/notify.js and the page's notificationText: every
//                control becomes a space and bidi goes, for one-line display.

/** Bidi embeddings (U+202A-E) and isolates (U+2066-9). */
export const BIDI = /[\u202a-\u202e\u2066-\u2069]/g
/** What cleanText removes. Tab (U+0009) and newline (U+000A) are kept. */
const MULTILINE_STRIP = /[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g
/** What cleanLine turns into a space. */
const LINE_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g

/** Multi-line untrusted text: a reason, a preview, a payload. */
export function cleanText(value) {
  return String(value ?? '').replace(MULTILINE_STRIP, '')
}

/** One line of untrusted text: a label, a headline, a notification. */
export function cleanLine(value) {
  return String(value ?? '').replace(LINE_CONTROLS, ' ').replace(BIDI, '')
}

/** cleanLine, cut to `max` characters with an ellipsis (the CLI's watch). */
export function clip(value, max = 120) {
  const text = cleanLine(value)
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** True when cleaning changed the text, so the page can say it did. */
export function wasCleaned(value, multiline = true) {
  const raw = String(value ?? '')
  return (multiline ? cleanText(raw) : cleanLine(raw)) !== raw
}
