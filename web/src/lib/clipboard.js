// Copying to the clipboard, the one way every copy button on the page does it.
//
// What is written is the text through lib/text.js cleanText: bidi
// embeddings, overrides and isolates go (so a token or a summary cannot paste
// in a different order than it reads), and so do C0 controls other than tab
// and newline, DEL, C1 and the line and paragraph separators (so an ESC from
// an agent's request path cannot reach a terminal the copy is pasted into).
// Everything else is kept as it is, `& < > " '`, tabs and newlines included:
// a pasted command needs them. A refusal is said in one sentence, the same
// everywhere.

import { cleanText } from './text.js'

/** The text a code block shows and a copy button writes. */
export const copyable = (text) => cleanText(text)

/** What the page says when the browser will not let it copy. */
export const COPY_REFUSED = 'Your browser would not let the page copy. Select the text instead.'

/** Write `text`, cleaned as copyable cleans it. Rejects when the browser refuses. */
export async function copyText(text, clipboard = globalThis.navigator?.clipboard) {
  if (!clipboard?.writeText) throw new Error(COPY_REFUSED)
  await clipboard.writeText(copyable(text))
}
