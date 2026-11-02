// Copying to the clipboard, the one way every copy button on the page does it.
//
// What is written is the text with bidi embeddings, overrides and isolates
// removed (lib/text.js BIDI, the ranges the old page's esc() removed), so a
// token or a summary cannot paste in a different order than it reads.
// Everything else is kept as it is, `& < > " '` included: a pasted command
// needs them. A refusal is said in one sentence, the same everywhere.

import { BIDI } from './text.js'

/** The text a code block shows and a copy button writes. */
export const copyable = (text) => String(text ?? '').replace(BIDI, '')

/** What the page says when the browser will not let it copy. */
export const COPY_REFUSED = 'Your browser would not let the page copy. Select the text instead.'

/** Write `text` (bidi removed). Rejects when the browser refuses. */
export async function copyText(text, clipboard = globalThis.navigator?.clipboard) {
  if (!clipboard?.writeText) throw new Error(COPY_REFUSED)
  await clipboard.writeText(copyable(text))
}
