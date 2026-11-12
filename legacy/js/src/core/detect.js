// The detector. It answers one question over the whole request: where does a
// placeholder appear, in any encoding a tool might have applied to it?
//
// This is deliberately a superset of the decoders the substituter understands.
// The substituter handles raw text and the base64 inside Authorization: Basic.
// The detector also sees percent-encoding, JSON string escapes and base64 in
// arbitrary places, so that a placeholder smuggled into a body as
// "YXYxLjdmMngwazltM3F6ci4..." is caught and the request is refused rather than
// forwarded with the agent believing it was substituted.

import * as ph from './placeholder.js'

const B64_CHARS = /[A-Za-z0-9+/=_-]/

/** Tolerant percent-decoder: never throws, leaves malformed escapes in place. */
export function percentDecode(s) {
  if (!s.includes('%')) return s
  let out = ''
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%' && i + 2 < s.length) {
      const hex = s.slice(i + 1, i + 3)
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        out += String.fromCharCode(parseInt(hex, 16))
        i += 2
        continue
      }
    }
    out += s[i]
  }
  return out
}

/** Undo JSON string escapes that can hide a placeholder: \uXXXX and \/ */
export function jsonUnescape(s) {
  if (!s.includes('\\')) return s
  return s
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\\//g, '/')
}

/** Every maximal run of base64-ish characters at least `min` long. */
export function base64Runs(s, min = ph.B64_MIN_RUN) {
  const runs = []
  let start = -1
  for (let i = 0; i <= s.length; i++) {
    const isB64 = i < s.length && B64_CHARS.test(s[i])
    if (isB64 && start === -1) start = i
    else if (!isB64 && start !== -1) {
      if (i - start >= min) runs.push({ start, text: s.slice(start, i) })
      start = -1
    }
  }
  return runs
}

/**
 * Decode a base64 run at all three byte alignments, in both the standard and
 * the URL-safe alphabet. A placeholder inside a larger base64 blob does not
 * start on a 3-byte boundary, so each alignment has to be tried separately.
 */
function* base64Decodings(run) {
  const normalized = run.replace(/-/g, '+').replace(/_/g, '/')
  for (const variant of new Set([run, normalized])) {
    for (let skip = 0; skip < 4; skip++) {
      let sliced = variant.slice(skip).replace(/=+$/, '')
      if (sliced.length < 8) continue
      // Re-pad rather than truncate. Truncating to a 4-character boundary would
      // drop up to two bytes from the end, which is exactly where a
      // placeholder's check characters live, so a smuggled token would decode
      // to something that no longer parses and would slip through.
      if (sliced.length % 4 === 1) sliced = sliced.slice(0, -1)
      const padded = sliced + '='.repeat((4 - (sliced.length % 4)) % 4)
      try {
        const decoded = Buffer.from(padded, 'base64').toString('latin1')
        if (decoded.includes(ph.PREFIX)) yield decoded
      } catch {
        // A run that is not valid base64 at this alignment is simply not a hit.
      }
    }
  }
}

/**
 * Find every placeholder in `text`, in any encoding.
 * Returns [{ text, encoding, offset, end, sid, slug, field, nonce, chk }].
 * `offset`/`end` are meaningful only for encoding === 'raw'.
 */
export function detectAll(text) {
  const hits = []
  const seen = new Set()

  const push = (parsed, encoding) => {
    const key = `${encoding}:${parsed.text}:${encoding === 'raw' ? parsed.offset : ''}`
    if (seen.has(key)) return
    seen.add(key)
    hits.push({ ...parsed, encoding })
  }

  for (const p of ph.findAll(text)) push(p, 'raw')

  const pct1 = percentDecode(text)
  if (pct1 !== text) {
    for (const p of ph.findAll(pct1)) push(p, 'percent')
    const pct2 = percentDecode(pct1)
    if (pct2 !== pct1) for (const p of ph.findAll(pct2)) push(p, 'percent-double')
  }

  const unescaped = jsonUnescape(text)
  if (unescaped !== text) for (const p of ph.findAll(unescaped)) push(p, 'json-escape')

  // Base64, over every form of the text — and over each with its whitespace
  // removed, because base64 in the wild is wrapped.
  //
  // A minimal placeholder encodes to 80 characters and the shortest run worth
  // decoding is 72, so one newline in the middle leaves two runs that are both
  // too short and the placeholder is not seen at all. That is not an exotic
  // input: `base64` the command wraps at 76 columns, MIME parts wrap at 76,
  // PEM wraps at 64. Inside a JSON string the same break is written `\n`,
  // whose backslash ends the run just as surely. Piping a placeholder through
  // any of them carried it straight past the detector.
  //
  // Only whitespace and its escapes are removed, so unrelated tokens can join
  // only where nothing else separates them — and a join has to base64-decode
  // to text bearing a valid keyed checksum before it becomes a hit, which is
  // what the checksum is for.
  const variants = new Set([text, pct1, unescaped])
  for (const v of [...variants]) {
    if (/\s|\\[nrtbf]/.test(v)) variants.add(v.replace(/\\[nrtbf]|\s+/g, ''))
  }
  for (const v of variants) {
    for (const run of base64Runs(v)) {
      for (const decoded of base64Decodings(run.text)) {
        for (const p of ph.findAll(decoded)) push(p, 'base64')
      }
    }
  }

  return hits
}

/** True when any encoding other than raw text carried a placeholder. */
export function hasEncodedHit(hits) {
  return hits.some((h) => h.encoding !== 'raw')
}
