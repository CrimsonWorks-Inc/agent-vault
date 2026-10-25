// The response scrubber. Upstreams echo credentials: in error bodies ("bad
// credentials: ghp_xxx"), in debug endpoints, in webhook payloads that repeat
// what was just sent. The agent must never read one back.
//
// The match set is every secret injected into this request plus every other
// currently unsealed credential value, each expanded into the encodings a
// response might carry it in. A byte-exact echo in any of those encodings is
// replaced. Derived-token regexes catch minted credentials the vault never
// stored, such as an installation token in a response body.
//
// Beyond the fixed needles, two views of the text are searched: one with
// every `\uXXXX` and `%XX` escape decoded, which catches a secret escaped one
// character at a time or only in part, and one with line breaks taken out of
// hex and base64 runs, which catches a blob wrapped at 64 or 76 columns.
//
// Honest limit: this is byte-and-encoding based. A secret split across markup,
// re-encoded in a scheme not listed, or transformed by the upstream is not
// caught. That is stated as a non-guarantee rather than papered over.

export const MIN_SECRET_LEN = 8

/**
 * Token shapes worth redacting even when the vault never stored them.
 *
 * Every one starts at a token boundary. Without that, `sk-` matched in the
 * MIDDLE of ordinary words: `disk-usage_by_repository_over_time` came back as
 * `di[[av:derived]]`, and `task-oriented_approach_to_the_problem` as
 * `ta[[av:derived]]`. On a streamed response the same match cut the stream
 * with AV_UNSCANNABLE. A scrubber that corrupts ordinary English is not a
 * cautious scrubber, it is a broken proxy — and this pattern class is a
 * heuristic for tokens the vault never stored, so a missed one costs a
 * heuristic while a false one costs every response that mentions a repository.
 *
 * The vault's OWN secrets are matched exactly, by value, and are unaffected by
 * any of this.
 */
const BOUNDARY = '(?<![A-Za-z0-9_-])'
export const DERIVED_PATTERNS = [
  { name: 'github', re: new RegExp(`${BOUNDARY}gh[pousr]_[A-Za-z0-9]{20,}`, 'g') },
  { name: 'github-pat', re: new RegExp(`${BOUNDARY}github_pat_[A-Za-z0-9_]{40,}`, 'g') },
  { name: 'slack', re: new RegExp(`${BOUNDARY}xox[abpors]-[0-9A-Za-z-]{10,}`, 'g') },
  { name: 'aws', re: new RegExp(`${BOUNDARY}AKIA[0-9A-Z]{16}`, 'g') },
  { name: 'google-oauth', re: new RegExp(`${BOUNDARY}ya29\\.[0-9A-Za-z_-]{20,}`, 'g') },
  { name: 'google-api', re: new RegExp(`${BOUNDARY}AIza[0-9A-Za-z_-]{35}`, 'g') },
  { name: 'anthropic', re: new RegExp(`${BOUNDARY}sk-ant-[A-Za-z0-9_-]{20,}`, 'g') },
  { name: 'openai', re: new RegExp(`${BOUNDARY}sk-(?:proj-)?[A-Za-z0-9_-]{20,}`, 'g') },
  { name: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
]

// Where a token of one of the shapes above can begin, and what it is made of.
// The stream scrubber uses these to keep a token that is still arriving in one
// piece (see push()).
const DERIVED_START = new RegExp(`${BOUNDARY}(?:gh[pousr]_|github_pat_|xox[abpors]-|AKIA|ya29\\.|AIza|sk-)`, 'g')
const TOKEN_CHAR = /[A-Za-z0-9_.-]/
// How far before the cut a token may begin and still be held back for. A run
// longer than this is emitted, and the pattern redacts what it can of it.
const MAX_DERIVED_HOLD = 512

// One character escaped for JSON or for a URL.
const ESCAPE = /\\u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})/g
const unescapeOne = (_, u, pct) => String.fromCharCode(parseInt(u ?? pct, 16))
const HAS_ESCAPE = /\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}/
// A hex or base64 run broken over lines, by real line breaks or JSON-escaped ones.
const BREAK = /\r\n|\r|\n|\\r\\n|\\n|\\r/g
const HAS_BREAK = /[\r\n]|\\[rn]/
// It starts with a full line of at least 16, which a wrapped blob has and the
// end of an ordinary line of prose does not: matching every word either side
// of every line break would search the whole of a large text body again.
const WRAPPED = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{16,}(?:(?:\r\n|\r|\n|\\r\\n|\\n|\\r)[A-Za-z0-9+/=_-]+)+/g

/** Every encoding of `secret` a response might carry. */
export function encodings(secret, minLen = MIN_SECRET_LEN) {
  const out = new Set()
  const add = (s) => { if (s && s.length >= minLen) out.add(s) }

  add(secret)
  // The same secret as the response actually carries it. Bodies are read
  // byte-for-byte as latin1 so a binary body survives intact, which means a
  // secret with any character outside ASCII arrives as its UTF-8 bytes —
  // "café" on the wire is five bytes that read back as "cafÃ©" and never
  // matched the needle. Any credential with an accent in it was published to
  // the agent whenever an upstream echoed it.
  add(Buffer.from(secret, 'utf8').toString('latin1'))
  add(encodeURIComponent(secret))
  add(secret.replace(/\//g, '\\/'))
  add(JSON.stringify(secret).slice(1, -1))
  add([...secret].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''))
  add(secret.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`))
  for (const blob of blobEncodings(secret)) add(blob)
  return [...out]
}

/**
 * The forms of `secret` that are runs of hex or base64 characters, which is
 * what a long blob gets wrapped over lines in.
 */
export function blobEncodings(secret) {
  const out = new Set()
  const hex = Buffer.from(secret, 'utf8').toString('hex')
  out.add(hex)
  // Uppercase hex is as common as lowercase, and was not caught at all.
  out.add(hex.toUpperCase())

  // Base64 at three alignments, standard and URL-safe. A secret embedded in a
  // larger base64 blob is offset by however many bytes precede it, so the
  // aligned substrings are what actually appear in the response.
  // A base64 character is "the secret's" when every bit it encodes comes from
  // the secret's bytes: character i covers bits [6i, 6i+6), so with `pad`
  // bytes in front the run is [ceil(4·pad/3), floor(4·(pad+len)/3)).
  //
  // The end used to be `length - 4`, chopping a blunt four characters off to
  // clear the padding. That is up to three bytes MORE than the padding, and
  // those bytes are the secret's last three — so a token echoed inside a
  // base64 blob came back to the agent with its tail intact. Redacting all but
  // the last three characters of a credential is not redacting it.
  const bytes = Buffer.from(secret, 'utf8')
  for (let pad = 0; pad < 3; pad++) {
    const std = Buffer.concat([Buffer.alloc(pad, 0x20), bytes]).toString('base64')
    const start = Math.ceil((pad * 4) / 3)
    const end = Math.floor((4 * (pad + bytes.length)) / 3)
    const core = std.slice(start, end)
    out.add(core)
    out.add(core.replace(/\+/g, '-').replace(/\//g, '_'))
  }
  return [...out]
}

export class Scrubber {
  /**
   * @param {{secret:string, label:string, replacement:string}[]} entries
   *   label is the credential name; replacement is what the agent sees instead
   *   (the placeholder it used, for this request's own secret).
   */
  constructor(entries = []) {
    this.patterns = []
    // What the decoded view and the unwrapped view are searched for: the
    // secret itself, and its hex and base64 forms.
    this.plain = []
    this.blobs = []
    this.maxLen = 0
    for (const e of entries) {
      if (!e.secret) continue
      // A secret this request actually injected is redacted at any length: we
      // know it exactly, so there is no false-positive risk. Only the bulk set
      // of other vault secrets keeps the length floor.
      const floor = e.always ? 1 : MIN_SECRET_LEN
      if (e.secret.length < floor) continue
      const replacement = e.replacement ?? `[[av:redacted:${e.label}]]`
      for (const enc of encodings(e.secret, floor)) {
        this.patterns.push({ needle: enc, replacement })
        if (enc.length > this.maxLen) this.maxLen = enc.length
      }
      for (const needle of new Set([e.secret, Buffer.from(e.secret, 'utf8').toString('latin1')])) {
        if (needle.length >= floor) this.plain.push({ needle, replacement })
      }
      for (const needle of blobEncodings(e.secret)) {
        if (needle.length >= floor) this.blobs.push({ needle, replacement })
      }
    }
    // Longest first, so an encoding that contains another is replaced whole.
    for (const list of [this.patterns, this.plain, this.blobs]) list.sort((a, b) => b.needle.length - a.needle.length)
    this.derivedSeen = new Set()
  }

  /**
   * True when any encoding of any secret appears in `text` with case ignored.
   * For text whose case has already been lost, such as an HTTP header name.
   */
  containsIgnoringCase(text) {
    const t = String(text).toLowerCase()
    // At the bulk floor even for a secret this request injected: dropping a
    // header because a four-character secret matched part of its name would
    // break ordinary responses, and a short secret is not much of a leak.
    this.folded ??= [...new Set(this.patterns.filter((p) => p.needle.length >= MIN_SECRET_LEN).map((p) => p.needle.toLowerCase()))]
    return this.folded.some((needle) => t.includes(needle))
  }

  /** Lookbehind a streaming caller must retain between chunks. */
  get overlap() { return Math.max(this.maxLen, 64) - 1 }

  /** Scrub a complete string. Returns { text, redactions }. */
  scrub(text) {
    let out = text
    let redactions = 0
    for (const { needle, replacement } of this.patterns) {
      if (!out.includes(needle)) continue
      const parts = out.split(needle)
      redactions += parts.length - 1
      out = parts.join(replacement)
    }
    const spans = this.viewSpans(out)
    if (spans.length) {
      const spliced = splice(out, spans)
      out = spliced.text
      redactions += spliced.count
    }
    for (const { name, re } of DERIVED_PATTERNS) {
      re.lastIndex = 0
      const matches = out.match(re)
      if (matches) {
        out = out.replace(re, () => '[[av:derived]]')
        this.derivedSeen.add(name)
        redactions += matches.length
      }
    }
    return { text: out, redactions }
  }

  /**
   * Where the secret appears in `text` once escapes are decoded or a wrapped
   * blob is joined up: [rawStart, rawEnd, replacement] for each hit. These are
   * the forms no fixed needle can list — `\u0072` for one character and the
   * rest plain, every byte percent-encoded, base64 broken every 64 columns.
   */
  viewSpans(text) {
    const spans = []
    if (this.plain.length && HAS_ESCAPE.test(text)) {
      find(view(text, ESCAPE, unescapeOne), this.plain, spans)
    }
    if (this.blobs.length && HAS_BREAK.test(text)) {
      for (const m of text.matchAll(WRAPPED)) find(view(m[0], BREAK, () => ''), this.blobs, spans, m.index)
    }
    return spans
  }

  /**
   * A streaming scrubber. Feed chunks; it holds back `overlap` bytes so a
   * secret split across a chunk boundary is still matched, and `flush()`
   * returns the tail.
   */
  stream() {
    const self = this
    let held = ''
    let redactions = 0
    return {
      push(chunk) {
        const combined = held + chunk
        const keep = Math.min(self.overlap, combined.length)
        let cut = combined.length - keep
        if (cut <= 0) { held = combined; return '' }

        // A known encoding straddling the cut is already here in full, so move
        // the cut past it. Scrubbing the head in isolation tore such a match in
        // two — neither half matched, and the secret went out whole. The
        // \u-escaped form is six times the secret's length, so any streamed
        // response could carry one across the boundary.
        //
        // A token of one of the derived shapes that runs across the cut is
        // held back whole instead, cut moved to where it starts: it may still
        // be growing. Scrubbing the head alone either found too few of its
        // characters to match, so both halves went out raw and the agent had
        // the whole token, or matched them and sent the rest raw after it.
        DERIVED_START.lastIndex = Math.max(0, cut - MAX_DERIVED_HOLD)
        for (let m; (m = DERIVED_START.exec(combined)) !== null && m.index < cut;) {
          let end = m.index
          while (end < cut && TOKEN_CHAR.test(combined[end])) end++
          if (end >= cut) { cut = m.index; break }
        }

        // Exact ones are already here in full, so the cut moves past them.
        for (const { needle } of self.patterns) {
          let i = combined.indexOf(needle)
          while (i !== -1 && i < cut) {
            if (i + needle.length > cut) cut = i + needle.length
            i = combined.indexOf(needle, i + 1)
          }
        }
        // And the same for one found only once escapes are decoded.
        for (const [start, end] of self.viewSpans(combined)) {
          if (start < cut && end > cut) cut = end
        }

        const { text, redactions: r } = self.scrub(combined.slice(0, cut))
        redactions += r
        held = combined.slice(cut)
        return text
      },
      flush() {
        const { text, redactions: r } = self.scrub(held)
        redactions += r
        held = ''
        return text
      },
      get redactions() { return redactions },
    }
  }
}

/**
 * `text` with every match of `re` replaced by `decode(match)`, and a way back
 * from positions in the result to the span of `text` they came from.
 *
 * The way back is worked out only for the hits there are, in one more pass
 * over the matches. Keeping a position for every escape up front cost memory
 * in proportion to how many escapes a body had — which an upstream chooses —
 * for a map that is almost never read.
 */
function view(text, re, decode) {
  return { text: text.replace(re, decode), raw: text, re, decode }
}

/**
 * Every occurrence of every needle in a view, as [rawStart, rawEnd,
 * replacement] spans of the raw text, offset by `base`.
 */
function find(v, needles, spans, base = 0) {
  const hits = []
  for (const { needle, replacement } of needles) {
    for (let i = v.text.indexOf(needle); i !== -1; i = v.text.indexOf(needle, i + needle.length)) {
      hits.push({ start: i, last: i + needle.length - 1, replacement })
    }
  }
  if (!hits.length) return
  // Each hit needs two positions mapped back: its first character's start and
  // its last character's end. Sorted, so one walk over the matches does both.
  const points = []
  for (const h of hits) points.push({ p: h.start, hit: h, end: false }, { p: h.last, hit: h, end: true })
  points.sort((a, b) => a.p - b.p)
  let k = 0
  let vi = 0 // where the current raw position lands in the view
  let ri = 0
  const resolve = (pt, raw) => { if (pt.end) pt.hit.rawEnd = raw; else pt.hit.rawStart = raw }
  for (const m of v.raw.matchAll(v.re)) {
    // Text before the match is the same in both.
    const plainEnd = vi + (m.index - ri)
    for (; k < points.length && points[k].p < plainEnd; k++) {
      const raw = ri + (points[k].p - vi)
      resolve(points[k], points[k].end ? raw + 1 : raw)
    }
    vi = plainEnd
    ri = m.index
    // A decoded character stands for the whole escape. A removed line break
    // stands for nothing, so no position can land in it.
    const width = v.decode(m[0], m[1], m[2]).length
    for (; k < points.length && points[k].p < vi + width; k++) {
      resolve(points[k], points[k].end ? ri + m[0].length : ri)
    }
    vi += width
    ri += m[0].length
  }
  for (; k < points.length; k++) {
    const raw = ri + (points[k].p - vi)
    resolve(points[k], points[k].end ? raw + 1 : raw)
  }
  for (const h of hits) spans.push([base + h.rawStart, base + h.rawEnd, h.replacement])
}

/** Replace raw spans, merging any that overlap. Returns the text and how many. */
function splice(text, spans) {
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1])
  const merged = []
  for (const s of spans) {
    const prev = merged[merged.length - 1]
    if (prev && s[0] < prev[1]) { prev[1] = Math.max(prev[1], s[1]); continue }
    merged.push([...s])
  }
  let out = ''
  let last = 0
  for (const [s, e, replacement] of merged) {
    out += text.slice(last, s) + replacement
    last = e
  }
  return { text: out + text.slice(last), count: merged.length }
}
