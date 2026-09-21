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
  add(Buffer.from(secret, 'utf8').toString('hex'))
  add(secret.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`))

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
    add(core)
    add(core.replace(/\+/g, '-').replace(/\//g, '_'))
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
    this.maxLen = 0
    for (const e of entries) {
      if (!e.secret) continue
      // A secret this request actually injected is redacted at any length: we
      // know it exactly, so there is no false-positive risk. Only the bulk set
      // of other vault secrets keeps the length floor.
      const floor = e.always ? 1 : MIN_SECRET_LEN
      if (e.secret.length < floor) continue
      for (const enc of encodings(e.secret, floor)) {
        this.patterns.push({ needle: enc, replacement: e.replacement ?? `[[av:redacted:${e.label}]]` })
        if (enc.length > this.maxLen) this.maxLen = enc.length
      }
    }
    // Longest first, so an encoding that contains another is replaced whole.
    this.patterns.sort((a, b) => b.needle.length - a.needle.length)
    this.derivedSeen = new Set()
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
        // The cut is never pulled back for the shape patterns, only pushed
        // forward for exact ones: a `ghp_...` near the end may still be
        // growing, and redacting the part we have would emit the rest raw.
        for (const { needle } of self.patterns) {
          let i = combined.indexOf(needle)
          while (i !== -1 && i < cut) {
            if (i + needle.length > cut) cut = i + needle.length
            i = combined.indexOf(needle, i + 1)
          }
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
