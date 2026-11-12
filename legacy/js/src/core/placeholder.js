// The placeholder grammar. This is the only grammar; everything else in the
// system references it rather than redefining it.
//
//   placeholder := "av1" "." sid "." label "." nonce "." chk
//   sid   := 12 x base32   session id, 60 bits
//   label := slug "_" field   slug [a-z0-9-]{1,24}, field [a-z0-9]{1,16}
//   nonce := 26 x base32   128 bits from the CSPRNG
//   chk   := 6 x base32    first 30 bits of HMAC-SHA256(K_ph, "av1."sid"."label"."nonce)
//
// Every byte is RFC 3986 unreserved and printable ASCII, so a placeholder
// survives a URL userinfo field, a SCRAM username, JSON, YAML, a shell word and
// a .pgpass line without escaping. The tail is fixed width, which lets the
// scanner parse from an "av1." hit without a regex and without partial matches.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import * as b32 from './base32.js'

export const PREFIX = 'av1.'
export const SID_LEN = 12
export const NONCE_LEN = 26
export const CHK_LEN = 6
export const SLUG_MAX = 24
export const FIELD_MAX = 16

// Derived constants. The tests re-derive these from the grammar so a change to
// the grammar that forgets to update them fails the build.
export const PH_MIN_LEN = 3 + 1 + SID_LEN + 1 + 3 + 1 + NONCE_LEN + 1 + CHK_LEN // 54
export const PH_MAX_LEN = 3 + 1 + SID_LEN + 1 + (SLUG_MAX + 1 + FIELD_MAX) + 1 + NONCE_LEN + 1 + CHK_LEN // 92
export const B64_MIN_RUN = Math.ceil((PH_MIN_LEN * 4) / 3) // 72
export const SCAN_OVERLAP = 3 * PH_MAX_LEN + 2 // 278, enough to cover a fully percent-encoded token

const SLUG_RE = /^[a-z0-9-]{1,24}$/
const FIELD_RE = /^[a-z0-9]{1,16}$/

/** The single pattern secret scanners are given (gitleaks, push protection). */
export const SCANNER_PATTERN =
  'av1\\.[0-9a-hjkmnp-tv-z]{12}\\.[a-z0-9-]{1,24}_[a-z0-9]{1,16}\\.[0-9a-hjkmnp-tv-z]{26}\\.[0-9a-hjkmnp-tv-z]{6}'

export function isValidSlug(s) { return SLUG_RE.test(s) }
export function isValidField(s) { return FIELD_RE.test(s) }

/** A new session id: 60 bits of randomness as 12 base32 characters. */
export function newSid() {
  return b32.encode(randomBytes(8), SID_LEN)
}

function chkFor(kPh, sid, label, nonce) {
  const mac = createHmac('sha256', kPh).update(`av1.${sid}.${label}.${nonce}`).digest()
  // First 30 bits, as 6 base32 characters.
  return b32.encode(mac, CHK_LEN)
}

/**
 * Mint a placeholder. Returns the text and the nonce hash the daemon stores;
 * the nonce itself is returned once and never persisted.
 */
export function mint({ kPh, sid, slug, field }) {
  if (!isValidSlug(slug)) throw new Error(`invalid credential slug: ${slug}`)
  if (!isValidField(field)) throw new Error(`invalid field name: ${field}`)
  if (sid.length !== SID_LEN || !b32.isBase32(sid)) throw new Error('invalid sid')
  const nonce = b32.encode(randomBytes(16), NONCE_LEN)
  const label = `${slug}_${field}`
  const chk = chkFor(kPh, sid, label, nonce)
  const text = `av1.${sid}.${label}.${nonce}.${chk}`
  return { text, sid, slug, field, nonce, nonceHash: hashNonce(nonce) }
}

/** SHA-256 of the nonce: the primary key the daemon looks a placeholder up by. */
export function hashNonce(nonce) {
  return createHmac('sha256', 'av/nonce/v1').update(nonce).digest('hex')
}

/**
 * Parse at `offset` in `s`, anchored on the fixed-width tail. Returns null when
 * the text at that offset is not shaped like a placeholder. Shape only: this
 * does no keyed verification, so it is safe to run on untrusted input anywhere.
 */
export function parseAt(s, offset = 0) {
  if (!s.startsWith(PREFIX, offset)) return null
  let p = offset + PREFIX.length

  const sid = s.slice(p, p + SID_LEN)
  if (sid.length !== SID_LEN || !b32.isBase32(sid)) return null
  p += SID_LEN
  if (s[p] !== '.') return null
  p += 1

  // The label is the one variable-width field, so it is read up to the next dot
  // and then validated; the two fixed-width groups after it anchor the parse.
  const dot = s.indexOf('.', p)
  if (dot < 0) return null
  const label = s.slice(p, dot)
  const us = label.indexOf('_')
  if (us < 1) return null
  const slug = label.slice(0, us)
  const field = label.slice(us + 1)
  if (!isValidSlug(slug) || !isValidField(field)) return null
  p = dot + 1

  const nonce = s.slice(p, p + NONCE_LEN)
  if (nonce.length !== NONCE_LEN || !b32.isBase32(nonce)) return null
  p += NONCE_LEN
  if (s[p] !== '.') return null
  p += 1

  const chk = s.slice(p, p + CHK_LEN)
  if (chk.length !== CHK_LEN || !b32.isBase32(chk)) return null
  p += CHK_LEN

  // A longer run of base32 after chk means this is some other token that merely
  // starts like a placeholder, not a placeholder with trailing data.
  const next = s[p]
  if (next !== undefined && b32.isBase32(next)) return null

  return { text: s.slice(offset, p), offset, end: p, sid, label, slug, field, nonce, chk }
}

/** Verify the keyed check characters. Only the daemon can do this. */
export function verify(kPh, parsed) {
  const want = Buffer.from(chkFor(kPh, parsed.sid, parsed.label, parsed.nonce))
  const got = Buffer.from(parsed.chk)
  return want.length === got.length && timingSafeEqual(want, got)
}

/**
 * Explain why a malformed placeholder is malformed, in the terms an agent can
 * act on. Error text is a product surface: an agent that reads "expected groups
 * of 12/26/6" fixes its own string handling without asking a human.
 */
export function diagnose(s) {
  if (!s.startsWith(PREFIX)) return 'does not start with "av1."'
  const parts = s.split('.')
  if (parts.length !== 5) return `expected 5 dot-separated groups, got ${parts.length}`
  const [, sid, label, nonce, chk] = parts
  const shape = `${sid.length}/${nonce.length}/${chk.length}`
  if (sid.length !== SID_LEN || nonce.length !== NONCE_LEN || chk.length !== CHK_LEN) {
    return `expected groups of ${SID_LEN}/${NONCE_LEN}/${CHK_LEN} chars, got ${shape}`
  }
  if (!label.includes('_')) return "label is missing its '_' between credential slug and field"
  if (label.includes('-') && label.split('_')[1]?.includes('-')) {
    return "label mixes '-' and '_' - the field name after '_' cannot contain '-'"
  }
  for (const [name, v] of [['sid', sid], ['nonce', nonce], ['chk', chk]]) {
    if (!b32.isBase32(v)) return `${name} contains a character outside the alphabet (i, l, o and u are never used)`
  }
  return 'check characters do not match; the placeholder was altered in transit'
}

/**
 * Find every placeholder-shaped run in a string. Used by the detector on the
 * whole request, and by the substituter on one site's value.
 */
export function findAll(s) {
  const out = []
  let i = 0
  for (;;) {
    const hit = s.indexOf(PREFIX, i)
    if (hit < 0) return out
    const p = parseAt(s, hit)
    if (p) {
      out.push(p)
      i = p.end
    } else {
      // Resume one byte in, so "av1.av1.<real>" still finds the real one.
      i = hit + 1
    }
  }
}
