// Crockford base32, lowercase, no padding. Alphabet excludes i, l, o and u so a
// placeholder survives being read aloud, retyped by a model, or logged by a tool
// that lowercases. Matches the grammar's [0-9a-hjkmnp-tv-z].
export const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz'

const VALUE = new Int8Array(128).fill(-1)
for (let i = 0; i < ALPHABET.length; i++) VALUE[ALPHABET.charCodeAt(i)] = i

/** True when every character of `s` is in the alphabet (and `s` is non-empty). */
export function isBase32(s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c > 127 || VALUE[c] < 0) return false
  }
  return true
}

/**
 * Encode `bytes` into exactly `chars` base32 characters, most significant bit first.
 * Bits beyond `chars * 5` are dropped; if the buffer is short it is zero-extended.
 */
export function encode(bytes, chars) {
  let out = ''
  let acc = 0
  let bits = 0
  let i = 0
  while (out.length < chars) {
    if (bits < 5) {
      acc = (acc << 8) | (i < bytes.length ? bytes[i++] : 0)
      bits += 8
    }
    bits -= 5
    out += ALPHABET[(acc >>> bits) & 31]
  }
  return out
}

/** Decode base32 characters back to the first `byteLen` bytes they encode. */
export function decode(s, byteLen) {
  const out = Buffer.alloc(byteLen)
  let acc = 0
  let bits = 0
  let o = 0
  for (let i = 0; i < s.length && o < byteLen; i++) {
    const v = VALUE[s.charCodeAt(i)]
    if (v < 0) throw new Error('not base32')
    acc = (acc << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out[o++] = (acc >>> bits) & 0xff
    }
  }
  return out
}
