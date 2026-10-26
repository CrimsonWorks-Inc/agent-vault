// ULID-style identifiers: time-ordered, so listings sort naturally and an id
// carries roughly when it was created without a lookup.

import { randomBytes } from 'node:crypto'

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

let lastMs = 0
let lastRandom = null

export function ulid(now = Date.now()) {
  let time = ''
  let t = now
  for (let i = 9; i >= 0; i--) {
    time = CROCKFORD[t % 32] + time
    t = Math.floor(t / 32)
  }

  // Within the same millisecond, increment rather than re-randomize, so ids
  // minted in a tight loop stay strictly ordered.
  if (now === lastMs && lastRandom) {
    let i = lastRandom.length - 1
    while (i >= 0 && lastRandom[i] === 255) { lastRandom[i] = 0; i-- }
    if (i >= 0) lastRandom[i] += 1
  } else {
    lastMs = now
    lastRandom = randomBytes(10)
  }

  let rand = ''
  let acc = 0
  let bits = 0
  for (const byte of lastRandom) {
    acc = (acc << 8) | byte
    bits += 8
    while (bits >= 5) { bits -= 5; rand += CROCKFORD[(acc >>> bits) & 31] }
  }
  return time + rand.slice(0, 16)
}

export const id = {
  workspace: () => `ws_${ulid()}`,
  credential: () => `cred_${ulid()}`,
  session: () => `ses_${ulid()}`,
  grant: () => `gr_${ulid()}`,
  placeholder: () => `ph_${ulid()}`,
  approval: () => `ap_${ulid()}`,
  request: () => `req_${ulid()}`,
  sessionRequest: () => `sr_${ulid()}`,
  client: () => `cl_${ulid()}`,
}
