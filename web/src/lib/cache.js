// Reads that change slowly (the access report, tripwires, notify settings),
// kept for half a minute so the five-second overview refresh does not ask
// the daemon for each of them every time. Anything the page changes clears it
// (app.html's `slow` map).

export function createCache({ ms = 30_000, now = () => Date.now() } = {}) {
  const hits = new Map()
  return {
    async get(key, fn, ttl = ms) {
      const hit = hits.get(key)
      if (hit && hit.at > now() - ttl) return hit.value
      const value = await fn()
      hits.set(key, { at: now(), value })
      return value
    },
    clear() { hits.clear() },
    has(key) { return hits.has(key) },
  }
}
