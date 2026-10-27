// Tripwires (F16): a run of suspicious denials ends the session that made them.
//
// Off by default (Q3). Counters are keyed by session id and fed only by
// AUTHENTICATED denials, after the audit record and the refund, before the
// denial is returned. An unauthenticated probe has no session to count
// against, and a session id read from a placeholder alone is exactly what a
// probe can forge, so it is never used. Preflight denials are never fed here.
// Nothing on the gateway can reset a counter; only revoking the session does.

export const DEFAULT_RULES = Object.freeze([
  { id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' },
  { id: 'bad_location', codes: ['AV_BAD_LOCATION'], threshold: 3, window_s: 600, action: 'revoke_session' },
  { id: 'cross_session', codes: ['AV_PH_CROSS_SESSION', 'AV_PH_WRONG_CONNECTOR'], threshold: 3, window_s: 600, action: 'revoke_session' },
  { id: 'deny_paths', rule_prefix: 'deny_paths:', threshold: 5, window_s: 600, action: 'revoke_session' },
])

export class Tripwires {
  #counts = new Map()
  constructor(vault, pipeline) { this.vault = vault; this.pipeline = pipeline }
  reset(sessionId) { this.#counts.delete(sessionId) }

  observe({ sessionId, credentialId, code, rule, preflight = false }) {
    const settings = this.vault.getSettings()?.tripwires
    if (!settings?.enabled || !sessionId || preflight || this.vault.locked) return null
    const session = this.vault.db.sessions[sessionId]
    if (!session || session.state !== 'active') { this.reset(sessionId); return null }
    for (const sid of this.#counts.keys()) if (this.vault.db.sessions[sid]?.state !== 'active') this.reset(sid)
    const now = Date.now()
    // Rules that cannot be read are the defaults, not none: tripwires that are
    // on stay on.
    const rules = Array.isArray(settings.rules) ? settings.rules : DEFAULT_RULES
    for (const item of rules) {
      if (item === null || typeof item !== 'object') continue
      // Store validates settings, but corrupt persisted counters or rules must
      // never turn NaN into an always-open threshold comparison.
      if (!Number.isInteger(item.threshold) || item.threshold < 1 || item.threshold > 1000 || !Number.isInteger(item.window_s) || item.window_s < 10 || item.window_s > 86400) continue
      const byCode = Array.isArray(item.codes) && item.codes.includes(code)
      const byRule = typeof item.rule_prefix === 'string' && item.rule_prefix !== '' && typeof rule === 'string' && rule.startsWith(item.rule_prefix)
      if (!byCode && !byRule) continue
      let counts = this.#counts.get(sessionId)
      if (!counts) { counts = new Map(); this.#counts.set(sessionId, counts) }
      const timestamps = (counts.get(item.id) ?? []).filter((at) => now - at < item.window_s * 1000)
      timestamps.push(now)
      counts.set(item.id, timestamps.slice(-item.threshold))
      if (timestamps.length < item.threshold) continue
      const cred = this.vault.db.credentials[credentialId]
      const record = () => this.vault.audit.write('tripwire.fired', { rule_id: item.id, session_id: sessionId, credential_slug: cred?.slug ?? null, count: Math.min(timestamps.length, item.threshold), window_s: item.window_s, action: item.action })
      if (item.action === 'revoke_session') {
        this.vault.revokeSession(sessionId, `tripwire:${item.id}`)
        this.pipeline.denyApprovals({ sessionId }, 'tripwire')
        this.reset(sessionId)
      } else if (item.action === 'quarantine_credential') {
        if (!cred) continue
        this.vault.setQuarantine(cred.slug, { by: 'tripwire', rule_id: item.id })
        this.pipeline.denyApprovals({ credentialId }, 'quarantined')
      } else if (item.action === 'panic') {
        // The panic sequence without the lock. Its own steps run before the
        // denial is returned; the hook for session requests is awaited.
        return this.pipeline.panic({ reason: null, lock: false }).then((result) => { this.lastPanic = result; record(); return item })
      } else continue
      record()
      return item
    }
    return null
  }
}
