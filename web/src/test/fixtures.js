// A vault's worth of answers, shaped as the UI server gives them today.
export const SOON = new Date(Date.now() + 3 * 86400e3).toISOString()

export function overviewRoutes(over = {}) {
  return {
    'GET status': { locked: false, daemon_version: '0.2.0', gateway_port: 7411, placeholders_live: 5, audit_records: 214 },
    'GET credentials': [
      { slug: 'gh-work', kind: 'github', expiry_warning: null },
      { slug: 'openai', kind: 'openai', expiry_warning: 'soon', expires_at: SOON },
      { slug: 'old', kind: 'http', expiry_warning: 'expired' },
    ],
    'GET sessions': [
      { id: 's_1', label: 'a', state: 'active' },
      { id: 's_2', label: 'b', state: 'active', infinite: true, expires_at: null },
      { id: 's_3', label: 'c', state: 'revoked' },
    ],
    'GET pending': [],
    'GET lockstate': { locked: false, has_passphrase: true, has_touchid: false },
    'GET unlock/state': { locked: false, has_passphrase: true, has_touchid: false },
    'GET presence/state': { enrolled: true, credentialId: 'c1', rpId: 'localhost' },
    'GET report/access': {
      complete: true,
      sessions: [{ id: 's_1', label: 'deploy bot \u202eevil', unused_methods: ['DELETE', 'PUT'] }],
      credentials: [{ slug: 'old', quarantined: true, expiry_warning: 'expired' }],
    },
    'GET tripwires': { enabled: false, rules_saved: false, rules: [], defaults: [{ id: 'replay', codes: ['AV_PH_REPLAY'], threshold: 1, window_s: 600, action: 'revoke_session' }] },
    'GET audit': [{ seq: 211, kind: 'tripwire.fired', rule_id: 'replay', ts: new Date().toISOString(), action: 'revoke_session' }],
    'GET notify': { webhook: null },
    'GET docs/context': { cli: 'agent-vault', gateway_port: 7411 },
    'GET audit/verify': { ok: true, count: 214 },
    'POST presence/challenge': { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' },
    'POST tripwires': { enabled: true },
    'POST panic': { revoked_sessions: 2, denied_approvals: 0, denied_session_requests: 1, locked: false },
    ...over,
  }
}
