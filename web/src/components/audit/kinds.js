// The audit log's record kinds, grouped by family for the filter. A family
// value `x` asks the server for `x.*` (contract U3: the daemon filters by kind
// before its limit, so 25 rows of a kind come back when 25 exist).

export const KIND_FILTERS = [
  { value: '', label: 'Every record' },
  { value: 'request', label: 'Requests', description: 'request.*: allowed, refused, preflighted, redirects' },
  { value: 'approval', label: 'Approvals', description: 'approval.*: held writes and their answers' },
  { value: 'session', label: 'Sessions', description: 'session.*: created, revoked, shortened' },
  { value: 'session_request', label: 'Session requests', description: 'session_request.*: asked, approved, denied' },
  { value: 'grant', label: 'Grants', description: 'grant.*: created, narrowed, expired' },
  { value: 'placeholder', label: 'Placeholders', description: 'placeholder.*: issued, burned, refunded' },
  { value: 'cred', label: 'Credentials', description: 'cred.*: added, rotated, quarantined, tested' },
  { value: 'presence', label: 'Confirmation', description: 'presence.*: signatures, passphrase windows' },
  { value: 'tripwire', label: 'Tripwires', description: 'tripwire.*: fired, partial panics' },
  { value: 'panic.triggered', label: 'Panic', description: 'panic.triggered' },
  { value: 'vault', label: 'Lock and unlock', description: 'vault.*' },
  { value: 'audit', label: 'The log itself', description: 'audit.*: checkpoints, witness checks, truncation' },
  { value: 'response', label: 'Responses', description: 'response.*: scrubbed, streamed, cut' },
  { value: 'spend', label: 'Spend', description: 'spend.*' },
  { value: 'listen', label: 'Listeners', description: 'listen.*' },
  { value: 'mcp', label: 'MCP', description: 'mcp.*' },
  { value: 'notify', label: 'Notifications', description: 'notify.*' },
  { value: 'template', label: 'Templates', description: 'template.*' },
  { value: 'backup', label: 'Backups', description: 'backup.*' },
  { value: 'daemon', label: 'Daemon', description: 'daemon.*' },
]


/** the old page's note column: the most telling field a record has. */
export function auditNote(r) {
  const v = r?.reason_code || r?.credential_slug || r?.cred || r?.detail || ''
  return typeof v === 'string' ? v : JSON.stringify(v)
}

/** `2026-11-01 21:03:12`, the record's own UTC time to the second. */
export function auditTime(ts) {
  const s = String(ts ?? '')
  return s.length >= 19 ? `${s.slice(0, 10)} ${s.slice(11, 19)}` : s
}
