// Hash routing. The fragment survives the redirect that burns the launch
// token, so `agent-vault ui` can open the page on a view: /#docs/connect,
// /#approvals/<id>. The same shape the old page used, so those links still work.

/** Every page in the sidebar, in order (contract U1). */
export const PAGES = [
  { id: 'overview', label: 'Overview' },
  { id: 'approvals', label: 'Approvals' },
  { id: 'credentials', label: 'Credentials' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'templates', label: 'Templates' },
  { id: 'audit', label: 'Audit' },
  { id: 'containment', label: 'Containment' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'settings', label: 'Settings' },
  { id: 'docs', label: 'Docs' },
]
const IDS = new Set(PAGES.map((p) => p.id))

/** `#approvals/abc` -> { page: 'approvals', rest: 'abc' }; unknown -> overview. */
export function parseHash(hash) {
  const raw = String(hash ?? '').replace(/^#\/?/, '')
  const slash = raw.indexOf('/')
  const head = slash === -1 ? raw : raw.slice(0, slash)
  let rest = slash === -1 ? '' : raw.slice(slash + 1)
  try { rest = decodeURIComponent(rest) } catch { rest = '' }
  return IDS.has(head) ? { page: head, rest } : { page: 'overview', rest: '' }
}

export function formatHash(page, rest = '') {
  return rest ? `#${page}/${encodeURIComponent(rest)}` : `#${page}`
}
