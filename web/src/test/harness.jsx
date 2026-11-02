// What component tests render inside: the same providers App.jsx sets up,
// over a fake fetch and a fake authenticator, so a test drives the real
// hooks (usePresence, useApi) and not mocks of them.
import { useMemo } from 'react'
import { render } from '@testing-library/react'
import { createApi } from '../lib/api.js'
import { createCache } from '../lib/cache.js'
import { ApiContext } from '../hooks/useApi.js'
import { PresenceContext, usePresenceController } from '../hooks/usePresence.js'
import { usePrompt } from '../hooks/usePrompt.js'
import { VaultContext } from '../hooks/useVault.js'
import { PromptProvider } from '../components/ui/PromptProvider.jsx'
import { PresenceStatus } from '../components/ui/PresenceStatus.jsx'
import { ToastProvider } from '../components/ui/Toast.jsx'
import { AUDIT_FIELDS, Cursors, LISTS, pageAnswer, pageList, pagingOf } from '../../../src/ui/list-paging.js'
import { towardPage } from '../../../src/ui/server.js'

/**
 * A fake UI server. `routes` maps "METHOD path" (path without the query) to a
 * value or a function of ({ query, body }). Every call is recorded.
 *
 * A list route's value is what the daemon answers (a bare array, or the
 * object a list sits inside). Asked with `paged=1`, it is paged here exactly
 * as src/ui/server.js pages it: the same pagingOf, towardPage, LISTS order
 * and search fields, and sealed cursors. So a component test sees the real
 * envelope, and a test that asks the wrong way gets the real 400. A value
 * that is already an envelope (it has `items`) is passed on as it is.
 */
export function fakeServer(routes = {}) {
  const calls = []
  const cursors = new Cursors()
  const fetch = async (url, init) => {
    const u = new URL(url, 'http://localhost')
    const path = u.pathname.replace(/^\/api\//, '')
    const body = init.body ? JSON.parse(init.body) : undefined
    const call = { method: init.method, path, query: Object.fromEntries(u.searchParams), body, headers: init.headers }
    calls.push(call)
    const key = `${init.method} ${path}`
    let answer = routes[key]
    if (answer === undefined) return { ok: false, status: 404, json: async () => ({ error: `no route ${key}` }) }
    if (typeof answer === 'function') answer = await answer(call)
    if (answer && answer.__status) return { ok: answer.__status < 400, status: answer.__status, json: async () => answer.body }
    if (init.method === 'GET') {
      try {
        answer = pagedLikeTheServer(path, u.searchParams, answer, cursors)
      } catch (e) {
        if (!e.problem) throw e
        const err = { error: e.message, code: e.code, detail: e.problem }
        return { ok: false, status: e.status, json: async () => err }
      }
    }
    return { ok: true, status: 200, json: async () => structuredClone(answer) }
  }
  return { fetch, calls }
}

/** How src/ui/server.js answers a list route's GET, for each paged route. */
const PAGED = {
  credentials: () => ({ spec: LISTS.credentials }),
  sessions: () => ({ spec: LISTS.sessions }),
  pending: () => ({ spec: LISTS.pending }),
  listeners: () => ({ spec: LISTS.listeners }),
  templates: (q) => (q.has('name') ? null : { spec: LISTS.templates }),
  tripwires: () => ({ spec: LISTS.tripwireRules, within: 'rules' }),
  'sessions/detail': (q) => ({ spec: LISTS.detailGrants, within: 'grants', filters: { sid: q.get('sid') ?? '' } }),
  'report/access': (q) => {
    const which = q.get('list') ?? 'sessions'
    return {
      spec: which === 'credentials' ? LISTS.reportCredentials : LISTS.reportSessions,
      within: which, drop: ['sessions', 'credentials'], filters: { since: q.get('since') || '7d' },
    }
  },
}

// The audit log, newest first by seq, `kind` an exact kind or a family (the
// daemon's ofKind), rows without a seq skipped (the server's #auditPage).
const AUDIT = { name: 'audit', key: (r) => [r.seq], dirs: [-1], fields: AUDIT_FIELDS }

function pagedLikeTheServer(path, params, answer, cursors) {
  if (path !== 'audit' && !PAGED[path]) return answer
  const paging = pagingOf(params)
  if (!paging || Array.isArray(answer?.items)) return answer
  const shown = towardPage(answer)
  if (path === 'audit') {
    const kind = params.get('kind')
    const rows = (Array.isArray(shown) ? shown : [])
      .filter((r) => Number.isSafeInteger(r?.seq))
      .filter((r) => kind === null || r.kind === kind || String(r.kind).startsWith(`${kind}.`))
    return { ...pageList(rows, AUDIT, paging, { kind }, cursors), total: null }
  }
  const route = PAGED[path](params)
  if (!route) return answer
  return pageAnswer(shown, route.spec, paging, route, cursors)
}

/** A platform authenticator that records what it was asked and signs anything. */
export function fakeAuthenticator({ onGet } = {}) {
  const asked = []
  return {
    asked,
    credentials: {
      async get(opts) {
        asked.push(opts)
        await onGet?.(opts)
        return {
          rawId: new Uint8Array([1, 2, 3]).buffer,
          response: { authenticatorData: new Uint8Array([4]).buffer, clientDataJSON: new Uint8Array([5]).buffer, signature: new Uint8Array([6]).buffer },
          getClientExtensionResults: () => ({}),
        }
      },
      async create() { throw new Error('not in this test') },
    },
  }
}

const DEFAULT_VAULT = { locked: false, lockState: { locked: false }, pending: [], pendingKnown: true, pendingCount: 0, context: { cli: 'agent-vault' }, refresh: () => {} }

function Providers({ server, authenticator, vault, children }) {
  const api = useMemo(() => createApi({ fetch: server.fetch }), [server])
  const slow = useMemo(() => createCache(), [])
  const ctx = useMemo(() => ({ api, slow }), [api, slow])
  return (
    <ApiContext.Provider value={ctx}>
      <ToastProvider>
        <PromptProvider>
          <WithPresence api={api} authenticator={authenticator} vault={vault}>{children}</WithPresence>
        </PromptProvider>
      </ToastProvider>
    </ApiContext.Provider>
  )
}

function WithPresence({ api, authenticator, vault, children }) {
  const prompt = usePrompt()
  const platform = useMemo(() => ({ credentials: () => authenticator?.credentials, random: (n) => new Uint8Array(n) }), [authenticator])
  const presence = usePresenceController({ api, askSecret: (label) => prompt.secret({ title: label }), platform })
  return (
    <PresenceContext.Provider value={presence}>
      <VaultContext.Provider value={{ ...DEFAULT_VAULT, ...vault }}>
        {children}
        <PresenceStatus />
      </VaultContext.Provider>
    </PresenceContext.Provider>
  )
}

export function renderWith(ui, { server = fakeServer(), authenticator = fakeAuthenticator(), vault = {} } = {}) {
  return { server, authenticator, ...render(<Providers server={server} authenticator={authenticator} vault={vault}>{ui}</Providers>) }
}
