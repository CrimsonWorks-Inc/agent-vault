// The one module that talks to the UI server (contract U4).
//
// Same origin, the session cookie, and the X-AV-UI header on every request:
// the server refuses an API call without that header (src/ui/server.js), and
// a form post or a page on another origin cannot set it, which is the CSRF
// defence. Nothing here stores a response anywhere but memory.

/** The header the UI server requires, copied from src/ui/server.js. */
export const UI_HEADER = 'x-av-ui'
export const UI_HEADER_VALUE = '1'

/**
 * A refused or failed request. `status` is the HTTP status (0 when the UI
 * server could not be reached at all), `code` the daemon's AV_* code when it
 * gave one, `detail` the problem object or text the server sent.
 *
 * `kind` says what the page should do about it:
 *   'session' -> the session cookie is gone: show "No session".
 *   'daemon'  -> the UI server is up but cannot reach the daemon.
 *   'server'  -> the UI server itself did not answer (it exits when idle).
 *   'http'    -> an ordinary refusal; show the message where the action was.
 */
export class ApiError extends Error {
  constructor(message, { status = 0, code = null, detail = null, kind = 'http' } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = detail
    this.kind = kind
  }
}

/**
 * Read an error body into an ApiError. Today the server answers
 * `{error, detail}` where detail is the daemon's problem (`{code, rule, ...}`);
 * U3 also allows a flat `{code, detail}`. Both are read.
 */
export function errorFrom(status, data) {
  const body = data && typeof data === 'object' ? data : {}
  const problem = body.detail && typeof body.detail === 'object' ? body.detail : null
  const code = (typeof body.code === 'string' && body.code) || (typeof problem?.code === 'string' && problem.code) || null
  const message = (typeof body.error === 'string' && body.error)
    || (typeof body.detail === 'string' && body.detail)
    || (typeof problem?.detail === 'string' && problem.detail)
    || (typeof problem?.message === 'string' && problem.message)
    || `request failed (${status})`
  return new ApiError(message, { status, code, detail: body.detail ?? null, kind: kindOf(status, body, code) })
}

/**
 * A 401 is a lost session only when it is the cookie check that refused. The
 * presence gate also answers 401 ("this action needs a fresh authenticator
 * signature", "challenge expired"), and those belong beside the button.
 */
function kindOf(status, body, code) {
  if (status === 401 && (code === 'AV_UI_NO_SESSION' || body.error === 'not authenticated')) return 'session'
  // The UI server answers 503 exactly when its control socket did not.
  if (status === 503) return 'daemon'
  return 'http'
}

/** `path` with the given query parameters; undefined, null and '' are left out. */
export function withQuery(path, params = {}) {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    q.set(k, String(v))
  }
  const text = q.toString()
  if (!text) return path
  return `${path}${path.includes('?') ? '&' : '?'}${text}`
}

/**
 * The client. `onFatal(error)` hears about every 'session', 'daemon' and
 * 'server' failure, so the app can swap to the matching full-page screen
 * whatever component made the call.
 */
export function createApi({ fetch: doFetch = (...a) => globalThis.fetch(...a), base = '/api/', onFatal = null } = {}) {
  const listeners = new Set(onFatal ? [onFatal] : [])

  async function request(method, path, body) {
    const init = {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { [UI_HEADER]: UI_HEADER_VALUE, accept: 'application/json' },
    }
    if (body !== undefined && body !== null) {
      init.headers['content-type'] = 'application/json'
      init.body = JSON.stringify(body)
    }
    let res
    try {
      res = await doFetch(`${base}${String(path).replace(/^\/+/, '')}`, init)
    } catch (e) {
      throw fatal(new ApiError('The agent-vault UI server did not answer. It stops after 30 idle minutes; start it again with agent-vault ui.', {
        status: 0, kind: 'server', detail: String(e?.message ?? e),
      }))
    }
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      const err = errorFrom(res.status, data)
      throw err.kind === 'http' ? err : fatal(err)
    }
    return data
  }

  function fatal(err) {
    for (const fn of listeners) {
      try { fn(err) } catch { /* a listener's failure is not the request's */ }
    }
    return err
  }

  return {
    request,
    get: (path, query) => request('GET', withQuery(path, query)),
    post: (path, body) => request('POST', path, body),
    del: (path, query, body) => request('DELETE', withQuery(path, query), body),
    /** Hear about session loss and unreachable daemons; returns an unsubscribe. */
    onFatal(fn) { listeners.add(fn); return () => listeners.delete(fn) },
  }
}
