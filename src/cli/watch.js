import { request } from 'node:http'
import { execFile, spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { CODES, EXIT } from '../core/errors.js'

// Controls, bidi embeddings/overrides/isolates and line separators: each
// changes what a terminal shows (cleanText in control-commands.js).
const clean = (value) => String(value ?? '').replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g, '')

/**
 * The four display fields of one stream entry, cleaned: control characters
 * stripped, placeholders replaced and query strings dropped from the headline.
 * Never the agent's reason or body. null for an entry that is not one.
 */
export function safeEntry(entry) {
  if (!entry || typeof entry !== 'object' || !['request', 'session'].includes(entry.kind) || typeof entry.id !== 'string') return null
  const headline = clean(entry.headline).replace(/av1\.[A-Za-z0-9_.-]+/g, '[placeholder]').replace(/\?[^\s]*/g, '')
  const created_at = typeof entry.created_at === 'number' && Number.isFinite(entry.created_at) ? entry.created_at
    : typeof entry.created_at === 'string' ? clean(entry.created_at) : undefined
  return { kind: entry.kind, id: clean(entry.id), headline, created_at }
}

/** Watch the local approval stream until SIGINT. Dependencies are injectable for tests. */
export async function watchApprovals({ socketPath, json = false, notify = true, open = false,
  onEvent, quiet = false, deps = {} } = {}) {
  const d = { request, execFile, spawn, signals: process, stdout: process.stdout,
    stderr: process.stderr, platform: process.platform, setTimeout, clearTimeout, ...deps }
  return new Promise((resolve, reject) => {
    let stopped = false, connected = false, req, res, retryTimer, noticeTimer
    let backoff = 1000, opened = false, warned = false, cooling = false
    let pending = []
    const seen = new Set()
    const finish = (error) => {
      if (stopped) return
      stopped = true
      d.clearTimeout(retryTimer)
      d.clearTimeout(noticeTimer)
      d.signals.removeListener('SIGINT', interrupt)
      res?.destroy()
      req?.destroy()
      if (error) reject(error)
      else resolve(0)
    }
    const interrupt = () => finish()
    const note = () => {
      if (!warned && !stopped) {
        warned = true
        d.stderr.write('note desktop notifications are unavailable\n')
      }
    }
    const desktop = (items) => {
      const first = items[0]
      const suffix = items.length > 1 ? ` and ${items.length - 1} more` : ''
      const text = clean(`${first.kind === 'request' ? 'Held request' : 'Session requested'}: ${first.headline}`).slice(0, 120 - suffix.length) + suffix
      const args = d.platform === 'darwin'
        ? ['-e', 'on run argv', '-e', 'display notification (item 1 of argv) with title "agent-vault"', '-e', 'end run', '--', text]
        : ['agent-vault', text]
      if (!['darwin', 'linux'].includes(d.platform)) return
      try { d.execFile(d.platform === 'darwin' ? 'osascript' : 'notify-send', args, (err) => { if (err) note() }) } catch { note() }
      cooling = true
      noticeTimer = d.setTimeout(() => {
        cooling = false
        if (pending.length) {
          const batch = pending
          pending = []
          desktop(batch)
        }
      }, 10_000)
    }
    const item = (safe) => {
      if (!safe || seen.has(safe.id)) return
      seen.add(safe.id)
      const { headline } = safe
      if (!json && !quiet) {
        const label = safe.kind === 'request' ? 'held' : 'session requested'
        const colored = d.stdout.isTTY && !process.env.NO_COLOR ? `\x1b[33m${label}\x1b[0m` : label
        d.stdout.write(`${colored} ${safe.id}  ${headline}\n`)
      }
      if (!json && notify) {
        if (cooling) pending.push(safe)
        else desktop([safe])
      }
      if (!json && open && !opened) {
        opened = true
        try {
          const child = d.spawn(process.execPath, [fileURLToPath(new URL('../../bin/agent-vault.js', import.meta.url)), 'ui'], { stdio: 'ignore', detached: true })
          child.on('error', () => {})
          child.unref()
        } catch { /* The stream remains useful if the UI cannot launch. */ }
      }
    }
    const event = (name, raw) => {
      backoff = 1000
      // Only the projection leaves this function, on every path: --json, the
      // terminal and the notification. The raw frame may carry more than the
      // four display fields, and none of the rest is ever printed.
      let data
      if (name === 'snapshot' && Array.isArray(raw.items)) data = { items: raw.items.map(safeEntry).filter(Boolean) }
      else if (name === 'pending') data = safeEntry(raw)
      if (!data) return
      if (json) d.stdout.write(`${JSON.stringify({ ok: true, data: { ...data, event: name } })}\n`)
      if (name === 'snapshot') data.items.forEach(item)
      else item(data)
      onEvent?.({ event: name, data })
    }
    const connect = () => {
      if (stopped) return
      let ended = false
      const disconnected = (error) => {
        if (ended || stopped) return
        ended = true
        res?.destroy()
        req?.destroy()
        if (!connected) return finish(Object.assign(new Error('the daemon cannot be reached'), { exit: EXIT.DAEMON_UNREACHABLE, cause: error }))
        retryTimer = d.setTimeout(connect, backoff)
        backoff = Math.min(backoff * 2, 30_000)
      }
      try {
        req = d.request({ socketPath, method: 'GET', path: '/v1/pending/stream', headers: { accept: 'text/event-stream' } }, (response) => {
          res = response
          if (stopped) return res.destroy()
          if (res.statusCode !== 200) {
            let body = ''
            res.setEncoding('utf8')
            res.on('data', (chunk) => { if (body.length < 65536) body += chunk })
            res.on('end', () => {
              let problem
              try { problem = JSON.parse(body) } catch { problem = {} }
              if (res.statusCode === 404 && /no control route/.test(problem.detail || '')) {
                return finish(Object.assign(new Error('the running daemon is older than this command'), {
                  exit: EXIT.VERSION_SKEW, next: 'restart the daemon you started with: agent-vault daemon', problem,
                }))
              }
              finish(Object.assign(new Error(problem.detail || `approval stream returned HTTP ${res.statusCode}`), {
                exit: CODES[problem.code]?.exit ?? EXIT.FAILURE, problem,
              }))
            })
            res.on('error', disconnected)
            return
          }
          connected = true
          let buffer = '', name = 'message', lines = []
          res.setEncoding('utf8')
          res.on('data', (chunk) => {
            if (stopped) return
            buffer += chunk
            if (buffer.length > 262144) return disconnected(new Error('approval stream frame too large'))
            let at
            while ((at = buffer.indexOf('\n')) !== -1) {
              const line = buffer.slice(0, at).replace(/\r$/, '')
              buffer = buffer.slice(at + 1)
              if (!line) {
                if (lines.length) {
                  try {
                    const data = JSON.parse(lines.join('\n'))
                    if (data && typeof data === 'object' && !Array.isArray(data)) event(name, data)
                  } catch { /* Ignore malformed frames; the next frame is independent. */ }
                }
                name = 'message'; lines = []
              } else if (line.startsWith('event:')) name = line.slice(6).replace(/^ /, '')
              else if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''))
              if (lines.reduce((n, s) => n + s.length, 0) > 262144) return disconnected(new Error('approval stream frame too large'))
            }
          })
          res.on('end', disconnected)
          res.on('error', disconnected)
          res.on('close', disconnected)
        })
        req.on('error', disconnected)
        req.end()
      } catch (error) { disconnected(error) }
    }
    d.signals.on('SIGINT', interrupt)
    connect()
  })
}
