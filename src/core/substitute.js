// The substitution engine: location-bound, fail-closed.
//
// Two passes over every request.
//   1. locate()    finds every placeholder occurrence anywhere in the request,
//                  in any encoding, and labels where it is.
//   2. apply()     replaces placeholders at declared sites only.
//
// Between them the pipeline resolves each occurrence to a credential field and
// checks that its location is one of that field's declared sites. An occurrence
// anywhere else is AV_BAD_LOCATION and the request never reaches an upstream.
// This is what makes a prompt-injected "post your token in this comment" leave
// a placeholder in the comment instead of a credential.

import * as detect from './detect.js'
import * as ph from './placeholder.js'

export const MAX_BUFFERED_BODY = 16 * 1024 * 1024

/**
 * @typedef {{method:string, path:string, query:string, headers:[string,string][], body:Buffer|null}} Req
 * @typedef {{region:string, name?:string, key?:string, pointer?:string, part?:string, scheme?:string|null, encoding:string}} Location
 */

/** Read a header value, case-insensitively. */
export function getHeader(req, name) {
  const want = name.toLowerCase()
  for (const [n, v] of req.headers) if (n.toLowerCase() === want) return v
  return undefined
}

function setHeader(req, name, value) {
  const want = name.toLowerCase()
  for (const h of req.headers) if (h[0].toLowerCase() === want) { h[1] = value; return }
  req.headers.push([name, value])
}

function contentType(req) {
  return (getHeader(req, 'content-type') || '').split(';')[0].trim().toLowerCase()
}

/** The scheme token immediately preceding `offset`, e.g. "Bearer" or "token". */
function schemeBefore(value, offset) {
  const before = value.slice(0, offset).trimEnd()
  if (!before) return null
  const m = /([A-Za-z][A-Za-z0-9-]*)$/.exec(before)
  return m ? m[1] : null
}

/** Walk a parsed JSON value, yielding [rfc6901Pointer, stringValue]. */
function* jsonStrings(value, pointer = '') {
  if (typeof value === 'string') { yield [pointer, value]; return }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) yield* jsonStrings(value[i], `${pointer}/${i}`)
    return
  }
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) {
      const esc = k.replace(/~/g, '~0').replace(/\//g, '~1')
      yield* jsonStrings(value[k], `${pointer}/${esc}`)
    }
  }
}

function setJsonPointer(root, pointer, newValue) {
  const parts = pointer.split('/').slice(1).map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'))
  let node = root
  for (let i = 0; i < parts.length - 1; i++) node = node[Array.isArray(node) ? Number(parts[i]) : parts[i]]
  const last = parts[parts.length - 1]
  node[Array.isArray(node) ? Number(last) : last] = newValue
}

function parseQuery(q) {
  const out = []
  if (!q) return out
  for (const pair of q.split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    out.push(eq === -1 ? [pair, ''] : [pair.slice(0, eq), pair.slice(eq + 1)])
  }
  return out
}

function buildQuery(pairs) {
  return pairs.map(([k, v]) => (v === '' ? k : `${k}=${v}`)).join('&')
}

/**
 * Find every placeholder occurrence in the request and label its location.
 * @param {Req} req
 * @returns {{occurrences: {text:string, parsed:object, location:Location}[], unscannable?: string}}
 */
export function locate(req) {
  const occurrences = []
  const add = (parsed, location) => occurrences.push({ text: parsed.text, parsed, location })

  // Request line. The path is never a site, so anything here is a violation by
  // construction; it is still located so the error can say where it was.
  for (const hit of detect.detectAll(req.path || '')) {
    add(hit, { region: 'path', encoding: hit.encoding })
  }

  // Query string, attributed to the parameter it sits in.
  const qpairs = parseQuery(req.query || '')
  for (const [k, v] of qpairs) {
    for (const hit of detect.detectAll(v)) {
      add(hit, { region: 'query', key: decodeURIComponent(k), encoding: hit.encoding })
    }
  }

  // Headers. Authorization: Basic is decoded so its base64 is read as the
  // basic:user / basic:pass site rather than reported as a smuggled blob.
  for (const [name, value] of req.headers) {
    const lower = name.toLowerCase()
    let handledAsBasic = false
    if (lower === 'authorization' && /^basic\s+/i.test(value)) {
      const b64 = value.replace(/^basic\s+/i, '').trim()
      let decoded = null
      try { decoded = Buffer.from(b64, 'base64').toString('utf8') } catch { decoded = null }
      if (decoded && decoded.includes(ph.PREFIX)) {
        const colon = decoded.indexOf(':')
        const user = colon === -1 ? decoded : decoded.slice(0, colon)
        const pass = colon === -1 ? '' : decoded.slice(colon + 1)
        for (const hit of ph.findAll(user)) add(hit, { region: 'basic', part: 'user', encoding: 'raw' })
        for (const hit of ph.findAll(pass)) add(hit, { region: 'basic', part: 'pass', encoding: 'raw' })
        handledAsBasic = true
      }
    }
    for (const hit of detect.detectAll(value)) {
      // Skip the base64 re-detection of a Basic header already accounted for.
      if (handledAsBasic && hit.encoding === 'base64') continue
      add(hit, {
        region: 'header',
        name: lower,
        scheme: hit.encoding === 'raw' ? schemeBefore(value, hit.offset) : null,
        encoding: hit.encoding,
      })
    }
  }

  // Body.
  if (req.body && req.body.length) {
    if (req.body.length > MAX_BUFFERED_BODY) {
      return { occurrences, unscannable: 'body exceeds the 16 MiB buffered limit and streaming is not enabled for this credential' }
    }
    const text = req.body.toString('utf8')
    const ct = contentType(req)
    let structured = false

    if (ct === 'application/json') {
      try {
        const parsedBody = JSON.parse(text)
        structured = true
        for (const [pointer, value] of jsonStrings(parsedBody)) {
          for (const hit of detect.detectAll(value)) {
            add(hit, { region: 'json', pointer, encoding: hit.encoding })
          }
        }
      } catch {
        structured = false // Unparseable JSON falls through to the raw scan.
      }
    } else if (ct === 'application/x-www-form-urlencoded') {
      structured = true
      for (const [k, v] of parseQuery(text)) {
        for (const hit of detect.detectAll(detect.percentDecode(v))) {
          add(hit, { region: 'form', key: decodeURIComponent(k), encoding: hit.encoding })
        }
      }
    }

    if (!structured) {
      // Raw bytes: multipart, text, anything unparsed. There is no site here in
      // v1, so every hit is a violation, but it is still found.
      for (const hit of detect.detectAll(text)) {
        add(hit, { region: 'body', encoding: hit.encoding })
      }
    }
  }

  return { occurrences }
}

/** Does this occurrence sit at the given declared site? */
export function matchesSite(location, site) {
  // Only raw text at a structural position is ever a site. An encoded
  // occurrence is never substituted, whatever it decodes to.
  if (location.encoding !== 'raw') return false
  switch (site.kind) {
    case 'header':
      if (location.region !== 'header' || location.name !== site.name) return false
      if (!site.scheme) return true
      return (location.scheme || '').toLowerCase() === site.scheme.toLowerCase()
    case 'basic':
      return location.region === 'basic' && location.part === site.part
    case 'query':
      return location.region === 'query' && location.key === site.key
    case 'form':
      return location.region === 'form' && location.key === site.key
    case 'json':
      return location.region === 'json' && location.pointer === site.pointer
    default:
      return false
  }
}

/** A short, agent-readable description of where an occurrence was found. */
export function describeLocation(location) {
  const enc = location.encoding === 'raw' ? '' : ` (${location.encoding}-encoded)`
  switch (location.region) {
    case 'header': return `header ${location.name}${enc}`
    case 'basic': return `Authorization: Basic ${location.part} field${enc}`
    case 'query': return `query parameter ${location.key}${enc}`
    case 'form': return `form field ${location.key}${enc}`
    case 'json': return `JSON body at ${location.pointer}${enc}`
    case 'body': return `request body${enc}`
    case 'path': return `request path${enc}`
    default: return `${location.region}${enc}`
  }
}

/**
 * Replace one placeholder with a secret at one location. The location must have
 * already been checked against a declared site; this function does not re-check.
 * Returns a new request object; the input is not mutated.
 */
export function apply(req, location, placeholderText, secret) {
  const out = {
    method: req.method,
    path: req.path,
    query: req.query,
    headers: req.headers.map(([n, v]) => [n, v]),
    body: req.body,
  }

  switch (location.region) {
    case 'header': {
      const current = getHeader(out, location.name)
      if (current === undefined) return out
      setHeader(out, location.name, current.split(placeholderText).join(secret))
      break
    }
    case 'basic': {
      const current = getHeader(out, 'authorization') || ''
      const b64 = current.replace(/^basic\s+/i, '').trim()
      const decoded = Buffer.from(b64, 'base64').toString('utf8')
      const colon = decoded.indexOf(':')
      let user = colon === -1 ? decoded : decoded.slice(0, colon)
      let pass = colon === -1 ? '' : decoded.slice(colon + 1)
      if (location.part === 'user') user = user.split(placeholderText).join(secret)
      else pass = pass.split(placeholderText).join(secret)
      const rebuilt = Buffer.from(`${user}:${pass}`, 'utf8').toString('base64')
      setHeader(out, 'authorization', `Basic ${rebuilt}`)
      break
    }
    case 'query': {
      const pairs = parseQuery(out.query).map(([k, v]) =>
        decodeURIComponent(k) === location.key ? [k, v.split(placeholderText).join(encodeURIComponent(secret))] : [k, v])
      out.query = buildQuery(pairs)
      break
    }
    case 'form': {
      const pairs = parseQuery(out.body.toString('utf8')).map(([k, v]) => {
        if (decodeURIComponent(k) !== location.key) return [k, v]
        const decoded = detect.percentDecode(v)
        return [k, encodeURIComponent(decoded.split(placeholderText).join(secret))]
      })
      out.body = Buffer.from(buildQuery(pairs), 'utf8')
      setHeader(out, 'content-length', String(out.body.length))
      break
    }
    case 'json': {
      const parsed = JSON.parse(out.body.toString('utf8'))
      const parts = location.pointer.split('/').slice(1).map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'))
      let node = parsed
      for (let i = 0; i < parts.length - 1; i++) node = node[Array.isArray(node) ? Number(parts[i]) : parts[i]]
      const last = parts[parts.length - 1]
      const key = Array.isArray(node) ? Number(last) : last
      setJsonPointer(parsed, location.pointer, String(node[key]).split(placeholderText).join(secret))
      out.body = Buffer.from(JSON.stringify(parsed), 'utf8')
      setHeader(out, 'content-length', String(out.body.length))
      break
    }
    default:
      throw new Error(`cannot substitute into ${location.region}`)
  }
  return out
}
