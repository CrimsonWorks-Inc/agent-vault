/**
 * The one reading of a request that the gateway enforces.
 *
 * Five rounds of review found the same bug five ways: one piece of code
 * checked a request and another sent it, and the two parsed it differently.
 * The payload rules read the query with URLSearchParams while Rack split it
 * on `;` too; the direct path folded `.method` into `_method` while a
 * redirect hop looked for `_method` alone. So the request is read here, once,
 * and every check reads this view: routes, methods, payload rules, method
 * overrides and preflight, on the direct path and on every redirect hop. What
 * goes upstream is built from the same view.
 *
 * The view reads a request as the UNION of what common upstreams accept. A
 * query is split on `&` and on `;`, as Rack does. A name is decoded once, as
 * every form parser does. A method-override name is folded as PHP and Rack
 * fold it. Where two of those readers could disagree about what a request
 * says, the checks refuse it rather than pick one, and a name no API sends,
 * one its readers cut, trim or decode differently, is refused outright.
 */

/** Headers a framework may honour in place of the request-line method. */
export const METHOD_OVERRIDE_HEADERS = new Set(['x-http-method-override', 'x-http-method', 'x-method-override'])

/**
 * Query and body fields a framework may honour in place of the request-line
 * method, by their folded names: Rails and Laravel's `_method`, `__method`,
 * and the override headers spelled as fields.
 */
const METHOD_OVERRIDE_FIELDS = new Set(['_method', '__method', 'x_http_method_override', 'x_http_method', 'x_method_override'])

/**
 * The names a field may be read as. PHP registers a name only up to its
 * first NUL and without its leading spaces, then turns a space, a dot and an
 * unmatched `[` in what is left into `_`: so `.method` and `_method%00x` are
 * Laravel's `_method`, `+force` is `force`, and `_method[]` is still the
 * `_method` field to Rack and PHP. The name as written is folded as well as
 * the name PHP keeps, and letter case and `-` against `_` are folded too: a
 * name only ever folds to refuse more.
 */
export function foldedNames(name) {
  const out = new Set()
  for (const base of [String(name), String(name).split('\0')[0].replace(/^ +/, '')]) {
    const n = base.toLowerCase().replace(/[ .-]/g, '_')
    out.add(n.replace(/\[.*$/s, '')).add(n.replace(/\[/g, '_'))
  }
  return [...out]
}

export const isOverrideField = (name) => foldedNames(name).some((n) => METHOD_OVERRIDE_FIELDS.has(n))

/**
 * A name its readers do not agree on: an empty one, or one holding a NUL or
 * another control character, a character outside ASCII, or a space at
 * either end. PHP reads `force%00` and `+force` as `force`, where every other
 * reader sees another name, and folding each such shape onto the names the
 * rules use would be one more list of spellings to get wrong. No API names a
 * parameter so, so the gateway refuses a request that does.
 */
export const isStrayName = (name) => !name || /[^\x20-\x7e]|^ | $/.test(name)

/** One component of a query or form body, decoded exactly as URLSearchParams does. */
const formDecode = (s) => new URLSearchParams(`x=${s}`).get('x')

/**
 * Every `name=value` pair in a query or a form body, in order, repeats kept.
 * Split on `&` and on `;`: the WHATWG parser splits on `&` alone and Rack on
 * both, and a pair one of them sees and the other does not is how a
 * parameter hid from the rules while it was still sent. `rawName` is the
 * name as written, before decoding. `separator` reads it as an `&`-only
 * reader does.
 */
export function queryParams(raw, separator = /[&;]/) {
  const out = []
  for (const pair of String(raw ?? '').split(separator)) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    const rawName = eq === -1 ? pair : pair.slice(0, eq)
    out.push({ rawName, name: formDecode(rawName), value: eq === -1 ? '' : formDecode(pair.slice(eq + 1)) })
  }
  return out
}

/** Every method a method-override header asks for, uppercased, in order. */
function headerOverrides(headers) {
  const out = []
  for (const [n, v] of headers) {
    if (!METHOD_OVERRIDE_HEADERS.has(String(n).toLowerCase())) continue
    for (const one of [v].flat()) {
      for (const m of String(one).split(',')) {
        const method = m.trim().toUpperCase()
        if (method && !out.includes(method)) out.push(method)
      }
    }
  }
  return out
}

/**
 * Every pair in a query or a form body, as both kinds of reader read it.
 * Split on `;` as well, `a=1;_method=DELETE` names DELETE; split on `&`
 * alone, `.method=GET;force=1` names `GET;force=1`, which is not GET.
 */
const bothReadings = (raw) => [...queryParams(raw), ...(raw.includes(';') ? queryParams(raw, '&') : [])]

/**
 * Every field name a framework may read, and every value a method-override
 * field carries: in the query, in a form or multipart body, and at the top
 * level of a JSON body. Each copy of a repeated field is returned, since
 * frameworks differ on which one wins.
 */
function fields(query, mediaType, body) {
  const names = [], overrides = []
  const read = (list) => { for (const p of list) { names.push(p.name); if (isOverrideField(p.name)) overrides.push(p.value) } }
  read(bothReadings(query))
  if (body == null || !body.length) return { names, overrides }
  const text = (Buffer.isBuffer(body) ? body.toString('utf8') : String(body)).replace(/^﻿/, '')
  if (mediaType === 'application/x-www-form-urlencoded') read(bothReadings(text))
  else if (mediaType === 'multipart/form-data') {
    // Each part's names, every `name` in its Content-Disposition with any
    // line it was folded onto, and its value: what follows the part's
    // headers up to the next delimiter. A part that names an override and
    // has no readable value counts as naming another method.
    for (const m of text.matchAll(/content-disposition:/gi)) {
      const rest = text.slice(m.index + m[0].length)
      const end = /\r?\n\r?\n/.exec(rest)
      const disposition = (end ? rest.slice(0, end.index) : rest).replace(/;[ \t]*\r?\n|\r?\n[ \t]+/g, (s) => (s[0] === ';' ? '; ' : ' ')).split(/\r?\n/)[0]
      const value = end && /^([\s\S]*?)\r?\n--/.exec(rest.slice(end.index + end[0].length))
      read([...disposition.matchAll(/;\s*name\*?\s*=\s*(?:"([^"]*)"|([^;]*))/gi)].map(([, quoted, bare]) => ({ name: quoted ?? bare.trim(), value: value ? value[1] : '' })))
    }
  } else if (/[/+]json$/.test(mediaType)) {
    let parsed
    try { parsed = JSON.parse(text) } catch { return { names, overrides } }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [k, v] of topLevelJsonFields(text, isOverrideField)) { names.push(k); if (isOverrideField(k)) overrides.push(typeof v === 'string' ? v : JSON.stringify(v)) }
    }
  }
  return { names, overrides }
}

/**
 * The top-level keys of a JSON object that JSON.parse has already accepted,
 * each as `[key, value]`, every copy of a repeated key included: JSON.parse
 * keeps only the last, and a server that keeps the first would run the
 * other. Only a value `wanted` accepts the key of is parsed; the rest is
 * stepped over and comes back as `[key]`.
 */
function topLevelJsonFields(text, wanted) {
  const out = []
  let i = text.indexOf('{') + 1
  const ws = () => { while (/\s/.test(text[i] ?? '')) i++ }
  const skipString = () => { i++; while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1; i++ }
  const skipValue = () => {
    let depth = 0
    while (i < text.length) {
      const c = text[i]
      if (c === '"') { skipString(); if (!depth) return; continue }
      if (c === '{' || c === '[') depth++
      else if (c === '}' || c === ']') { if (!depth) return; if (!--depth) { i++; return } }
      else if (c === ',' && !depth) return
      i++
    }
  }
  for (ws(); text[i] === '"'; ws()) {
    let start = i
    skipString()
    const key = JSON.parse(text.slice(start, i))
    ws(); i++ /* : */; ws()
    start = i
    skipValue()
    out.push(wanted(key) ? [key, JSON.parse(text.slice(start, i))] : [key])
    ws()
    if (text[i] === ',') i++
  }
  return out
}

/**
 * The request as the gateway reads it. Pure: the same request always gives
 * the same view, and nothing here refuses; the checks decide what to do with
 * what it found.
 *
 * - `method`: the request-line method, uppercased.
 * - `query`: the query exactly as it will be sent, without its `?`.
 * - `params`: `queryParams(query)`.
 * - `semicolon`: the query separates a pair with `;`, which readers split
 *   differently.
 * - `unsendable`: the query holds a character a URL cannot carry as written,
 *   so the URL parser would send something other than what was read.
 * - `strayName`: a field name in the query, a form or multipart body, or at
 *   the top level of a JSON body is one its readers do not agree on
 *   (`isStrayName`), whatever rules a grant carries.
 * - `headers`, `body`: as given; the body is read by the payload rules.
 * - `contentType`, `mediaType`: the Content-Type, and its lowercased type
 *   without parameters.
 * - `overrides.headers`: methods asked for in override headers.
 * - `overrides.fields`: values of override fields, wherever a framework
 *   reads one.
 */
export function requestView({ method = 'GET', query = '', headers = [], body = null, contentType } = {}) {
  const q = String(query ?? '').replace(/^\?/, '')
  const params = queryParams(q)
  const type = contentType !== undefined ? contentType : headers.find(([n]) => String(n).toLowerCase() === 'content-type')?.[1]
  const mediaType = String(type ?? '').split(';')[0].trim().toLowerCase()
  const read = fields(q, mediaType, body)
  return Object.freeze({
    method: String(method || 'GET').toUpperCase(),
    query: q,
    params,
    semicolon: q.includes(';'),
    unsendable: /[#\t\n\r]|[\x00-\x20]$/.test(q),
    strayName: read.names.some(isStrayName),
    headers,
    body,
    contentType: type ?? '',
    mediaType,
    overrides: Object.freeze({ headers: headerOverrides(headers), fields: read.overrides }),
  })
}

/** A view, as opposed to the loose fields a caller may still pass. */
export const isView = (v) => v != null && Array.isArray(v.params) && typeof v.overrides === 'object'
