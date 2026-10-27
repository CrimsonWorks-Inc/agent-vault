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
 * says, the checks refuse it rather than pick one.
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
 * The names a field may be read as. PHP turns a space, a dot and an unmatched
 * `[` in a name into `_`, so `.method` is Laravel's `_method`, and
 * `_method[]` is still the `_method` field to Rack and PHP. Letter case and
 * `-` against `_` are folded too: a name only ever folds to refuse more.
 */
export function foldedNames(name) {
  const n = String(name).toLowerCase().replace(/[ .-]/g, '_')
  return [n.replace(/\[.*$/s, ''), n.replace(/\[/g, '_')]
}

export const isOverrideField = (name) => foldedNames(name).some((n) => METHOD_OVERRIDE_FIELDS.has(n))

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
 * The override values in a query or a form body, as both kinds of reader
 * read it. Split on `;` as well, `a=1;_method=DELETE` names DELETE; split on
 * `&` alone, `.method=GET;force=1` names `GET;force=1`, which is not GET.
 */
const overrideValues = (raw) => [...queryParams(raw), ...(raw.includes(';') ? queryParams(raw, '&') : [])].filter((p) => isOverrideField(p.name)).map((p) => p.value)

/**
 * Every value a method-override field carries: in the query, in a form or
 * multipart body, and at the top level of a JSON body. Each copy of a
 * repeated field is returned, since frameworks differ on which one wins.
 */
function fieldOverrides(query, mediaType, body) {
  const out = overrideValues(query)
  if (body == null || !body.length) return out
  const text = (Buffer.isBuffer(body) ? body.toString('utf8') : String(body)).replace(/^﻿/, '')
  if (mediaType === 'application/x-www-form-urlencoded') out.push(...overrideValues(text))
  else if (mediaType === 'multipart/form-data') {
    // Each part's name, from its Content-Disposition, and its value up to the
    // next delimiter. A part that names an override and has no readable
    // value counts as naming another method.
    for (const m of text.matchAll(/content-disposition:[^\r\n]*?;\s*name\*?\s*=\s*(?:"([^"]*)"|([^;\r\n]*))[^\r\n]*\r?\n/gi)) {
      if (!isOverrideField(m[1] ?? m[2].trim())) continue
      const rest = text.slice(m.index + m[0].length)
      const value = /^(?:[^\r\n]+\r?\n)*?\r?\n([\s\S]*?)\r?\n--/.exec(rest)
      out.push(value ? value[1] : '')
    }
  } else if (/[/+]json$/.test(mediaType)) {
    let parsed
    try { parsed = JSON.parse(text) } catch { return out }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) for (const v of topLevelJsonValues(text, isOverrideField)) out.push(typeof v === 'string' ? v : JSON.stringify(v))
  }
  return out
}

/**
 * The values of the top-level keys `wanted` accepts, in a JSON object that
 * JSON.parse has already accepted, every copy of a repeated key included:
 * JSON.parse keeps only the last, and a server that keeps the first would
 * run the other. Only a wanted value is parsed; the rest is stepped over.
 */
function topLevelJsonValues(text, wanted) {
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
    if (wanted(key)) out.push(JSON.parse(text.slice(start, i)))
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
  return Object.freeze({
    method: String(method || 'GET').toUpperCase(),
    query: q,
    params,
    semicolon: q.includes(';'),
    unsendable: /[#\t\n\r]|[\x00-\x20]$/.test(q),
    headers,
    body,
    contentType: type ?? '',
    mediaType,
    overrides: Object.freeze({ headers: headerOverrides(headers), fields: fieldOverrides(q, mediaType, body) }),
  })
}

/** A view, as opposed to the loose fields a caller may still pass. */
export const isView = (v) => v != null && Array.isArray(v.params) && typeof v.overrides === 'object'
