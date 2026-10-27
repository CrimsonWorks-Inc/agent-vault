import { deny } from './errors.js'
import { requestView, isView, foldedNames, queryParams } from './request-view.js'

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v)
const own = (v, k) => Object.hasOwn(v, k)
// What each refusal says. None of them repeats a value from the request.
const DETAIL = {
  payload_invalid: 'this grant carries a payload rule that is not valid, so nothing can be checked against it',
  payload_size: 'the request body is larger than this grant allows',
  payload_content_type: 'this grant constrains the body, and the content-type is not one those constraints can read',
  payload_duplicate_key: 'a name appears twice, so two readers could disagree about which value counts',
  payload_depth: 'the JSON body nests more than 64 levels deep',
  payload_unparseable: 'the body could not be read as strict JSON, form data or UTF-8 text',
  graphql_persisted: 'a persisted GraphQL query cannot be checked; send the query text',
  graphql_unreadable: 'this grant checks GraphQL operations, and no query could be read from this request',
  graphql_unparseable: 'the GraphQL document could not be read within the bounds this check allows',
  'payload:graphql:operation': 'the GraphQL document contains an operation type this grant does not allow',
  'payload:graphql:deny_field': 'the GraphQL document names a field this grant denies',
}
const fail = rule => { throw deny('AV_POLICY_DENIED', DETAIL[rule] ?? 'a query parameter is not one this grant names', { rule }) }
const finite = v => typeof v === 'number' && Number.isFinite(v)
const uint = v => Number.isInteger(v) && v >= 0

/** Pure validation of one layer RuleSet. */
export function validatePayload(set) {
  const problems = []
  const bad = () => problems.push({ field: 'payload', message: 'invalid payload constraint' })
  if (!object(set)) { bad(); return problems }
  for (const k of Object.keys(set)) if (!['json','form','query','query_strict','graphql','max_body_bytes'].includes(k)) bad()
  if (own(set, 'max_body_bytes') && !uint(set.max_body_bytes)) bad()
  if (own(set, 'query_strict') && typeof set.query_strict !== 'boolean') bad()
  for (const kind of ['json','form','query']) {
    if (!own(set, kind)) continue
    if (!object(set[kind]) || Object.keys(set[kind]).length > 32) { bad(); continue }
    for (const [key,c] of Object.entries(set[kind])) {
      if (kind === 'json' && (!key.startsWith('/') || key.length > 256 || /~(?![01])/u.test(key) || key.split('/').includes('-'))) bad()
      if (!object(c)) { bad(); continue }
      for (const k of Object.keys(c)) if (!['required','absent','one_of','min','max','max_length'].includes(k)) bad()
      for (const k of ['required','absent']) if (own(c,k) && typeof c[k] !== 'boolean') bad()
      if (c.required && c.absent) bad()
      for (const k of ['min','max']) if (own(c,k) && !finite(c[k])) bad()
      if (own(c,'max_length') && !uint(c.max_length)) bad()
      if (own(c,'one_of') && (!Array.isArray(c.one_of) || c.one_of.length > 64 || c.one_of.some(v => !(v === null || typeof v === 'boolean' || finite(v) || typeof v === 'string' && v.length <= 256)))) bad()
    }
  }
  if (own(set,'graphql')) {
    const g = set.graphql
    if (!object(g) || Object.keys(g).some(k => !['operations','deny_fields'].includes(k)) || !Array.isArray(g.operations) || g.operations.some(v => !['query','mutation','subscription'].includes(v)) || own(g,'deny_fields') && (!Array.isArray(g.deny_fields) || g.deny_fields.length > 64 || g.deny_fields.some(v => typeof v !== 'string' || !/^[_A-Za-z][_0-9A-Za-z]*$/.test(v)))) bad()
  }
  return problems
}

/** JSON recursive descent: duplicate keys are checked before any value is lost. */
export function parseStrictJson(text) {
  let i = 0
  const ws = () => { while (/[\x20\t\r\n]/.test(text[i] ?? '\0')) i++ }
  const string = () => {
    const start = i++
    while (i < text.length) {
      const c = text[i++]
      if (c === '"') { try { return JSON.parse(text.slice(start,i)) } catch { fail('payload_unparseable') } }
      if (c === '\\') i++
    }
    fail('payload_unparseable')
  }
  const value = depth => {
    ws()
    const c = text[i]
    if (c === '{' || c === '[') {
      if (depth > 64) fail('payload_depth')
      i++; ws()
      const obj = c === '{', end = obj ? '}' : ']', out = obj ? Object.create(null) : []
      if (text[i] === end) { i++; return out }
      while (true) {
        ws()
        if (obj) {
          if (text[i] !== '"') fail('payload_unparseable')
          const k = string(); ws()
          if (text[i++] !== ':') fail('payload_unparseable')
          if (own(out,k)) fail('payload_duplicate_key')
          out[k] = value(depth+1)
        } else out.push(value(depth+1))
        ws()
        if (text[i] === end) { i++; return out }
        if (text[i++] !== ',') fail('payload_unparseable')
      }
    }
    if (c === '"') return string()
    const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i))
    if (!m) fail('payload_unparseable')
    i += m[0].length
    const out = JSON.parse(m[0]); if (typeof out === 'number' && !finite(out)) fail('payload_unparseable')
    return out
  }
  const out = value(1); ws(); if (i !== text.length) fail('payload_unparseable'); return out
}

/** Restricted GraphQL executable-document parser; checks every definition. */
export function scanGraphQL(document, rules) {
  const invalid = () => fail('graphql_unparseable')
  if (typeof document !== 'string' || Buffer.byteLength(document) > 256*1024) invalid()
  const t = []; let i = 0
  while (i < document.length) {
    const c = document[i]
    if (/[\s,\uFEFF]/u.test(c)) { i++; continue }
    if (c === '#') { while (i < document.length && !/[\r\n]/.test(document[i])) i++; continue }
    if (c === '"') {
      const start = i
      if (document.startsWith('"""',i)) {
        i += 3; let closed = false
        while (i < document.length) {
          if (document.startsWith('\\"""',i)) { i += 4; continue }
          if (document.startsWith('"""',i)) { i += 3; closed = true; break }
          if (document.charCodeAt(i) < 32 && !/[\t\r\n]/.test(document[i])) invalid()
          i++
        }
        if (!closed) invalid()
      } else {
        i++; let closed = false
        while (i < document.length) { const x = document[i++]; if (x === '"') { closed = true; break } if (x === '\\') i++; else if (x.charCodeAt(0) < 32) invalid() }
        if (!closed) invalid()
        try { JSON.parse(document.slice(start,i)) } catch { invalid() }
      }
      t.push({kind:'string',v:''})
    } else {
      const m = /^(?:[_A-Za-z][_0-9A-Za-z]*|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|\.\.\.|[!$():=@\[\]{|}])/.exec(document.slice(i))
      if (!m) invalid()
      i += m[0].length
      const v = m[0], kind = /^[_A-Za-z]/.test(v) ? 'name' : /^-?\d/.test(v) ? 'number' : 'punct'
      if (kind === 'name' && rules.deny_fields?.includes(v)) fail('payload:graphql:deny_field')
      t.push({kind,v})
    }
    if (t.length > 100000) invalid()
  }
  let p = 0, depth = 0, operations = 0
  const at = v => t[p]?.v === v
  const eat = v => { if (!at(v)) invalid(); p++ }
  const name = () => { if (t[p]?.kind !== 'name') invalid(); return t[p++].v }
  const value = (constant = false, d = 0) => {
    if (d > 64) invalid()
    if (at('$') && !constant) { p++; name() }
    else if (at('[')) { p++; while (!at(']')) value(constant,d+1); p++ }
    else if (at('{')) { p++; while (!at('}')) { name(); eat(':'); value(constant,d+1) } p++ }
    else if (['name','number','string'].includes(t[p]?.kind)) p++
    else invalid()
  }
  const args = () => { if (!at('(')) return; p++; let n=0; while (!at(')')) { name(); eat(':'); value(); n++ } if (!n) invalid(); p++ }
  const directives = () => { while (at('@')) { p++; name(); args() } }
  const type = (d=0) => { if (d>64) invalid(); if (at('[')) { p++; type(d+1); eat(']') } else name(); if (at('!')) p++ }
  const selection = () => {
    eat('{'); if (++depth > 64) invalid(); let n = 0
    while (!at('}')) {
      if (at('...')) { p++; if (at('on')) { p++; name(); directives(); selection() } else if (at('@') || at('{')) { directives(); selection() } else { const x = name(); if (x === 'on') invalid(); directives() } }
      else { name(); if (at(':')) { p++; name() } args(); directives(); if (at('{')) selection() }
      n++
    }
    if (!n) invalid(); p++; depth--
  }
  while (p < t.length) {
    if (at('fragment')) { p++; if (name() === 'on') invalid(); eat('on'); name(); directives(); selection(); continue }
    let op = 'query'
    if (!at('{')) {
      op = name(); if (!['query','mutation','subscription'].includes(op)) invalid()
      if (t[p]?.kind === 'name') name()
      if (at('(')) {
        p++; let n=0
        while (!at(')')) { eat('$'); name(); eat(':'); type(); if (at('=')) { p++; value(true) } directives(); n++ }
        if (!n) invalid(); p++
      }
      directives()
    }
    if (!rules.operations.includes(op)) fail('payload:graphql:operation')
    operations++; selection()
  }
  if (!operations) invalid()
}

function params(list) {
  const out = Object.create(null)
  for (const {name,value} of list) { if (own(out,name)) fail('payload_duplicate_key'); out[name]=value }
  return out
}

// A request two reasonable upstreams could read differently. Neither reading
// is checked in place of the other: it is refused, and nothing is sent.
const AMBIGUOUS = {
  semicolon: 'the query separates parameters with ;, which some servers split on and others do not',
  form_semicolon: 'the form body separates fields with ;, which some servers split on and others do not',
  spelling: 'a parameter name differs from one this grant names only by case, percent-encoding or punctuation a server may fold',
}
const ambiguous = why => { throw deny('AV_POLICY_DENIED', AMBIGUOUS[why], { rule: 'request_ambiguous', hint: 'Send each parameter once, separated by &, under exactly the name the grant uses.' }) }

/**
 * A name written other than as the rule writes it, that some server would
 * still read as the rule's name: `FORCE`, `%66orce`, `force[]` or `dry.run`
 * for `dry_run`. The rules match names exactly, so the check would see
 * another parameter where the upstream sees this one.
 */
function respelled(rules, list) {
  for (const key of Object.keys(rules ?? {})) {
    const want = foldedNames(key)[0]
    for (const p of list) if (p.rawName !== key && foldedNames(p.name).includes(want)) ambiguous('spelling')
  }
}

// Where a refusal says it happened. The key comes from the policy a human
// wrote, never from the request, so naming it echoes nothing the agent sent.
const WHERE = { json: 'the JSON field', form: 'the form field', query: 'the query parameter' }
const BROKE = {
  absent: 'is present, and this grant requires it to be absent',
  required: 'is missing, and this grant requires it',
  one_of: 'is not one of the values this grant allows',
  min: 'is below the minimum this grant allows, or is not a number',
  max: 'is above the maximum this grant allows, or is not a number',
  max_length: 'is longer than this grant allows, or is not a string or list',
}
function check(kind,key,c,present,v) {
  const no = constraint => { throw deny('AV_POLICY_DENIED', `${WHERE[kind]} ${key} ${BROKE[constraint]}`, { rule: `payload:${kind}:${key}:${constraint}` }) }
  if (c.absent && present) no('absent')
  if (c.required && !present) no('required')
  if (!present) return
  if (c.one_of && !c.one_of.some(x => x === v)) no('one_of')
  for (const k of ['min','max']) if (own(c,k) && (!finite(v) || (k === 'min' ? v < c[k] : v > c[k]))) no(k)
  if (own(c,'max_length') && (!(typeof v === 'string' || Array.isArray(v)) || v.length > c.max_length)) no('max_length')
}

/**
 * A query parameter name the agent chose, as it may appear in a rule name.
 * Rule names reach the audit log, so this one is bounded and printable
 * rather than the agent's text verbatim.
 */
const nameForRule = name => encodeURIComponent(name).slice(0, 64)

/**
 * Every payload rule, against the request's one view (request-view.js). A
 * caller may pass the view, with the decided `path`, or the loose fields
 * (`method`, `contentType`, `body`, `query`, `path`), which are read into a
 * view the same way.
 */
export function evaluatePayload(sets, input = {}) {
  if (sets === undefined) return
  if (!Array.isArray(sets)) fail('payload_invalid')
  if (!sets.length) return
  const view = isView(input) ? input : requestView(input)
  const {body} = view, path = input.path ?? ''
  const bytes = body == null ? 0 : Buffer.byteLength(body)
  for (const set of sets) {
    if (validatePayload(set).length) fail('payload_invalid')
    if (bytes > (set.max_body_bytes ?? 1024*1024)) fail('payload_size')
  }
  // Rack splits a query on `;` as well as `&`, and the WHATWG parser does
  // not, so `dry_run=true;force=true` is one parameter to one upstream and
  // two to the other. With any rule to enforce, that is refused.
  if (view.semicolon) ambiguous('semicolon')
  // Decoded only when a rule reads the body. A grant with query rules alone
  // says nothing about the body, and an upload that is not UTF-8 is not a
  // reason to refuse it.
  let bodyText
  const text = () => {
    if (bodyText !== undefined) return bodyText
    try { bodyText = body == null ? '' : Buffer.isBuffer(body) ? new TextDecoder('utf-8',{fatal:true}).decode(body) : String(body) } catch { fail('payload_unparseable') }
    return bodyText
  }
  const ct = view.mediaType, isJson = /^application\/(?:json|[^/]+\+json)$/.test(ct)
  const isForm = ct === 'application/x-www-form-urlencoded'
  let json, parsed = false, q, form, formList
  const getJson = () => { if (!parsed) { json = parseStrictJson(text()); parsed=true } return json }
  const getQuery = () => q ??= params(view.params)
  // A form body is read by the query's own parser, `;` included.
  const getFormList = () => {
    if (formList) return formList
    if (text().includes(';')) ambiguous('form_semicolon')
    return formList = queryParams(text())
  }
  const getForm = () => form ??= params(getFormList())
  for (const set of sets) {
    // A repeated name is refused first, as the duplicate it is.
    if (set.query) { getQuery(); respelled(set.query, view.params) }
    if (set.form && bytes && isForm) { getForm(); respelled(set.form, getFormList()) }
    if (set.query_strict) for (const k of Object.keys(getQuery())) if (!own(set.query ?? {},k)) fail(`payload:query:${nameForRule(k)}:strict`)
    for (const kind of ['json','form','query']) {
      if (!set[kind]) continue
      let data
      if (kind === 'json' && bytes) { if (!isJson) fail('payload_content_type'); data=getJson() }
      if (kind === 'form' && bytes) { if (!isForm) fail('payload_content_type'); data=getForm() }
      if (kind === 'query') data=getQuery()
      for (const [key,c] of Object.entries(set[kind])) {
        let v=data, present=data !== undefined
        const keys = kind === 'json' ? key.slice(1).split('/').map(k => k.replace(/~1/g,'/').replace(/~0/g,'~')) : [key]
        for (const k of keys) {
          // A key that differs from the rule's only by case is the rule's
          // key to a reader that ignores case, and another key here.
          if (object(v) && Object.keys(v).some(x => x !== k && x.toLowerCase() === k.toLowerCase())) ambiguous('spelling')
          if (v === null || typeof v !== 'object' || !own(v,k) || Array.isArray(v) && !/^(0|[1-9]\d*)$/.test(k)) { present=false; v=undefined; break }
          v=v[k]
        }
        check(kind,key,c,present,v)
      }
    }
    if (set.graphql) {
      // Every place a GraphQL server may read a document from is read, and
      // every document found is checked. Servers differ on which one wins
      // when there are several (express-graphql prefers the URL's `query`,
      // even on a POST), so checking only the one this code expects would be
      // two readers disagreeing about what runs.
      const docs=[]
      if (own(getQuery(),'query')) docs.push(q.query)
      if (bytes && ct === 'application/graphql') docs.push(text())
      else if (bytes && isForm && own(getForm(),'query')) docs.push(form.query)
      else if (bytes && isJson) {
        const data=getJson(), entries=Array.isArray(data) ? data : [data]
        if (!entries.length) fail('graphql_unreadable')
        for (const entry of entries) {
          if (object(entry) && typeof entry.query === 'string') docs.push(entry.query)
          else if (object(entry) && entry.extensions?.persistedQuery && !own(entry,'query')) fail('graphql_persisted')
          else if (Array.isArray(data) || object(entry) && own(entry,'query')) fail('graphql_unreadable')
        }
      }
      if (!docs.length && /\/graphql\/?$/.test(String(path ?? '').split('?')[0])) fail('graphql_unreadable')
      for (const doc of docs) scanGraphQL(doc,set.graphql)
    }
  }
}
