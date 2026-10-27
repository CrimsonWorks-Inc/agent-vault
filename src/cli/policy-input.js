// One CLI parser for create, template, narrow and owner approval overrides.
import { readFileSync } from 'node:fs'
import { EXIT } from '../core/errors.js'

export const usage = (message) => { throw Object.assign(new Error(message), { exit: EXIT.USAGE }) }
export const textFlag = (value, name) => {
  if (typeof value !== 'string' || !value.trim()) usage(`${name} needs a value`)
  return value
}
export function numberFlag(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER, integer = true } = {}) {
  textFlag(value, name)
  const n = Number(value)
  if (!Number.isFinite(n) || n < min || n > max || (integer && !Number.isSafeInteger(n))) usage(`${name} must be ${integer ? 'a whole number' : 'a number'} between ${min} and ${max}`)
  return n
}
export function readJson(path, name = 'file') {
  textFlag(path, name)
  try { return JSON.parse(readFileSync(path, 'utf8')) } catch (e) { usage(`cannot read ${name}: ${e.code || 'not JSON'}`) }
}
export const listFlag = (value, name) => textFlag(value, name).split(',').map((x) => x.trim()).filter(Boolean)
export function expiryInput(value) {
  if (value === 'none') return null
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) usage('expiry must be YYYY-MM-DD or none')
  const date = new Date(`${value}T00:00:00.000Z`)
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) usage('expiry must be a valid calendar date')
  return date.toISOString()
}
export function grantInput(args) {
  const spec = {}
  for (const flag of ['hosts', 'methods', 'paths', 'deny-paths']) if (args[flag] !== undefined) {
    const list = listFlag(args[flag], `--${flag}`)
    if (!list.length) usage(`--${flag} needs a nonempty list`)
    spec[flag.replaceAll('-', '_')] = flag === 'methods' ? list.map((v) => v.toUpperCase()) : list
  }
  if (args.approval !== undefined) {
    if (!['each', 'on-write', 'first-use', 'auto'].includes(args.approval)) usage('--approval is one of: each, on-write, first-use, auto')
    spec.approval = args.approval
  }
  for (const [flag, field, min, max] of [
    ['budget', 'budget', 0], ['uses', 'uses', 1], ['concurrency', 'max_concurrent', 1],
    ['redirects', 'redirects', 0, 5], ['spend-tokens', 'spend_tokens', 0], ['grant-ttl', 'grant_ttl_minutes', 1],
  ]) if (args[flag] !== undefined) spec[field] = numberFlag(args[flag], `--${flag}`, { min, ...(max === undefined ? {} : { max }) })
  for (const flag of ['rate', 'quota']) if (args[flag] !== undefined) {
    const m = /^(\d+)\/(\w+)$/.exec(textFlag(args[flag], `--${flag}`))
    const units = flag === 'rate' ? { s: 'second', sec: 'second', second: 'second', m: 'minute', min: 'minute', minute: 'minute', h: 'hour', hour: 'hour' } : { h: 'hour', hour: 'hour', d: 'day', day: 'day' }
    if (!m || !units[m[2]]) usage(`invalid --${flag} interval`)
    spec[flag] = { count: numberFlag(m[1], `--${flag}`, { min: 1 }), [flag === 'rate' ? 'per' : 'window']: units[m[2]] }
  }
  if (args['spend-usd'] !== undefined) {
    const v = textFlag(args['spend-usd'], '--spend-usd')
    if (!/^\d+(?:\.\d{1,6})?$/.test(v)) usage('--spend-usd needs a nonnegative amount with at most 6 decimals')
    spec.spend_usd = numberFlag(v, '--spend-usd', { integer: false, max: Number.MAX_SAFE_INTEGER / 1e6 })
  }
  if (args.route !== undefined) spec.routes = args.route.map((value) => {
    const m = /^([A-Za-z]+(?:,[A-Za-z]+)*):(\/[^\r\n]*)$/.exec(textFlag(value, '--route'))
    if (!m) usage('--route must be METHODS:/path')
    return { methods: m[1].toUpperCase().split(','), paths: [m[2]] }
  })
  if (args['payload-file'] !== undefined) {
    spec.payload = readJson(args['payload-file'], '--payload-file')
    if (!spec.payload || Array.isArray(spec.payload) || typeof spec.payload !== 'object') usage('--payload-file must hold an object')
  }
  if (args.graphql !== undefined) {
    const operations = listFlag(args.graphql, '--graphql')
    if (!operations.length || operations.some((v) => !['query', 'mutation', 'subscription'].includes(v))) usage('--graphql is query, mutation or subscription')
    spec.payload = { ...spec.payload, graphql: { ...spec.payload?.graphql, operations } }
  }
  return spec
}
export function sessionInput(args) {
  const shared = grantInput(args)
  if (args.infinite !== undefined && args.infinite !== true) usage('--infinite takes no value')
  if (args.infinite && args.ttl !== undefined) usage('--ttl and --infinite cannot be combined')
  const body = {
    ...(args.label !== undefined ? { label: textFlag(args.label, '--label') } : {}),
    ...(args.ttl !== undefined ? { ttl_hours: numberFlag(args.ttl, '--ttl', { min: Number.MIN_VALUE, integer: false }) } : {}),
    ...(args.infinite === true ? { infinite: true } : {}),
    ...(args.remote === true ? { remote: true } : {}),
  }
  if (args.remote !== undefined && args.remote !== true) usage('--remote takes no value')
  if ([args.cred !== undefined, args['grants-file'] !== undefined, args.template !== undefined].filter(Boolean).length !== 1) usage('send exactly one of --cred, --grants-file or --template')
  if (args.template !== undefined) return { ...body, ...shared, template: textFlag(args.template, '--template') }
  if (args['grants-file'] !== undefined) {
    if (Object.keys(shared).length) usage('with --grants-file, put each credential\'s limits in the file')
    const grants = readJson(args['grants-file'], '--grants-file')
    if (!Array.isArray(grants)) usage('--grants-file must hold a JSON array of grant specs')
    return { ...body, grants }
  }
  const creds = listFlag(args.cred, '--cred')
  if (!creds.length) usage('--cred needs a credential')
  return creds.length === 1 ? { ...body, cred: creds[0], ...shared } : { ...body, grants: creds.map((cred) => ({ cred, ...shared })) }
}
