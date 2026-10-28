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
// Every flag grantInput reads. A flag outside the command's list was ignored,
// so a typo like --spend_tokens created or narrowed a session without the
// limit the human typed. Refused instead, before anything is sent.
export const GRANT_FLAGS = ['hosts', 'methods', 'paths', 'deny-paths', 'approval', 'budget', 'uses', 'concurrency', 'redirects', 'spend-tokens', 'grant-ttl', 'rate', 'quota', 'spend-usd', 'route', 'payload-file', 'graphql']
export function knownFlags(args, allowed, command) {
  for (const flag of Object.keys(args)) if (flag !== '_' && !allowed.includes(flag)) usage(`${command} does not take --${flag}; nothing was sent`)
}

// Each flag `approve` reads, and the override field it becomes: the shared
// parser's flags, plus the spellings parseOverrides and the generated hint use.
export const APPROVAL_FLAGS = {
  hosts: 'hosts', methods: 'methods', paths: 'paths', 'deny-paths': 'deny_paths', approval: 'approval', infinite: 'infinite',
  budget: 'budget', uses: 'uses', ttl_minutes: 'ttl_minutes', 'ttl-minutes': 'ttl_minutes',
  concurrency: 'max_concurrent', max_concurrent: 'max_concurrent', redirects: 'redirects',
  'spend-tokens': 'spend_tokens', spend_tokens: 'spend_tokens', 'spend-usd': 'spend_usd', spend_usd: 'spend_usd',
  'grant-ttl': 'grant_ttl_minutes', grant_ttl: 'grant_ttl_minutes', grant_ttl_minutes: 'grant_ttl_minutes',
  rate: 'rate', quota: 'quota', route: 'routes', routes: 'routes', payload: 'payload', 'payload-file': 'payload', graphql: 'payload',
}

/**
 * The owner's narrowing of an approval, from `parse` (parseOverrides) and the
 * shared parser. Every flag that was typed must arrive in the overrides: a
 * flag parsed into nothing was approved as the agent asked, with the human
 * believing they had narrowed it. parseOverrides throws a TypeError naming
 * `.field` on a value it cannot read (C23); that is the human's typo, so it
 * is a usage error and nothing is sent.
 */
export function approvalOverrides(args, parse) {
  knownFlags(args, Object.keys(APPROVAL_FLAGS), 'approve')
  const given = Object.keys(args).filter((flag) => flag !== '_')
  for (const flag of given) if (args[flag] === true && flag !== 'infinite') usage(`--${flag} needs a value; nothing was sent`)
  // Two spellings of one field: only one of them would be sent.
  for (const field of new Set(given.map((flag) => APPROVAL_FLAGS[flag]))) {
    const flags = given.filter((flag) => APPROVAL_FLAGS[flag] === field)
    const merged = flags.length === 2 && flags.includes('payload-file') && flags.includes('graphql')
    if (flags.length > 1 && !merged) usage(`give only one of ${flags.map((f) => `--${f}`).join(', ')}; nothing was sent`)
  }
  let overrides
  try {
    // Where both read a field, parseOverrides' value is the one sent (C21):
    // it is the parser the page and the UI server read the same narrowing
    // with, so all three sign the same operation. grantInput still reads every
    // flag, so a value it would refuse stays a usage error, and it is the only
    // reader of --payload-file and --graphql. It used to win, and sent
    // `--rate 60/min` as an object where the page sent the text.
    const typed = parse(args)
    overrides = { ...grantInput(args), ...typed }
  } catch (e) {
    if (e instanceof TypeError && typeof e.field === 'string' && e.field) {
      const why = e.message.startsWith(`${e.field}:`) ? e.message.slice(e.field.length + 1).trim() : e.message
      usage(`--${e.field}: ${why || 'not a valid value'}; nothing was sent`)
    }
    throw e
  }
  for (const flag of given) if (!Object.hasOwn(overrides, APPROVAL_FLAGS[flag])) usage(`--${flag} was given but narrows nothing; nothing was sent`)
  // NaN and Infinity travel as JSON null, which the daemon reads as absent.
  for (const [field, v] of Object.entries(overrides)) if (typeof v === 'number' && !Number.isFinite(v)) usage(`--${field} must be a number; nothing was sent`)
  return overrides
}

export function sessionInput(args) {
  // No --remote (R3): the CLI talks to the local socket, and an infinite session can never be remote.
  knownFlags(args, [...GRANT_FLAGS, 'label', 'ttl', 'infinite', 'cred', 'grants-file', 'template'], 'session')
  const shared = grantInput(args)
  if (args.infinite !== undefined && args.infinite !== true) usage('--infinite takes no value')
  if (args.infinite && args.ttl !== undefined) usage('--ttl and --infinite cannot be combined')
  const body = {
    ...(args.label !== undefined ? { label: textFlag(args.label, '--label') } : {}),
    ...(args.ttl !== undefined ? { ttl_hours: numberFlag(args.ttl, '--ttl', { min: Number.MIN_VALUE, integer: false }) } : {}),
    ...(args.infinite === true ? { infinite: true } : {}),
  }
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
