// Guided flows for the commands with too many options to remember.
//
// The questions ask about intent, not about the data model. Nobody thinks "I
// want methods GET and HEAD with approval mode on-write"; they think "the agent
// should be able to read my repo but ask before changing anything". The mapping
// from one to the other lives in buildPolicy, which is pure and tested, so the
// interactive layer stays thin.

import * as p from './prompt.js'
import { listProfiles, defaultSites, defaultField, PROFILES } from '../connectors/profiles.js'

const C = p.colors

// ------------------------------------------------------------- pure decisions

export const ACCESS_LEVELS = {
  read: {
    label: 'Read only',
    hint: 'GET and HEAD, nothing can be changed',
    methods: ['GET', 'HEAD'],
    approval: 'auto',
  },
  write: {
    label: 'Read, and write with your approval',
    hint: 'you are asked before anything is created or changed',
    methods: ['GET', 'HEAD', 'POST', 'PATCH', 'PUT'],
    approval: 'on-write',
  },
  full: {
    label: 'Read and write freely, including delete',
    hint: 'no approval prompts; only for things you can afford to lose',
    methods: ['GET', 'HEAD', 'POST', 'PATCH', 'PUT', 'DELETE'],
    approval: 'auto',
  },
}

/** Turn wizard answers into the policy the daemon stores. */
export function buildPolicy({ kind, access, paths, budget, ttlHours }) {
  const level = ACCESS_LEVELS[access]
  if (!level) throw new Error(`unknown access level: ${access}`)
  const profile = PROFILES[kind]
  return {
    methods: [...level.methods],
    paths: paths && paths.length ? [...paths] : ['/**'],
    budget: Number(budget ?? profile?.defaultBudget?.limit ?? 500),
    approval: level.approval,
    ttl_hours: Number(ttlHours ?? 8),
  }
}

/** A slug that is valid, descriptive, and not already taken. */
export function suggestSlug(kind, existing = []) {
  const base = String(kind).replace(/[^a-z0-9-]/g, '-').slice(0, 20) || 'cred'
  if (!existing.includes(base)) return base
  for (let i = 2; i < 100; i++) {
    const candidate = `${base}-${i}`
    if (!existing.includes(candidate)) return candidate
  }
  return `${base}-${Date.now().toString(36).slice(-4)}`
}

/** Scope options worth offering for a given connector kind. */
export function scopePresets(kind) {
  switch (kind) {
    case 'github':
      return [
        { value: 'repo', label: 'One repository', hint: 'the narrowest useful scope' },
        { value: 'owner', label: 'Everything under one owner', hint: 'all repos for a user or org' },
        { value: 'all', label: 'Everything this token can reach', hint: 'still bounded by the profile deny list' },
        { value: 'custom', label: 'Custom path patterns' },
      ]
    case 'slack':
      return [
        { value: 'all', label: 'Every API this token can reach' },
        { value: 'custom', label: 'Custom path patterns' },
      ]
    case 'anthropic': case 'openai': case 'google-genai':
      return [
        { value: 'all', label: 'The model API', hint: 'admin and key-management paths are denied by the profile' },
        { value: 'custom', label: 'Custom path patterns' },
      ]
    default:
      return [
        { value: 'all', label: 'Every path on this host' },
        { value: 'custom', label: 'Custom path patterns' },
      ]
  }
}

/** Expand a chosen scope into path globs. */
export function pathsForScope(kind, scope, detail) {
  if (scope === 'all') return ['/**']
  if (scope === 'custom') return String(detail || '/**').split(',').map((s) => s.trim()).filter(Boolean)
  if (kind === 'github') {
    if (scope === 'repo') {
      const [owner, repo] = String(detail || '').split('/')
      return ['/user', `/repos/${owner}/${repo}`, `/repos/${owner}/${repo}/**`]
    }
    if (scope === 'owner') return ['/user', `/repos/${detail}/**`, `/orgs/${detail}/**`]
  }
  return ['/**']
}

export const BUDGET_CHOICES = (kind) => {
  const llm = ['anthropic', 'openai', 'google-genai'].includes(kind)
  return llm
    ? [
      { value: 20000, label: '20,000 requests', hint: 'a long working session' },
      { value: 5000, label: '5,000 requests' },
      { value: 500, label: '500 requests' },
      { value: 'custom', label: 'Something else' },
    ]
    : [
      { value: 500, label: '500 requests', hint: 'a normal task' },
      { value: 100, label: '100 requests', hint: 'a small, focused task' },
      { value: 5000, label: '5,000 requests', hint: 'a long run' },
      { value: 'custom', label: 'Something else' },
    ]
}

// --------------------------------------------------------------- credentials

/**
 * Walk someone through storing a credential.
 * @param {(method:string, path:string, body?:any) => Promise<any>} control
 */
export async function credentialWizard(control, { slug: presetSlug } = {}) {
  const existing = (await control('GET', '/v1/credentials')).map((c) => c.slug)

  p.step(1, 4, 'What are you connecting to?')
  const profiles = listProfiles().filter((x) => !x.l4)
  const kind = await p.select('Service', [
    ...profiles.filter((x) => x.kind !== 'http').map((x) => ({
      value: x.kind,
      label: x.kind,
      hint: x.hosts[0] || '',
    })),
    { value: 'http', label: 'Something else', hint: 'any HTTP API, you name the host' },
  ])

  let host
  let sites
  if (kind === 'http') {
    host = await p.text('Host', {
      placeholder: 'api.example.com',
      validate: (v) => (/^[a-z0-9.-]+(:\d+)?$/i.test(v) ? null : 'that does not look like a hostname'),
    })
    sites = [await p.select('Where does the token go in a request?', [
      { value: 'header:authorization:Bearer', label: 'Authorization: Bearer <token>', hint: 'the common one' },
      { value: 'header:x-api-key', label: 'X-API-Key: <token>' },
      { value: 'header:authorization:token', label: 'Authorization: token <token>' },
      { value: 'basic:pass', label: 'HTTP basic auth password' },
      { value: 'query:key', label: 'A query parameter named key', hint: 'ends up in server logs' },
    ])]
  }

  p.step(2, 4, 'Name it')
  const slug = presetSlug || await p.text('Name', {
    defaultValue: suggestSlug(kind, existing),
    validate: (v) => {
      if (!/^[a-z0-9-]{1,24}$/.test(v)) return 'lowercase letters, numbers and dashes, up to 24 characters'
      if (existing.includes(v)) return `${v} already exists`
      return null
    },
  })

  p.step(3, 4, 'The value')
  p.note([
    'It is read without echoing, never appears in your shell history,',
    'and is encrypted before it touches disk. You will not see it again.',
  ])
  const value = await p.secret(`Paste the ${kind === 'http' ? 'token' : kind + ' token'}:`)
  if (!value) throw new Error('no value entered')

  p.step(4, 4, 'Confirm')
  const field = defaultField(kind)
  const siteList = sites || defaultSites(kind, field)
  p.summary('About to store', [
    ['name', slug],
    ['service', kind],
    ['host', host || PROFILES[kind]?.hosts[0] || '—'],
    ['injected at', siteList.join(', ')],
    ['value', `${value.length} characters, ending ${C.dim(`…${value.slice(-4)}`)}`],
  ])
  if (!await p.confirm('Store it?', { defaultYes: true })) throw new p.Cancelled()

  const created = await control('POST', '/v1/credentials', {
    slug, kind, host, value, sites: sites || undefined,
  })
  console.log(`\n${C.green('stored')} ${slug} ${C.dim(`fingerprint ${created.fields[0].fp8}`)}`)
  return created
}

// ------------------------------------------------------------------ sessions

/**
 * Walk someone through handing an agent a scoped session.
 */
export async function sessionWizard(control, { cred: presetCred } = {}) {
  const creds = await control('GET', '/v1/credentials')
  if (!creds.length) {
    throw new Error('no credentials yet; run "agent-vault cred add" first')
  }

  p.step(1, 5, 'Which credential?')
  const slug = presetCred || await p.select('Credential', creds.map((c) => ({
    value: c.slug, label: c.slug, hint: `${c.kind} · ${c.connector.host || ''}`,
  })))
  const cred = creds.find((c) => c.slug === slug)
  if (!cred) throw new Error(`no credential named ${slug}`)

  p.step(2, 5, 'What should the agent be able to do?')
  const access = await p.select('Access', Object.entries(ACCESS_LEVELS).map(([value, l]) => ({
    value, label: l.label, hint: l.hint,
  })))
  if (access === 'full') {
    p.note(['Nothing will pause for you. The budget and the expiry are the only limits.'])
    if (!await p.confirm('Are you sure?')) throw new p.Cancelled()
  }

  p.step(3, 5, 'How much of it?')
  const scope = await p.select('Scope', scopePresets(cred.kind))
  let detail
  if (scope === 'repo') {
    detail = await p.text('Repository', {
      placeholder: 'owner/name',
      validate: (v) => (/^[\w.-]+\/[\w.-]+$/.test(v) ? null : 'use the owner/name form'),
    })
  } else if (scope === 'owner') {
    detail = await p.text('Owner', { placeholder: 'an org or user name' })
  } else if (scope === 'custom') {
    p.note(['Comma separated. * matches one path segment, ** matches many.'])
    detail = await p.text('Paths', { defaultValue: '/**' })
  }
  const paths = pathsForScope(cred.kind, scope, detail)

  p.step(4, 5, 'Limits')
  let budget = await p.select('Budget', BUDGET_CHOICES(cred.kind))
  if (budget === 'custom') {
    budget = Number(await p.text('How many requests?', {
      defaultValue: '500',
      validate: (v) => (/^\d+$/.test(v) && Number(v) > 0 ? null : 'a whole number greater than zero'),
    }))
  }
  const ttlHours = await p.select('Expires in', [
    { value: 8, label: '8 hours', hint: 'a working day' },
    { value: 1, label: '1 hour', hint: 'a quick task' },
    { value: 24, label: '24 hours' },
  ])

  p.step(5, 5, 'Confirm')
  const policy = buildPolicy({ kind: cred.kind, access, paths, budget, ttlHours })
  p.summary('About to create', [
    ['credential', cred.slug],
    ['can call', policy.methods.join(' ')],
    ['on paths', policy.paths.join('\n' + ' '.repeat(18))],
    ['budget', `${policy.budget} requests`],
    ['writes', policy.approval === 'on-write' ? 'ask me first' : 'no approval'],
    ['expires', `${policy.ttl_hours}h from now`],
  ])
  if (!await p.confirm('Create the session?', { defaultYes: true })) throw new p.Cancelled()

  const session = await control('POST', '/v1/sessions', {
    cred: cred.slug,
    label: `${cred.slug} ${access}`,
    methods: policy.methods,
    paths: policy.paths,
    budget: policy.budget,
    approval: policy.approval,
    ttl_hours: policy.ttl_hours,
  })

  console.log(`\n${C.green('session created')} ${C.dim(session.session_id)}\n`)
  console.log(`  ${C.bold('Give the agent these two things:')}\n`)
  console.log(`    base url     ${C.cyan(session.base_url)}`)
  console.log(`    placeholder  ${C.cyan(session.placeholder)}\n`)
  console.log(`  ${C.dim('It puts the placeholder here, and nowhere else:')}`)
  for (const usage of session.usage) console.log(`    ${usage}`)
  console.log(`\n  ${C.dim('Or hand it the whole environment:')}`)
  console.log(`    ${C.cyan('eval "$(agent-vault env)"')}`)
  for (const problem of session.lint || []) {
    console.log(`  ${problem.level === 'error' ? C.red('lint') : C.yellow('lint')} ${problem.message}`)
  }
  return session
}

// ---------------------------------------------------------------- quickstart

/** The whole path from nothing to an agent that can make a call. */
export async function quickstart(control) {
  console.log(`\n${C.bold('agent-vault quickstart')}`)
  p.note(['Three steps: store a credential, scope a session, hand it to your agent.'])

  const creds = await control('GET', '/v1/credentials')
  let cred = null
  if (creds.length) {
    const names = creds.map((c) => c.slug).join(', ')
    if (await p.confirm(`Use a credential you already have (${names})?`, { defaultYes: true })) {
      if (creds.length === 1) {
        cred = creds[0]
      } else {
        const chosen = await p.select('Which one?', creds.map((x) => ({ value: x.slug, label: x.slug, hint: x.kind })))
        cred = creds.find((c) => c.slug === chosen)
      }
    }
  }
  if (!cred) cred = await credentialWizard(control)

  const session = await sessionWizard(control, { cred: cred.slug })
  console.log(`\n${C.green('ready')}  ${C.dim('watch what the agent does with:')} ${C.cyan('agent-vault audit tail')}\n`)
  return session
}
