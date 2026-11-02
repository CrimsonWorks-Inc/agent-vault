// The Sessions page's rules, held to what app.html did with the same inputs.
import { describe, expect, it } from 'vitest'
import {
  advancedFields, approvalMode, autoWrites, buildSessionBody, defaultMappings, describedRows, detailMarkdown, envCommand,
  exampleCall, freshForm, handoffFrom, mappingProblems, narrowSummary, NARROWINGS, sessionsRoute, suggestedName,
  templateLimits, templateOverrides, templateSessionBody, barSteps, spendLines,
} from './sessionLogic.js'

const kinds = new Map([['gh-work', 'github'], ['openai', 'openai']])

describe('buildSessionBody (app.html readSessionForm)', () => {
  it('builds one grant per picked credential with the shared limits', () => {
    const form = { ...freshForm([{ slug: 'gh-work' }]), picked: ['gh-work', 'openai'], label: '  triage ', methods: 'get, head ,post', paths: '/a/**, /b' }
    const { body, picked } = buildSessionBody(form, kinds)
    expect(picked).toEqual(['gh-work', 'openai'])
    expect(body).toEqual({
      label: 'triage',
      grants: [
        { cred: 'gh-work', methods: ['GET', 'HEAD', 'POST'], paths: ['/a/**', '/b'], budget: 500, approval: 'on-write' },
        { cred: 'openai', methods: ['GET', 'HEAD', 'POST'], paths: ['/a/**', '/b'], budget: 500, approval: 'on-write' },
      ],
      ttl_hours: 8,
    })
  })

  it('No expiry is no lifetime at all, never a long one', () => {
    const { body } = buildSessionBody({ ...freshForm([{ slug: 'gh-work' }]), lifetime: 'never' }, kinds)
    expect(body.infinite).toBe(true)
    expect('ttl_hours' in body).toBe(false)
  })

  it('an empty label is "ui session", as app.html sent it', () => {
    expect(buildSessionBody(freshForm([{ slug: 'gh-work' }]), kinds).body.label).toBe('ui session')
  })

  it('refuses nothing picked and more than 16, in app.html words', () => {
    expect(buildSessionBody({ ...freshForm([]), picked: [] }, kinds)).toEqual({ error: 'Pick at least one credential' })
    const many = Array.from({ length: 17 }, (_, i) => `c${i}`)
    expect(buildSessionBody({ ...freshForm([]), picked: many }, kinds)).toEqual({ error: 'A session holds at most 16 credentials' })
  })

  it('spend limits go only with a model credential; hidden is absent', () => {
    const base = { ...freshForm([]), spendTokens: '1000', spendUsd: '2.5' }
    expect(buildSessionBody({ ...base, picked: ['gh-work'] }, kinds).body.grants[0].spend_tokens).toBeUndefined()
    const g = buildSessionBody({ ...base, picked: ['openai'] }, kinds).body.grants[0]
    expect(g.spend_tokens).toBe(1000)
    expect(g.spend_usd).toBe(2.5)
  })
})

describe('advancedFields (app.html)', () => {
  it('passes rate and quota as typed, numbers as numbers, empty as absent', () => {
    expect(advancedFields({ rate: ' 60/min ', quota: '1000/day', concurrency: '3', redirects: '', grantTtl: '30' }))
      .toEqual({ fields: { rate: '60/min', quota: '1000/day', max_concurrent: 3, grant_ttl_minutes: 30 } })
  })
  it('says what is wrong, in the same words', () => {
    expect(advancedFields({ concurrency: 'abc' })).toEqual({ error: 'max_concurrent must be a number' })
    expect(advancedFields({ payload: '{nope' }).error).toMatch(/^The payload rules are not JSON: /)
    expect(advancedFields({ payload: '[1]' })).toEqual({ error: 'The payload rules must be a JSON object.' })
    expect(advancedFields({ routes: [{ methods: ['GET'], paths: '' }] })).toEqual({ error: 'Each route needs at least one method and one path.' })
    expect(advancedFields({ routes: Array.from({ length: 17 }, () => ({ methods: ['GET'], paths: '/a' })) })).toEqual({ error: 'At most 16 routes.' })
  })
  it('GraphQL queries only merges into the payload rules', () => {
    expect(advancedFields({ payload: '{"json":{}}', graphqlQueriesOnly: true }).fields.payload)
      .toEqual({ json: {}, graphql: { operations: ['query'] } })
  })
  it('routes become methods and trimmed paths; blank rows are dropped', () => {
    expect(advancedFields({ routes: [{ methods: ['GET', 'POST'], paths: '/a, /b ' }, { methods: [], paths: '' }] }).fields.routes)
      .toEqual([{ methods: ['GET', 'POST'], paths: ['/a', '/b'] }])
  })
})

describe('warnings and badges', () => {
  it('auto or first-use with a writing method is elevated (C26)', () => {
    expect(autoWrites('auto', ['GET', 'POST'])).toBe(true)
    expect(autoWrites('first-use', ['DELETE'])).toBe(true)
    expect(autoWrites('auto', ['GET', 'HEAD'])).toBe(false)
    expect(autoWrites('on-write', ['POST'])).toBe(false)
  })
  it('the approval badge shows the strictest mode, or the laxest when elevated', () => {
    expect(approvalMode({ creds: [{ approval: 'auto' }, { approval: 'each' }] })).toEqual({ mode: 'each', elevated: false })
    expect(approvalMode({ creds: [{ approval: 'auto' }, { approval: 'each' }], elevated: ['approval_auto_writes'] })).toEqual({ mode: 'auto', elevated: true })
    expect(approvalMode({ creds: [{ approval: null }] })).toEqual({ mode: 'auto', elevated: false })
    expect(approvalMode({ creds: [] })).toBeNull()
  })
  it('the three narrowings send exactly app.html\'s bodies', () => {
    expect(NARROWINGS['drop-writes'].body('s_1')).toEqual({ sid: 's_1', narrow: { methods: ['GET', 'HEAD'] } })
    expect(NARROWINGS['approve-each'].body('s_1')).toEqual({ sid: 's_1', narrow: { approval: 'each' } })
    expect(NARROWINGS['end-1h'].body('s_1')).toEqual({ sid: 's_1', narrow: {}, session_ttl_minutes: 60 })
  })
})

describe('templates (F17)', () => {
  const spec = { grants: [{ cred: 'a', methods: ['GET', 'POST'], approval: 'first-use', budget: 200, grant_ttl_minutes: 60 }, { cred: 'b', approval: 'each', budget: 100, grant_ttl_minutes: 30 }], ttl_hours: 8 }
  it('limits are the laxest grant\'s', () => {
    expect(templateLimits(spec)).toEqual({ creds: ['a', 'b'], methods: ['GET', 'POST', 'HEAD'], approvalFloor: 1, budget: 200, grantTtl: 60, infinite: false, ttlHours: 8 })
    expect(templateLimits({ infinite: true }).ttlHours).toBeNull()
  })
  it('overrides only narrow, and say so when they would widen', () => {
    const L = templateLimits(spec)
    expect(templateOverrides(L, { methods: L.methods })).toEqual({ overrides: {} })
    expect(templateOverrides(L, { methods: ['GET'], approval: 'each', budget: '50', lifetime: '1', grantTtl: '10', label: 'x' }))
      .toEqual({ overrides: { label: 'x', methods: ['GET'], approval: 'each', budget: 50, ttl_hours: 1, grant_ttl_minutes: 10 } })
    expect(templateOverrides(L, { methods: [] }).error).toBe('Pick at least one method the template allows.')
    expect(templateOverrides(L, { methods: L.methods, approval: 'auto' }).error).toBe('That approval mode is laxer than the template; a template can only be narrowed.')
    expect(templateOverrides(L, { methods: L.methods, budget: '500' }).error).toBe('The budget can only go down from 200.')
    expect(templateOverrides(L, { methods: L.methods, lifetime: 'never' }).error).toBe('This template has a lifetime; it cannot be made endless.')
    expect(templateOverrides(L, { methods: L.methods, lifetime: '24' }).error).toBe('The lifetime can only go down from 8 hours.')
    expect(templateOverrides(L, { methods: L.methods, grantTtl: '90' }).error).toBe('A grant lifetime can only go down.')
  })
  it('the body pins the hash of the template on screen', () => {
    const t = { name: 'gh-read', hash: 'h1', limits: templateLimits(spec) }
    expect(templateSessionBody(t, { methods: ['GET'] })).toEqual({ body: { template: 'gh-read', template_hash: 'h1', methods: ['GET'] }, picked: ['a', 'b'] })
  })
})

describe('the hand-off', () => {
  const g = { cred: 'gh-work', base_url: 'http://127.0.0.1:7411/gh-work', placeholder: 'AVPH_x' }
  it('the curl line puts the placeholder where the site says', () => {
    expect(exampleCall({ ...g, token: 'avs_t', sites: ['header:Authorization:Bearer'], probe: '/user' }))
      .toBe('curl "http://127.0.0.1:7411/gh-work/user" \\\n  -H "AV-Session: avs_t" \\\n  -H "Authorization: Bearer AVPH_x"')
    expect(exampleCall({ ...g, token: 'avs_t', sites: ['query:token'] }))
      .toBe('curl "http://127.0.0.1:7411/gh-work/" \\\n  -H "AV-Session: avs_t"\n\n# then put the placeholder at: query:token')
  })
  it('suggests the name a tool reads, and maps several keys to names', () => {
    expect(suggestedName({ cred: 'gh-work' })).toBe('GH_WORK_TOKEN')
    expect(suggestedName({ cred: 'x', env: { key: 'GITHUB_TOKEN' } })).toBe('GITHUB_TOKEN')
    const rows = [...defaultMappings([{ cred: 'gh-work' }, { cred: 'openai' }]), { name: 'GH_URL', cred: 'gh-work', what: 'base_url' }]
    expect(envCommand({ cli: 'agent-vault', sessionId: 's_1', mappings: rows }))
      .toBe('agent-vault env --session s_1 --out .env --map GH_WORK_TOKEN=gh-work --map OPENAI_TOKEN=openai --map GH_URL=gh-work:base_url')
  })
  it('a name env would refuse is said before anything is copied', () => {
    expect(mappingProblems([{ name: 'OK_1' }, { name: '1BAD' }, { name: 'DUP' }, { name: 'DUP' }]))
      .toEqual([null, 'Letters, digits and _ only, not starting with a digit', 'DUP is mapped twice', 'DUP is mapped twice'])
  })
  it('keeps only what the card shows, and takes the first credential\'s site', () => {
    const h = handoffFrom(
      { session_id: 's_1', token: 'avs_t', expires_at: null, infinite: true, extra: 'x', grants: [{ ...g, usage: ['header Authorization'], secret: 'no' }] },
      { cli: 'av', creds: [{ slug: 'gh-work', fields: [{ sites: ['header:Authorization:Bearer'] }], probe_path: '/user' }] },
    )
    expect(h).toEqual({
      session_id: 's_1', token: 'avs_t', expires_at: null, infinite: true, cli: 'av', sites: ['header:Authorization:Bearer'], probe: '/user',
      grants: [{ cred: 'gh-work', base_url: g.base_url, placeholder: 'AVPH_x', usage: ['header Authorization'], lint: [], env: undefined }],
    })
  })
})

describe('detail and narrow', () => {
  it('a narrow summary lists only what changed', () => {
    const r = narrowSummary({ session_id: 's_1', infinite: true, grants: [
      { cred: 'a', before: { methods: ['GET', 'POST'], approval: 'auto' }, after: { methods: ['GET', 'HEAD'], approval: 'auto' }, expires_at: null },
      { cred: 'b', before: { approval: 'each' }, after: { approval: 'each' } },
    ] })
    expect(r.ends).toBe('never expires')
    expect(r.grants[0].changes).toEqual([{ key: 'methods', before: 'GET, POST', after: 'GET, HEAD' }])
    expect(r.grants[1].changes).toEqual([])
  })
  it('the described table and the payload rules apart', () => {
    const { rows, payload } = describedRows({ hosts: ['h'], budget: { invalid: true }, rate: { count: 60, per: 'min' }, payload: [{ a: 1 }] })
    expect(rows.find(([k]) => k === 'budget')[1]).toBe('invalid: every request is refused')
    expect(rows.find(([k]) => k === 'rate')[1]).toBe('60/min')
    expect(rows.find(([k]) => k === 'redirects')[1]).toBe('0')
    expect(payload).toBe('[\n  {\n    "a": 1\n  }\n]')
  })
  it('spend lines and bar steps', () => {
    const [tok] = spendLines({ tokens_used: 100, reserved_tokens: 50, limit_tokens: 1000 })
    expect(tok.text).toBe('tokens: 100 used, 50 reserved, of 1000')
    expect(barSteps(100, 50, 1000)).toEqual({ used: 2, reserved: 3 })
    expect(barSteps(5000, 0, 1000)).toEqual({ used: 20, reserved: 20 })
    expect(barSteps(1, 1, 0)).toBeNull()
  })
  it('the Markdown summary is app.html\'s', () => {
    const md = detailMarkdown({ session: { id: 's_1', label: 'a\nb', state: 'active', infinite: true }, grants: [{ cred: 'gh', state: 'active', effective: { methods: ['GET'], budget: { limit: 5 } }, budget: { used: 1 } }], activity: { complete: false, requests: { allowed: 1 }, paths: [{ count: 1, method: 'GET', path: '/u' }] } })
    expect(md).toBe([
      '## Session `s_1` (a b)', '', '- state: active', '- expires: never', '- elevated: no',
      '- **history incomplete:** the audit log does not cover the whole session',
      '', '### `gh` (active)', '', '- methods: `GET`', '- budget: 1 used of 5',
      '', '### Activity', '', '- 1 allowed, 0 refused, 0 held', '- 1 × `GET /u`',
    ].join('\n'))
  })
  it('routes inside the page', () => {
    expect(sessionsRoute('')).toEqual({ tab: 'list' })
    expect(sessionsRoute('new')).toEqual({ tab: 'new' })
    expect(sessionsRoute('new:gh-read')).toEqual({ tab: 'new', template: 'gh-read' })
    expect(sessionsRoute('review')).toEqual({ tab: 'review' })
    expect(sessionsRoute('detail:s_9')).toEqual({ tab: 'list', detail: 's_9' })
  })
})
