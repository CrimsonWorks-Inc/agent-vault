import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as policy from '../../src/core/policy.js'

const GH = { kind: 'github', hosts: ['api.github.com'], deny_paths: ['/repos/*/*/hooks', '/user/keys'] }
const WS = { hosts: ['api.github.com'], methods: ['GET', 'HEAD'], paths: ['/repos/frozencrow/*', '/user'], budget: { unit: 'requests', limit: 500 } }

test('intersection narrows and never widens', () => {
  const eff = policy.intersect([GH, WS, { methods: ['GET'] }])
  assert.deepEqual(eff.methods, ['GET'])
  const widened = policy.intersect([GH, WS, { methods: ['GET', 'POST', 'DELETE'] }])
  assert.deepEqual(widened.methods, ['GET'], 'a child must not add a method the parent lacks')
})

test('numeric limits take the minimum and approval takes the stricter mode', () => {
  const eff = policy.intersect([
    { budget: { unit: 'requests', limit: 500 }, approval: 'on-write', max_concurrent: 8 },
    { budget: { unit: 'requests', limit: 100 }, approval: 'each', max_concurrent: 20 },
  ])
  assert.equal(eff.budget.limit, 100)
  assert.equal(eff.approval, 'each')
  assert.equal(eff.max_concurrent, 8)
})

test('enums narrow: a child cannot upgrade read-only to raw', () => {
  assert.equal(policy.intersect([{ sql_profile: 'read-only' }, { sql_profile: 'raw' }]).sql_profile, 'read-only')
  assert.equal(policy.intersect([{ sql_profile: 'raw' }, { sql_profile: 'read-write' }]).sql_profile, 'read-write')
  assert.equal(policy.intersect([{ mode: 'run' }, { mode: 'agent' }]).mode, 'run')
})

test('an allowed request passes and returns its normalized destination', () => {
  const eff = policy.intersect([GH, WS])
  const r = policy.evaluateHttp(eff, { method: 'GET', host: 'api.github.com', path: '/repos/frozencrow/agent-vault' })
  assert.equal(r.host, 'api.github.com')
  assert.equal(r.path, '/repos/frozencrow/agent-vault')
})

test('a host outside the grant is denied with the reachable hosts named', () => {
  const eff = policy.intersect([GH, WS])
  try {
    policy.evaluateHttp(eff, { method: 'GET', host: 'evil.test', path: '/' })
    assert.fail('should have denied')
  } catch (e) {
    assert.equal(e.code, 'AV_NO_GRANT')
    assert.match(e.hint, /api\.github\.com/)
  }
})

test('a write method under a read-only grant is denied', () => {
  const eff = policy.intersect([GH, WS])
  assert.throws(
    () => policy.evaluateHttp(eff, { method: 'POST', host: 'api.github.com', path: '/repos/frozencrow/x/issues' }),
    (e) => e.code === 'AV_POLICY_DENIED' && e.rule === 'methods',
  )
})

test('a profile deny list outranks a permissive grant', () => {
  const eff = policy.intersect([GH, { hosts: ['api.github.com'], methods: ['GET'], paths: ['/**'] }])
  assert.throws(
    () => policy.evaluateHttp(eff, { method: 'GET', host: 'api.github.com', path: '/user/keys' }),
    (e) => e.code === 'AV_POLICY_DENIED' && e.rule.startsWith('deny_paths'),
  )
})

test('path traversal cannot escape an allowed prefix', () => {
  const eff = policy.intersect([GH, WS])
  for (const evil of [
    '/repos/frozencrow/../../user/keys',
    '/repos/frozencrow/%2e%2e/%2e%2e/user/keys',
    '/repos/frozencrow/..%2f..%2fuser%2fkeys',
  ]) {
    assert.throws(() => policy.evaluateHttp(eff, { method: 'GET', host: 'api.github.com', path: evil }), /AV_/, evil)
  }
})

test('normalization rejects userinfo, trailing dots and illegal characters', () => {
  assert.equal(policy.normalizeHost('API.GitHub.Com.'), 'api.github.com')
  assert.throws(() => policy.normalizeHost('user@evil.test'), /AV_POLICY_DENIED/)
  assert.throws(() => policy.normalizeHost('evil\\test'), /AV_POLICY_DENIED/)
})

test('glob semantics: * spans one segment, ** spans many', () => {
  assert.ok(policy.matchPath('/repos/*/issues', '/repos/frozencrow/issues'))
  assert.ok(!policy.matchPath('/repos/*/issues', '/repos/frozencrow/agent-vault/issues'))
  assert.ok(policy.matchPath('/repos/**', '/repos/frozencrow/agent-vault/issues/1'))
})

test('wildcard hosts over shared suffixes are refused by lint', () => {
  const problems = policy.lint({ hosts: ['*.s3.amazonaws.com'], budget: { limit: 1 } })
  assert.ok(problems.some((p) => p.level === 'error' && p.rule === 'hosts'))
  assert.equal(policy.lint({ hosts: ['*.internal.example.com'], budget: { limit: 1 } }).filter((p) => p.rule === 'hosts').length, 0)
})

test('lint requires a budget on every grant', () => {
  assert.ok(policy.lint({ hosts: ['api.github.com'] }).some((p) => p.level === 'error' && p.rule === 'budget'))
})

test('approval modes behave as documented', () => {
  assert.equal(policy.needsApproval({ approval: 'auto' }, { method: 'POST' }), false)
  assert.equal(policy.needsApproval({ approval: 'on-write' }, { method: 'GET' }), false)
  assert.equal(policy.needsApproval({ approval: 'on-write' }, { method: 'POST' }), true)
  assert.equal(policy.needsApproval({ approval: 'each' }, { method: 'GET' }), true)
  assert.equal(policy.needsApproval({ approval: 'first-use' }, { method: 'GET', firstUse: true }), true)
})

test('all policy fields validate strictly and malformed fields appear in lint', () => {
  const invalid = {
    kind: 1, hosts: 'h', methods: ['TRACE'], paths: [1], deny_paths: null,
    approval: 'each-time', sql_profile: 'write', mode: 'shell', databases: [1], rcpt: false,
    commands: [null], graphql: false, stream_bodies: 'true', placeholder_policy: { max_uses: 0 },
    budget: { unit: 'tokens', limit: 1 }, spend: { tokens: NaN }, rate: { count: '5', per: 'minute' },
    quota: { count: 1, window: 'minute' }, max_concurrent: 1.5, redirects: { max: 6 },
    routes: [{ methods: ['GET'], paths: [] }], payload: { json: { '/x': { required: true, absent: true } } },
  }
  for (const [field, value] of Object.entries(invalid)) {
    assert.ok(policy.validate({ [field]: value }).some((p) => p.field === field), field)
  }
  for (const bad of [NaN, Infinity, -1, 1.5, '', '2.5', null]) {
    assert.ok(policy.validate({ budget: { limit: bad } }).length)
    assert.ok(policy.validate({ spend: { tokens: bad } }).length)
  }
  for (const bad of [null, [], 'x', 5]) assert.ok(policy.validate(bad).length)
  assert.ok(policy.lint({ approval: 'bad', budget: { limit: 1 } }).some((p) => p.level === 'error' && p.rule === 'approval'))
})

test('payload and route validation covers bounds, unknown keys, pointers and constraints', () => {
  const badPayloads = [
    { unknown: true }, { query_strict: 1 }, { max_body_bytes: -1 },
    { json: { x: {} } }, { json: { '/x/~2': {} } }, { json: { '/x/-': {} } },
    { query: { x: { one_of: [Infinity] } } }, { form: { x: { min: '1' } } },
    { query: { x: { max_length: 0.5 } } }, { query: { x: { unknown: 1 } } },
    { json: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`/${i}`, {}])) },
    { graphql: { operations: ['other'] } }, { graphql: { operations: ['query'], deny_fields: ['bad-field'] } },
    { query: { x: { one_of: Array(65).fill(1) } } },
  ]
  for (const payload of badPayloads) assert.ok(policy.validate({ payload }).some((p) => p.field === 'payload'), JSON.stringify(payload))
  assert.deepEqual(policy.validate({ payload: { json: { '/x/~1': { required: true, min: 0, max: 1 } }, graphql: { operations: ['query'], deny_fields: ['createKey'] } } }), [])
  for (const routes of [[{ methods: [], paths: ['/'] }], [{ methods: ['TRACE'], paths: ['/'] }], Array(65).fill({ methods: ['GET'], paths: ['/'] })]) {
    assert.ok(policy.validate({ routes }).some((p) => p.field === 'routes'))
  }
  assert.deepEqual(policy.validate({ routes: [] }), [])
})

test('limit intersections preserve invalid values and canonical window winners', () => {
  assert.deepEqual(policy.PER_MS, { second: 1000, minute: 60000, hour: 3600000 })
  assert.deepEqual(policy.WINDOW_MS, { hour: 3600000, day: 86400000 })
  assert.deepEqual(policy.intersect([{ rate: { count: 60, per: 'second' } }, { rate: { count: 100, per: 'minute' } }]).rate, { count: 100, per: 'minute' })
  assert.deepEqual(policy.intersect([{ rate: { count: 60, per: 'minute' } }, { rate: { count: 1, per: 'second' } }]).rate, { count: 1, per: 'second' })
  for (const field of ['rate', 'quota', 'max_concurrent', 'budget', 'spend']) {
    const bad = { rate: { count: NaN, per: 'second' }, quota: { count: 0, window: 'day' }, max_concurrent: NaN, budget: { unit: 'tokens', limit: 1 }, spend: { tokens: '' } }[field]
    const good = { rate: { count: 1, per: 'second' }, quota: { count: 1, window: 'day' }, max_concurrent: 1, budget: { limit: 1 }, spend: { tokens: 1 } }[field]
    for (const layers of [[{ [field]: bad }, { [field]: good }], [{ [field]: good }, { [field]: bad }]]) {
      const effective = policy.intersect(layers)
      assert.ok(policy.validate(effective).some((p) => p.field === field), field)
      assert.throws(() => policy.evaluateHttp(effective, { host: 'example.test', path: '/' }), (e) => e.rule === `${field}_invalid`)
    }
  }
  assert.deepEqual(policy.intersect([{ redirects: { max: 5 } }, { redirects: { max: NaN } }]).redirects, { max: 0 })
  for (const approval of ['bad', '', false, 0, null]) assert.equal(policy.needsApproval({ approval }, { method: 'GET' }), true)
})

test('grant input defaults, narrow conversion and detached description', () => {
  const options = { profile: { defaultBudget: { unit: 'requests', limit: 7 } }, ceiling: ['api.example.test'] }
  const layer = policy.grantPolicyFromInput({ rate: '60/min', quota: '10/day', spend_tokens: 0, spend_usd: 0.000001 }, options)
  assert.deepEqual(layer.hosts, ['api.example.test'])
  assert.deepEqual(layer.methods, ['GET', 'HEAD'])
  assert.deepEqual(layer.budget, { unit: 'requests', limit: 7 })
  assert.deepEqual(layer.redirects, { max: 0 })
  assert.deepEqual(layer.rate, { count: 60, per: 'minute' })
  assert.deepEqual(layer.quota, { count: 10, window: 'day' })
  assert.deepEqual(layer.spend, { tokens: 0, usd_micros: 1 })
  assert.deepEqual(policy.grantPolicyFromInput({ methods: ['GET'] }, { ...options, defaults: false }), { methods: ['GET'] })
  for (const spec of [{ budget: '' }, { rate: '1/day' }, { spend_usd: 0.0000001 }, { approval: 'bad' }, { redirects: '1' }]) {
    assert.throws(() => policy.grantPolicyFromInput(spec, options), (e) => e.rule === 'policy_invalid')
  }
  const effective = policy.intersect([layer, { payload: { query: { x: { required: true } } }, routes: [{ methods: ['GET'], paths: ['/'] }] }])
  const described = policy.describeEffective(effective)
  assert.deepEqual(described.budget, { limit: 7 })
  assert.deepEqual(described.routes, effective.route_sets)
  described.payload[0].query.x.required = false
  assert.equal(effective.payload_sets[0].query.x.required, true)
  assert.deepEqual(policy.describeEffective({}).redirects, { max: 0 })
})

// Seeded random layers over every field in contracts.md 0.6. Each field is
// left out of a layer a quarter of the time, because "absent" is where an
// intersection most easily widens: absent means no constraint for every field
// except `redirects`, where it means 0 and only stated values are combined.
test('every-field randomized intersections only narrow, and an effective policy is a reusable layer', () => {
  let seed = 0x12345678
  const random = (n) => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n }
  const maybe = (value) => (random(4) === 0 ? undefined : value)
  const make = () => {
    const layer = {
      kind: 'http', hosts: maybe(random(2) ? ['*.example.test'] : ['api.example.test']),
      methods: maybe(random(2) ? ['GET', 'POST'] : ['GET']), paths: maybe(random(2) ? ['/a/**'] : ['/a/b']),
      deny_paths: maybe([random(2) ? '/blocked' : '/private']), approval: maybe(policy.APPROVAL_ORDER[random(4)]),
      sql_profile: maybe(policy.SQL_ORDER[random(3)]), mode: maybe(policy.SSH_MODE_ORDER[random(2)]),
      budget: maybe({ unit: 'requests', limit: random(100) }),
      spend: maybe(random(3) ? { tokens: random(100), usd_micros: random(100) } : { tokens: random(100) }),
      rate: maybe({ count: random(99) + 1, per: ['second', 'minute', 'hour'][random(3)] }),
      quota: maybe({ count: random(99) + 1, window: ['hour', 'day'][random(2)] }), max_concurrent: maybe(random(10) + 1),
      placeholder_policy: maybe({ max_uses: random(10) + 1, ttl: random(10) + 1, max_active: random(10) + 1 }),
      databases: maybe(['db', `db${random(5)}`]), rcpt: maybe(['a', `a${random(5)}`]), commands: maybe(['ls', `cmd${random(5)}`]),
      graphql: maybe({ legacy: true }), stream_bodies: maybe(!!random(2)), redirects: maybe({ max: random(6) }),
      routes: maybe([{ methods: random(2) ? ['GET'] : ['GET', 'POST'], paths: [random(2) ? '/a/**' : '/a/b'] }]),
      payload: maybe({ query: { x: { max_length: random(10) } } }),
    }
    for (const k of Object.keys(layer)) if (layer[k] === undefined) delete layer[k]
    return layer
  }
  const stated = (layers, field) => layers.filter((l) => l[field] !== undefined)
  for (let i = 0; i < 400; i++) {
    const layers = random(3) ? [make(), make()] : [make(), make(), make()]
    const c = policy.intersect(layers)
    assert.deepEqual(policy.validate(c), [], JSON.stringify(layers))
    // Idempotent, and the effective policy means the same thing stored as a layer.
    assert.deepEqual(policy.intersect([c]), c)
    for (const field of ['methods', 'databases', 'rcpt', 'commands']) {
      const sides = stated(layers, field)
      if (!sides.length) { assert.equal(c[field] ?? null, null, field); continue }
      for (const value of c[field]) for (const side of sides) assert.ok(side[field].includes(value), field)
    }
    const minOf = (field, key) => {
      const values = stated(layers, field).map((l) => l[field][key]).filter((v) => v !== undefined)
      if (!values.length) assert.equal(c[field]?.[key], undefined, `${field}.${key}`)
      else assert.equal(c[field][key], Math.min(...values), `${field}.${key}`)
    }
    minOf('budget', 'limit'); minOf('spend', 'tokens'); minOf('spend', 'usd_micros')
    for (const key of ['max_uses', 'ttl', 'max_active']) for (const side of stated(layers, 'placeholder_policy')) assert.ok(c.placeholder_policy[key] <= side.placeholder_policy[key], key)
    if (stated(layers, 'max_concurrent').length) for (const side of stated(layers, 'max_concurrent')) assert.ok(c.max_concurrent <= side.max_concurrent)
    else assert.equal(c.max_concurrent, undefined)
    for (const [field, units, key] of [['rate', policy.PER_MS, 'per'], ['quota', policy.WINDOW_MS, 'window']]) {
      const sides = stated(layers, field)
      if (!sides.length) { assert.equal(c[field], undefined, field); continue }
      // The winner is one of the layers' own values, returned verbatim, and
      // allows no more per unit of time than any of them.
      assert.ok(sides.some((side) => side[field] === c[field] || JSON.stringify(side[field]) === JSON.stringify(c[field])), field)
      for (const side of sides) assert.ok(c[field].count / units[c[field][key]] <= side[field].count / units[side[field][key]], field)
    }
    // Absent redirects mean 0 hops; only stated values are combined.
    const hops = stated(layers, 'redirects').map((l) => l.redirects.max)
    assert.equal(c.redirects?.max ?? 0, hops.length ? Math.min(...hops) : 0)
    const approvals = stated(layers, 'approval').map((l) => policy.APPROVAL_ORDER.indexOf(l.approval))
    if (approvals.length) assert.equal(policy.APPROVAL_ORDER.indexOf(c.approval), Math.max(...approvals))
    for (const [key, order] of [['sql_profile', policy.SQL_ORDER], ['mode', policy.SSH_MODE_ORDER]]) {
      const sides = stated(layers, key).map((l) => order.indexOf(l[key]))
      if (sides.length) assert.equal(order.indexOf(c[key]), Math.min(...sides), key)
    }
    assert.ok(!c.stream_bodies || layers.every((l) => l.stream_bodies === true))
    assert.deepEqual(c.deny_paths, layers.flatMap((l) => l.deny_paths ?? []))
    assert.deepEqual(c.route_sets, stated(layers, 'routes').map((l) => l.routes))
    assert.deepEqual(c.payload_sets, stated(layers, 'payload').map((l) => l.payload))
    assert.equal(Object.hasOwn(c, 'routes') || Object.hasOwn(c, 'payload'), false)
    // And what it permits: nothing that any layer alone forbids.
    for (const host of ['api.example.test', 'other.example.test']) for (const path of ['/a/b', '/a/c', '/blocked']) for (const method of ['GET', 'POST']) {
      const req = { host, path, method }
      let allowed = true
      try { policy.evaluateHttp(c, req) } catch { allowed = false }
      if (allowed) for (const layer of layers) assert.doesNotThrow(() => policy.evaluateHttp(policy.intersect([layer]), req), JSON.stringify({ layer, req }))
    }
  }
})
