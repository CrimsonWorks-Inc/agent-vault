// A placeholder in a JSON body, a form body, and a GraphQL variable.
// Substituted only at a declared site. The upstream record is what was sent.
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { rustSkipReason, openWorld, gateway, leaksSecret, SECRET, PASSPHRASE } from './lib/harness.js'

const ORDINARY = 'ordinary-traffic-control'

const skip = rustSkipReason()
if (skip) {
  test('bodies', { skip }, () => {})
} else {
  describe('bodies', { concurrency: false, timeout: 120_000 }, () => {
    let w
    let ph
    let token
    before(async () => {
      w = await openWorld()
      const added = await w.control('POST', '/v1/credentials', {
        slug: 'body', kind: 'http', host: `127.0.0.1:${w.upstream.port}`, scheme: 'http',
        value: SECRET,
        sites: ['json:/variables/token', 'json:/input/token', 'form:token', 'header:authorization:Bearer'],
      })
      assert.equal(added.status, 200, added.text)
      const phrase = await w.control('POST', '/v1/passphrase', { passphrase: PASSPHRASE })
      assert.equal(phrase.status, 200, phrase.text)
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'body', label: 'body', methods: ['GET', 'POST'], paths: ['/**'],
        budget: 20, approval: 'auto', ttl_hours: 1,
        presence: { passphrase: PASSPHRASE },
      })
      assert.equal(session.status, 200, session.text)
      ph = session.json.placeholder
      token = session.json.token
    })
    after(async () => { await w?.close() })

    function post(path, headers, body) {
      return gateway(w, `/p/body${path}`, { method: 'POST', token, headers, body })
    }

    test('a JSON placeholder is substituted only at the declared pointer', async () => {
      const before = w.upstream.hits.length
      const res = await post('/echo', { 'content-type': 'application/json' }, JSON.stringify({
        input: { token: ph, note: ORDINARY },
      }))
      assert.equal(res.status, 200, res.text)
      assert.equal(res.json.ordinary, ORDINARY)
      assert.equal(leaksSecret(res.text), null)
      assert.equal(w.upstream.hits.length, before + 1)
      const sent = JSON.parse(w.upstream.hits.at(-1).body)
      assert.equal(sent.input.token, SECRET)
      assert.equal(sent.input.note, ORDINARY)
      assert.equal(sent.input.token === ph, false)

      const refused = await post('/echo', { 'content-type': 'application/json' }, JSON.stringify({
        input: { other: ph, note: ORDINARY },
      }))
      assert.equal(refused.status, 403, refused.text)
      assert.equal(refused.json.code, 'AV_BAD_LOCATION')
      assert.equal(refused.json.rule, 'injection_site')
      assert.equal(w.upstream.hits.length, before + 1)
      assert.equal(leaksSecret(refused.text), null)
    })

    test('a form placeholder is substituted only in the declared field', async () => {
      const before = w.upstream.hits.length
      const res = await post('/echo', { 'content-type': 'application/x-www-form-urlencoded' },
        `token=${encodeURIComponent(ph)}&note=${ORDINARY}`)
      assert.equal(res.status, 200, res.text)
      assert.equal(leaksSecret(res.text), null)
      const sent = w.upstream.hits.at(-1).body
      assert.ok(sent.includes(SECRET), sent)
      assert.ok(sent.includes(ORDINARY))
      assert.equal(sent.includes(ph), false)
      assert.equal(w.upstream.hits.length, before + 1)

      const refused = await post('/echo', { 'content-type': 'application/x-www-form-urlencoded' },
        `note=${encodeURIComponent(ph)}`)
      assert.equal(refused.status, 403, refused.text)
      assert.equal(refused.json.code, 'AV_BAD_LOCATION')
      assert.equal(refused.json.rule, 'injection_site')
      assert.equal(w.upstream.hits.length, before + 1)
      assert.equal(leaksSecret(refused.text), null)
    })

    test('a GraphQL variable is substituted only when that variable is a declared site', async () => {
      const before = w.upstream.hits.length
      const res = await post('/graphql', { 'content-type': 'application/json' }, JSON.stringify({
        query: 'query Ping { ping }',
        variables: { token: ph, note: ORDINARY },
      }))
      // The shared upstream answers a non-/echo POST with 201. The body is still scrubbed.
      assert.equal(res.status, 201, res.text)
      assert.equal(res.json.ordinary, ORDINARY)
      assert.equal(leaksSecret(res.text), null)
      const sent = JSON.parse(w.upstream.hits.at(-1).body)
      assert.equal(sent.query, 'query Ping { ping }')
      assert.equal(sent.variables.token, SECRET)
      assert.equal(sent.variables.note, ORDINARY)
      assert.equal(w.upstream.hits.length, before + 1)

      const inQuery = await post('/graphql', { 'content-type': 'application/json' }, JSON.stringify({
        query: `query Ping { ping(token: "${ph}") }`,
        variables: { note: ORDINARY },
      }))
      assert.equal(inQuery.status, 403, inQuery.text)
      assert.equal(inQuery.json.code, 'AV_BAD_LOCATION')
      assert.equal(inQuery.json.rule, 'injection_site')
      assert.equal(w.upstream.hits.length, before + 1)
      assert.equal(leaksSecret(inQuery.text), null)
    })

    test('a GraphQL operation allowlist refuses a mutation and a denied field, and a query still passes', async () => {
      const session = await w.control('POST', '/v1/sessions', {
        cred: 'body', label: 'gql', methods: ['POST'], paths: ['/**'],
        budget: 10, approval: 'auto', ttl_hours: 1,
        presence: { passphrase: PASSPHRASE },
        payload: { graphql: { operations: ['query'], deny_fields: ['SecretField'] } },
      })
      assert.equal(session.status, 200, session.text)
      const send = (query) => gateway(w, '/p/body/graphql', {
        method: 'POST', token: session.json.token, placeholder: session.json.placeholder,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query, variables: { note: ORDINARY } }),
      })
      const before = w.upstream.hits.length
      const mutation = await send('mutation Ping { ping }')
      assert.equal(mutation.status, 403, mutation.text)
      assert.equal(mutation.json.code, 'AV_POLICY_DENIED')
      assert.equal(mutation.json.rule, 'payload:graphql:operation')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(mutation.text), null)

      const field = await send('query Ping { SecretField }')
      assert.equal(field.status, 403, field.text)
      assert.equal(field.json.code, 'AV_POLICY_DENIED')
      assert.equal(field.json.rule, 'payload:graphql:deny_field')
      assert.equal(w.upstream.hits.length, before)
      assert.equal(leaksSecret(field.text), null)

      const ok = await send('query Ping { ping }')
      assert.equal(ok.status, 201, ok.text)
      assert.equal(ok.json.ordinary, ORDINARY)
      assert.equal(w.upstream.hits.length, before + 1)
      const sent = JSON.parse(w.upstream.hits.at(-1).body)
      assert.equal(sent.query, 'query Ping { ping }')
      assert.equal(sent.variables.note, ORDINARY)
      assert.equal(leaksSecret(ok.text), null)
    })
  })
}
