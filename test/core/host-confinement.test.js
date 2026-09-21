import { test } from 'node:test'
import assert from 'node:assert/strict'
import { credentialHostCeiling, confineHosts, hostOnly } from '../../src/core/policy.js'

// The pen-test finding: a grant could name a host unrelated to the credential,
// letting an agent aim the credential at a server it controls.

test('a credential ceiling is its own host plus its profile hosts', () => {
  const ceiling = credentialHostCeiling({ connector: { host: 'api.example.com' } }, [])
  assert.deepEqual(ceiling, ['api.example.com'])
  const gh = credentialHostCeiling({ connector: {} }, ['api.github.com', 'uploads.github.com'])
  assert.deepEqual(gh, ['api.github.com', 'uploads.github.com'])
})

test('the port is stripped from the ceiling, since it travels with the connection', () => {
  assert.deepEqual(credentialHostCeiling({ connector: { host: '127.0.0.1:9931' } }, []), ['127.0.0.1'])
})

test('confineHosts rejects any host outside the ceiling', () => {
  // This is the exact exfiltration attempt from the pen test.
  assert.throws(
    () => confineHosts(['127.0.0.1'], ['api.example.com']),
    (e) => e.code === 'AV_POLICY_DENIED' && /outside what credential permits/.test(e.detail),
  )
})

test('confineHosts keeps hosts that are inside the ceiling', () => {
  assert.deepEqual(confineHosts(['api.github.com'], ['api.github.com', 'uploads.github.com']), ['api.github.com'])
})

test('an empty request defaults to the whole ceiling, never to unrestricted', () => {
  assert.deepEqual(confineHosts(null, ['api.example.com']), ['api.example.com'])
  assert.deepEqual(confineHosts([], ['api.example.com']), ['api.example.com'])
})

test('a credential that declares no host cannot be granted at all', () => {
  assert.throws(() => confineHosts(['anything'], []), /no host it may reach/)
})

test('a smuggled port cannot slip a host past the ceiling', () => {
  // "127.0.0.1:9931" must be judged as 127.0.0.1, not as a novel host.
  assert.throws(() => confineHosts(['127.0.0.1:9931'], ['api.example.com']), /AV_POLICY_DENIED/)
  assert.equal(hostOnly('127.0.0.1:9931'), '127.0.0.1')
  assert.equal(hostOnly('[::1]:8443'), '[::1]')
  assert.equal(hostOnly('API.Example.com.'), 'api.example.com')
})
