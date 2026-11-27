import { describe, expect, it } from 'vitest'
import { operationFor } from '../../lib/presence.js'
import { parseOverrides } from '../../../../legacy/js/src/pending.js'
import { bulkable, bulkDecisions, bulkOutcome, decisionCall, readNarrowing, typedNarrowing } from './decide.js'

const SESSION = { id: 'sr_1', kind: 'session', narrowable: ['methods', 'budget'], owner_settable: ['approval', 'infinite'] }
const REQUEST = { id: 'ap_1', kind: 'request', narrowable: [], owner_settable: [] }

describe('decide.js: one decision, read and signed as the old page did', () => {
  it('reads only what was typed, only when approving; the owner approval goes as chosen, even empty', () => {
    const draft = { fields: { methods: ' GET ', budget: '' }, approval: '', infinite: false }
    expect(typedNarrowing(SESSION, draft, true)).toEqual({ methods: 'GET', approval: '' })
    expect(typedNarrowing(SESSION, { ...draft, infinite: true, approval: 'each' }, true)).toEqual({ methods: 'GET', approval: 'each', infinite: true })
    expect(typedNarrowing(SESSION, draft, false)).toEqual({})
    expect(typedNarrowing(REQUEST, draft, true)).toEqual({})
  })

  it('parses with the CLI\'s own parser, and says why when it cannot', () => {
    expect(readNarrowing({ methods: 'get,head' })).toEqual({ overrides: parseOverrides({ methods: 'get,head' }) })
    expect(readNarrowing({ budget: 'lots' }).error).toMatch(/^That narrowing does not parse, so nothing was sent: budget/)
    expect(readNarrowing({ hosts: 'x' }).error).toMatch(/not a narrowing an approval applies/)
  })

  it('a session request: signed over id, verdict and the parsed narrowing; denial sends no overrides', async () => {
    const calls = []
    const api = { post: async (path, body) => { calls.push([path, body]); return {} } }
    const yes = await decisionCall(SESSION, true, { fields: { methods: 'GET' } }, { operationFor, api })
    expect(yes.operation).toEqual(await operationFor('session_request.decide', { id: 'sr_1', granted: true, methods: ['GET'] }))
    await yes.send({ p: 1 })
    expect(calls[0]).toEqual(['session-requests/decide', { id: 'sr_1', granted: true, overrides: { methods: ['GET'] }, presence: { p: 1 } }])
    const no = await decisionCall(SESSION, false, { fields: { methods: 'GET' } }, { operationFor, api })
    expect(no.operation).toEqual({ op: 'session_request.decide', id: 'sr_1', granted: false })
    await no.send({ p: 2 })
    expect(calls[1][1].overrides).toBeUndefined()
  })

  it('a held request: approval.approve / approval.deny over { id, granted }', async () => {
    const api = { post: async (path, body) => ({ path, body }) }
    const yes = await decisionCall(REQUEST, true, {}, { operationFor, api })
    expect(yes.operation).toEqual({ op: 'approval.approve', id: 'ap_1', granted: true })
    expect(await yes.send('proof')).toEqual({ path: 'approvals', body: { id: 'ap_1', granted: true, presence: 'proof' } })
    expect((await decisionCall(REQUEST, false, {}, { operationFor, api })).operation).toEqual({ op: 'approval.deny', id: 'ap_1', granted: false })
  })

  it('a narrowing that does not parse throws before any operation exists', async () => {
    await expect(decisionCall(SESSION, true, { fields: { budget: 'x' } }, { operationFor, api: {} })).rejects.toThrow(/does not parse/)
  })
})

describe('decide.js: a proposed credential', () => {
  const PROPOSAL = { id: 'cp_1', kind: 'credential', hosts: ['api.linear.app'], narrowable: [], owner_settable: [], proposal: { slug: 'linear' } }

  it('approves only once the host is confirmed and a key typed, binding the hosts and the key by digest', async () => {
    const calls = []
    const api = { post: async (path, body) => { calls.push([path, body]); return {} } }
    await expect(decisionCall(PROPOSAL, true, { value: 'k' }, { operationFor, api })).rejects.toThrow('Confirm the host first.')
    await expect(decisionCall(PROPOSAL, true, { hostsConfirmed: true, value: ' ' }, { operationFor, api })).rejects.toThrow('Type the key first.')
    await expect(decisionCall({ ...PROPOSAL, hosts: [] }, true, { hostsConfirmed: true, value: 'k' }, { operationFor, api })).rejects.toThrow(/names no host/)
    const yes = await decisionCall(PROPOSAL, true, { hostsConfirmed: true, value: 'test-key-fake\n' }, { operationFor, api })
    expect(yes.operation).toEqual(await operationFor('cred_proposal.approve', { id: 'cp_1', granted: true, hosts: ['api.linear.app'], value: 'test-key-fake' }))
    expect(yes.operation.value).toBeUndefined()
    expect(yes.operation.value_sha256).toMatch(/^[0-9a-f]{64}$/)
    await yes.send({ p: 1 })
    expect(calls[0]).toEqual(['cred-proposals/decide', { id: 'cp_1', granted: true, hosts: ['api.linear.app'], value: 'test-key-fake', presence: { p: 1 } }])
  })

  it('denies with no key and no hosts, and is never part of a bulk decision', async () => {
    const api = { post: async (path, body) => ({ path, body }) }
    const no = await decisionCall(PROPOSAL, false, { hostsConfirmed: true, value: 'k' }, { operationFor, api })
    expect(no.operation).toEqual({ op: 'cred_proposal.deny', id: 'cp_1', granted: false })
    expect(await no.send('proof')).toEqual({ path: 'cred-proposals/decide', body: { id: 'cp_1', granted: false, presence: 'proof' } })
    expect([PROPOSAL, SESSION, REQUEST].filter(bulkable).map((i) => i.id)).toEqual(['sr_1', 'ap_1'])
  })
})

describe('decide.js: several decisions, one signature', () => {
  it('carries exactly the ticked items, refuses none and more than the daemon reads', () => {
    expect(bulkDecisions([SESSION, REQUEST], false)).toEqual([{ id: 'sr_1', kind: 'session', granted: false }, { id: 'ap_1', kind: 'request', granted: false }])
    expect(() => bulkDecisions([], true)).toThrow('Nothing selected')
    const many = Array.from({ length: 26 }, (_, i) => ({ id: `r${i}`, kind: 'request' }))
    expect(() => bulkDecisions(many, true)).toThrow(/too many at once/)
  })

  it('reports what happened to each one', () => {
    const d = [{ id: 'a' }, { id: 'b' }, { id: 'c' }]
    expect(bulkOutcome(d, { decided: [{ outcome: 'decided' }, { outcome: 'skipped' }] }, false)).toBe('2 denied, 1 no longer pending')
    expect(bulkOutcome(d, { decided: [] }, true)).toBe('3 approved')
  })
})
