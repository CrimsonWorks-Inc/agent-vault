import { describe, expect, it } from 'vitest'
import { operationFor } from '../../lib/presence.js'
import { parseOverrides } from '../../../../src/pending.js'
import { bulkDecisions, bulkOutcome, decisionCall, readNarrowing, typedNarrowing } from './decide.js'

const SESSION = { id: 'sr_1', kind: 'session', narrowable: ['methods', 'budget'], owner_settable: ['approval', 'infinite'] }
const REQUEST = { id: 'ap_1', kind: 'request', narrowable: [], owner_settable: [] }

describe('decide.js: one decision, read and signed as app.html did', () => {
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
