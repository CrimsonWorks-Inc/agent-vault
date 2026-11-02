import { describe, expect, it, vi } from 'vitest'
import { act, configure, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeAuthenticator, fakeServer, renderWith } from '../test/harness.jsx'
import { operationFor } from '../lib/presence.js'
import { SESSIONS, callsTo, challengeOf, envelope, pagesRoutes } from './fixtures.pages-a.js'
import { Sessions } from './Sessions.jsx'

// Whole pages over a fake server: generous when the machine is busy.
vi.setConfig({ testTimeout: 30000 })
configure({ asyncUtilTimeout: 5000 })

const click = async (el) => { await act(async () => { fireEvent.click(el) }) }
const type = (el, value) => fireEvent.change(el, { target: { value } })
const enrolled = (server) => waitFor(() => expect(callsTo(server, 'GET', 'presence/state').length).toBeGreaterThan(0))
const pick = async (buttonName, option) => {
  await click(screen.getByRole('button', { name: buttonName }))
  await click(await screen.findByRole('option', { name: option }))
}

const CREATED = {
  session_id: 's_new', token: 'avs_test_token_123', expires_at: null, infinite: true, label: 'triage',
  grants: [
    { cred: 'gh-work', base_url: 'http://127.0.0.1:7411/gh-work', placeholder: 'AVPH_gh_secretish', usage: ['header Authorization (Bearer)'] },
    { cred: 'openai', base_url: 'http://127.0.0.1:7411/openai', placeholder: 'AVPH_oa_secretish', usage: ['header Authorization (Bearer)'] },
  ],
}

describe('Sessions: the list', () => {
  it('loading, then each session with its badges; infinite reads "never expires"', async () => {
    let release
    const gate = new Promise((r) => { release = r })
    const server = fakeServer(pagesRoutes({ 'GET sessions': async (c) => { await gate; return envelope(SESSIONS)(c) } }))
    renderWith(<Sessions />, { server })
    expect(await screen.findByRole('heading', { name: 'Sessions', level: 1 })).toBeTruthy()
    expect(screen.getAllByText('Loading').length).toBeGreaterThan(0)
    await act(async () => { release() })
    await screen.findAllByText('issue triage')
    expect(screen.getAllByText('never expires').length).toBeGreaterThan(0)
    expect(screen.getAllByText('approval: auto').length).toBeGreaterThan(0) // elevated: the laxest mode
    expect(screen.getAllByText('approval: on-write').length).toBeGreaterThan(0)
    expect(screen.getAllByText('remote').length).toBeGreaterThan(0)
    expect(screen.getAllByText('infinite').length).toBeGreaterThan(0)
    expect(screen.getAllByText('elevated').length).toBeGreaterThan(0)
    // A revoked session has nothing to narrow or revoke.
    expect(screen.queryAllByRole('button', { name: 'Revoke session s_old' })).toHaveLength(0)
    expect(screen.getAllByRole('button', { name: 'Details of session s_old' }).length).toBeGreaterThan(0)
  })

  it('empty and error states', async () => {
    const server = fakeServer(pagesRoutes({ 'GET sessions': envelope([]) }))
    renderWith(<Sessions />, { server })
    expect(await screen.findByText('No sessions yet.')).toBeTruthy()
    const broken = fakeServer(pagesRoutes({ 'GET sessions': { __status: 500, body: { error: 'nope' } } }))
    renderWith(<Sessions />, { server: broken })
    expect(await screen.findByText('Could not read the sessions.')).toBeTruthy()
  })

  it('pages with paged=1 and the server cursor', async () => {
    const many = Array.from({ length: 64 }, (_, i) => ({ id: `s_${i}`, label: `bot ${i}`, state: 'active', grants: 1, creds: [], expires_at: null, infinite: true }))
    const server = fakeServer(pagesRoutes({ 'GET sessions': envelope(many) }))
    renderWith(<Sessions />, { server })
    await screen.findAllByText('bot 0')
    expect(callsTo(server, 'GET', 'sessions')[0].query).toEqual({ paged: '1', limit: '25' })
    await click(screen.getByRole('button', { name: 'Next page' }))
    await screen.findAllByText('bot 25')
    expect(callsTo(server, 'GET', 'sessions').at(-1).query).toEqual({ paged: '1', limit: '25', cursor: 'srv-25' })
    await click(screen.getByRole('button', { name: 'Previous page' }))
    await screen.findAllByText('bot 0')
    expect(callsTo(server, 'GET', 'sessions').at(-1).query).toEqual({ paged: '1', limit: '25' })
  })
})

describe('Sessions: revoke and narrow are signed over exactly what is sent', () => {
  it('Revoke: session.revoke, DELETE sessions?sid with only the proof', async () => {
    const server = fakeServer(pagesRoutes({ 'DELETE sessions': { ok: true } }))
    renderWith(<Sessions />, { server })
    await screen.findAllByText('issue triage'); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'Revoke session s_live' })[0])
    expect(await challengeOf(server)).toEqual({ op: 'session.revoke', sid: 's_live' })
    await waitFor(() => expect(callsTo(server, 'DELETE', 'sessions')).toHaveLength(1))
    expect(callsTo(server, 'DELETE', 'sessions')[0].query).toEqual({ sid: 's_live' })
    expect(Object.keys(callsTo(server, 'DELETE', 'sessions')[0].body)).toEqual(['presence'])
    expect(await screen.findByText('Revoked')).toBeTruthy()
  })

  for (const [label, body, title] of [
    ['Drop write access', { narrow: { methods: ['GET', 'HEAD'] } }, 'Write access dropped'],
    ['Require approval for everything', { narrow: { approval: 'each' } }, 'Every request now needs your approval'],
    ['End in 1 hour', { narrow: {}, session_ttl_minutes: 60 }, 'Ends within the hour'],
  ]) {
    it(`${label}: session.narrow over app.html's body, and the before/after card`, async () => {
      const result = { session_id: 's_live', expires_at: '2026-11-01T12:00:00Z', infinite: false, grants: [{ cred: 'gh-work', before: { methods: ['GET', 'POST'] }, after: { methods: ['GET', 'HEAD'] }, expires_at: null }] }
      const server = fakeServer(pagesRoutes({ 'POST sessions/narrow': result }))
      renderWith(<Sessions />, { server })
      await screen.findAllByText('issue triage'); await enrolled(server)
      await click(screen.getAllByRole('button', { name: 'Narrow session s_live' })[0])
      const dialog = await screen.findByRole('dialog')
      await click(within(dialog).getByRole('button', { name: new RegExp(label) }))
      const expected = { sid: 's_live', ...body }
      expect(await challengeOf(server)).toEqual(await operationFor('session.narrow', expected))
      await waitFor(() => expect(callsTo(server, 'POST', 'sessions/narrow')).toHaveLength(1))
      const { presence, ...sent } = callsTo(server, 'POST', 'sessions/narrow')[0].body
      expect(sent).toEqual(expected)
      expect(presence.challengeId).toBe('ch1')
      expect(await screen.findByRole('heading', { name: title })).toBeTruthy()
      expect(screen.getByText('session s_live expires 2026-11-01T12:00:00Z')).toBeTruthy()
      expect(screen.getByText('GET, POST')).toBeTruthy()
      expect(screen.getByText('GET, HEAD')).toBeTruthy()
    })
  }
})

describe('Sessions: New session and the hand-off card', () => {
  it('creates an infinite, auto-approved session: warnings first, then session.create over the exact body', async () => {
    const server = fakeServer(pagesRoutes({ 'POST sessions': CREATED }))
    renderWith(<Sessions rest="new" />, { server, vault: { context: { cli: 'agent-vault' } } })
    await screen.findByRole('group', { name: 'Credentials' }); await enrolled(server)
    // gh-work is picked by default; add openai.
    await click(screen.getByRole('checkbox', { name: /openai/ }))
    type(screen.getByPlaceholderText('issue triage'), 'triage')
    type(screen.getByDisplayValue('GET,HEAD'), 'GET,POST')
    await pick('Approval', 'never ask (auto)')
    await pick('Lifetime', 'No expiry')
    expect(screen.getByText(/No approval prompts for writes/)).toBeTruthy()
    expect(screen.getByText(/This session never expires/)).toBeTruthy()
    await click(screen.getByRole('button', { name: /Create session/ }))
    const body = {
      label: 'triage',
      grants: ['gh-work', 'openai'].map((cred) => ({ cred, methods: ['GET', 'POST'], paths: ['/**'], budget: 500, approval: 'auto' })),
      infinite: true,
    }
    expect(await challengeOf(server)).toEqual(await operationFor('session.create', body))
    await waitFor(() => expect(callsTo(server, 'POST', 'sessions')).toHaveLength(1))
    const { presence, ...sent } = callsTo(server, 'POST', 'sessions')[0].body
    expect(sent).toEqual(body)
    expect(presence.challengeId).toBe('ch1')

    const card = await screen.findByRole('heading', { name: 'Hand this to the agent' })
    const handoff = card.closest('[data-handoff]')
    expect(handoff.textContent).toContain('avs_test_token_123')
    expect(handoff.textContent).toContain('AVPH_gh_secretish')
    expect(handoff.textContent).toContain('never expires')
    expect(handoff.textContent).toContain('agent-vault env --session s_new --out .env --map GH_WORK_TOKEN=gh-work --map OPENAI_TOKEN=openai')
    expect(handoff.textContent).toContain('curl "http://127.0.0.1:7411/gh-work/user"')
    expect(handoff.textContent).toContain('-H "Authorization: Bearer AVPH_gh_secretish"')
    expect(await screen.findByText('Session s_new created')).toBeTruthy()
  })

  it('the env-file mapping: rename, add a base URL, refuse a bad name', async () => {
    const server = fakeServer(pagesRoutes({ 'POST sessions': CREATED }))
    renderWith(<Sessions rest="new" />, { server })
    await screen.findByRole('group', { name: 'Credentials' }); await enrolled(server)
    await click(screen.getByRole('button', { name: /Create session/ }))
    const handoff = (await screen.findByRole('heading', { name: 'Hand this to the agent' })).closest('[data-handoff]')
    type(within(handoff).getByLabelText('Variable name 1'), 'GITHUB_TOKEN')
    await click(within(handoff).getByRole('button', { name: 'Add a mapping' }))
    type(within(handoff).getByLabelText('Variable name 3'), 'GH_BASE')
    await click(within(handoff).getByRole('button', { name: 'Value for GH_BASE' }))
    await click(await screen.findByRole('option', { name: 'base URL' }))
    expect(handoff.textContent).toContain('--map GITHUB_TOKEN=gh-work --map OPENAI_TOKEN=openai --map GH_BASE=gh-work:base_url')
    type(within(handoff).getByLabelText('Variable name 2'), '9-bad')
    expect(within(handoff).getByText('Letters, digits and _ only, not starting with a digit')).toBeTruthy()
    expect(within(handoff).getByText('Fix the names above to get the command.')).toBeTruthy()
    expect(handoff.textContent).not.toContain('agent-vault env --session')
  })

  it('Done drops the token and placeholders from the page, and nothing was stored', async () => {
    const server = fakeServer(pagesRoutes({ 'POST sessions': CREATED }))
    renderWith(<Sessions rest="new" />, { server })
    await screen.findByRole('group', { name: 'Credentials' }); await enrolled(server)
    await click(screen.getByRole('button', { name: /Create session/ }))
    await screen.findByRole('heading', { name: 'Hand this to the agent' })
    expect(document.body.textContent).toContain('avs_test_token_123')
    await click(screen.getByRole('button', { name: 'Done' }))
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Hand this to the agent' })).toBeNull())
    expect(document.body.textContent).not.toContain('avs_test_token_123')
    expect(document.body.textContent).not.toContain('AVPH_')
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })
    expect(stored).not.toContain('avs_test_token_123')
    expect(stored).not.toContain('AVPH_')
  })

  it('a form mistake is said before signing and spends no tap', async () => {
    const authenticator = fakeAuthenticator()
    const server = fakeServer(pagesRoutes())
    renderWith(<Sessions rest="new" />, { server, authenticator })
    await screen.findByRole('group', { name: 'Credentials' }); await enrolled(server)
    await click(screen.getByRole('checkbox', { name: /gh-work/ })) // nothing picked now
    await click(screen.getByRole('button', { name: /Create session/ }))
    expect(await screen.findByText('Pick at least one credential')).toBeTruthy()
    await click(screen.getByRole('checkbox', { name: /gh-work/ }))
    await click(screen.getByRole('button', { name: 'Advanced limits' }))
    type(screen.getByPlaceholderText('{ "json": { "/channel": { "one_of": ["#bots"] } } }'), '{nope')
    await click(screen.getByRole('button', { name: /Create session/ }))
    expect(await screen.findByText(/^The payload rules are not JSON/)).toBeTruthy()
    expect(authenticator.asked).toHaveLength(0)
    expect(callsTo(server, 'POST', 'presence/challenge')).toHaveLength(0)
  })

  it('spend limits appear only for a model credential', async () => {
    const server = fakeServer(pagesRoutes())
    renderWith(<Sessions rest="new" />, { server })
    await screen.findByRole('group', { name: 'Credentials' })
    await click(screen.getByRole('button', { name: 'Advanced limits' }))
    expect(screen.queryByLabelText('Spend limit: tokens')).toBeNull()
    await click(screen.getByRole('checkbox', { name: /openai/ }))
    expect(screen.getByLabelText('Spend limit: tokens')).toBeTruthy()
  })

  it('Save as template: template.save over {name, spec: the session body}', async () => {
    const server = fakeServer(pagesRoutes({ 'POST templates': { name: 'gh-read', version: 3, lint: [{ message: 'wide paths' }] } }))
    renderWith(<Sessions rest="new" />, { server })
    await screen.findByRole('group', { name: 'Credentials' }); await enrolled(server)
    await click(screen.getByRole('button', { name: 'Save as template' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Template name (lower case, digits and dashes)')).toBeTruthy()
    type(within(dialog).getByRole('textbox'), 'gh-read')
    await click(within(dialog).getByRole('button', { name: 'Save' }))
    const spec = { label: 'ui session', grants: [{ cred: 'gh-work', methods: ['GET', 'HEAD'], paths: ['/**'], budget: 500, approval: 'on-write' }], ttl_hours: 8 }
    expect(await challengeOf(server)).toEqual(await operationFor('template.save', { name: 'gh-read', spec }))
    expect(await screen.findByText('Saved template gh-read v3, 1 warning')).toBeTruthy()
  })

  it('from a template: only narrower choices, and the hash of the template on screen', async () => {
    const server = fakeServer(pagesRoutes({ 'POST sessions': CREATED }))
    renderWith(<Sessions rest="new:gh-read" />, { server })
    expect(await screen.findByText(/These fields can only narrow it/)).toBeTruthy()
    await enrolled(server)
    expect(callsTo(server, 'GET', 'templates').some((c) => c.query.name === 'gh-read')).toBe(true)
    await click(screen.getByRole('checkbox', { name: 'POST' }))
    await pick('Approval', 'each')
    await click(screen.getByRole('button', { name: /Create from template/ }))
    const body = { template: 'gh-read', template_hash: 'h_abc', methods: ['GET', 'HEAD'], approval: 'each' }
    expect(await challengeOf(server)).toEqual(await operationFor('session.create', body))
    await screen.findByRole('heading', { name: 'Hand this to the agent' })
  })

  it('without a credential, says to add one first', async () => {
    const server = fakeServer(pagesRoutes({ 'GET credentials': envelope([]) }))
    renderWith(<Sessions rest="new" />, { server })
    expect(await screen.findByText('Add a credential first')).toBeTruthy()
  })
})

describe('Sessions: detail and access review', () => {
  it('detail: the facts, the paged grants, agent payload rules as text, incomplete history', async () => {
    const server = fakeServer(pagesRoutes())
    const { container } = renderWith(<Sessions rest="detail:s_live" />, { server })
    expect(await screen.findByText(/History is incomplete: the log was rotated/)).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Session s_live' })).toBeTruthy()
    await screen.findAllByText('ph_1')
    const paged = callsTo(server, 'GET', 'sessions/detail').find((c) => c.query.paged === '1')
    expect(paged.query).toEqual({ sid: 's_live', paged: '1', limit: '25' })
    expect(callsTo(server, 'GET', 'sessions/detail').some((c) => c.query.sid === 's_live' && !c.query.paged)).toBe(true)
    const payload = container.querySelector('figure[data-untrusted]')
    expect(payload.textContent).toContain('"one_of"')
    expect(payload.textContent).not.toMatch(/[\u202a-\u202e]/)
    expect(screen.getByText('12 allowed · 2 refused · 1 held · approvals: 1 asked, 1 granted, 0 denied')).toBeTruthy()
    expect(screen.getAllByText('tokens: 100 used, 50 reserved, of 1000').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Copy as Markdown' })).toBeTruthy()
  })

  it('access review: both lists paged by the server, with what to tighten', async () => {
    const server = fakeServer(pagesRoutes())
    renderWith(<Sessions rest="review" />, { server })
    await screen.findAllByText('granted but never used:')
    const asks = callsTo(server, 'GET', 'report/access').filter((c) => c.query.paged === '1')
    expect(asks.map((c) => c.query.list).sort()).toEqual(['credentials', 'sessions'])
    for (const c of asks) expect(c.query).toMatchObject({ since: '7d', paged: '1', limit: '25' })
    expect(screen.getAllByText('HEAD').length).toBeGreaterThan(0)
    expect(screen.getAllByText('quarantined').length).toBeGreaterThan(0)
  })
})
