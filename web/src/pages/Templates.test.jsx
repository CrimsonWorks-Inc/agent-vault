import { describe, expect, it, vi } from 'vitest'
import { act, configure, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { TEMPLATES, callsTo, challengeOf, envelope, pagesRoutes, Enrolled } from './fixtures.pages-a.jsx'
import { Templates } from './Templates.jsx'

// Whole pages over a fake server: generous when the machine is busy.
vi.setConfig({ testTimeout: 30000 })
configure({ asyncUtilTimeout: 5000 })

const click = async (el) => { await act(async () => { fireEvent.click(el) }) }
const enrolled = (server) => waitFor(() => expect(callsTo(server, 'GET', 'presence/state').length).toBeGreaterThan(0))

describe('Templates', () => {
  it('lists the saved templates by name, with version, elevation and credentials', async () => {
    const server = fakeServer(pagesRoutes())
    renderWith(<Enrolled><Templates /></Enrolled>, { server })
    expect(await screen.findByRole('heading', { name: 'Templates', level: 1 })).toBeTruthy()
    await screen.findAllByText('gh-read')
    expect(screen.getAllByText('v2').length).toBeGreaterThan(0)
    expect(screen.getAllByText('elevated').length).toBeGreaterThan(0)
    expect(screen.getAllByText('read GitHub').length).toBeGreaterThan(0)
    expect(screen.getByText('2 templates, by name')).toBeTruthy()
  })

  it('empty: says how to make one; error: says what went wrong', async () => {
    const server = fakeServer(pagesRoutes({ 'GET templates': envelope([]) }))
    renderWith(<Enrolled><Templates /></Enrolled>, { server })
    expect(await screen.findByText('No templates yet')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Open New session' }).getAttribute('href')).toBe('#sessions/new')
    const broken = fakeServer(pagesRoutes({ 'GET templates': { __status: 503, body: { error: 'x' } } }))
    renderWith(<Enrolled><Templates /></Enrolled>, { server: broken })
    // 503 is "cannot reach the daemon", which App swaps for its own screen; the page still says it failed.
    expect(await screen.findByText('Could not read the templates.')).toBeTruthy()
  })

  it('pages and searches through the server (paged=1, cursor, q)', async () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ name: `t-${String(i).padStart(2, '0')}`, version: 1, creds: [], elevated: [] }))
    const server = fakeServer(pagesRoutes({ 'GET templates': envelope(many) }))
    renderWith(<Enrolled><Templates /></Enrolled>, { server })
    await screen.findAllByText('t-00')
    expect(callsTo(server, 'GET', 'templates')[0].query).toEqual({ paged: '1', limit: '25' })
    await click(screen.getByRole('button', { name: 'Next page' }))
    await screen.findAllByText('t-25')
    expect(callsTo(server, 'GET', 'templates').at(-1).query.cursor).toBe('srv-25')
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search templates' }), { target: { value: 'ship' } })
    await waitFor(() => expect(callsTo(server, 'GET', 'templates').at(-1).query).toEqual({ paged: '1', limit: '25', q: 'ship' }))
  })

  it('Delete: template.delete, DELETE templates?name with only the proof', async () => {
    const server = fakeServer(pagesRoutes({ 'DELETE templates': { ok: true } }))
    renderWith(<Enrolled><Templates /></Enrolled>, { server })
    await screen.findAllByText('gh-read'); await enrolled(server)
    await click(screen.getAllByRole('button', { name: 'Delete template gh-read' })[0])
    expect(await challengeOf(server)).toEqual({ op: 'template.delete', name: 'gh-read' })
    await waitFor(() => expect(callsTo(server, 'DELETE', 'templates')).toHaveLength(1))
    expect(callsTo(server, 'DELETE', 'templates')[0].query).toEqual({ name: 'gh-read' })
    expect(Object.keys(callsTo(server, 'DELETE', 'templates')[0].body)).toEqual(['presence'])
    expect(await screen.findByText('Deleted template gh-read')).toBeTruthy()
  })

  it('View shows the stored spec; Use opens New session on it', async () => {
    const server = fakeServer(pagesRoutes())
    renderWith(<Enrolled><Templates /></Enrolled>, { server })
    await screen.findAllByText('gh-read')
    await click(screen.getAllByRole('button', { name: 'View template gh-read' })[0])
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('h_abc')).toBeTruthy()
    expect(dialog.textContent).toContain('"grant_ttl_minutes": 60')
    await click(screen.getAllByRole('button', { name: `Start a session from ${TEMPLATES[1].name}` })[0])
    expect(location.hash).toBe('#sessions/new%3Aship-it')
  })
})
