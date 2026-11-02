import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { Notifications } from './Notifications.jsx'

afterEach(() => { delete globalThis.Notification })

describe('Notifications (parity with the old page)', () => {
  it('shows the webhook read-only, and the notify command with the server\'s cli name', async () => {
    const server = fakeServer({ 'GET notify': { webhook: { host: 'hooks.example.com', detail: 'minimal', configured_at: '2026-10-30T10:00:00Z' } } })
    renderWith(<Notifications />, { server, vault: { context: { cli: 'av' } } })
    expect(await screen.findByText('hooks.example.com')).toBeTruthy()
    expect(screen.getByText(/minimal · since 2026-10-30/)).toBeTruthy()
    expect(screen.getByText('av watch')).toBeTruthy()
    expect(screen.queryByText(/agent-vault notify set/)).toBeNull()
  })

  it('no webhook: says how to set one, with the cli name', async () => {
    const server = fakeServer({ 'GET notify': { webhook: null } })
    renderWith(<Notifications />, { server, vault: { context: { cli: 'av' } } })
    expect(await screen.findByText('No webhook. Set one from the command line:')).toBeTruthy()
    expect(screen.getAllByText('av notify set').length).toBeGreaterThan(0)
  })

  it('a browser without notifications is told so', async () => {
    const server = fakeServer({ 'GET notify': { webhook: null } })
    renderWith(<Notifications />, { server })
    expect(await screen.findByText('This browser cannot show desktop notifications.')).toBeTruthy()
  })

  it('turning them on asks for permission and remembers it', async () => {
    const N = vi.fn()
    N.permission = 'default'
    N.requestPermission = vi.fn(async () => { N.permission = 'granted'; return 'granted' })
    globalThis.Notification = N
    const server = fakeServer({ 'GET notify': { webhook: null } })
    renderWith(<Notifications />, { server })
    fireEvent.click(await screen.findByRole('switch'))
    await waitFor(() => expect(N.requestPermission).toHaveBeenCalled())
    expect(await screen.findByText('Desktop notifications on while this tab is open')).toBeTruthy()
    expect(globalThis.localStorage.getItem('agent-vault.notify')).toBe('on')
  })

  it('previews a notice from what is waiting: the daemon\'s headline, cleaned and cut, never the claim', async () => {
    const server = fakeServer({ 'GET notify': { webhook: null } })
    const long = `GET api.github.com/${'x'.repeat(200)}`
    renderWith(<Notifications />, {
      server,
      vault: { pending: [{ id: 'r1', kind: 'request', headline: 'POST\u202e api.github.com/issues', claim: 'APPROVE ME' }, { id: 's1', kind: 'session', headline: long }] },
    })
    expect(await screen.findByText('Held request: POST api.github.com/issues')).toBeTruthy()
    const cut = screen.getByText(/^Session requested: GET/)
    expect(cut.textContent.length).toBe(120)
    expect(screen.queryByText(/APPROVE ME/)).toBeNull()
    expect(screen.getAllByRole('link', { name: 'Open in Approvals' })[0].getAttribute('href')).toBe('#approvals/r1')
  })

  it('says so when the settings cannot be read', async () => {
    const server = fakeServer({ 'GET notify': { __status: 500, body: { error: 'nope' } } })
    renderWith(<Notifications />, { server })
    expect(await screen.findByText('Could not read the notification settings.')).toBeTruthy()
  })
})
