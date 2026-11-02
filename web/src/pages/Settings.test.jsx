import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { fakeServer, renderWith } from '../test/harness.jsx'
import { Settings } from './Settings.jsx'

const CHALLENGE = { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' }

beforeEach(() => { globalThis.PublicKeyCredential = function PublicKeyCredential() {} })
afterEach(() => { delete globalThis.PublicKeyCredential })

function routes(over = {}) {
  return {
    'GET presence/state': { enrolled: true, rpId: 'localhost' },
    'GET unlock/state': { locked: false, has_passphrase: true, has_touchid: true },
    'GET lockstate': { locked: false, has_passphrase: true, has_touchid: true },
    'POST presence/challenge': CHALLENGE,
    'POST touchid/remove': { ok: true },
    'POST lock': { locked: true },
    ...over,
  }
}

describe('Settings', () => {
  it('enrolled: the authenticator can be replaced, Touch ID unlock is on, the vault can be locked', async () => {
    const server = fakeServer(routes())
    renderWith(<Settings />, { server })
    expect(screen.getByRole('status', { name: 'Loading settings' })).toBeTruthy()
    expect(await screen.findByRole('button', { name: /Replace authenticator/ })).toBeTruthy()
    expect(screen.getByText('confirmation on')).toBeTruthy()
    expect(screen.getByText(/Unlock with a fingerprint; your passphrase still works/)).toBeTruthy()
    expect(screen.getByRole('button', { name: /Lock vault/ })).toBeTruthy()
    expect(screen.getByText('No credential value is ever sent to this page, and every change needs a fingerprint.')).toBeTruthy()
  })

  it('not enrolled: offers to set up change confirmation', async () => {
    const server = fakeServer(routes({ 'GET presence/state': { enrolled: false } }))
    renderWith(<Settings />, { server })
    expect(await screen.findByRole('button', { name: /Set up change confirmation/ })).toBeTruthy()
    expect(screen.getByText('confirmation not set up')).toBeTruthy()
  })

  it('no passphrase: Touch ID unlock says what it needs first', async () => {
    const server = fakeServer(routes({ 'GET unlock/state': { locked: false, has_passphrase: false, has_touchid: false } }))
    renderWith(<Settings />, { server })
    expect(await screen.findByText('needs a passphrase')).toBeTruthy()
  })

  it('turning Touch ID unlock off is signed over exactly { op: touchid.remove }', async () => {
    const server = fakeServer(routes())
    renderWith(<Settings />, { server })
    fireEvent.click(await screen.findByRole('button', { name: /Turn off/ }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'touchid/remove')).toBe(true))
    expect(server.calls.find((c) => c.path === 'presence/challenge').body.operation).toEqual({ op: 'touchid.remove' })
    expect(Object.keys(server.calls.find((c) => c.path === 'touchid/remove').body)).toEqual(['presence'])
  })

  it('locking is confirmed in the page, then signed over exactly { op: vault.lock }', async () => {
    const server = fakeServer(routes())
    renderWith(<Settings />, { server })
    fireEvent.click(await screen.findByRole('button', { name: /Lock vault/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Lock the vault?')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Lock with Touch ID' }))
    await waitFor(() => expect(server.calls.some((c) => c.path === 'lock')).toBe(true))
    expect(server.calls.find((c) => c.path === 'presence/challenge').body.operation).toEqual({ op: 'vault.lock' })
    expect(await screen.findByText('Vault locked')).toBeTruthy()
  })

  it('locked: the lock banner offers Touch ID and the passphrase', async () => {
    const server = fakeServer(routes({ 'GET unlock/state': { locked: true, has_passphrase: true, has_touchid: true } }))
    renderWith(<Settings />, { server, vault: { locked: true } })
    expect(await screen.findByText('The vault is locked.')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Unlock with Touch ID/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Use passphrase/ })).toBeTruthy()
  })

  it('a browser without WebAuthn is told the command line can make every change', async () => {
    delete globalThis.PublicKeyCredential
    const server = fakeServer(routes())
    renderWith(<Settings />, { server })
    expect(await screen.findByText('This browser has no WebAuthn.')).toBeTruthy()
  })
})
