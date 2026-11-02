import { describe, expect, it } from 'vitest'
import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { fakeAuthenticator, fakeServer, renderWith } from '../../test/harness.jsx'
import { operationFor } from '../../lib/presence.js'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useEffect } from 'react'
import { GatedButton } from './GatedButton.jsx'

const CHALLENGE = { challengeId: 'ch1', challenge: 'AAEC', allowCredentials: [{ id: 'Y3JlZDE' }], rpId: 'localhost' }

function Revoke({ sid, onDone, review = false }) {
  const api = useApi()
  const presence = usePresence()
  useEffect(() => { presence.refresh() }, []) // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <GatedButton
      review={review}
      operation={() => operationFor('session.revoke', { sid })}
      label={`revoke session ${sid}`}
      send={(proof) => api.del('sessions', { sid }, { presence: proof })}
      onDone={onDone}
      variant="danger"
    >
      Revoke
    </GatedButton>
  )
}

function server(enrolled = true) {
  return fakeServer({
    'GET presence/state': { enrolled, rpId: 'localhost' },
    'POST presence/challenge': CHALLENGE,
    'DELETE sessions': { ok: true },
  })
}

describe('GatedButton (U7)', () => {
  it('names the operation on the page before the platform dialog opens', async () => {
    let shownAtDialog = null
    const authenticator = fakeAuthenticator({
      onGet: () => { shownAtDialog = document.querySelector('[data-presence-status]')?.textContent ?? null },
    })
    const s = server()
    let done = false
    renderWith(<Revoke sid="s_123" onDone={() => { done = true }} />, { server: s, authenticator })
    await waitFor(() => expect(s.calls.some((c) => c.path === 'presence/state')).toBe(true))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Revoke/ })) })
    await waitFor(() => expect(done).toBe(true))
    expect(shownAtDialog).toContain('Touch ID to revoke session s_123')
  })

  it('signs exactly the operation, then sends the proof with the request', async () => {
    const s = server()
    const authenticator = fakeAuthenticator()
    let done = false
    renderWith(<Revoke sid="s_9" onDone={() => { done = true }} />, { server: s, authenticator })
    await waitFor(() => expect(s.calls.some((c) => c.path === 'presence/state')).toBe(true))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Revoke/ })) })
    await waitFor(() => expect(done).toBe(true))
    const challenge = s.calls.find((c) => c.path === 'presence/challenge')
    expect(challenge.body).toEqual({ operation: { op: 'session.revoke', sid: 's_9' } })
    const del = s.calls.find((c) => c.method === 'DELETE')
    expect(del.query).toEqual({ sid: 's_9' })
    expect(del.body.presence).toMatchObject({ challengeId: 'ch1', credentialId: 'AQID' })
    expect(authenticator.asked[0].publicKey.userVerification).toBe('required')
    // The status line is gone once the signature is in.
    expect(document.querySelector('[data-presence-status]')).toBeNull()
  })

  it('does nothing, and says why, without an enrolled authenticator', async () => {
    const s = server(false)
    const authenticator = fakeAuthenticator()
    renderWith(<Revoke sid="s_1" />, { server: s, authenticator })
    await waitFor(() => expect(s.calls.some((c) => c.path === 'presence/state')).toBe(true))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Revoke/ })) })
    await screen.findByText('No authenticator enrolled. Set one up from the Overview tab first.')
    expect(authenticator.asked).toHaveLength(0)
    expect(s.calls.some((c) => c.method === 'DELETE')).toBe(false)
  })

  it('with review, shows the exact operation and signs only on "Sign it"', async () => {
    const s = server()
    const authenticator = fakeAuthenticator()
    renderWith(<Revoke sid="s_7" review />, { server: s, authenticator })
    await waitFor(() => expect(s.calls.some((c) => c.path === 'presence/state')).toBe(true))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Revoke/ })) })
    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('"sid": "s_7"')
    expect(authenticator.asked).toHaveLength(0)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Sign it/ })) })
    await waitFor(() => expect(authenticator.asked).toHaveLength(1))
  })
})
