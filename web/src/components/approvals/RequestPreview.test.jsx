// The held-request preview (F13), ported from test/security/control-ui-page.test.js
// ("a held request preview is escaped, monospace and labelled as the agent's",
// "an ordinary preview shows the body, and a binary one shows none"). Every
// byte of a preview came from the agent: it must reach the page as text,
// never as markup or an attribute, and say who wrote it.
import { describe, expect, it } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { renderWith } from '../../test/harness.jsx'
import { RequestPreview } from './RequestPreview.jsx'

const HOSTILE = '<img src=x onerror=alert(1)>'

function open() {
  fireEvent.click(screen.getByRole('button', { name: /What it sends/ }))
}

describe('RequestPreview', () => {
  it('paints the agent\'s request as text, in monospace, labelled as the agent\'s', () => {
    const { container } = renderWith(<RequestPreview preview={{
      method: 'POST', host: 'api.example.com', path: `/x/${HOSTILE}`,
      query: [['q', HOSTILE]], headers: [[HOSTILE, 'v']], content_type: 'application/json',
      body: { text: `{"title": "${HOSTILE}<script>steal()</script>"}`, bytes: 40, shown_bytes: 40, truncated: false, kind: 'json' },
      placeholders: [{ label: 'demo.token', location: HOSTILE }], untrusted: true,
    }} />)
    expect(screen.getByRole('button', { name: 'What it sends (written by the agent, not verified)' })).toBeTruthy()
    open()
    expect(container.querySelector('img, script')).toBeNull()
    const html = container.innerHTML
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect(container.textContent).toContain(`demo.token @ ${HOSTILE}`)
    expect(container.textContent).toContain('<script>steal()</script>')
    // The body is UntrustedText: marked, and monospace.
    const body = container.querySelector('[data-untrusted]')
    expect(body?.textContent).toContain(HOSTILE)
    expect(container.querySelector('.font-mono')).toBeTruthy()
    for (const el of container.querySelectorAll('*')) {
      for (const a of el.attributes) expect(a.value.includes('onerror')).toBe(false)
    }
  })

  it('an ordinary preview shows the body; a binary one shows none; none at all renders nothing', () => {
    const { container, unmount } = renderWith(<RequestPreview preview={{ method: 'POST', host: 'h', path: '/c', body: { text: '{"comment": "looks good"}', bytes: 25, kind: 'json' } }} />)
    open()
    expect(container.textContent).toContain('looks good')
    unmount()
    const binary = renderWith(<RequestPreview preview={{ body: { text: null, kind: 'binary', bytes: 9 } }} />)
    fireEvent.click(screen.getByRole('button', { name: /What it sends/ }))
    expect(binary.container.textContent).toContain('A binary body, not shown.')
    binary.unmount()
    const none = renderWith(<RequestPreview preview={null} />)
    expect(none.container.querySelector('button')).toBeNull()
  })
})
