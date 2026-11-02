// Rendered checks ported from the legacy tests that read the old page's
// source. Where a protection is about what the browser builds, it is held
// here against the real component, not against text.
//
// test/security/integrate3-seams.test.js F13 carries a held request's
// preview from the gateway, through src/pending.js and the UI server, and
// asserts the page is handed the agent's markup as data. This is the other
// half: the page paints that data as text.

import { describe, expect, it } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { renderWith } from '../test/harness.jsx'
import { RequestPreview } from '../components/approvals/RequestPreview.jsx'

const HOSTILE = '<img src=x onerror=alert(1)><script>steal()</script>'

describe('ported from the old page source tests', () => {
  it("F13: a held request's preview is painted as text, labelled as the agent's", () => {
    const { container } = renderWith(
      <RequestPreview preview={{
        method: 'POST', host: 'api.example.com', path: `/x/${HOSTILE}`,
        query: [['q', HOSTILE]], headers: [[HOSTILE, 'v']], content_type: 'application/json',
        body: { text: JSON.stringify({ title: HOSTILE }), bytes: 80, shown_bytes: 80, truncated: false, kind: 'json' },
        placeholders: [{ label: 'demo.token', location: HOSTILE }],
      }}
      />,
    )
    const open = screen.getByRole('button', { name: /What it sends \(written by the agent, not verified\)/ })
    fireEvent.click(open)
    const shown = container.querySelector('[data-untrusted] pre')
    expect(shown?.textContent).toBe(JSON.stringify({ title: HOSTILE }))
    expect(container.querySelector('[data-untrusted] figcaption')?.textContent).toMatch(/Written by the agent, not verified/)
    // The markup was text everywhere it appears: body, path, query, header, chip.
    expect(container.querySelector('img, script')).toBeNull()
    expect(container.textContent.split(HOSTILE).length - 1).toBeGreaterThanOrEqual(4)
    expect(container.innerHTML).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })
})
