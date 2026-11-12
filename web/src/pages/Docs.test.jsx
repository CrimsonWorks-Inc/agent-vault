import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fireEvent, screen, within } from '@testing-library/react'
import { renderWith } from '../test/harness.jsx'
import { CODES } from '../../../legacy/js/src/core/errors.js'
import { REFUSED } from '../components/docs/RefusedTable.jsx'
import { SECTIONS, commandReference } from '../components/docs/sections.jsx'
import { Docs, docsContext } from './Docs.jsx'

const CTX = { cli: 'av', gateway_port: 7999, cred_slugs: ['gh-mine', 'openai'], version: '0.2.0' }

describe('Docs (parity with the old page)', () => {
  it('prints every command with the server\'s cli name, port and first credential', () => {
    renderWith(<Docs rest="start" />, { vault: { context: CTX } })
    expect(screen.getByText('v0.2.0')).toBeTruthy()
    expect(screen.getByText('av setup')).toBeTruthy()
    expect(screen.getByText('av session create --cred gh-mine --methods GET,HEAD --paths "/repos/**" --budget 200')).toBeTruthy()
    expect(screen.queryByText(/^agent-vault setup/)).toBeNull()
  })

  it('falls back to the old page\'s defaults when the daemon said nothing', () => {
    expect(docsContext({})).toEqual({ cli: 'agent-vault', gateway_port: 7411, cred: 'gh-work', version: null })
  })

  it('opens the section named in the link, marks it current, and links the others', () => {
    renderWith(<Docs rest="connect" />, { vault: { context: CTX } })
    const nav = screen.getByRole('navigation', { name: 'Docs sections' })
    expect(within(nav).getByRole('link', { name: 'Connect your agent' }).getAttribute('aria-current')).toBe('page')
    expect(within(nav).getByRole('link', { name: 'Commands' }).getAttribute('href')).toBe('#docs/commands')
    expect(screen.getByText('av listen add lan --address 10.0.0.5:7999 --surfaces gateway,mcp --tls managed')).toBeTruthy()
    for (const agent of ['claude-code', 'cursor', 'gemini', 'codex']) expect(document.body.textContent).toContain(agent)
  })

  it('an unknown section opens How it works', () => {
    renderWith(<Docs rest="nope" />, { vault: { context: CTX } })
    expect(screen.getByRole('heading', { name: 'How it works' })).toBeTruthy()
  })

  it('every section can be opened, and the CLI\'s docs command knows each one', () => {
    // vitest runs from the repo root (npm test) or from web/; jsdom's import.meta.url is not a file URL.
    const file = ['legacy/js/src/cli/index.js', '../legacy/js/src/cli/index.js'].map((p) => resolve(process.cwd(), p)).find(existsSync)
    const cli = readFileSync(file, 'utf8')
    const listed = cli.match(/const sections = \[([^\]]+)\]/)
    const known = [...listed[1].matchAll(/'([a-z]+)'/g)].map((m) => m[1])
    expect(SECTIONS.map((s) => s.id)).toEqual(known)
    for (const s of SECTIONS) {
      const { unmount } = renderWith(<Docs rest={s.id} />, { vault: { context: CTX } })
      expect(screen.getByRole('heading', { level: 2, name: s.title })).toBeTruthy()
      unmount()
    }
  })

  it('every denial a caller can hit is in the refused table, with fixes in the cli\'s name', () => {
    const internal = new Set(['AV_INTERNAL', 'AV_NOT_FOUND', 'AV_MCP_PROTOCOL', 'AV_MCP_SESSION_UNKNOWN'])
    const listed = new Set(REFUSED.map(([code]) => code))
    const missing = Object.keys(CODES).filter((c) => !internal.has(c) && !listed.has(c))
    expect(missing).toEqual([])
    renderWith(<Docs rest="refused" />, { vault: { context: CTX } })
    const table = screen.getByRole('table', { name: 'Refusal codes' })
    expect(within(table).getAllByRole('row')).toHaveLength(REFUSED.length + 1)
    expect(within(table).getByText('av cred release <slug>')).toBeTruthy()
  })

  it('the command reference is the full list, in the cli\'s name, copyable', () => {
    renderWith(<Docs rest="commands" />, { vault: { context: CTX } })
    const ref = commandReference('av')
    expect(ref.split('\n').every((l) => !l.startsWith('agent-vault'))).toBe(true)
    expect(screen.getByText((_, el) => el?.tagName === 'PRE' && el.textContent === ref)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Copy the command' })).toBeTruthy()
  })

  it('a command copies to the clipboard', async () => {
    const written = []
    Object.defineProperty(globalThis.navigator, 'clipboard', { value: { writeText: async (t) => { written.push(t) } }, configurable: true })
    renderWith(<Docs rest="locking" />, { vault: { context: CTX } })
    fireEvent.click(screen.getAllByRole('button', { name: 'Copy the command' })[0])
    expect(await screen.findByText('Copied')).toBeTruthy()
    expect(written).toEqual(['av passphrase set'])
  })

  it('routes every model profile with its environment variables', () => {
    renderWith(<Docs rest="models" />, { vault: { context: CTX } })
    const text = document.body.textContent
    for (const v of ['ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_API_KEY', 'GOOGLE_GEMINI_BASE_URL', 'GEMINI_API_KEY']) {
      expect(text).toContain(v)
    }
  })
})
