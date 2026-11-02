// Docs, at parity with the old page's (contract U5): eight sections, each with
// commands written against this install. The CLI name, port and credential
// names come from GET docs/context, which App.jsx reads once into
// useVault().context, so `sudo agent-vault`-style installs and renamed
// binaries print their own commands.

import { useEffect, useRef } from 'react'
import { useVault } from '../hooks/useVault.js'
import { formatHash } from '../lib/router.js'
import { cx } from '../lib/cx.js'
import { Badge } from '../components/ui/Badge.jsx'
import { Card } from '../components/ui/Card.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { SECTIONS } from '../components/docs/sections.jsx'

/** What the sections print, with the old page's defaults for a daemon that said nothing. */
export function docsContext(ctx = {}) {
  return {
    cli: ctx.cli || 'agent-vault',
    gateway_port: ctx.gateway_port || 7411,
    // A credential the reader actually has, so the examples are theirs.
    cred: (Array.isArray(ctx.cred_slugs) && ctx.cred_slugs[0]) || 'gh-work',
    version: ctx.version || null,
  }
}

export function Docs({ rest = '' }) {
  const { context } = useVault()
  const c = docsContext(context)
  const section = SECTIONS.find((s) => s.id === rest) || SECTIONS[0]
  const top = useRef(null)
  const first = useRef(true)

  // A new section starts at its top, not wherever the last one was scrolled to.
  useEffect(() => {
    if (first.current) { first.current = false; return }
    top.current?.scrollIntoView?.({ block: 'start' })
  }, [section.id])

  const Body = section.Body
  return (
    <>
      <div ref={top} />
      <PageHeader
        eyebrow="agent-vault"
        title="Docs"
        status={c.version ? <Badge mono>v{c.version}</Badge> : null}
        description="Written against this install, so the commands below are yours to paste."
      />
      <nav aria-label="Docs sections" className="mb-6 flex flex-wrap gap-2">
        {SECTIONS.map((s) => {
          const current = s.id === section.id
          return (
            <a
              key={s.id}
              href={formatHash('docs', s.id)}
              aria-current={current ? 'page' : undefined}
              className={cx(
                'rounded-pill border px-3 py-1.5 text-sm transition-colors focus:outline-none focus-visible:outline-2 focus-visible:outline-focus',
                current ? 'border-accent bg-accent font-medium text-on-accent' : 'border-line bg-surface text-muted hover:border-accent hover:text-accent',
              )}
            >
              {s.title}
            </a>
          )
        })}
      </nav>
      <Card as="article" aria-labelledby="docs-section-title" className="min-w-0">
        <h2 id="docs-section-title" className="mb-4 text-xl font-semibold tracking-tight text-ink">{section.title}</h2>
        <Body c={c} />
      </Card>
    </>
  )
}
