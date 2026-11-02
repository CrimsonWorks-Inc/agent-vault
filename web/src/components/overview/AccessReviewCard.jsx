import { useState } from 'react'
import { CheckBadgeIcon } from '@heroicons/react/24/outline'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { EmptyState } from '../ui/EmptyState.jsx'
import { Notice } from '../ui/Notice.jsx'

/** How many findings show before "Show all". Every one is still a click away. */
export const REVIEW_PREVIEW = 6

/**
 * Access review (F19): methods granted and never used in the last 7 days, and
 * credentials that are quarantined or expiring. A session's label is chosen
 * by whoever created it (a session request cannot carry one), so it is shown
 * as cleaned text, as app.html showed it.
 */
export function AccessReviewCard({ report }) {
  const [all, setAll] = useState(false)
  if (!report || typeof report !== 'object') return null
  const unused = (report.sessions || []).filter((s) => (s.unused_methods || []).length)
  const flagged = (report.credentials || []).filter((c) => c.quarantined === true || c.expiry_warning)
  const findings = [
    ...flagged.map((c) => ({ key: `c-${c.slug}`, kind: 'cred', c })),
    ...unused.map((s) => ({ key: `s-${s.id}`, kind: 'session', s })),
  ]
  const shown = all ? findings : findings.slice(0, REVIEW_PREVIEW)
  return (
    <Card
      eyebrow="Last 7 days"
      title="Access review"
      description={findings.length ? `${findings.length} thing${findings.length > 1 ? 's' : ''} to tighten` : undefined}
      padded={false}
    >
      {report.complete === false && (
        <div className="px-5 pt-4">
          <Notice tone="warn">The audit log does not cover the whole period, so this review is incomplete.</Notice>
        </div>
      )}
      {findings.length > 0 && (
        <ul className="divide-y divide-line">
          {shown.map((f) => (f.kind === 'cred' ? (
            <li key={f.key} className="flex flex-wrap items-center justify-between gap-2 px-5 py-2.5">
              <span className="font-mono text-sm text-ink">{f.c.slug}</span>
              <span className="inline-flex flex-wrap gap-1.5">
                {f.c.quarantined === true && <Badge tone="crit">quarantined</Badge>}
                {f.c.expiry_warning === 'expired' ? <Badge tone="crit">expired</Badge> : f.c.expiry_warning ? <Badge tone="warn">expires soon</Badge> : null}
              </span>
            </li>
          ) : (
            <li key={f.key} className="px-5 py-2.5">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <span className="min-w-0 truncate text-sm font-medium text-ink">{cleanLine(f.s.label || f.s.id)}</span>
                <span className="font-mono text-xs text-warn">never used: {f.s.unused_methods.join(', ')}</span>
              </div>
              <p className="text-xs text-muted">granted but never used · narrow it to what it uses</p>
            </li>
          )))}
        </ul>
      )}
      {findings.length > REVIEW_PREVIEW && (
        <div className="border-t border-line px-5 py-2.5">
          <Button size="sm" variant="ghost" onClick={() => setAll((x) => !x)} aria-expanded={all}>
            {all ? 'Show fewer' : `Show all ${findings.length}`}
          </Button>
        </div>
      )}
      {!findings.length && (
        <EmptyState icon={CheckBadgeIcon} title="Nothing to tighten">
          Every granted method was used, and no credential is expiring or quarantined.
        </EmptyState>
      )}
    </Card>
  )
}
