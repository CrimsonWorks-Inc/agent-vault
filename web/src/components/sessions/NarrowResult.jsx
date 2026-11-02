import { ArrowRightIcon } from '@heroicons/react/16/solid'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { narrowSummary } from './sessionLogic.js'

/** What a narrow changed, grant by grant, from the route's before and after (F15). */
export function NarrowResult({ title, result, onDismiss }) {
  const r = narrowSummary(result)
  return (
    <Card
      eyebrow="Narrowed"
      title={title}
      description={r.ends ? `session ${cleanLine(r.sessionId)} ${r.ends}` : undefined}
      padded={false}
      footer={<Button size="sm" onClick={onDismiss}>Done</Button>}
    >
      <ul className="divide-y divide-line">
        {r.grants.map((g, i) => (
          <li key={`${g.cred}-${i}`} className="px-5 py-3">
            <p className="font-mono text-sm font-medium text-ink">{cleanLine(g.cred)}</p>
            {g.changes.length ? (
              <ul className="mt-1 space-y-0.5 text-sm text-muted">
                {g.changes.map((c) => (
                  <li key={c.key} className="flex flex-wrap items-center gap-x-1.5">
                    <span className="text-ink">{c.key}:</span>
                    <span className="font-mono text-xs">{cleanLine(c.before)}</span>
                    <ArrowRightIcon aria-label="becomes" className="size-3.5" />
                    <span className="font-mono text-xs text-ink">{cleanLine(c.after)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-sm text-muted">already that narrow; nothing changed</p>
            )}
            {g.expires_at && <p className="mt-1 text-xs text-muted">grant expires {cleanLine(g.expires_at)}</p>}
          </li>
        ))}
      </ul>
    </Card>
  )
}
