import { BellAlertIcon } from '@heroicons/react/24/outline'
import { notificationText } from '../../lib/notify.js'
import { formatHash } from '../../lib/router.js'
import { Card } from '../ui/Card.jsx'
import { EmptyState } from '../ui/EmptyState.jsx'

/**
 * What a desktop notice says, shown for what is waiting now. The words are
 * the daemon's headline, controls out and cut to 120 characters, exactly as
 * the CLI's `watch` writes them (lib/notify.js): never the agent's reason,
 * and the notice only ever opens Approvals.
 */
export function NoticePreview({ pending = [], max = 3 }) {
  const shown = pending.slice(0, max)
  return (
    <Card eyebrow="Preview" title="What a notice says" description="The daemon's summary of what it received, never the reason the agent gave. Clicking one only opens Approvals." padded={false}>
      {shown.length === 0 ? (
        <EmptyState icon={BellAlertIcon} title="Nothing is waiting right now">
          When a held request or a session request arrives, its notice reads like this: <span className="font-mono text-ink">Held request: POST api.github.com/repos/acme/app/issues</span>
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {shown.map((item) => (
            <li key={item.id} className="flex items-start gap-3 px-5 py-3">
              <BellAlertIcon aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-accent" />
              <div className="min-w-0">
                <p className="text-sm font-medium text-ink">agent-vault</p>
                <p className="break-words text-sm text-muted">{notificationText(item)}</p>
                <a href={formatHash('approvals', item.id)} className="mt-1 inline-block text-sm font-medium text-accent underline-offset-2 hover:underline">
                  Open in Approvals
                </a>
              </div>
            </li>
          ))}
          {pending.length > max && <li className="px-5 py-3 text-sm text-muted">and {pending.length - max} more waiting</li>}
        </ul>
      )}
    </Card>
  )
}
