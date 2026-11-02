// Notifications, at parity with the old page's card (contract U5): desktop
// notices in this tab, and the webhook, which is read-only here because its
// URL is a credential in its own right and is set from the command line.
// The notices themselves are raised by App.jsx, whichever page is open.

import { useApiQuery, useSlowCache } from '../hooks/useApi.js'
import { useVault } from '../hooks/useVault.js'
import { Button } from '../components/ui/Button.jsx'
import { Card } from '../components/ui/Card.jsx'
import { Notice } from '../components/ui/Notice.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Skeleton } from '../components/ui/Skeleton.jsx'
import { NotificationsCard } from '../components/overview/NotificationsCard.jsx'
import { NoticePreview } from '../components/notifications/NoticePreview.jsx'
import { Cmd } from '../components/docs/Prose.jsx'

export function Notifications() {
  const vault = useVault()
  const slow = useSlowCache()
  const cli = vault.context.cli
  const q = useApiQuery((api) => slow.get('notify', () => api.get('notify')), [])

  return (
    <>
      <PageHeader
        eyebrow="agent-vault"
        title="Notifications"
        description="Hear about it when something starts waiting for you. A notice is a signal, never an approval: deciding still needs your fingerprint."
      />
      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <div className="min-w-0 space-y-4">
          {q.error && !q.data && (
            <Notice tone="crit" title="Could not read the notification settings." actions={<Button size="sm" onClick={q.reload}>Try again</Button>}>
              {q.error.message}
            </Notice>
          )}
          {q.data === undefined && q.loading
            ? (
              <div role="status" aria-label="Loading the notification settings" className="space-y-3 rounded-card border border-line bg-surface p-5">
                <Skeleton className="w-1/3" /><Skeleton className="w-2/3" /><Skeleton className="w-1/2" />
              </div>
            )
            : <NotificationsCard notify={q.data ?? null} cli={cli} />}
          <NoticePreview pending={vault.pending} />
        </div>
        <Card eyebrow="Command line" title="From a terminal" className="min-w-0">
          <p className="mb-3 text-sm text-muted">
            <span className="font-mono text-ink">watch</span> prints each waiting item the moment it arrives and shows a desktop
            notification, with or without this page open. A webhook sends the same signal elsewhere: HTTPS only, counts and ids
            by default, and its URL is kept sealed like a credential.
          </p>
          <Cmd code={`${cli} watch`} caption="Print and notify as items arrive." />
          <Cmd code={`${cli} notify set --detail minimal`} caption="Set the webhook. Its URL is read from the terminal." />
          <Cmd code={`${cli} notify show\n${cli} notify test\n${cli} notify off`} caption="See it, send a test, or remove it." />
        </Card>
      </div>
    </>
  )
}
