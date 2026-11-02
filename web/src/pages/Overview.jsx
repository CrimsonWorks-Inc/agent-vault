// The Overview, at parity with the old page's (contract U5), and the reference
// page for wave 2: data through useApiQuery + lib/api.js, slow reads through
// the shared cache, gated changes through GatedButton / usePresence, agent
// text through UntrustedText, and composed pieces under components/overview.
//
// Every card stands alone: a daemon without a route, or a locked vault,
// leaves that card out rather than the page blank (the old page's `quiet`).

import { useCallback } from 'react'
import { useApiQuery, useSlowCache } from '../hooks/useApi.js'
import { usePresence } from '../hooks/usePresence.js'
import { useVault } from '../hooks/useVault.js'
import { fetchAll, fetchPages, pageQuery, readEnvelope } from '../lib/paging.js'
import { prfSupported } from '../lib/presence.js'
import { ago, expiresIn, plural, soonestExpiry } from '../lib/format.js'
import { formatHash } from '../lib/router.js'
import { Badge } from '../components/ui/Badge.jsx'
import { Button } from '../components/ui/Button.jsx'
import { Notice } from '../components/ui/Notice.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Skeleton } from '../components/ui/Skeleton.jsx'
import { AccessReviewCard } from '../components/overview/AccessReviewCard.jsx'
import { AtAGlance } from '../components/overview/AtAGlance.jsx'
import { ContainmentCard } from '../components/overview/ContainmentCard.jsx'
import { NotificationsCard } from '../components/overview/NotificationsCard.jsx'
import { ConfirmationCard, LockBanner, UnlockingCard } from '../components/overview/SecurityCards.jsx'

export const OVERVIEW_POLL_MS = 5000

/**
 * Tripwires, paged (U3): the rules are the items, and `enabled`,
 * `rules_saved` and `defaults` sit beside them.
 */
export async function readTripwires(get) {
  const r = await fetchPages(get, 'tripwires')
  return { ...r.beside, rules: r.items }
}

/**
 * The access report, paged (U3): one list per request (`list=sessions`, then
 * `list=credentials`), with `complete` beside each page. Put back together in
 * the shape the card reads.
 */
export async function readAccessReport(get, since = '7d') {
  const s = await fetchPages(get, 'report/access', { filters: { since, list: 'sessions' } })
  const c = await fetchPages(get, 'report/access', { filters: { since, list: 'credentials' } })
  const incomplete = s.beside.complete === false || c.beside.complete === false
  return {
    ...s.beside,
    sessions: s.items,
    credentials: c.items,
    complete: incomplete ? false : (s.beside.complete ?? c.beside.complete),
  }
}

/** The last few tripwire firings: one page of audit, filtered in the daemon. */
export function readFired(get, limit = 5) {
  return get('audit', pageQuery({ limit, filters: { kind: 'tripwire.fired' } })).then((data) => readEnvelope(data).items)
}

/** Everything the overview shows, in one load (the old page's views.overview). */
export async function loadOverview(api, slow, presence) {
  const [status, creds, sessions] = await Promise.all([
    api.get('status'), fetchAll(api.get, 'credentials'), fetchAll(api.get, 'sessions'),
  ])
  const quiet = (p) => p.catch(() => null)
  const [report, tripwires, fired, notify, unlockState] = await Promise.all([
    status.locked ? null : quiet(slow.get('report', () => readAccessReport(api.get))),
    quiet(slow.get('tripwires', () => readTripwires(api.get))),
    status.locked ? null : quiet(slow.get('fired', () => readFired(api.get))),
    quiet(slow.get('notify', () => api.get('notify'))),
    quiet(api.get('unlock/state')),
    presence.refresh(),
  ])
  return { status, creds, sessions, report, tripwires, fired, notify, unlockState, readAt: new Date().toISOString() }
}

export function Overview() {
  const presence = usePresence()
  const vault = useVault()
  const slow = useSlowCache()
  const { data, error, loading, reload } = useApiQuery((api) => loadOverview(api, slow, presence), [], { poll: OVERVIEW_POLL_MS })
  const changed = useCallback(() => { reload(); vault.refresh() }, [reload, vault])
  const webauthn = prfSupported()

  // A first load that failed says so, with a way to ask again: never a
  // skeleton that waits forever. (The daemon-down, UI-server-down and
  // no-session screens replace the whole page before this is drawn.)
  if (!data) return error && !loading ? <OverviewError error={error} onRetry={reload} /> : <OverviewSkeleton />
  const { status, creds, sessions, report, tripwires, fired, notify, unlockState, readAt } = data
  const live = sessions.filter((s) => s.state === 'active')
  const pending = vault.pending
  const expiring = creds.filter((c) => c.expiry_warning === 'expired' || c.expiry_warning === 'soon')

  return (
    <>
      <PageHeader
        eyebrow="agent-vault"
        title="Overview"
        status={status.locked ? <Badge tone="crit" dot>locked</Badge> : <Badge tone="ok" dot>unlocked</Badge>}
        description={<>Daemon <span className="font-mono text-ink">{status.daemon_version}</span> on gateway port <span className="font-mono text-ink">{status.gateway_port}</span>.</>}
      />

      <div className="space-y-4">
        {error && <StaleNotice error={error} readAt={readAt} onRetry={reload} />}
        {status.locked && <LockBanner unlockState={unlockState} webauthn={webauthn} onChanged={changed} />}
        {presence.known && !presence.enrolled && <ConfirmationCard enrolled={false} onChanged={changed} />}

        {pending.length > 0 && (
          <Notice
            tone="warn"
            title={`${pending.length} ${pending.some((a) => a.kind === 'session') ? 'decision' : 'request'}${pending.length > 1 ? 's' : ''} waiting for you.`}
          >
            <a href={formatHash('approvals')} className="font-medium text-accent underline-offset-2 hover:underline">Open Approvals</a> to decide.
          </Notice>
        )}

        <AtAGlance
          credentials={creds.length}
          activeSessions={live.length}
          placeholders={status.placeholders_live}
          auditRecords={status.audit_records}
        />

        {expiring.length > 0 && (
          <Notice tone="warn" title={`${plural(expiring.length, 'credential')} expiring.`}>
            {expiring.map((c, i) => (
              <span key={c.slug}>
                {i > 0 && ' · '}
                <span className="font-mono text-ink">{c.slug}</span> {c.expiry_warning === 'expired' ? 'expired' : expiresIn(soonestExpiry(c))}
              </span>
            ))}
            . Rotate them from <a href={formatHash('credentials')} className="font-medium text-accent underline-offset-2 hover:underline">Credentials</a>.
          </Notice>
        )}

        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <div className="space-y-4">
            <ContainmentCard tripwires={tripwires} fired={fired} onChanged={changed} />
            <AccessReviewCard report={report} />
          </div>
          <div className="space-y-4">
            {presence.enrolled && <ConfirmationCard enrolled onChanged={changed} />}
            {!status.locked && <UnlockingCard unlockState={unlockState} webauthn={webauthn} onChanged={changed} />}
            <NotificationsCard notify={notify} cli={vault.context.cli} />
          </div>
        </div>
      </div>
    </>
  )
}

/** The first read failed: what was said, and Try again. */
function OverviewError({ error, onRetry }) {
  return (
    <>
      <PageHeader eyebrow="agent-vault" title="Overview" />
      <Notice
        tone="crit"
        role="alert"
        title="Could not read the overview."
        actions={<Button size="sm" onClick={onRetry}>Try again</Button>}
      >
        {error.message}
      </Notice>
    </>
  )
}

/**
 * A refresh failed: the last good read stays, marked as stale, so a lock,
 * a panic or a waiting decision is never shown as current when it is not.
 */
function StaleNotice({ error, readAt, onRetry }) {
  return (
    <Notice
      tone="warn"
      role="alert"
      title={`This overview is stale: it was last read ${ago(readAt)}.`}
      actions={<Button size="sm" onClick={onRetry}>Try again</Button>}
    >
      The last refresh failed: {error.message}
    </Notice>
  )
}

function OverviewSkeleton() {
  return (
    <div role="status" aria-label="Loading the overview">
      <PageHeader eyebrow="agent-vault" title="Overview" />
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-px overflow-hidden rounded-card border border-line bg-line lg:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="space-y-3 bg-surface p-5"><Skeleton className="w-20" /><Skeleton className="h-6 w-12" /></div>
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {[0, 1].map((i) => (
            <div key={i} className="space-y-3 rounded-card border border-line bg-surface p-5"><Skeleton className="w-1/3" /><Skeleton className="w-2/3" /><Skeleton className="w-1/2" /></div>
          ))}
        </div>
      </div>
    </div>
  )
}
