import { CheckBadgeIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import { useApiQuery, useSlowCache } from '../../hooks/useApi.js'
import { usePaged } from '../../hooks/usePaged.js'
import { ago } from '../../lib/format.js'
import { readAccessReport } from '../../pages/Overview.jsx'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { Card } from '../ui/Card.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Pagination } from '../ui/Pagination.jsx'
import { SearchInput } from '../ui/SearchInput.jsx'
import { ListError } from '../credentials/ListError.jsx'

export const REVIEW_SINCE = '7d'

/**
 * The access review (F19), in full: every session the last 7 days touched,
 * with the methods it was granted and never used, and every credential with
 * its use and what to notice. Each list is paged by the server
 * (report/access?list=sessions|credentials, U3). Whether the audit log covers
 * the whole period comes from the report itself, read through the same
 * 30-second cache the Overview's card uses.
 */
export function AccessReview() {
  const slow = useSlowCache()
  // The Overview's own reader and cache key, so the two never disagree.
  const header = useApiQuery((api) => slow.get('report', () => readAccessReport(api.get, REVIEW_SINCE)), [])
  const sessions = usePaged('report/access', { filters: { since: REVIEW_SINCE, list: 'sessions' }, storageKey: 'agent-vault.page-size.report/access:sessions' })
  const creds = usePaged('report/access', { filters: { since: REVIEW_SINCE, list: 'credentials' }, storageKey: 'agent-vault.page-size.report/access:credentials' })
  const report = header.data

  const unused = Array.isArray(report?.sessions) ? report.sessions.filter((s) => (s.unused_methods || []).length).length : null
  const flagged = Array.isArray(report?.credentials) ? report.credentials.filter((c) => c.quarantined === true || c.expiry_warning).length : null

  return (
    <div className="space-y-4">
      {report?.complete === false && (
        <Notice tone="warn">The audit log does not cover the whole period, so this review is incomplete.</Notice>
      )}
      {unused === 0 && flagged === 0 && (
        <Notice tone="ok" title="Nothing to tighten">Every granted method was used, and no credential is expiring or quarantined.</Notice>
      )}
      {header.error && !report && <Notice tone="warn">The review could not be read: {header.error.message}</Notice>}

      <Card
        eyebrow="Last 7 days"
        title="Sessions"
        description={unused ? `${unused} with methods granted and never used` : undefined}
        padded={false}
        actions={<SearchInput value={sessions.q} onChange={sessions.setQ} label="Search reviewed sessions" placeholder="Search label, id or credential" />}
      >
        {sessions.error ? <ListError error={sessions.error} onRetry={sessions.reload} what="the review" /> : (
          <DataTable
            caption="Sessions under review"
            rows={sessions.items}
            rowKey="id"
            loading={sessions.loading}
            empty={sessions.q ? { icon: MagnifyingGlassIcon, title: 'Nothing matches' } : { icon: CheckBadgeIcon, title: 'No sessions in the last 7 days' }}
            columns={[
              {
                key: 'label', header: 'Session', primary: true,
                cell: (s) => (
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="font-medium text-ink">{cleanLine(s.label || s.id)}</span>
                    <Badge tone={s.state === 'active' ? 'ok' : 'neutral'} dot>{cleanLine(s.state)}</Badge>
                    {(s.elevated || []).length > 0 && <Badge tone="warn" title={s.elevated.join(', ')}>elevated</Badge>}
                  </span>
                ),
              },
              { key: 'creds', header: 'Credentials', cell: (s) => <span className="font-mono text-xs">{cleanLine((s.creds || []).join(', ')) || '—'}</span> },
              { key: 'requests', header: 'Requests', align: 'right', cell: (s) => <span className="tabular-nums">{s.requests ?? 0} <span className="text-muted">/ {s.denials ?? 0} refused</span></span> },
              { key: 'last', header: 'Last seen', cell: (s) => <span className="whitespace-nowrap text-sm">{s.last_seen_at ? ago(s.last_seen_at) : 'never'}</span> },
              {
                key: 'unused', header: 'Review',
                cell: (s) => ((s.unused_methods || []).length ? (
                  <span className="text-sm">
                    <span className="text-warn">granted but never used: <span className="font-mono">{s.unused_methods.join(', ')}</span></span>
                    <span className="block text-xs text-muted">narrow it to what it uses</span>
                  </span>
                ) : <span className="text-sm text-muted">every granted method was used</span>),
              },
            ]}
          />
        )}
        <div className="border-t border-line px-4"><Pagination {...sessions.pagination} label="Reviewed session pages" /></div>
      </Card>

      <Card
        eyebrow="Last 7 days"
        title="Credentials"
        description={flagged ? `${flagged} quarantined or expiring` : undefined}
        padded={false}
        actions={<SearchInput value={creds.q} onChange={creds.setQ} label="Search reviewed credentials" placeholder="Search name" />}
      >
        {creds.error ? <ListError error={creds.error} onRetry={creds.reload} what="the review" /> : (
          <DataTable
            caption="Credentials under review"
            rows={creds.items}
            rowKey="slug"
            loading={creds.loading}
            empty={creds.q ? { icon: MagnifyingGlassIcon, title: 'Nothing matches' } : { title: 'No credentials' }}
            columns={[
              {
                key: 'slug', header: 'Credential', primary: true,
                cell: (c) => (
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="font-mono text-sm font-medium text-ink">{cleanLine(c.slug)}</span>
                    {c.quarantined === true && <Badge tone="crit">quarantined</Badge>}
                    {c.expiry_warning === 'expired' ? <Badge tone="crit">expired</Badge> : c.expiry_warning ? <Badge tone="warn">expires soon</Badge> : null}
                  </span>
                ),
              },
              { key: 'sessions', header: 'Sessions', align: 'right', cell: (c) => <span className="tabular-nums">{c.sessions_active ?? 0} active <span className="text-muted">of {c.sessions_total ?? 0}</span></span> },
              { key: 'requests', header: 'Requests', align: 'right', cell: (c) => <span className="tabular-nums">{c.requests ?? 0} <span className="text-muted">/ {c.denials ?? 0} refused</span></span> },
              { key: 'last', header: 'Last used', cell: (c) => <span className="whitespace-nowrap text-sm">{c.last_used_at ? ago(c.last_used_at) : 'not in this period'}</span> },
            ]}
          />
        )}
        <div className="border-t border-line px-4"><Pagination {...creds.pagination} label="Reviewed credential pages" /></div>
      </Card>
    </div>
  )
}
