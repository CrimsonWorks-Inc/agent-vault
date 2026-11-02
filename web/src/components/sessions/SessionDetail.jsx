import { MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import { XMarkIcon } from '@heroicons/react/16/solid'
import { useApiQuery } from '../../hooks/useApi.js'
import { usePaged } from '../../hooks/usePaged.js'
import { until } from '../../lib/format.js'
import { fetchPages } from '../../lib/paging.js'
import { cleanLine } from '../../lib/text.js'
import { cx } from '../../lib/cx.js'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { KeyValue } from '../ui/KeyValue.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Pagination } from '../ui/Pagination.jsx'
import { SearchInput } from '../ui/SearchInput.jsx'
import { Skeleton } from '../ui/Skeleton.jsx'
import { UntrustedText } from '../ui/UntrustedText.jsx'
import { CopyButton } from './CopyButton.jsx'
import {
  activityLine, barSteps, describedRows, detailMarkdown, grantUsageRows, placeholderText, sessionFacts, spendLines,
} from './sessionLogic.js'

// Bar widths in 5% steps, written out so Tailwind sees each class and the
// bar needs no inline style (CSP, U2).
const WIDTH = ['w-0', 'w-[5%]', 'w-[10%]', 'w-[15%]', 'w-[20%]', 'w-[25%]', 'w-[30%]', 'w-[35%]', 'w-[40%]', 'w-[45%]', 'w-[50%]',
  'w-[55%]', 'w-[60%]', 'w-[65%]', 'w-[70%]', 'w-[75%]', 'w-[80%]', 'w-[85%]', 'w-[90%]', 'w-[95%]', 'w-full']

/**
 * The whole record for the header, the activity and the Markdown copy:
 * every page of grants (paged=1, U3) with `session` and `activity` from
 * beside them.
 */
export async function readSessionDetail(get, sid) {
  const r = await fetchPages(get, 'sessions/detail', { filters: { sid } })
  return { ...r.beside, grants: r.items }
}

/**
 * `session show`, as a card (F19): the session's facts, each grant's
 * effective policy and use, and what the audit log says it did. The grants
 * are paged (U3); the header, the activity and the Markdown copy come from
 * the whole record.
 */
export function SessionDetail({ sid, onClose }) {
  const { data: d, error, loading } = useApiQuery((api) => readSessionDetail(api.get, sid), [sid])
  const grants = usePaged('sessions/detail', { filters: { sid } })

  if (error && !d) {
    return (
      <Card title={`Session ${cleanLine(sid)}`} actions={<Button size="sm" icon={XMarkIcon} onClick={onClose}>Close</Button>}>
        <Notice tone="crit" role="alert" title="Could not read this session.">{error.message}</Notice>
      </Card>
    )
  }
  if (!d) {
    return (
      <Card title={`Session ${cleanLine(sid)}`} aria-busy={loading}>
        <div className="space-y-2" role="status" aria-label="Loading the session"><Skeleton className="w-1/3" /><Skeleton className="w-2/3" /><Skeleton className="w-1/2" /></div>
      </Card>
    )
  }
  const s = d.session || {}
  const a = d.activity || {}
  return (
    <Card
      eyebrow="Session detail"
      title={`Session ${cleanLine(s.id ?? sid)}`}
      padded={false}
      actions={(
        <>
          <CopyButton text={() => detailMarkdown(d)}>Copy as Markdown</CopyButton>
          <Button size="sm" icon={XMarkIcon} onClick={onClose}>Close</Button>
        </>
      )}
    >
      {a.complete === false && (
        <div className="px-5 pt-4">
          <Notice tone="warn">History is incomplete: {cleanLine(a.note || 'the audit log does not cover the whole session')}. Missing records are not zero activity.</Notice>
        </div>
      )}
      <div className="px-5 py-4">
        <KeyValue rows={sessionFacts(s)} />
      </div>

      <div className="border-t border-line">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4">
          <h3 className="text-sm font-semibold text-ink">Grants</h3>
          <SearchInput value={grants.q} onChange={grants.setQ} label="Search grants" placeholder="Search credential or grant" />
        </div>
        <DataTable
          caption={`Grants of session ${s.id ?? sid}`}
          rows={grants.items}
          rowKey={(g, i) => g.grant_id ?? `${g.cred}-${i}`}
          loading={grants.loading}
          empty={grants.q ? { icon: MagnifyingGlassIcon, title: 'Nothing matches' } : { title: 'No grants' }}
          columns={[
            { key: 'cred', header: 'Credential', primary: true, cell: (g) => <GrantTitle g={g} /> },
            { key: 'policy', header: 'Effective policy', cell: (g) => <GrantPolicy g={g} /> },
            { key: 'use', header: 'Use', cell: (g) => <GrantUse g={g} /> },
            { key: 'placeholders', header: 'Placeholders', cell: (g) => <GrantPlaceholders g={g} /> },
          ]}
        />
        {grants.error && <div className="px-5 pb-3"><Notice tone="crit" role="alert">{grants.error.message}</Notice></div>}
        <div className="border-t border-line px-4"><Pagination {...grants.pagination} label="Grant pages" /></div>
      </div>

      <div className="border-t border-line px-5 py-4">
        <h3 className="text-sm font-semibold text-ink">Activity</h3>
        <p className="mt-1 text-sm text-muted">{activityLine(a)}</p>
        <div className="mt-3 grid gap-4 md:grid-cols-2">
          {(a.paths || []).length > 0 && <CountList caption="Requests by path" rows={a.paths.map((p) => [p.count, `${p.method} ${p.path}`])} />}
          {(a.denials || []).length > 0 && <CountList caption="Refusals" rows={a.denials.map((x) => [x.count, `${x.code} ${x.rule || ''}`])} />}
        </div>
        {(a.tripwires || []).length > 0 && (
          <p className="mt-2 text-sm text-crit">tripwires: {a.tripwires.map((t) => `${cleanLine(t.rule_id)} at ${cleanLine(t.at)}`).join(', ')}</p>
        )}
      </div>
    </Card>
  )
}

function CountList({ caption, rows }) {
  return (
    <div>
      <p className="font-mono text-eyebrow uppercase tracking-[0.12em] text-muted">{caption}</p>
      <ul className="mt-1 divide-y divide-line text-sm">
        {rows.map(([n, what], i) => (
          <li key={i} className="flex gap-3 py-1.5">
            <span className="w-10 shrink-0 text-right font-mono tabular-nums text-muted">{n}</span>
            <span className="min-w-0 break-words font-mono text-[0.8125rem] text-ink">{cleanLine(what)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function GrantTitle({ g }) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <span className="font-mono text-sm font-medium text-ink">{cleanLine(g.cred)}</span>
      <Badge tone={g.state === 'active' ? 'ok' : 'neutral'} dot>{cleanLine(g.state)}</Badge>
      {g.expires_at && <span className="text-xs text-muted">grant {until(g.expires_at)}</span>}
    </span>
  )
}

function GrantPolicy({ g }) {
  const { rows, payload } = describedRows(g.effective)
  return (
    <div className="min-w-0 md:min-w-64">
      <KeyValue rows={rows.map(([k, v]) => [k, cleanLine(v)])} className="text-xs" />
      {payload && (
        <div className="mt-2">
          <p className="text-xs text-muted">payload rules</p>
          <UntrustedText text={payload} block source="whoever wrote the session's rules" maxHeight="max-h-48" />
        </div>
      )}
    </div>
  )
}

function GrantUse({ g }) {
  return (
    <div className="min-w-0 space-y-2">
      <KeyValue rows={grantUsageRows(g).map(([k, v]) => [k, cleanLine(v)])} className="text-xs" />
      {spendLines(g.spend).map((line) => (
        <div key={line.text} className="space-y-1">
          <p className="text-xs text-muted">{cleanLine(line.text)}</p>
          <SpendBar used={line.used} reserved={line.reserved} limit={line.limit} />
        </div>
      ))}
    </div>
  )
}

/** Used, then reserved, against the limit (F5). */
export function SpendBar({ used, reserved, limit }) {
  const steps = barSteps(used, reserved, limit)
  if (!steps) return null
  return (
    <div className="relative h-1.5 w-full max-w-56 overflow-hidden rounded-pill bg-sunken" role="img" aria-label={`${used} used, ${reserved} reserved, of ${limit}`}>
      <span className={cx('absolute inset-y-0 left-0 rounded-pill bg-warn/50', WIDTH[steps.reserved])} />
      <span className={cx('absolute inset-y-0 left-0 rounded-pill bg-accent', WIDTH[steps.used])} />
    </div>
  )
}

function GrantPlaceholders({ g }) {
  const list = g.placeholders || []
  if (!list.length) return <span className="text-xs text-muted">none</span>
  return (
    <ul className="space-y-1 text-xs">
      {list.map((p) => (
        <li key={p.id} className="min-w-0">
          <span className="block font-mono text-ink">{cleanLine(p.id)}</span>
          <span className="font-mono text-muted">{cleanLine(placeholderText(p))}</span>
        </li>
      ))}
    </ul>
  )
}
