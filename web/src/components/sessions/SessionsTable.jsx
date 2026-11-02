import { MagnifyingGlassIcon, UserGroupIcon } from '@heroicons/react/24/outline'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { approvalMode, sessionExpiry } from './sessionLogic.js'
import { SessionActions } from './SessionActions.jsx'

/**
 * Every session, newest first (U3), with what to notice about each: its
 * state, whether it is remote, how it asks for approval, whether it never
 * expires or is elevated, and the template it came from.
 */
export function SessionsTable({ list, onDetails, onNarrowed, onChanged }) {
  const searching = Boolean(list.q.trim())
  return (
    <DataTable
      caption="Sessions"
      rows={list.items}
      rowKey="id"
      loading={list.loading}
      empty={searching
        ? { icon: MagnifyingGlassIcon, title: 'Nothing matches', body: `No session matches “${list.q.trim()}”.` }
        : { icon: UserGroupIcon, title: 'No sessions yet.', body: 'Create one from New session, or approve one an agent asks for.' }}
      rowClassName={(s) => (s.state === 'active' ? '' : 'text-muted')}
      columns={[
        { key: 'label', header: 'Session', primary: true, cell: (s) => <SessionTitle s={s} /> },
        { key: 'id', header: 'ID', cell: (s) => <span className="font-mono text-[0.8125rem]">{cleanLine(s.id)}</span> },
        {
          key: 'creds', header: 'Grants',
          cell: (s) => (
            <span className="text-sm">
              {s.grants} grant(s)
              {(s.creds || []).length > 0 && (
                <span className="block whitespace-nowrap font-mono text-xs text-muted">{s.creds.map((c) => cleanLine(c.slug ?? '?')).join(', ')}</span>
              )}
            </span>
          ),
        },
        { key: 'expires', header: 'Expires', cell: (s) => <span className="whitespace-nowrap text-sm">{sessionExpiry(s)}</span> },
        {
          key: 'actions', header: 'Actions', align: 'right', className: 'w-px',
          cell: (s) => <SessionActions s={s} onDetails={onDetails} onNarrowed={onNarrowed} onChanged={onChanged} />,
        },
      ]}
    />
  )
}

/** The label (the owner's or the daemon's words, cleaned) and its badges. */
export function SessionTitle({ s }) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <span className="font-medium text-ink">{cleanLine(s.label ?? '') || <span className="text-muted">no label</span>}</span>
      <SessionBadges s={s} />
    </span>
  )
}

export function SessionBadges({ s }) {
  const approval = approvalMode(s)
  const elevated = s.elevated || []
  return (
    <>
      <Badge tone={s.state === 'active' ? 'ok' : 'neutral'} dot>{cleanLine(s.state)}</Badge>
      {s.remote && <Badge tone="warn">remote</Badge>}
      {approval && <Badge tone={approval.elevated ? 'warn' : 'neutral'}>approval: {approval.mode}</Badge>}
      {s.infinite && <Badge tone="warn">infinite</Badge>}
      {elevated.length > 0 && <Badge tone="warn" title={elevated.join(', ')}>elevated</Badge>}
      {s.template && <Badge>template {cleanLine(s.template)}</Badge>}
    </>
  )
}
