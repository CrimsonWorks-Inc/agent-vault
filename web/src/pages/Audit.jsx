// Audit, at parity with the old page's (contract U5), and paged through the whole
// log rather than its last 60 records (U3): newest first, filtered by kind in
// the daemon, searchable over the fields the server scrubbed for the page.
//
// The log is encrypted with a key derived from the vault key, so while the
// vault is locked there is nothing to show, and that is the answer, not an
// error.

import { useEffect, useState } from 'react'
import { DocumentMagnifyingGlassIcon, LockClosedIcon } from '@heroicons/react/24/outline'
import { usePaged } from '../hooks/usePaged.js'
import { useVault } from '../hooks/useVault.js'
import { formatHash } from '../lib/router.js'
import { cleanLine } from '../lib/text.js'
import { Badge } from '../components/ui/Badge.jsx'
import { Button } from '../components/ui/Button.jsx'
import { Card } from '../components/ui/Card.jsx'
import { DataTable } from '../components/ui/DataTable.jsx'
import { Notice } from '../components/ui/Notice.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'
import { Select } from '../components/ui/Select.jsx'
import { WitnessCard } from '../components/audit/WitnessCard.jsx'
import { KIND_FILTERS, auditNote, auditTime } from '../components/audit/kinds.js'

const DESCRIPTION = 'Append-only, hash-chained, and anchored at its end. Paths are recorded and scrubbed; no credential value, body, query string or full placeholder ever is.'

export function Audit() {
  const vault = useVault()
  const locked = vault.locked === true
  return (
    <>
      <PageHeader
        eyebrow="agent-vault"
        title="Audit"
        status={locked ? <Badge tone="crit" dot>locked</Badge> : null}
        description={locked ? 'The log is encrypted with the vault key, so it cannot be read while the vault is locked.' : DESCRIPTION}
      />
      {locked ? <LockedAudit /> : <AuditLog onLockedMaybe={vault.refresh} />}
    </>
  )
}

/** the old page's locked answer: nothing to read until the vault is unlocked. */
export function LockedAudit() {
  return (
    <Notice
      tone="crit"
      title="Unlock to read the audit log."
      actions={<a href={formatHash('overview')} className="inline-flex h-9 items-center gap-1.5 rounded-control bg-accent px-3.5 text-sm font-medium text-on-accent hover:bg-accent-hover focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"><LockClosedIcon aria-hidden="true" className="size-4" />Go to Overview</a>}
    >
      The log is encrypted with a key derived from the vault key, so there is nothing to show while it is locked.
    </Notice>
  )
}

function AuditLog({ onLockedMaybe }) {
  const [kind, setKind] = useState('')
  const list = usePaged('audit', { filters: kind ? { kind } : {} })

  // An error may be the vault locking under us: ask the vault rather than
  // reading the error text (an older daemon reports it as an internal error).
  useEffect(() => { if (list.error) onLockedMaybe?.() }, [list.error, onLockedMaybe])

  return (
    <div className="space-y-4">
      <WitnessCard />

      {list.error && !list.loading && (
        <Notice tone="crit" title="Could not read the audit log." actions={<Button size="sm" onClick={list.reload}>Try again</Button>}>
          {list.error.message}
        </Notice>
      )}

      <Card
        eyebrow="Records"
        title="Newest first"
        padded={false}
        actions={(
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
            <Select aria-label="Kind of record" value={kind} onChange={setKind} options={KIND_FILTERS} className="sm:w-48" />
            <SearchInput value={list.q} onChange={list.setQ} label="Search the audit log" placeholder="Search kind, id, code…" />
          </div>
        )}
      >
        <DataTable
          caption="Audit records, newest first"
          rows={list.items}
          rowKey={(r, i) => r?.seq ?? `${r?.ts}-${i}`}
          loading={list.loading}
          empty={list.q || kind
            ? { icon: DocumentMagnifyingGlassIcon, title: 'No records match', body: 'Try another kind, or clear the search.' }
            : { icon: DocumentMagnifyingGlassIcon, title: 'No records yet', body: 'Every request, decision and change is recorded here as it happens.' }}
          columns={[
            { key: 'seq', header: 'Seq', className: 'w-16 font-mono text-xs text-muted tabular-nums', cell: (r) => (Number.isInteger(r.seq) ? r.seq : '') },
            { key: 'ts', header: 'Time (UTC)', className: 'whitespace-nowrap font-mono text-xs text-muted', cell: (r) => auditTime(r.ts) },
            { key: 'decision', header: 'Decision', cell: (r) => <Decision value={r.decision} /> },
            { key: 'kind', header: 'Kind', primary: true, cell: (r) => <span className="break-all font-mono text-[0.8125rem]">{cleanLine(r.kind)}</span> },
            { key: 'note', header: 'Note', className: 'max-w-xs', cell: (r) => <span className="break-all font-mono text-xs text-muted">{cleanLine(auditNote(r))}</span> },
          ]}
        />
        <div className="border-t border-line px-4"><Pagination {...list.pagination} label="Audit pages" /></div>
      </Card>
    </div>
  )
}

/** allow and deny in words and colour; anything else quietly. */
function Decision({ value }) {
  if (value === 'allow') return <Badge tone="ok">allow</Badge>
  if (value === 'deny') return <Badge tone="crit">deny</Badge>
  return value ? <span className="text-xs text-muted">{cleanLine(value)}</span> : <span className="text-xs text-muted" aria-label="no decision">–</span>
}
