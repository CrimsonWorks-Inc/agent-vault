import { BoltIcon } from '@heroicons/react/24/outline'
import { usePaged } from '../../hooks/usePaged.js'
import { ago, span } from '../../lib/format.js'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Pagination } from '../ui/Pagination.jsx'
import { SearchInput } from '../ui/SearchInput.jsx'
import { auditTime } from '../audit/kinds.js'

/**
 * Every time a tripwire fired, newest first: the audit log's tripwire.fired
 * records, filtered in the daemon (U3), so the whole history pages.
 */
export function FiredTable() {
  const list = usePaged('audit', {
    filters: { kind: 'tripwire.fired' },
    searchFields: ['rule_id', 'session_id', 'credential_slug', 'action'],
    storageKey: 'agent-vault.page-size.tripwires-fired',
  })
  return (
    <Card
      eyebrow="History"
      title="Tripwires that fired"
      padded={false}
      actions={<SearchInput value={list.q} onChange={list.setQ} label="Search fired tripwires" placeholder="Search session, credential…" />}
    >
      {list.error && !list.loading && (
        <Notice tone="crit" className="m-4" title="Could not read the audit log." actions={<Button size="sm" onClick={list.reload}>Try again</Button>}>
          {list.error.message}
        </Notice>
      )}
      <DataTable
        caption="Tripwires that fired, newest first"
        rows={list.items}
        rowKey={(r, i) => r?.seq ?? `${r?.ts}-${i}`}
        loading={list.loading}
        empty={{ icon: BoltIcon, title: list.q ? 'Nothing matches that search' : 'No tripwire has fired', body: list.q ? null : 'When one does, the session it caught is revoked before its refused request returns, and the record lands here.' }}
        columns={[
          { key: 'rule_id', header: 'Rule', primary: true, cell: (r) => <span className="font-mono font-medium">{cleanLine(r.rule_id)}</span> },
          { key: 'ts', header: 'When', cell: (r) => <span title={auditTime(r.ts)} className="whitespace-nowrap text-muted">{r.ts ? ago(r.ts) : ''}</span> },
          { key: 'session_id', header: 'Session', cell: (r) => <span className="break-all font-mono text-xs">{cleanLine(r.session_id || '')}</span> },
          { key: 'credential_slug', header: 'Credential', cell: (r) => <span className="font-mono text-xs">{cleanLine(r.credential_slug || '')}</span> },
          { key: 'count', header: 'Tripped', cell: (r) => (Number.isFinite(r.count) ? `${r.count} in ${span(r.window_s)}` : '') },
          { key: 'action', header: 'Action', cell: (r) => <span className="font-mono text-xs text-crit">→ {cleanLine(r.action || '')}</span> },
        ]}
      />
      <div className="border-t border-line px-4"><Pagination {...list.pagination} label="Fired tripwire pages" /></div>
    </Card>
  )
}
