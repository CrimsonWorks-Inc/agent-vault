import { DocumentDuplicateIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import { EyeIcon, PlayIcon } from '@heroicons/react/16/solid'
import { useApi } from '../../hooks/useApi.js'
import { useToast } from '../../hooks/useToast.js'
import { ago } from '../../lib/format.js'
import { queryBound } from '../../lib/presence.js'
import { formatHash } from '../../lib/router.js'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { Button } from '../ui/Button.jsx'
import { DataTable } from '../ui/DataTable.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'

/**
 * Saved session shapes (F17), by name. A template's fields are defaults a new
 * session can only narrow. Deleting one is signed (template.delete).
 */
export function TemplatesTable({ list, onView, onChanged }) {
  const api = useApi()
  const toast = useToast()
  const searching = Boolean(list.q.trim())
  return (
    <DataTable
      caption="Templates"
      rows={list.items}
      rowKey="name"
      loading={list.loading}
      empty={searching
        ? { icon: MagnifyingGlassIcon, title: 'Nothing matches', body: `No template matches “${list.q.trim()}”.` }
        : {
            icon: DocumentDuplicateIcon,
            title: 'No templates yet',
            body: 'Fill in New session the way you want it, then choose Save as template.',
            action: <a href={formatHash('sessions', 'new')} className="text-sm font-medium text-accent underline-offset-2 hover:underline">Open New session</a>,
          }}
      columns={[
        {
          key: 'name', header: 'Template', primary: true,
          cell: (t) => (
            <span className="flex flex-wrap items-center gap-1.5">
              <span className="font-mono text-sm font-medium text-ink">{cleanLine(t.name)}</span>
              <Badge mono>v{t.version}</Badge>
              {(t.elevated || []).length > 0 && <Badge tone="warn" title={t.elevated.join(', ')}>elevated</Badge>}
            </span>
          ),
        },
        { key: 'summary', header: 'Summary', cell: (t) => <span className="text-sm text-muted">{cleanLine(t.summary || '')}</span> },
        { key: 'creds', header: 'Credentials', cell: (t) => <span className="font-mono text-xs">{cleanLine((t.creds || []).join(', '))}</span> },
        { key: 'updated', header: 'Updated', cell: (t) => <span className="whitespace-nowrap text-sm">{t.updated_at ? ago(t.updated_at) : ''}</span> },
        {
          key: 'actions', header: 'Actions', align: 'right', className: 'w-px',
          cell: (t) => (
            <div className="flex flex-wrap items-center gap-1.5 md:flex-nowrap md:justify-end">
              <Button size="sm" icon={EyeIcon} onClick={() => onView(t.name)} aria-label={`View template ${cleanLine(t.name)}`}>View</Button>
              <Button
                size="sm"
                icon={PlayIcon}
                onClick={() => { globalThis.location.hash = formatHash('sessions', `new:${t.name}`) }}
                aria-label={`Start a session from ${cleanLine(t.name)}`}
              >
                Use
              </Button>
              <GatedButton
                size="sm"
                variant="danger"
                label={`delete template ${cleanLine(t.name)}`}
                operation={queryBound('DELETE templates', { name: t.name }).operation}
                send={(proof) => { const r = queryBound('DELETE templates', { name: t.name }); return api.del(r.path, r.query, { presence: proof }) }}
                onDone={() => { toast(`Deleted template ${cleanLine(t.name)}`, { tone: 'ok' }); onChanged?.() }}
                aria-label={`Delete template ${cleanLine(t.name)}`}
              >
                Delete
              </GatedButton>
            </div>
          ),
        },
      ]}
    />
  )
}
