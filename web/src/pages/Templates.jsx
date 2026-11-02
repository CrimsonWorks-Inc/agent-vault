// Templates (F17), at parity with app.html's templates card: the saved
// session shapes, paged and searchable (U3, by name), with delete (signed),
// a view of each spec, and a way to start a session from one. Templates are
// saved from New session ("Save as template").

import { useState } from 'react'
import { PlusIcon } from '@heroicons/react/16/solid'
import { usePaged } from '../hooks/usePaged.js'
import { formatHash } from '../lib/router.js'
import { Card } from '../components/ui/Card.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'
import { ListError } from '../components/credentials/ListError.jsx'
import { TemplatesTable } from '../components/templates/TemplatesTable.jsx'
import { TemplateView } from '../components/templates/TemplateView.jsx'

export const TEMPLATE_SEARCH_FIELDS = ['name', 'summary']

export function Templates() {
  const list = usePaged('templates', { searchFields: TEMPLATE_SEARCH_FIELDS })
  const [viewing, setViewing] = useState(null)

  return (
    <>
      <PageHeader
        eyebrow="Agents"
        title="Templates"
        description="A template is a saved session shape. A session made from one can only narrow it: fewer methods, a stricter approval, a smaller budget, a shorter life."
        actions={(
          <a
            href={formatHash('sessions', 'new')}
            className="inline-flex h-9 items-center gap-2 rounded-control border border-accent bg-accent px-3.5 text-sm font-medium text-on-accent shadow-card hover:bg-accent-hover focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus"
          >
            <PlusIcon aria-hidden="true" className="size-4" />New template
          </a>
        )}
      />
      <Card
        title="Saved"
        description={list.total !== null && !list.q ? `${list.total} template${list.total === 1 ? '' : 's'}, by name` : 'By name'}
        padded={false}
        actions={<SearchInput value={list.q} onChange={list.setQ} label="Search templates" placeholder="Search name or credential" />}
      >
        {list.error
          ? <ListError error={list.error} onRetry={list.reload} what="the templates" />
          : <TemplatesTable list={list} onView={setViewing} onChanged={list.reload} />}
        <div className="border-t border-line px-4"><Pagination {...list.pagination} label="Template pages" /></div>
      </Card>
      <TemplateView key={viewing ?? 'none'} name={viewing} onClose={() => setViewing(null)} />
    </>
  )
}
