// Sessions, at parity with app.html's (contract U5): the list, paged and
// searchable (U3), with details, the three one-click narrowings and revoke;
// the New session form (free-form or from a template, infinite and
// auto-approval with their warnings); the hand-off card, shown once; and the
// access review. Deep links: #sessions, #sessions/new, #sessions/new:<template>,
// #sessions/review, #sessions/detail:<sid>.

import { useCallback, useEffect, useState } from 'react'
import { PlusIcon } from '@heroicons/react/16/solid'
import { KeyIcon } from '@heroicons/react/24/outline'
import { useApiQuery } from '../hooks/useApi.js'
import { usePaged } from '../hooks/usePaged.js'
import { useVault } from '../hooks/useVault.js'
import { fetchAll } from '../lib/paging.js'
import { formatHash } from '../lib/router.js'
import { Button } from '../components/ui/Button.jsx'
import { Card } from '../components/ui/Card.jsx'
import { EmptyState } from '../components/ui/EmptyState.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'
import { Skeleton } from '../components/ui/Skeleton.jsx'
import { Tabs } from '../components/ui/Tabs.jsx'
import { ListError } from '../components/credentials/ListError.jsx'
import { AccessReview } from '../components/sessions/AccessReview.jsx'
import { HandoffCard } from '../components/sessions/HandoffCard.jsx'
import { NarrowResult } from '../components/sessions/NarrowResult.jsx'
import { NewSessionForm } from '../components/sessions/NewSessionForm.jsx'
import { SessionDetail } from '../components/sessions/SessionDetail.jsx'
import { SessionsTable } from '../components/sessions/SessionsTable.jsx'
import { NARROWINGS, sessionsRoute } from '../components/sessions/sessionLogic.js'

export const SESSION_SEARCH_FIELDS = ['id', 'label', 'state']

const go = (rest) => {
  try { globalThis.location.hash = formatHash('sessions', rest) } catch { /* no address bar to keep in step */ }
}

export function Sessions({ rest = '' }) {
  const vault = useVault()
  const route = sessionsRoute(rest)
  const [tab, setTab] = useState(route.tab)
  const [detail, setDetail] = useState(route.detail ?? null)
  // The hand-off lives here and nowhere else: Done, or leaving the page,
  // drops it with this component's state (U7).
  const [handoff, setHandoff] = useState(null)
  const [narrowed, setNarrowed] = useState(null)
  const list = usePaged('sessions', { searchFields: SESSION_SEARCH_FIELDS })

  // The address bar leads: a link to #sessions/new opens that tab.
  useEffect(() => {
    const r = sessionsRoute(rest)
    setTab(r.tab)
    setDetail(r.detail ?? null)
  }, [rest])

  const choose = (id) => { setTab(id); go(id === 'list' ? '' : id) }
  const openDetail = (sid) => { setDetail(sid); setTab('list'); go(`detail:${sid}`); globalThis.scrollTo?.({ top: 0 }) }
  const closeDetail = () => { setDetail(null); go('') }

  const reload = list.reload
  const changed = useCallback(() => { reload(); vault.refresh?.() }, [reload, vault])
  const onNarrowed = useCallback((sid, which, result) => {
    setNarrowed({ title: NARROWINGS[which]?.title ?? 'Narrowed', result })
    // What the detail showed is no longer true.
    setDetail((d) => (d === sid ? null : d))
    reload()
  }, [reload])
  const onCreated = useCallback((h) => {
    setHandoff(h)
    setTab('list')
    go('')
    globalThis.scrollTo?.({ top: 0 })
    reload()
    vault.refresh?.()
  }, [reload, vault])

  const tabs = [
    {
      id: 'list',
      label: 'Sessions',
      content: (
        <Card
          title="Sessions"
          description={list.total !== null && !list.q ? `${list.total} session${list.total === 1 ? '' : 's'}, newest first` : 'Newest first'}
          padded={false}
          actions={(
            <>
              <SearchInput value={list.q} onChange={list.setQ} label="Search sessions" placeholder="Search label, id or credential" className="sm:w-64" />
              <Button size="md" variant="primary" icon={PlusIcon} onClick={() => choose('new')}>New session</Button>
            </>
          )}
        >
          {list.error
            ? <ListError error={list.error} onRetry={reload} what="the sessions" />
            : <SessionsTable list={list} onDetails={openDetail} onNarrowed={onNarrowed} onChanged={changed} />}
          <div className="border-t border-line px-4"><Pagination {...list.pagination} label="Session pages" /></div>
        </Card>
      ),
    },
    { id: 'new', label: 'New session', content: <NewSession template={route.template} onCreated={onCreated} /> },
    { id: 'review', label: 'Access review', content: <AccessReview /> },
  ]

  return (
    <>
      <PageHeader
        eyebrow="Agents"
        title="Sessions"
        description="A session is what an agent holds. Revoking one cuts off every placeholder it issued. Narrowing one takes capability away while it runs; nothing here can widen a live session."
      />
      <div className="space-y-4">
        {handoff && <HandoffCard handoff={handoff} onDismiss={() => setHandoff(null)} />}
        {narrowed && <NarrowResult title={narrowed.title} result={narrowed.result} onDismiss={() => setNarrowed(null)} />}
        {detail && <SessionDetail key={detail} sid={detail} onClose={closeDetail} />}
        <Tabs tabs={tabs} selected={tab} onChange={choose} />
      </div>
    </>
  )
}

/**
 * The New session tab: everything the form picks from. Credentials and
 * templates are read whole, as a picker needs them; a vault with no
 * credential gets a way to add one instead of a form that cannot submit.
 */
function NewSession({ template, onCreated }) {
  const { data, error, reload } = useApiQuery(async (api) => {
    const [creds, templates] = await Promise.all([
      fetchAll(api.get, 'credentials'),
      fetchAll(api.get, 'templates').catch(() => []),
    ])
    return { creds, templates }
  }, [])

  if (error && !data) return <Card><ListError error={error} onRetry={reload} what="the credentials" /></Card>
  if (!data) {
    return (
      <Card title="New session">
        <div className="space-y-3" role="status" aria-label="Loading the form"><Skeleton className="w-1/3" /><Skeleton className="w-2/3" /><Skeleton className="w-1/2" /></div>
      </Card>
    )
  }
  if (!data.creds.length) {
    return (
      <Card>
        <EmptyState
          icon={KeyIcon}
          title="Add a credential first"
          action={<a href={formatHash('credentials')} className="text-sm font-medium text-accent underline-offset-2 hover:underline">Go to Credentials</a>}
        >
          A session grants an agent the use of stored credentials, so there is nothing to grant yet.
        </EmptyState>
      </Card>
    )
  }
  return <NewSessionForm creds={data.creds} templates={data.templates} initialTemplate={template} onCreated={onCreated} onTemplatesChanged={reload} />
}
