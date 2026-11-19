// Credentials, at parity with the old page's (contract U5): the stored list,
// paged and searchable (U3), with test, rotate, scrub patterns, expiry,
// quarantine, release and remove on each row, and the form to add one.
// Folders (schema 2) organize the list: a tree beside it, filters for
// status and kind, an order, and moves one at a time or by selection.
// Pins are shown, read-only; they are set from the command line, where the
// live certificate chain can be checked (F11).

import { useCallback, useEffect, useMemo, useState } from 'react'
import { FolderIcon, PencilSquareIcon, XMarkIcon } from '@heroicons/react/16/solid'
import { useApi, useSlowCache } from '../hooks/useApi.js'
import { usePaged } from '../hooks/usePaged.js'
import { usePrompt } from '../hooks/usePrompt.js'
import { useToast } from '../hooks/useToast.js'
import { folderPaths, folderProblem, leafOf } from '../lib/folders.js'
import { cleanLine } from '../lib/text.js'
import { Button } from '../components/ui/Button.jsx'
import { Card } from '../components/ui/Card.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'
import { AddCredentialCard } from '../components/credentials/AddCredentialCard.jsx'
import { CredentialFilters, isFiltered, NO_FILTERS } from '../components/credentials/CredentialFilters.jsx'
import { CredentialsTable } from '../components/credentials/CredentialsTable.jsx'
import { ALL, FolderTree, placeKey, placeOf } from '../components/credentials/FolderTree.jsx'
import { ListError } from '../components/credentials/ListError.jsx'
import { ManageCredential } from '../components/credentials/ManageCredential.jsx'
import { MoveDialog } from '../components/credentials/MoveDialog.jsx'
import { RotateDialog } from '../components/credentials/RotateDialog.jsx'

// Where you were and how you had it filtered, per browser. A convenience
// only: an empty or blocked store just starts at All.
const VIEW_KEY = 'agent-vault.credentials.view'
function recallView() {
  try {
    const v = JSON.parse(globalThis.localStorage?.getItem(VIEW_KEY) ?? 'null')
    return {
      place: placeOf(typeof v?.place === 'string' ? v.place : 'all'),
      filters: {
        status: Array.isArray(v?.status) ? v.status.filter((x) => typeof x === 'string') : [],
        kind: typeof v?.kind === 'string' ? v.kind : '',
        sort: typeof v?.sort === 'string' ? v.sort : 'name',
      },
    }
  } catch { return { place: ALL, filters: NO_FILTERS } }
}
function rememberView(place, filters) {
  try { globalThis.localStorage?.setItem(VIEW_KEY, JSON.stringify({ place: placeKey(place), ...filters })) } catch { /* not kept */ }
}

/** The list query for a place and filters (list_paging.rs credential_view_of). */
export function viewQuery(place, filters) {
  return {
    ...(place.kind === 'folder' ? { folder: place.path } : {}),
    ...(place.kind === 'unfiled' ? { unfiled: 1 } : {}),
    ...(filters.status.length ? { status: [...filters.status].sort() } : {}),
    ...(filters.kind ? { kind: filters.kind } : {}),
    ...(filters.sort && filters.sort !== 'name' ? { sort: filters.sort } : {}),
  }
}

export function Credentials() {
  const api = useApi()
  const slow = useSlowCache()
  const prompt = usePrompt()
  const toast = useToast()
  const [{ place, filters }, setView] = useState(recallView)
  const setPlace = (p) => setView((v) => ({ ...v, place: p }))
  const setFilters = (f) => setView((v) => ({ ...v, filters: f }))
  useEffect(() => rememberView(place, filters), [place, filters])
  const query = useMemo(() => viewQuery(place, filters), [place, filters])
  const list = usePaged('credentials', { filters: query })
  // The last probe and the last scrub sample, per credential, as the old page
  // kept them: they survive a re-read of the list, not a reload.
  const [tests, setTests] = useState(() => new Map())
  const [samples, setSamples] = useState(() => new Map())
  const [managing, setManaging] = useState(null)
  const [rotating, setRotating] = useState(null)
  const [moving, setMoving] = useState({ slugs: [], current: '' })
  const [selected, setSelected] = useState(() => new Set())
  const [tree, setTree] = useState(null)

  const loadTree = useCallback(async () => {
    try { setTree(await api.get('credentials/folders')) } catch { /* the list says what is wrong */ }
  }, [api])
  useEffect(() => { loadTree() }, [loadTree])
  // A folder renamed or emptied away from under you goes back to All.
  useEffect(() => {
    if (tree && place.kind === 'folder' && !tree.folders?.some((f) => f.path === place.path)) setPlace(ALL)
  }, [tree, place])
  useEffect(() => { setSelected(new Set()) }, [query])

  const reloadList = list.reload
  const reload = useCallback(async () => { await Promise.all([reloadList(), loadTree()]) }, [reloadList, loadTree])
  const onTest = useCallback(async (slug) => {
    let result
    try { result = await api.post('credentials/test', { slug }) } catch (e) { result = { error: e?.message || String(e) } }
    setTests((m) => new Map(m).set(slug, result))
    slow.clear()
    await reload()
  }, [api, slow, reload])
  const onSample = useCallback((slug, sample) => setSamples((m) => {
    const next = new Map(m)
    if (sample) next.set(slug, sample)
    else next.delete(slug)
    return next
  }), [])
  const onMove = useCallback((slugs, current = '') => setMoving({ slugs, current }), [])

  const renameFolder = async () => {
    const from = place.path
    const to = await prompt.text({
      title: `Rename ${cleanLine(leafOf(from))}`,
      body: 'Everything in it and beneath it moves too.',
      label: 'New path',
      initial: from,
      submit: 'Rename',
    })
    if (to === null || to.trim() === from) return
    const problem = folderProblem(to.trim())
    if (problem) { toast(problem, { tone: 'crit' }); return }
    try {
      const r = await api.post('credentials/folder/rename', { from, to: to.trim() })
      const n = r?.moved?.length ?? 0
      toast(`Renamed to ${cleanLine(to.trim())} · ${n} credential${n === 1 ? '' : 's'} moved`, { tone: 'ok' })
      setPlace({ kind: 'folder', path: to.trim() })
      await reload()
    } catch (e) { toast(e?.message || String(e), { tone: 'crit' }) }
  }

  const managed = managing ? list.items.find((c) => c.slug === managing) ?? null : null
  const narrowed = place.kind !== 'all' || isFiltered(filters)
  const title = place.kind === 'folder' ? cleanLine(place.path).split('/').join(' / ') : place.kind === 'unfiled' ? 'Unfiled' : 'Stored'
  const countText = list.total !== null && list.total !== undefined
    ? `${list.total} credential${list.total === 1 ? '' : 's'}${narrowed || list.q ? ' match' : ''}`
    : undefined

  return (
    <>
      <PageHeader
        eyebrow="Vault"
        title="Credentials"
        description="The value is write-only. It goes straight to the daemon and is never sent back to this page. Pins are shown here and set from the command line, where the live certificate chain can be checked."
      />
      <div className="grid gap-4 lg:grid-cols-[15rem_minmax(0,1fr)]">
        <FolderTree tree={tree} place={place} onPlace={setPlace} className="lg:sticky lg:top-4 lg:self-start" />
        <div className="min-w-0 space-y-4">
          <Card
            title={title}
            description={countText}
            padded={false}
            actions={(
              <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
                {place.kind === 'folder' && <Button size="sm" variant="ghost" icon={PencilSquareIcon} onClick={renameFolder}>Rename folder</Button>}
                <SearchInput value={list.q} onChange={list.setQ} label="Search credentials" placeholder="Search name, host, folder" />
              </div>
            )}
          >
            <div className="space-y-3 border-b border-line px-4 py-3">
              <CredentialFilters filters={filters} onChange={setFilters} kinds={tree?.kinds ?? []} />
              {selected.size > 0 && (
                <div className="flex flex-wrap items-center gap-2 rounded-control bg-accent-soft px-3 py-2 text-sm text-accent" role="status">
                  <span className="font-medium">{selected.size} selected</span>
                  <Button size="sm" icon={FolderIcon} onClick={() => onMove([...selected])}>Move to folder…</Button>
                  <button type="button" onClick={() => setSelected(new Set())} className="ml-auto inline-flex items-center gap-1 text-xs hover:underline focus:outline-none focus-visible:outline-2 focus-visible:outline-focus">
                    <XMarkIcon aria-hidden="true" className="size-3.5" />Clear selection
                  </button>
                </div>
              )}
            </div>
            {list.error ? (
              <ListError error={list.error} onRetry={reload} what="the credentials" />
            ) : (
              <CredentialsTable
                list={list}
                tests={tests}
                onTest={onTest}
                onManage={setManaging}
                onRotate={setRotating}
                onChanged={reload}
                onMove={onMove}
                selected={selected}
                onSelect={setSelected}
                narrowed={narrowed}
                showFolder={place.kind !== 'folder' || filters.sort === 'folder'}
              />
            )}
            <div className="border-t border-line px-4">
              <Pagination {...list.pagination} label="Credentials pages" />
            </div>
          </Card>
          <AddCredentialCard onAdded={reload} />
        </div>
      </div>
      <ManageCredential
        c={managed}
        sample={managed ? samples.get(managed.slug) : null}
        onSample={onSample}
        onClose={() => setManaging(null)}
        onChanged={reload}
      />
      <RotateDialog slug={rotating} onClose={() => setRotating(null)} onDone={reload} />
      <MoveDialog
        slugs={moving.slugs}
        current={moving.current}
        folders={folderPaths(tree?.folders)}
        onClose={() => setMoving({ slugs: [], current: '' })}
        onDone={() => { setSelected(new Set()); reload() }}
      />
    </>
  )
}
