// Approvals, at parity with the old page's (contract U5): every held request and
// session request, from GET pending (built by src/pending.js, the module the
// CLI renders from). This page paints what it is given and decides nothing:
// which kinds exist, what may be narrowed and which route settles each one
// all come with the item.
//
// The list refreshes every five seconds and keeps your place, your ticks and
// whatever you have typed into a narrowing: losing a half-typed narrowing
// could send an approval wider than the one being written.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { CheckBadgeIcon } from '@heroicons/react/24/outline'
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
import { BulkBar } from '../components/approvals/BulkBar.jsx'
import { PendingCard, PickBox } from '../components/approvals/PendingCard.jsx'

export const APPROVALS_POLL_MS = 5000

export function Approvals({ rest = '' }) {
  const vault = useVault()
  const list = usePaged('pending', { poll: APPROVALS_POLL_MS })
  const [selected, setSelected] = useState(() => new Set())
  const [drafts, setDrafts] = useState(() => ({}))
  const focus = rest ? cleanLine(rest) : ''

  // `#approvals/<id>` (a notification's click): find that one item, wherever
  // it is in the list, by searching for its id.
  const { setQ } = list
  useEffect(() => { if (focus) setQ(focus) }, [focus, setQ])

  // A tick cannot outlive the thing it was about: an item no longer on the
  // page drops out of the selection, so the signature covers only what is shown.
  const { items } = list
  useEffect(() => {
    setSelected((cur) => {
      const present = new Set(items.map((i) => i.id))
      const next = new Set([...cur].filter((id) => present.has(id)))
      return next.size === cur.size ? cur : next
    })
  }, [items])

  // Scroll the deep-linked item into view once, when it first shows; the
  // five-second refresh must not pull the page back to it after that.
  const scrolledTo = useRef('')
  useEffect(() => {
    if (!focus || scrolledTo.current === focus) return
    const all = [...document.querySelectorAll('[data-item]')].filter((x) => x.dataset.item === focus)
    const el = all.find((x) => x.offsetParent !== null) || all[0]
    if (!el) return
    scrolledTo.current = focus
    el.scrollIntoView?.({ block: 'center' })
  }, [focus, items])

  const picked = useMemo(() => items.filter((i) => selected.has(i.id)), [items, selected])
  const pick = useCallback((id, on) => setSelected((cur) => {
    const next = new Set(cur)
    if (on) next.add(id)
    else next.delete(id)
    return next
  }), [])
  const allOnPage = items.length > 0 && items.every((i) => selected.has(i.id))
  const pickAll = (on) => setSelected(on ? new Set(items.map((i) => i.id)) : new Set())

  const setDraft = useCallback((id, draft) => setDrafts((cur) => ({ ...cur, [id]: draft })), [])
  const decided = useCallback((item) => {
    setDrafts((cur) => { const { [item.id]: _gone, ...keep } = cur; return keep })
    setSelected((cur) => { const next = new Set(cur); next.delete(item.id); return next })
    list.reload()
    vault.refresh()
  }, [list, vault])
  const decidedMany = useCallback(() => {
    setSelected(new Set())
    list.reload()
    vault.refresh()
  }, [list, vault])

  const waiting = vault.pendingKnown ? vault.pendingCount : list.total
  const nothing = !list.loading && !list.error && items.length === 0 && !list.q

  return (
    <>
      <PageHeader
        eyebrow="agent-vault"
        title="Approvals"
        status={waiting > 0 ? <Badge tone="warn" dot>{waiting} waiting</Badge> : null}
        description={nothing
          ? 'Requests an agent cannot make without you.'
          : 'The summary is written by the daemon from what it actually received. The reason is whatever the agent claimed, and is not verified.'}
      />

      <div className="space-y-4">
        {focus && list.q === focus && (
          <Notice
            tone="info"
            title={`Showing ${focus}`}
            actions={<Button size="sm" onClick={() => { setQ(''); globalThis.location.hash = formatHash('approvals') }}>Show everything waiting</Button>}
          >
            Opened from a notification. Deciding it still needs your fingerprint.
          </Notice>
        )}

        <BulkBar picked={picked} onClear={() => setSelected(new Set())} onDone={decidedMany} />

        {list.error && !list.loading && (
          <Notice tone="crit" title="Could not read what is waiting." actions={<Button size="sm" onClick={list.reload}>Try again</Button>}>
            {list.error.message}
          </Notice>
        )}

        <Card
          title="Waiting for you"
          padded={false}
          actions={<SearchInput value={list.q} onChange={list.setQ} label="Search waiting decisions" placeholder="Search id, kind, summary…" />}
        >
          <DataTable
            caption="Waiting decisions"
            rows={items}
            rowKey="id"
            loading={list.loading}
            rowClassName={(item) => (item.id === focus ? 'bg-warn-soft/40 outline outline-2 -outline-offset-2 outline-warn' : '')}
            empty={list.q
              ? { title: 'Nothing waiting matches that search', body: 'Clear the search to see everything waiting.' }
              : { icon: CheckBadgeIcon, title: 'Nothing waiting.', body: 'When an agent asks for a session, or a write is held for you, it appears here.' }}
            columns={[
              {
                key: 'select',
                header: (
                  <label className="inline-flex items-center gap-2 normal-case tracking-normal">
                    <input type="checkbox" className="size-4 accent-accent" checked={allOnPage} onChange={(e) => pickAll(e.target.checked)} aria-label="Select every item on this page" disabled={!items.length} />
                  </label>
                ),
                hideOnCard: true,
                className: 'w-10 align-top',
                cell: (item) => <PickBox item={item} checked={selected.has(item.id)} onChange={(on) => pick(item.id, on)} className="mt-0.5 [&>span]:sr-only" />,
              },
              {
                key: 'decision',
                header: 'Decision',
                primary: true,
                className: 'align-top py-4',
                cell: (item) => (
                  <PendingCard
                    item={item}
                    draft={drafts[item.id]}
                    onDraft={(d) => setDraft(item.id, d)}
                    selected={selected.has(item.id)}
                    onSelect={(on) => pick(item.id, on)}
                    onDecided={decided}
                  />
                ),
              },
            ]}
          />
          <div className="border-t border-line px-4"><Pagination {...list.pagination} label="Waiting decisions pages" /></div>
        </Card>
      </div>
    </>
  )
}
