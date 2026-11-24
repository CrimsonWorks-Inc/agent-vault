import { useState } from 'react'
import { ChevronRightIcon, FolderIcon, FolderOpenIcon, InboxIcon, Squares2X2Icon } from '@heroicons/react/16/solid'
import { cx } from '../../lib/cx.js'
import { cleanLine } from '../../lib/text.js'
import { folderTree, isWithin } from '../../lib/folders.js'
import { Select } from '../ui/Select.jsx'

/** What the list is showing: everything, the unfiled, or one folder down. */
export const ALL = { kind: 'all' }
export const UNFILED = { kind: 'unfiled' }
export const inFolder = (path) => ({ kind: 'folder', path })
export const placeKey = (p) => (p.kind === 'folder' ? `folder:${p.path}` : p.kind)
export const placeOf = (key) => (key === 'unfiled' ? UNFILED : key?.startsWith('folder:') ? inFolder(key.slice(7)) : ALL)

/**
 * The folder tree beside the list on large screens, and a picker above it
 * on small ones. Counts include everything beneath a folder.
 */
export function FolderTree({ tree, place, onPlace, className }) {
  const nodes = folderTree(tree?.folders)
  return (
    <>
      <nav aria-label="Folders" className={cx('hidden lg:block', className)}>
        <ul className="space-y-0.5 text-sm">
          <PlaceRow icon={Squares2X2Icon} label="All credentials" count={tree?.total} active={place.kind === 'all'} onClick={() => onPlace(ALL)} />
          <PlaceRow icon={InboxIcon} label="Unfiled" count={tree?.unfiled} active={place.kind === 'unfiled'} onClick={() => onPlace(UNFILED)} />
        </ul>
        {nodes.length > 0 && (
          <>
            <p className="mb-1 mt-4 px-2 font-mono text-eyebrow uppercase tracking-[0.14em] text-muted">Folders</p>
            <ul className="space-y-0.5 text-sm">
              {nodes.map((n) => <FolderNode key={n.path} node={n} depth={0} place={place} onPlace={onPlace} />)}
            </ul>
          </>
        )}
      </nav>
      <div className="lg:hidden">
        <Select
          aria-label="Show folder"
          value={placeKey(place)}
          onChange={(k) => onPlace(placeOf(k))}
          options={[
            { value: 'all', label: `All credentials${count(tree?.total)}` },
            { value: 'unfiled', label: `Unfiled${count(tree?.unfiled)}` },
            ...(tree?.folders ?? []).map((f) => ({
              value: `folder:${f.path}`,
              label: `${' '.repeat(f.path.split('/').length - 1)}${cleanLine(f.path.split('/').pop())}${count(f.total)}`,
            })),
          ]}
        />
      </div>
    </>
  )
}

const count = (n) => (Number.isInteger(n) ? ` (${n})` : '')

function PlaceRow({ icon: Icon, label, count: n, active, onClick, depth = 0, toggle = null, mono = false }) {
  return (
    <li>
      <div
        className={cx(
          'group flex items-center gap-1 rounded-control pr-2',
          active ? 'bg-accent-soft text-accent' : 'text-ink hover:bg-sunken',
        )}
      >
        <span className={cx('flex shrink-0 items-center', DEPTH_PAD[depth] ?? DEPTH_PAD[3])}>{toggle ?? <span className="size-5" />}</span>
        <button
          type="button"
          onClick={onClick}
          aria-current={active ? 'true' : undefined}
          className="flex min-w-0 flex-1 items-center gap-2 py-1.5 text-left focus:outline-none focus-visible:outline-2 focus-visible:outline-focus"
        >
          <Icon aria-hidden="true" className={cx('size-4 shrink-0', active ? 'text-accent' : 'text-muted')} />
          <span className={cx('truncate', mono && 'font-mono text-[0.8125rem]', active && 'font-medium')}>{label}</span>
          {Number.isInteger(n) && <span className="ml-auto pl-2 text-xs tabular-nums text-muted">{n}</span>}
        </button>
      </div>
    </li>
  )
}

// Static classes, so Tailwind sees them and nothing needs an inline style (CSP, U2).
const DEPTH_PAD = ['pl-0', 'pl-3', 'pl-6', 'pl-9']

function FolderNode({ node, depth, place, onPlace }) {
  const here = place.kind === 'folder'
  const containsPlace = here && isWithin(place.path, node.path) && place.path !== node.path
  const [open, setOpen] = useState(containsPlace || depth === 0)
  const expanded = open || containsPlace
  const active = here && place.path === node.path
  const toggle = node.children.length > 0 ? (
    <button
      type="button"
      onClick={() => setOpen(!expanded)}
      aria-expanded={expanded}
      aria-label={`${expanded ? 'Collapse' : 'Expand'} ${node.name}`}
      className="flex size-5 items-center justify-center rounded text-muted hover:text-ink focus:outline-none focus-visible:outline-2 focus-visible:outline-focus"
    >
      <ChevronRightIcon aria-hidden="true" className={cx('size-3.5 transition-transform', expanded && 'rotate-90')} />
    </button>
  ) : null
  return (
    <>
      <PlaceRow
        icon={active || containsPlace ? FolderOpenIcon : FolderIcon}
        label={cleanLine(node.name)}
        count={node.total}
        active={active}
        depth={depth}
        toggle={toggle}
        onClick={() => onPlace(inFolder(node.path))}
      />
      {expanded && node.children.map((c) => <FolderNode key={c.path} node={c} depth={depth + 1} place={place} onPlace={onPlace} />)}
    </>
  )
}
