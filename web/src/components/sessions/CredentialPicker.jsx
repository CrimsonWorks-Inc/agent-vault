import { useState } from 'react'
import { cleanLine } from '../../lib/text.js'
import { Badge } from '../ui/Badge.jsx'
import { SearchInput } from '../ui/SearchInput.jsx'
import { Check } from './Check.jsx'
import { MAX_SESSION_CREDS } from './sessionLogic.js'

/**
 * Which credentials a new session holds (the old page's multi-select). A filter
 * box once there are more than a few; the picked ones stay listed first so a
 * filter never hides a choice already made.
 */
export function CredentialPicker({ creds, picked, onChange }) {
  const [q, setQ] = useState('')
  const term = q.trim().toLowerCase()
  const shown = creds.filter((c) => picked.includes(c.slug) || !term || `${c.slug} ${c.kind}`.toLowerCase().includes(term))
  const toggle = (slug, on) => onChange(on ? [...picked, slug] : picked.filter((s) => s !== slug))
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium text-ink">Credentials</legend>
      <p className="text-xs text-muted">{picked.length} picked, at most {MAX_SESSION_CREDS}. Each one becomes a grant with the limits below.</p>
      {creds.length > 6 && <SearchInput value={q} onChange={setQ} label="Filter credentials" placeholder="Filter credentials" className="sm:max-w-none" />}
      <div className="max-h-56 overflow-y-auto rounded-control border border-line-strong/60 bg-surface">
        <ul className="divide-y divide-line">
          {shown.map((c) => (
            <li key={c.slug} className="px-3 py-2">
              <Check checked={picked.includes(c.slug)} onChange={(on) => toggle(c.slug, on)} mono>
                {cleanLine(c.slug)} <Badge mono className="ml-1">{cleanLine(c.kind)}</Badge>
              </Check>
            </li>
          ))}
          {!shown.length && <li className="px-3 py-2 text-sm text-muted">Nothing matches.</li>}
        </ul>
      </div>
    </fieldset>
  )
}
