import { useState } from 'react'
import { PlusIcon, XMarkIcon } from '@heroicons/react/16/solid'
import { Button } from '../ui/Button.jsx'
import { CodeBlock } from '../ui/CodeBlock.jsx'
import { IconButton } from '../ui/IconButton.jsx'
import { Input } from '../ui/Input.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Select } from '../ui/Select.jsx'
import { MAX_MAPPINGS, defaultMappings, envCommand, mappingProblems } from './sessionLogic.js'

const WHAT = [
  { value: 'placeholder', label: 'placeholder' },
  { value: 'base_url', label: 'base URL' },
]

/**
 * The names a tool reads, mapped to the session's credentials, and the
 * `env` command that writes them. One row per credential to begin with,
 * named as a tool would most likely look for it; rows can be renamed, added
 * (a second name, or a credential's base URL) and removed. The command
 * writes placeholders and loopback URLs only; the session token is not in it.
 */
export function EnvMapping({ cli, sessionId, grants }) {
  const [rows, setRows] = useState(() => defaultMappings(grants))
  const creds = [...new Set(grants.map((g) => g.cred))].map((c) => ({ value: c, label: c }))
  const problems = mappingProblems(rows)
  const ok = rows.length > 0 && problems.every((p) => p === null)
  const set = (i, patch) => setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)))

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">An env file for your tools: placeholders only, written readable by you alone.</p>
      <div className="overflow-hidden rounded-control border border-line">
        <div className="hidden grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,0.8fr)_2.25rem] gap-2 border-b border-line bg-sunken/60 px-3 py-1.5 font-mono text-eyebrow uppercase tracking-[0.12em] text-muted sm:grid">
          <span>Variable</span><span>Credential</span><span>Value</span><span className="sr-only">Remove</span>
        </div>
        <ul className="divide-y divide-line">
          {rows.map((r, i) => (
            <li key={i} className="grid grid-cols-[minmax(0,1fr)_2.25rem] gap-2 px-3 py-2 sm:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,0.8fr)_2.25rem] sm:items-start">
              <div className="min-w-0">
                <Input
                  mono
                  aria-label={`Variable name ${i + 1}`}
                  value={r.name}
                  invalid={problems[i] !== null}
                  onChange={(e) => set(i, { name: e.target.value })}
                  autoComplete="off"
                />
                {problems[i] && <p className="mt-1 text-xs text-crit" role="alert">{problems[i]}</p>}
              </div>
              <IconButton
                icon={XMarkIcon}
                label={`Remove ${r.name || 'this mapping'}`}
                size="sm"
                className="sm:order-last"
                onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
              />
              <Select aria-label={`Credential for ${r.name || `mapping ${i + 1}`}`} mono value={r.cred} onChange={(v) => set(i, { cred: v })} options={creds} className="col-span-2 sm:col-span-1" />
              <Select aria-label={`Value for ${r.name || `mapping ${i + 1}`}`} value={r.what} onChange={(v) => set(i, { what: v })} options={WHAT} className="col-span-2 sm:col-span-1" />
            </li>
          ))}
        </ul>
      </div>
      <Button
        size="sm"
        icon={PlusIcon}
        disabled={rows.length >= MAX_MAPPINGS}
        onClick={() => setRows((rs) => [...rs, { name: '', cred: grants[0]?.cred ?? '', what: 'placeholder' }])}
      >
        Add a mapping
      </Button>
      {ok ? (
        <CodeBlock code={envCommand({ cli, sessionId, mappings: rows })} label="Copy the env command" wrap />
      ) : (
        <Notice tone="warn">{rows.length ? 'Fix the names above to get the command.' : 'Map at least one name to get the command.'}</Notice>
      )}
      <p className="text-xs text-muted">
        Each name becomes one line of the file. A credential’s placeholder works only where its usage says; its base URL is the loopback address to send it to.
      </p>
    </div>
  )
}
