import { useState } from 'react'
import { useApi, useSlowCache } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { useToast } from '../../hooks/useToast.js'
import { ago } from '../../lib/format.js'
import { queryBound } from '../../lib/presence.js'
import { cleanLine } from '../../lib/text.js'
import { CodeBlock } from '../ui/CodeBlock.jsx'
import { Field } from '../ui/Field.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Input } from '../ui/Input.jsx'

/**
 * Extra token shapes to redact from every response, per credential (F4).
 * Adding and removing a pattern are both signed, over exactly what is sent.
 */
export function ScrubRules({ c, sample, onSample, onChanged }) {
  const api = useApi()
  const slow = useSlowCache()
  const presence = usePresence()
  const toast = useToast()
  const [pattern, setPattern] = useState('')
  const [text, setText] = useState('')
  const slug = c.slug
  const list = Array.isArray(c.scrub_patterns) ? c.scrub_patterns : []

  const addBody = () => ({ slug, pattern: pattern.trim(), ...(text ? { sample: text } : {}) })
  // Built at the click, and refused here when empty, so a slip costs no tap.
  const addOperation = async () => {
    if (!pattern.trim()) throw new Error('Type a pattern first')
    return presence.operationFor('cred.scrub_add', addBody())
  }

  return (
    <section aria-labelledby={`scrub-${slug}`} className="space-y-3">
      <h3 id={`scrub-${slug}`} className="text-sm font-semibold text-ink">Scrub patterns ({list.length})</h3>
      {list.length ? (
        <ul className="divide-y divide-line rounded-control border border-line">
          {list.map((p) => (
            <li key={p.id} className="flex flex-col gap-2 px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <CodeBlock inline code={cleanLine(p.source)} />
                <p className="mt-1 font-mono text-xs text-muted">{cleanLine(p.id)} · added {ago(p.added_at)}</p>
              </div>
              <GatedButton
                size="sm"
                variant="danger"
                label={`remove scrub pattern ${p.id} from ${slug}`}
                operation={queryBound('DELETE credentials/scrub', { slug, id: p.id }).operation}
                send={(proof) => { const r = queryBound('DELETE credentials/scrub', { slug, id: p.id }); return api.del(r.path, r.query, { presence: proof }) }}
                onDone={() => { toast(`Removed ${p.id}`, { tone: 'ok' }); slow.clear(); onChanged?.() }}
                aria-label={`Remove pattern ${p.id}`}
              >
                Remove
              </GatedButton>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted">No extra patterns yet.</p>
      )}
      <p className="text-sm text-muted">
        Another shape of token to redact from every response, such as <CodeBlock inline code="acme_[A-Za-z0-9]{20,40}" />.
        A pattern that could match ordinary text or run long is refused.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Pattern">
          <Input mono autoComplete="off" value={pattern} onChange={(e) => setPattern(e.target.value)} />
        </Field>
        <Field label="Try on text" optional>
          <Input mono autoComplete="off" value={text} onChange={(e) => setText(e.target.value)} />
        </Field>
      </div>
      <GatedButton
        label={`add a scrub pattern to ${slug}`}
        operation={addOperation}
        send={(proof) => api.post('credentials/scrub', { ...addBody(), presence: proof })}
        onDone={(r) => {
          onSample(slug, r?.sample || null)
          setPattern('')
          toast(`Added ${r?.id || 'the pattern'} to ${slug}`, { tone: 'ok' })
          slow.clear()
          onChanged?.()
        }}
      >
        Add pattern
      </GatedButton>
      {sample && (
        <p className="text-sm text-muted" data-scrub-sample="">
          {sample.matches} match(es) in your text: <span className="font-mono text-ink">{cleanLine(sample.redacted)}</span>
        </p>
      )}
    </section>
  )
}
