import { Disclosure } from '../ui/Disclosure.jsx'
import { Field } from '../ui/Field.jsx'
import { Input } from '../ui/Input.jsx'
import { Select } from '../ui/Select.jsx'
import { UntrustedText } from '../ui/UntrustedText.jsx'
import { OWNER_APPROVALS } from './decide.js'

/** Every narrowing input says this, whatever the agent proposed. */
export const NARROW_PLACEHOLDER = 'unchanged'

/** The attribution beside a proposed value. A constant: nothing the agent wrote is in it. */
export const PROPOSED_BY = 'Proposed by the agent, not verified'

/**
 * What the agent proposed for one field, as text for UntrustedText, or null
 * when it proposed nothing. Structured values (routes, payload) as JSON.
 * Never put into an attribute: it is the agent's words, so it is shown as
 * text beside the input, marked as theirs (U7).
 */
export function proposedText(v) {
  if (v === undefined || v === null) return null
  if (Array.isArray(v)) return v.map((x) => (typeof x === 'object' && x !== null ? JSON.stringify(x) : String(x))).join(', ')
  return typeof v === 'object' ? JSON.stringify(v) : String(v)
}

/**
 * The narrowing a human can type before approving, one field per dimension
 * GET pending says is narrowable, and the owner's own options (approval mode,
 * no expiry), which the agent cannot ask for. Controlled from the page, so a
 * half-typed narrowing survives the five-second refresh.
 */
export function NarrowingFields({ item, draft, onChange }) {
  const fields = item.narrowable || []
  const owner = item.owner_settable || []
  const d = draft || {}
  const set = (patch) => onChange({ ...d, ...patch })
  if (!fields.length && !owner.length) return null
  const typed = fields.filter((f) => String(d.fields?.[f] ?? '').trim()).length
  return (
    <div className="mt-4 space-y-4">
      {fields.length > 0 && (
        // Folded so twenty-five waiting items stay readable; it opens by
        // itself once anything has been typed, and the title says what it holds.
        <Disclosure
          title={`Narrow it before approving${typed ? ` (${typed} narrowed)` : ''}`}
          defaultOpen={typed > 0}
        >
          <fieldset>
            <legend className="mb-2 text-sm text-muted">Narrow it before approving, if it asks for more than it needs:</legend>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {fields.map((f) => {
                const asked = proposedText(item.proposal?.[f])
                return (
                  <Field key={f} label={<span className="font-mono">{f}</span>}>
                    <Input
                      mono
                      data-field={f}
                      value={d.fields?.[f] ?? ''}
                      placeholder={NARROW_PLACEHOLDER}
                      autoComplete="off"
                      spellCheck={false}
                      onChange={(e) => set({ fields: { ...(d.fields || {}), [f]: e.target.value } })}
                    />
                    {asked !== null && (
                      <p className="mt-1 flex min-w-0 items-baseline gap-1.5 text-xs text-muted">
                        <span className="shrink-0">asked:</span>
                        <UntrustedText text={asked} label={PROPOSED_BY} />
                      </p>
                    )}
                  </Field>
                )
              })}
            </div>
          </fieldset>
        </Disclosure>
      )}
      {owner.length > 0 && (
        <fieldset>
          <legend className="mb-2 text-sm text-muted">Owner options, which the agent cannot ask for:</legend>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <Field label={<span className="font-mono">approval</span>} className="sm:w-56">
              <Select value={d.approval ?? ''} onChange={(v) => set({ approval: v })} options={OWNER_APPROVALS} />
            </Field>
            <label className="flex h-9 items-center gap-2 text-sm text-ink">
              <input
                type="checkbox"
                className="size-4 accent-accent"
                checked={d.infinite === true}
                onChange={(e) => set({ infinite: e.target.checked })}
              />
              No expiry
            </label>
          </div>
        </fieldset>
      )}
    </div>
  )
}
