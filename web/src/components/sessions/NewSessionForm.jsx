import { useEffect, useMemo, useRef, useState } from 'react'
import { BookmarkIcon } from '@heroicons/react/16/solid'
import { useApi } from '../../hooks/useApi.js'
import { usePresence } from '../../hooks/usePresence.js'
import { usePrompt } from '../../hooks/usePrompt.js'
import { useToast } from '../../hooks/useToast.js'
import { useVault } from '../../hooks/useVault.js'
import { fetchAll } from '../../lib/paging.js'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { Card } from '../ui/Card.jsx'
import { Disclosure } from '../ui/Disclosure.jsx'
import { Field } from '../ui/Field.jsx'
import { GatedButton } from '../ui/GatedButton.jsx'
import { Input } from '../ui/Input.jsx'
import { Notice } from '../ui/Notice.jsx'
import { Select } from '../ui/Select.jsx'
import { Textarea } from '../ui/Textarea.jsx'
import { Check } from './Check.jsx'
import { CredentialPicker } from './CredentialPicker.jsx'
import { RoutesEditor } from './RoutesEditor.jsx'
import {
  APPROVAL_OPTIONS, APPROVAL_ORDER, AUTO_WARNING, LIFETIME_OPTIONS, NEVER_WARNING, autoWrites, buildSessionBody,
  freshForm, handoffFrom, picksModel, templateLimits, templateSessionBody,
} from './sessionLogic.js'

/**
 * The New session form (F17): free-form, or narrowing a template. Every
 * check runs while the operation is built, before anything is signed, so a
 * typo is said now and costs no tap. The body that is signed is the body
 * that is sent (session.create).
 */
export function NewSessionForm({ creds, templates, initialTemplate, onCreated, onTemplatesChanged }) {
  const api = useApi()
  const toast = useToast()
  const vault = useVault()
  const [template, setTemplate] = useState(null) // { name, version, hash, spec, limits, elevated }
  const [choosing, setChoosing] = useState(false)
  const kinds = useMemo(() => new Map(creds.map((c) => [c.slug, c.kind])), [creds])

  /** Fill the form from a template: its fields become the ceiling. */
  const chooseTemplate = async (name) => {
    if (!name) { setTemplate(null); return }
    setChoosing(true)
    try {
      const t = await api.get('templates', { name })
      const listed = templates.find((x) => x.name === name)
      setTemplate({ name: t.name, version: t.version, hash: t.hash, spec: t.spec, limits: templateLimits(t.spec), elevated: listed?.elevated || [] })
    } catch (e) {
      toast(e?.message || String(e), { tone: 'crit' })
    } finally {
      setChoosing(false)
    }
  }
  const started = useRef(false)
  useEffect(() => {
    if (started.current || !initialTemplate) return
    started.current = true
    chooseTemplate(initialTemplate)
  }, [initialTemplate]) // eslint-disable-line react-hooks/exhaustive-deps

  /** After the session exists: what to hand the agent. */
  const created = async (s, picked) => {
    // The first credential's own injection site, so the example call puts
    // the placeholder where it actually goes.
    const all = await fetchAll(api.get, 'credentials').catch(() => [])
    onCreated(handoffFrom(s, { cli: vault.context?.cli, creds: all, picked }))
    setTemplate(null)
    toast(`Session ${s?.session_id ?? ''} created`, { tone: 'ok' })
  }

  const options = [
    { value: '', label: 'none: set every field below' },
    ...templates.map((t) => ({ value: t.name, label: `${cleanLine(t.name)} v${t.version}: ${cleanLine(t.summary || '')}` })),
  ]

  return (
    <Card title="New session" description="Each credential picked becomes one grant. Creating it asks for Touch ID.">
      <div className="space-y-5">
        {templates.length > 0 && (
          <Field label="Start from template" className="max-w-xl">
            <Select value={template?.name ?? ''} onChange={chooseTemplate} options={options} disabled={choosing} />
          </Field>
        )}
        {template
          ? <TemplateForm t={template} onClear={() => setTemplate(null)} onCreated={created} />
          : <FreeForm creds={creds} kinds={kinds} onCreated={created} onTemplatesChanged={onTemplatesChanged} />}
      </div>
    </Card>
  )
}

function FreeForm({ creds, kinds, onCreated, onTemplatesChanged }) {
  const api = useApi()
  const presence = usePresence()
  const prompt = usePrompt()
  const toast = useToast()
  const [form, setForm] = useState(() => freshForm(creds))
  const [saving, setSaving] = useState(false)
  const sent = useRef(null)
  const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v && v.target ? v.target.value : v }))

  const methods = form.methods.split(',').map((m) => m.trim()).filter(Boolean)
  const showAuto = autoWrites(form.approval, methods)
  const showNever = form.lifetime === 'never'
  const models = picksModel(form.picked, kinds)

  const operation = () => {
    const r = buildSessionBody(form, kinds)
    if (r.error) throw new Error(r.error)
    sent.current = r
    return presence.operationFor('session.create', r.body)
  }

  const saveTemplate = async () => {
    const r = buildSessionBody(form, kinds)
    if (r.error) { toast(r.error, { tone: 'warn' }); return }
    const name = await prompt.text({ title: 'Template name (lower case, digits and dashes)', placeholder: 'gh-read', submit: 'Save' })
    if (!name) return
    // The spec is the session this form would create, as it would send it.
    const body = { name, spec: r.body }
    setSaving(true)
    try {
      const op = await presence.operationFor('template.save', body)
      const saved = await presence.gated(op, (proof) => api.post('templates', { ...body, presence: proof }), { label: `save template ${name}` })
      const problems = (saved?.lint || []).length
      toast(`Saved template ${saved?.name ?? name} v${saved?.version ?? '?'}${problems ? `, ${problems} warning${problems > 1 ? 's' : ''}` : ''}`, { tone: 'ok' })
      onTemplatesChanged?.()
    } catch (e) {
      toast(e?.message || String(e), { tone: 'crit' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="space-y-5" onSubmit={(e) => e.preventDefault()} aria-label="New session">
      <CredentialPicker creds={creds} picked={form.picked} onChange={set('picked')} />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Field label="Label"><Input placeholder="issue triage" autoComplete="off" value={form.label} onChange={set('label')} /></Field>
        <Field label="Methods"><Input mono autoComplete="off" value={form.methods} onChange={set('methods')} /></Field>
        <Field label="Paths"><Input mono autoComplete="off" value={form.paths} onChange={set('paths')} /></Field>
        <Field label="Budget"><Input type="number" min={1} value={form.budget} onChange={set('budget')} /></Field>
        <Field label="Approval"><Select value={form.approval} onChange={set('approval')} options={APPROVAL_OPTIONS} /></Field>
        <Field label="Lifetime"><Select value={form.lifetime} onChange={set('lifetime')} options={LIFETIME_OPTIONS} /></Field>
        <Field label="Grant lifetime (minutes)" optional>
          <Input type="number" min={1} placeholder="as long as the session" value={form.grantTtl} onChange={set('grantTtl')} />
        </Field>
      </div>

      <Disclosure title="Advanced limits">
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Field label="Rate"><Input mono placeholder="60/min" autoComplete="off" value={form.rate} onChange={set('rate')} /></Field>
            <Field label="Concurrency"><Input type="number" min={1} placeholder="no limit" value={form.concurrency} onChange={set('concurrency')} /></Field>
            <Field label="Quota"><Input mono placeholder="1000/day" autoComplete="off" value={form.quota} onChange={set('quota')} /></Field>
            <Field label="Follow redirects (0–5)"><Input type="number" min={0} max={5} placeholder="0" value={form.redirects} onChange={set('redirects')} /></Field>
          </div>
          {models && (
            <div className="grid gap-4 sm:grid-cols-2" data-spend-box="">
              <Field label="Spend limit: tokens"><Input type="number" min={0} placeholder="no limit" value={form.spendTokens} onChange={set('spendTokens')} /></Field>
              <Field label="Spend limit: USD (an estimate)"><Input type="number" min={0} step="0.01" placeholder="no limit" value={form.spendUsd} onChange={set('spendUsd')} /></Field>
            </div>
          )}
          <Field label="Payload rules (JSON)" optional>
            <Textarea mono rows={3} placeholder='{ "json": { "/channel": { "one_of": ["#bots"] } } }' value={form.payload} onChange={set('payload')} />
          </Field>
          <Check checked={form.graphql} onChange={set('graphql')}>GraphQL: queries only</Check>
          <RoutesEditor routes={form.routes} onChange={set('routes')} />
        </div>
      </Disclosure>

      {showAuto && <Notice tone="warn" role="status">{AUTO_WARNING}</Notice>}
      {showNever && <Notice tone="warn" role="status">{NEVER_WARNING}</Notice>}

      <div className="flex flex-wrap gap-2">
        <GatedButton
          variant="primary"
          label={`create session ${form.label.trim() || 'ui session'}`}
          operation={operation}
          send={(proof) => api.post('sessions', { ...sent.current.body, presence: proof })}
          onDone={async (s) => { const picked = sent.current.picked; setForm(freshForm(creds)); await onCreated(s, picked) }}
        >
          Create session
        </GatedButton>
        <Button icon={BookmarkIcon} loading={saving} onClick={saveTemplate}>Save as template</Button>
      </div>
    </form>
  )
}

/** The same form over a template: its values are the ceiling, and only lower ones are offered. */
function TemplateForm({ t, onClear, onCreated }) {
  const api = useApi()
  const presence = usePresence()
  const L = t.limits
  const [chosen, setChosen] = useState(() => ({ label: '', methods: L.methods.slice(), approval: '', budget: '', lifetime: 'template', grantTtl: '' }))
  const sent = useRef(null)
  const set = (k) => (v) => setChosen((c) => ({ ...c, [k]: v && v.target ? v.target.value : v }))
  const elevated = t.elevated || []

  const approvalOptions = [
    { value: '', label: 'as the template says' },
    ...APPROVAL_ORDER.map((m, i) => ({ value: m, label: m, disabled: i < L.approvalFloor })),
  ]
  const lifetimeOptions = [
    { value: 'template', label: `as the template says (${L.infinite ? 'no expiry' : `${L.ttlHours} hours`})` },
    ...[1, 8, 24].map((h) => ({ value: String(h), label: `${h} hour${h > 1 ? 's' : ''}`, disabled: !L.infinite && h > L.ttlHours })),
  ]

  const operation = () => {
    const r = templateSessionBody(t, { ...chosen, label: chosen.label.trim() })
    if (r.error) throw new Error(r.error)
    sent.current = r
    return presence.operationFor('session.create', r.body)
  }

  return (
    <div className="space-y-5">
      <Notice tone="info">
        Starting from template <strong>{cleanLine(t.name)}</strong> v{t.version} for <span className="font-mono">{cleanLine(L.creds.join(', ')) || 'its credentials'}</span>. These fields can only narrow it.
      </Notice>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <Field label="Label"><Input placeholder="from the template" autoComplete="off" value={chosen.label} onChange={set('label')} /></Field>
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1.5 text-sm font-medium text-ink">Methods</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-1.5">
            {L.methods.map((m) => (
              <Check key={m} mono checked={chosen.methods.includes(m)} onChange={(on) => set('methods')(on ? [...chosen.methods, m] : chosen.methods.filter((x) => x !== m))}>{m}</Check>
            ))}
          </div>
        </fieldset>
        <Field label="Approval"><Select value={chosen.approval} onChange={set('approval')} options={approvalOptions} /></Field>
        <Field label="Budget">
          <Input type="number" min={1} max={L.budget ?? undefined} placeholder={L.budget !== null ? `up to ${L.budget}` : 'as the template says'} value={chosen.budget} onChange={set('budget')} />
        </Field>
        <Field label="Lifetime"><Select value={chosen.lifetime} onChange={set('lifetime')} options={lifetimeOptions} /></Field>
        <Field label="Grant lifetime (minutes)">
          <Input type="number" min={1} max={L.grantTtl ?? undefined} placeholder={L.grantTtl !== null ? `up to ${L.grantTtl}` : 'as long as the session'} value={chosen.grantTtl} onChange={set('grantTtl')} />
        </Field>
      </div>
      {elevated.includes('approval_auto_writes') && <Notice tone="warn">{AUTO_WARNING}</Notice>}
      {elevated.includes('infinite') && <Notice tone="warn">{NEVER_WARNING}</Notice>}
      <div className="flex flex-wrap gap-2">
        <GatedButton
          variant="primary"
          label={`create session from template ${t.name}`}
          operation={operation}
          send={(proof) => api.post('sessions', { ...sent.current.body, presence: proof })}
          onDone={(s) => onCreated(s, sent.current.picked)}
        >
          Create from template
        </GatedButton>
        <Button onClick={onClear}>Do not use a template</Button>
      </div>
    </div>
  )
}
