import { PlusIcon } from '@heroicons/react/16/solid'
import { useToast } from '../../hooks/useToast.js'
import { Button } from '../ui/Button.jsx'
import { Input } from '../ui/Input.jsx'
import { Check } from './Check.jsx'
import { MAX_ROUTE_ROWS, ROUTE_METHODS } from './sessionLogic.js'

/** Routes: a method may only be used on its paths (F3), up to 16 rows. */
export function RoutesEditor({ routes, onChange }) {
  const toast = useToast()
  const set = (i, patch) => onChange(routes.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  const add = () => {
    if (routes.length >= MAX_ROUTE_ROWS) { toast(`At most ${MAX_ROUTE_ROWS} routes`, { tone: 'warn' }); return }
    onChange([...routes, { methods: [], paths: '' }])
  }
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium text-ink">Routes: a method may only be used on its paths (up to {MAX_ROUTE_ROWS})</legend>
      {routes.length > 0 && (
        <ul className="space-y-2">
          {routes.map((r, i) => (
            <li key={i} className="space-y-2 rounded-control border border-line p-3" aria-label={`Route ${i + 1}`}>
              <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                {ROUTE_METHODS.map((m) => (
                  <Check
                    key={m}
                    mono
                    checked={r.methods.includes(m)}
                    onChange={(on) => set(i, { methods: on ? [...r.methods, m] : r.methods.filter((x) => x !== m) })}
                  >
                    {m}
                  </Check>
                ))}
              </div>
              <div className="flex flex-col gap-2 sm:flex-row">
                <Input mono aria-label={`Paths for route ${i + 1}`} placeholder="/repos/*/issues, /user" autoComplete="off" value={r.paths} onChange={(e) => set(i, { paths: e.target.value })} />
                <Button size="md" onClick={() => onChange(routes.filter((_, j) => j !== i))}>Remove</Button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <Button size="sm" icon={PlusIcon} onClick={add}>Add route</Button>
    </fieldset>
  )
}
