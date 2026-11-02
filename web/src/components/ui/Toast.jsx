import { useCallback, useMemo, useRef, useState } from 'react'
import { CheckCircleIcon, ExclamationTriangleIcon, InformationCircleIcon, XCircleIcon, XMarkIcon } from '@heroicons/react/20/solid'
import { ToastContext } from '../../hooks/useToast.js'
import { cx } from '../../lib/cx.js'

const ICONS = { ok: CheckCircleIcon, warn: ExclamationTriangleIcon, crit: XCircleIcon, info: InformationCircleIcon }
const INK = { ok: 'text-ok', warn: 'text-warn', crit: 'text-crit', info: 'text-accent' }

/**
 * Holds the toasts and renders them in a polite live region. A toast stays
 * longer when it reports a failure, because those are the ones people need to
 * read twice.
 */
export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const next = useRef(0)

  const dismiss = useCallback((id) => setItems((xs) => xs.filter((x) => x.id !== id)), [])
  const toast = useCallback((message, { tone = 'info', ms } = {}) => {
    const id = ++next.current
    setItems((xs) => [...xs.slice(-3), { id, message: String(message), tone }])
    setTimeout(() => dismiss(id), ms ?? (tone === 'crit' || tone === 'warn' ? 7000 : 3200))
    return id
  }, [dismiss])
  const value = useMemo(() => Object.assign(toast, { dismiss }), [toast, dismiss])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div aria-live="polite" role="status" className="pointer-events-none fixed inset-x-0 bottom-0 z-[60] flex flex-col items-center gap-2 p-4 sm:items-end">
        {items.map((t) => {
          const Icon = ICONS[t.tone] || ICONS.info
          return (
            <div key={t.id} className="pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-card border border-line bg-surface px-4 py-3 text-sm text-ink shadow-raised">
              <Icon aria-hidden="true" className={cx('mt-0.5 size-5 shrink-0', INK[t.tone] || INK.info)} />
              <p className="min-w-0 flex-1 break-words">{t.message}</p>
              <button type="button" onClick={() => dismiss(t.id)} className="text-muted hover:text-ink" aria-label="Dismiss">
                <XMarkIcon aria-hidden="true" className="size-4" />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}
