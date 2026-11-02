// Short status lines ("Revoked", "Not confirmed. Nothing was changed.").
// components/ui/Toast.jsx renders them in an aria-live region.

import { createContext, useContext } from 'react'

export const ToastContext = createContext(null)

/** `toast(message, { tone: 'ok' | 'warn' | 'crit' | 'info' })` */
export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast needs a ToastContext provider (App.jsx)')
  return ctx
}
