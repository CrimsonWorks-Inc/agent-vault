// What the header always shows, whichever page is open: whether the vault is
// locked, and how many decisions are waiting. Polled every five seconds,
// The old page's refreshChrome.

import { createContext, useContext } from 'react'

export const VaultContext = createContext(null)

/** `{ locked, lockState, pending, pendingCount, refresh }` */
export function useVault() {
  const ctx = useContext(VaultContext)
  if (!ctx) throw new Error('useVault needs a VaultContext provider (App.jsx)')
  return ctx
}
