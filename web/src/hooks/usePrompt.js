// Promise-shaped dialogs the page draws itself, never window.prompt or
// window.confirm (prompt() would show a passphrase in clear text).
//
//   const prompt = usePrompt()
//   const pass = await prompt.secret({ title: 'Vault passphrase' })   // null on cancel
//   const ok = await prompt.confirm({ title: 'Lock the vault?', body: '...', danger: true })
//   const reason = await prompt.text({ title: 'Reason', placeholder: '...' })

import { createContext, useContext } from 'react'

export const PromptContext = createContext(null)

export function usePrompt() {
  const ctx = useContext(PromptContext)
  if (!ctx) throw new Error('usePrompt needs a PromptContext provider (App.jsx)')
  return ctx
}
