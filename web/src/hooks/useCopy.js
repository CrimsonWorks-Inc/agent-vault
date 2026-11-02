// A copy button's action: lib/clipboard.js copyText, and on a refusal the
// same toast wherever the button is (a code block, the Markdown summary, the
// audit checkpoint).

import { useCallback } from 'react'
import { COPY_REFUSED, copyText } from '../lib/clipboard.js'
import { useToast } from './useToast.js'

/** `copy(text)` resolves true when the text was written, false when refused. */
export function useCopy() {
  const toast = useToast()
  return useCallback(async (text) => {
    try {
      await copyText(text)
      return true
    } catch {
      toast(COPY_REFUSED, { tone: 'warn' })
      return false
    }
  }, [toast])
}
