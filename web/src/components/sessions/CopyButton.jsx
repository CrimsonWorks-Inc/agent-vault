import { useState } from 'react'
import { CheckIcon, ClipboardDocumentIcon } from '@heroicons/react/16/solid'
import { useToast } from '../../hooks/useToast.js'
import { Button } from '../ui/Button.jsx'
import { copyable } from '../ui/CodeBlock.jsx'

/**
 * Copy a longer text that is not on screen as a block (the Markdown summary):
 * "Copied" for a moment, or app.html's words when the browser refuses.
 */
export function CopyButton({ text, children = 'Copy', ...rest }) {
  const toast = useToast()
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await globalThis.navigator.clipboard.writeText(copyable(typeof text === 'function' ? text() : text))
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch {
      toast('Your browser would not let the page copy. Select the text instead.', { tone: 'warn' })
    }
  }
  return (
    <Button size="sm" icon={copied ? CheckIcon : ClipboardDocumentIcon} onClick={copy} {...rest}>
      {copied ? 'Copied' : children}
    </Button>
  )
}
