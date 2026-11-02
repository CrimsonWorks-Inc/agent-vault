import { useState } from 'react'
import { CheckIcon, ClipboardDocumentIcon } from '@heroicons/react/16/solid'
import { useCopy } from '../../hooks/useCopy.js'
import { Button } from '../ui/Button.jsx'

/**
 * Copy a longer text that is not on screen as a block (the Markdown summary):
 * "Copied" for a moment, or the page's one refusal toast (hooks/useCopy.js).
 */
export function CopyButton({ text, children = 'Copy', ...rest }) {
  const copyText = useCopy()
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    if (!(await copyText(typeof text === 'function' ? text() : text))) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  return (
    <Button size="sm" icon={copied ? CheckIcon : ClipboardDocumentIcon} onClick={copy} {...rest}>
      {copied ? 'Copied' : children}
    </Button>
  )
}
