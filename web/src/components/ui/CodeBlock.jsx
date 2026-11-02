import { useState } from 'react'
import { CheckIcon, ClipboardDocumentIcon } from '@heroicons/react/16/solid'
import { useCopy } from '../../hooks/useCopy.js'
import { copyable } from '../../lib/clipboard.js'
import { cx } from '../../lib/cx.js'

/**
 * Text to read or paste: a command, a JSON body, a Markdown summary. Shown as
 * text (never HTML), bidi removed as the copy is (lib/clipboard.js), with a
 * copy button. `label` names it for the copy button ("Copy the CLI line"). A
 * refused copy is a toast, as it is for every copy button.
 */
export function CodeBlock({ code, label = 'Copy', copy = true, wrap = false, className, inline = false }) {
  const copyText = useCopy()
  const [copied, setCopied] = useState(false)
  const doCopy = async () => {
    if (!(await copyText(code))) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  if (inline) return <code className={cx('rounded-[0.3rem] bg-sunken px-1.5 py-0.5 font-mono text-[0.8125rem] text-ink', className)}>{copyable(code)}</code>
  return (
    <div className={cx('group relative rounded-control border border-line bg-sunken', className)}>
      <pre className={cx('overflow-x-auto px-3.5 py-3 font-mono text-[0.8125rem] leading-relaxed text-ink', wrap ? 'whitespace-pre-wrap break-words' : 'whitespace-pre', copy && 'pr-24')}>{copyable(code)}</pre>
      {copy && (
        <button
          type="button"
          onClick={doCopy}
          className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-[0.375rem] border border-line bg-surface px-2 py-1 text-xs font-medium text-muted transition-colors hover:border-accent hover:text-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-focus"
          aria-label={copied ? 'Copied' : label}
        >
          {copied ? <CheckIcon aria-hidden="true" className="size-3.5" /> : <ClipboardDocumentIcon aria-hidden="true" className="size-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      )}
    </div>
  )
}
