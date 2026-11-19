import { useEffect, useState } from 'react'
import { useApi } from '../../hooks/useApi.js'
import { useToast } from '../../hooks/useToast.js'
import { folderProblem } from '../../lib/folders.js'
import { cleanLine } from '../../lib/text.js'
import { Button } from '../ui/Button.jsx'
import { Field } from '../ui/Field.jsx'
import { Input } from '../ui/Input.jsx'
import { Modal } from '../ui/Modal.jsx'

/**
 * File one or more credentials under a folder, or take them out of every
 * folder. Folders only organize: nothing here is signed, and every move is
 * in the audit log as cred.folder_set.
 */
export function MoveDialog({ slugs, current = '', folders = [], onClose, onDone }) {
  const api = useApi()
  const toast = useToast()
  const [path, setPath] = useState(current)
  const [busy, setBusy] = useState(false)
  const open = slugs.length > 0
  useEffect(() => { if (open) setPath(current) }, [open, current])
  const trimmed = path.trim()
  const problem = trimmed ? folderProblem(trimmed) : null
  const what = slugs.length === 1 ? cleanLine(slugs[0]) : `${slugs.length} credentials`

  const move = async (folder) => {
    setBusy(true)
    let done = 0
    try {
      for (const slug of slugs) {
        await api.post('credentials/folder', { slug, folder })
        done += 1
      }
      toast(folder ? `Moved ${what} to ${cleanLine(folder)}` : `Took ${what} out of its folder`, { tone: 'ok' })
      onDone?.()
      onClose()
    } catch (e) {
      toast(`${done ? `Moved ${done} of ${slugs.length}, then: ` : ''}${e?.message || String(e)}`, { tone: 'crit' })
      if (done) onDone?.()
    } finally { setBusy(false) }
  }

  return (
    <Modal
      open={open}
      onClose={busy ? () => {} : onClose}
      title={`Move ${what}`}
      description="Folders only organize the list. They change nothing an agent can reach."
      footer={(
        <>
          {current && <Button variant="ghost" disabled={busy} onClick={() => move(null)}>No folder</Button>}
          <span className="flex-1" />
          <Button disabled={busy} onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={busy} disabled={!trimmed || Boolean(problem)} onClick={() => move(trimmed)}>Move</Button>
        </>
      )}
    >
      <form onSubmit={(e) => { e.preventDefault(); if (trimmed && !problem) move(trimmed) }} className="space-y-3">
        <Field label="Folder" hint="Use / for subfolders, like clients/acme." error={problem}>
          <Input mono value={path} onChange={(e) => setPath(e.target.value)} placeholder="clients/acme" list="av-folder-paths" autoFocus />
        </Field>
        <datalist id="av-folder-paths">
          {folders.map((f) => <option key={f} value={f} />)}
        </datalist>
        {folders.length > 0 && (
          <div className="flex flex-wrap gap-1.5" aria-label="Existing folders">
            {folders.slice(0, 12).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setPath(f)}
                className="rounded-pill border border-line bg-sunken px-2 py-px font-mono text-[0.6875rem] text-muted hover:text-ink focus:outline-none focus-visible:outline-2 focus-visible:outline-focus"
              >
                {cleanLine(f)}
              </button>
            ))}
          </div>
        )}
      </form>
    </Modal>
  )
}
