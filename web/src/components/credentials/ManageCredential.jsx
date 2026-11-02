import { Button } from '../ui/Button.jsx'
import { Modal } from '../ui/Modal.jsx'
import { CredentialName } from './CredentialsTable.jsx'
import { ExpiryEditor } from './ExpiryEditor.jsx'
import { ScrubRules } from './ScrubRules.jsx'

/**
 * The two things the old page kept under each row (scrub patterns and expiry),
 * in one dialog per credential. `c` is the credential as the list has it now,
 * so a change shows here as soon as the list is read again.
 */
export function ManageCredential({ c, sample, onSample, onClose, onChanged }) {
  return (
    <Modal
      open={Boolean(c)}
      onClose={onClose}
      size="lg"
      title={c ? <CredentialName c={c} /> : ''}
      description="Changes here are signed with Touch ID, each over exactly what it sends."
      footer={<Button onClick={onClose}>Done</Button>}
    >
      {c && (
        <div className="space-y-6">
          <ScrubRules c={c} sample={sample} onSample={onSample} onChanged={onChanged} />
          <div className="border-t border-line pt-5">
            <ExpiryEditor c={c} onChanged={onChanged} />
          </div>
        </div>
      )}
    </Modal>
  )
}
