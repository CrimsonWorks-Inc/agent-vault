import { useRef } from 'react'
import { Button } from './Button.jsx'
import { Modal } from './Modal.jsx'

/**
 * Are you sure? Never window.confirm: a page-drawn dialog can say what will
 * happen, and cannot be answered by a script that stubs window.confirm.
 * Cancel has the initial focus, so Enter does not confirm by accident.
 */
export function ConfirmDialog({ open, title, body, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false, busy = false, onConfirm, onCancel, children }) {
  const cancelRef = useRef(null)
  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={title}
      description={body}
      initialFocus={cancelRef}
      footer={(
        <>
          <Button ref={cancelRef} onClick={onCancel}>{cancelLabel}</Button>
          <Button variant={danger ? 'panic' : 'primary'} loading={busy} onClick={onConfirm}>{confirmLabel}</Button>
        </>
      )}
    >
      {children}
    </Modal>
  )
}
