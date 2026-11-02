// Credentials, at parity with app.html's (contract U5): the stored list,
// paged and searchable (U3), with test, rotate, scrub patterns, expiry,
// quarantine, release and remove on each row, and the form to add one.
// Pins are shown, read-only; they are set from the command line, where the
// live certificate chain can be checked (F11).

import { useCallback, useState } from 'react'
import { useApi, useSlowCache } from '../hooks/useApi.js'
import { usePaged } from '../hooks/usePaged.js'
import { Card } from '../components/ui/Card.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { Pagination } from '../components/ui/Pagination.jsx'
import { SearchInput } from '../components/ui/SearchInput.jsx'
import { AddCredentialCard } from '../components/credentials/AddCredentialCard.jsx'
import { CredentialsTable } from '../components/credentials/CredentialsTable.jsx'
import { ListError } from '../components/credentials/ListError.jsx'
import { ManageCredential } from '../components/credentials/ManageCredential.jsx'
import { RotateDialog } from '../components/credentials/RotateDialog.jsx'

export const CREDENTIAL_SEARCH_FIELDS = ['slug', 'id', 'kind', 'label']

export function Credentials() {
  const api = useApi()
  const slow = useSlowCache()
  const list = usePaged('credentials', { searchFields: CREDENTIAL_SEARCH_FIELDS })
  // The last probe and the last scrub sample, per credential, as app.html
  // kept them: they survive a re-read of the list, not a reload.
  const [tests, setTests] = useState(() => new Map())
  const [samples, setSamples] = useState(() => new Map())
  const [managing, setManaging] = useState(null)
  const [rotating, setRotating] = useState(null)


  const reload = list.reload
  const onTest = useCallback(async (slug) => {
    let result
    try { result = await api.post('credentials/test', { slug }) } catch (e) { result = { error: e?.message || String(e) } }
    setTests((m) => new Map(m).set(slug, result))
    slow.clear()
    await reload()
  }, [api, slow, reload])
  const onSample = useCallback((slug, sample) => setSamples((m) => {
    const next = new Map(m)
    if (sample) next.set(slug, sample)
    else next.delete(slug)
    return next
  }), [])

  const managed = managing ? list.items.find((c) => c.slug === managing) ?? null : null

  return (
    <>
      <PageHeader
        eyebrow="Vault"
        title="Credentials"
        description="The value is write-only. It goes straight to the daemon and is never sent back to this page. Pins are shown here and set from the command line, where the live certificate chain can be checked."
      />
      <div className="space-y-4">
        <Card
          title="Stored"
          description={list.total !== null && list.total !== undefined && !list.q ? `${list.total} credential${list.total === 1 ? '' : 's'}` : undefined}
          padded={false}
          actions={<SearchInput value={list.q} onChange={list.setQ} label="Search credentials" placeholder="Search name or kind" />}
        >
          {list.error ? (
            <ListError error={list.error} onRetry={reload} what="the credentials" />
          ) : (
            <CredentialsTable
              list={list}
              tests={tests}
              onTest={onTest}
              onManage={setManaging}
              onRotate={setRotating}
              onChanged={reload}
            />
          )}
          <div className="border-t border-line px-4">
            <Pagination {...list.pagination} label="Credentials pages" />
          </div>
        </Card>
        <AddCredentialCard onAdded={reload} />
      </div>
      <ManageCredential
        c={managed}
        sample={managed ? samples.get(managed.slug) : null}
        onSample={onSample}
        onClose={() => setManaging(null)}
        onChanged={reload}
      />
      <RotateDialog slug={rotating} onClose={() => setRotating(null)} onDone={reload} />
    </>
  )
}
