import { WrenchScrewdriverIcon } from '@heroicons/react/24/outline'
import { PAGES } from '../lib/router.js'
import { Card } from '../components/ui/Card.jsx'
import { EmptyState } from '../components/ui/EmptyState.jsx'
import { PageHeader } from '../components/ui/PageHeader.jsx'
import { CodeBlock } from '../components/ui/CodeBlock.jsx'
import { useVault } from '../hooks/useVault.js'

/** A page not yet ported to this app. Its file is replaced in wave 2. */
export function ComingSoon({ page }) {
  const { context } = useVault()
  const label = PAGES.find((p) => p.id === page)?.label || page
  return (
    <>
      <PageHeader eyebrow="agent-vault" title={label} />
      <Card>
        <EmptyState icon={WrenchScrewdriverIcon} title={`${label} is ported in wave 2`}>
          <p>This page is being rebuilt. Until it lands, the command line does everything it will:</p>
          <CodeBlock className="mt-3 text-left" code={`${context.cli} --help`} label="Copy the command" />
        </EmptyState>
      </Card>
    </>
  )
}
