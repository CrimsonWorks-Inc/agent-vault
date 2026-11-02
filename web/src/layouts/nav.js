// Icons for the sidebar, beside the page list in lib/router.js.
import {
  BellAlertIcon, BookOpenIcon, ClipboardDocumentListIcon, Cog6ToothIcon, DocumentDuplicateIcon,
  InboxStackIcon, KeyIcon, ShieldExclamationIcon, Squares2X2Icon, UserGroupIcon,
} from '@heroicons/react/20/solid'

export const NAV_ICONS = {
  overview: Squares2X2Icon,
  approvals: InboxStackIcon,
  credentials: KeyIcon,
  sessions: UserGroupIcon,
  templates: DocumentDuplicateIcon,
  audit: ClipboardDocumentListIcon,
  containment: ShieldExclamationIcon,
  notifications: BellAlertIcon,
  settings: Cog6ToothIcon,
  docs: BookOpenIcon,
}

/** Where a group divider sits in the sidebar: after these ids. */
export const NAV_GROUPS = [
  { title: 'Vault', ids: ['overview', 'approvals', 'credentials', 'sessions', 'templates'] },
  { title: 'Oversight', ids: ['audit', 'containment', 'notifications'] },
  { title: 'Setup', ids: ['settings', 'docs'] },
]
