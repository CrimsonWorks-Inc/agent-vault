// The route table: one component per page id in lib/router.js PAGES.
// Page workers replace a page's own file; this table does not change.
import { Approvals } from './Approvals.jsx'
import { Audit } from './Audit.jsx'
import { Containment } from './Containment.jsx'
import { Credentials } from './Credentials.jsx'
import { Docs } from './Docs.jsx'
import { Notifications } from './Notifications.jsx'
import { Overview } from './Overview.jsx'
import { Sessions } from './Sessions.jsx'
import { Settings } from './Settings.jsx'
import { Templates } from './Templates.jsx'

export const PAGE_COMPONENTS = {
  overview: Overview,
  approvals: Approvals,
  credentials: Credentials,
  sessions: Sessions,
  templates: Templates,
  audit: Audit,
  containment: Containment,
  notifications: Notifications,
  settings: Settings,
  docs: Docs,
}
