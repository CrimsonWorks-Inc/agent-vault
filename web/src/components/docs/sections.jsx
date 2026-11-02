// The Docs page's sections, ported from the old page's DOCS (contract U5). The
// commands are built from this install's own daemon: its CLI name, its port
// and its first credential, so the reader can paste them without translating.
// `c` is { cli, gateway_port, cred } (pages/Docs.jsx docsContext).

import { B, C, Cmd, H3, P, Prose, UL } from './Prose.jsx'
import { RefusedTable } from './RefusedTable.jsx'

function How() {
  return (
    <Prose>
      <P>An agent that holds your API token can do anything that token can do, forever.
        agent-vault takes the token away and hands the agent a <B>placeholder</B> instead.</P>
      <P>A placeholder looks like this, and is not a secret:</P>
      <Cmd code="av1.k3m9q2x7n4p1.github_token.7hq2m4x8k1n6p3r9t5w2y7.a4f2c9" />
      <H3>Three things make it safe</H3>
      <UL>
        <li><B>It only works in one place.</B> Every credential declares where its
          value may be written: an <C>Authorization</C> header, an <C>x-api-key</C> header,
          a query parameter, a field in the JSON body. A placeholder found anywhere
          else is refused with <C>AV_BAD_LOCATION</C> and nothing is sent upstream.
          An agent that tries to paste it into a chat message or a file it is writing gets
          an error, not a token.</li>
        <li><B>It only works for one session.</B> A placeholder is bound to the
          session that issued it. Revoke the session and every placeholder it ever handed
          out stops working at once.</li>
        <li><B>It expires.</B> Ask for an n-use placeholder and the vault stops
          honouring it after n substitutions.</li>
      </UL>
      <H3>The real value never comes back</H3>
      <P>The daemon substitutes the credential on its way out and scrubs the response on
        its way back, so a token echoed by an upstream API does not reach the agent.
        The vault files are owned by a separate system user, so an agent running as you
        cannot read them even with full shell access.</P>
    </Prose>
  )
}

function Start({ c }) {
  return (
    <>
      <Prose>
        <P>Four steps. The first one asks for your password once; the rest do not.</P>
        <H3>1. Install the daemon</H3>
      </Prose>
      <Cmd code={`${c.cli} setup`} caption="Creates the _agentvault system user and starts the daemon at login." />
      <Prose>
        <H3>2. Store a credential</H3>
        <P>The value is read from the terminal, never from the command line, so it does not
          land in your shell history or in the process list.</P>
      </Prose>
      <Cmd code={`${c.cli} cred add`} caption="Walks you through it. Or pass the flags yourself:" />
      <Cmd code={`${c.cli} cred add gh-work --kind github`} />
      <Prose>
        <H3>3. Scope a session</H3>
        <P>A session says what the agent holding it may do: which credential, which methods,
          which paths, how many requests.</P>
      </Prose>
      <Cmd code={`${c.cli} session create`} caption="Walks you through it, then prints what to give the agent." />
      <Cmd code={`${c.cli} session create --cred ${c.cred} --methods GET,HEAD --paths "/repos/**" --budget 200`} />
      <Prose>
        <H3>3b. Let it write without asking</H3>
        <P>By default a session asks you before every write (<C>on-write</C>). To let the
          agent write without asking:</P>
      </Prose>
      <Cmd code={`${c.cli} session create --cred ${c.cred} --methods GET,POST --approval auto`} />
      <Prose>
        <P>auto means no approval prompts at all, including for writes. Because that takes you out of the loop for the life of the session, creating one asks for your passphrase or fingerprint every time, even inside the five-minute window, and is refused on a vault with no passphrase. Read-only sessions are unaffected: GET and HEAD never ask under on-write either.</P>
        <P>So a read-only <C>--approval auto</C> session needs no passphrase at all. The
          other modes are <C>each</C> (ask for every request) and <C>first-use</C> (ask
          once). One approval of a first request takes you out of every later write just
          the same, so <C>first-use</C> with any write method asks for your passphrase or
          fingerprint every time too.</P>
        <P>A session can also have no expiry: <C>--infinite</C> in place of <C>--ttl</C>.
          It lasts until you revoke it, is never reachable from a network listener, and asks
          for your passphrase or fingerprint every time you create one, for the same reason.</P>
      </Prose>
      <Cmd code={`${c.cli} session create --cred ${c.cred} --infinite`} caption="Revoke it when you are done: session revoke <sid>." />
      <Prose>
        <H3>3c. Tighter limits</H3>
        <P>A grant can carry more than methods, paths and a budget. Each of these only ever takes
          capability away, and each is under <B>Advanced limits</B> on the Sessions page too:</P>
        <UL>
          <li><B>Rate, concurrency and quota</B>: <C>--rate 60/min</C>, <C>--concurrency 4</C>,
            {' '}<C>--quota 1000/day</C>. Over the limit is <C>AV_QUOTA_EXCEEDED</C> with the seconds to wait.</li>
          <li><B>Routes</B>: <C>--route GET:/repos/**</C>, repeated, so a method is allowed
            only on its own paths.</li>
          <li><B>Payload rules</B>: <C>--payload-file F</C> constrains JSON fields, form
            fields and query parameters; <C>--graphql query</C> allows GraphQL queries and nothing
            else. Constrain the request&apos;s own fields, never the place the placeholder goes.</li>
          <li><B>Spend</B>, for model providers: <C>--spend-tokens 50000</C> or <C>--spend-usd 5</C>.
            The dollar figure is an estimate from a dated price table.</li>
          <li><B>Redirects</B>: <C>--redirects 2</C> follows up to two, each checked
            against the grant; none are followed by default.</li>
          <li><B>Grant lifetime</B>: <C>--grant-ttl 30</C> ends one credential&apos;s access
            after thirty minutes while the session goes on (<C>AV_GRANT_EXPIRED</C>).</li>
        </UL>
      </Prose>
      <Cmd code={`${c.cli} session create --cred ${c.cred} --methods GET,POST --rate 60/min --route GET:/repos/** --route POST:/repos/*/issues --grant-ttl 60`} />
      <Prose>
        <H3>3d. Save the shape as a template</H3>
        <P>A template is a session shape you wrote once and reuse: by name from the command line or the
          Sessions page, or named by an agent asking for a session. It is configuration, not standing
          approval: every session made from it still needs you, the fields on top of it can only narrow it,
          and if the template changes after you looked at it, the create is refused.</P>
      </Prose>
      <Cmd code={`${c.cli} template save gh-read --cred ${c.cred} --methods GET,HEAD\n${c.cli} session create --template gh-read`} />
      <Prose>
        <H3>4. Connect the agent</H3>
        <P>See <B>Connect your agent</B> for the three ways to do this.
          The shortest one is <C>{`${c.cli} mcp install --agent claude-code`}</C>.</P>
      </Prose>
    </>
  )
}

const MCP_TOOLS = [
  ['vault_status', 'is the vault reachable and unlocked'],
  ['vault_list_creds', 'what this session may use, and where each placeholder goes'],
  ['vault_get_placeholder', 'request one, with a reason you will see'],
  ['vault_http', 'make the request; the vault injects the credential'],
  ['vault_explain_denial', 'why that was refused, and what is allowed instead'],
  ['vault_request_session', null],
  ['vault_approval_status', 'whether you have answered a write that was held for you'],
  ['vault_describe_access', 'what this session may do right now: hosts, methods, paths, approval mode, budgets and limits, lifetimes, and where each placeholder goes. Read-only: it returns no secret, no token and no placeholder, and changes nothing'],
  ['vault_preflight', 'would this request be allowed, held for you, or refused? Nothing is sent upstream and nothing is spent; it is a prediction, and the real request is checked again'],
]

function Connect({ c }) {
  return (
    <>
      <Prose>
        <P>Three ways in, in the order you should try them.</P>
        <H3>1. MCP over stdio: the easy one</H3>
        <P>The vault writes itself into your agent&apos;s own config file. It merges rather than
          overwrites, keeps a backup, and running it twice changes nothing.</P>
      </Prose>
      <Cmd code={`${c.cli} mcp install --agent claude-code`} caption="Also: cursor, gemini, codex." />
      <Cmd code={`${c.cli} mcp install --agent codex --print`} caption="Show the block without writing anything." />
      <Prose>
        <P>Restart the agent afterwards. It gains nine tools:</P>
        <UL>
          {MCP_TOOLS.map(([name, what]) => (
            <li key={name}>
              <C>{name}</C>{' '}
              {what ? `— ${what}` : <>— ask you for a session; nothing exists until you approve it here or with <span className="font-mono text-[0.8125rem]">agent-vault approve</span></>}
            </li>
          ))}
        </UL>
        <P>The agent is told to call <C>vault_preflight</C> before a write it is unsure of, and
          {' '}<C>vault_describe_access</C> to learn its limits. A session request can name a template you
          saved, <C>{'vault_request_session { template }'}</C>, so you are shown a shape you wrote
          rather than a policy to read.</P>
        <P>No token is written to the config file: the bridge finds your current session
          from the state file, which is written whether you create the session here or with
          {' '}<span className="font-mono text-[0.8125rem]">agent-vault session create</span>. Only the session that was made
          most recently is there, so making a new one anywhere points the bridge at it.</P>
        <H3>2. MCP over HTTP: for an agent on another machine</H3>
        <P>The daemon speaks Streamable HTTP on the same port as the proxy.</P>
      </Prose>
      <Cmd code={`${c.cli} mcp url`} caption="Prints the endpoint and the Authorization header to use." />
      <Cmd code={`${c.cli} mcp install --agent cursor --transport http`} caption="Writes the HTTP form, reading the token from $AGENT_VAULT_SESSION at launch." />
      <Prose>
        <P>By default the daemon listens on loopback only. To reach it from elsewhere, add a
          listener explicitly, and treat that as opening a door. A listener on a network
          address must carry TLS; plaintext there would put session tokens and substituted
          credentials on the wire, so it is refused rather than warned about.</P>
      </Prose>
      <Cmd code={`${c.cli} listen add lan --address 10.0.0.5:${c.gateway_port} --surfaces gateway,mcp --tls managed`} />
      <Prose>
        <H3>As a custom connector</H3>
        <P>Claude Desktop and Claude Code refuse a connector URL that is not <C>https</C>,
          and there is <B>no exemption for loopback</B>. So even though nothing leaves this
          machine, the endpoint needs a certificate.</P>
        <P>The daemon generates one and keeps the private key behind its own uid. What you
          get back is the public certificate, which is also its own CA, so pointing the client
          at that file is what makes the listener trusted.</P>
      </Prose>
      <Cmd code={`${c.cli} tls setup`} caption="Generates the certificate and writes the trust anchor where you can read it." />
      <Cmd code={`${c.cli} listen add mcp-tls --address 127.0.0.1:7443 --surfaces mcp --tls managed`} caption="Only the mcp surface. A connector cannot reach the credential proxy through it." />
      <Cmd code={`${c.cli} mcp install --agent claude-code --transport http --tls`} />
      <Prose>
        <P>One more step, and it is the one people lose an afternoon to: a self-signed
          certificate is refused until the client is told to trust it, and Node does not read
          the macOS keychain by default. Set this in the environment the client launches
          with:</P>
      </Prose>
      <Cmd code={'export NODE_EXTRA_CA_CERTS="$HOME/.agent-vault/agent-vault-ca.pem"'} />
      <Prose>
        <P>Without it you get a bare TLS handshake failure that says nothing about
          certificates. With it, <C>https://localhost:7443/mcp</C> works.</P>
        <P>Note that this is for a client running <em>on this machine</em>. A connector added
          on claude.ai is opened from Anthropic&apos;s servers, not your browser, so a loopback
          address is unreachable: that would mean exposing the vault to the internet, which is
          a different decision entirely.</P>
        <H3>3. Environment variables: for anything else</H3>
        <P>Any agent that can make an HTTP request can use the vault, MCP or not.</P>
      </Prose>
      <Cmd code={`eval "$(${c.cli} env)"`} caption="Exports AGENT_VAULT_URL, AGENT_VAULT_SESSION and a placeholder." />
      <Cmd code={`${c.cli} exec -- <your agent command>`} caption="Same thing, but scoped to one child process, with stale real tokens stripped from its environment." />
      <Prose>
        <H3>Give a tool an env file</H3>
        <P>Most tools read a token from a variable of their own: <C>GH_TOKEN</C>,
          {' '}<C>OPENAI_API_KEY</C>. Map those names to credentials in a session, and the vault
          writes a placeholder under each one, plus the base URLs for credentials whose SDK
          reads one.</P>
      </Prose>
      <Cmd code={`${c.cli} env --out .env --map GH_TOKEN=${c.cred} --profile-vars`} />
      <Prose>
        <P>The file holds placeholders, which only work through this vault, and is written readable by you alone. It is never overwritten unless you say so.</P>
        <P>The session token is never written into it. <C>{'--map NAME=<slug>:base_url'}</C> maps
          a credential&apos;s gateway URL, <C>--map-file F</C> reads one <C>NAME=SPEC</C> per line,
          and <C>exec --map</C> does the same for one child process without writing a file.</P>
        <P>When a session holds two credentials for the same host, use the
          {' '}<C>{'/p/<credential>/'}</C> route: <C>/t/</C> picks the first grant for the
          host, and refuses the other credential&apos;s placeholder.</P>
        <P>The agent then makes requests through one of two routes:</P>
      </Prose>
      <Cmd
        code={`curl "$AGENT_VAULT_URL/p/${c.cred}/user" \\\n  -H "AV-Session: $AGENT_VAULT_SESSION" \\\n  -H "Authorization: Bearer $AGENT_VAULT_PLACEHOLDER"`}
        caption="/p/<credential>/<path>: the vault knows the host from the credential. The placeholder goes wherever the credential's usage says; Authorization: Bearer is the usual one."
      />
      <Cmd
        code={'curl "$AGENT_VAULT_URL/t/https/api.github.com/user" \\\n  -H "AV-Session: $AGENT_VAULT_SESSION" \\\n  -H "Authorization: Bearer $AGENT_VAULT_PLACEHOLDER"'}
        caption="/t/<scheme>/<host>/<path>: for a host you granted explicitly."
      />
    </>
  )
}

const MODELS = [
  ['Anthropic', 'anthropic-key', 'anthropic', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY'],
  ['OpenAI', 'openai-key', 'openai', 'OPENAI_BASE_URL', 'OPENAI_API_KEY'],
  ['Google Gemini', 'gemini-key', 'google-genai', 'GOOGLE_GEMINI_BASE_URL', 'GEMINI_API_KEY'],
]

function Models({ c }) {
  return (
    <>
      <Prose>
        <P>The same machinery works for the model API key the agent runs on, which is usually
          the most valuable secret on the machine. Store the key, then point the SDK&apos;s base URL
          at the vault and give it a placeholder instead of the key.</P>
        <P>Every one of these SDKs reads a base URL from the environment, so no code changes.</P>
      </Prose>
      {MODELS.map(([title, slug, kind, baseVar, keyVar]) => (
        <div key={slug}>
          <Prose><H3>{title}</H3></Prose>
          <Cmd code={[
            `${c.cli} cred add ${slug} --kind ${kind}`,
            `${c.cli} session create --cred ${slug} --methods GET,POST --budget 5000`,
            `eval "$(${c.cli} env)"`,
            `export ${baseVar}="$AGENT_VAULT_URL/p/${slug}"`,
            `export ${keyVar}="$AGENT_VAULT_PLACEHOLDER"`,
          ].join('\n')}
          />
        </div>
      ))}
      <Prose>
        <P>Each block makes its own session: a placeholder belongs to one
          credential, and one from the Anthropic session is refused by the OpenAI connector
          (AV_PH_WRONG_CONNECTOR).</P>
        <P>Each of these profiles already refuses the admin and organization paths that would
          let a key mint more keys, even under a grant of <C>/**</C>. You get a request
          budget and an audit trail as a side effect.</P>
      </Prose>
    </>
  )
}

function Locking({ c }) {
  return (
    <>
      <Prose>
        <P>There are two separate protections here, and they are easy to confuse.</P>
        <H3>The lock: can the vault be used at all</H3>
        <P>While locked, every proxied request is refused with <C>AV_LOCKED</C>. The
          lock survives restarts. Set a passphrase and the lock becomes cryptographic: the
          credential encryption key is wrapped with it, so a locked vault on a stolen disk is
          just ciphertext.</P>
      </Prose>
      <Cmd code={`${c.cli} passphrase set`} />
      <Cmd code={`${c.cli} lock\n${c.cli} unlock`} />
      <Prose>
        <P>Once a passphrase exists you can add <B>Touch ID unlock</B> from the
          Settings page. That is a real second factor, not a convenience: the authenticator
          returns a secret that unwraps the key, and only your fingerprint can produce it.
          Your passphrase stays as recovery, and the vault will not let you remove it while
          Touch ID is the only other way in.</P>
        <H3>Change confirmation: who may change what an agent can do</H3>
        <P>Separate from the lock. Adding a credential, creating a session, approving a
          request and revoking a session each need a fresh fingerprint, and the signature
          covers that one operation, so it cannot be replayed against a different one.</P>
        <P>This is what keeps an agent out of this page. An agent driving a browser can
          click every button here and reach the platform dialog, and stop, because it has no
          finger. Set it up on the Settings page.</P>
        <P>Enrolling that authenticator asks for your passphrase once, and only once. It is
          the one change a fingerprint cannot authorise, because the fingerprint being enrolled
          is the thing in question; otherwise anything that reached the vault could install its
          own key and use it to approve everything else. The daemon verifies each later
          signature itself and checks it against the operation in the request it received, so a
          page that shows one action and submits another is caught.</P>
        <P>To move to a new device or authenticator, use <B>Replace authenticator</B> on the
          Settings page. The new key is registered first, and enrolled only when the one you have now
          signs for it, so a replacement needs the old key, not just access to this page.</P>
        <P>Both factors work everywhere: the passphrase is what the command line uses, and a
          confirmed passphrase opens a five-minute window so you are not asked on every call.</P>
      </Prose>
    </>
  )
}

function Safety({ c }) {
  return (
    <>
      <Prose>
        <P>What to do when an agent does something you did not expect, and how to get your
          vault back if this machine does not come back.</P>
        <H3>End a session now</H3>
        <P>Revoking a session ends it and every placeholder it handed out, at once, whatever
          lifetime it was given.</P>
        <P>Revoking: agent-vault session revoke &lt;sid&gt;, or Panic, ends an infinite session like any other.</P>
      </Prose>
      <Cmd code={`${c.cli} session revoke <sid>`} />
      <Prose>
        <H3>Narrow it instead</H3>
        <P>A live session can be tightened without ending it: drop its writes, make every request wait
          for you, or give it an hour to live. A narrow is intersected with what the session already has,
          so it can never widen anything, and an endless session given a lifetime stops being endless. The
          Sessions page has the three common ones as buttons.</P>
      </Prose>
      <Cmd code={`${c.cli} session narrow <sid> --methods GET,HEAD\n${c.cli} session narrow <sid> --approval each --ttl 60`} />
      <Prose>
        <H3>Panic</H3>
        <P>Panic revokes every session, infinite ones included, denies every held request and every
          session request, and can lock the vault as well. Nothing comes back by itself: agents need new
          sessions afterwards. The Containment page has a Panic button, and it asks for no fingerprint, because
          in an emergency a prompt only slows you down.</P>
      </Prose>
      <Cmd code={`${c.cli} panic --lock --reason "agent went off script"`} />
      <Prose>
        <H3>Quarantine a credential</H3>
        <P>Quarantine stops every use of one credential at once (<C>AV_QUARANTINED</C>), and denies
          anything waiting on it. Its sessions are paused, not revoked: releasing it brings back the ones
          that are still live. Releasing needs your passphrase or fingerprint; quarantining does not.</P>
      </Prose>
      <Cmd code={`${c.cli} cred quarantine ${c.cred} --reason "odd traffic"\n${c.cli} cred release ${c.cred}`} />
      <Prose>
        <H3>Tripwires</H3>
        <P>Tripwires act for you when a session behaves like an attack: a replayed placeholder, a
          placeholder put where it does not belong, one session&apos;s placeholder used in another, or repeated
          attempts at paths you denied. The session is revoked before the refused request even returns.
          They are off until you turn them on. This page asks for your passphrase or fingerprint before
          it changes tripwires at all, turning them on included. From the command line, <C>tripwire on</C>{' '}
          needs nothing once rules are stored; the first time, it also stores the default rules, and that
          needs your passphrase or fingerprint. Turning them off or changing the rules always does.</P>
        <P>The trade, stated plainly: panic, quarantine and turning on tripwires whose rules are already
          stored are open to anything that can reach the vault, because each one only takes capability
          away. So an agent can end your sessions or quarantine a credential. That is a
          denial of service against your own work, and it is audited; it can never gain the agent anything.</P>
      </Prose>
      <Cmd code={`${c.cli} tripwire on\n${c.cli} tripwire show`} />
      <Prose>
        <H3>Rotate a credential</H3>
        <P>Rotation stores a new value under the same name. Sessions keep working with the new value, or,
          with <C>--revoke</C>, lose their grants at once. The old value stays scrubbed from responses
          for a while (a day by default), in case an upstream echoes it. Anything waiting for your approval
          on that credential is denied, because you approved it against the old key.</P>
      </Prose>
      <Cmd code={`${c.cli} cred rotate ${c.cred} --retire-hours 24`} />
      <Prose>
        <H3>Know when a token runs out</H3>
        <P>Record when a token expires, and the Overview page and <C>doctor</C> warn you a week
          ahead. It is a reminder, not a lock: an expired token is still sent until the upstream refuses
          it. <C>cred test</C> runs the connector&apos;s own read-only probe and records whether the
          token still works; GitHub also reports expiry in its responses, which the vault notices on
          its own.</P>
      </Prose>
      <Cmd code={`${c.cli} cred expiry ${c.cred} 2027-01-31\n${c.cli} cred test ${c.cred}`} />
      <Prose>
        <H3>Extra shapes to scrub, and pinned keys</H3>
        <P>Every stored value is already scrubbed from responses. A scrub pattern adds another shape of
          token to redact, for an upstream that hands out tokens of its own. A pin refuses any TLS key for
          a host that you did not pin, so nothing is sent through a proxy that intercepts TLS. Pins are set
          from the command line, where the live chain can be fetched and checked out of band; the
          Credentials page shows them.</P>
      </Prose>
      <Cmd code={`${c.cli} cred scrub ${c.cred} --add 'acme_[A-Za-z0-9]{20,40}' --sample 'token acme_...'\n${c.cli} cred pin ${c.cred} --host api.github.com --live`} />
      <Prose>
        <H3>Hear about it when something is waiting</H3>
        <P>A held request or a session request waits for you. <C>watch</C> prints each one the moment
          it arrives and shows a desktop notification; the Notifications page can do the same while its tab is
          open. A notice is a signal, never an approval: it carries what the daemon saw, never what the
          agent claimed, and it only opens Approvals. An optional webhook sends the same signal elsewhere:
          HTTPS only, counts and ids by default, and its URL is kept sealed like a credential.</P>
      </Prose>
      <Cmd code={`${c.cli} watch\n${c.cli} notify set --detail minimal`} />
      <Prose>
        <H3>Review what each session did</H3>
        <P>The detail view of a session, and <C>session show</C>, list what it may do, what it did,
          what was refused and what waited for you. The access review covers every session and points out
          methods that were granted and never used. Both say so when the audit log does not cover the
          whole period: missing records are never counted as no activity.</P>
      </Prose>
      <Cmd code={`${c.cli} session show <sid> --markdown\n${c.cli} report --since 7d`} />
      <Prose>
        <H3>Back up and restore</H3>
        <P>The backup is encrypted with a recovery passphrase that is not your vault passphrase. Sessions and placeholders are never backed up: after a restore, every agent needs a new session.</P>
        <P>Exporting asks for your passphrase every time, even inside the five-minute window, and is
          refused on a vault with no passphrase: a backup holds every secret, and an agent that could make
          one would choose its own recovery passphrase. Quarantines travel with the backup and stay in
          force after a restore.</P>
      </Prose>
      <Cmd code={`${c.cli} backup export --out vault-backup.json\n${c.cli} backup inspect vault-backup.json\n${c.cli} backup restore vault-backup.json --on-conflict rename`} />
      <Prose>
        <H3>Keep a witness</H3>
        <P>The audit log is hash-chained, so an edit is detectable. Removing records from the end is not,
          unless something outside the log remembers where the end was. A witness is that memory: a
          checkpoint of the head, authenticated with a key only this vault holds, appended to a file. Verify
          against it later, and a log that was cut short shows up.</P>
        <P>The honest limit: a witness file that an agent can write, it can truncate. Its value comes from
          being copied somewhere the agent cannot rewrite, such as another machine or a write-once store.
          The Audit page shows the head and copies a checkpoint for you.</P>
      </Prose>
      <Cmd code={`${c.cli} audit witness --out ~/.agent-vault/witness.jsonl\n# every hour, from cron:\n0 * * * * ${c.cli} audit witness\n${c.cli} audit verify --witness ~/.agent-vault/witness.jsonl`} />
    </>
  )
}

function Refused({ c }) {
  return (
    <>
      <Prose>
        <P>Every refusal carries a code and a suggested next step. The agent can ask
          {' '}<C>vault_explain_denial</C>, or you can read the audit log.</P>
      </Prose>
      <Cmd code={`${c.cli} audit tail --limit 40\n${c.cli} audit verify`} caption="The log is hash-chained; verify proves nothing was edited or removed." />
      <RefusedTable cli={c.cli} />
      <Prose className="mt-6"><H3>Nothing works at all</H3></Prose>
      <Cmd code={`${c.cli} doctor`} caption="Checks the daemon, the socket, permissions and the listeners." />
    </>
  )
}

/** The full command reference, aligned the way the CLI's help is. */
export function commandReference(cli) {
  const x = cli
  return `${x} setup                      install the daemon and its system user
${x} status                     is it running, and what is live
${x} doctor                     diagnose a broken install
${x} quickstart                 credential, session, and what to hand the agent

${x} cred add [slug] [--kind K] [--host H] [--expires YYYY-MM-DD]
                               store a credential (value read from the terminal)
${x} cred list | cred rm SLUG
${x} cred rotate SLUG [--field F] [--revoke] [--retire-hours N]
                               replace the value; sessions keep working
${x} cred test [SLUG | --all]   run the connector's read-only probe
${x} cred expiry SLUG YYYY-MM-DD|none
${x} cred scrub SLUG [--add PATTERN [--sample TEXT] | --rm ID]
${x} cred pin SLUG --host H [--add sha256/...] [--rm sha256/... | --clear] [--live]
${x} cred quarantine SLUG [--reason T] | cred release SLUG
${x} profiles                   the built-in connector kinds and their ceilings

${x} session create --cred S[,S...] [--methods GET,POST] [--paths "/repos/**"]
               [--budget N] [--uses N] [--approval each|on-write|first-use|auto]
               [--ttl HOURS | --infinite] [--label TEXT] [--grants-file F]
               [--template NAME] [--rate 60/min] [--concurrency N] [--quota 1000/day]
               [--route GET:/repos/**]... [--payload-file F] [--graphql query]
               [--redirects N] [--spend-tokens N] [--spend-usd X] [--grant-ttl MIN]
${x} session list | session revoke [SID]
${x} session narrow [SID] [--cred S] [any limit above] [--ttl MIN]
                               tighten a live session; it can never widen
${x} session show [SID] [--markdown]
${x} template save NAME --cred S [session flags] | template list
${x} template show NAME | template rm NAME
${x} ph next CRED [--uses N]    issue a placeholder
${x} ph check PLACEHOLDER       is it well formed (offline; not whether it is still live)
${x} ph pattern                 the regex that recognises one

${x} env                        shell exports for an agent
${x} env --out F [--force] [--map NAME=S[:base_url]]... [--map-file F] [--profile-vars]
                               an env file of placeholders, 0600, never replaced unasked
${x} exec [--map NAME=S]... -- COMMAND
                               run a command with those exports
${x} preflight --cred S --method M --path P [--body-file F]
                               would this request pass? nothing is sent
${x} mcp                        stdio transport
${x} mcp url                    the Streamable HTTP endpoint
${x} mcp install --agent AGENT  write the config for that tool

${x} approvals [--show ID] | approve ID | deny ID
${x} watch [--no-notify] [--open]
${x} notify set | notify show | notify off | notify test
${x} panic [--lock] [--reason T]
${x} tripwire show | tripwire on | tripwire off | tripwire set --rule ID ...
${x} audit tail [--limit N] | audit verify [--witness F]
${x} audit export [--since-seq N] [--out F] [--follow] | audit witness [--out F]
${x} report [--since 7d] [--markdown]
${x} backup export --out F | backup inspect F | backup restore F [--on-conflict skip|rename|fail]
${x} lock | unlock
${x} passphrase set | passphrase remove
${x} listen add ID --address HOST:PORT | listen list | listen rm ID
${x} ui                         open this page`
}

function Commands({ c }) {
  return (
    <>
      <Prose><P>Every command takes <C>--json</C> for a machine-readable envelope.</P></Prose>
      <div className="max-w-full">
        <Cmd code={commandReference(c.cli)} />
      </div>
    </>
  )
}

/** In the order the old page showed them; the ids are the `#docs/<id>` links. */
export const SECTIONS = [
  { id: 'how', title: 'How it works', Body: How },
  { id: 'start', title: 'Start here', Body: Start },
  { id: 'connect', title: 'Connect your agent', Body: Connect },
  { id: 'models', title: 'Route model keys', Body: Models },
  { id: 'locking', title: 'Locking', Body: Locking },
  { id: 'safety', title: 'Containment and recovery', Body: Safety },
  { id: 'refused', title: 'When a request is refused', Body: Refused },
  { id: 'commands', title: 'Commands', Body: Commands },
]
