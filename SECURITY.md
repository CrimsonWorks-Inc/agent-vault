# Security

agent-vault holds credentials. If you find a way to get one out of it, or to
make it inject one somewhere it should not, that is a vulnerability and we want
to hear about it before anyone else does.

## Reporting

Email **eric@frozencrow.com** with `agent-vault security` in the subject. Please
do not open a public issue for anything that would let someone recover a
credential, bypass the human-presence gate, or execute code inside the daemon.

Useful to include, roughly in order of usefulness:

- A reproduction. A short script that demonstrates the problem is worth more
  than a description of it, and it is what tells us we have actually fixed it.
- Which attacker it assumes. Most interesting reports assume an agent running
  as the human — see the threat model in the README.
- The version, or the commit, and the Node version.

You will get an acknowledgement. This is a small project maintained by one
person, so a same-day reply is not a promise; a reply is.

## Scope

**In scope**, and the categories we care most about:

- Recovering a credential value by any route: the API, the MCP tools, the web
  UI, the audit log, an error message, a response that should have been
  scrubbed.
- Causing a substitution at a site the credential does not declare, or toward a
  host or path the grant does not allow.
- Widening capability without the human factor — creating or extending a
  session, grant, placeholder, credential, listener, or approving a held
  request.
- Getting code to run inside the privileged daemon, or reading the vault
  directory as the human's account.
- Forging, truncating, or erasing audit records without detection.

**Out of scope**, because they are documented rather than accidental — the
README's "Threat model" section says why:

- A vault with no passphrase and no enrolled authenticator. The control socket
  is open by design in that state, and every widening call is audited as
  `control.widening_ungated`.
- The first `sudo agent-vault-setup`. The installer is JavaScript in a
  directory you own, so the first install runs code an agent could have edited
  beforehand. Afterwards the root-owned copy is used.
- An agent spending what you granted it, within its budget, methods, paths and
  expiry. A grant is a grant.
- An upstream keeping a credential you sent it. Responses are scrubbed on the
  way back; the secret still reached the upstream, because that is the point.
- Denial of service against your own vault by something already running as you.
  It can lock the vault or revoke your sessions. It cannot read a credential.

If you think something in the out-of-scope list is worse than we have judged,
say so. Those boundaries are a claim about the design, and a claim can be wrong.

## What this project has and has not had

No third-party audit. Every finding so far was found by its own author, which is
the single best reason to be careful with it. The `Where the spec and the code
disagree` section of the README lists them, including the ones that were
serious, because a security tool that only publishes its wins is not telling you
anything.

Version 0.x. Do not store a credential here that you cannot rotate.
