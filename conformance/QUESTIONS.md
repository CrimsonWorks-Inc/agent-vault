# Questions for the coordinator

The contract is the JavaScript daemon's actual behavior. The eight items below stay as the suite asserts them; the port will reproduce those quirks, and cleaning them up is a separate change after the port.

The suite matches the JavaScript daemon. These are places that JavaScript does not match the frozen contract's `--json` envelope, or where a refusal is easy to misread. `src/` was not changed.

1. `passphrase set --json` does not print `{ok, data}`. On success it prints the human line `passphrase set` and exits 0. `passphrase remove --json` also prints human text on the success path. That path is unreachable while the passphrase is the only human factor: remove then exits 6 with `{ok:false}` and the message that the last factor cannot be dropped.

2. `daemon` ignores `--json`. It prints the human `gateway http://127.0.0.1:<port>` lines and stays up until SIGTERM.

3. `setup --dev --json` prints an envelope only when the vault already exists (`{ok:true, data:{existed:true}}`). Creating the vault prints human text (`created <dir>`) and exits 0, with no envelope. `setup --json` without `--dev` does print the envelope and does not run sudo: `{mode:'system', command, installer, installed:false}` and the command starts with `sudo`.

4. `exec --json` does not wrap the child. The child's stdout is the process stdout (`child-ok` in the suite). A missing binary exits 127 with `{ok:false}`.

5. `preflight --json` prints a success envelope and then sets the exit code from `would`: 0 for allow, 10 for hold, 6 for a refusal. A caller that only checks `ok` will treat a held write as success.

6. `backup export` on a pipe cannot finish once a passphrase exists. `controlWithPresence` throws "needs your passphrase, and there is no terminal" before it reads the fresh-presence passphrase. With no factor enrolled it exits 5 after the two recovery lines, and the error envelope has no `code` because that path drops the problem object. The control route does the round trip when the body carries `presence.passphrase` and `recovery_passphrase`.

7. `cred test <slug> --json` for an `http` credential exits 7 with `{ok:false, error.code:'AV_NOT_FOUND'}` ("this connector has no probe"). `cred test --all --json` exits 0 and reports `rule: 'no_probe'` inside the success envelope. The control route is the same split: one slug is 404 `no_probe`; `{all:true}` is 200.

8. `POST /v1/sessions` with `{}` is 404 `AV_NOT_FOUND`, not `session_shape`. `session_shape` is what you get from sending `cred` and `grants` together. Rotating a credential to the value it already holds is 403 `AV_POLICY_DENIED` ("that is the value already stored"), so a rotation test has to supply a new value.
