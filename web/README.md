# web/: the agent-vault control page

The source of the page `agent-vault ui` serves. It is built into `src/ui/dist`, and that build is committed: the npm package ships the build, not this folder, and has no runtime dependencies (contract D2). `web/BRAND.md` has the look.

```sh
npm ci                 # the exact devDependencies from package-lock.json
npm run build:ui       # web/ -> src/ui/dist (commit it with the source change)
npm run check:ui       # does src/ui/dist equal a fresh build? (prepack runs this)
npm run test:ui        # node --test web/test + vitest for components
npm test               # everything, the UI included
```

## Layout

| Path | What it holds |
|---|---|
| `src/lib/` | Plain JS, no JSX, tested with `node --test`: `api.js` (the only fetch), `presence.js` (WebAuthn, byte-identical to app.html), `paging.js`, `text.js`, `format.js`, `router.js`, `theme.js`, `notify.js`, `cache.js` |
| `src/hooks/` | `useApi`/`useApiQuery`, `usePaged`, `usePresence`, `usePolling`, `useAction`, `usePrompt`, `useToast`, `useVault` |
| `src/components/ui/` | The primitives. Pages use these, never raw Headless UI or long class strings |
| `src/components/<feature>/` | Pieces composed for one page (`overview/`) |
| `src/layouts/` | `AppLayout` (sidebar, header, drawer) and `CenteredLayout` (No session, Cannot reach the daemon) |
| `src/pages/` | One file per route. `pages/index.js` is the route table |
| `src/styles/theme.css` | The only place colours, fonts, radii and shadows are defined |
| `test/` | Node tests: lib, U7 invariants, drift, brand, package |
| `scripts/` | `build-ui.mjs`, `check-dist.mjs`, `compare-trees.mjs`, and dev-only `dev-vault.mjs` and `screenshots.mjs` |

## Looking at it

**Against a throwaway vault (recommended).** Never your real vault:

```sh
npm run build:ui
node web/scripts/dev-vault.mjs --enrolled          # prints {"page": "http://127.0.0.1:5180/", ...}
```

It creates a temp vault with fake credentials, 64 sessions, over 200 audit records and 3 waiting session requests. It starts a daemon and the real UI server (`src/ui/server.js`), claims the session itself, and serves `src/ui/dist` under the strict CSP with `/api` proxied. It reads the dist on every request, so rebuild and reload. Flags: `--locked`, `--pending N`, `--port N`.

**Screenshots** (headless Chrome over DevTools; it fails on any CSP violation and reports horizontal overflow):

```sh
node --experimental-websocket web/scripts/screenshots.mjs \
  --url http://127.0.0.1:5180/ --hash '#sessions' --out "$S/ui-shots/pages-a" --name sessions [--drawer] [--viewport]
```

It shoots light and dark at 1440 and 390 wide. Use `127.0.0.1`, not `localhost`: another dev server on `[::1]` can answer `localhost` instead.

**With hot reload** (`npm run dev:ui`): run `agent-vault ui` on a throwaway vault, open the link it prints (that sets the `av_ui` cookie for `localhost`), then open Vite's `http://localhost:5173`. `/api` is proxied to `AV_UI_PROXY` (default `http://localhost:7412`). Touch ID cannot complete from Vite's origin, because the UI server checks the WebAuthn origin.

## The rules the tests hold

- No `dangerouslySetInnerHTML`, `innerHTML`, `eval` or `new Function` in `src/`. Agent-written text goes through `<UntrustedText>`.
- No colour literal outside `styles/theme.css`.
- No raw bidi or control characters in any source file. Write `\u202e`, never the character itself.
- Every gated change goes through `GatedButton` or `usePresence().gated`. Both put "Touch ID to <operation>" on screen before the platform dialog opens.
- Browser storage holds the theme, the page size and the notifications switch, and nothing else.
- `src/ui/dist` equals a fresh build (`test/dist-drift.test.js`).
- Wherever the words `agent-vault` and another word sit together in page text, that word must be a real CLI command. `test/security/session-requests.test.js` scans `src/`, which includes the built bundle. Write "agent-vault, by ioLite Labs", never "agent-vault by …".
