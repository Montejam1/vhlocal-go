# Operator browser checks

These are browser tests, separate from the Go **source-string checks**. They have
not been run merely because Go tests or TypeScript compilation pass. Record an
actual execution as `machine_executed`, operator observations as `attested`, and
anything else as `not run`, including the browser version and build identity.

Prerequisites: an installed `@playwright/test` development package and Chromium
runtime. If needed, install explicitly with `npm install --no-save --package-lock=false
@playwright/test` and `npx playwright install chromium` in `web-react`. They are
test tools, not production dependencies. The implementation/offline gate never
downloads a browser or starts a model.

Build React with `npm run build`, then build Go so `/app` embeds the new assets.
Start that binary on a separate local port with temporary reports, ledger, log,
activity and queue paths; do not restart an active scanning server. Set
`VHLOCAL_BROWSER_URL=http://127.0.0.1:18421` and run `make browser-test` at the root.
All `/api/` requests in these tests are intercepted with synthetic data; no scan
is launched and no operator reports are changed.

The tests cover `/` and `/app`: summary order, search, keyboard selection and
captured evidence, switching reports while an old response is pending, and the
diagram corpus (render or isolated fallback without losing narrative). Inspect
the HTML test report and record failures; do not count skipped tests as passes.
