# Application browser startup boundary

This milestone runs the actual application and console entrypoints in a
sandboxed browser against the isolated nginx runtime. It uses the immutable
application-profile context produced by the fresh-install boundary. The shared
checkout's normal bootstrap may run afterward to provide diagnostic tooling;
it does not rebuild or alter the application context under test.

## Qualification scope

The two positive routes are `/login?next=%2Fconsole&lng=en` and
`/console?lng=en`. Each receives a new browser context with no existing cookies,
disabled resource caching and service-worker bypass. Both must load the actual
production document, scripts and SDK WASM, become `app-ready`, populate the React
root and render the visible **Sign-in is temporarily unavailable** heading.
The enabled **Retry sign-in check** button is clicked and must perform another
real session check while preserving the current route and requested destination.

No gateway is attached to this static runtime. Its production nginx configuration
still routes `/v1/auth/me` to the gateway name. A real 502 response or the
application's bounded 15-second abort therefore leaves session status
unconfirmed. The test requires the unavailable state; it must not claim a
confirmed anonymous user, navigate to an identity provider or make authenticated
console requests. This is browser startup and error-state qualification, not
successful sign-in or an OIDC journey.

The worker also opens a third fresh context and aborts only the exact SDK WASM
request. The public entrypoint must remain unmounted and display its actual
startup recovery UI with an enabled **Reload page** button. No response body or
application result is substituted. This negative control establishes that the
positive application startup actually depends on its SDK initialization.

The console document now includes the same startup recovery markup and styles
as the public entrypoint, driven by the unchanged `startup.js`. The existing
recovery suite exercises both documents and is included in the selected
application test roster. This closes the console's missing recovery surface;
the browser gate still uses two positive routes and one public WASM-negative
control.

## Source and resource binding

`ui/scripts/application-browser-startup.mjs` receives only the live loopback
origin owned by the runtime checker and the exact validated context/hash. It
does not create a Vite server, perform another build, add a backend, or own a
Docker container. The existing production nginx configuration, digest-pinned
base image and startup hook remain selected.

Every observed document and allowed asset response must match the expected
context bytes and content type, accounting for the already-reviewed default
runtime-config/HTML transformations. The SDK WASM must arrive freshly from
nginx with its exact expected byte count, SHA-256 and `application/wasm` type.
The main document must retain the reviewed enforcing production CSP. Browser
CSP and sandbox bypasses are not permitted.

The application and console entrypoints import the shared bootstrap/API graph.
The released SDK awaits its actual WASM initialization at module scope before
constructing the native API client. The observed mounted application, exact
WASM response and abort-WASM negative control together distinguish execution
from a successful static download.

The request policy allows only the selected document, inventoried local assets,
the exact `/v1/auth/me` session check and embedded images. It blocks the known
external Google Fonts requests and records that limit. Font acquisition is not
needed for the application's bounded readiness transition. Unexpected external
requests, writes, redirects, windows, module failures, page errors or unclassified
console failures fail the check. Expected backend failure is classified narrowly
against the actual session request; it is not a general error suppression.

## Browser and process ownership

Puppeteer is already retained in the reviewed root and application package locks.
The explicit worker loads it only when browser startup is requested. Importing
the source-closure or static-runtime modules before checkout dependencies exist
does not resolve Puppeteer. The browser uses the existing hosted `chrome` channel
with its ordinary sandbox; neither `--no-sandbox` nor a privileged helper is
introduced. The report records the actual Puppeteer, Node and browser versions.

The worker loads the runtime-context helpers only inside its explicit
qualification function. Its observation validators do not import the runtime
entrypoint during module evaluation. This matters when the standalone runtime
CLI loads those validators while awaiting the completed browser gate: a static
import back to that still-evaluating CLI would deadlock module evaluation.
Independent-process CLI fixtures cover this path, including completion,
cleanup and failed diagnostics; ordinary in-process unit imports cannot expose
that lifecycle failure.

Puppeteer starts Chromium in a separate Linux process session. Killing only the
Node worker's process group would leave a gap if launch failed or the worker
died before returning a browser object. The thin
`ui/scripts/application-browser-process.py` bridge therefore reuses
`scripts/installer_startup_process.py`, the existing kernel-subreaper process
owner. The guardian is enabled before launching the worker. It adopts detached
descendants, signals only owned children with PID identity protection, reaps
them and requires an empty kernel child set before returning success.

The browser worker has its own deadline and bounded browser/context shutdown.
The outer owner independently bounds the entire worker and its descendants.
The Python bridge executes in an isolated interpreter and compiles the exact
guardian source bytes whose SHA-256 is recorded. Node/Python injection settings
are excluded; the caller's `HOME` is preserved. The guardian and bridge are
explicit diagnostic-tool dependencies, outside the shipped nginx context.

A cleanup-pending or unknown-ownership result cannot publish a successful report.
The existing isolated owner remains responsible for late cleanup, and its
temporary browser profile is preserved while ownership remains unresolved.
Ordinary timeouts never kill that subreaper to shorten the wait. The runtime
checker independently attempts both container and image cleanup even if the
browser fails, and revalidates the closed context on success and failure.
If its controller cannot exit, the outer call stops waiting after a separate
two-second cancellation window and reports cleanup as unproven. It closes only
its own observation handles and preserves the still-owned temporary state.

Focused process tests exercise real detached children after an immediately
successful worker exit, an immediately failed exit before any launch journal,
and a deadline. Those are ownership tests; they do not claim that Chrome or
Docker ran.

## Invocation and CI order

After normal UI dependencies are available, run from `ui/`:

```sh
node scripts/application-runtime-context.mjs \
  --context /absolute/application-profile-runtime-context \
  --report /absolute/application-browser-runtime.json \
  --check-container \
  --browser-startup \
  --browser-report /absolute/application-browser-startup.json \
  --browser-channel chrome
```

Both reports must be new, distinct JSON files outside the context. The optional
browser flags require the separate browser report and explicit `chrome` channel.
Without them, the existing static-runtime version 1 behavior and report shape
are unchanged.

The required Website Surface lane preserves all five pre-bootstrap gates:
full-profile fresh installation and runtime, selected-profile audit, and
application-profile fresh installation and runtime. After the existing bootstrap,
the browser gate replays that already-qualified application context in another
owned diagnostic container. It does not borrow application files from the
subsequently bootstrapped checkout.

## Evidence and remaining gates

Successful browser evidence remains private until worker descendants, browser
contexts/profile, container and image cleanup have completed. The runtime
checker independently validates its routes, source,
context, exact served origin, SDK/resource identities and diagnostic-tool input
hashes before publishing the separate browser report. The runtime version 1
report adds an optional extension binding that report's exact byte count and
SHA-256. The browser report records the runtime image/context identities and
cleanup alongside its observed routes and negative control.

After valid browser-mode setup, handled failures produce two explicitly failed
diagnostic reports after both independent runtime cleanup attempts and context
revalidation. Every qualification flag is false. The reports retain the original
context/source identity, bounded failure stage and messages, observed cleanup
results and whether the context remained unchanged. A verified process-owner
result can prove descendant cleanup even when the worker failed; missing or
unverified ownership never implies cleanup. Unresolved browser state remains in
its owned temporary directory. The runtime failure report binds the browser
diagnostic bytes and hash, and the command still exits unsuccessfully.

Invalid preflight inputs do not create reports. Static-only failure behavior
remains unchanged. These failed artifacts make the always-run CI upload useful
without allowing a failed browser run to acquire passing qualification.

Injected Docker, browser-worker or browser-driver fixtures are labeled
`fixture-passed`; none can set actual browser or SDK execution flags. Actual
browser execution may set `browser_startup_observed` and
`sdk_wasm_initialized_in_browser` only after the complete real gate succeeds.
Candidate PR evidence records that execution separately from focused tests.
The reports continue to keep host deployment, OIDC journey, image publication
and activation false. They are diagnostic evidence and do not replace the
selected signed release or composition authority.
