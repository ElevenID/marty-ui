import { AuthController } from "./controller.js";
import { consumeAuthorizationRequest, safeError, validateConfig } from "./protocol.js";
import { createProviderClient } from "./sdk.js";
import { renderView } from "./view.js";
import { consumeRecoveryRequest, RecoveryController } from "./recovery.js";
import { renderRecoveryView } from "./recovery-view.js";

const root = document.getElementById("app");
let controller;
const recoveryPage = window.location.pathname.startsWith("/account/");
let requestValidated = false;
const actions = {
  signIn: (...args) => controller.signIn(...args),
  switchAccount: () => controller.switchAccount(),
  verifyTotp: (...args) => controller.verifyTotp(...args),
  decide: (outcome) => controller.decide(outcome),
  continueToApp: () => controller.continueToApp(),
  cancel: () => controller.cancel(),
};
const render = (state) => renderView(document, root, state, actions);

try {
  const replaceLocation = (cleanUrl) => window.history.replaceState(null, "", cleanUrl);
  let request = recoveryPage ? consumeRecoveryRequest(window.location.href, replaceLocation)
    : consumeAuthorizationRequest(window.location.href, replaceLocation);
  requestValidated = true;
  const response = await fetch("/config.json", { cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error("Configuration unavailable");
  const source = await response.text();
  if (source.length > 32_768) throw new Error("Configuration too large");
  const config = validateConfig(JSON.parse(source));
  document.getElementById("brand-name").textContent = config.brand;
  document.title = `Sign in · ${config.brand}`;
  if (recoveryPage) {
    const recoveryActions = {
      requestEmail: (email) => controller.requestEmail(email),
      confirmRecovery: () => controller.confirmRecovery(),
      verifyTotp: (factor, code) => controller.verifyTotp(factor, code),
      savePassword: (password, confirmation) => controller.savePassword(password, confirmation),
      signIn: () => { controller.dispose(); window.location.replace(config.accountLifecycle.signInUri); },
      restart: () => { controller?.dispose(); window.location.replace("/account/recover"); },
    };
    const renderRecovery = (state) => renderRecoveryView(document, root, state, recoveryActions);
    controller = new RecoveryController({ config, mode: request.mode, tokenHash: request.tokenHash, origin: window.location.origin,
      createClient: createProviderClient, onChange: renderRecovery, navigate: (url) => window.location.replace(url) });
    document.title = `Account recovery · ${config.brand}`;
    renderRecovery(controller.state);
  } else {
    if (config.accountLifecycle) actions.recover = () => { controller.dispose(); window.location.replace("/account/recover"); };
    controller = new AuthController({
      config,
      authorizationId: request,
      createClient: createProviderClient,
      onChange: render,
      navigate: (url) => window.location.replace(url),
      postCallback: ({ action, fields }) => {
        // Top-level POST lets Auth set its application cookie without CORS or
        // third-party cookies. Tokens never enter a URL or rendered UI state.
        const form = document.createElement("form");
        form.method = "post";
        form.action = action;
        form.hidden = true;
        form.autocomplete = "off";
        for (const [name, value] of Object.entries(fields)) {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = name;
          input.value = value;
          form.append(input);
        }
        document.body.append(form);
        try { HTMLFormElement.prototype.submit.call(form); }
        finally { form.remove(); }
      },
    });
    render(controller.state);
  }
  request = null;
} catch (error) {
  if (recoveryPage) renderRecoveryView(document, root, { phase: "blocked", busy: false, error: requestValidated ? "configuration" : "request" }, {
    restart: () => window.location.replace("/account/recover"),
  });
  else render({ phase: "blocked", busy: false, error: safeError(error, "configuration") });
}

window.addEventListener("pagehide", () => controller?.dispose());
window.addEventListener("pageshow", (event) => {
  // A back/forward-cache restore must not revive old consent or session state.
  if (event.persisted) window.location.reload();
});
