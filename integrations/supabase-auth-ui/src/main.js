import { AuthController } from "./controller.js";
import { consumeAuthorizationRequest, safeError, validateConfig } from "./protocol.js";
import { createProviderClient } from "./sdk.js";
import { renderView } from "./view.js";

const root = document.getElementById("app");
let controller;
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
  const authorizationId = consumeAuthorizationRequest(window.location.href, (cleanUrl) => window.history.replaceState(null, "", cleanUrl));
  const response = await fetch("/config.json", { cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error("Configuration unavailable");
  const source = await response.text();
  if (source.length > 32_768) throw new Error("Configuration too large");
  const config = validateConfig(JSON.parse(source));
  document.getElementById("brand-name").textContent = config.brand;
  document.title = `Sign in · ${config.brand}`;
  controller = new AuthController({
    config,
    authorizationId,
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
} catch (error) {
  render({ phase: "blocked", busy: false, error: safeError(error, "configuration") });
}

window.addEventListener("pagehide", () => controller?.dispose());
window.addEventListener("pageshow", (event) => {
  // A back/forward-cache restore must not revive old consent or session state.
  if (event.persisted) window.location.reload();
});
