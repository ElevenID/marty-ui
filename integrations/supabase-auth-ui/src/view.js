import { MESSAGES } from "./protocol.js";

const PERMISSIONS = Object.freeze({
  openid: ["Identify your account", "Use your account identity to sign you in."],
  email: ["View your email address", "Share your email address and its verification status."],
  profile: ["View your basic profile", "Share the basic profile information available from your account."],
  phone: ["View your phone information", "Share the phone information available from your account."],
  offline_access: ["Keep access between visits", "Allow the application to request access after this sign-in."],
});

export function renderView(document, root, state, actions) {
  const element = (tag, className, content) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = content;
    return node;
  };
  const button = (label, className, action, disabled = state.busy) => {
    const node = element("button", className, label);
    node.type = "button";
    node.disabled = disabled;
    node.addEventListener("click", action);
    return node;
  };
  const content = document.createDocumentFragment();
  content.append(element("p", "eyebrow", "ACCOUNT ACCESS"));
  const heading = element("h1");
  heading.tabIndex = -1;
  content.append(heading);
  const intro = (value) => content.append(element("p", "intro", value));
  const account = () => {
    const node = element("div", "account");
    node.append(element("span", "account-caption", "Signed in as"), element("span", "account-email", state.email));
    content.append(node);
  };
  const switchAccount = () => {
    const node = element("p", "switch");
    node.append(button("Use another account", "text-button", actions.switchAccount, false));
    content.append(node);
  };
  const notice = () => {
    if (!state.error) return;
    const node = element("p", "notice", MESSAGES[state.error] ?? MESSAGES.authorization);
    node.setAttribute("role", "alert");
    content.append(node);
  };
  const field = (labelText, id, type, autocomplete) => {
    const wrapper = element("div", "field");
    const label = element("label", null, labelText);
    label.htmlFor = id;
    const input = element("input");
    input.id = id;
    input.name = id;
    input.type = type;
    input.autocomplete = autocomplete;
    input.required = true;
    input.disabled = state.busy;
    wrapper.append(label, input);
    return { wrapper, input };
  };
  const destination = (origin) => {
    const node = element("p", "destination", "You will return to ");
    node.append(element("strong", null, origin), document.createTextNode("."));
    content.append(node);
  };

  if (state.phase === "signin") {
    heading.textContent = "Sign in to continue";
    intro("Sign in with an existing account to review this application request.");
    notice();
    const form = element("form");
    const email = field("Email address", "email", "email", "username");
    email.input.maxLength = 254;
    email.input.spellcheck = false;
    email.input.autocapitalize = "none";
    const password = field("Password", "password", "password", "current-password");
    password.input.maxLength = 1024;
    const submit = element("button", "primary", state.busy ? "Signing in…" : "Sign in");
    submit.type = "submit";
    submit.disabled = state.busy;
    form.append(email.wrapper, password.wrapper, submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const enteredPassword = password.input.value;
      password.input.value = "";
      void actions.signIn(email.input.value, enteredPassword);
    });
    content.append(form);
    if (actions.recover) {
      const accountActions = element("div", "actions");
      accountActions.setAttribute("role", "group");
      accountActions.setAttribute("aria-label", "Account help");
      accountActions.append(
        button("Forgot your password?", "secondary", actions.recover),
        button("Create an account", "secondary", actions.register),
        button("Set up an authenticator", "secondary", actions.security),
      );
      content.append(accountActions);
    } else content.append(element("p", "help", "Need an account, a password reset or authenticator setup? Contact your operator. This page supports existing, verified accounts."));
  } else if (state.phase === "checking") {
    heading.textContent = "Checking your account";
    intro("Verifying your sign-in and any required account verification.");
    const progress = element("div", "progress");
    progress.setAttribute("role", "status");
    const spinner = element("span", "spinner");
    spinner.setAttribute("aria-hidden", "true");
    progress.append(spinner, element("span", null, "Please keep this page open."));
    content.append(progress);
    switchAccount();
  } else if (state.phase === "mfa") {
    heading.textContent = "Verify it’s you";
    intro("Enter the current six-digit code from your enrolled authenticator app.");
    account();
    notice();
    const form = element("form");
    let factorId = state.selectedFactorId ?? state.factors[0].id;
    if (state.factors.length > 1) {
      const wrapper = element("div", "field");
      const label = element("label", null, "Authenticator");
      label.htmlFor = "factor";
      const select = element("select");
      select.id = "factor";
      select.disabled = state.busy;
      for (const factor of state.factors) {
        const option = element("option", null, factor.label);
        option.value = factor.id;
        select.append(option);
      }
      select.value = factorId;
      select.addEventListener("change", () => { factorId = select.value; });
      wrapper.append(label, select);
      form.append(wrapper);
    }
    const code = field("Verification code", "code", "text", "one-time-code");
    code.input.className = "code-input";
    code.input.inputMode = "numeric";
    code.input.pattern = "[0-9]{6}";
    code.input.maxLength = 6;
    code.input.minLength = 6;
    const submit = element("button", "primary", state.busy ? "Verifying…" : "Verify account");
    submit.type = "submit";
    submit.disabled = state.busy;
    form.append(code.wrapper, submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const enteredCode = code.input.value;
      code.input.value = "";
      void actions.verifyTotp(factorId, enteredCode);
    });
    content.append(form);
    switchAccount();
    content.append(element("p", "help", "If your authenticator is unavailable, contact your operator. Recovery and new authenticator enrollment are not available here."));
  } else if (state.phase === "consent") {
    heading.textContent = `Continue to ${state.details.label}?`;
    intro("Review what this application is asking to access. Allow access only if you started this sign-in.");
    if (state.details.providerName !== state.details.label) content.append(element("p", "provider-name", `Provider registration: ${state.details.providerName}`));
    account();
    content.append(element("p", "section-label", "Requested permissions"));
    const list = element("ul", "permissions");
    for (const scope of state.details.scopes) {
      const [label, description] = PERMISSIONS[scope] ?? ["Additional permission", "Review this permission with the application operator if you do not recognize it."];
      const item = element("li", "permission");
      const symbol = element("span", "permission-symbol", "+");
      symbol.setAttribute("aria-hidden", "true");
      const body = element("div");
      body.append(element("span", "permission-title", label), element("p", "permission-description", description), element("span", "scope-name", scope));
      item.append(symbol, body);
      list.append(item);
    }
    content.append(list);
    const buttons = element("div", "actions");
    buttons.append(button(state.busy ? "Completing your choice…" : "Allow access", "primary", () => actions.decide("approve")), button("Deny access", "secondary", () => actions.decide("deny")));
    content.append(buttons);
    switchAccount();
    destination(state.details.callbackOrigin);
  } else if (state.phase === "return") {
    heading.textContent = `Return to ${state.label}`;
    intro("Your provider reports that this application already has your consent. Continue to return to the application with this account.");
    account();
    const buttons = element("div", "actions");
    buttons.append(button(state.busy ? "Checking your account…" : `Continue to ${state.label}`, "primary", actions.continueToApp), button("Cancel this sign-in", "secondary", actions.cancel, false));
    content.append(buttons);
    switchAccount();
    destination(state.callbackOrigin);
    content.append(element("p", "help", "Cancelling closes this sign-in on this page. It does not revoke an earlier consent grant."));
  } else if (state.phase === "leaving") {
    heading.textContent = `Returning to ${state.label}`;
    intro("Your choice is complete. Opening the application…");
  } else {
    heading.textContent = state.error === "cancelled" ? "Sign-in cancelled" : "Unable to continue";
    notice();
    if (!state.restartRequired && !["configuration", "request", "cancelled", "restart"].includes(state.error)) content.append(button("Start sign-in again", "secondary", actions.switchAccount, false));
    if (state.restartRequired && !["restart", "cancelled"].includes(state.error)) content.append(element("p", "help", "Return to your application and start a new sign-in. This authorization request cannot be reused."));
    if (actions.security && ["mfa_incomplete", "mfa_unavailable"].includes(state.error)) content.append(button("Set up an authenticator", "secondary", actions.security, false));
  }
  root.setAttribute("aria-busy", String(state.busy));
  const previousPhase = root.dataset.phase;
  root.dataset.phase = state.phase;
  root.replaceChildren(content);
  if (previousPhase !== state.phase) heading.focus({ preventScroll: true });
}
