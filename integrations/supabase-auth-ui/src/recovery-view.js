import { RECOVERY_MESSAGES } from "./recovery.js";

export function renderRecoveryView(document, root, state, actions) {
  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const content = document.createDocumentFragment();
  content.append(element("p", "eyebrow", "ACCOUNT RECOVERY"));
  const heading = element("h1"); heading.tabIndex = -1; content.append(heading);
  const intro = (text) => content.append(element("p", "intro", text));
  const button = (text, action, className = "secondary") => {
    const node = element("button", className, text); node.type = "button";
    node.disabled = state.busy; node.addEventListener("click", action); return node;
  };
  const field = (text, name, type, autocomplete) => {
    const wrapper = element("div", "field"), label = element("label", null, text), input = element("input");
    label.htmlFor = name; input.id = name; input.name = name; input.type = type;
    input.autocomplete = autocomplete; input.required = true; input.disabled = state.busy;
    wrapper.append(label, input); return { wrapper, input };
  };
  if (state.error) {
    const notice = element("p", "notice", RECOVERY_MESSAGES[state.error] ?? RECOVERY_MESSAGES.session);
    notice.setAttribute("role", "alert"); content.append(notice);
  }
  if (state.phase === "request") {
    heading.textContent = "Reset your password";
    intro("Enter your email address. If the account can be recovered, you will receive a one-time recovery link.");
    const form = element("form"), email = field("Email address", "recovery-email", "email", "username");
    email.input.maxLength = 254; email.input.spellcheck = false; email.input.autocapitalize = "none";
    const submit = element("button", "primary", state.busy ? "Requesting email…" : "Send recovery email");
    submit.type = "submit"; submit.disabled = state.busy;
    form.append(email.wrapper, submit);
    form.addEventListener("submit", (event) => { event.preventDefault(); void actions.requestEmail(email.input.value); });
    content.append(form);
    if (actions.register) {
      const accountActions = element("div", "actions");
      accountActions.append(button("New here? Create an account", actions.register));
      content.append(accountActions);
    }
  } else if (state.phase === "sent") {
    heading.textContent = "Check your email";
    intro("If the account can be recovered, you will receive a recovery email. Check your inbox and spam folder, and use the newest link.");
    content.append(element("p", "help", "If no message arrives, check the address you entered. If you have not created an account on this sign-in service, create one first."));
    const accountActions = element("div", "actions");
    accountActions.append(button("Return to sign in", actions.signIn));
    if (actions.register) accountActions.append(button("New here? Create an account", actions.register));
    content.append(accountActions);
  } else if (state.phase === "confirm") {
    heading.textContent = "Continue password recovery";
    intro("Continue to verify this one-time recovery link. Your password has not changed.");
    content.append(button("Continue password recovery", actions.confirmRecovery, "primary"));
  } else if (state.phase === "verifying") {
    heading.textContent = "Checking your recovery link";
    intro("Verifying this one-time link and your account’s required verification methods.");
  } else if (state.phase === "mfa") {
    heading.textContent = "Verify your authenticator";
    intro("Your enrolled authenticator is still required to change your password.");
    const form = element("form"), choice = element("div", "field"), label = element("label", null, "Authenticator"), select = element("select");
    label.htmlFor = "recovery-factor"; select.id = "recovery-factor"; select.disabled = state.busy;
    for (const factor of state.factors ?? []) {
      const option = element("option", null, factor.label); option.value = factor.id; select.append(option);
    }
    choice.append(label, select);
    const code = field("Verification code", "recovery-code", "text", "one-time-code");
    code.input.inputMode = "numeric"; code.input.pattern = "[0-9]{6}"; code.input.maxLength = 6;
    const submit = element("button", "primary", "Verify account"); submit.type = "submit"; submit.disabled = state.busy;
    form.append(choice, code.wrapper, submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault(); const value = code.input.value; code.input.value = ""; void actions.verifyTotp(select.value, value);
    });
    content.append(form);
  } else if (state.phase === "password") {
    heading.textContent = "Choose a new password";
    intro("Use at least 12 characters. Your enrolled verification methods stay required.");
    const form = element("form"), password = field("New password", "new-password", "password", "new-password"), confirmation = field("Confirm new password", "confirm-password", "password", "new-password");
    for (const item of [password, confirmation]) { item.input.minLength = 12; item.input.maxLength = 1024; }
    const submit = element("button", "primary", state.busy ? "Saving password…" : "Save password"); submit.type = "submit"; submit.disabled = state.busy;
    form.append(password.wrapper, confirmation.wrapper, submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault(); const value = password.input.value, repeated = confirmation.input.value;
      password.input.value = ""; confirmation.input.value = ""; void actions.savePassword(value, repeated);
    });
    content.append(form);
  } else if (state.phase === "saved") {
    heading.textContent = "Password saved";
    intro(state.busy ? "Returning to the application for a fresh sign-in…" : "Start a new sign-in from the application.");
    if (!state.busy) content.append(button("Return to sign in", actions.signIn));
  } else {
    heading.textContent = "Unable to use this recovery link";
    intro("Request a new email. Recovery links can expire and can only be used once.");
    if (state.error !== "configuration") content.append(button("Request a new recovery email", actions.restart));
  }
  root.setAttribute("aria-busy", String(state.busy));
  const phase = `recover-${state.phase}`, previous = root.dataset.phase;
  root.dataset.phase = phase; root.replaceChildren(content);
  if (phase !== previous) heading.focus({ preventScroll: true });
}
