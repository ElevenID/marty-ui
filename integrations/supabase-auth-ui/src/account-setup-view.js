import { SETUP_MESSAGES } from "./account-setup.js";

export function renderSetupView(document, root, state, actions) {
  const node = (tag, className, text) => {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text !== undefined) value.textContent = text;
    return value;
  };
  const content = document.createDocumentFragment();
  content.append(node("p", "eyebrow", "ACCOUNT SETUP"));
  const heading = node("h1"); heading.tabIndex = -1; content.append(heading);
  const intro = (text) => content.append(node("p", "intro", text));
  const button = (text, action, kind = "secondary") => {
    const value = node("button", kind, text); value.type = "button"; value.disabled = state.busy;
    value.addEventListener("click", action); return value;
  };
  const field = (text, id, type, autocomplete) => {
    const wrapper = node("div", "field"), label = node("label", null, text), input = node("input");
    label.htmlFor = id; input.id = id; input.name = id; input.type = type; input.autocomplete = autocomplete;
    input.disabled = state.busy; input.required = true; wrapper.append(label, input); return { wrapper, input };
  };
  if (state.error) {
    const notice = node("p", "notice", SETUP_MESSAGES[state.error] ?? SETUP_MESSAGES.setup);
    notice.setAttribute("role", "alert"); content.append(notice);
  }
  if (["register", "signin", "resend"].includes(state.phase)) {
    heading.textContent = state.phase === "register" ? "Create your account" : state.phase === "signin" ? "Set up your authenticator" : "Verify your email";
    intro(state.phase === "register" ? "Create an account, verify your email, then set up an authenticator. Organization and merchant access are granted separately."
      : state.phase === "signin" ? "Sign in with your verified email and password to set up your first authenticator. Existing verified factors will stay in place."
        : "Enter your email address to request a new verification link.");
    const form = node("form"), email = field("Email address", "setup-email", "email", "username");
    email.input.maxLength = 254; email.input.spellcheck = false; email.input.autocapitalize = "none";
    form.append(email.wrapper);
    let password, confirmation;
    if (state.phase !== "resend") {
      password = field("Password", "setup-password", "password", state.phase === "register" ? "new-password" : "current-password");
      password.input.maxLength = 1024;
      if (state.phase === "register") password.input.minLength = 12;
      form.append(password.wrapper);
      if (state.phase === "register") {
        confirmation = field("Confirm password", "setup-confirm-password", "password", "new-password");
        confirmation.input.minLength = 12; confirmation.input.maxLength = 1024; form.append(confirmation.wrapper);
      }
    }
    const submit = node("button", "primary", state.busy ? "Please wait…" : state.phase === "register" ? "Create account" : state.phase === "signin" ? "Sign in for setup" : "Send verification email");
    submit.type = "submit"; submit.disabled = state.busy; form.append(submit);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const secret = password?.input.value, repeated = confirmation?.input.value;
      if (password) password.input.value = "";
      if (confirmation) confirmation.input.value = "";
      if (state.phase === "register") void actions.register(email.input.value, secret, repeated);
      else if (state.phase === "signin") void actions.signIn(email.input.value, secret);
      else void actions.resendEmail(email.input.value);
    });
    content.append(form);
    if (state.phase === "signin") content.append(button("Request a verification email", actions.resend, "text-button"));
  } else if (state.phase === "sent") {
    heading.textContent = "Check your email";
    intro("If this address can be verified, a one-time verification email is on its way. Use the newest link.");
    content.append(button("Already verified? Set up an authenticator", actions.security));
  } else if (state.phase === "confirm") {
    heading.textContent = "Confirm your email";
    intro("Continue to verify this one-time email link. You will then sign in with your password for authenticator setup.");
    content.append(button("Confirm email address", actions.confirmEmail, "primary"));
  } else if (state.phase === "checking") {
    heading.textContent = "Checking your account";
    intro("Verifying your account and authenticator status.");
  } else if (state.phase === "offer") {
    heading.textContent = "Add your authenticator";
    intro("Use an authenticator app to generate the verification codes required for sign-in.");
    content.append(button("Set up authenticator", actions.beginEnrollment, "primary"));
    content.append(button("Cancel setup", actions.cancel, "text-button"));
  } else if (state.phase === "enroll") {
    heading.textContent = "Scan your setup code";
    intro("Scan this QR code in your authenticator app, save the account there, then enter its six-digit code.");
    const display = actions.enrollmentDisplay();
    if (display) {
      const qr = node("img", "enrollment-qr"); qr.src = display.qr; qr.alt = "Authenticator setup QR code";
      content.append(qr);
      content.append(button(state.showKey ? "Hide setup key" : "Show setup key instead", actions.toggleSetupKey, "text-button"));
      if (display.secret) content.append(node("code", "setup-key", display.secret));
    }
    const form = node("form"), code = field("Verification code", "enrollment-code", "text", "one-time-code");
    code.input.inputMode = "numeric"; code.input.pattern = "[0-9]{6}"; code.input.maxLength = 6;
    const submit = node("button", "primary", "Verify authenticator"); submit.type = "submit"; submit.disabled = state.busy;
    form.append(code.wrapper, submit);
    form.addEventListener("submit", (event) => { event.preventDefault(); const value = code.input.value; code.input.value = ""; void actions.verifyEnrollment(value); });
    content.append(form, button("Cancel setup", actions.cancel, "text-button"));
  } else if (["complete", "ready", "confirmed", "cancelled"].includes(state.phase)) {
    heading.textContent = state.phase === "confirmed" ? "Email verified" : state.phase === "cancelled" ? "Setup cancelled" : "Authenticator configured";
    intro(state.busy ? "Closing this setup session and opening the next sign-in step…" : "Start a fresh sign-in to continue.");
    if (!state.busy) content.append(button("Continue to sign in", actions.application));
  } else {
    heading.textContent = "Unable to complete setup";
    if (state.error !== "configuration") {
      content.append(button("Request a verification email", actions.resend));
      content.append(button("Start a fresh setup sign-in", actions.security, "text-button"));
    }
  }
  root.setAttribute("aria-busy", String(state.busy));
  const phase = `setup-${state.phase}`, previous = root.dataset.phase;
  root.dataset.phase = phase; root.replaceChildren(content);
  if (phase !== previous) heading.focus({ preventScroll: true });
}
