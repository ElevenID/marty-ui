// Keep this transport separate so the browser contract exercises the actual
// production form submission, including redirects enforced by form-action.
// Destination and proof are validated by nativeCallbackPost before this call.
export function postNativeCallback(document, window, { action, fields }) {
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
  try { window.HTMLFormElement.prototype.submit.call(form); }
  finally { form.remove(); }
}
