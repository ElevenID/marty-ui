const byId = (id) => document.getElementById(id);
let applicationId = '';
let deliveryEvidencePolling = false;
let refreshTimer = null;

function short(value) {
  if (!value) return 'not returned';
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function renderStatus(element, icon, text) {
  const marker = document.createElement('span');
  marker.textContent = icon;
  element.replaceChildren(marker, document.createTextNode(` ${text}`));
}

function renderGatewayResult(element, allowed, result) {
  const summary = document.createElement('strong');
  summary.textContent = `${allowed ? 'Gateway accepted' : 'Gateway denied'} · HTTP ${result.status}`;
  const request = document.createElement('span');
  request.textContent = `Request ${short(result.requestId)}`;
  element.replaceChildren(summary, request);
}

function renderTimeline(element, activity) {
  if (!activity.length) {
    const empty = document.createElement('li');
    empty.className = 'empty';
    empty.textContent = 'Waiting for activity';
    element.replaceChildren(empty);
    return;
  }
  element.replaceChildren(...activity.map((item) => {
    const row = document.createElement('li');
    row.className = item.type;
    const title = document.createElement('strong');
    title.textContent = item.title;
    const detail = document.createElement('span');
    detail.textContent = item.detail;
    row.append(title, detail);
    return row;
  }));
}

function render(state) {
  applicationId = state.application.id;
  byId('application-id').textContent = short(applicationId);
  byId('application-status').textContent = state.application.status;
  byId('application-status').className = `status ${state.application.status === 'APPROVED' ? 'good' : 'neutral'}`;
  byId('gateway-origin').textContent = state.gatewayOrigin;
  byId('key-prefix').textContent = state.integration.runtimeKeyPrefix;
  byId('callback-url').textContent = state.integration.callbackUrl;
  byId('enrollment-status').textContent = state.enrollmentStatus;
  byId('webhook-status').className = `signature ${state.webhookEvents.length ? 'verified' : 'waiting'}`;
  renderStatus(byId('webhook-status'), state.webhookEvents.length ? '✓' : '○', state.webhookStatus);
  const receiverTest = byId('receiver-test-status');
  if (state.receiverTests?.lastResult) {
    const result = state.receiverTests.lastResult;
    receiverTest.hidden = false;
    receiverTest.className = `receiver-test ${result.admissionsUnchanged ? 'passed' : 'failed'}`;
    receiverTest.textContent = `${result.kind} · ${result.code} · admissions ${result.admissionsUnchanged ? 'unchanged' : 'changed'}`;
  } else {
    receiverTest.hidden = true;
    receiverTest.textContent = '';
  }
  if (state.webhookEvents.length && !state.deliveryEvidence && !deliveryEvidencePolling) {
    void refreshDeliveryEvidence();
  }
  if (state.lastGatewayResult) {
    const allowed = state.lastGatewayResult.status >= 200 && state.lastGatewayResult.status < 300;
    byId('gateway-result').className = `result ${allowed ? 'allowed' : 'denied'}`;
    renderGatewayResult(byId('gateway-result'), allowed, state.lastGatewayResult);
  }
  const activity = [
    ...state.gatewayRequests.map((item) => ({ type: 'request', title: `${item.method} ${item.path}`, detail: `${item.authentication} · ${item.origin}` })),
    ...state.webhookEvents.map((item) => ({ type: 'event', title: `${item.type} verified`, detail: `Event ${short(item.eventId)} · Correlation ${short(item.correlationId)}` })),
    ...(state.deliveryEvidence ? [{ type: 'event', title: 'Gateway delivery record bound', detail: `HTTP ${state.deliveryEvidence.responseStatusCode} · Correlation ${short(state.deliveryEvidence.correlationId)}` }] : []),
  ];
  renderTimeline(byId('timeline'), activity);
}

async function refreshDeliveryEvidence() {
  deliveryEvidencePolling = true;
  try {
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const response = await fetch('/api/delivery-evidence/refresh', { method: 'POST' });
      if (response.status !== 202) break;
      await new Promise((resolve) => setTimeout(resolve, 750));
    }
    await refresh();
  } finally {
    deliveryEvidencePolling = false;
  }
}

async function refresh() {
  const response = await fetch('/api/demo-state', { cache: 'no-store' });
  if (!response.ok) throw new Error(`Northstar state returned HTTP ${response.status}`);
  render(await response.json());
}

function setControlsEnabled(enabled) {
  byId('deny-button').disabled = !enabled;
  byId('approve-button').disabled = !enabled;
}

function showLoadError(detail) {
  document.documentElement.dataset.demoState = 'error';
  byId('integration-status').className = 'integration unavailable';
  byId('integration-label').textContent = 'Marty Gateway unavailable';
  byId('application-status').textContent = 'UNAVAILABLE';
  byId('application-status').className = 'status error';
  byId('load-error-detail').textContent = detail;
  byId('load-error').hidden = false;
  setControlsEnabled(false);
}

function startRefreshLoop() {
  if (refreshTimer === null) {
    refreshTimer = setInterval(() => { void refresh().catch(() => {}); }, 1000);
  }
}

async function initialize() {
  document.documentElement.dataset.demoState = 'loading';
  byId('integration-status').className = 'integration';
  byId('integration-label').textContent = 'Connecting to Marty Gateway';
  byId('load-error').hidden = true;
  setControlsEnabled(false);
  try {
    await refresh();
    const initialApplication = await fetch('/api/applications/refresh', { method: 'POST' });
    if (!initialApplication.ok) {
      let detail = `Public applicant lookup returned HTTP ${initialApplication.status}.`;
      try {
        const body = await initialApplication.json();
        if (body.detail) detail = body.detail;
      } catch {}
      throw new Error(detail);
    }
    await refresh();
    setControlsEnabled(true);
    byId('integration-status').className = 'integration ready';
    byId('integration-label').textContent = 'Marty Gateway connected';
    document.documentElement.dataset.demoState = 'ready';
    startRefreshLoop();
  } catch (error) {
    await refresh().catch(() => {});
    showLoadError(error instanceof Error ? error.message : 'The public gateway is unavailable.');
  }
}

async function approve(mode) {
  setControlsEnabled(false);
  try {
    await fetch(`/api/applications/${encodeURIComponent(applicationId)}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mode }),
    });
    await refresh();
  } finally {
    if (document.documentElement.dataset.demoState === 'ready') setControlsEnabled(true);
  }
}

byId('deny-button').addEventListener('click', () => approve('read-only'));
byId('approve-button').addEventListener('click', () => approve('runtime'));
byId('retry-button').addEventListener('click', () => initialize());
await initialize();
