const fs = require('fs');
const path = require('path');

const VIDEO_SIZE = Object.freeze({ width: 1920, height: 1080 });

function createArtifactDir(root, defaultName, env = process.env) {
  const configured = String(env.DEMO_ARTIFACT_DIR || '').trim();
  const artifactDir = configured
    ? path.resolve(configured)
    : path.join(root, 'tests', 'artifacts', defaultName);
  fs.mkdirSync(artifactDir, { recursive: true });
  return artifactDir;
}

async function showStep(page, title, detail, options = {}) {
  if (!options.enabled) return;
  await page.evaluate(({ title: headingText, detail: detailText, eyebrowText }) => {
    document.getElementById('elevenid-recording-step')?.remove();
    const overlay = document.createElement('div');
    overlay.id = 'elevenid-recording-step';
    Object.assign(overlay.style, {
      position: 'fixed',
      zIndex: '2147483647',
      left: '32px',
      bottom: '132px',
      width: 'min(620px, calc(100vw - 64px))',
      padding: '18px 22px',
      borderRadius: '6px',
      background: 'rgba(17, 24, 39, 0.97)',
      color: '#f8fafc',
      boxShadow: '0 18px 48px rgba(0, 0, 0, 0.34)',
      fontFamily: 'Arial, sans-serif',
      pointerEvents: 'none',
    });
    const eyebrow = document.createElement('div');
    eyebrow.textContent = eyebrowText;
    Object.assign(eyebrow.style, { fontSize: '13px', fontWeight: '700', color: '#7dd3fc', textTransform: 'uppercase' });
    const heading = document.createElement('div');
    heading.textContent = headingText;
    Object.assign(heading.style, { marginTop: '6px', fontSize: '26px', fontWeight: '700', lineHeight: '1.2' });
    const copy = document.createElement('div');
    copy.textContent = detailText;
    Object.assign(copy.style, { marginTop: '8px', fontSize: '16px', lineHeight: '1.45', color: '#e2e8f0' });
    overlay.append(eyebrow, heading, copy);
    document.body.appendChild(overlay);
  }, {
    title,
    detail,
    eyebrowText: options.eyebrow || 'ElevenID LLC Credential Platform v2026.07.0',
  });
  await page.waitForTimeout(options.durationMs || 2200);
  await page.evaluate(() => document.getElementById('elevenid-recording-step')?.remove()).catch(() => {});
}

function buildVerificationDisplay(result, options = {}) {
  const actor = String(options.actor || '').trim();
  const testId = String(options.testId || '').trim().toUpperCase();
  const evaluatedState = String(options.evaluatedState || '').trim().toUpperCase();
  const comparison = String(options.comparison || '').trim();
  if (!actor) throw new TypeError('Verification display actor is required');
  if (!/^[A-Z0-9-]{6,48}$/.test(testId)) {
    throw new TypeError('Verification display testId must be a stable presentation-safe identifier');
  }

  const normalizedDecision = String(result?.decision || result?.evaluation || '').trim().toLowerCase();
  const decision = normalizedDecision === 'allow' || normalizedDecision === 'allowed'
    ? 'ALLOWED'
    : normalizedDecision === 'deny' || normalizedDecision === 'denied'
      ? 'DENIED'
      : 'UNRESOLVED';
  const reason = String(result?.decisionReason || '').trim()
    || (decision === 'ALLOWED'
      ? 'Policy evaluation completed without a denial reason.'
      : 'No machine decision reason was returned.');

  if (evaluatedState && !/^[A-Z][A-Z0-9_-]{1,31}$/.test(evaluatedState)) {
    throw new TypeError('Verification display evaluatedState must be presentation-safe');
  }

  return Object.freeze({ actor, testId, decision, reason, evaluatedState, comparison });
}

async function showVerificationResult(page, result, options = {}) {
  if (!options.enabled) return;
  const display = buildVerificationDisplay(result, options);
  await page.evaluate((model) => {
    document.getElementById('elevenid-verification-result')?.remove();
    const overlay = document.createElement('section');
    overlay.id = 'elevenid-verification-result';
    overlay.setAttribute('aria-label', 'Verification result');
    Object.assign(overlay.style, {
      position: 'fixed',
      zIndex: '2147483647',
      right: '48px',
      top: '170px',
      width: 'min(780px, calc(100vw - 96px))',
      padding: '28px 32px',
      borderRadius: '10px',
      border: '1px solid rgba(148, 163, 184, 0.55)',
      borderLeft: `10px solid ${model.decision === 'ALLOWED' ? '#22c55e' : model.decision === 'DENIED' ? '#f97316' : '#94a3b8'}`,
      background: 'rgba(15, 23, 42, 0.98)',
      color: '#f8fafc',
      boxShadow: '0 24px 64px rgba(0, 0, 0, 0.40)',
      fontFamily: 'Arial, sans-serif',
      pointerEvents: 'none',
    });
    const eyebrow = document.createElement('div');
    eyebrow.textContent = 'STATUS-AWARE VERIFICATION';
    Object.assign(eyebrow.style, {
      fontSize: '14px',
      fontWeight: '700',
      letterSpacing: '0.08em',
      color: '#bae6fd',
    });
    const decision = document.createElement('div');
    decision.textContent = model.decision;
    Object.assign(decision.style, {
      marginTop: '10px',
      fontSize: '48px',
      fontWeight: '800',
      lineHeight: '1',
      color: model.decision === 'ALLOWED' ? '#86efac' : model.decision === 'DENIED' ? '#fdba74' : '#cbd5e1',
    });
    const reason = document.createElement('div');
    reason.textContent = model.reason;
    Object.assign(reason.style, { marginTop: '16px', fontSize: '24px', lineHeight: '1.35', color: '#f1f5f9' });
    const context = document.createElement('div');
    context.textContent = [
      model.evaluatedState ? `Evaluated lifecycle state: ${model.evaluatedState}` : '',
      model.comparison,
    ].filter(Boolean).join(' | ');
    Object.assign(context.style, {
      marginTop: '14px',
      padding: '12px 14px',
      borderRadius: '6px',
      background: 'rgba(30, 41, 59, 0.95)',
      fontSize: '19px',
      fontWeight: '700',
      color: '#e0f2fe',
    });
    const metadata = document.createElement('div');
    Object.assign(metadata.style, {
      display: 'grid',
      gridTemplateColumns: '110px 1fr',
      gap: '8px 16px',
      marginTop: '24px',
      paddingTop: '18px',
      borderTop: '1px solid rgba(148, 163, 184, 0.35)',
      fontSize: '18px',
    });
    for (const [label, value] of [['Actor', model.actor], ['Test ID', model.testId]]) {
      const key = document.createElement('strong');
      key.textContent = label;
      key.style.color = '#94a3b8';
      const content = document.createElement('span');
      content.textContent = value;
      content.style.fontFamily = label === 'Test ID' ? 'monospace' : 'Arial, sans-serif';
      metadata.append(key, content);
    }
    overlay.append(eyebrow, decision, reason);
    if (context.textContent) overlay.append(context);
    overlay.append(metadata);
    document.body.appendChild(overlay);
  }, display);
  await page.waitForTimeout(options.durationMs || 3000);
  await page.evaluate(() => document.getElementById('elevenid-verification-result')?.remove()).catch(() => {});
}

async function maskProtocolField(page, label, enabled) {
  if (!enabled) return;
  await page.getByLabel(label).evaluate((element) => {
    element.style.color = 'transparent';
    element.style.caretColor = 'transparent';
    element.style.textShadow = '0 0 10px #64748b';
  });
}

async function finalizeVideo(video, artifactDir, filename) {
  if (!video) return null;
  const rawPath = await video.path();
  const finalPath = path.join(artifactDir, filename);
  fs.rmSync(finalPath, { force: true });
  await video.saveAs(finalPath);
  if (path.resolve(rawPath) !== path.resolve(finalPath)) fs.rmSync(rawPath, { force: true });
  return finalPath;
}

module.exports = {
  VIDEO_SIZE,
  buildVerificationDisplay,
  createArtifactDir,
  finalizeVideo,
  maskProtocolField,
  showStep,
  showVerificationResult,
};
