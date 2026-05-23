const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

const DEFAULT_CANVAS_DISPLAY_URL =
  'https://canvas-sandbox.elevenidllc.com/credentials/canvas-sandbox-urn%3Auuid%3A8f7e2803-5d55-4983-86dc-a86f59d6f261';
const DEFAULT_EMPLOYER_VERIFY_URL =
  'https://beta.elevenidllc.com/verify/canvas-credentials?external_credential_id=canvas-sandbox-urn%3Auuid%3A8f7e2803-5d55-4983-86dc-a86f59d6f261&canvas_account_id=canvas-real-account-1&organization_id=00000000-0000-0000-0000-000000000001';
const DEFAULT_CANVAS_ASSIGNMENT_URL = 'https://canvas-test.elevenidllc.com/courses/1/assignments/1';
const DEFAULT_CANVAS_LOGIN_URL = 'https://canvas-test.elevenidllc.com/login/canvas';

function latestSeedUrl(label) {
  const seedLogPath = path.resolve(__dirname, '..', '..', 'canvas-seed-latest.log');
  if (!fs.existsSync(seedLogPath)) return '';
  const lines = fs.readFileSync(seedLogPath, 'utf8').split(/\r?\n/).reverse();
  const match = lines.find((line) => line.includes(`${label}:`));
  return match ? match.slice(match.indexOf(`${label}:`) + label.length + 1).trim() : '';
}

const canvasDisplayUrl =
  process.env.CANVAS_DEMO_CANVAS_DISPLAY_URL || latestSeedUrl('canvas_display') || DEFAULT_CANVAS_DISPLAY_URL;
const employerVerifyUrl =
  process.env.CANVAS_DEMO_EMPLOYER_VERIFY_URL || latestSeedUrl('employer_verify') || DEFAULT_EMPLOYER_VERIFY_URL;
const canvasLoginUrl = process.env.CANVAS_DEMO_CANVAS_LOGIN_URL || DEFAULT_CANVAS_LOGIN_URL;
const canvasAssignmentUrl = process.env.CANVAS_DEMO_CANVAS_ASSIGNMENT_URL || DEFAULT_CANVAS_ASSIGNMENT_URL;
const canvasUsername = process.env.CANVAS_DEMO_LEARNER_USERNAME || 'learner+elevenid@example.edu';
const canvasPassword = process.env.CANVAS_DEMO_LEARNER_PASSWORD || 'ChangeMe123!';

const artifactsDir = path.resolve(__dirname, '..', 'artifacts', 'canvas-employer-demo');
const finalVideoPath = path.join(artifactsDir, 'canvas-employer-demo.webm');
const viewport = { width: 1600, height: 950 };

function ensureCleanArtifactDir() {
  fs.rmSync(artifactsDir, { recursive: true, force: true });
  fs.mkdirSync(artifactsDir, { recursive: true });
}

async function pause(page, milliseconds = 1800) {
  await page.waitForTimeout(milliseconds);
}

async function showStep(page, title, detail) {
  await page.evaluate(
    ({ title, detail }) => {
      let overlay = document.getElementById('marty-demo-step-overlay');
      if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'marty-demo-step-overlay';
        document.body.appendChild(overlay);
      }
      overlay.innerHTML = `
        <div style="font-size: 12px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase; color: #cfe7ff;">Demo step</div>
        <div style="margin-top: 6px; font-size: 28px; font-weight: 800; line-height: 1.15;">${title}</div>
        <div style="margin-top: 8px; font-size: 16px; line-height: 1.35; color: #ecf6ff;">${detail}</div>
      `;
      Object.assign(overlay.style, {
        position: 'fixed',
        zIndex: '2147483647',
        left: '24px',
        bottom: '24px',
        maxWidth: '560px',
        padding: '18px 22px',
        borderRadius: '12px',
        background: 'rgba(14, 39, 68, 0.94)',
        color: 'white',
        boxShadow: '0 16px 42px rgba(0, 0, 0, 0.28)',
        fontFamily: 'Arial, sans-serif',
        pointerEvents: 'none',
      });
    },
    { title, detail },
  );
  console.log(`STEP: ${title} - ${detail}`);
  await pause(page, 2400);
}

async function removeStepOverlay(page) {
  await page.evaluate(() => {
    document.getElementById('marty-demo-step-overlay')?.remove();
  });
}

async function waitForVisibleText(page, text, timeout = 30000) {
  await page.getByText(text, { exact: false }).first().waitFor({ state: 'visible', timeout });
}

async function signIntoCanvas(page) {
  await page.goto(canvasLoginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  if (page.url().includes('/login/')) {
    await page.locator('input[name="pseudonym_session[unique_id]"]').first().fill(canvasUsername);
    await page.locator('input[name="pseudonym_session[password]"]').first().fill(canvasPassword);
    await showStep(
      page,
      'Learner starts in Canvas',
      'The demo begins as the enrolled student in the real Canvas LMS course, not on an ElevenID marketing page.',
    );
    await Promise.all([
      page.waitForLoadState('domcontentloaded', { timeout: 60000 }).catch(() => undefined),
      page.locator('button[type="submit"], input[type="submit"]').first().click(),
    ]);
  }
  await pause(page, 2500);
}

async function waitForCanvasLtiFrame(page) {
  const deadline = Date.now() + 70000;
  while (Date.now() < deadline) {
    const frame = page.frames().find((candidate) => candidate.url().includes('/canvas/lti/experience'));
    if (frame) {
      try {
        await frame.getByText('Canvas launch verified', { exact: false }).waitFor({ state: 'visible', timeout: 5000 });
        return frame;
      } catch (_error) {
        // Keep polling while Canvas and the tool finish their form-post redirects.
      }
    }
    await pause(page, 1200);
  }
  throw new Error('Timed out waiting for Canvas LTI experience frame.');
}

async function main() {
  ensureCleanArtifactDir();

  const browser = await chromium.launch({
    headless: process.env.PLAYWRIGHT_HEADED !== '1',
    slowMo: 140,
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    recordVideo: { dir: artifactsDir, size: viewport },
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    viewport,
  });
  const page = await context.newPage();

  try {
    await signIntoCanvas(page);
    await showStep(
      page,
      'Canvas course context is active',
      'The learner is enrolled in ElevenID LTI Test Course, which contains the launch assignment and quiz-backed badge scenario.',
    );

    await page.goto(canvasAssignmentUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await waitForVisibleText(page, 'Submitting an external tool', 60000);
    await showStep(
      page,
      'Canvas launches ElevenID through LTI',
      'The assignment is an external tool placement, so Canvas sends a signed LTI launch instead of a hand-built link.',
    );

    await waitForCanvasLtiFrame(page);
    await showStep(
      page,
      'LTI launch is verified and bound',
      'ElevenID validates the Canvas launch, resolves the Canvas Platform and Program Binding, and selects the correct credential application.',
    );

    await showStep(
      page,
      'AGS quiz score becomes policy input',
      'The seeded demo submits a signed Canvas AGS score event. MIP normalizes it into an EvidenceFact and Cedar permits approval.',
    );

    await page.goto(canvasDisplayUrl, { waitUntil: 'networkidle', timeout: 45000 });
    await waitForVisibleText(page, 'Canvas Credentials');
    await showStep(
      page,
      'Canvas shows the learner badge',
      'The badge is visible inside Canvas Credentials, but it points back to a canonical ElevenID issuance record.',
    );

    await showStep(
      page,
      'Mirror is not the source of truth',
      'The Canvas credential includes the canonical credential ID, issuer DID, subject DID, and Canvas account context.',
    );

    await page.goto(employerVerifyUrl, { waitUntil: 'networkidle', timeout: 45000 });
    await page.getByTestId('employer-canvas-verification-result').waitFor({ state: 'visible', timeout: 45000 });
    await showStep(
      page,
      'Employer verification is product UI',
      'This replaces the raw Open Badge JSON view: canonical credential, issuer, mirror, trust, and status are shown as readable fields.',
    );

    await page.getByText('Status', { exact: true }).scrollIntoViewIfNeeded();
    await showStep(
      page,
      'Canonical status travels with the badge',
      'The Canvas mirror is checked against the canonical ElevenID credential status instead of a Canvas-only database lookup.',
    );

    await showStep(
      page,
      'Employer verifies outside Canvas',
      'An employer can verify the same badge without logging into Canvas or trusting a Canvas database lookup.',
    );

    await page.getByText('Employer Checks', { exact: false }).scrollIntoViewIfNeeded();
    await showStep(
      page,
      'Provenance checks pass',
      'The employer sees that canonical issuance exists, the Canvas mirror is linked, and the issuer organization matches.',
    );

    await page.getByText('Issuer DID', { exact: false }).scrollIntoViewIfNeeded();
    await showStep(
      page,
      'Issuer identity stays external',
      'The issuer DID and remote-key-backed Marty identity remain outside Canvas while Canvas receives a useful badge mirror.',
    );

    await page.goto(employerVerifyUrl, { waitUntil: 'networkidle', timeout: 45000 });
    await page.getByTestId('employer-canvas-verification-result').waitFor({ state: 'visible', timeout: 45000 });
    await showStep(
      page,
      'End state',
      'LTI launch, Canvas AGS score, MIP policy, wallet issuance, Canvas mirror, revocation status, and employer verification all point to the same credential.',
    );
    await removeStepOverlay(page);
    await pause(page, 1600);
  } finally {
    const video = page.video();
    await page.close();
    if (video) {
      const rawVideoPath = await video.path();
      await video.saveAs(finalVideoPath);
      if (rawVideoPath !== finalVideoPath && fs.existsSync(rawVideoPath)) {
        fs.rmSync(rawVideoPath);
      }
    }
    await context.close();
    await browser.close();
  }

  console.log(`VIDEO: ${finalVideoPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
