const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

const DEFAULT_CANVAS_DISPLAY_URL =
  'https://canvas-sandbox.elevenidllc.com/credentials/canvas-sandbox-urn%3Auuid%3A8f7e2803-5d55-4983-86dc-a86f59d6f261';
const DEFAULT_CONSOLE_PROVENANCE_URL =
  'https://beta.elevenidllc.com/console/org/operate/verify?external_credential_id=canvas-sandbox-urn%3Auuid%3A8f7e2803-5d55-4983-86dc-a86f59d6f261&canvas_account_id=canvas-real-account-1&organization_id=00000000-0000-0000-0000-000000000001';
const DEFAULT_CANVAS_ASSIGNMENT_URL = 'https://canvas-test.elevenidllc.com/courses/1/assignments/1';
const DEFAULT_CANVAS_LOGIN_URL = 'https://canvas-test.elevenidllc.com/login/canvas';
const DEFAULT_APPLICANT_IDENTITY_URL = 'https://beta.elevenidllc.com/console/applicant/identity';
const DEFAULT_CANVAS_ADMIN_URL = 'https://beta.elevenidllc.com/console/org/deploy/canvas';
const DEFAULT_CREDENTIAL_TEMPLATE_URL =
  'https://beta.elevenidllc.com/console/org/templates/credentials/50000000-0000-0000-0000-000000000041';
const DEFAULT_CONSOLE_VERIFY_URL = 'https://beta.elevenidllc.com/console/org/operate/verify';
const DEFAULT_CANVAS_DEMO_ADMIN_EMAIL = 'canvas.admin@marty.demo';
const DEFAULT_CANVAS_DEMO_ADMIN_PASSWORD = 'CanvasAdmin123!';

function latestSeedUrl(label) {
  const seedLogPath = path.resolve(__dirname, '..', '..', 'canvas-seed-latest.log');
  if (!fs.existsSync(seedLogPath)) return '';
  const seedLogBuffer = fs.readFileSync(seedLogPath);
  const seedLogText =
    seedLogBuffer[0] === 0xff && seedLogBuffer[1] === 0xfe
      ? seedLogBuffer.toString('utf16le')
      : seedLogBuffer.toString('utf8');
  const lines = seedLogText.split(/\r?\n/).reverse();
  const match = lines.find((line) => line.includes(`${label}:`));
  const value = match ? match.slice(match.indexOf(`${label}:`) + label.length + 1).trim() : '';
  return value;
}

function resolveSeededDemoUrl(envName, seedLabel, fallback) {
  const envValue = process.env[envName];
  if (envValue) return { url: envValue, source: envName };
  const seedValue = latestSeedUrl(seedLabel);
  if (seedValue) return { url: seedValue, source: 'canvas-seed-latest.log' };
  return { url: fallback, source: 'fallback' };
}

function toConsoleCanvasProvenanceUrl(url) {
  const parsed = new URL(String(url || ''));
  if (parsed.pathname !== '/console/org/operate/verify') {
    throw new Error(
      `Canvas provenance URL must use /console/org/operate/verify; got ${parsed.pathname}. ` +
        'Rerun the Canvas seeder so old public verification paths are not used.',
    );
  }
  return parsed.toString();
}

function canvasProvenanceParams(url) {
  const parsed = new URL(url);
  return {
    externalCredentialId: parsed.searchParams.get('external_credential_id') || '',
    credentialId: parsed.searchParams.get('credential_id') || '',
    deliveryRecordId: parsed.searchParams.get('delivery_record_id') || '',
    canvasAccountId: parsed.searchParams.get('canvas_account_id') || '',
  };
}

function requireIntentionalFallback(label, resolved) {
  if (resolved.source !== 'fallback' || process.env.CANVAS_DEMO_ALLOW_FALLBACK_URLS === '1') {
    return;
  }
  throw new Error(
    `${label} is using the built-in fallback URL. Run the Canvas seeder first, set ${label}, ` +
      'or set CANVAS_DEMO_ALLOW_FALLBACK_URLS=1 for a placeholder recording.',
  );
}

const resolvedCanvasDisplayUrl = resolveSeededDemoUrl(
  'CANVAS_DEMO_CANVAS_DISPLAY_URL',
  'canvas_display',
  DEFAULT_CANVAS_DISPLAY_URL,
);
const resolvedConsoleProvenanceUrl = resolveSeededDemoUrl(
  'CANVAS_DEMO_CONSOLE_PROVENANCE_URL',
  'console_provenance',
  DEFAULT_CONSOLE_PROVENANCE_URL,
);

const canvasDisplayUrl = resolvedCanvasDisplayUrl.url;
const consoleProvenanceUrl = toConsoleCanvasProvenanceUrl(resolvedConsoleProvenanceUrl.url);
const canvasLoginUrl = process.env.CANVAS_DEMO_CANVAS_LOGIN_URL || DEFAULT_CANVAS_LOGIN_URL;
const canvasAssignmentUrl = process.env.CANVAS_DEMO_CANVAS_ASSIGNMENT_URL || DEFAULT_CANVAS_ASSIGNMENT_URL;
const applicantIdentityUrl = process.env.CANVAS_DEMO_APPLICANT_IDENTITY_URL || DEFAULT_APPLICANT_IDENTITY_URL;
const canvasAdminUrl = process.env.CANVAS_DEMO_CANVAS_ADMIN_URL || DEFAULT_CANVAS_ADMIN_URL;
const credentialTemplateUrl = process.env.CANVAS_DEMO_CREDENTIAL_TEMPLATE_URL || DEFAULT_CREDENTIAL_TEMPLATE_URL;
const consoleVerifyUrl = process.env.CANVAS_DEMO_CONSOLE_VERIFY_URL || DEFAULT_CONSOLE_VERIFY_URL;
const elevenIdBaseUrl =
  process.env.CANVAS_DEMO_ELEVENID_BASE_URL || new URL(applicantIdentityUrl).origin;
const elevenIdOrigin = new URL(elevenIdBaseUrl).origin;
const consoleStorageState = process.env.CANVAS_DEMO_CONSOLE_STORAGE_STATE || '';
const useConsoleStorageState =
  process.env.CANVAS_DEMO_USE_STORAGE_STATE === '1'
  && consoleStorageState
  && fs.existsSync(consoleStorageState);
const canvasDemoAdminEmail = process.env.CANVAS_DEMO_ADMIN_EMAIL || DEFAULT_CANVAS_DEMO_ADMIN_EMAIL;
const canvasDemoAdminPassword =
  process.env.CANVAS_DEMO_ADMIN_PASSWORD || DEFAULT_CANVAS_DEMO_ADMIN_PASSWORD;
const canvasUsername = process.env.CANVAS_DEMO_LEARNER_USERNAME || 'learner+elevenid@example.edu';
const canvasPassword = process.env.CANVAS_DEMO_LEARNER_PASSWORD || 'ChangeMe123!';

const artifactsDir = path.resolve(__dirname, '..', 'artifacts', 'canvas-employer-demo');
const finalVideoPath = path.join(artifactsDir, 'canvas-employer-demo.webm');
const stepLogPath = path.join(artifactsDir, 'canvas-employer-demo-steps.json');
const viewport = { width: 1600, height: 950 };
const demoSteps = [];
const badgeName = 'Interoperable Credentials Foundations Badge';

function ensureCleanArtifactDir() {
  fs.rmSync(artifactsDir, { recursive: true, force: true });
  fs.mkdirSync(artifactsDir, { recursive: true });
}

async function pause(page, milliseconds = 1800) {
  await page.waitForTimeout(milliseconds);
}

async function showStep(page, title, detail) {
  demoSteps.push({
    index: demoSteps.length + 1,
    title,
    detail,
    url: page.url(),
    timestamp: new Date().toISOString(),
  });
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

async function isVisibleText(page, text, timeout = 8000) {
  return page
    .getByText(text, { exact: false })
    .first()
    .waitFor({ state: 'visible', timeout })
    .then(() => true)
    .catch(() => false);
}

async function gotoFeaturePage(page, url, expectedText, unavailableTitle, unavailableDetail) {
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
  if (await isVisibleText(page, expectedText, 12000)) {
    return true;
  }
  await showStep(page, unavailableTitle, unavailableDetail);
  return false;
}

async function tryContinueIntoElevenId(page, frame) {
  const continueControl = frame.getByRole('link', { name: /continue in elevenid/i }).first();
  if (!(await continueControl.isVisible({ timeout: 8000 }).catch(() => false))) {
    return false;
  }

  await Promise.all([
    page.waitForLoadState('domcontentloaded', { timeout: 60000 }).catch(() => undefined),
    continueControl.click(),
  ]);
  await pause(page, 3500);

  const applicationVisible =
    (await isVisibleText(page, 'Course completion requirement', 10000))
    || (await isVisibleText(page, 'Credential Application', 5000))
    || (await isVisibleText(page, 'Interoperable Credentials Foundations Badge', 5000));

  if (!applicationVisible) {
    await showStep(
      page,
      'Canvas sign-in hands off to ElevenID',
      'The launch finalization endpoint exchanges the verified Canvas launch for the normal ElevenID console session. If this page shows sign-in, refresh the Canvas LTI session before recording.',
    );
    return false;
  }

  await page.getByTestId('canvas-application-context').waitFor({ state: 'visible', timeout: 15000 });

  await showStep(
    page,
    'Normal credential application is preselected',
    'The Canvas launch opens the regular credential application surface with the correct template, course, learner, and activity already bound.',
  );

  if (await isVisibleText(page, 'Course completion requirement', 3000)) {
    await showStep(
      page,
      'Canvas is source context, not a custom form',
      'The learner reviews course details from Canvas while ElevenID keeps the normal application flow and issuer-controlled requirements.',
    );
  }

  return true;
}

async function tryShowLearnerIdentity(page) {
  const visible = await gotoFeaturePage(
    page,
    applicantIdentityUrl,
    'My Identity',
    'Learner identity view requires sign-in',
    'After Canvas launch finalization, the learner should land in the normal applicant console. This recording did not have an active learner console session for My Identity.',
  );
  if (!visible) return false;

  const badge = page.getByText(badgeName, { exact: true }).first();
  await badge.waitFor({ state: 'visible', timeout: 15000 });
  await badge.scrollIntoViewIfNeeded();
  // MyIdentityPage renders credential-specific accessible names. Application
  // rows use a Details button, so scope that fallback to this badge's row.
  const credentialDetails = page.getByRole('button', { name: `View ${badgeName} details`, exact: true });
  if (await credentialDetails.count()) {
    await credentialDetails.click();
  } else {
    const badgeRow = badge.locator('xpath=ancestor::*[.//button[normalize-space()="Details"]][1]');
    await badgeRow.getByRole('button', { name: 'Details', exact: true }).click();
  }
  const details = page.getByRole('dialog');
  await details.getByText(badgeName, { exact: true }).waitFor({ state: 'visible' });
  await details.getByTestId('identity-canvas-source').waitFor({ state: 'visible' });
  await details.getByTestId('identity-canvas-delivery').waitFor({ state: 'visible' });
  await showStep(
    page,
    'Learner sees the badge in My Identity',
    'The Canvas-earned badge appears as a normal learner credential/application, with badge artwork, claim state, source context, and mirror delivery metadata.',
  );

  await showStep(
    page,
    'Credential details include Canvas source and delivery',
    'The details modal shows this badge, its Canvas source, and its mirror delivery metadata. These displayed fields do not qualify a wallet or provider portability test.',
  );
  await details.getByRole('button', { name: /close/i }).click();
  return true;
}

async function tryShowCredentialTemplateDestinations(page) {
  const visible = await gotoFeaturePage(
    page,
    credentialTemplateUrl,
    'Credential Template',
    'Credential template destinations require org admin access',
    'The recorder signs in as the Canvas demo admin for this section. Run Keycloak setup if canvas.admin@marty.demo is not available yet.',
  );
  if (!visible) return false;

  const destinationsTab = page.getByRole('tab', { name: /destinations/i }).first();
  await destinationsTab.waitFor({ state: 'visible', timeout: 10000 });
  await destinationsTab.click();
  await waitForVisibleText(page, 'Canvas Credentials');
  await showStep(
    page,
    'Credential template owns destinations',
    'Canvas Credentials is shown as an organization-managed destination for this badge, not a student wallet. Projection policy limits Canvas to the public badge view.',
  );

  await waitForVisibleText(page, 'Mirror health');
  await page.getByText('Mirror health', { exact: false }).first().scrollIntoViewIfNeeded();
  await showStep(
    page,
    'Mirror health is visible per badge',
    'The template displays mirror health for its Canvas destination. Counts on this screen are not an assertion that a real external provider delivery occurred.',
  );
  return true;
}

async function tryShowCanvasAdmin(page) {
  const visible = await gotoFeaturePage(
    page,
    canvasAdminUrl,
    'Canvas',
    'Canvas admin setup requires org admin access',
    'The recorder signs in as the Canvas demo admin for this section. Run Keycloak setup if canvas.admin@marty.demo is not available yet.',
  );
  if (!visible) return false;

  await page.getByTestId('canvas-readiness').waitFor({ state: 'visible', timeout: 15000 });
  await page.getByTestId('canvas-mirror-ops').waitFor({ state: 'visible', timeout: 15000 });

  await showStep(
    page,
    'Canvas platform and program bindings are managed',
    'Admins configure Canvas trust, LTI launch binding, course/activity scope, feature gates, evidence requirements, and Canvas Credentials provider settings from the console.',
  );

  if (await isVisibleText(page, 'Canvas Credentials provider', 5000)) {
    await page.getByText('Canvas Credentials provider', { exact: false }).first().scrollIntoViewIfNeeded().catch(() => undefined);
    await showStep(
      page,
      'Provider secrets stay outside Canvas',
      'Canvas Credentials API tokens are saved as managed organization secrets; bindings keep only a secret reference plus issuer and badgeclass IDs.',
    );
  } else if (await isVisibleText(page, 'Validate provider', 3000)) {
    await page.getByText('Validate provider', { exact: false }).first().scrollIntoViewIfNeeded().catch(() => undefined);
    await showStep(
      page,
      'Provider contract can be checked safely',
      'The setup wizard can validate Canvas Credentials configuration without publishing a badge, so real provider onboarding stays separate from demo sandbox mode.',
    );
  }

  if (await isVisibleText(page, 'Deep Linking', 3000) || await isVisibleText(page, 'AGS', 3000) || await isVisibleText(page, 'NRPS', 3000)) {
    await showStep(
      page,
      'Canvas standards breadth is surfaced',
      'The integration now tracks LTI Deep Linking, AGS score evidence, NRPS roster/role context, and feature gates per Canvas program binding.',
    );
  }
  return true;
}

async function tryShowConsoleVerification(page) {
  await page.goto(consoleVerifyUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const verifyPageVisible = await isVisibleText(page, 'Credential Verification', 30000);

  if (!verifyPageVisible) {
    await showStep(
      page,
      'Verifier console requires sign-in',
      'The verifier-console checkpoint uses the Canvas demo admin session. Run Keycloak setup if the demo admin cannot authenticate yet.',
    );
    return false;
  }

  await showStep(
    page,
    'Employer uses Credential Verification',
    'The product verification path is the organization console: select a saved verification flow or presentation policy, then generate an OID4VP request.',
  );

  const newVerification = page.getByRole('button', { name: /new verification/i }).first();
  await newVerification.waitFor({ state: 'visible', timeout: 10000 });
  await newVerification.click();
  const dialog = page.getByRole('dialog', { name: 'New Verification Session', exact: true });
  await dialog.getByText('Select Policy', { exact: true }).waitFor({ state: 'visible', timeout: 10000 });
  await showStep(
    page,
    'Verification setup starts from policy',
    'The policy selection dialog is open. This walkthrough does not generate a verification request or prove a wallet presentation result.',
  );

  return true;
}

async function showConsoleCanvasProvenance(page) {
  await page.goto(consoleProvenanceUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });

  if (!(await isVisibleText(page, 'Canvas mirror provenance', 12000))) {
    await waitForVisibleText(page, 'Credential Verification', 30000);
    const provenanceTab = page.getByRole('tab', { name: /canvas provenance/i }).first();
    if (await provenanceTab.isVisible({ timeout: 8000 }).catch(() => false)) {
      await provenanceTab.click();
    }
  }

  await waitForVisibleText(page, 'Canvas mirror provenance', 30000);

  if (!(await page.getByTestId('canvas-provenance-result').isVisible({ timeout: 5000 }).catch(() => false))) {
    const params = canvasProvenanceParams(consoleProvenanceUrl);
    const lookupValue = params.externalCredentialId || params.credentialId || params.deliveryRecordId;
    if (lookupValue) {
      const lookupInput = page.getByTestId('canvas-provenance-lookup').first();
      if (await lookupInput.isVisible({ timeout: 8000 }).catch(() => false)) {
        await lookupInput.fill(lookupValue);
      }
    }
    if (params.canvasAccountId) {
      const canvasAccountInput = page.getByLabel(/canvas account/i).first();
      if (await canvasAccountInput.isVisible({ timeout: 5000 }).catch(() => false)) {
        await canvasAccountInput.fill(params.canvasAccountId);
      }
    }
    await page.getByRole('button', { name: /^resolve$/i }).first().click();
  }

  await page.getByTestId('canvas-provenance-result').waitFor({ state: 'visible', timeout: 45000 });
}

async function fillDemoAdminLoginForm(page) {
  const usernameInput = page
    .locator('input[name="username"], #username, input[type="email"]')
    .first();
  await usernameInput.waitFor({ state: 'visible', timeout: 30000 });
  await usernameInput.fill(canvasDemoAdminEmail);

  const passwordInput = page.locator('input[name="password"], #password, input[type="password"]').first();
  if (!(await passwordInput.isVisible({ timeout: 2000 }).catch(() => false))) {
    await page.locator('button[type="submit"], input[type="submit"]').first().click().catch(() => undefined);
    await passwordInput.waitFor({ state: 'visible', timeout: 15000 });
  }
  await passwordInput.fill(canvasDemoAdminPassword);

  await Promise.all([
    page.waitForLoadState('domcontentloaded', { timeout: 60000 }).catch(() => undefined),
    page.locator('button[type="submit"], input[type="submit"]').first().click(),
  ]);
}

async function waitForDemoAdminSession(page) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    if (page.url().startsWith(elevenIdOrigin)) {
      const auth = await page
        .evaluate(async () => {
          const response = await fetch('/v1/auth/me', { credentials: 'include' });
          if (!response.ok) return null;
          return response.json();
        })
        .catch(() => null);
      if (auth?.authenticated && auth?.user?.email === canvasDemoAdminEmail) {
        return auth.user;
      }
    }
    await pause(page, 1000);
  }
  return null;
}

async function signIntoDemoAdmin(page, targetUrl) {
  if (useConsoleStorageState) {
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    return Boolean(await waitForDemoAdminSession(page));
  }

  await showStep(
    page,
    'Switching to issuer admin',
    'The learner flow stays separate from organization administration. The recorder now signs in as Canvas Demo Admin for setup, destination, and verification screens.',
  );

  await page.goto(elevenIdOrigin, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => undefined);
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  }).catch(() => undefined);
  await page.context().clearCookies();
  const loginUrl = `${elevenIdOrigin}/v1/auth/login?redirect_uri=${encodeURIComponent(targetUrl)}`;
  await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => undefined);

  try {
    const usernameInput = page
      .locator('input[name="username"], #username, input[type="email"]')
      .first();
    if (await usernameInput.isVisible({ timeout: 12000 }).catch(() => false)) {
      await fillDemoAdminLoginForm(page);
    }
    let adminUser = await waitForDemoAdminSession(page);
    if (!adminUser) {
      await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => undefined);
      await fillDemoAdminLoginForm(page);
      adminUser = await waitForDemoAdminSession(page);
    }
    if (!adminUser) {
      throw new Error('Timed out waiting for Canvas demo admin session');
    }
    await showStep(
      page,
      'Issuer admin session is active',
      `Signed in as ${adminUser.given_name || 'Canvas'} ${adminUser.family_name || 'Demo Admin'} with Marty organization access.`,
    );
  } catch (error) {
    await showStep(
      page,
      'Canvas demo admin sign-in needs setup',
      `Could not authenticate ${canvasDemoAdminEmail}. Run the Keycloak setup/seeder, then record again.`,
    );
    return false;
  }

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => undefined);
  await pause(page, 2200);
  return true;
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

const REQUIRED_CHECKPOINTS = [
  'canvas_lti_launch', 'elevenid_application', 'learner_identity', 'admin_session',
  'template_destinations', 'canvas_admin', 'sandbox_display', 'console_provenance',
  'verification_setup',
];

function createRunReport() {
  return {
    scope: 'LEGACY_CANVAS_SANDBOX_WALKTHROUGH',
    qualifies_as_real_oss_portability: false,
    status: 'RUNNING',
    started_at: new Date().toISOString(),
    completed_at: null,
    finished_at: null,
    video: null,
    failure: null,
    finalization_errors: [],
    checkpoints: [],
    urls: {
      canvas_login: canvasLoginUrl,
      canvas_assignment: canvasAssignmentUrl,
      applicant_identity: applicantIdentityUrl,
      credential_template: credentialTemplateUrl,
      canvas_admin: canvasAdminUrl,
      canvas_display: canvasDisplayUrl,
      canvas_display_source: resolvedCanvasDisplayUrl.source,
      console_canvas_provenance: consoleProvenanceUrl,
      console_canvas_provenance_source: resolvedConsoleProvenanceUrl.source,
      console_verify: consoleVerifyUrl,
      console_auth: useConsoleStorageState ? 'storage_state' : 'canvas_demo_admin',
      console_admin_email: canvasDemoAdminEmail,
      console_storage_state: consoleStorageState || null,
    },
    // Overlay narration is retained separately from required checkpoint results.
    steps: demoSteps,
  };
}

async function runCanvasJourney(page, report, overrides = {}) {
  let ltiFrame;
  const actions = {
    canvas_lti_launch: async () => {
      await signIntoCanvas(page);
      await page.goto(canvasAssignmentUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
      await waitForVisibleText(page, 'Submitting an external tool', 60000);
      await showStep(page, 'Canvas launches ElevenID through LTI',
        'The configured Canvas assignment has loaded its external tool placement.');
      ltiFrame = await waitForCanvasLtiFrame(page);
      await showStep(page, 'LTI launch is verified and bound',
        'The embedded ElevenID experience reports a verified Canvas launch.');
      return true;
    },
    elevenid_application: () => tryContinueIntoElevenId(page, ltiFrame),
    learner_identity: () => tryShowLearnerIdentity(page),
    admin_session: () => signIntoDemoAdmin(page, credentialTemplateUrl),
    template_destinations: () => tryShowCredentialTemplateDestinations(page),
    canvas_admin: () => tryShowCanvasAdmin(page),
    sandbox_display: async () => {
      await page.goto(canvasDisplayUrl, { waitUntil: 'networkidle', timeout: 45000 });
      await waitForVisibleText(page, 'Canvas Credentials');
      await waitForVisibleText(page, badgeName);
      await showStep(page, 'Canvas destination sandbox shows the badge',
        'This page simulates the Canvas Credentials destination. It does not establish delivery to a real external provider.');
      return true;
    },
    console_provenance: async () => {
      await showConsoleCanvasProvenance(page);
      await page.getByTestId('canvas-provenance-result').getByText('Issuer DID', { exact: false }).first().scrollIntoViewIfNeeded();
      await showStep(page, 'Canvas mirror provenance is in the console',
        'The console resolved the configured mirror lookup and displays its issuer DID. This lookup does not prove remote key custody or wallet presentation.');
      return true;
    },
    verification_setup: () => tryShowConsoleVerification(page),
    ...overrides,
  };

  for (const name of REQUIRED_CHECKPOINTS) {
    const checkpoint = { name, status: 'RUNNING', started_at: new Date().toISOString() };
    report.checkpoints.push(checkpoint);
    try {
      if (await actions[name]() !== true) {
        throw new Error(`Required Canvas checkpoint did not complete: ${name}`);
      }
      checkpoint.status = 'PASSED';
    } catch (error) {
      checkpoint.status = 'FAILED';
      checkpoint.error = error.message;
      throw error;
    } finally {
      checkpoint.finished_at = new Date().toISOString();
    }
  }
}

function finishRunReport(report, error) {
  const allPassed = report.checkpoints.length === REQUIRED_CHECKPOINTS.length
    && report.checkpoints.every((checkpoint, index) => (
      checkpoint.name === REQUIRED_CHECKPOINTS[index] && checkpoint.status === 'PASSED'
    ));
  report.finished_at = new Date().toISOString();
  report.failure = error?.message || (allPassed ? null : 'Required Canvas checkpoints are incomplete');
  report.status = report.failure ? 'FAILED' : 'COMPLETED';
  report.completed_at = report.failure ? null : report.finished_at;
  return report;
}

async function main() {
  // Refused configuration must not erase an earlier recording.
  requireIntentionalFallback('CANVAS_DEMO_CANVAS_DISPLAY_URL', resolvedCanvasDisplayUrl);
  requireIntentionalFallback('CANVAS_DEMO_CONSOLE_PROVENANCE_URL', resolvedConsoleProvenanceUrl);
  ensureCleanArtifactDir();
  demoSteps.length = 0;
  const report = createRunReport();
  let browser;
  let context;
  let page;
  let failure;
  try {
    browser = await chromium.launch({
      headless: process.env.PLAYWRIGHT_HEADED !== '1',
      slowMo: 140,
    });
    const contextOptions = {
      ignoreHTTPSErrors: true,
      recordVideo: { dir: artifactsDir, size: viewport },
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      viewport,
    };
    if (useConsoleStorageState) contextOptions.storageState = consoleStorageState;
    context = await browser.newContext(contextOptions);
    page = await context.newPage();
    await runCanvasJourney(page, report);
    await removeStepOverlay(page);
    await pause(page, 1600);
  } catch (error) {
    failure = error;
  } finally {
    // Preserve the first business/setup failure, attempt every close, and write
    // a report even when recording finalization itself fails.
    const finalize = async (name, operation) => {
      try {
        await operation();
      } catch (error) {
        report.finalization_errors.push({ operation: name, error: error.message });
        failure ||= error;
      }
    };
    if (page) {
      const video = page.video();
      await finalize('page_close', () => page.close());
      if (video) {
        await finalize('video_save', async () => {
          const rawVideoPath = await video.path();
          await video.saveAs(finalVideoPath);
          report.video = finalVideoPath;
          if (rawVideoPath !== finalVideoPath && fs.existsSync(rawVideoPath)) fs.rmSync(rawVideoPath);
        });
      }
    }
    if (context) await finalize('context_close', () => context.close());
    if (browser) await finalize('browser_close', () => browser.close());
    finishRunReport(report, failure);
    fs.writeFileSync(stepLogPath, JSON.stringify(report, null, 2), 'utf8');
  }

  console.log(`STEPS: ${stepLogPath}`);
  if (failure || report.status !== 'COMPLETED') throw failure || new Error(report.failure);
  console.log(`VIDEO: ${finalVideoPath}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = {
  REQUIRED_CHECKPOINTS, createRunReport, runCanvasJourney, finishRunReport, main,
  tryContinueIntoElevenId, tryShowLearnerIdentity, tryShowCredentialTemplateDestinations,
  tryShowCanvasAdmin, tryShowConsoleVerification, signIntoDemoAdmin,
};
