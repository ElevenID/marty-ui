const fs = require('fs');
const path = require('path');

const VIDEO_SIZE = Object.freeze({ width: 1920, height: 1080 });

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
      bottom: '32px',
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

module.exports = { VIDEO_SIZE, finalizeVideo, maskProtocolField, showStep };
