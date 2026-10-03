#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');

async function main() {
  const [recorderRoot, inputPath] = process.argv.slice(2);
  if (!recorderRoot || !inputPath || process.argv.length !== 4) {
    throw new Error('Pinned recorder root and protected publication input are required');
  }
  const { verifyLiveYoutube } = require(path.join(recorderRoot, 'src',
    'passportPublicationEvidence.js'));
  const { createAuthorizedYouTube } = require(path.join(recorderRoot, 'src',
    'youtubeAuth.js'));
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const publication = input.publication;
  const title = input.scenario_title;
  const youtube = publication?.youtube;
  if (publication?.schema !== 'marty.passport-beta-demo-publication/v1'
    || publication.status !== 'public_verified'
    || typeof title !== 'string' || !title.trim()
    || !/^[A-Za-z0-9_-]{11}$/.test(youtube?.video_id || '')
    || !/^PL[A-Za-z0-9_-]{10,}$/.test(youtube?.playlist_id || '')) {
    throw new Error('Protected D-12 publication identity is invalid');
  }
  const checkedAt = await verifyLiveYoutube(createAuthorizedYouTube(),
    { playlistId: youtube.playlist_id },
    { videoId: youtube.video_id, playlistId: youtube.playlist_id,
      captionLanguage: 'en', privacyStatus: 'public' });
  const { chromium } = require(path.join(recorderRoot, 'node_modules', 'playwright'));
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const url = 'https://beta.elevenidllc.com/demos/2026.08.0/physical-passport-issuance-evidence';
    await page.route('https://www.youtube-nocookie.com/**', (route) => route.fulfill({
      status: 200, contentType: 'text/html', body: '<title>Privacy-enhanced player</title>',
    }));
    const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    if (response?.status() !== 200 || page.url() !== url) {
      throw new Error('D-12 public scenario page is unavailable');
    }
    const heading = page.getByRole('heading', { level: 1, name: title, exact: true });
    const load = page.getByRole('button', { name: `Load ${title} from YouTube`, exact: true });
    await heading.waitFor({ state: 'visible', timeout: 15000 });
    await load.waitFor({ state: 'visible', timeout: 15000 });
    await load.click();
    const player = page.getByTitle(`${title} video`, { exact: true });
    await player.waitFor({ state: 'visible', timeout: 15000 });
    const source = await player.getAttribute('src');
    if (!source?.startsWith(`https://www.youtube-nocookie.com/embed/${youtube.video_id}`)) {
      throw new Error('D-12 public scenario player differs from the reviewed video');
    }
  } finally {
    await browser.close();
  }
  process.stdout.write(`${JSON.stringify({ verified: true,
    video_id: youtube.video_id, playlist_id: youtube.playlist_id,
    checked_at_utc: checkedAt, page_verified: true })}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { main };
