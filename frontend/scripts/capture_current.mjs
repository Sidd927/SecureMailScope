import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const ARTIFACTS_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/f8aa79a9-46d6-4f91-8540-60449cc311c7';
const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEBUG_PORT = 9226;

const RUN_CASE_B = '871ea0c739b246098ff481c887afcc0f';

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendCdp(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1000000);
    const handler = (msg) => {
      const parsed = JSON.parse(msg.data);
      if (parsed.id === id) {
        ws.removeEventListener('message', handler);
        if (parsed.error) reject(parsed.error);
        else resolve(parsed.result);
      }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--user-data-dir=/tmp/chrome-test-capture',
  ]);

  let version = null;
  for (let i = 0; i < 30; i++) {
    await sleep(300);
    try {
      const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`);
      if (res.ok) {
        version = await res.json();
        break;
      }
    } catch {}
  }

  if (!version) {
    chromeProc.kill();
    console.error('Failed to connect to Chrome');
    process.exit(1);
  }

  const browserWs = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve) => browserWs.addEventListener('open', resolve));

  const target = await sendCdp(browserWs, 'Target.createTarget', { url: 'about:blank' });
  const targetWsUrl = `ws://127.0.0.1:${DEBUG_PORT}/devtools/page/${target.targetId}`;
  const pageWs = new WebSocket(targetWsUrl);
  await new Promise((resolve) => pageWs.addEventListener('open', resolve));

  await sendCdp(pageWs, 'Page.enable');
  await sendCdp(pageWs, 'Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false,
  });

  const url = `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=overview`;
  console.log(`Navigating to ${url}...`);
  await sendCdp(pageWs, 'Page.navigate', { url });
  await sleep(3500);

  const screenshot = await sendCdp(pageWs, 'Page.captureScreenshot', { format: 'png' });
  const outPath = path.join(ARTIFACTS_DIR, 'current-inspection.png');
  fs.writeFileSync(outPath, Buffer.from(screenshot.data, 'base64'));
  console.log('Saved inspection screenshot:', outPath);

  pageWs.close();
  await sendCdp(browserWs, 'Target.closeTarget', { targetId: target.targetId });
  browserWs.close();
  chromeProc.kill();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
