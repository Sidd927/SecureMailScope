import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const ARTIFACTS_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/c94bd2f3-94f0-4940-880e-098ae23efaaa';
const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEBUG_PORT = 9222;

const tasks = [
  {
    name: 'god_mode_protocol_journey_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=timeline',
    width: 1440,
    height: 900,
  },
  {
    name: 'god_mode_evidence_ledger_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=evidence',
    width: 1440,
    height: 900,
  },
  {
    name: 'god_mode_certificates_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=certs',
    width: 1440,
    height: 900,
  },
  {
    name: 'god_mode_multistream_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=871ea0c739b246098ff481c887afcc0f&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'god_mode_compliant_case_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=9aaefe1d93f046faac255dfe67c86c18&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'god_mode_workbench_1280x800.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1280,
    height: 800,
  },
  {
    name: 'god_mode_workbench_768x1024.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 768,
    height: 1024,
  },
];

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
        if (parsed.error) {
          reject(parsed.error);
        } else {
          resolve(parsed.result);
        }
      }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  console.log('Launching headless Chrome on port', DEBUG_PORT);
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
  ]);

  // Wait for port to become active
  let version = null;
  for (let i = 0; i < 20; i++) {
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
    console.error('Failed to connect to Chrome CDP');
    chromeProc.kill();
    process.exit(1);
  }

  console.log('Connecting to browser WebSocket:', version.webSocketDebuggerUrl);
  const browserWs = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve) => browserWs.addEventListener('open', resolve));

  for (const t of tasks) {
    console.log(`Processing: ${t.name} -> ${t.url}`);
    // Create new target
    const target = await sendCdp(browserWs, 'Target.createTarget', { url: 'about:blank' });
    const targetWsUrl = `ws://127.0.0.1:${DEBUG_PORT}/devtools/page/${target.targetId}`;
    const pageWs = new WebSocket(targetWsUrl);
    await new Promise((resolve) => pageWs.addEventListener('open', resolve));

    await sendCdp(pageWs, 'Page.enable');
    await sendCdp(pageWs, 'Emulation.setDeviceMetricsOverride', {
      width: t.width,
      height: t.height,
      deviceScaleFactor: 1,
      mobile: false,
    });

    await sendCdp(pageWs, 'Page.navigate', { url: t.url });
    // Wait 3.5 seconds for data fetching and rendering
    await sleep(3500);

    const screenshot = await sendCdp(pageWs, 'Page.captureScreenshot', { format: 'png' });
    const outPath = path.join(ARTIFACTS_DIR, t.name);
    fs.writeFileSync(outPath, Buffer.from(screenshot.data, 'base64'));
    console.log(`Saved screenshot: ${outPath} (${screenshot.data.length} bytes)`);

    pageWs.close();
    await sendCdp(browserWs, 'Target.closeTarget', { targetId: target.targetId });
  }

  browserWs.close();
  chromeProc.kill();
  console.log('All screenshots captured successfully!');
}

main().catch((err) => {
  console.error('Error during screenshot capture:', err);
  process.exit(1);
});
