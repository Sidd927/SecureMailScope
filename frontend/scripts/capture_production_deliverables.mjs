import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const ARTIFACTS_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/6d94de98-bbef-49b8-8afd-e84d6c9bc53c';
const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEBUG_PORT = 9224;

const captureTasks = [
  {
    name: '01_case_desk.png',
    url: 'http://127.0.0.1:5173/?view=home',
    width: 1440,
    height: 900,
  },
  {
    name: '02_investigation_overview.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: '03_finding.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview&finding=Certificate%20public%20key%20strength',
    width: 1440,
    height: 900,
  },
  {
    name: '04_protocol_journey.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=journey',
    width: 1440,
    height: 900,
  },
  {
    name: '05_certificate.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=certs',
    width: 1440,
    height: 900,
  },
  {
    name: '06_cross_session.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=871ea0c739b246098ff481c887afcc0f&tab=cross_session',
    width: 1440,
    height: 900,
  },
  {
    name: '07_provenance.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=provenance',
    width: 1440,
    height: 900,
  },
  {
    name: '08_report.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=report',
    width: 1440,
    height: 900,
  },
  {
    name: '09_upload_lifecycle.png',
    url: 'http://127.0.0.1:5173/?view=home&modal=intake',
    width: 1440,
    height: 900,
  },
  {
    name: '10_error_state.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=unregistered_invalid_session_capture&tab=overview',
    width: 1440,
    height: 900,
  },
  // Responsive viewports
  {
    name: 'responsive_1600x1000.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1600,
    height: 1000,
  },
  {
    name: 'responsive_1280x800.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1280,
    height: 800,
  },
  {
    name: 'responsive_1024x768.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1024,
    height: 768,
  },
  {
    name: 'responsive_768x1024.png',
    url: 'http://127.0.0.1:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
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
  if (!fs.existsSync(ARTIFACTS_DIR)) {
    fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  }

  console.log(`Starting headless Chrome on debug port ${DEBUG_PORT}...`);
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--user-data-dir=/tmp/chrome-audit-profile-final',
  ]);

  let version = null;
  for (let i = 0; i < 25; i++) {
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
    console.error('Failed to connect to Chrome CDP endpoint');
    chromeProc.kill();
    process.exit(1);
  }

  console.log('Connected to Chrome WebSocket:', version.webSocketDebuggerUrl);
  const browserWs = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve) => browserWs.addEventListener('open', resolve));

  for (const t of captureTasks) {
    console.log(`\nCapturing: ${t.name} (${t.width}x${t.height}) -> ${t.url}`);
    const target = await sendCdp(browserWs, 'Target.createTarget', { url: 'about:blank' });
    const targetWsUrl = `ws://127.0.0.1:${DEBUG_PORT}/devtools/page/${target.targetId}`;
    const pageWs = new WebSocket(targetWsUrl);
    await new Promise((resolve) => pageWs.addEventListener('open', resolve));

    await sendCdp(pageWs, 'Page.enable');
    await sendCdp(pageWs, 'Runtime.enable');
    await sendCdp(pageWs, 'Emulation.setDeviceMetricsOverride', {
      width: t.width,
      height: t.height,
      deviceScaleFactor: 1,
      mobile: t.width < 800,
    });

    await sendCdp(pageWs, 'Page.navigate', { url: t.url });
    // Allow data fetching & rendering to stabilize
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
  console.log('\nAll 14 deliverable screenshots captured successfully in artifacts directory!');
}

main().catch((err) => {
  console.error('Capture script error:', err);
  process.exit(1);
});
