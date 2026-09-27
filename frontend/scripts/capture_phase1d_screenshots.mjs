import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const ARTIFACTS_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/b43e7f3d-2177-47fc-915f-8e69df23609b';
const DEMO_DIR = '/Users/siddhant_patil/Projects/SecureMailScope/demo/phase1d';
const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEBUG_PORT = 9225;

const RUN_CASE_A = '58d5f74ba5024c83ad6e62dae6dd06b6'; // backup_weak_certificate.pcap (44.00 CRITICAL)
const RUN_CASE_B = '871ea0c739b246098ff481c887afcc0f'; // deepdive_cross_session_control_endpoint.pcap (22.15 CRITICAL)
const RUN_CASE_C = '9aaefe1d93f046faac255dfe67c86c18'; // scene_b_certificate_honesty.pcap (100.00 STRONG)

const tasks = [
  {
    name: '01-home.png',
    url: 'http://localhost:5173/?view=home',
    width: 1440,
    height: 900,
  },
  {
    name: '02-case-b-overview-1440.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=overview`,
    width: 1440,
    height: 900,
  },
  {
    name: '03-case-b-overview-1600.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=overview`,
    width: 1600,
    height: 1000,
  },
  {
    name: '04-case-a-overview.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_A}&tab=overview`,
    width: 1440,
    height: 900,
  },
  {
    name: '05-case-c-overview.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_C}&tab=overview`,
    width: 1440,
    height: 900,
  },
  {
    name: '06-findings.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=evidence`,
    width: 1440,
    height: 900,
  },
  {
    name: '07-protocol-journey.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=timeline&frame=7`,
    width: 1440,
    height: 900,
  },
  {
    name: '08-certificates.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_A}&tab=certs`,
    width: 1440,
    height: 900,
  },
  {
    name: '09-cross-session.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=cross_session`,
    width: 1440,
    height: 900,
  },
  {
    name: '10-provenance.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=provenance`,
    width: 1440,
    height: 900,
  },
  {
    name: '11-report.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=report`,
    width: 1440,
    height: 900,
  },
  {
    name: '12-responsive-768.png',
    url: `http://localhost:5173/?view=workbench&run_id=${RUN_CASE_B}&tab=overview`,
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
  if (!fs.existsSync(DEMO_DIR)) {
    fs.mkdirSync(DEMO_DIR, { recursive: true });
  }

  console.log(`Starting headless Chrome on debug port ${DEBUG_PORT}...`);
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--user-data-dir=/tmp/chrome-phase1d-capture',
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
    console.error('Failed to connect to Chrome CDP endpoint');
    chromeProc.kill();
    process.exit(1);
  }

  console.log('Connected to Chrome WebSocket:', version.webSocketDebuggerUrl);
  const browserWs = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve) => browserWs.addEventListener('open', resolve));

  for (const t of tasks) {
    console.log(`\nCapturing [${t.name}] (${t.width}x${t.height}) -> ${t.url}`);
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
    const buf = Buffer.from(screenshot.data, 'base64');

    const outArtifact = path.join(ARTIFACTS_DIR, t.name);
    const outDemo = path.join(DEMO_DIR, t.name);

    fs.writeFileSync(outArtifact, buf);
    fs.writeFileSync(outDemo, buf);

    console.log(`Saved screenshot: ${t.name} (${buf.length} bytes) to artifacts and demo/phase1d`);

    pageWs.close();
    await sendCdp(browserWs, 'Target.closeTarget', { targetId: target.targetId });
  }

  browserWs.close();
  chromeProc.kill();
  console.log('\nAll 12 Phase 1D deliverable screenshots captured successfully!');
}

main().catch((err) => {
  console.error('Phase 1D capture script error:', err);
  process.exit(1);
});
