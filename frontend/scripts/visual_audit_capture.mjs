import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const ARTIFACTS_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/c94bd2f3-94f0-4940-880e-098ae23efaaa';
const CHROME_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEBUG_PORT = 9223;

const auditTasks = [
  {
    name: 'audit_A_launchpad_1440x900.png',
    url: 'http://localhost:5173/?view=home',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_B_overview_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_B_overview_fullpage.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1440,
    height: 1800,
  },
  {
    name: 'audit_C_findings_deck_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1440,
    height: 900,
    scroll: 380,
  },
  {
    name: 'audit_D_protocol_journey_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=timeline',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_E_evidence_ledger_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=evidence',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_F_certificate_forensics_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=certs',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_G_cross_session_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=871ea0c739b246098ff481c887afcc0f&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_H_contextual_inspector_open.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=timeline&finding=Certificate%20public%20key%20strength',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_I_command_palette_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview&modal=command',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_J_error_unavailable_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=invalid_unregistered_pcap_case_9999&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_K_empty_insufficient_history.png',
    url: 'http://localhost:5173/?view=workbench&run_id=d461211725ca49a08c078f27a56d4470&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_L_responsive_1280x800.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1280,
    height: 800,
  },
  {
    name: 'audit_M_responsive_1440x900.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1440,
    height: 900,
  },
  {
    name: 'audit_N_responsive_1600x1000.png',
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview',
    width: 1600,
    height: 1000,
  },
  {
    name: 'audit_O_responsive_768x1024.png',
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
  console.log('Launching headless Chrome on audit port', DEBUG_PORT);
  const chromeProc = spawn(CHROME_PATH, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
  ]);

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

  const browserWs = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve) => browserWs.addEventListener('open', resolve));

  for (const t of auditTasks) {
    console.log(`Auditing: ${t.name}`);
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

    if (t.scroll) {
      await sendCdp(pageWs, 'Runtime.evaluate', {
        expression: `window.scrollTo({ top: ${t.scroll}, behavior: 'instant' })`,
      });
      await sleep(500);
    }

    const screenshot = await sendCdp(pageWs, 'Page.captureScreenshot', { format: 'png' });
    const outPath = path.join(ARTIFACTS_DIR, t.name);
    fs.writeFileSync(outPath, Buffer.from(screenshot.data, 'base64'));
    console.log(`Captured: ${t.name} (${screenshot.data.length} bytes)`);

    pageWs.close();
    await sendCdp(browserWs, 'Target.closeTarget', { targetId: target.targetId });
  }

  browserWs.close();
  chromeProc.kill();
  console.log('Complete Visual Audit Capture Finished!');
}

main().catch((err) => {
  console.error('Audit capture failed:', err);
  process.exit(1);
});
