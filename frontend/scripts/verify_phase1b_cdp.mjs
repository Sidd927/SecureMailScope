import fs from 'fs';
import path from 'path';

const DEBUG_PORT = 9222;
const ARTIFACT_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/b43e7f3d-2177-47fc-915f-8e69df23609b';
const AUDIT_DIR = '/Users/siddhant_patil/Projects/SecureMailScope/audit/phase1b';

if (!fs.existsSync(AUDIT_DIR)) {
  fs.mkdirSync(AUDIT_DIR, { recursive: true });
}

async function getTargetTab() {
  const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`);
  const tabs = await res.json();
  const tab = tabs.find(t => t.url.includes('localhost:5173') || t.title.includes('SecureMailScope'));
  if (!tab) throw new Error('SecureMailScope tab not found in Chrome on port 9222');
  return tab;
}

function createCdpClient(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 1;
  const callbacks = new Map();
  const listeners = new Map();

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && callbacks.has(msg.id)) {
      const { resolve, reject } = callbacks.get(msg.id);
      callbacks.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
    } else if (msg.method) {
      const arr = listeners.get(msg.method) || [];
      for (const fn of arr) fn(msg.params);
    }
  };

  const ready = new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });

  const send = async (method, params = {}) => {
    await ready;
    const reqId = id++;
    return new Promise((resolve, reject) => {
      callbacks.set(reqId, { resolve, reject });
      ws.send(JSON.stringify({ id: reqId, method, params }));
    });
  };

  const on = (method, handler) => {
    if (!listeners.has(method)) listeners.set(method, []);
    listeners.get(method).push(handler);
  };

  const close = () => ws.close();

  return { ready, send, on, close };
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function captureShot(cdp, filename) {
  const shot = await cdp.send('Page.captureScreenshot', { format: 'png' });
  const buf = Buffer.from(shot.data, 'base64');
  const auditPath = path.join(AUDIT_DIR, filename);
  const artifactPath = path.join(ARTIFACT_DIR, filename);
  fs.writeFileSync(auditPath, buf);
  fs.writeFileSync(artifactPath, buf);
  console.log(`Saved screenshot: ${auditPath} and ${artifactPath} (${(buf.length / 1024).toFixed(1)} KB)`);
  return artifactPath;
}

async function run() {
  console.log('=== PHASE 1B CDP CASE DESK VALIDATION STARTING ===');
  const tab = await getTargetTab();
  console.log(`Connected to Chrome tab: ${tab.title} (${tab.id})`);
  const cdp = createCdpClient(tab.webSocketDebuggerUrl);
  await cdp.ready;

  await cdp.send('Page.enable');
  await cdp.send('DOM.enable');
  await cdp.send('Network.enable');

  const consoleErrors = [];
  cdp.on('Runtime.consoleAPICalled', (params) => {
    if (params.type === 'error') {
      const text = params.args.map(a => a.value ?? a.description ?? '').join(' ');
      consoleErrors.push(text);
      console.error(`[Browser ERROR] ${text}`);
    }
  });

  // 1. Viewport 1440x900 Case Desk
  console.log('\n--- 1. Testing Case Desk at 1440x900 ---');
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1500);

  // Evaluate Case Desk elements
  const caseDeskCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const hero = document.querySelector('.sms-case-desk__hero');
      const title = document.querySelector('.sms-case-desk__title')?.innerText;
      const techPills = Array.from(document.querySelectorAll('.sms-tech-pill')).map(p => p.innerText.trim());
      const ingestBay = document.querySelector('.sms-ingest-bay');
      const ingestTitle = document.querySelector('.sms-ingest-drop__title')?.innerText;
      const ledgerRows = Array.from(document.querySelectorAll('.sms-ledger__row')).map(r => ({
        posture: r.querySelector('.sms-ledger__col-posture span')?.innerText,
        score: r.querySelector('.sms-ledger__score')?.innerText,
        file: r.querySelector('.sms-ledger__filename')?.innerText,
        signalOrHash: r.querySelector('.sms-ledger__meta-line')?.innerText
      }));
      const scenarios = Array.from(document.querySelectorAll('.sms-scenario-card')).map(s => ({
        file: s.querySelector('.sms-scenario-card__file')?.innerText,
        score: s.querySelector('.sms-scenario-card__score')?.innerText,
        signal: s.querySelector('.sms-scenario-card__signal')?.innerText
      }));
      return {
        hasHero: !!hero,
        title,
        techPillCount: techPills.length,
        techPills,
        hasIngestBay: !!ingestBay,
        ingestTitle,
        ledgerRowCount: ledgerRows.length,
        ledgerRows,
        scenarioCount: scenarios.length,
        scenarios
      };
    })()`,
    returnByValue: true
  });
  console.log('Case Desk DOM Check:', JSON.stringify(caseDeskCheck.result.value, null, 2));
  await captureShot(cdp, 'phase1b_casedesk_1440x900.png');

  // 2. Stage real PCAP file and inspect in-browser SHA-256 computation
  console.log('\n--- 2. Testing Staged Ingest with Real PCAP ---');
  const pcapPath = '/Users/siddhant_patil/Projects/SecureMailScope/frontend/public/test_caps/backup_weak_certificate.pcap';
  const fileInputNode = await cdp.send('DOM.querySelector', {
    nodeId: (await cdp.send('DOM.getDocument')).root.nodeId,
    selector: 'input[type="file"]'
  });
  
  if (fileInputNode.nodeId) {
    await cdp.send('DOM.setFileInputFiles', {
      files: [pcapPath],
      nodeId: fileInputNode.nodeId
    });
    // Trigger change event
    await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const input = document.querySelector('input[type="file"]');
        if (input) input.dispatchEvent(new Event('change', { bubbles: true }));
      })()`
    });
    await sleep(1500);

    const stagedCheck = await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const staged = document.querySelector('.sms-ingest-staged');
        const fileName = document.querySelector('.sms-ingest-file-card__name')?.innerText;
        const hashVal = document.querySelector('.sms-ingest-hash-val')?.innerText;
        const analyzeBtn = document.querySelector('.sms-ingest-execute-btn')?.innerText;
        return {
          isStaged: !!staged,
          fileName,
          hashVal,
          analyzeBtn
        };
      })()`,
      returnByValue: true
    });
    console.log('Staged Ingest Check:', JSON.stringify(stagedCheck.result.value, null, 2));
    await captureShot(cdp, 'phase1b_staged_capture_1440x900.png');
  }

  // 3. Test Scenario Pivot
  console.log('\n--- 3. Testing Validated Scenario Pivot ---');
  // Return to home first
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1000);
  
  // Click on the second scenario (deepdive_cross_session_control_endpoint.pcap)
  await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const btns = Array.from(document.querySelectorAll('.sms-scenario-card__btn'));
      if (btns[1]) btns[1].click();
    })()`
  });
  await sleep(2500);

  const pivotCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const inWorkbench = document.querySelector('.sms-workbench-root');
      const activeFilename = document.querySelector('.sms-header__case-name')?.innerText;
      const scoreVal = document.querySelector('.sms-header__score-val')?.innerText;
      return {
        inWorkbench: !!inWorkbench,
        activeFilename,
        scoreVal
      };
    })()`,
    returnByValue: true
  });
  console.log('Scenario Pivot Check:', JSON.stringify(pivotCheck.result.value, null, 2));
  await captureShot(cdp, 'phase1b_scenario_pivot_1440x900.png');

  // 4. Responsive Testing at 1280x800
  console.log('\n--- 4. Testing Responsive Case Desk at 1280x800 ---');
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1280,
    height: 800,
    deviceScaleFactor: 1,
    mobile: false
  });
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1200);

  const overflowCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      return {
        docScrollWidth: document.documentElement.scrollWidth,
        windowInnerWidth: window.innerWidth,
        hasHorizontalOverflow: document.documentElement.scrollWidth > window.innerWidth
      };
    })()`,
    returnByValue: true
  });
  console.log('1280x800 Overflow Check:', JSON.stringify(overflowCheck.result.value, null, 2));
  await captureShot(cdp, 'phase1b_casedesk_1280x800.png');

  console.log('\n=== PHASE 1B CASE DESK VALIDATION COMPLETE ===');
  console.log(`Total Console errors recorded: ${consoleErrors.length}`);
  cdp.close();
}

run().catch((err) => {
  console.error('Validation script failed:', err);
  process.exit(1);
});
