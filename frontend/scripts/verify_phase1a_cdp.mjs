import fs from 'fs';
import path from 'path';

const DEBUG_PORT = 9222;
const ARTIFACT_DIR = '/Users/siddhant_patil/.gemini/antigravity-ide/brain/b43e7f3d-2177-47fc-915f-8e69df23609b';
const AUDIT_DIR = '/Users/siddhant_patil/Projects/SecureMailScope/audit/phase1a';

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
  console.log('=== PHASE 1A CDP VALIDATION STARTING ===');
  const tab = await getTargetTab();
  console.log(`Connected to Chrome tab: ${tab.title} (${tab.id})`);
  const cdp = createCdpClient(tab.webSocketDebuggerUrl);
  await cdp.ready;

  await cdp.send('Page.enable');
  await cdp.send('DOM.enable');
  await cdp.send('Network.enable');

  const consoleLogs = [];
  cdp.on('Runtime.consoleAPICalled', (params) => {
    const text = params.args.map(a => a.value ?? a.description ?? '').join(' ');
    consoleLogs.push({ type: params.type, text });
    if (params.type === 'error') {
      console.error(`[Browser ERROR] ${text}`);
    }
  });

  // 1. Viewport 1440x900 Home View
  console.log('\n--- 1. Testing Home View at 1440x900 ---');
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1500);

  // Evaluate header elements
  const homeHeaderCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const header = document.querySelector('.sms-header');
      const brand = document.querySelector('.sms-brand-logo');
      const livePill = document.querySelector('.sms-status-pill--live');
      const archBadge = document.querySelector('.sms-header__arch-badge');
      return {
        hasHeader: !!header,
        hasBrandLogo: !!brand,
        brandText: brand ? brand.innerText.trim().replace(/\\n/g, ' ') : null,
        isEngineLive: !!livePill,
        livePillText: livePill ? livePill.innerText.trim() : null,
        archBadgeText: archBadge ? archBadge.innerText.trim() : null,
      };
    })()`,
    returnByValue: true
  });
  console.log('Home Header Check:', JSON.stringify(homeHeaderCheck.result.value, null, 2));
  await captureShot(cdp, 'phase1a_home_1440x900.png');

  // 2. Viewport 1440x900 Workbench View (Case A: backup_weak_certificate.pcap, 44.0 CRITICAL)
  console.log('\n--- 2. Testing Workbench Case A at 1440x900 ---');
  await cdp.send('Page.navigate', {
    url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=overview'
  });
  await sleep(2000);

  const workbenchCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const casePill = document.querySelector('.sms-header__case-pill');
      const caseName = document.querySelector('.sms-header__case-name');
      const caseMeta = document.querySelector('.sms-header__case-meta');
      const findingBadge = document.querySelector('.sms-header__finding-badge');
      const scoreVal = document.querySelector('.sms-header__score-val');
      const posturePill = document.querySelector('.sms-header__posture-cluster span');
      const tabs = Array.from(document.querySelectorAll('.sms-tab')).map(t => ({
        label: t.querySelector('.sms-tab__label')?.innerText,
        active: t.getAttribute('aria-selected') === 'true',
        badge: t.querySelector('.sms-tab__badge')?.innerText ?? null,
        key: t.querySelector('.sms-tab__key')?.innerText ?? null
      }));
      return {
        caseFilename: caseName ? caseName.innerText : null,
        sessionCountMeta: caseMeta ? caseMeta.innerText : null,
        findingBadge: findingBadge ? findingBadge.innerText : null,
        scoreText: scoreVal ? scoreVal.innerText : null,
        postureBandText: posturePill ? posturePill.innerText : null,
        tabsCount: tabs.length,
        tabs
      };
    })()`,
    returnByValue: true
  });
  console.log('Workbench Header & Tabs Check:', JSON.stringify(workbenchCheck.result.value, null, 2));
  await captureShot(cdp, 'phase1a_workbench_weak_cert_1440x900.png');

  // 3. Open Score Deduction Modal
  console.log('\n--- 3. Testing Score Waterfall Modal ---');
  await cdp.send('Runtime.evaluate', {
    expression: `document.querySelector('.sms-header__score-link')?.click()`
  });
  await sleep(500);
  await captureShot(cdp, 'phase1a_score_waterfall_modal_1440x900.png');

  // Close modal via Escape
  await cdp.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await sleep(400);

  // 4. Testing Workbench Case B at 1440x900 (deepdive_cross_session_control_endpoint.pcap, 22.15 CRITICAL)
  console.log('\n--- 4. Testing Workbench Case B at 1440x900 ---');
  await cdp.send('Page.navigate', {
    url: 'http://localhost:5173/?view=workbench&run_id=871ea0c739b246098ff481c887afcc0f&tab=overview'
  });
  await sleep(2000);
  const caseBCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const caseName = document.querySelector('.sms-header__case-name')?.innerText;
      const caseMeta = document.querySelector('.sms-header__case-meta')?.innerText;
      const findingBadge = document.querySelector('.sms-header__finding-badge')?.innerText;
      const scoreVal = document.querySelector('.sms-header__score-val')?.innerText;
      return { caseName, caseMeta, findingBadge, scoreVal };
    })()`,
    returnByValue: true
  });
  console.log('Case B Header Check:', JSON.stringify(caseBCheck.result.value, null, 2));
  await captureShot(cdp, 'phase1a_workbench_cross_session_1440x900.png');

  // 5. Responsive Testing at 1280x800
  console.log('\n--- 5. Testing Responsive at 1280x800 ---');
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1280,
    height: 800,
    deviceScaleFactor: 1,
    mobile: false
  });
  await sleep(1000);
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
  await captureShot(cdp, 'phase1a_workbench_1280x800.png');

  // 6. Responsive Home at 1280x800
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1200);
  await captureShot(cdp, 'phase1a_home_1280x800.png');

  console.log('\n=== PHASE 1A VALIDATION COMPLETE ===');
  console.log(`Total Console logs recorded: ${consoleLogs.length}`);
  cdp.close();
}

run().catch((err) => {
  console.error('Validation script failed:', err);
  process.exit(1);
});
