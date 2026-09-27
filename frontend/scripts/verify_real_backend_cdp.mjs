import fs from 'fs';
import path from 'path';

const DEBUG_PORT = 9222;

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

async function runVerification() {
  console.log('=== REAL-BACKEND VERIFICATION RUNNING VIA CDP ===');
  const tab = await getTargetTab();
  console.log(`Connecting to Chrome tab: ${tab.title} (${tab.id})`);
  const cdp = createCdpClient(tab.webSocketDebuggerUrl);
  await cdp.ready;

  await cdp.send('Page.enable');
  await cdp.send('DOM.enable');
  await cdp.send('Network.enable');

  const networkLog = [];
  cdp.on('Network.requestWillBeSent', (params) => {
    if (params.request.url.includes('/api/v1/')) {
      networkLog.push({
        requestId: params.requestId,
        timestamp: params.wallTime,
        url: params.request.url,
        method: params.request.method,
        hasPostData: !!params.request.hasPostData,
        postData: params.request.postData
      });
      console.log(`[NET REQ] ${params.request.method} ${params.request.url}`);
    }
  });

  const responseBodies = new Map();
  cdp.on('Network.responseReceived', async (params) => {
    if (params.response.url.includes('/api/v1/')) {
      console.log(`[NET RES] ${params.response.status} ${params.response.url}`);
      try {
        const bodyRes = await cdp.send('Network.getResponseBody', { requestId: params.requestId });
        responseBodies.set(params.requestId, {
          status: params.response.status,
          url: params.response.url,
          body: bodyRes.body
        });
      } catch (e) {
        // Body might not be available or already consumed
      }
    }
  });

  // STEP 1: Navigate to fresh Home
  console.log('\n--- Step 1: Navigate to Home screen ---');
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1500);

  // Check Home DOM and status badge
  const homeCheck = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const statusPill = document.querySelector('.sms-status');
      const offlineBanner = document.querySelector('.sms-offline-banner');
      const title = document.querySelector('.sms-home__title')?.innerText;
      const fileInput = document.querySelector('input[type="file"]') ? true : false;
      return {
        statusText: statusPill?.innerText,
        statusClass: statusPill?.className,
        hasOfflineBanner: !!offlineBanner,
        title,
        hasFileInput: fileInput
      };
    })()`,
    returnByValue: true
  });
  console.log('Home state check:', homeCheck.result.value);

  // STEP 2: Upload backup_weak_certificate.pcap
  console.log('\n--- Step 2: Upload backup_weak_certificate.pcap ---');
  const pcapWeakPath = path.resolve('demo/captures/backup_weak_certificate.pcap');
  const docRoot = await cdp.send('DOM.getDocument');
  const fileInputNode = await cdp.send('DOM.querySelector', {
    nodeId: docRoot.root.nodeId,
    selector: 'input[type="file"]'
  });

  console.log(`Setting file on input node: ${fileInputNode.nodeId} -> ${pcapWeakPath}`);
  await cdp.send('DOM.setFileInputFiles', {
    files: [pcapWeakPath],
    nodeId: fileInputNode.nodeId
  });

  // Trigger change event
  await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const input = document.querySelector('input[type="file"]');
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`
  });

  console.log('Waiting for analysis and workbench transition...');
  await sleep(3000);

  // Capture Weak Cert DOM state
  const weakCertDom = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const score = document.querySelector('.sms-score__value')?.innerText;
      const band = document.querySelector('.sms-score__band')?.innerText;
      const findings = Array.from(document.querySelectorAll('.sms-finding-item, .sms-finding-card, .sms-finding-row, .sms-table__row, [data-finding-id]')).map(el => el.innerText);
      const allText = document.body.innerText;
      const statusPill = document.querySelector('.sms-status');
      const currentUrl = window.location.href;
      return {
        score,
        band,
        statusText: statusPill?.innerText,
        statusClass: statusPill?.className,
        currentUrl,
        hasRSA1024: allText.includes('RSA') || allText.includes('1024'),
        hasSHA1: allText.includes('SHA-1') || allText.includes('sha1'),
        hasStream0: allText.includes('Stream #0') || allText.includes('Stream 0') || allText.includes(':0'),
        hasSMTPS465: allText.includes('465') || allText.includes('SMTPS'),
        findingsSnippet: findings.slice(0, 5)
      };
    })()`,
    returnByValue: true
  });
  console.log('Weak Cert Workbench DOM:', weakCertDom.result.value);

  // Take screenshot 1
  const ss1 = await cdp.send('Page.captureScreenshot', { format: 'png' });
  const ss1Path = path.resolve('demo/test_weak_cert_workbench.png');
  fs.writeFileSync(ss1Path, Buffer.from(ss1.data, 'base64'));
  console.log(`Saved screenshot 1 to: ${ss1Path}`);

  // Test Report preview tab
  console.log('\n--- Step 3: Switch to Reports Tab ---');
  await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const btn = Array.from(document.querySelectorAll('button, [role="tab"]')).find(el => el.innerText.trim().toLowerCase() === 'report' || el.innerText.trim().toLowerCase() === 'reports');
      if (btn) btn.click();
    })()`
  });
  await sleep(2000);

  const reportDom = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const text = document.body.innerText;
      return {
        hasReportDoc: text.includes('Forensic Report') || text.includes('Assessment ID') || text.includes('Report'),
        snippet: text.slice(0, 500)
      };
    })()`,
    returnByValue: true
  });
  console.log('Report tab DOM state:', reportDom.result.value);

  // STEP 4: Test Cross Session
  console.log('\n--- Step 4: Test deepdive_cross_session_control_endpoint.pcap ---');
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=home' });
  await sleep(1500);

  const docRoot2 = await cdp.send('DOM.getDocument');
  const fileInputNode2 = await cdp.send('DOM.querySelector', {
    nodeId: docRoot2.root.nodeId,
    selector: 'input[type="file"]'
  });

  const pcapCrossPath = path.resolve('demo/captures/deepdive_cross_session_control_endpoint.pcap');
  console.log(`Setting file on input node: ${fileInputNode2.nodeId} -> ${pcapCrossPath}`);
  await cdp.send('DOM.setFileInputFiles', {
    files: [pcapCrossPath],
    nodeId: fileInputNode2.nodeId
  });

  await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const input = document.querySelector('input[type="file"]');
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`
  });

  console.log('Waiting for cross-session analysis and workbench transition...');
  await sleep(3500);

  const crossCertDom = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const score = document.querySelector('.sms-score__value')?.innerText;
      const band = document.querySelector('.sms-score__band')?.innerText;
      const allText = document.body.innerText;
      const statusPill = document.querySelector('.sms-status');
      const currentUrl = window.location.href;
      return {
        score,
        band,
        statusText: statusPill?.innerText,
        statusClass: statusPill?.className,
        currentUrl,
        has22: allText.includes('22.15'),
        hasCSFinding: allText.includes('CS-STARTTLS-001') || allText.includes('deviation from baseline') || allText.includes('STARTTLS')
      };
    })()`,
    returnByValue: true
  });
  console.log('Cross Session Workbench DOM:', crossCertDom.result.value);

  // Switch to Cross-Session Tab
  console.log('\n--- Step 5: Switch to Cross-Session Tab ---');
  await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const btn = Array.from(document.querySelectorAll('button, [role="tab"]')).find(el => el.innerText.trim().toLowerCase().includes('cross-session') || el.innerText.trim().toLowerCase().includes('cross session'));
      if (btn) btn.click();
    })()`
  });
  await sleep(2000);

  const crossTabDom = await cdp.send('Runtime.evaluate', {
    expression: `(() => {
      const allText = document.body.innerText;
      return {
        hasSubject10_0_0_6: allText.includes('10.0.0.6'),
        hasControl10_0_0_7: allText.includes('10.0.0.7'),
        hasCS_STARTTLS_001: allText.includes('CS-STARTTLS-001') || allText.includes('STARTTLS/STLS advertisement deviation')
      };
    })()`,
    returnByValue: true
  });
  console.log('Cross Session Tab DOM:', crossTabDom.result.value);

  // Take screenshot 2
  const ss2 = await cdp.send('Page.captureScreenshot', { format: 'png' });
  const ss2Path = path.resolve('demo/test_cross_session_workbench.png');
  fs.writeFileSync(ss2Path, Buffer.from(ss2.data, 'base64'));
  console.log(`Saved screenshot 2 to: ${ss2Path}`);

  // Summary of all API calls
  console.log('\n=== SUMMARY OF ALL INTERCEPTED API CALLS ===');
  const postCalls = networkLog.filter(n => n.method === 'POST');
  console.log(`Total API Requests: ${networkLog.length}, Total POST: ${postCalls.length}`);
  for (const [reqId, res] of responseBodies.entries()) {
    console.log(`\nResponse [${res.status}] ${res.url}:`);
    console.log(res.body.slice(0, 300) + (res.body.length > 300 ? '...' : ''));
  }

  cdp.close();
  console.log('\n=== TEST COMPLETE ===');
}

runVerification().catch(err => {
  console.error('VERIFICATION ERROR:', err);
  process.exit(1);
});
