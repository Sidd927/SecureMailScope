import fs from 'fs';
import path from 'path';

const DEBUG_PORT = 9222;

async function getTargetTab() {
  const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`);
  const tabs = await res.json();
  const tab = tabs.find(t => t.url.includes('localhost:5173') || t.title.includes('SecureMailScope'));
  if (!tab) throw new Error('SecureMailScope tab not found');
  return tab;
}

function createCdpClient(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 1;
  const callbacks = new Map();

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && callbacks.has(msg.id)) {
      const { resolve, reject } = callbacks.get(msg.id);
      callbacks.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message));
      else resolve(msg.result);
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

  const close = () => ws.close();
  return { ready, send, close };
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function capture() {
  const tab = await getTargetTab();
  const cdp = createCdpClient(tab.webSocketDebuggerUrl);
  await cdp.ready;
  await cdp.send('Page.enable');

  // Go to weak cert workbench
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=journey' });
  await sleep(1500);
  const ssJourney = await cdp.send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('demo/test_weak_cert_journey.png', Buffer.from(ssJourney.data, 'base64'));

  // Go to certs tab
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=certs' });
  await sleep(1500);
  const ssCerts = await cdp.send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('demo/test_weak_cert_certs.png', Buffer.from(ssCerts.data, 'base64'));

  // Go to report tab
  await cdp.send('Page.navigate', { url: 'http://localhost:5173/?view=workbench&run_id=58d5f74ba5024c83ad6e62dae6dd06b6&tab=report' });
  await sleep(1500);
  const ssReport = await cdp.send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('demo/test_weak_cert_report.png', Buffer.from(ssReport.data, 'base64'));

  cdp.close();
  console.log('Deep evidence screenshots captured.');
}

capture().catch(console.error);
