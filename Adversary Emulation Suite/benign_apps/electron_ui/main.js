const { app, BrowserWindow, ipcMain } = require('electron');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

let server;
let settingsPath;
let completed = false;

function appendAudit(file, line) {
  const dir = process.env.BKAES_AUDIT_JOB_DIR;
  if (!dir) return;
  try { fs.appendFileSync(path.join(dir, file), line + '\r\n', 'utf8'); } catch (_) {}
}

function fail(reason) {
  appendAudit('bkaes-assertions.txt', `[BKAES_ASSERT_FAIL] electron_ui ${reason}`);
  app.exit(1);
}

function createLoopbackServer() {
  server = http.createServer((request, response) => {
    if (request.url === '/api/status') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({service: 'normal-electron-ui', state: 'healthy'}));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

app.whenReady().then(async () => {
  settingsPath = path.join(os.tmpdir(), `bkaes-electron-${process.pid}.json`);
  fs.writeFileSync(settingsPath, JSON.stringify({theme: 'dark', currency: 'AUD', overlay: true}));
  const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
  if (settings.currency !== 'AUD') return fail('settings roundtrip failed');
  let port;
  try { port = await createLoopbackServer(); } catch (error) { return fail(`loopback bind failed: ${error.message}`); }

  ipcMain.handle('normal:summary', async () => ({port, platform: process.platform, arch: process.arch}));
  ipcMain.handle('normal:complete', async (_event, result) => {
    if (!result || result.total !== 377 || result.serverState !== 'healthy') return fail('renderer self-test mismatch');
    completed = true;
    appendAudit('bkaes-protection-outcome.txt',
      '[BKAES_OUTCOME] benign_electron_ui=passed calculation=377 loopback=ok settings=roundtrip ui=chromium');
    setTimeout(() => app.quit(), 400);
    return {ok: true};
  });

  const window = new BrowserWindow({
    width: 720, height: 480, show: true, title: 'BKAES Normal Electron Dashboard',
    webPreferences: {preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false}
  });
  await window.loadFile(path.join(__dirname, 'index.html'));
  setTimeout(() => { if (!completed) fail('renderer watchdog expired'); }, 8000).unref();
}).catch(error => fail(error.message));

app.on('before-quit', () => {
  if (server) server.close();
  if (settingsPath) { try { fs.unlinkSync(settingsPath); } catch (_) {} }
});
app.on('window-all-closed', () => { if (completed) app.quit(); });
