let PATHS = [];
let pathsLoaded = false;
let loadingPromise = null;

const DEFAULT_PATHS = [
  "/.env", "/.git/config", "/.git/HEAD", "/.gitignore", "/backup.sql", "/dump.sql",
  "/.htpasswd", "/.htaccess", "/wp-config.php", "/phpinfo.php", "/info.php", "/admin/",
  "/.vscode/sftp.json", "/.idea/workspace.xml", "/debug.log", "/error.log",
  "/credentials", "/wwwroot.zip", "/robots.txt", "/.DS_Store", "/Thumbs.db",
  "/node_modules/", "/vendor/", "/composer.json", "/package.json", "/Dockerfile",
  "/docker-compose.yml", "/Jenkinsfile", "/.travis.yml", "/.circleci/config.yml"
];

async function loadWordlist() {
  if (pathsLoaded) return;
  if (loadingPromise) return loadingPromise;
  loadingPromise = (async () => {
    try {
      const url = browser.runtime.getURL('wordlist.txt');
      const response = await fetch(url);
      if (!response.ok) throw new Error('wordlist fetch failed');
      const text = await response.text();
      PATHS = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith('//') && !l.startsWith('/*'));
      if (PATHS.length === 0) PATHS = DEFAULT_PATHS;
    } catch (e) {
      console.error('wordlist load error', e);
      PATHS = DEFAULT_PATHS;
    } finally {
      pathsLoaded = true;
      loadingPromise = null;
    }
  })();
  return loadingPromise;
}
loadWordlist();

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function getOptions() {
  const opts = await browser.storage.local.get('options');
  return opts.options || { timeout: 10, batchSize: 10, categories: ['git','docker','cicd','cloud','cms','backup','logs','ide'] };
}

// Контекстное меню
browser.contextMenus.create({ id: "scan-site", title: "Просканировать Sensitive Scanner", contexts: ["page"] });
browser.contextMenus.onClicked.addListener(async (info, tab) => {
  const baseUrl = new URL(tab.url).origin;
  try {
    const results = await performScan(baseUrl, 'site');
    await browser.storage.local.set({ lastScanResults: { baseUrl, mode: 'site', results, timestamp: Date.now() } });
    const count = results.filter(r => r.status !== 404).length;
    browser.browserAction.setBadgeText({ text: count > 0 ? String(count) : '' });
  } catch (e) { console.error(e); }
});

function checkPath(fullUrl, displayPath, timeout = 10) {
  return new Promise((resolve) => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('GET', fullUrl, true);
      xhr.responseType = 'text';
      xhr.timeout = timeout * 1000;
      xhr.onload = () => {
        const text = xhr.responseText || '';
        const debugDetected = checkForDjangoDebug(text);
        if ((xhr.status === 301 || xhr.status === 302) && xhr.getResponseHeader('Location')) {
          let redirectUrl = xhr.getResponseHeader('Location');
          try { redirectUrl = new URL(redirectUrl, fullUrl).href; } catch (e) {}
          const origProtocol = new URL(fullUrl).protocol;
          const newProtocol = new URL(redirectUrl).protocol;
          if (origProtocol !== newProtocol) {
            return checkPath(redirectUrl, displayPath, timeout).then(resolve);
          }
        }
        resolve({ path: displayPath, status: xhr.status, size: text.length, redirected: xhr.responseURL !== fullUrl, debugMode: debugDetected });
      };
      xhr.onerror = () => resolve({ path: displayPath, status: 'network_error', size: 0, error: 'XHR error' });
      xhr.ontimeout = () => resolve({ path: displayPath, status: 'network_error', size: 0, error: 'timeout' });
      xhr.send();
    } catch (e) {
      resolve({ path: displayPath, status: 'network_error', size: 0, error: e.message });
    }
  });
}

function checkForDjangoDebug(text) {
  if (!text) return false;
  const markers = ['DEBUG = True', 'DJANGO_SETTINGS_MODULE', "You're seeing this error because you have DEBUG = True", 'Traceback (most recent call last)', 'Request URL:', 'Django version:'];
  return markers.some(m => text.includes(m));
}

// Сканирование без прогресса (для контекстного меню)
async function performScan(baseUrl, mode) {
  await loadWordlist();
  const options = await getOptions();
  const timeout = options.timeout;
  const batchSize = options.batchSize;
  const total = PATHS.length;
  if (total === 0) return [];
  const results = [];
  for (let i = 0; i < total; i += batchSize) {
    const batch = PATHS.slice(i, i + batchSize);
    const batchResults = await Promise.allSettled(
      batch.map(path => {
        let url;
        if (mode === 'path') {
          const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
          url = new URL(path.startsWith('/') ? path.slice(1) : path, base).href;
        } else {
          url = new URL(path, baseUrl).href;
        }
        return checkPath(url, path, timeout);
      })
    );
    for (let j = 0; j < batch.length; j++) {
      const res = batchResults[j];
      results.push(res.status === 'fulfilled' ? res.value : { path: batch[j], status: 'error', size: 0, error: res.reason?.message });
    }
  }
  return results;
}

// Обработка порта попапа
browser.runtime.onConnect.addListener((port) => {
  if (port.name === "scanner") {
    let scanPaused = false;
    port.onMessage.addListener(async (msg) => {
      if (msg.command === "start") {
        const baseUrl = msg.url;
        const mode = msg.mode || 'site';
        await loadWordlist();
        const options = await getOptions();
        const timeout = options.timeout;
        const batchSize = options.batchSize;
        const total = PATHS.length;
        if (total === 0) {
          port.postMessage({ type: "result", results: [] });
          return;
        }
        const results = [];
        let completed = 0;
        const startTime = Date.now();
        scanPaused = false;
        for (let i = 0; i < total; i += batchSize) {
          while (scanPaused) await sleep(200);
          const batch = PATHS.slice(i, i + batchSize);
          const batchResults = await Promise.allSettled(
            batch.map(path => {
              let url;
              if (mode === 'path') {
                const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
                url = new URL(path.startsWith('/') ? path.slice(1) : path, base).href;
              } else {
                url = new URL(path, baseUrl).href;
              }
              return checkPath(url, path, timeout);
            })
          );
          for (let j = 0; j < batch.length; j++) {
            const res = batchResults[j];
            results.push(res.status === 'fulfilled' ? res.value : { path: batch[j], status: 'error', size: 0 });
            completed++;
          }
          const elapsed = (Date.now() - startTime) / 1000;
          const rate = completed / elapsed;
          port.postMessage({ type: "progress", current: completed, total: total, rate: Math.round(rate), eta: Math.round((total - completed) / rate) });
        }
        // Security headers
        let securityHeaders = null;
        try {
          const secXhr = new XMLHttpRequest();
          secXhr.open('GET', baseUrl, true);
          secXhr.timeout = 4000;
          secXhr.send();
          secXhr.onload = () => {
            securityHeaders = {
              'Content-Security-Policy': secXhr.getResponseHeader('Content-Security-Policy'),
              'X-Frame-Options': secXhr.getResponseHeader('X-Frame-Options'),
              'Strict-Transport-Security': secXhr.getResponseHeader('Strict-Transport-Security'),
              'X-Content-Type-Options': secXhr.getResponseHeader('X-Content-Type-Options'),
              'Referrer-Policy': secXhr.getResponseHeader('Referrer-Policy')
            };
            port.postMessage({ type: "result", results, securityHeaders });
          };
        } catch (e) {
          port.postMessage({ type: "result", results });
        }
        setTimeout(() => { if (!securityHeaders) port.postMessage({ type: "result", results }); }, 600);
      } else if (msg.command === "pause") {
        scanPaused = msg.value;
      }
    });
  }
});