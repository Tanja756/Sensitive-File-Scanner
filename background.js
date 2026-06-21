let pathEntries = [];
let wpPathEntries = [];
let pmaPathEntries = [];
let djangoPathEntries = [];
let pathsLoaded = false;
let wpPathsLoaded = false;
let pmaPathsLoaded = false;
let djangoPathsLoaded = false;
let loadingPromise = null;
let wpLoadingPromise = null;
let pmaLoadingPromise = null;
let djangoLoadingPromise = null;

async function loadWordlist(force = false) {
  if (pathsLoaded && !force) return;
  if (loadingPromise && !force) return loadingPromise;
  loadingPromise = (async () => {
    try {
      const stored = await browser.storage.local.get(['customWordlist', 'useCustomOnly']);
      let builtin = [];
      try {
        const url = browser.runtime.getURL('wordlist.txt');
        const response = await fetch(url);
        if (response.ok) {
          builtin = parseWordlistText(await response.text());
        }
      } catch (e) {
        console.error('wordlist fetch error', e);
      }
      if (builtin.length === 0) {
        builtin = DEFAULT_PATHS.map(path => ({ path, category: inferCategory(path) }));
      }
      let custom = [];
      if (stored.customWordlist && stored.customWordlist.trim()) {
        custom = parseWordlistText(stored.customWordlist);
      }
      if (stored.useCustomOnly && custom.length > 0) {
        pathEntries = custom;
      } else {
        pathEntries = mergeWordlistEntries(builtin, custom);
      }
    } catch (e) {
      console.error('wordlist load error', e);
      pathEntries = DEFAULT_PATHS.map(path => ({ path, category: inferCategory(path) }));
    } finally {
      pathsLoaded = true;
      loadingPromise = null;
    }
  })();
  return loadingPromise;
}
async function loadWpWordlist(force = false) {
  if (wpPathsLoaded && !force) return;
  if (wpLoadingPromise && !force) return wpLoadingPromise;
  wpLoadingPromise = (async () => {
    try {
      const url = browser.runtime.getURL('wordlist-wp.txt');
      const response = await fetch(url);
      if (response.ok) {
        wpPathEntries = parseWordlistText(await response.text());
      }
    } catch (e) {
      console.error('wp wordlist fetch error', e);
    }
    if (wpPathEntries.length === 0) {
      // Fallback: essential WordPress paths
      wpPathEntries = [
        { path: '/wp-config.php', category: 'cms' },
        { path: '/xmlrpc.php', category: 'cms' },
        { path: '/wp-login.php', category: 'cms' },
        { path: '/wp-content/', category: 'cms' },
        { path: '/wp-includes/', category: 'cms' },
        { path: '/wp-admin/', category: 'cms' },
        { path: '/wp-json/', category: 'cms' },
        { path: '/readme.html', category: 'cms' },
        { path: '/license.txt', category: 'cms' }
      ];
    }
  })();
  return wpLoadingPromise;
}

async function loadPmaWordlist(force = false) {
  if (pmaPathsLoaded && !force) return;
  if (pmaLoadingPromise && !force) return pmaLoadingPromise;
  pmaLoadingPromise = (async () => {
    try {
      const url = browser.runtime.getURL('wordlist-pma.txt');
      const response = await fetch(url);
      if (response.ok) {
        pmaPathEntries = parseWordlistText(await response.text());
      }
    } catch (e) {
      console.error('pma wordlist fetch error', e);
    }
    if (pmaPathEntries.length === 0) {
      pmaPathEntries = [
        { path: '/phpmyadmin/', category: 'cms' },
        { path: '/phpMyAdmin/', category: 'cms' },
        { path: '/pma/', category: 'cms' },
        { path: '/phpmyadmin/README', category: 'cms' },
        { path: '/phpmyadmin/config.inc.php', category: 'cms' },
        { path: '/phpmyadmin/setup/', category: 'cms' },
        { path: '/phpmyadmin/sql.php', category: 'cms' }
      ];
    }
  })();
  return pmaLoadingPromise;
}

async function loadDjangoWordlist(force = false) {
  if (djangoPathsLoaded && !force) return;
  if (djangoLoadingPromise && !force) return djangoLoadingPromise;
  djangoLoadingPromise = (async () => {
    try {
      djangoPathEntries = [
        { path: '/.env', category: 'cloud' },
        { path: '/.env.local', category: 'cloud' },
        { path: '/.env.production', category: 'cloud' },
        { path: '/.env.development', category: 'cloud' },
        { path: '/.env.staging', category: 'cloud' },
        { path: '/.env.backup', category: 'cloud' },
        { path: '/.env.old', category: 'cloud' },
        { path: '/debug.log', category: 'logs' },
        { path: '/error.log', category: 'logs' },
        { path: '/django.log', category: 'logs' },
        { path: '/django_debug.log', category: 'logs' },
        { path: '/django-error.log', category: 'logs' },
        { path: '/access.log', category: 'logs' },
        { path: '/app.log', category: 'logs' },
        { path: '/__debug__/', category: 'cms' },
        { path: '/settings/', category: 'cms' },
        { path: '/debug/', category: 'cms' },
        { path: '/env/', category: 'cms' },
        { path: '/admin/', category: 'cms' },
        { path: '/manage.py', category: 'cms' },
        { path: '/robots.txt', category: 'cms' },
        { path: '/admin/login/', category: 'cms' },
        { path: '/api/', category: 'cms' },
        { path: '/static/', category: 'cms' },
      ];
    } finally {
      djangoPathsLoaded = true;
      djangoLoadingPromise = null;
    }
  })();
  return djangoLoadingPromise;
}

loadWordlist();
loadWpWordlist();
loadPmaWordlist();
loadDjangoWordlist();

browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && (changes.customWordlist || changes.useCustomOnly)) {
    pathsLoaded = false;
    loadWordlist(true);
  }
});

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function getOptions() {
  const opts = await browser.storage.local.get('options');
  return opts.options || {
    timeout: 10, batchSize: 10, rateLimit: 0, useHead: true,
    categories: ['git', 'docker', 'cicd', 'cloud', 'cms', 'backup', 'logs', 'ide']
  };
}

function getFilteredPaths(options) {
  return filterByCategories(pathEntries, options.categories);
}

browser.contextMenus.create({
  id: 'scan-site',
  title: 'Просканировать Sensitive Scanner',
  contexts: ['page']
});

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  const baseUrl = new URL(tab.url).origin;
  try {
    const { results, analysis } = await performScan(baseUrl, 'site', {});
    await saveScanToStorage(baseUrl, 'site', results, analysis);
    const count = results.filter(r => r.interesting).length;
    try {
      await browser.action.setBadgeText({ text: count > 0 ? String(count) : '' });
      await browser.action.setBadgeBackgroundColor({ color: '#c0392b' });
    } catch (e) {
      try {
        await browser.browserAction.setBadgeText({ text: count > 0 ? String(count) : '' });
      } catch (_) {}
    }
  } catch (e) { console.error(e); }
});

function xhrRequest(method, url, timeoutSec) {
  return new Promise((resolve) => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open(method, url, true);
      xhr.responseType = 'text';
      xhr.timeout = timeoutSec * 1000;
      xhr.onload = () => {
        const text = xhr.responseType === 'text' ? (xhr.responseText || '') : '';
        resolve({
          status: xhr.status,
          text,
          responseUrl: xhr.responseURL || url,
          headers: {
            location: xhr.getResponseHeader('Location'),
            contentType: xhr.getResponseHeader('Content-Type')
          }
        });
      };
      xhr.onerror = () => resolve({ status: 'network_error', text: '', error: 'XHR error' });
      xhr.ontimeout = () => resolve({ status: 'network_error', text: '', error: 'timeout' });
      xhr.send();
    } catch (e) {
      resolve({ status: 'network_error', text: '', error: e.message });
    }
  });
}

async function fetch404Baseline(baseUrl, mode, timeout) {
  const nonce = `_sfs_baseline_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const probePath = `/${nonce}.html`;
  const url = buildUrl(probePath, baseUrl, mode);
  const res = await xhrRequest('GET', url, timeout);
  if (res.status === 'network_error') return { error: true, reason: res.error || 'network_error' };
  return {
    status: res.status,
    fingerprint: simpleFingerprint(res.text),
    size: (res.text || '').length
  };
}

async function checkPath(fullUrl, displayPath, timeout, options, baseline) {
  const needBody = requiresBodyVerification(displayPath);
  const useHead = options.useHead !== false && !needBody;

  let status, text, responseUrl, redirected;

  if (useHead) {
    const head = await xhrRequest('HEAD', fullUrl, timeout);
    if (head.status === 'network_error') {
      return { path: displayPath, status: 'network_error', size: 0, error: head.error };
    }
    if (head.status === 404 || head.status === 410) {
      return { path: displayPath, status: head.status, size: 0, interesting: false };
    }
    if (![200, 201, 204, 301, 302, 401, 403, 405].includes(head.status)) {
      return { path: displayPath, status: head.status, size: 0, interesting: head.status !== 404 };
    }
    if (head.status === 405 || head.status === 501) {
      // Server doesn't support HEAD — fall through to GET
    } else if (!needBody && head.status !== 200 && head.status !== 403) {
      return {
        path: displayPath,
        status: head.status,
        size: 0,
        interesting: head.status !== 404,
        severity: getPathSeverity(displayPath)
      };
    }
  }

  const get = await xhrRequest('GET', fullUrl, timeout);
  if (get.status === 'network_error') {
    return { path: displayPath, status: 'network_error', size: 0, error: get.error };
  }

  status = get.status;
  text = get.text || '';
  responseUrl = get.responseUrl;
  redirected = responseUrl !== fullUrl;

  if ((status === 301 || status === 302) && get.headers.location) {
    let redirectUrl = get.headers.location;
    try {
      redirectUrl = new URL(redirectUrl, fullUrl).href;
      const origProtocol = new URL(fullUrl).protocol;
      const newProtocol = new URL(redirectUrl).protocol;
      if (origProtocol !== newProtocol) {
        return checkPath(redirectUrl, displayPath, timeout, options, baseline);
      }
    } catch (e) {}
  }

  const fingerprint = simpleFingerprint(text);
  const debugMode = checkForDjangoDebug(text);
  let debugData = null;
  if (debugMode) {
    debugData = extractDjangoDebugData(text);
  }
  const signatureOk = matchesSignature(displayPath, text);
  const severity = getPathSeverity(displayPath);

  let result = {
    path: displayPath,
    status,
    size: text.length,
    redirected,
    debugMode,
    debugData: debugData && debugData.length > 0 ? debugData : null,
    fingerprint,
    signatureOk,
    severity
  };

  if (status === 200 && needsBodyCapture(displayPath)) {
    result.bodySnippet = text.substring(0, 1000);
  }

  if (isSoft404(result, baseline)) {
    result.interesting = false;
    result.soft404 = true;
    return result;
  }

  if (status === 404) {
    result.interesting = false;
    return result;
  }

  if (status === 200 && needBody && !signatureOk) {
    result.interesting = false;
    result.likelyFalsePositive = true;
    return result;
  }

  result.interesting = status !== 404 && status !== 'network_error';
  return result;
}

async function runScanLoop(baseUrl, mode, options, state, customPaths) {
  let paths;
  if (customPaths) {
    paths = customPaths;
  } else {
    paths = getFilteredPaths(options);
  }
  const total = paths.length;
  const results = [];
  if (total === 0) return { results, analysis: analyzeAll([]), total: 0 };

  let baseline = await fetch404Baseline(baseUrl, mode, options.timeout);
  let resolvedUrl = baseUrl;
  let protocolNote = null;

  if (baseline && baseline.error) {
    const reason = baseline.reason;
    const parsed = new URL(baseUrl);
    if (parsed.protocol === 'http:') {
      protocolNote = '❌ Сайт не отвечает по HTTP. Firefox может блокировать запросы:\n'
        + `• Причина: ${reason === 'timeout' ? 'таймаут' : 'ошибка сети'}\n`
        + '• Откройте about:preferences#privacy → HTTPS-Only Mode\n'
        + '• Добавьте сайт в исключения или отключите режим';
    } else {
      const httpUrl = `http://${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
      const httpBaseline = await fetch404Baseline(httpUrl, mode, options.timeout);
      if (httpBaseline && !httpBaseline.error) {
        baseline = httpBaseline;
        resolvedUrl = httpUrl;
        protocolNote = '⚠️ HTTPS не отвечает — переключено на HTTP';
      } else {
        protocolNote = '❌ Сайт не отвечает ни по HTTP, ни по HTTPS.\n'
          + 'Проверьте доступность сайта в браузере.';
      }
    }
  }

  let completed = 0;
  const startTime = Date.now();
  const { batchSize, rateLimit, timeout } = options;

  for (let i = 0; i < total; i += batchSize) {
    if (state.stopped) break;
    while (state.paused && !state.stopped) await sleep(200);
    if (state.stopped) break;

    const batch = paths.slice(i, i + batchSize);
    const batchResults = await Promise.allSettled(
      batch.map(({ path }) => {
        const url = buildUrl(path, resolvedUrl, mode);
        return checkPath(url, path, timeout, options, baseline);
      })
    );

    for (let j = 0; j < batch.length; j++) {
      const res = batchResults[j];
      const entry = batch[j];
      const item = res.status === 'fulfilled'
        ? { ...res.value, category: entry.category }
        : { path: entry.path, status: 'error', size: 0, category: entry.category, interesting: false };
      results.push(item);
      completed++;
    }

    if (state.onProgress) {
      const elapsed = Math.max((Date.now() - startTime) / 1000, 0.1);
      const rate = completed / elapsed;
      state.onProgress({
        current: completed,
        total,
        rate: Math.round(rate),
        eta: rate > 0 ? Math.round((total - completed) / rate) : 0
      });
    }

    if (i + batchSize < total && !state.stopped) {
      await sleep(rateLimit || 0);
    }
  }

  const analysis = analyzeAll(results);
  return { results, analysis, total, stopped: state.stopped, protocolNote };
}

async function performScan(baseUrl, mode, state = {}) {
  const options = await getOptions();
  if (mode === 'wp') {
    await loadWpWordlist();
    return runScanLoop(baseUrl, mode, options, state, wpPathEntries);
  }
  if (mode === 'pma') {
    await loadPmaWordlist();
    return runScanLoop(baseUrl, mode, options, state, pmaPathEntries);
  }
  if (mode === 'django') {
    await loadDjangoWordlist();
    return runScanLoop(baseUrl, mode, options, state, djangoPathEntries);
  }
  await loadWordlist();
  return runScanLoop(baseUrl, mode, options, state, pathEntries);
}

async function checkOpenProxy(baseUrl, timeout) {
  try {
    const proxyUrl = baseUrl.replace(/\/+$/, '') + '/http://httpbin.org/get';
    const res = await xhrRequest('GET', proxyUrl, timeout);
    if (res.status === 'network_error') return null;
    const text = (res.text || '').toLowerCase();
    if (res.status === 200 && (text.includes('"url"') || text.includes('httpbin') || text.includes('"origin"'))) {
      return { isOpenProxy: true };
    }
    return null;
  } catch (e) {
    return null;
  }
}

async function fetchSecurityHeadersReal(baseUrl) {
  return new Promise((resolve) => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('GET', baseUrl, true);
      xhr.timeout = 4000;
      xhr.onload = () => {
        resolve({
          'Content-Security-Policy': xhr.getResponseHeader('Content-Security-Policy'),
          'X-Frame-Options': xhr.getResponseHeader('X-Frame-Options'),
          'Strict-Transport-Security': xhr.getResponseHeader('Strict-Transport-Security'),
          'X-Content-Type-Options': xhr.getResponseHeader('X-Content-Type-Options'),
          'Referrer-Policy': xhr.getResponseHeader('Referrer-Policy')
        });
      };
      xhr.onerror = () => resolve(null);
      xhr.ontimeout = () => resolve(null);
      xhr.send();
    } catch (e) {
      resolve(null);
    }
  });
}

const MAX_HISTORY = 20;

async function saveScanToStorage(baseUrl, mode, results, analysis) {
  const interesting = results.filter(r => r.interesting);
  const payload = {
    baseUrl,
    mode,
    results,
    analysis,
    timestamp: Date.now(),
    findingsCount: interesting.length
  };
  await browser.storage.local.set({ lastScanResults: payload });

  const { scanHistory = [] } = await browser.storage.local.get('scanHistory');
  const entry = {
    id: `${Date.now()}`,
    baseUrl,
    mode,
    timestamp: payload.timestamp,
    findingsCount: interesting.length,
    results,
    analysis
  };
  const updated = [entry, ...scanHistory.filter(h => h.baseUrl !== baseUrl || h.mode !== mode)].slice(0, MAX_HISTORY);
  await browser.storage.local.set({ scanHistory: updated });
}

browser.runtime.onConnect.addListener((port) => {
  if (port.name !== 'scanner') return;

  const state = { paused: false, stopped: false };

  port.onMessage.addListener(async (msg) => {
    if (msg.command === 'pause') {
      state.paused = msg.value;
    } else if (msg.command === 'stop') {
      state.stopped = true;
      state.paused = false;
    } else if (msg.command === 'start') {
      state.paused = false;
      state.stopped = false;
      const baseUrl = msg.url;
      const mode = msg.mode || 'site';

      const options = await getOptions();
      let scanPaths;

      if (mode === 'wp') {
        await loadWpWordlist();
        scanPaths = wpPathEntries;
      } else if (mode === 'pma') {
        await loadPmaWordlist();
        scanPaths = pmaPathEntries;
      } else if (mode === 'django') {
        await loadDjangoWordlist();
        scanPaths = djangoPathEntries;
      } else {
        await loadWordlist();
        scanPaths = getFilteredPaths(options);
      }

      if (scanPaths.length === 0) {
        port.postMessage({ type: 'result', results: [], analysis: analyzeAll([]), total: 0 });
        return;
      }

      state.onProgress = (progress) => port.postMessage({ type: 'progress', ...progress });

      const { results, analysis, total, stopped, protocolNote } = await runScanLoop(baseUrl, mode, options, state, scanPaths);

      if (!msg.skipSave) {
        await saveScanToStorage(baseUrl, mode, results, analysis);
        const count = results.filter(r => r.interesting).length;
        try {
          await browser.action.setBadgeText({ text: count > 0 ? String(count) : '' });
        } catch (e) {
          try { await browser.browserAction.setBadgeText({ text: count > 0 ? String(count) : '' }); } catch (_) {}
        }
      }

      const securityHeaders = await fetchSecurityHeadersReal(baseUrl);
      const proxyResult = await checkOpenProxy(baseUrl, options.timeout);
      if (proxyResult && proxyResult.isOpenProxy) {
        if (!analysis.vulnerabilities) analysis.vulnerabilities = [];
        if (!analysis.vulnerabilities.includes('open_proxy')) {
          analysis.vulnerabilities.push('open_proxy');
        }
        results.push({
          path: '/CONNECT (proxy tunnel)',
          status: 200,
          size: 0,
          interesting: true,
          severity: 'critical',
          category: 'cloud',
          proxyCheck: true
        });
      }
      port.postMessage({
        type: 'result',
        results,
        analysis,
        total,
        stopped,
        securityHeaders,
        proxyResult,
        protocolNote
      });
    }
  });
});
