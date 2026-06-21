if (typeof importScripts !== 'undefined') {
  importScripts('scanner-utils.js', 'detection.js');
}

let pathEntries = [];
let wpPathEntries = [];
let pmaPathEntries = [];
let djangoPathEntries = [];
let iisPathEntries = [];
let pathsLoaded = false;
let wpPathsLoaded = false;
let pmaPathsLoaded = false;
let djangoPathsLoaded = false;
let iisPathsLoaded = false;
let loadingPromise = null;
let wpLoadingPromise = null;
let pmaLoadingPromise = null;
let djangoLoadingPromise = null;
let iisLoadingPromise = null;

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

async function loadIisWordlist(force = false) {
  if (iisPathsLoaded && !force) return;
  if (iisLoadingPromise && !force) return iisLoadingPromise;
  iisLoadingPromise = (async () => {
    try {
      const url = browser.runtime.getURL('wordlist-iis.txt');
      const response = await fetch(url);
      if (response.ok) {
        iisPathEntries = parseWordlistText(await response.text());
      }
    } catch (e) {
      console.error('iis wordlist fetch error', e);
    }
    if (iisPathEntries.length === 0) {
      iisPathEntries = [
        { path: '/web.config', category: 'cms' },
        { path: '/global.asax', category: 'cms' },
        { path: '/bin/', category: 'cms' },
        { path: '/App_Code/', category: 'cms' },
        { path: '/App_Data/', category: 'cms' },
        { path: '/iisstart.htm', category: 'cms' },
        { path: '/Trace.axd', category: 'cms' },
        { path: '/elmah.axd', category: 'cms' },
        { path: '/appsettings.json', category: 'cms' }
      ];
    }
  })();
  return iisLoadingPromise;
}

loadWordlist();
loadWpWordlist();
loadPmaWordlist();
loadDjangoWordlist();
loadIisWordlist();

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
    scanProtocol: 'https',
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
  const baseOrigin = new URL(tab.url).origin;
  try {
    const options = await getOptions();
    const state = {};
    const scanPaths = getFilteredPaths(options);
    const { results, analysis } = await performMultiProtocolScan(baseOrigin, 'site', options, state, scanPaths);
    await saveScanToStorage(baseOrigin, 'site', results, analysis);
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
  console.log('[Scanner] XHR ' + method + ' ' + url + ' timeout=' + timeoutSec);
  return new Promise((resolve) => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open(method, url, true);
      xhr.responseType = 'text';
      xhr.timeout = timeoutSec * 1000;
      xhr.withCredentials = false;
      xhr.onload = () => {
        const text = xhr.responseType === 'text' ? (xhr.responseText || '') : '';
        console.log('[Scanner] XHR done ' + method + ' ' + url + ' status=' + xhr.status + ' size=' + text.length);
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
      xhr.onerror = (e) => {
        console.error('[Scanner] XHR error', url, e, xhr.status, xhr.readyState);
        resolve({ status: 'network_error', text: '', error: 'xhr_error' });
      };
      xhr.ontimeout = () => {
        console.warn('[Scanner] XHR timeout ' + url);
        resolve({ status: 'network_error', text: '', error: 'timeout' });
      };
      xhr.onabort = () => {
        console.warn('[Scanner] XHR abort ' + url);
        resolve({ status: 'network_error', text: '', error: 'aborted' });
      };
      xhr.send();
    } catch (e) {
      console.error('[Scanner] XHR exception', url, e);
      resolve({ status: 'network_error', text: '', error: e.message });
    }
  });
}

async function fetch404Baseline(baseUrl, mode, timeout) {
  const probe1 = `_sfs_baseline_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const probe2 = `_sfs_baseline_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const url1 = buildUrl(`/${probe1}.html`, baseUrl, mode);
  const url2 = buildUrl(`/${probe2}.html`, baseUrl, mode);
  console.log('[Scanner] baseline probes ' + url1 + ' | ' + url2);

  const [res1, res2] = await Promise.all([
    xhrRequest('GET', url1, timeout),
    xhrRequest('GET', url2, timeout)
  ]);

  if (res1.status === 'network_error' && res2.status === 'network_error') {
    console.warn('[Scanner] both baseline probes failed');
    return { error: true, reason: res1.error || res2.error || 'network_error' };
  }

  const valid = res1.status !== 'network_error' ? res1 : res2;
  const fp1 = simpleFingerprint(res1.text || '');
  const fp2 = simpleFingerprint(res2.text || '');
  const catchAll = res1.status !== 'network_error' && res2.status !== 'network_error' && fp1 === fp2;

  const baseline = {
    status: valid.status,
    fingerprint: fp1,
    size: (valid.text || '').length,
    text: valid.text || '',
    headers: valid.headers || {},
    catchAll,
    fingerprints: [fp1, fp2]
  };

  if (catchAll) {
    console.log('[Scanner] catch-all detected (two probes have identical content)');
  }
  console.log('[Scanner] baseline status=' + baseline.status + ' size=' + baseline.size + ' catchAll=' + baseline.catchAll);
  return baseline;
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

  if (status === 200) {
    const catchAllContent = is_catch_all_page(text);
    if (catchAllContent) {
      result.interesting = false;
      result.catchAllContent = true;
    }
    const secrets = scanBodyForSecrets(text);
    if (secrets.length > 0) {
      result.secrets = secrets;
      result.interesting = true;
    }
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

  if (status === 200 && needBody && !signatureOk && !result.interesting) {
    result.interesting = false;
    result.likelyFalsePositive = true;
    return result;
  }

  if (result.interesting === undefined) {
    result.interesting = status !== 404 && status !== 'network_error';
  }
  return result;
}

function getScanUrls(baseUrl, scanProtocol) {
  const parsed = new URL(baseUrl);
  const host = parsed.host;
  if (scanProtocol === 'both') return [`https://${host}`, `http://${host}`];
  if (scanProtocol === 'http') return [`http://${host}`];
  return [`https://${host}`];
}

async function performMultiProtocolScan(baseUrl, mode, options, state, scanPaths) {
  const urls = getScanUrls(baseUrl, options.scanProtocol);
  console.log('[Scanner] performMultiProtocolScan baseUrl=' + baseUrl + ' protocol=' + options.scanProtocol + ' urls=' + JSON.stringify(urls));
  let allResults = [];
  let allProtocolNotes = [];
  let overallStopped = false;
  let overallTotal = 0;

  for (const scanUrl of urls) {
    if (state.stopped) { console.log('[Scanner] multi-protocol scan stopped before ' + scanUrl); overallStopped = true; break; }
    while (state.paused && !state.stopped) await sleep(200);
    if (state.stopped) { console.log('[Scanner] multi-protocol scan stopped during pause before ' + scanUrl); overallStopped = true; break; }

    console.log('[Scanner] scanning protocol ' + scanUrl);
    const { results, total, stopped, protocolNote } = await runScanLoop(scanUrl, mode, options, state, scanPaths);
    allResults.push(...results);
    if (protocolNote) allProtocolNotes.push(protocolNote);
    overallTotal += total;
    if (stopped) { overallStopped = true; break; }
  }

  const analysis = analyzeAll(allResults);
  console.log('[Scanner] multi-protocol done totalResults=' + allResults.length + ' interesting=' + allResults.filter(r => r.interesting).length);
  return { results: allResults, analysis, total: overallTotal, stopped: overallStopped, protocolNote: allProtocolNotes.join(' ') };
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
  if (total === 0) {
    console.log('[Scanner] no paths to scan for ' + baseUrl);
    return { results, analysis: analyzeAll([]), total: 0 };
  }
  console.log('[Scanner] runScanLoop start baseUrl=' + baseUrl + ' mode=' + mode + ' total=' + total);

  let baseline = await fetch404Baseline(baseUrl, mode, options.timeout);
  let serverInfo = null;
  if (baseline && !baseline.error) {
    serverInfo = detectServerBy404(baseline.text, baseline.headers, baseline.status);
  }
  let resolvedUrl = baseUrl;
  let protocolNote = null;

  if (baseline && baseline.error) {
    const reason = baseline.reason;
    const parsed = new URL(baseUrl);
    if (parsed.protocol === 'http:') {
      console.warn('[Scanner] HTTP baseline failed for ' + baseUrl + ' reason=' + reason);
      protocolNote = '❌ Сайт не отвечает по HTTP. Firefox может блокировать запросы:\n'
        + `• Причина: ${reason === 'timeout' ? 'таймаут' : 'ошибка сети'}\n`
        + '• Откройте about:preferences#privacy → HTTPS-Only Mode\n'
        + '• Добавьте сайт в исключения или отключите режим';
    } else {
      const httpUrl = `http://${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
      console.log('[Scanner] HTTPS baseline failed, trying HTTP ' + httpUrl);
      const httpBaseline = await fetch404Baseline(httpUrl, mode, options.timeout);
      if (httpBaseline && !httpBaseline.error) {
        baseline = httpBaseline;
        resolvedUrl = httpUrl;
        protocolNote = '⚠️ HTTPS не отвечает — переключено на HTTP';
        console.log('[Scanner] HTTP baseline OK, switched to ' + httpUrl);
      } else {
        console.error('[Scanner] both HTTP and HTTPS failed for ' + baseUrl);
        protocolNote = '❌ Сайт не отвечает ни по HTTP, ни по HTTPS.\n'
          + 'Проверьте доступность сайта в браузере.';
      }
    }
  } else {
    console.log('[Scanner] baseline OK status=' + baseline.status + ' resolvedUrl=' + resolvedUrl);
  }

  let completed = 0;
  const startTime = Date.now();
  const { batchSize, rateLimit, timeout } = options;

  for (let i = 0; i < total; i += batchSize) {
    if (state.stopped) { console.log('[Scanner] scan stopped at batch ' + i); break; }
    while (state.paused && !state.stopped) await sleep(200);
    if (state.stopped) { console.log('[Scanner] scan stopped after pause at batch ' + i); break; }

    const batch = paths.slice(i, i + batchSize);
    console.log('[Scanner] batch ' + (i / batchSize + 1) + '/' + Math.ceil(total / batchSize) + ' paths=' + batch.length);
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
      if (item.interesting) console.log('[Scanner] found interesting', item.path, item.status, item.severity);
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

  console.log('[Scanner] scan done baseUrl=' + baseUrl + ' completed=' + completed + ' interesting=' + results.filter(r => r.interesting).length);

  const deduped = deduplicate_by_fingerprint(results);
  if (deduped > 0) {
    console.log('[Scanner] deduplicated ' + deduped + ' catch-all results by fingerprint');
  }

  const analysis = analyzeAll(results, serverInfo);
  return { results, analysis, total, stopped: state.stopped, protocolNote, serverInfo };
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
  if (mode === 'iis') {
    await loadIisWordlist();
    return runScanLoop(baseUrl, mode, options, state, iisPathEntries);
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
    } else if (msg.command === 'detectServer') {
      const baseUrl = msg.url;
      console.log('[Scanner] detectServer for ' + baseUrl);
      const options = await getOptions();
      const baseline = await fetch404Baseline(baseUrl, 'site', options.timeout);
      if (baseline && !baseline.error) {
        const serverInfo = detectServerBy404(baseline.text, baseline.headers, baseline.status);
        port.postMessage({ type: 'serverDetected', serverInfo });
      } else {
        port.postMessage({ type: 'serverDetected', serverInfo: null });
      }
    } else if (msg.command === 'start') {
      state.paused = false;
      state.stopped = false;
      const baseUrl = msg.url;
      const mode = msg.mode || 'site';
      console.log('[Scanner] port start command url=' + baseUrl + ' mode=' + mode);

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
      } else if (mode === 'iis') {
        await loadIisWordlist();
        scanPaths = iisPathEntries;
      } else {
        await loadWordlist();
        scanPaths = getFilteredPaths(options);
      }

      if (scanPaths.length === 0) {
        port.postMessage({ type: 'result', results: [], analysis: analyzeAll([]), total: 0 });
        return;
      }

      state.onProgress = (progress) => port.postMessage({ type: 'progress', ...progress });

      const { results, analysis, total, stopped, protocolNote } = await performMultiProtocolScan(baseUrl, mode, options, state, scanPaths);

      port.postMessage({ type: 'statusUpdate', text: 'Сканирование завершено. Проверка заголовков безопасности...' });
      const securityHeaders = await Promise.race([
        fetchSecurityHeadersReal(baseUrl),
        new Promise(resolve => setTimeout(() => resolve(null), 6000))
      ]);

      port.postMessage({ type: 'statusUpdate', text: 'Проверка open proxy...' });
      const proxyResult = await Promise.race([
        checkOpenProxy(baseUrl, options.timeout),
        new Promise(resolve => setTimeout(() => resolve(null), 8000))
      ]);

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

      saveScanToStorage(baseUrl, mode, results, analysis).then(() => {
        const count = results.filter(r => r.interesting).length;
        try { browser.action.setBadgeText({ text: count > 0 ? String(count) : '' }); }
        catch (e) { try { browser.browserAction.setBadgeText({ text: count > 0 ? String(count) : '' }); } catch (_) {} }
      }).catch(() => {});

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
