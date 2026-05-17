let port = null;
let currentScanData = null;
let additionalPort = null;
let additionalButton = null;
let paused = false;
let currentFilter = 'all';

const SEV_LABELS = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };

function getFullUrl(path, baseUrl, mode) {
  return buildUrl(path, baseUrl, mode);
}

function enrichResult(item, baseUrl, mode) {
  const severity = item.severity || getPathSeverity(item.path);
  return {
    ...item,
    severity,
    fullUrl: getFullUrl(item.path, baseUrl, mode),
    baseUrl,
    mode
  };
}

function isInteresting(r) {
  if (r.interesting === false || r.soft404 || r.likelyFalsePositive) return false;
  if (r.status === 404 || r.status === 'network_error' || r.status === 'error') return false;
  return true;
}

function getInterestingResults(results) {
  return results.filter(isInteresting);
}

function checkDebugBanner(results) {
  const debugBanner = document.getElementById('debugBanner');
  if (!debugBanner) return;
  if (results.some(r => r.debugMode === true)) {
    debugBanner.classList.remove('hidden');
  } else {
    debugBanner.classList.add('hidden');
  }
}

function renderDetectionPanel(analysis) {
  const panel = document.getElementById('detectionPanel');
  if (!panel) return;
  if (!analysis || ((!analysis.detectedTech || analysis.detectedTech.length === 0) &&
      (!analysis.vulnerabilities || analysis.vulnerabilities.length === 0))) {
    panel.classList.add('hidden');
    panel.innerHTML = '';
    return;
  }
  let html = '';
  if (analysis.detectedTech && analysis.detectedTech.length > 0) {
    html += '<strong>Технологии:</strong><ul>';
    for (const t of analysis.detectedTech) {
      html += `<li>${t.name} <span class="meta-text">(${t.confidence})</span></li>`;
    }
    html += '</ul>';
  }
  if (analysis.vulnerabilities && analysis.vulnerabilities.length > 0) {
    html += '<strong>Уязвимости:</strong><ul>';
    for (const v of analysis.vulnerabilities) {
      const meta = VULN_LABELS[v] || { label: v, severity: 'medium' };
      html += `<li class="vuln-item sev-${meta.severity}">${meta.label}</li>`;
    }
    html += '</ul>';
  }
  panel.innerHTML = html;
  panel.classList.remove('hidden');
}

function initFilters() {
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      applyFilter();
    });
  });
  const allBtn = document.querySelector('.filter-btn[data-filter="all"]');
  if (allBtn) allBtn.classList.add('active');
}

function applyFilter() {
  if (!currentScanData) return;
  let filtered;
  const results = currentScanData.results;
  if (currentFilter === 'all') {
    filtered = getInterestingResults(results);
  } else if (currentFilter === 'network_error') {
    filtered = results.filter(r => r.status === 'network_error' || r.status === 'error');
  } else {
    const statuses = currentFilter.split(',').flatMap(s => {
      if (s === '3xx') return [301, 302, 304];
      if (s === '500') return [500, 501, 502, 503];
      return [parseInt(s, 10)];
    }).filter(s => !isNaN(s));
    filtered = results.filter(r => statuses.includes(r.status));
  }
  displayResults(filtered);
}

function sortBySeverity(items) {
  return items.slice().sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 5;
    const sb = SEVERITY_ORDER[b.severity] ?? 5;
    if (sa !== sb) return sa - sb;
    const priority = { 200: 1, 301: 2, 302: 2, 401: 3, 403: 3, 500: 4 };
    return (priority[a.status] || 5) - (priority[b.status] || 5);
  });
}

function displayResults(interesting) {
  const resultsTable = document.getElementById('resultsTable');
  const tbody = resultsTable.querySelector('tbody');
  tbody.innerHTML = '';
  if (interesting.length === 0) {
    resultsTable.classList.add('hidden');
    return;
  }
  resultsTable.classList.remove('hidden');
  for (const item of sortBySeverity(interesting)) {
    const row = tbody.insertRow();
    const sevCell = row.insertCell();
    const sev = item.severity || 'medium';
    sevCell.textContent = SEV_LABELS[sev] || sev.toUpperCase();
    sevCell.className = `sev-${sev}`;
    sevCell.title = sev;
    const pathCell = row.insertCell();
    const link = document.createElement('a');
    link.href = item.fullUrl;
    link.target = '_blank';
    link.textContent = item.path;
    link.style.color = 'inherit';
    pathCell.appendChild(link);
    const statusCell = row.insertCell();
    statusCell.textContent = item.status;
    statusCell.className = `status-${item.status}`;
    row.insertCell().textContent = item.size + ' B';
    const actionCell = row.insertCell();
    const scanBtn = document.createElement('button');
    scanBtn.className = 'scan-btn';
    scanBtn.innerHTML = '🔍';
    scanBtn.title = 'Сканировать эту директорию';
    scanBtn.addEventListener('click', () => startAdditionalScan(item, scanBtn));
    actionCell.appendChild(scanBtn);
  }
}

function showScanResults(data, statusMessage) {
  const statusDiv = document.getElementById('status');
  const exportContainer = document.getElementById('exportContainer');
  const filtersContainer = document.getElementById('filtersContainer');
  const lastScanInfo = document.getElementById('lastScanInfo');

  currentScanData = data;
  checkDebugBanner(data.results);
  renderDetectionPanel(data.analysis);

  if (data.timestamp) {
    lastScanInfo.textContent = `Скан: ${new Date(data.timestamp).toLocaleString()} (${data.mode}) — ${data.findingsCount ?? getInterestingResults(data.results).length} находок`;
    lastScanInfo.classList.remove('hidden');
  }

  const networkErrors = data.results.filter(r => r.status === 'network_error' || r.status === 'error');
  const interesting = getInterestingResults(data.results);

  if (statusMessage) {
    statusDiv.innerHTML = statusMessage;
  } else if (networkErrors.length > 0) {
    statusDiv.innerHTML = `❌ Ошибки сети: ${networkErrors.length}`;
  } else {
    statusDiv.innerHTML = '';
  }

  if (interesting.length > 0) {
    statusDiv.innerHTML += `${statusDiv.innerHTML ? '<br>' : ''}⚠️ Найдено ${interesting.length} потенциально опасных путей:`;
    displayResults(interesting);
    exportContainer.classList.remove('hidden');
    filtersContainer.classList.remove('hidden');
    applyFilter();
  } else if (networkErrors.length === 0) {
    statusDiv.textContent = '✅ Ничего критичного не найдено.';
    document.getElementById('resultsTable').classList.add('hidden');
    exportContainer.classList.add('hidden');
    filtersContainer.classList.add('hidden');
  }
}

async function loadHistorySelect() {
  const { scanHistory = [] } = await browser.storage.local.get('scanHistory');
  const select = document.getElementById('historySelect');
  const current = select.value;
  select.innerHTML = '<option value="">— выберите скан —</option>';
  for (const h of scanHistory) {
    const host = (() => { try { return new URL(h.baseUrl).hostname; } catch (e) { return h.baseUrl; } })();
    const opt = document.createElement('option');
    opt.value = h.id;
    opt.textContent = `${new Date(h.timestamp).toLocaleString()} — ${host} (${h.mode}, ${h.findingsCount} находок)`;
    select.appendChild(opt);
  }
  if (current) select.value = current;
}

async function restoreLastResults() {
  await loadHistorySelect();
  const data = await browser.storage.local.get('lastScanResults');
  if (!data.lastScanResults) return;
  const { baseUrl, mode, results, timestamp, analysis } = data.lastScanResults;
  const enriched = results.map(r => r.fullUrl ? r : enrichResult(r, baseUrl, mode));
  showScanResults({
    baseUrl, mode, results: enriched, timestamp,
    analysis: analysis || analyzeAll(enriched),
    findingsCount: getInterestingResults(enriched).length
  });
}

function handleScanComplete(msg, baseUrl, mode) {
  const progressContainer = document.getElementById('progressContainer');
  const pauseBtn = document.getElementById('pauseBtn');
  const stopBtn = document.getElementById('stopBtn');
  progressContainer.classList.add('hidden');
  pauseBtn.classList.add('hidden');
  stopBtn.classList.add('hidden');

  const enriched = msg.results.map(r => enrichResult(r, baseUrl, mode));
  const analysis = msg.analysis || analyzeAll(enriched);
  const findingsCount = getInterestingResults(enriched).length;

  let statusMsg = '';
  if (msg.stopped) statusMsg = '⏹ Сканирование остановлено. ';
  if (msg.securityHeaders) renderSecurityHeaders(msg.securityHeaders);

  showScanResults({ baseUrl, mode, results: enriched, analysis, timestamp: Date.now(), findingsCount }, statusMsg);
  loadHistorySelect();
}

function renderSecurityHeaders(h) {
  const secDiv = document.getElementById('securityHeaders');
  if (!secDiv) return;
  const items = [
    { name: 'Content-Security-Policy', value: h['Content-Security-Policy'] },
    { name: 'X-Frame-Options', value: h['X-Frame-Options'] },
    { name: 'Strict-Transport-Security', value: h['Strict-Transport-Security'] },
    { name: 'X-Content-Type-Options', value: h['X-Content-Type-Options'] },
    { name: 'Referrer-Policy', value: h['Referrer-Policy'] }
  ];
  let html = '<strong>Security Headers:</strong><ul>';
  items.forEach(i => {
    html += `<li>${i.value ? '✅' : '❌'} ${i.name}: ${i.value || 'отсутствует'}</li>`;
  });
  html += '</ul>';
  secDiv.innerHTML = html;
  secDiv.classList.remove('hidden');
}

function startAdditionalScan(item, button) {
  const fullUrl = item.fullUrl;
  const parentUrl = fullUrl.substring(0, fullUrl.lastIndexOf('/') + 1);
  button.innerHTML = '⏳';
  button.disabled = true;
  additionalButton = button;
  if (additionalPort) additionalPort.disconnect();
  additionalPort = browser.runtime.connect({ name: 'scanner' });
  additionalPort.onMessage.addListener((msg) => {
    if (msg.type === 'result') {
      button.innerHTML = '🔍';
      button.disabled = false;
      additionalButton = null;
      const enrichedNew = msg.results.map(r => enrichResult(r, parentUrl, 'path'));
      const existingUrls = new Set(currentScanData.results.map(r => r.fullUrl));
      for (const enriched of enrichedNew) {
        if (!existingUrls.has(enriched.fullUrl)) {
          currentScanData.results.push(enriched);
          existingUrls.add(enriched.fullUrl);
        }
      }
      currentScanData.analysis = analyzeAll(currentScanData.results);
      showScanResults(currentScanData);
      additionalPort.disconnect();
      additionalPort = null;
    }
  });
  additionalPort.postMessage({ command: 'start', url: parentUrl, mode: 'path', skipSave: false });
}

function resetScanUI() {
  document.getElementById('resultsTable').classList.add('hidden');
  document.getElementById('lastScanInfo').classList.add('hidden');
  document.getElementById('exportContainer').classList.add('hidden');
  document.getElementById('filtersContainer').classList.add('hidden');
  document.getElementById('detectionPanel').classList.add('hidden');
  document.getElementById('securityHeaders').classList.add('hidden');
  document.getElementById('progressContainer').classList.remove('hidden');
  document.getElementById('progressBar').value = 0;
  document.getElementById('progressText').textContent = '0 / 0';
  document.getElementById('status').textContent = 'Сканирование...';
  document.getElementById('debugBanner').classList.add('hidden');
  document.getElementById('pauseBtn').textContent = '⏸ Пауза';
  document.getElementById('pauseBtn').classList.remove('hidden');
  document.getElementById('stopBtn').classList.remove('hidden');
  document.getElementById('stopBtn').disabled = false;
}

function startScan(mode) {
  currentScanData = null;
  paused = false;
  if (additionalPort) { additionalPort.disconnect(); additionalPort = null; }
  if (additionalButton) { additionalButton.innerHTML = '🔍'; additionalButton.disabled = false; additionalButton = null; }
  if (port) { port.disconnect(); port = null; }
  resetScanUI();

  browser.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
    const baseUrl = mode === 'path' ? tab.url : new URL(tab.url).origin;
    port = browser.runtime.connect({ name: 'scanner' });
    port.onMessage.addListener((msg) => {
      if (msg.type === 'progress') {
        const percent = Math.round((msg.current / msg.total) * 100);
        document.getElementById('progressBar').value = percent;
        let text = `${msg.current} / ${msg.total}`;
        if (msg.rate !== undefined) text += ` (${msg.rate} req/s, ост. ~${msg.eta}с)`;
        document.getElementById('progressText').textContent = text;
      } else if (msg.type === 'result') {
        handleScanComplete(msg, baseUrl, mode);
        port.disconnect();
        port = null;
      }
    });
    port.postMessage({ command: 'start', url: baseUrl, mode });
  }).catch(err => {
    console.error('[popup]', err);
    document.getElementById('status').textContent = 'Ошибка получения адреса страницы';
  });
}

document.getElementById('exportBtn').addEventListener('click', () => {
  if (!currentScanData) return;
  const rows = [['URL', 'Статус', 'Severity', 'Размер']];
  for (const item of getInterestingResults(currentScanData.results)) {
    rows.push([item.fullUrl, item.status, item.severity, item.size]);
  }
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadBlob(csv, 'text/csv', 'csv');
});

document.getElementById('exportJsonBtn').addEventListener('click', () => {
  if (!currentScanData) return;
  const exportData = {
    scanTime: new Date().toISOString(),
    baseUrl: currentScanData.baseUrl,
    mode: currentScanData.mode,
    analysis: currentScanData.analysis,
    results: getInterestingResults(currentScanData.results)
  };
  downloadBlob(JSON.stringify(exportData, null, 2), 'application/json', 'json');
});

document.getElementById('exportHtmlBtn').addEventListener('click', () => {
  if (!currentScanData) return;
  const { results, baseUrl, mode, analysis } = currentScanData;
  const interesting = getInterestingResults(results);
  const vulnHtml = (analysis?.vulnerabilities || []).map(v => {
    const m = VULN_LABELS[v] || { label: v };
    return `<li>${m.label}</li>`;
  }).join('');
  const techHtml = (analysis?.detectedTech || []).map(t => `<li>${t.name} (${t.confidence})</li>`).join('');
  const html = `<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>Scan Report</title>
<style>body{font-family:sans-serif;margin:20px}table{width:100%;border-collapse:collapse}
th,td{padding:8px;border-bottom:1px solid #ddd}th{background:#f2f2f2}
.sev-critical{color:#c0392b;font-weight:bold}.sev-high{color:#e67e22}</style></head><body>
<h1>Отчёт Sensitive File Scanner</h1>
<p><strong>URL:</strong> ${baseUrl}<br><strong>Режим:</strong> ${mode}<br><strong>Дата:</strong> ${new Date().toLocaleString()}</p>
${techHtml ? `<h3>Технологии</h3><ul>${techHtml}</ul>` : ''}
${vulnHtml ? `<h3>Уязвимости</h3><ul>${vulnHtml}</ul>` : ''}
<table><thead><tr><th>Severity</th><th>Путь</th><th>URL</th><th>Статус</th><th>Размер</th></tr></thead><tbody>
${interesting.map(i => `<tr><td class="sev-${i.severity}">${i.severity}</td><td>${i.path}</td><td><a href="${i.fullUrl}">${i.fullUrl}</a></td><td>${i.status}</td><td>${i.size}</td></tr>`).join('')}
</tbody></table></body></html>`;
  downloadBlob(html, 'text/html', 'html');
});

function downloadBlob(content, mime, ext) {
  const host = currentScanData?.baseUrl ? new URL(currentScanData.baseUrl).hostname : 'scan';
  const blob = new Blob([content], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan_${host}_${new Date().toISOString().slice(0, 10)}.${ext}`;
  a.click();
  URL.revokeObjectURL(a.href);
}

document.getElementById('pauseBtn').addEventListener('click', () => {
  if (!port) return;
  paused = !paused;
  document.getElementById('pauseBtn').textContent = paused ? '▶ Продолжить' : '⏸ Пауза';
  port.postMessage({ command: 'pause', value: paused });
});

document.getElementById('stopBtn').addEventListener('click', () => {
  if (!port) return;
  port.postMessage({ command: 'stop' });
  document.getElementById('stopBtn').disabled = true;
});

document.getElementById('optionsLink').addEventListener('click', (e) => {
  e.preventDefault();
  browser.runtime.openOptionsPage();
});

document.getElementById('historySelect').addEventListener('change', async (e) => {
  const id = e.target.value;
  if (!id) return;
  const { scanHistory = [] } = await browser.storage.local.get('scanHistory');
  const entry = scanHistory.find(h => h.id === id);
  if (!entry) return;
  const enriched = entry.results.map(r => r.fullUrl ? r : enrichResult(r, entry.baseUrl, entry.mode));
  showScanResults({
    baseUrl: entry.baseUrl,
    mode: entry.mode,
    results: enriched,
    analysis: entry.analysis || analyzeAll(enriched),
    timestamp: entry.timestamp,
    findingsCount: entry.findingsCount
  });
});

document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
  if (!confirm('Очистить всю историю сканов?')) return;
  await browser.storage.local.remove('scanHistory');
  await loadHistorySelect();
});

const themeToggle = document.getElementById('themeToggle');
if (themeToggle) {
  if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark');
    themeToggle.textContent = '☀️';
  }
  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark');
    const theme = document.body.classList.contains('dark') ? 'dark' : 'light';
    localStorage.setItem('theme', theme);
    themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙';
  });
}

document.getElementById('scanSiteBtn').addEventListener('click', () => startScan('site'));
document.getElementById('scanPathBtn').addEventListener('click', () => startScan('path'));

initFilters();
restoreLastResults();
