let port = null;
let currentScanData = null; // { baseUrl, mode, results: [...] }
let additionalPort = null;
let additionalButton = null;
let paused = false;
let currentFilter = 'all';

function getFullUrl(path, baseUrl, mode) {
  if (mode === 'path') {
    const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
    return new URL(path.startsWith('/') ? path.slice(1) : path, base).href;
  } else {
    return new URL(path, baseUrl).href;
  }
}

function enrichResult(item, baseUrl, mode) {
  return {
    ...item,
    fullUrl: getFullUrl(item.path, baseUrl, mode),
    baseUrl: baseUrl,
    mode: mode
  };
}

function checkDebugBanner(results) {
  const debugBanner = document.getElementById('debugBanner');
  if (debugBanner) {
    if (results.some(r => r.debugMode === true)) {
      debugBanner.classList.remove('hidden');
    } else {
      debugBanner.classList.add('hidden');
    }
  }
}

function initFilters() {
  const btns = document.querySelectorAll('.filter-btn');
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
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
  const results = currentScanData.results;
  let filtered;
  if (currentFilter === 'all') {
    filtered = results.filter(r => r.status !== 404);
  } else if (currentFilter === 'network_error') {
    filtered = results.filter(r => r.status === 'network_error' || r.status === 'error');
  } else {
    const statuses = currentFilter.split(',').flatMap(s => {
      if (s === '3xx') return [301, 302, 304];
      if (s === '500') return [500, 501, 502, 503];
      return [parseInt(s)];
    }).filter(s => !isNaN(s));
    filtered = results.filter(r => statuses.includes(r.status));
  }
  displayResults(filtered);
}

async function restoreLastResults() {
  const data = await browser.storage.local.get('lastScanResults');
  if (data.lastScanResults) {
    const { baseUrl, mode, results, timestamp } = data.lastScanResults;
    const enrichedResults = results.map(r => {
      if (!r.fullUrl) return enrichResult(r, baseUrl, mode);
      return r;
    });
    currentScanData = { baseUrl, mode, results: enrichedResults };
    const statusDiv = document.getElementById('status');
    const lastScanInfo = document.getElementById('lastScanInfo');
    const exportContainer = document.getElementById('exportContainer');
    const filtersContainer = document.getElementById('filtersContainer');
    lastScanInfo.textContent = `Предыдущее сканирование: ${new Date(timestamp).toLocaleString()} (${mode})`;
    lastScanInfo.classList.remove('hidden');
    const networkErrors = enrichedResults.filter(r => r.status === 'network_error' || r.status === 'error');
    const httpResults = enrichedResults.filter(r => r.status !== 'network_error' && r.status !== 'error');
    if (networkErrors.length > 0) {
      statusDiv.innerHTML = `❌ Ошибки сети для ${networkErrors.length} путей (см. консоль)`;
    }
    const interesting = httpResults.filter(r => r.status !== 404);
    if (interesting.length > 0) {
      statusDiv.innerHTML += `<br>⚠️ Найдено ${interesting.length} потенциально опасных путей:`;
      displayResults(interesting);
      exportContainer.classList.remove('hidden');
      if (filtersContainer) filtersContainer.classList.remove('hidden');
      checkDebugBanner(enrichedResults);
    } else if (networkErrors.length === 0) {
      statusDiv.textContent = '✅ Ничего критичного не найдено.';
      exportContainer.classList.add('hidden');
      checkDebugBanner(enrichedResults);
    } else {
      checkDebugBanner(enrichedResults);
    }
  }
}

function displayResults(interesting) {
  const resultsTable = document.getElementById('resultsTable');
  const tbody = resultsTable.querySelector('tbody');
  tbody.innerHTML = '';
  resultsTable.classList.remove('hidden');
  interesting.sort((a, b) => {
    const priority = { 200: 1, 301: 2, 302: 2, 401: 3, 403: 3, 500: 4 };
    return (priority[a.status] || 5) - (priority[b.status] || 5);
  });
  for (const item of interesting) {
    const row = tbody.insertRow();
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

function startAdditionalScan(item, button) {
  const fullUrl = item.fullUrl;
  const parentUrl = fullUrl.substring(0, fullUrl.lastIndexOf('/') + 1);
  button.innerHTML = '⏳';
  button.disabled = true;
  additionalButton = button;
  if (additionalPort) additionalPort.disconnect();
  additionalPort = browser.runtime.connect({ name: "scanner" });
  additionalPort.onMessage.addListener((msg) => {
    if (msg.type === "progress") {
    } else if (msg.type === "result") {
      button.innerHTML = '🔍';
      button.disabled = false;
      additionalButton = null;
      const newResults = msg.results;
      const enrichedNew = newResults.map(r => enrichResult(r, parentUrl, 'path'));
      const existingUrls = new Set(currentScanData.results.map(r => r.fullUrl));
      let addedCount = 0;
      for (const enriched of enrichedNew) {
        if (!existingUrls.has(enriched.fullUrl)) {
          currentScanData.results.push(enriched);
          existingUrls.add(enriched.fullUrl);
          addedCount++;
        }
      }
      const allInteresting = currentScanData.results.filter(r => r.status !== 404 && r.status !== 'network_error' && r.status !== 'error');
      displayResults(allInteresting);
      checkDebugBanner(currentScanData.results);
      applyFilter();
      const toSave = {
        baseUrl: currentScanData.baseUrl,
        mode: currentScanData.mode,
        results: currentScanData.results,
        timestamp: Date.now()
      };
      browser.storage.local.set({ lastScanResults: toSave });
      document.getElementById('exportContainer').classList.remove('hidden');
      document.getElementById('filtersContainer').classList.remove('hidden');
      additionalPort.disconnect();
      additionalPort = null;
    }
  });
  additionalPort.postMessage({ command: "start", url: parentUrl, mode: "path" });
}

function startScan(mode) {
  const statusDiv = document.getElementById('status');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const resultsTable = document.getElementById('resultsTable');
  const lastScanInfo = document.getElementById('lastScanInfo');
  const exportContainer = document.getElementById('exportContainer');
  const filtersContainer = document.getElementById('filtersContainer');
  const debugBanner = document.getElementById('debugBanner');
  const pauseBtn = document.getElementById('pauseBtn');

  currentScanData = null;
  paused = false;
  if (additionalPort) { additionalPort.disconnect(); additionalPort = null; }
  if (additionalButton) { additionalButton.innerHTML = '🔍'; additionalButton.disabled = false; additionalButton = null; }
  if (port) { port.disconnect(); port = null; }

  resultsTable.classList.add('hidden');
  lastScanInfo.classList.add('hidden');
  exportContainer.classList.add('hidden');
  if (filtersContainer) filtersContainer.classList.add('hidden');
  progressContainer.classList.remove('hidden');
  progressBar.value = 0;
  progressBar.max = 100;
  progressText.textContent = '0 / 0';
  statusDiv.textContent = 'Сканирование...';
  if (debugBanner) debugBanner.classList.add('hidden');
  if (pauseBtn) { pauseBtn.textContent = '⏸ Пауза'; pauseBtn.classList.remove('hidden'); }

  browser.storage.local.remove('lastScanResults');

  browser.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
    let baseUrl;
    if (mode === 'path') {
      baseUrl = tab.url;
    } else {
      baseUrl = new URL(tab.url).origin;
    }
    port = browser.runtime.connect({ name: "scanner" });
    port.onMessage.addListener((msg) => {
      if (msg.type === "progress") {
        const percent = Math.round((msg.current / msg.total) * 100);
        progressBar.value = percent;
        let text = `${msg.current} / ${msg.total}`;
        if (msg.rate !== undefined) text += ` (${msg.rate} req/s, ост. ~${msg.eta}с)`;
        progressText.textContent = text;
      } else if (msg.type === "result") {
        progressContainer.classList.add('hidden');
        if (pauseBtn) pauseBtn.classList.add('hidden');
        const results = msg.results;
        const enriched = results.map(r => enrichResult(r, baseUrl, mode));
        currentScanData = { baseUrl, mode, results: enriched };
        checkDebugBanner(enriched);

        if (msg.securityHeaders) {
          const secDiv = document.getElementById('securityHeaders');
          if (secDiv) {
            const h = msg.securityHeaders;
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
        }

        const networkErrors = enriched.filter(r => r.status === 'network_error' || r.status === 'error');
        const httpResults = enriched.filter(r => r.status !== 'network_error' && r.status !== 'error');
        if (networkErrors.length > 0) {
          statusDiv.innerHTML = `❌ Ошибки сети для ${networkErrors.length} путей (см. консоль)`;
        }
        const interesting = httpResults.filter(r => r.status !== 404);
        const toSave = {
          baseUrl: baseUrl,
          mode: mode,
          results: enriched,
          timestamp: Date.now()
        };
        browser.storage.local.set({ lastScanResults: toSave });
        if (interesting.length > 0) {
          statusDiv.innerHTML += `<br>⚠️ Найдено ${interesting.length} потенциально опасных путей:`;
          displayResults(interesting);
          exportContainer.classList.remove('hidden');
          if (filtersContainer) filtersContainer.classList.remove('hidden');
          applyFilter();
        } else if (networkErrors.length === 0) {
          statusDiv.textContent = '✅ Ничего критичного не найдено.';
        }
        port.disconnect();
        port = null;
      } else if (msg.type === "paused") {
      }
    });
    port.postMessage({ command: "start", url: baseUrl, mode: mode });
  }).catch(err => {
    console.error('[popup] ошибка получения вкладки:', err);
    statusDiv.textContent = 'Ошибка получения адреса страницы';
  });
}

// Экспорт CSV
document.getElementById('exportBtn').addEventListener('click', () => {
  if (!currentScanData) return;
  const { results, baseUrl } = currentScanData;
  const rows = [ ['Путь (URL)', 'Статус', 'Размер (байт)'] ];
  for (const item of results) {
    if (item.status === 'network_error' || item.status === 'error' || item.status === 404) continue;
    rows.push([item.fullUrl, item.status, item.size]);
  }
  const csv = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan_${new URL(baseUrl).hostname}_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
});

// Экспорт JSON
document.getElementById('exportJsonBtn').addEventListener('click', () => {
  if (!currentScanData) return;
  const exportData = {
    scanTime: new Date().toISOString(),
    baseUrl: currentScanData.baseUrl,
    mode: currentScanData.mode,
    results: currentScanData.results.filter(r => r.status !== 404 && r.status !== 'network_error')
  };
  const json = JSON.stringify(exportData, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan_${new URL(currentScanData.baseUrl).hostname}_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

// Экспорт HTML
document.getElementById('exportHtmlBtn').addEventListener('click', () => {
  if (!currentScanData) return;
  const { results, baseUrl, mode } = currentScanData;
  const interesting = results.filter(r => r.status !== 404 && r.status !== 'network_error' && r.status !== 'error');
  // Generate HTML
  const html = `
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Отчёт сканирования Sensitive File Scanner</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    h1 { color: #2c3e50; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background-color: #f2f2f2; }
    .status-200 { color: green; font-weight: bold; }
    .status-301, .status-302 { color: orange; }
    .status-401, .status-403 { color: darkorange; font-weight: bold; }
    .status-500 { color: red; font-weight: bold; }
    .status-error { color: gray; }
    .meta { margin-bottom: 10px; color: #555; }
  </style>
</head>
<body>
  <h1>Отчёт сканирования Sensitive File Scanner</h1>
  <div class="meta">
    <strong>Дата сканирования:</strong> ${new Date().toLocaleString()}<br>
    <strong>Базовый URL:</strong> ${baseUrl}<br>
    <strong>Режим:</strong> ${mode === 'site' ? 'Сайт' : 'Текущий путь'}
  </div>
  <table>
    <thead>
      <tr>
        <th>Путь</th>
        <th>Полный URL</th>
        <th>Статус</th>
        <th>Размер (байт)</th>
      </tr>
    </thead>
    <tbody>
      ${interesting.map(item => `
        <tr>
          <td>${item.path}</td>
          <td><a href="${item.fullUrl}" target="_blank">${item.fullUrl}</a></td>
          <td class="status-${item.status}">${item.status}</td>
          <td>${item.size}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
</body>
</html>
  `.trim();
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan_${new URL(baseUrl).hostname}_${new Date().toISOString().slice(0,10)}.html`;
  a.click();
  URL.revokeObjectURL(a.href);
});

// Пауза
document.getElementById('pauseBtn').addEventListener('click', () => {
  if (!port) return;
  paused = !paused;
  document.getElementById('pauseBtn').textContent = paused ? '▶ Продолжить' : '⏸ Пауза';
  port.postMessage({ command: "pause", value: paused });
});

// Тёмная тема
const themeToggle = document.getElementById('themeToggle');
if (themeToggle) {
  const currentTheme = localStorage.getItem('theme') || 'light';
  if (currentTheme === 'dark') {
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

// Назначение кнопок
document.getElementById('scanSiteBtn').addEventListener('click', () => startScan('site'));
document.getElementById('scanPathBtn').addEventListener('click', () => startScan('path'));

initFilters();
restoreLastResults();