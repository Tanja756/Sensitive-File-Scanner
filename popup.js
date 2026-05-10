let port = null;
let currentScanData = null; // { baseUrl, mode, results }

// Восстановление предыдущих результатов при загрузке
async function restoreLastResults() {
  const data = await browser.storage.local.get('lastScanResults');
  if (data.lastScanResults) {
    const { baseUrl, mode, results, timestamp } = data.lastScanResults;
    currentScanData = { baseUrl, mode, results };

    const statusDiv = document.getElementById('status');
    const lastScanInfo = document.getElementById('lastScanInfo');
    const exportContainer = document.getElementById('exportContainer');

    lastScanInfo.textContent = `Предыдущее сканирование: ${new Date(timestamp).toLocaleString()} (${mode})`;
    lastScanInfo.classList.remove('hidden');

    const networkErrors = results.filter(r => r.status === 'network_error' || r.status === 'error');
    const httpResults = results.filter(r => r.status !== 'network_error' && r.status !== 'error');

    if (networkErrors.length > 0) {
      statusDiv.innerHTML = `❌ Ошибки сети для ${networkErrors.length} путей (см. консоль)`;
    }

    const interesting = httpResults.filter(r => r.status !== 404);
    if (interesting.length > 0) {
      statusDiv.innerHTML += `<br>⚠️ Найдено ${interesting.length} потенциально опасных путей:`;
      displayResults(interesting, baseUrl, mode);
      exportContainer.classList.remove('hidden');
    } else if (networkErrors.length === 0) {
      statusDiv.textContent = '✅ Ничего критичного не найдено.';
      exportContainer.classList.add('hidden');
    }
  }
}

function displayResults(interesting, baseUrl, mode) {
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

    let fullUrl;
    if (mode === 'path') {
      const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
      fullUrl = new URL(item.path.startsWith('/') ? item.path.slice(1) : item.path, base).href;
    } else {
      fullUrl = new URL(item.path, baseUrl).href;
    }

    const link = document.createElement('a');
    link.href = fullUrl;
    link.target = '_blank';
    link.textContent = item.path;
    link.style.color = 'inherit';
    pathCell.appendChild(link);

    const statusCell = row.insertCell();
    statusCell.textContent = item.status;
    statusCell.className = `status-${item.status}`;
    row.insertCell().textContent = item.size + ' B';
  }
}

function startScan(mode) {
  console.log(`[popup] startScan вызван, mode: ${mode}`);
  const statusDiv = document.getElementById('status');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const resultsTable = document.getElementById('resultsTable');
  const lastScanInfo = document.getElementById('lastScanInfo');
  const exportContainer = document.getElementById('exportContainer');

  // Сброс состояния
  currentScanData = null;
  resultsTable.classList.add('hidden');
  lastScanInfo.classList.add('hidden');
  exportContainer.classList.add('hidden');
  progressContainer.classList.remove('hidden');
  progressBar.value = 0;
  progressBar.max = 100;
  progressText.textContent = '0 / 0';
  statusDiv.textContent = 'Сканирование...';

  browser.storage.local.remove('lastScanResults');

  if (port) {
    port.disconnect();
  }

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
        progressText.textContent = `${msg.current} / ${msg.total}`;
      } else if (msg.type === "result") {
        progressContainer.classList.add('hidden');
        const results = msg.results;

        currentScanData = { baseUrl, mode, results };

        const networkErrors = results.filter(r => r.status === 'network_error' || r.status === 'error');
        const httpResults = results.filter(r => r.status !== 'network_error' && r.status !== 'error');

        if (networkErrors.length > 0) {
          statusDiv.innerHTML = `❌ Ошибки сети для ${networkErrors.length} путей (см. консоль)`;
        }

        const interesting = httpResults.filter(r => r.status !== 404);

        // Сохраняем в storage
        const toSave = {
          baseUrl: baseUrl,
          mode: mode,
          results: results,
          timestamp: Date.now()
        };
        browser.storage.local.set({ lastScanResults: toSave });

        if (interesting.length > 0) {
          statusDiv.innerHTML += `<br>⚠️ Найдено ${interesting.length} потенциально опасных путей:`;
          displayResults(interesting, baseUrl, mode);
          exportContainer.classList.remove('hidden');
        } else if (networkErrors.length === 0) {
          statusDiv.textContent = '✅ Ничего критичного не найдено.';
        }

        port.disconnect();
        port = null;
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
  const { results, baseUrl, mode } = currentScanData;
  const rows = [ ['Путь', 'Статус', 'Размер (байт)'] ];
  for (const item of results) {
    if (item.status === 'network_error' || item.status === 'error') continue;
    if (item.status === 404) continue;
    let fullUrl;
    if (mode === 'path') {
      const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
      fullUrl = new URL(item.path.startsWith('/') ? item.path.slice(1) : item.path, base).href;
    } else {
      fullUrl = new URL(item.path, baseUrl).href;
    }
    rows.push([fullUrl, item.status, item.size]);
  }
  const csv = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan_${new URL(baseUrl).hostname}_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
});

// Назначение кнопок
document.getElementById('scanSiteBtn').addEventListener('click', () => startScan('site'));
document.getElementById('scanPathBtn').addEventListener('click', () => startScan('path'));

// Восстановление результатов при загрузке
restoreLastResults();