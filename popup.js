let port = null;
let currentScanData = null; // { baseUrl, mode, results: [...] }
let additionalPort = null;
let additionalButton = null;

// Вспомогательная функция: вычислить полный URL
function getFullUrl(path, baseUrl, mode) {
  if (mode === 'path') {
    const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
    return new URL(path.startsWith('/') ? path.slice(1) : path, base).href;
  } else {
    return new URL(path, baseUrl).href;
  }
}

// Обогащаем результат полями fullUrl, baseUrl, mode
function enrichResult(item, baseUrl, mode) {
  return {
    ...item,
    fullUrl: getFullUrl(item.path, baseUrl, mode),
    baseUrl: baseUrl,
    mode: mode
  };
}

// Баннер DEBUG = True
function checkDebugBanner(results) {
  const debugBanner = document.getElementById('debugBanner');
  if (results.some(r => r.debugMode === true)) {
    debugBanner.classList.remove('hidden');
  } else {
    debugBanner.classList.add('hidden');
  }
}

// Восстановление предыдущих результатов при загрузке
async function restoreLastResults() {
  const data = await browser.storage.local.get('lastScanResults');
  if (data.lastScanResults) {
    const { baseUrl, mode, results, timestamp } = data.lastScanResults;
    // Миграция – если результаты старые и нет fullUrl
    const enrichedResults = results.map(r => {
      if (!r.fullUrl) {
        return enrichResult(r, baseUrl, mode);
      }
      return r;
    });

    currentScanData = { baseUrl, mode, results: enrichedResults };

    const statusDiv = document.getElementById('status');
    const lastScanInfo = document.getElementById('lastScanInfo');
    const exportContainer = document.getElementById('exportContainer');

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

// Отображение таблицы результатов (принимает массив интересных обогащённых объектов)
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

    // Кнопка "Сканировать папку"
    const actionCell = row.insertCell();
    const scanBtn = document.createElement('button');
    scanBtn.className = 'scan-btn';
    scanBtn.innerHTML = '🔍'; // иконка лупы
    scanBtn.title = 'Сканировать эту директорию';
    scanBtn.addEventListener('click', () => {
      startAdditionalScan(item, scanBtn);
    });
    actionCell.appendChild(scanBtn);
  }
}

// Запуск дополнительного сканирования для родительской директории найденного элемента
function startAdditionalScan(item, button) {
  // Вычисляем родительский URL
  const fullUrl = item.fullUrl;
  // Определяем родительскую директорию: убираем всё после последнего слеша
  const parentUrl = fullUrl.substring(0, fullUrl.lastIndexOf('/') + 1);
  console.log(`[popup] дополнительное сканирование: ${parentUrl}`);

  // Меняем иконку на индикатор загрузки
  button.innerHTML = '⏳';
  button.disabled = true;
  additionalButton = button;

  // Если предыдущий дополнительный порт существует, закрываем
  if (additionalPort) {
    additionalPort.disconnect();
  }

  additionalPort = browser.runtime.connect({ name: "scanner" });

  additionalPort.onMessage.addListener((msg) => {
    if (msg.type === "progress") {
      // Можно показывать мини-прогресс, но оставим просто индикатор
    } else if (msg.type === "result") {
      // Восстанавливаем иконку
      button.innerHTML = '🔍';
      button.disabled = false;
      additionalButton = null;

      const newResults = msg.results;
      console.log(`[popup] дополнительное сканирование завершено, получено ${newResults.length} результатов`);

      // Обогащаем новые результаты
      const enrichedNew = newResults.map(r => enrichResult(r, parentUrl, 'path'));

      // Добавляем в currentScanData.results, избегая дубликатов по fullUrl
      const existingUrls = new Set(currentScanData.results.map(r => r.fullUrl));
      let addedCount = 0;
      for (const enriched of enrichedNew) {
        if (!existingUrls.has(enriched.fullUrl)) {
          currentScanData.results.push(enriched);
          existingUrls.add(enriched.fullUrl);
          addedCount++;
        }
      }
      console.log(`[popup] добавлено ${addedCount} новых уникальных результатов`);

      // Обновляем отображение – показываем все интересные (не 404) из актуального results
      const allInteresting = currentScanData.results.filter(
        r => r.status !== 404 && r.status !== 'network_error' && r.status !== 'error'
      );
      displayResults(allInteresting);
      checkDebugBanner(currentScanData.results);

      // Сохраняем обновлённые данные в storage
      const toSave = {
        baseUrl: currentScanData.baseUrl,
        mode: currentScanData.mode,
        results: currentScanData.results,
        timestamp: Date.now()
      };
      browser.storage.local.set({ lastScanResults: toSave });

      // Показываем кнопку экспорта
      document.getElementById('exportContainer').classList.remove('hidden');

      additionalPort.disconnect();
      additionalPort = null;
    }
  });

  // Запускаем сканирование с parentUrl в режиме path
  additionalPort.postMessage({ command: "start", url: parentUrl, mode: "path" });
}

// Основное сканирование
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
  if (additionalPort) {
    additionalPort.disconnect();
    additionalPort = null;
  }
  if (additionalButton) {
    additionalButton.innerHTML = '🔍';
    additionalButton.disabled = false;
    additionalButton = null;
  }

  resultsTable.classList.add('hidden');
  lastScanInfo.classList.add('hidden');
  exportContainer.classList.add('hidden');
  progressContainer.classList.remove('hidden');
  progressBar.value = 0;
  progressBar.max = 100;
  progressText.textContent = '0 / 0';
  statusDiv.textContent = 'Сканирование...';
  document.getElementById('debugBanner').classList.add('hidden');

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

        // Обогащаем результаты
        const enriched = results.map(r => enrichResult(r, baseUrl, mode));

        currentScanData = { baseUrl, mode, results: enriched };
        checkDebugBanner(enriched);

        const networkErrors = enriched.filter(r => r.status === 'network_error' || r.status === 'error');
        const httpResults = enriched.filter(r => r.status !== 'network_error' && r.status !== 'error');

        if (networkErrors.length > 0) {
          statusDiv.innerHTML = `❌ Ошибки сети для ${networkErrors.length} путей (см. консоль)`;
        }

        const interesting = httpResults.filter(r => r.status !== 404);

        // Сохраняем в storage
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
  const { results } = currentScanData;
  const rows = [ ['Путь (URL)', 'Статус', 'Размер (байт)'] ];
  for (const item of results) {
    if (item.status === 'network_error' || item.status === 'error' || item.status === 404) continue;
    rows.push([item.fullUrl, item.status, item.size]);
  }
  const csv = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan_${new URL(currentScanData.baseUrl).hostname}_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
});

// Назначение кнопок
document.getElementById('scanSiteBtn').addEventListener('click', () => startScan('site'));
document.getElementById('scanPathBtn').addEventListener('click', () => startScan('path'));

// Восстановление результатов при загрузке
restoreLastResults();