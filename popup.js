let port = null;

function startScan(mode) {
  console.log(`[popup] startScan вызван, mode: ${mode}`);
  const statusDiv = document.getElementById('status');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const resultsTable = document.getElementById('resultsTable');
  const tbody = resultsTable.querySelector('tbody');

  // Очистка
  tbody.innerHTML = '';
  resultsTable.classList.add('hidden');
  progressContainer.classList.remove('hidden');
  progressBar.value = 0;
  progressBar.max = 100;
  progressText.textContent = '0 / 0';
  statusDiv.textContent = 'Сканирование...';

  if (port) {
    console.log('[popup] отключаем предыдущий порт');
    port.disconnect();
  }

  browser.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
    console.log('[popup] текущая вкладка:', tab.url);
    let baseUrl;
    if (mode === 'path') {
      baseUrl = tab.url;
      console.log('[popup] baseUrl (path mode):', baseUrl);
    } else {
      baseUrl = new URL(tab.url).origin;
      console.log('[popup] baseUrl (site mode):', baseUrl);
    }

    port = browser.runtime.connect({ name: "scanner" });

    port.onMessage.addListener((msg) => {
      console.log('[popup] сообщение от порта:', msg);
      if (msg.type === "progress") {
        const percent = Math.round((msg.current / msg.total) * 100);
        progressBar.value = percent;
        progressText.textContent = `${msg.current} / ${msg.total}`;
        console.log(`[popup] прогресс: ${msg.current}/${msg.total}`);
      } else if (msg.type === "result") {
        progressContainer.classList.add('hidden');
        const results = msg.results;
        console.log('[popup] получено результатов:', results.length);
        console.log('[popup] все результаты:', results);

        const networkErrors = results.filter(r => r.status === 'network_error' || r.status === 'error');
        const httpResults = results.filter(r => r.status !== 'network_error' && r.status !== 'error');

        console.log('[popup] networkErrors:', networkErrors.length, 'httpResults:', httpResults.length);
        if (networkErrors.length > 0) {
          statusDiv.innerHTML = `❌ Ошибки сети для ${networkErrors.length} путей (см. консоль фона)`;
          console.log('[popup] ошибки сети:', networkErrors);
        }

        const interesting = httpResults.filter(r => r.status !== 404);
        console.log('[popup] интересных после фильтрации 404:', interesting.length);

        if (interesting.length === 0 && networkErrors.length === 0) {
          statusDiv.innerHTML = '✅ Ничего критичного не найдено.';
          return;
        }

        if (interesting.length > 0) {
          statusDiv.innerHTML += `<br>⚠️ Найдено ${interesting.length} потенциально опасных путей:`;
          resultsTable.classList.remove('hidden');
          interesting.sort((a, b) => {
            const priority = { 200: 1, 301: 2, 302: 2, 401: 3, 403: 3, 500: 4 };
            return (priority[a.status] || 5) - (priority[b.status] || 5);
          });
          for (const item of interesting) {
            const row = tbody.insertRow();
            row.insertCell().textContent = item.path;
            const statusCell = row.insertCell();
            statusCell.textContent = item.status;
            statusCell.className = `status-${item.status}`;
            row.insertCell().textContent = item.size + ' B';
          }
        }

        port.disconnect();
        port = null;
      }
    });

    console.log('[popup] отправка start порту');
    port.postMessage({ command: "start", url: baseUrl, mode: mode });
  }).catch(err => {
    console.error('[popup] ошибка получения вкладки:', err);
    statusDiv.textContent = 'Ошибка получения адреса страницы';
  });
}

document.getElementById('scanSiteBtn').addEventListener('click', () => startScan('site'));
document.getElementById('scanPathBtn').addEventListener('click', () => startScan('path'));