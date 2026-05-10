let PATHS = [];
let pathsLoaded = false;
let loadingPromise = null;

async function loadWordlist() {
  if (pathsLoaded) {
    console.log('[bg] wordlist уже загружен, путей:', PATHS.length);
    return;
  }
  if (loadingPromise) {
    console.log('[bg] ожидание предыдущей загрузки wordlist...');
    return loadingPromise;
  }

  console.log('[bg] начинаем загрузку wordlist.txt');
  loadingPromise = (async () => {
    try {
      const url = browser.runtime.getURL('wordlist.txt');
      console.log('[bg] URL wordlist:', url);
      const response = await fetch(url);
      console.log('[bg] ответ загрузки wordlist:', response.status, response.statusText);
      const text = await response.text();
      console.log('[bg] получен текст длиной', text.length);
      PATHS = text
      .split('\n')
      .map(line => line.trim())
      .filter(line => {
        return line &&
               !line.startsWith('#') &&
               !line.startsWith('//') &&
               !line.startsWith('/*') &&
               !line.startsWith('*') &&
               !line.startsWith('===')
      });
        console.log('[bg] итого путей в PATHS:', PATHS.length);
    } catch (e) {
      console.error('[bg] ошибка загрузки wordlist:', e);
      PATHS = ["/.env", "/.git/config", "/backup.sql"];
      console.log('[bg] fallback список:', PATHS.length);
    } finally {
      pathsLoaded = true;
      loadingPromise = null;
    }
  })();

  return loadingPromise;
}

// Стартуем загрузку сразу
loadWordlist();

function resolvePath(baseUrl, path) {
  const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
  const relativePath = path.startsWith('/') ? path.slice(1) : path;
  return new URL(relativePath, base).href;
}

browser.runtime.onConnect.addListener((port) => {
  console.log('[bg] получено соединение на порт:', port.name);
  if (port.name === "scanner") {
    port.onMessage.addListener(async (msg) => {
      console.log('[bg] получено сообщение:', msg);
      if (msg.command === "start") {
        const baseUrl = msg.url;
        const mode = msg.mode || 'site';
        console.log('[bg] запуск сканирования, baseUrl:', baseUrl, 'mode:', mode);

        // Ждём загрузки wordlist
        await loadWordlist();
        console.log('[bg] после loadWordlist, PATHS length:', PATHS.length);

        const total = PATHS.length;
        console.log('[bg] общее количество путей для проверки:', total);
        if (total === 0) {
          console.warn('[bg] PATHS пуст, возвращаем пустой результат');
          port.postMessage({ type: "result", results: [] });
          return;
        }

        let completed = 0;
        const results = [];
        const batchSize = 10;

        for (let i = 0; i < total; i += batchSize) {
          const batch = PATHS.slice(i, i + batchSize);
          console.log(`[bg] обработка пакета ${Math.floor(i/batchSize)+1}, пути:`, batch);
          const batchResults = await Promise.allSettled(
            batch.map(path => {
              let url;
              if (mode === 'path') {
                url = resolvePath(baseUrl, path);
              } else {
                url = new URL(path, baseUrl).href;
              }
              console.log(`[bg] запрос: ${url}`);
              return checkPath(url, path);
            })
          );

          for (let j = 0; j < batch.length; j++) {
            const result = batchResults[j];
            if (result.status === 'fulfilled') {
              console.log(`[bg] ответ ${result.value.path}: статус ${result.value.status}, размер ${result.value.size}`);
              results.push(result.value);
            } else {
              console.warn(`[bg] ошибка для ${batch[j]}:`, result.reason);
              results.push({
                path: batch[j],
                status: 'error',
                size: 0,
                error: result.reason?.message || 'Unknown error'
              });
            }
            completed++;
          }

          port.postMessage({
            type: "progress",
            current: completed,
            total: total
          });
        }

        console.log('[bg] сканирование завершено, отправка результатов, всего:', results.length);
        port.postMessage({
          type: "result",
          results: results
        });
      }
    });
  }
});

function checkPath(fullUrl, displayPath) {
  return new Promise((resolve) => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('GET', fullUrl, true);
      xhr.responseType = 'text';
      xhr.timeout = 10000;

      xhr.onload = () => {
        const text = xhr.responseText;
        const debugDetected = checkForDjangoDebug(text);
        resolve({
          path: displayPath,
          status: xhr.status,
          size: text.length,
          redirected: xhr.responseURL !== fullUrl,
          debugMode: debugDetected
        });
      };

      xhr.onerror = () => {
        resolve({
          path: displayPath,
          status: 'network_error',
          size: 0,
          error: 'XHR error'
        });
      };

      xhr.ontimeout = () => {
        resolve({
          path: displayPath,
          status: 'network_error',
          size: 0,
          error: 'timeout'
        });
      };

      xhr.send();
    } catch (e) {
      resolve({
        path: displayPath,
        status: 'network_error',
        size: 0,
        error: e.message
      });
    }
  });
}

function checkForDjangoDebug(text) {
  if (!text) return false;
  const markers = [
    'DEBUG = True',
    'DJANGO_SETTINGS_MODULE',
    "You're seeing this error because you have DEBUG = True",
    'Traceback (most recent call last)',
    'Request URL:',
    'Django version:'
  ];
  return markers.some(marker => text.includes(marker));
}