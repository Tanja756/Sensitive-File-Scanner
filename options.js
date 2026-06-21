const defaults = {
  timeout: 10,
  batchSize: 10,
  rateLimit: 0,
  useHead: true,
  scanProtocol: 'https',
  categories: ['git', 'docker', 'cicd', 'cloud', 'cms', 'backup', 'logs', 'ide']
};

function countWordlistLines(text) {
  if (!text || !text.trim()) return 0;
  return text.split('\n').filter(l => {
    const t = l.trim();
    return t && !t.startsWith('#') && !t.startsWith('//') && !t.startsWith('/*');
  }).length;
}

function updateWordlistStatus(customText) {
  const el = document.getElementById('wordlistStatus');
  const n = countWordlistLines(customText);
  el.textContent = n > 0 ? `Пользовательских путей: ${n}` : 'Пользовательский список пуст (используется только встроенный wordlist.txt)';
}

async function restore() {
  const data = await browser.storage.local.get(['options', 'customWordlist', 'useCustomOnly']);
  const config = data.options || defaults;
  document.getElementById('timeout').value = config.timeout;
  document.getElementById('batchSize').value = config.batchSize;
  document.getElementById('rateLimit').value = config.rateLimit;
  document.getElementById('useHead').checked = config.useHead !== false;
  const protoRadio = document.querySelector(`input[name="scanProtocol"][value="${config.scanProtocol || 'https'}"]`);
  if (protoRadio) protoRadio.checked = true;
  document.querySelectorAll('.category').forEach(cb => {
    cb.checked = config.categories.includes(cb.dataset.cat);
  });
  document.getElementById('customWordlist').value = data.customWordlist || '';
  document.getElementById('useCustomOnly').checked = !!data.useCustomOnly;
  updateWordlistStatus(data.customWordlist || '');
}

document.getElementById('customWordlist').addEventListener('input', (e) => {
  updateWordlistStatus(e.target.value);
});

document.getElementById('wordlistFile').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById('customWordlist').value = reader.result;
    updateWordlistStatus(reader.result);
    document.getElementById('status').textContent = `Загружено из ${file.name}`;
  };
  reader.readAsText(file);
  e.target.value = '';
});

document.getElementById('clearCustomBtn').addEventListener('click', () => {
  document.getElementById('customWordlist').value = '';
  updateWordlistStatus('');
});

document.getElementById('saveBtn').addEventListener('click', async () => {
  const timeout = parseInt(document.getElementById('timeout').value, 10) || 10;
  const batchSize = parseInt(document.getElementById('batchSize').value, 10) || 10;
  const rateLimit = parseInt(document.getElementById('rateLimit').value, 10) || 0;
  const useHead = document.getElementById('useHead').checked;
  const scanProtocol = document.querySelector('input[name="scanProtocol"]:checked')?.value || 'https';
  const categories = Array.from(document.querySelectorAll('.category:checked')).map(cb => cb.dataset.cat);
  const customWordlist = document.getElementById('customWordlist').value;
  const useCustomOnly = document.getElementById('useCustomOnly').checked;

  await browser.storage.local.set({
    options: { timeout, batchSize, rateLimit, useHead, scanProtocol, categories },
    customWordlist,
    useCustomOnly
  });

  document.getElementById('status').textContent = 'Сохранено. Перезагрузите скан для применения wordlist.';
});

restore();
