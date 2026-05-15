const defaults = {
  timeout: 10,
  batchSize: 10,
  rateLimit: 0,
  categories: ['git','docker','cicd','cloud','cms','backup','logs','ide']
};

async function restore() {
  const opts = await browser.storage.local.get('options');
  const config = opts.options || defaults;
  document.getElementById('timeout').value = config.timeout;
  document.getElementById('batchSize').value = config.batchSize;
  document.getElementById('rateLimit').value = config.rateLimit;
  const catCheckboxes = document.querySelectorAll('.category');
  catCheckboxes.forEach(cb => {
    cb.checked = config.categories.includes(cb.dataset.cat);
  });
}

document.getElementById('saveBtn').addEventListener('click', async () => {
  const timeout = parseInt(document.getElementById('timeout').value) || 10;
  const batchSize = parseInt(document.getElementById('batchSize').value) || 10;
  const rateLimit = parseInt(document.getElementById('rateLimit').value) || 0;
  const categories = Array.from(document.querySelectorAll('.category:checked')).map(cb => cb.dataset.cat);
  await browser.storage.local.set({ options: { timeout, batchSize, rateLimit, categories } });
  document.getElementById('status').textContent = 'Сохранено.';
});

restore();