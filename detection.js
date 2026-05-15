// detection.js - определение технологий и уязвимостей

function detectWordPress(results) {
  const wpPaths = ['/wp-admin/', '/wp-login.php', '/wp-includes/', '/wp-content/'];
  const found = results.some(r => wpPaths.some(p => r.path === p && r.status === 200));
  if (found) return { name: 'WordPress', confidence: 'high' };
  const readme = results.find(r => r.path === '/readme.html' && r.status === 200);
  if (readme && readme.size > 100) return { name: 'WordPress', confidence: 'medium' };
  return null;
}

function detectDjangoDebug(results) {
  const debugPaths = ['/.env', '/debug.log', '/error.log'];
  const hasDebugPath = results.some(r => debugPaths.includes(r.path) && r.status === 200);
  const hasDebugContent = results.some(r => r.debugMode === true);
  if (hasDebugPath || hasDebugContent) return { name: 'Django', confidence: 'high', debug: true };
  return null;
}

function detectJoomla(results) {
  const paths = ['/administrator/', '/templates/system/', '/language/en-GB/en-GB.ini'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) return { name: 'Joomla', confidence: 'high' };
  return null;
}

function detectDrupal(results) {
  const paths = ['/sites/default/settings.php', '/misc/drupal.js', '/modules/system/system.info'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) return { name: 'Drupal', confidence: 'high' };
  return null;
}

function detectLaravel(results) {
  const paths = ['/artisan', '/vendor/', '/composer.json', '/config/app.php'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) return { name: 'Laravel', confidence: 'high' };
  return null;
}

function detectBitrix(results) {
  const paths = ['/bitrix/admin/', '/bitrix/php_interface/dbconn.php', '/bitrix/.settings.php', '/local/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) return { name: '1C-Bitrix', confidence: 'high' };
  return null;
}

function analyzeAll(results) {
  const tech = [];
  const django = detectDjangoDebug(results);
  if (django) tech.push(django);
  const wp = detectWordPress(results);
  if (wp) tech.push(wp);
  const joomla = detectJoomla(results);
  if (joomla) tech.push(joomla);
  const drupal = detectDrupal(results);
  if (drupal) tech.push(drupal);
  const laravel = detectLaravel(results);
  if (laravel) tech.push(laravel);
  const bitrix = detectBitrix(results);
  if (bitrix) tech.push(bitrix);

  const vulns = [];
  if (results.some(r => r.path.startsWith('/.git/') && r.status === 200)) vulns.push('exposed_git');
  if (results.some(r => r.path === '/.env' && r.status === 200)) vulns.push('env_exposed');
  if (results.some(r => r.debugMode)) vulns.push('debug_mode');

  return { detectedTech: tech, vulnerabilities: vulns };
}