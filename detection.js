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

// New detections
function detectMagento(results) {
  const paths = ['/app/etc/env.php', '/downloader/', '/var/export/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'Magento', confidence: 'high' };
  }
  return null;
}

function detectShopify(results) {
  // Shopify often has /cdn.shopify.com or specific assets, but we check for common paths
  const paths = ['/admin/', '/cart/', '/checkout/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'Shopify', confidence: 'medium' };
  }
  return null;
}

function detectTypo3(results) {
  const paths = ['/typo3/', '/typo3conf/', '/fileadmin/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'TYPO3', confidence: 'high' };
  }
  return null;
}

function detectGhost(results) {
  const paths = ['/ghost/', '/content/', '/assets/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'Ghost', confidence: 'medium' };
  }
  return null;
}

function detectStrapi(results) {
  const paths = ['/admin/', '/api/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'Strapi', confidence: 'medium' };
  }
  return null;
}

function detectAspNet(results) {
  const paths = ['/web.config', '/bin/', '/App_Code/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'ASP.NET', confidence: 'high' };
  }
  return null;
}

function detectRubyOnRails(results) {
  const paths = ['/config/', '/app/', '/public/'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'Ruby on Rails', confidence: 'medium' };
  }
  return null;
}

function detectExpress(results) {
  // Express.js apps often have no specific paths, but we can check for common middleware paths
  const paths = ['/node_modules/express/', '/package.json'];
  if (results.some(r => paths.some(p => r.path === p && r.status === 200))) {
    return { name: 'Express.js', confidence: 'medium' };
  }
  return null;
}

function analyzeAll(results) {
  const tech = [];
  const wordpress = detectWordPress(results);
  if (wordpress) tech.push(wordpress);
  const django = detectDjangoDebug(results);
  if (django) tech.push(django);
  const joomla = detectJoomla(results);
  if (joomla) tech.push(joomla);
  const drupal = detectDrupal(results);
  if (drupal) tech.push(drupal);
  const laravel = detectLaravel(results);
  if (laravel) tech.push(laravel);
  const bitrix = detectBitrix(results);
  if (bitrix) tech.push(bitrix);
  const magento = detectMagento(results);
  if (magento) tech.push(magento);
  const shopify = detectShopify(results);
  if (shopify) tech.push(shopify);
  const typo3 = detectTypo3(results);
  if (typo3) tech.push(typo3);
  const ghost = detectGhost(results);
  if (ghost) tech.push(ghost);
  const strapi = detectStrapi(results);
  if (strapi) tech.push(strapi);
  const aspnet = detectAspNet(results);
  if (aspnet) tech.push(aspnet);
  const rubyonrails = detectRubyOnRails(results);
  if (rubyonrails) tech.push(rubyonrails);
  const express = detectExpress(results);
  if (express) tech.push(express);

  const vulns = [];
  if (results.some(r => r.path.startsWith('/.git/') && r.status === 200)) vulns.push('exposed_git');
  if (results.some(r => r.path === '/.env' && r.status === 200)) vulns.push('env_exposed');
  if (results.some(r => r.debugMode)) vulns.push('debug_mode');
  // New vulnerability checks
  if (results.some(r => r.path === '/phpinfo.php' && r.status === 200)) vulns.push('phpinfo_exposed');
  if (results.some(r => ['/status', '/server-status'].includes(r.path) && r.status === 200)) vulns.push('status_exposed');
  if (results.some(r => ['/swagger-ui.html', '/api-docs', '/api.json'].includes(r.path) && r.status === 200)) vulns.push('swagger_exposed');
  if (results.some(r => r.path.startsWith('/actuator/') && r.status === 200)) vulns.push('actuator_exposed');
  if (results.some(r => r.path === '/console' && r.status === 200)) vulns.push('h2_console_exposed');

  return { detectedTech: tech, vulnerabilities: vulns };
}