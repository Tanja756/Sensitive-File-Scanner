// detection.js - определение технологий и уязвимостей

function scanHit(r) {
  if (r.interesting === false || r.soft404 || r.likelyFalsePositive) return false;
  return r.status === 200;
}

function detectWordPress(results) {
  const wpPaths = ['/wp-admin/', '/wp-login.php', '/wp-includes/', '/wp-content/'];
  const found = results.some(r => wpPaths.some(p => r.path === p && scanHit(r)));
  if (found) return { name: 'WordPress', confidence: 'high' };
  const readme = results.find(r => r.path === '/readme.html' && scanHit(r));
  if (readme && readme.size > 100) return { name: 'WordPress', confidence: 'medium' };
  return null;
}

function detectDjangoDebug(results) {
  const debugPaths = ['/.env', '/debug.log', '/error.log', '/django.log', '/django_debug.log'];
  const hasDebugPath = results.some(r => debugPaths.includes(r.path) && scanHit(r));
  const hasDebugContent = results.some(r => r.debugMode === true);
  const hasDebugData = results.some(r => r.debugData && r.debugData.length > 0);
  if (hasDebugPath || hasDebugContent || hasDebugData) return { name: 'Django', confidence: 'high', debug: true, dataExposed: hasDebugData };
  return null;
}

function detectJoomla(results) {
  const paths = ['/administrator/', '/templates/system/', '/language/en-GB/en-GB.ini'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) return { name: 'Joomla', confidence: 'high' };
  return null;
}

function detectDrupal(results) {
  const paths = ['/sites/default/settings.php', '/misc/drupal.js', '/modules/system/system.info'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) return { name: 'Drupal', confidence: 'high' };
  return null;
}

function detectLaravel(results) {
  const paths = ['/artisan', '/vendor/', '/composer.json', '/config/app.php'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) return { name: 'Laravel', confidence: 'high' };
  return null;
}

function detectBitrix(results) {
  const paths = ['/bitrix/admin/', '/bitrix/php_interface/dbconn.php', '/bitrix/.settings.php', '/local/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) return { name: '1C-Bitrix', confidence: 'high' };
  return null;
}

// New detections
function detectMagento(results) {
  const paths = ['/app/etc/env.php', '/downloader/', '/var/export/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'Magento', confidence: 'high' };
  }
  return null;
}

function detectShopify(results) {
  // Shopify often has /cdn.shopify.com or specific assets, but we check for common paths
  const paths = ['/admin/', '/cart/', '/checkout/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'Shopify', confidence: 'medium' };
  }
  return null;
}

function detectTypo3(results) {
  const paths = ['/typo3/', '/typo3conf/', '/fileadmin/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'TYPO3', confidence: 'high' };
  }
  return null;
}

function detectGhost(results) {
  const paths = ['/ghost/', '/content/', '/assets/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'Ghost', confidence: 'medium' };
  }
  return null;
}

function detectStrapi(results) {
  const paths = ['/admin/', '/api/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'Strapi', confidence: 'medium' };
  }
  return null;
}

function detectAspNet(results) {
  const paths = ['/web.config', '/bin/', '/App_Code/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'ASP.NET', confidence: 'high' };
  }
  return null;
}

function detectRubyOnRails(results) {
  const paths = ['/config/', '/app/', '/public/'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'Ruby on Rails', confidence: 'medium' };
  }
  return null;
}

function detectExpress(results) {
  // Express.js apps often have no specific paths, but we can check for common middleware paths
  const paths = ['/node_modules/express/', '/package.json'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) {
    return { name: 'Express.js', confidence: 'medium' };
  }
  return null;
}

function detectSolr(results) {
  const paths = ['/solr/admin/info/system', '/solr/admin/cores'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) return { name: 'Apache Solr', confidence: 'high' };
  return null;
}
function detectDruid(results) {
  if (results.some(r => r.path === '/druid/index.html' && scanHit(r))) return { name: 'Apache Druid', confidence: 'high' };
  return null;
}
function detectGeoServer(results) {
  if (results.some(r => r.path === '/geoserver/web/' && scanHit(r))) return { name: 'GeoServer', confidence: 'high' };
  return null;
}
function detectDockerRegistry(results) {
  if (results.some(r => r.path === '/v2/_catalog' && scanHit(r))) return { name: 'Docker Registry', confidence: 'high' };
  return null;
}
function detectJenkins(results) {
  const paths = ['/hudson', '/jenkins', '/jenkins/login'];
  if (results.some(r => paths.some(p => r.path === p && scanHit(r)))) return { name: 'Jenkins/Hudson', confidence: 'high' };
  return null;
}

const PMA_BASE_PATHS = ['/phpmyadmin/', '/phpMyAdmin/', '/pma/'];

const PMA_VULN_DB = [
  { maxVersion: '4.8.2', label: 'pma_vuln_cve_2018_12613', desc: 'File inclusion / RCE' },
  { maxVersion: '4.9.0', label: 'pma_vuln_cve_2018_19968', desc: 'SQL injection' },
  { maxVersion: '5.0.4', label: 'pma_vuln_cve_2020_26935', desc: 'XSS' },
  { maxVersion: '5.1.0', label: 'pma_vuln_cve_2021_21311', desc: 'Directory traversal / RCE' },
  { maxVersion: '5.1.2', label: 'pma_vuln_cve_2021_39277', desc: 'XSS' },
  { maxVersion: '5.2.0', label: 'pma_vuln_cve_2022_23804', desc: 'XSS via Twig' },
  { maxVersion: '5.2.1', label: 'pma_vuln_cve_2023_25776', desc: 'SQL injection' },
  { maxVersion: '5.2.2', label: 'pma_vuln_cve_2023_24810', desc: 'XSS via drag-and-drop' },
];

const PMA_KNOWN_OLD = '4.8.0';
const PMA_LATEST = '5.2.2';

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

function detectPhpMyAdmin(results) {
  const pmaRoot = results.find(r =>
    PMA_BASE_PATHS.some(p => r.path === p) && scanHit(r)
  );
  if (!pmaRoot) return null;

  let version = null;

  for (const r of results) {
    if (!scanHit(r) || !r.bodySnippet) continue;
    const snippet = r.bodySnippet;
    const m = snippet.match(/phpMyAdmin\s+v?(\d+\.\d+\.\d+)/i)
           || snippet.match(/Version\s+(\d+\.\d+\.\d+)/i);
    if (m) { version = m[1]; break; }
  }

  const setupExposed = results.some(r =>
    scanHit(r) && /\/phpmyadmin\/setup\//i.test(r.path)
  );
  const configExposed = results.some(r =>
    scanHit(r) && /\/phpmyadmin\/config\.inc\.php/i.test(r.path)
  );
  const sqlExecutor = results.some(r =>
    scanHit(r) && /\/phpmyadmin\/sql\.php/i.test(r.path)
  );

  const vulns = [];
  if (setupExposed) vulns.push('pma_setup_exposed');
  if (configExposed) vulns.push('pma_config_exposed');
  if (sqlExecutor) vulns.push('pma_sql_executor');

  if (version) {
    vulns.push('pma_version_disclosed');
    if (compareVersions(version, PMA_KNOWN_OLD) <= 0) {
      vulns.push('pma_old_version');
    }
    for (const v of PMA_VULN_DB) {
      if (compareVersions(version, v.maxVersion) <= 0) {
        vulns.push(v.label);
      }
    }
  }

  return {
    name: 'phpMyAdmin',
    confidence: 'high',
    version,
    vulnerabilities: vulns
  };
}

function detectIIS(results) {
  const hasWebConfig = results.some(r => r.path === '/web.config' && scanHit(r));
  const hasIisStart = results.some(r => r.path === '/iisstart.htm' && scanHit(r));
  const hasAppCode = results.some(r => r.path === '/App_Code/' && scanHit(r));
  const hasAppData = results.some(r => r.path === '/App_Data/' && scanHit(r));
  const hasBin = results.some(r => r.path === '/bin/' && scanHit(r));
  const hasGlobalAsax = results.some(r => r.path === '/global.asax' && scanHit(r));
  const isIIS = hasWebConfig || hasIisStart || hasAppCode || hasAppData || hasBin || hasGlobalAsax;
  if (!isIIS) return null;

  const vulns = [];
  if (hasWebConfig) {
    const configResult = results.find(r => r.path === '/web.config');
    if (configResult && configResult.size > 0) vulns.push('iis_webconfig_exposed');
    ['/web.config.bak', '/web.config.old', '/web.config.save', '/web.config~'].forEach(bak => {
      if (results.some(r => r.path === bak && scanHit(r))) vulns.push('iis_webconfig_backup');
    });
  }
  if (results.some(r => r.path === '/App_Offline.htm' && scanHit(r) && r.size > 0)) vulns.push('iis_app_offline');
  if (results.some(r => (r.path === '/Trace.axd' || r.path === '/trace.axd') && scanHit(r))) vulns.push('iis_trace_enabled');
  if (results.some(r => (r.path === '/elmah.axd' || r.path === '/ELMAH/elmah.axd') && scanHit(r))) vulns.push('iis_elmah_exposed');

  const dirPaths = ['/bin/', '/App_Code/', '/App_Data/', '/Scripts/', '/Content/', '/Views/'];
  for (const dir of dirPaths) {
    const result = results.find(r => r.path === dir && scanHit(r));
    if (result && result.status === 200 && result.bodySnippet) {
      const body = result.bodySnippet.toLowerCase();
      if (body.includes('[parent directory]') || body.includes('index of ') || body.includes('<title>index of') || body.includes('parent directory')) {
        vulns.push('iis_directory_listing');
        break;
      }
    }
  }

  if (hasAppCode || hasAppData) vulns.push('iis_source_exposed');
  const subConfigs = ['/Views/web.config', '/Areas/Admin/Views/web.config', '/App_Data/web.config'];
  for (const sub of subConfigs) {
    if (results.some(r => r.path === sub && scanHit(r) && r.size > 0)) vulns.push('iis_sub_webconfig');
  }
  if (results.some(r => (/^\/webdav\/?$/i.test(r.path) || /^\/dav\/?$/i.test(r.path)) && scanHit(r))) vulns.push('iis_webdav_enabled');
  if (results.some(r => /^\/aspnet_client\//.test(r.path) && scanHit(r))) vulns.push('iis_aspnet_version_disclosure');
  if (results.some(r => /^\/WebResource\.axd/.test(r.path) && scanHit(r))) vulns.push('iis_webresource_exposed');
  if (results.some(r => /^\/appsettings\.(?:json|Development\.json|Production\.json)/.test(r.path) && scanHit(r))) vulns.push('iis_appsettings_exposed');

  return { name: 'IIS', confidence: 'high', vulnerabilities: vulns };
}

function detectServerBy404(text, headers, status) {
  if (status !== 404) return null;
  const serverHeader = headers && headers['server'] ? headers['server'].toLowerCase() : '';
  const lowerText = text.toLowerCase();

  if (serverHeader.includes('nginx')) return { name: 'nginx', confidence: 'high' };
  if (serverHeader.includes('apache')) return { name: 'Apache', confidence: 'high' };
  if (serverHeader.includes('microsoft-iis')) return { name: 'IIS', confidence: 'high' };
  if (serverHeader.includes('tomcat')) return { name: 'Apache Tomcat', confidence: 'high' };
  if (serverHeader.includes('jetty')) return { name: 'Jetty', confidence: 'high' };
  if (serverHeader.includes('caddy')) return { name: 'Caddy', confidence: 'high' };
  if (serverHeader.includes('openresty')) return { name: 'OpenResty', confidence: 'high' };
  if (serverHeader.includes('werkzeug')) return { name: 'Flask (Werkzeug)', confidence: 'high' };

  if (lowerText.includes('<h1>404 not found</h1>') && lowerText.includes('nginx')) return { name: 'nginx', confidence: 'high' };
  if (lowerText.includes('<h1>not found</h1>') && lowerText.includes('the requested url was not found on this server.')) return { name: 'Apache', confidence: 'high' };
  if (lowerText.includes('server error</h1>') && lowerText.includes('404 - file or directory not found.')) return { name: 'IIS', confidence: 'high' };
  if (lowerText.includes('<h1>not found</h1>') && lowerText.includes('the requested url was not found on the server.') && !lowerText.includes('on this server')) return { name: 'Flask (Werkzeug)', confidence: 'high' };
  if (lowerText.includes('<h1>not found</h1>') && lowerText.includes('the requested resource was not found on this server.')) return { name: 'Django', confidence: 'high' };
  if (lowerText.includes('<h1>404</h1>') && lowerText.includes('not found') && lowerText.includes('laravel')) return { name: 'Laravel', confidence: 'high' };
  if (lowerText.includes('oops! an error occurred') && lowerText.includes('the server returned a "404 not found".')) return { name: 'Symfony', confidence: 'high' };
  if (lowerText.includes('cannot get /') && lowerText.includes('error')) return { name: 'Express.js', confidence: 'high' };
  if (lowerText.includes('<h1>404</h1>') && lowerText.includes('this page could not be found.')) return { name: 'Next.js', confidence: 'high' };
  if (lowerText.includes('whitelabel error page') && lowerText.includes('this application has no explicit mapping for /error')) return { name: 'Spring Boot', confidence: 'high' };
  if (lowerText.includes('http status 404 – not found') && lowerText.includes('the origin server did not find a current representation')) return { name: 'Apache Tomcat', confidence: 'high' };
  if (lowerText.includes('error 404 - not found') && lowerText.includes('powered by eclipse jetty')) return { name: 'Jetty', confidence: 'high' };
  if (lowerText.includes('the page you were looking for doesn\'t exist.')) return { name: 'Ruby on Rails', confidence: 'high' };
  if (lowerText.includes('sinatra doesn\'t know this ditty.')) return { name: 'Sinatra', confidence: 'high' };
  if (lowerText.includes('server error in \'/\' application.') && lowerText.includes('the resource cannot be found.')) return { name: 'ASP.NET', confidence: 'high' };
  if (serverHeader) {
    const parts = serverHeader.split('/');
    return { name: parts[0].trim(), confidence: 'low' };
  }
  return null;
}

function analyzeAll(results, serverInfo = null) {
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
  const solr = detectSolr(results);
  if (solr) tech.push(solr);
  const druid = detectDruid(results);
  if (druid) tech.push(druid);
  const geoserver = detectGeoServer(results);
  if (geoserver) tech.push(geoserver);
  const dockerReg = detectDockerRegistry(results);
  if (dockerReg) tech.push(dockerReg);
  const jenkins = detectJenkins(results);
  if (jenkins) tech.push(jenkins);
  const phpMyAdmin = detectPhpMyAdmin(results);
  if (phpMyAdmin) {
    tech.push({ name: phpMyAdmin.name, confidence: phpMyAdmin.confidence, version: phpMyAdmin.version });
  }
  const iis = detectIIS(results);
  if (iis) tech.push({ name: iis.name, confidence: iis.confidence });
  if (serverInfo) tech.push({ name: serverInfo.name, confidence: serverInfo.confidence });

  const vulns = [];
  if (phpMyAdmin && phpMyAdmin.vulnerabilities) {
    phpMyAdmin.vulnerabilities.forEach(v => vulns.push(v));
  }
  if (iis && iis.vulnerabilities) {
    iis.vulnerabilities.forEach(v => vulns.push(v));
  }
  if (results.some(r => r.path.startsWith('/.git/') && scanHit(r))) vulns.push('exposed_git');
  if (results.some(r => r.path === '/.env' && scanHit(r))) vulns.push('env_exposed');
  if (results.some(r => r.debugMode)) vulns.push('debug_mode');
  // New vulnerability checks
  if (results.some(r => r.path === '/phpinfo.php' && scanHit(r))) vulns.push('phpinfo_exposed');
  if (results.some(r => ['/status', '/server-status'].includes(r.path) && scanHit(r))) vulns.push('status_exposed');
  if (results.some(r => ['/swagger-ui.html', '/api-docs', '/api.json'].includes(r.path) && scanHit(r))) vulns.push('swagger_exposed');
  if (results.some(r => r.path.startsWith('/actuator/') && scanHit(r))) vulns.push('actuator_exposed');
  if (results.some(r => r.path === '/console' && scanHit(r))) vulns.push('h2_console_exposed');
  // Infrastructure vulnerability checks
  if (results.some(r => r.path.includes('eval-stdin.php') && scanHit(r))) vulns.push('phpunit_rce');
  if (results.some(r => r.path.includes('/solr/admin/') && scanHit(r))) vulns.push('solr_exposed');
  if (results.some(r => r.path.includes('/v2/_catalog') && scanHit(r))) vulns.push('docker_registry_api');
  if (results.some(r => r.path.includes('/druid/index.html') && scanHit(r))) vulns.push('druid_exposed');
  if (results.some(r => r.path.includes('/geoserver/web/') && scanHit(r))) vulns.push('geoserver_exposed');
  if (results.some(r => ['/hudson', '/jenkins', '/jenkins/login'].includes(r.path) && scanHit(r))) vulns.push('jenkins_exposed');
  if (results.some(r => r.path === '/query' && scanHit(r))) vulns.push('db_diagnostics');
  if (phpMyAdmin) vulns.push('phpmyadmin_exposed');
  if (results.some(r => '/pgadmin/' === r.path && scanHit(r))) vulns.push('pgadmin_exposed');
  if (results.some(r => '/adminer.php' === r.path && scanHit(r))) vulns.push('adminer_exposed');
  // Router/IoT vulnerability checks
  if (results.some(r => r.path === '/HNAP1' && scanHit(r))) vulns.push('router_hnap');
  if (results.some(r => ['/evox/about'].includes(r.path) && scanHit(r))) vulns.push('router_evox');
  if (results.some(r => r.path.includes('/cgi-bin/authLogin.cgi') && scanHit(r))) vulns.push('cgi_exposed');
  // Secrets & credentials
  if (results.some(r => ['/secrets.json', '/credentials.json', '/cdp_api_key.json', '/secrets.yml', '/secrets.yaml'].includes(r.path) && scanHit(r))) vulns.push('secrets_exposed');
  // Subdirectory .env exposure
  const envSubdirs = ['/app/.env', '/src/.env', '/config/.env', '/backend/.env', '/api/.env', '/laravel/.env', '/magento/.env'];
  if (results.some(r => envSubdirs.includes(r.path) && scanHit(r))) vulns.push('env_in_subdir');
  // Source code exposure (non-minified JS bundles)
  const sourceFiles = ['/app.js', '/main.js', '/bundle.js', '/server.js', '/index.js', '/config.js'];
  if (results.some(r => sourceFiles.includes(r.path) && scanHit(r) && r.size > 10000)) vulns.push('source_code_exposed');
  // Open proxy / CONNECT tunnel
  if (results.some(r => r.proxyCheck === true || r.path.includes('CONNECT'))) vulns.push('open_proxy');

  // Django debug data exposure
  if (results.some(r => r.debugData && r.debugData.length > 0)) vulns.push('django_debug_data_exposed');

  // Secrets in response body
  const secretsInResponse = results.filter(r => r.secrets && r.secrets.length > 0);
  if (secretsInResponse.length > 0) {
    const hasCritical = secretsInResponse.some(r => r.secrets.some(s => s.severity === 'critical'));
    const hasHigh = secretsInResponse.some(r => r.secrets.some(s => s.severity === 'high'));
    vulns.push(hasCritical ? 'secrets_exposed' : hasHigh ? 'secrets_exposed' : 'secrets_exposed');
  }

  // WordPress-specific vulnerabilities
  if (results.some(r => r.path === '/xmlrpc.php' && scanHit(r))) vulns.push('wp_xmlrpc_enabled');
  if (results.some(r => r.path === '/wp-config.php' && scanHit(r))) vulns.push('wp_config_exposed');
  if (results.some(r => r.path === '/wp-content/debug.log' && scanHit(r) && r.size > 0)) vulns.push('wp_debug_log');
  if (results.some(r => r.path === '/wp-admin/install.php' && scanHit(r))) vulns.push('wp_install_accessible');
  if (results.some(r => r.path === '/wp-json/wp/v2/users' && scanHit(r))) vulns.push('wp_rest_users');
  if (results.some(r => r.path === '/readme.html' && scanHit(r))) vulns.push('wp_readme_exposed');
  if (results.some(r => r.path === '/license.txt' && scanHit(r))) vulns.push('wp_license_exposed');
  if (results.some(r => r.path === '/wp-json/' && scanHit(r))) vulns.push('wp_rest_api_exposed');

  return { detectedTech: tech, vulnerabilities: vulns };
}
