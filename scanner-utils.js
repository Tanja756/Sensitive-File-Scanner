// Shared utilities: wordlist parsing, categories, severity, signatures, baseline

const DEFAULT_PATHS = [
  "/.env", "/.env.local", "/.env.production", "/.env.bak", "/.env.swp",
  "/.git/config", "/.git/HEAD", "/.gitignore", "/backup.sql", "/dump.sql",
  "/.htpasswd", "/.htaccess", "/wp-config.php", "/phpinfo.php", "/info.php", "/admin/",
  "/.vscode/sftp.json", "/.idea/workspace.xml", "/debug.log", "/error.log",
  "/credentials", "/credentials.json", "/secrets.json",
  "/wwwroot.zip", "/robots.txt", "/.DS_Store", "/Thumbs.db",
  "/node_modules/", "/vendor/", "/composer.json", "/package.json", "/Dockerfile",
  "/docker-compose.yml", "/Jenkinsfile", "/.travis.yml", "/.circleci/config.yml",
  "/app.js", "/main.js", "/bundle.js", "/config.js", "/config.json",
  "/v2/_catalog", "/solr/admin/info/system", "/druid/index.html",
  "/geoserver/web/", "/hudson", "/actuator/", "/actuator/health",
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
  "/HNAP1", "/cgi-bin/authLogin.cgi",
  "/query?q=SHOW+DIAGNOSTICS", "/phpmyadmin/"
];

const SECTION_CAT_RULES = [
  [/GIT|SVN|Mercurial|Bazaar|CVS|Fossil/i, 'git'],
  [/DOCKER/i, 'docker'],
  [/CI\/CD/i, 'cicd'],
  [/Облака|инфраструктур|ENV-файл/i, 'cloud'],
  [/CMS|phpMyAdmin|phpmyadmin|Битрикс|WordPress|Typo3|Joomla|Drupal|Magento|Laravel/i, 'cms'],
  [/Резервн|дамп|backup|архив/i, 'backup'],
  [/Лог|log/i, 'logs'],
  [/IDE|редактор|vscode|idea/i, 'ide'],
  [/Административ|веб-шелл|phpinfo|Actuator|Swagger|Spring|отладк/i, 'cms'],
  [/Node|npm|composer|vendor/i, 'cms']
];

const VULN_LABELS = {
  exposed_git: { label: 'Открытый Git-репозиторий', severity: 'critical' },
  env_exposed: { label: 'Файл .env доступен', severity: 'critical' },
  debug_mode: { label: 'Режим отладки (DEBUG)', severity: 'critical' },
  phpinfo_exposed: { label: 'phpinfo() раскрыт', severity: 'high' },
  status_exposed: { label: 'Status-страница сервера', severity: 'high' },
  swagger_exposed: { label: 'Swagger/OpenAPI раскрыт', severity: 'high' },
  actuator_exposed: { label: 'Spring Boot Actuator', severity: 'high' },
  h2_console_exposed: { label: 'H2 Console', severity: 'critical' },
  phpunit_rce: { label: 'PHPUnit RCE (eval-stdin.php)', severity: 'critical' },
  solr_exposed: { label: 'Apache Solr административная панель', severity: 'critical' },
  docker_registry_api: { label: 'Docker Registry API открыт', severity: 'critical' },
  druid_exposed: { label: 'Apache Druid UI доступен', severity: 'high' },
  geoserver_exposed: { label: 'GeoServer web-панель доступна', severity: 'high' },
  jenkins_exposed: { label: 'Jenkins/Hudson панель доступна', severity: 'high' },
  router_hnap: { label: 'HNAP1 интерфейс роутера', severity: 'high' },
  router_evox: { label: 'eVoX/about интерфейс', severity: 'high' },
  cgi_exposed: { label: 'CGIBin/админка', severity: 'high' },
  db_diagnostics: { label: 'Диагностика БД (SHOW DIAGNOSTICS)', severity: 'high' },
  phpmyadmin_exposed: { label: 'phpMyAdmin доступен', severity: 'high' },
  pgadmin_exposed: { label: 'pgAdmin доступен', severity: 'high' },
  adminer_exposed: { label: 'Adminer.php доступен', severity: 'high' },
  secrets_exposed: { label: 'Файл секретов (secrets/credentials)', severity: 'critical' },
  env_in_subdir: { label: '.env в подкаталоге', severity: 'high' },
  source_code_exposed: { label: 'Исходный код JS (бандл) раскрыт', severity: 'medium' },
  open_proxy: { label: 'Открытый прокси/CONNECT туннель', severity: 'critical' },
  // WordPress-specific
  wp_xmlrpc_enabled: { label: 'XML-RPC (xmlrpc.php) включён', severity: 'high' },
  wp_config_exposed: { label: 'wp-config.php доступен (критично!)', severity: 'critical' },
  wp_debug_log: { label: 'WP debug.log содержит данные', severity: 'high' },
  wp_install_accessible: { label: 'WP установщик (install.php) доступен', severity: 'high' },
  wp_rest_users: { label: 'REST API раскрывает список пользователей', severity: 'high' },
  wp_readme_exposed: { label: 'readme.html раскрывает версию WP', severity: 'low' },
  wp_license_exposed: { label: 'license.txt раскрывает информацию', severity: 'low' },
  wp_rest_api_exposed: { label: 'WordPress REST API доступен', severity: 'medium' },
  // phpMyAdmin
  pma_version_disclosed: { label: 'Версия phpMyAdmin раскрыта', severity: 'medium' },
  pma_setup_exposed: { label: 'phpMyAdmin установщик (setup/) доступен', severity: 'critical' },
  pma_config_exposed: { label: 'config.inc.php phpMyAdmin доступен (критично!)', severity: 'critical' },
  pma_sql_executor: { label: 'phpMyAdmin SQL-исполнитель (sql.php) доступен', severity: 'high' },
  pma_old_version: { label: 'Установлена устаревшая версия phpMyAdmin', severity: 'high' },
  pma_vuln_cve_2018_12613: { label: 'CVE-2018-12613: phpMyAdmin < 4.8.2 File Inclusion / RCE', severity: 'critical' },
  pma_vuln_cve_2018_19968: { label: 'CVE-2018-19968: phpMyAdmin < 4.9.0 SQL Injection', severity: 'critical' },
  pma_vuln_cve_2020_26935: { label: 'CVE-2020-26935: phpMyAdmin < 5.0.4 XSS', severity: 'high' },
  pma_vuln_cve_2021_21311: { label: 'CVE-2021-21311: phpMyAdmin < 5.1.0 Directory Traversal / RCE', severity: 'critical' },
  pma_vuln_cve_2021_39277: { label: 'CVE-2021-39277: phpMyAdmin < 5.1.2 XSS', severity: 'high' },
  pma_vuln_cve_2022_23804: { label: 'CVE-2022-23804: phpMyAdmin < 5.2.0 XSS via Twig', severity: 'high' },
  pma_vuln_cve_2023_25776: { label: 'CVE-2023-25776: phpMyAdmin < 5.2.1 SQL Injection', severity: 'critical' },
  pma_vuln_cve_2023_24810: { label: 'CVE-2023-24810: phpMyAdmin < 5.2.2 XSS via drag-and-drop', severity: 'high' },
  django_debug_data_exposed: { label: 'Режим отладки Django — раскрыты ключи/пароли', severity: 'critical' },
  // IIS-specific
  iis_webconfig_exposed: { label: 'web.config доступен (содержит ключи/строки подключения)', severity: 'critical' },
  iis_webconfig_backup: { label: 'Бэкап web.config доступен', severity: 'critical' },
  iis_app_offline: { label: 'App_Offline.htm доступен (индикация временного отключения)', severity: 'low' },
  iis_trace_enabled: { label: 'ASP.NET Tracing (Trace.axd) включён', severity: 'high' },
  iis_elmah_exposed: { label: 'ELMAH (elmah.axd) доступен — утечка ошибок', severity: 'high' },
  iis_directory_listing: { label: 'Листинг директорий включён (риск перечисления файлов)', severity: 'high' },
  iis_source_exposed: { label: 'Исходный код (App_Code/App_Data) доступен', severity: 'critical' },
  iis_sub_webconfig: { label: 'web.config в подкаталоге доступен', severity: 'high' },
  iis_webdav_enabled: { label: 'WebDAV включён (риск загрузки/изменения файлов)', severity: 'high' },
  iis_aspnet_version_disclosure: { label: 'Раскрыта версия ASP.NET через aspnet_client', severity: 'medium' },
  iis_webresource_exposed: { label: 'WebResource.axd доступен (может раскрыть сборки)', severity: 'medium' },
  iis_appsettings_exposed: { label: 'appsettings.json доступен (секреты .NET Core)', severity: 'critical' }
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function categoryFromSectionComment(line) {
  for (const [re, cat] of SECTION_CAT_RULES) {
    if (re.test(line)) return cat;
  }
  return null;
}

function inferCategory(path) {
  const p = path.toLowerCase();
  if (p.includes('.git') || p.includes('.svn') || p.includes('.hg') || p.includes('/cvs')) return 'git';
  if (p.includes('docker') || p === '/dockerfile' || p.endsWith('dockerfile')) return 'docker';
  if (p.includes('jenkins') || p.includes('hudson') || p.includes('gitlab-ci') || p.includes('travis') || p.includes('circleci') || p.includes('drone') || p.includes('pipelines')) return 'cicd';
  if (p.includes('.aws') || p.includes('.kube') || p.includes('terraform') || p.includes('.env') || p.includes('credentials') || p.includes('gcp') || p.includes('.azure')) return 'cloud';
  if (p.includes('wp-') || p.includes('bitrix') || p.includes('typo3') || p.includes('joomla') || p.includes('drupal') || p.includes('magento') || p.includes('phpinfo') || p.includes('/admin') || p.includes('phpmyadmin')) return 'cms';
  if (p.includes('backup') || p.includes('dump') || p.includes('.sql') || p.includes('.zip') || p.includes('.tar') || p.includes('.gz') || p.includes('wwwroot')) return 'backup';
  if (p.includes('.log') || p.includes('debug')) return 'logs';
  if (p.includes('.vscode') || p.includes('.idea') || p.includes('sftp.json')) return 'ide';
  if (p.includes('/druid') || p.includes('/solr') || p.includes('/geoserver') || p.includes('/v2/_catalog') || p.includes('/actuator')) return 'cloud';
  if (p.includes('/hnap') || p.includes('/cgi-bin') || p.includes('/evox')) return 'cms';
  if (p.includes('/hudson') || p.includes('/jenkins')) return 'cicd';
  if (p.endsWith('.js') && !p.includes('favicon')) return 'cloud';
  if (p.includes('/phpunit') || p.includes('/eval-stdin')) return 'cms';
  return 'cloud';
}

function parseWordlistText(text) {
  let currentCat = null;
  const entries = [];
  const seen = new Set();
  for (const rawLine of text.split('\n')) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('/*')) {
      const cat = categoryFromSectionComment(trimmed);
      if (cat) currentCat = cat;
      continue;
    }
    const path = trimmed.split(/\s+/)[0];
    if (!path.startsWith('/')) continue;
    if (seen.has(path)) continue;
    seen.add(path);
    const category = currentCat || inferCategory(path);
    entries.push({ path, category });
  }
  return entries;
}

function filterByCategories(entries, categories) {
  if (!categories || categories.length === 0) return entries;
  return entries.filter(e => categories.includes(e.category));
}

function getPathSeverity(path) {
  const p = path.toLowerCase();
  const critical = [
    '.env', '.htpasswd', 'wp-config', 'dbconn.php', '.settings.php',
    'terraform.tfstate', '.aws/credentials', '.kube/config', 'credentials',
    'service-account.json', 'gcp-credentials', '/.git/config', 'license_key.php',
    'parameters.yml', 'secrets.yml', 'shell.php', 'c99.php', 'r57.php', 'b374k',
    '/console', 'actuator/env', 'actuator/heapdump',
    'secrets.json', 'secrets.yml', 'secrets.yaml', 'cdp_api_key',
    'eval-stdin.php', 'v2/_catalog', 'solr/admin',
    'druid/index.html', 'geoserver/web/', 'hnap1',
    'cgi-bin/authlogin.cgi', 'shoW+diagnostics',
    'connect', 'proxy tunnel', 'open_proxy',
    'config.inc.php', 'phpmyadmin/setup/index.php', '/phpmyadmin/config.inc'
  ];
  const high = [
    '.git/', 'phpinfo', 'backup.sql', 'dump.sql', 'db.sql', 'wwwroot.zip',
    'swagger', 'api-docs', 'server-status', '/admin/', 'web.config',
    'localconfiguration.php', 'sftp.json', 'phpmyadmin', 'pgadmin',
    'hudson', 'jenkins', '/actuator', 'geoserver', 'druid/',
    'cgi-bin/authlogin.cgi', 'evox/about', 'webui/'
  ];
  if (critical.some(k => p.includes(k))) return 'critical';
  if (high.some(k => p.includes(k))) return 'high';
  if (p.includes('.log') || p.includes('debug')) return 'medium';
  if (p.includes('robots.txt') || p.includes('package.json') || p.includes('composer.json')) return 'low';
  if (p.endsWith('.js') && !p.includes('favicon')) return 'medium';
  return 'medium';
}

function simpleFingerprint(text) {
  if (!text) return '0:0';
  const sample = text.slice(0, 512);
  let hash = 0;
  for (let i = 0; i < sample.length; i++) {
    hash = ((hash << 5) - hash) + sample.charCodeAt(i);
    hash |= 0;
  }
  return `${text.length}:${hash}`;
}

const PATH_SIGNATURES = [
  { test: p => p.includes('.env') && !p.includes('.example'), patterns: [/^[A-Za-z_][A-Za-z0-9_]*\s*=/m] },
  { test: p => p.endsWith('/.git/config') || p === '/.git/config', patterns: [/\[core\]/i, /\[remote/i] },
  { test: p => p.endsWith('/.git/HEAD') || p === '/.git/HEAD', patterns: [/^ref:/m] },
  { test: p => p.includes('phpinfo'), patterns: [/phpinfo\s*\(/i, /PHP Version/i] },
  { test: p => p.includes('wp-config'), patterns: [/DB_NAME/i, /define\s*\(/i] },
  { test: p => p.includes('.htpasswd'), patterns: [/:\$apr1\$/, /:\$2[aby]\$/] },
  { test: p => p.includes('swagger') || p.includes('api-docs'), patterns: [/swagger/i, /"openapi"/i, /"paths"\s*:/] },
  { test: p => p.includes('actuator'), patterns: [/status|health|beans|env/i] },
  { test: p => p.includes('eval-stdin'), patterns: [/php/i, /passthru|exec|shell_exec|system/i] },
  { test: p => p.includes('solr/admin'), patterns: [/solr/i, /admin/i, /lucene/i] },
  { test: p => p.includes('druid/index'), patterns: [/druid/i, /apache druid/i] },
  { test: p => p.includes('v2/_catalog'), patterns: [/repositories/i, /"name"/i] },
  { test: p => p.includes('geoserver'), patterns: [/geoserver/i, /GeoServer/i] },
  { test: p => p.includes('/secrets.json') || p.includes('/credentials.json'), patterns: [/"[A-Za-z_]+"\s*:/m] },
  { test: p => p.endsWith('.js') && !p.includes('.min.'), patterns: [/require\(|import |export |module\.exports|from\s+['"]/i] },
  { test: p => /\/phpmyadmin\/?$/i.test(p) || /\/phpmyadmin\/index\.php/i.test(p), patterns: [/phpMyAdmin/i, /MySQL/i] },
  { test: p => /\/phpmyadmin\/README/i.test(p), patterns: [/phpMyAdmin/i, /Version\s+\d+\.\d+\.\d+/i] },
  { test: p => /\/phpmyadmin\/config\.inc\.php/i.test(p), patterns: [/\$cfg\[/i, /\$dbserver/i, /allowdeny/i] },
  { test: p => p.includes('.log') || p.includes('django'), patterns: [/DEBUG\s*=\s*True|Traceback|SECRET_KEY|DJANGO_SETTINGS_MODULE/i] }
];

// Paths that may contain version info — body snippet captured for analysis
const BODY_CAPTURE_PATHS = [
  '/phpmyadmin/README', '/phpMyAdmin/README', '/pma/README',
  '/phpmyadmin/ChangeLog', '/phpMyAdmin/ChangeLog', '/pma/ChangeLog',
  '/phpmyadmin/changelog.php', '/phpMyAdmin/changelog.php', '/pma/changelog.php',
  '/phpmyadmin/Documentation.html', '/phpMyAdmin/Documentation.html', '/pma/Documentation.html',
  '/phpmyadmin/robots.txt', '/phpMyAdmin/robots.txt', '/pma/robots.txt',
  '/phpmyadmin/js/version.js', '/phpMyAdmin/js/version.js', '/pma/js/version.js',
  '/debug.log', '/error.log', '/django.log', '/django_debug.log',
  '/settings/', '/env/', '/__debug__/',
];

function needsBodyCapture(path) {
  return BODY_CAPTURE_PATHS.includes(path);
}

function requiresBodyVerification(path) {
  return PATH_SIGNATURES.some(s => s.test(path));
}

function matchesSignature(path, text) {
  const rules = PATH_SIGNATURES.filter(s => s.test(path));
  if (rules.length === 0) return true;
  return rules.some(r => r.patterns.some(re => re.test(text)));
}

function checkForDjangoDebug(text) {
  if (!text) return false;
  const markers = [
    'DEBUG = True', 'DJANGO_SETTINGS_MODULE',
    "You're seeing this error because you have DEBUG = True",
    'Traceback (most recent call last)', 'Request URL:', 'Django version:'
  ];
  return markers.some(m => text.includes(m));
}

const DJANGO_SECRET_PATTERNS = [
  { key: 'SECRET_KEY', pattern: /SECRET_KEY[:\s]*['"]([^'"]+)['"]/ },
  { key: 'DATABASE_URL', pattern: /DATABASE_URL[:\s]*['"]([^'"]+)['"]/ },
  { key: 'DB_NAME', pattern: /(?:['"]NAME['"]|DB_NAME)[:\s]*['"]([^'"]+)['"]/ },
  { key: 'DB_USER', pattern: /(?:['"]USER['"]|DB_USER)[:\s]*['"]([^'"]+)['"]/ },
  { key: 'DB_PASSWORD', pattern: /(?:['"]PASSWORD['"]|DB_PASSWORD)[:\s]*['"]([^'"]+)['"]/ },
  { key: 'DB_HOST', pattern: /(?:['"]HOST['"]|DB_HOST)[:\s]*['"]([^'"]+)['"]/ },
  { key: 'DB_PORT', pattern: /(?:['"]PORT['"]|DB_PORT)[:\s]*['"]([^'"]+)['"]/ },
  { key: 'EMAIL_HOST', pattern: /EMAIL_HOST[:\s]*['"]([^'"]+)['"]/ },
  { key: 'EMAIL_PORT', pattern: /EMAIL_PORT[:\s]*['"]([^'"]+)['"]/ },
  { key: 'EMAIL_HOST_USER', pattern: /EMAIL_HOST_USER[:\s]*['"]([^'"]+)['"]/ },
  { key: 'EMAIL_HOST_PASSWORD', pattern: /EMAIL_HOST_PASSWORD[:\s]*['"]([^'"]+)['"]/ },
  { key: 'AWS_ACCESS_KEY_ID', pattern: /AWS_ACCESS_KEY_ID[:\s]*['"]([^'"]+)['"]/ },
  { key: 'AWS_SECRET_ACCESS_KEY', pattern: /AWS_SECRET_ACCESS_KEY[:\s]*['"]([^'"]+)['"]/ },
  { key: 'AWS_STORAGE_BUCKET_NAME', pattern: /AWS_STORAGE_BUCKET_NAME[:\s]*['"]([^'"]+)['"]/ },
  { key: 'ALLOWED_HOSTS', pattern: /ALLOWED_HOSTS[:\s]*\[([^\]]+)\]/ },
  { key: 'ADMIN_URL', pattern: /ADMIN_URL[:\s]*['"]([^'"]+)['"]/ },
  { key: 'CACHE_HOST', pattern: /CACHE_HOST[:\s]*['"]([^'"]+)['"]/ },
  { key: 'REDIS_URL', pattern: /REDIS_URL[:\s]*['"]([^'"]+)['"]/ },
  { key: 'CELERY_BROKER_URL', pattern: /CELERY_BROKER_URL[:\s]*['"]([^'"]+)['"]/ },
  { key: 'SENTRY_DSN', pattern: /SENTRY_DSN[:\s]*['"]([^'"]+)['"]/ },
  { key: 'SOCIAL_AUTH_*', pattern: /SOCIAL_AUTH_[A-Z_]+[:\s]*['"]([^'"]+)['"]/ },
  { key: 'ADMINS', pattern: /ADMINS?\s*[:\s]*['"]([^'"]+)['"]/ },
  { key: 'SENDGRID_API_KEY', pattern: /SENDGRID_API_KEY[:\s]*['"]([^'"]+)['"]/ },
  { key: 'STRIPE_API_KEY', pattern: /STRIPE(?:_LIVE|_TEST|_SECRET|_PUBLISHABLE|_API)?_KEY[:\s]*['"]([^'"]+)['"]/ },
  { key: 'RECAPTCHA_SECRET', pattern: /(?:RECAPTCHA|NOCAPTCHA)_?(?:SECRET|SITE|PRIVATE)?_?KEY[:\s]*['"]([^'"]+)['"]/ },
  { key: 'JWT_SECRET', pattern: /(?:JWT|JWS)_?(?:SECRET|SIGNING|VERIFICATION)_?(?:KEY)?[:\s]*['"]([^'"]+)['"]/ },
  { key: 'OAUTH_TOKEN', pattern: /(?:SOCIAL_AUTH|OAUTH|OAUTH2)_?(?:[A-Z_]*_)?(?:TOKEN|SECRET|KEY)[:\s]*['"]([^'"]+)['"]/ },
  { key: 'CACHE_PASSWORD', pattern: /CACHE_PASSWORD[:\s]*['"]([^'"]+)['"]/ },
  { key: 'REDIS_PASSWORD', pattern: /REDIS(?:TOWER|_)?PASSWORD[:\s]*['"]([^'"]+)['"]/ },
  { key: 'HASHIDS_SALT', pattern: /HASHIDS_SALT[:\s]*['"]([^'"]+)['"]/ },
];

function extractDjangoDebugData(text) {
  if (!text) return [];
  const findings = [];
  const seen = new Set();

  // Extract setting→value pairs from HTML debug table first
  // <th>KEY</th><td class="code"><pre>'value'</pre></td>
  const htmlTableRE = /<th>([A-Z][A-Z0-9_]+)<\/th><td[^>]*><pre>\s*['"]?([^<]+?)['"]?\s*<\/pre><\/td>/gi;
  const htmlPairs = [];
  let hm;
  while ((hm = htmlTableRE.exec(text)) !== null) {
    htmlPairs.push({ key: hm[1], value: hm[2].trim() });
  }

  // Check named patterns against both plain text AND html pairs
  for (const { key, pattern } of DJANGO_SECRET_PATTERNS) {
    // Try plain-text match
    const match = text.match(pattern);
    if (match && match[1]) {
      const val = match[1].trim();
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({ key, value: val });
      }
    } else {
      // Try HTML table context
      const htmlMatch = htmlPairs.find(p => p.key === key);
      if (htmlMatch && !seen.has(key)) {
        seen.add(key);
        findings.push({ key, value: htmlMatch.value });
      }
    }
  }

  const broadPattern = /['"]([A-Z][A-Z0-9_]*(?:KEY|SECRET|PASSWORD|TOKEN|ACCESS|SALT|LOGIN|DSN))['"][:\s]*['"]([^'"]{4,})['"]/gi;
  let m;
  while ((m = broadPattern.exec(text)) !== null) {
    if (!seen.has(m[1])) {
      seen.add(m[1]);
      findings.push({ key: m[1], value: m[2] });
    }
  }

  const broadEnvPattern = /^([A-Z][A-Z0-9_]*(?:KEY|SECRET|PASSWORD|TOKEN|ACCESS|SALT|LOGIN))\s*=\s*(.+)$/gm;
  while ((m = broadEnvPattern.exec(text)) !== null) {
    if (!seen.has(m[1])) {
      seen.add(m[1]);
      findings.push({ key: m[1], value: m[2].trim() });
    }
  }

  // Catch‑all: any HTML table row with credential‑looking name not yet found
  for (const p of htmlPairs) {
    if (!seen.has(p.key) && /(?:KEY|SECRET|TOKEN|PASSWORD|SALT|DSN|ACCESS)/i.test(p.key) && p.value.length > 3) {
      seen.add(p.key);
      findings.push(p);
    }
  }

  return findings;
}

const CATCH_ALL_PATTERNS = [
  /404 Not Found/i,
  /Page Not Found/i,
  /Page not found/i,
  /Not Found/i,
  /Access Denied/i,
  /Access denied/i,
  /Something went wrong/i,
  /Oops/i,
  /nginx/i,
  /Apache.*is functioning normally/i,
  /Страница не найдена/i,
  /Не найдено/i,
  /Доступ запрещён/i,
  /Доступ запрещен/i,
  /Ничего не найдено/i
];

function is_catch_all_page(text) {
  if (!text) return false;
  let matches = 0;
  for (const re of CATCH_ALL_PATTERNS) {
    if (re.test(text)) matches++;
  }
  return matches >= 2;
}

function deduplicate_by_fingerprint(results) {
  const seen = new Map();
  for (const r of results) {
    if (r.status !== 200 && r.status !== 403) continue;
    if (r.signatureOk) continue; // verified real finding
    if (!r.fingerprint || r.fingerprint === '0:0') continue;
    if (seen.has(r.fingerprint)) {
      seen.get(r.fingerprint).push(r);
    } else {
      seen.set(r.fingerprint, [r]);
    }
  }
  let deduped = 0;
  for (const [, group] of seen) {
    if (group.length >= 2) {
      for (const r of group) {
        if (!r.catchAllDup) {
          r.catchAllDup = true;
          r.interesting = false;
          deduped++;
        }
      }
    }
  }
  return deduped;
}

function isSoft404(result, baseline) {
  if (!baseline || baseline.error || result.status === 404) return result.status === 404;
  if (result.status !== 200 && result.status !== 403) return false;
  if (result.fingerprint && baseline.fingerprint) {
    if (result.fingerprint === baseline.fingerprint) return true;
    if (baseline.fingerprints && baseline.fingerprints.some(fp => fp === result.fingerprint)) return true;
  }
  return false;
}

const SECRET_RULES = [
  { id: 'sift-key', name: 'Sift_Key', patterns: [/\.with(?:AccountId|BeaconKey)\(["'].*["']\)/], severity: 'medium' },
  { id: 'sentry-dsn', name: 'Sentry_DSN', patterns: [/https?:\/\/(\w+)(:\w+)?@sentry\.io\/[0-9]+/], severity: 'medium' },
  { id: 'intercom-api-key', name: 'Intercom_API_Key', patterns: [/Intercom\.initialize\(["']?\w+["']?,\s?["']?\w+["']?,\s?["']?\w+["']?\)/], severity: 'medium' },
  { id: 'singular-config', name: 'Singular_Config', patterns: [/SingularConfig\(["']?[\w._]+["']?,\s?["']?[\w._]+["']?\)/], severity: 'low' },
  { id: 'adjust-config', name: 'Adjust_Config', patterns: [/AdjustConfig\(["']?[\w]+["']?,\s?["']?[\w]+["']?(,\s?["']?[\w]+["']?)?\)/, /([aA]djust)?[Cc]onfig\.setAppSecret\(.*\)/], severity: 'medium' },
  { id: 'bitmovin-api-key', name: 'Bitmovin_API_Key', patterns: [/BITMOVIN_API_KEY\s?=\s?["']?.*["']?/], severity: 'high' },
  { id: 'salesforce-mc-token', name: 'Salesforce_MC_Token', patterns: [/setAccessToken\(\w+\.MC_ACCESS_TOKEN\)/], severity: 'high' },
  { id: 'appdynamics-key', name: 'AppDynamics_Key', patterns: [/AgentConfiguration\.builder\(\)(\s*)?([.\w()\s]+)\.withAppKey\(.*?\)/], severity: 'medium' },
  { id: 'appcenter-secret', name: 'AppCenter_Secret', patterns: [/AppCenter\.(configure|start)\(.*\)/], severity: 'medium' },
  { id: 'aws-access-key-id', name: 'AWS_Access_Key_ID', patterns: [/([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}/], severity: 'critical' },
  { id: 'aws-s3-bucket', name: 'S3_Bucket', patterns: [/\/\/s3-[a-z0-9-]+\.amazonaws\.com\/[a-z0-9._-]+/, /\/\/s3\.amazonaws\.com\/[a-z0-9._-]+/, /[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com/, /[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)/, /[a-z0-9.-]+\.s3\.amazonaws\.com/, /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/], severity: 'medium' },
  { id: 'artifactory-api-token', name: 'Artifactory_API_Token', patterns: [/(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}/], severity: 'high' },
  { id: 'artifactory-password', name: 'Artifactory_Password', patterns: [/(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}/], severity: 'high' },
  { id: 'auth-basic', name: 'Authorization_Basic', patterns: [/basic\s[a-zA-Z0-9_\-:.=]+/i], severity: 'high' },
  { id: 'auth-bearer', name: 'Authorization_Bearer', patterns: [/bearer\s[a-zA-Z0-9_\-:.=]+/i], severity: 'high' },
  { id: 'aws-api-key', name: 'AWS_API_Key', patterns: [/AKIA[0-9A-Z]{16}/], severity: 'critical' },
  { id: 'basic-auth-creds', name: 'Basic_Auth_Credentials', patterns: [/:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+/], severity: 'high' },
  { id: 'cloudinary-basic-auth', name: 'Cloudinary_Basic_Auth', patterns: [/cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+/], severity: 'high' },
  { id: 'dynatrace-token', name: 'Dynatrace_Token', patterns: [/dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}/], severity: 'high' },
  { id: 'discord-bot-token', name: 'Discord_BOT_Token', patterns: [/((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})/], severity: 'high' },
  { id: 'facebook-access-token', name: 'Facebook_Access_Token', patterns: [/EAACEdEose0cBA[0-9A-Za-z]+/], severity: 'high' },
  { id: 'facebook-client-id', name: 'Facebook_ClientID', patterns: [/[fF][aA][cC][eE][bB][oO][oO][kK](.{0,20})?["'][0-9]{13,17}/], severity: 'high' },
  { id: 'facebook-oauth', name: 'Facebook_OAuth', patterns: [/[fF][aA][cC][eE][bB][oO][oO][kK].*["'][0-9a-f]{32}["']/], severity: 'high' },
  { id: 'facebook-secret-key', name: 'Facebook_Secret_Key', patterns: [/([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?["'][0-9a-f]{32}/], severity: 'critical' },
  { id: 'firebase', name: 'Firebase_URL', patterns: [/[a-z0-9.-]+\.firebaseio\.com/, /[a-z0-9.-]+\.firebaseapp\.com/], severity: 'medium' },
  { id: 'generic-api-key', name: 'Generic_API_Key', patterns: [/[aA][pP][iI][_]?[kK][eE][yY].*["'][0-9a-zA-Z]{32,45}["']/], severity: 'medium' },
  { id: 'generic-secret', name: 'Generic_Secret', patterns: [/[sS][eE][cC][rR][eE][tT].*["'][0-9a-zA-Z]{32,45}["']/], severity: 'high' },
  { id: 'github', name: 'GitHub_Token', patterns: [/[gG][iI][tT][hH][uU][bB].*["'][0-9a-zA-Z]{35,40}["']/], severity: 'high' },
  { id: 'github-access-token', name: 'GitHub_Access_Token', patterns: [/[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github\.com/], severity: 'high' },
  { id: 'google-api-key', name: 'Google_API_Key', patterns: [/AIza[0-9A-Za-z\-_]{35}/], severity: 'high' },
  { id: 'google-cloud-oauth', name: 'Google_Cloud_OAuth', patterns: [/[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/], severity: 'high' },
  { id: 'google-cloud-service-account', name: 'Google_Service_Account', patterns: [/"type":\s*"service_account"/], severity: 'high' },
  { id: 'google-oauth-access-token', name: 'Google_OAuth_Access_Token', patterns: [/ya29\.[0-9A-Za-z\-_]+/], severity: 'high' },
  { id: 'heroku-api-key', name: 'Heroku_API_Key', patterns: [/[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/], severity: 'high' },
  { id: 'mailchimp-api-key', name: 'MailChimp_API_Key', patterns: [/[0-9a-f]{32}-us[0-9]{1,2}/], severity: 'high' },
  { id: 'mailgun-api-key', name: 'Mailgun_API_Key', patterns: [/key-[0-9a-zA-Z]{32}/], severity: 'high' },
  { id: 'password-in-url', name: 'Password_in_URL', patterns: [/[a-zA-Z]{3,10}:\/\/[^\/\s:@]{3,20}:[^\/\s:@]{3,20}@.{1,100}/], severity: 'critical' },
  { id: 'paypal-braintree-token', name: 'PayPal_Braintree_Token', patterns: [/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/], severity: 'high' },
  { id: 'pgp-private-key', name: 'PGP_Private_Key', patterns: [/-----BEGIN PGP PRIVATE KEY BLOCK-----/], severity: 'critical' },
  { id: 'picatic-api-key', name: 'Picatic_API_Key', patterns: [/sk_live_[0-9a-z]{32}/], severity: 'high' },
  { id: 'rsa-private-key', name: 'RSA_Private_Key', patterns: [/-----BEGIN RSA PRIVATE KEY-----/], severity: 'critical' },
  { id: 'slack-token', name: 'Slack_Token', patterns: [/xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/, /xox[baprs]-([0-9a-zA-Z]{10,48})?/], severity: 'high' },
  { id: 'slack-webhook', name: 'Slack_Webhook', patterns: [/https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/], severity: 'high' },
  { id: 'square-access-token', name: 'Square_Access_Token', patterns: [/sq0atp-[0-9A-Za-z\-_]{22}/], severity: 'high' },
  { id: 'square-oauth-secret', name: 'Square_OAuth_Secret', patterns: [/sq0csp-[0-9A-Za-z\-_]{43}/], severity: 'high' },
  { id: 'ssh-dsa-private-key', name: 'SSH_DSA_Private_Key', patterns: [/-----BEGIN DSA PRIVATE KEY-----/], severity: 'critical' },
  { id: 'ssh-ec-private-key', name: 'SSH_EC_Private_Key', patterns: [/-----BEGIN EC PRIVATE KEY-----/], severity: 'critical' },
  { id: 'stripe-api-key', name: 'Stripe_API_Key', patterns: [/sk_live_[0-9a-zA-Z]{24}/], severity: 'critical' },
  { id: 'stripe-restricted-api-key', name: 'Stripe_Restricted_API_Key', patterns: [/rk_live_[0-9a-zA-Z]{24}/], severity: 'critical' },
  { id: 'twilio-api-key', name: 'Twilio_API_Key', patterns: [/SK[0-9a-fA-F]{32}/], severity: 'high' },
  { id: 'twitter-access-token', name: 'Twitter_Access_Token', patterns: [/[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}/], severity: 'high' },
  { id: 'twitter-client-id', name: 'Twitter_ClientID', patterns: [/[tT][wW][iI][tT][tT][eE][rR](.{0,20})?["'][0-9a-z]{18,25}/], severity: 'high' },
  { id: 'twitter-oauth', name: 'Twitter_OAuth', patterns: [/[tT][wW][iI][tT][tT][eE][rR].*["'][0-9a-zA-Z]{35,44}["']/], severity: 'high' },
  { id: 'twitter-secret-key', name: 'Twitter_Secret_Key', patterns: [/[tT][wW][iI][tT][tT][eE][rR](.{0,20})?["'][0-9a-z]{35,44}/], severity: 'critical' },
  { id: 'private-key', name: 'Private_Key', patterns: [/BEGIN OPENSSH PRIVATE KEY/, /BEGIN PRIVATE KEY/, /BEGIN RSA PRIVATE KEY/, /BEGIN DSA PRIVATE KEY/, /BEGIN EC PRIVATE KEY/, /BEGIN PGP PRIVATE KEY BLOCK/, /ssh-rsa AAAA/], severity: 'critical' },
  { id: 'sendgrid-api-key', name: 'Sendgrid_API_Key', patterns: [/SG\.[a-zA-Z0-9_]{22}\.[a-zA-Z0-9_\-]{43}/], severity: 'high' },
  { id: 'shopify-access-token', name: 'Shopify_Access_Token', patterns: [/shp[a-zA-Z0-9_]{32}/, /shpat_[a-fA-F0-9]{32}/], severity: 'high' },
  { id: 'shopify-api-key', name: 'Shopify_API_Key', patterns: [/shpca_[a-zA-Z0-9_]{32}/], severity: 'high' },
  { id: 'shopify-password', name: 'Shopify_Password', patterns: [/shppa_[a-zA-Z0-9_]{32}/], severity: 'high' },
  { id: 'shopify-secret-key', name: 'Shopify_Secret_Key', patterns: [/shpss_[a-zA-Z0-9_]{32}/], severity: 'critical' },
  { id: 'fcm-server-key', name: 'FCM_Server_Key', patterns: [/AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}/], severity: 'high' },
];

function maskSecret(value) {
  if (!value) return '';
  if (value.length <= 8) return '*'.repeat(value.length);
  const first4 = value.slice(0, 4);
  const last4 = value.slice(-4);
  const middle = '*'.repeat(Math.min(value.length - 8, 20));
  return first4 + middle + last4;
}

function scanBodyForSecrets(text) {
  if (!text) return [];
  const findings = [];
  const seen = new Set();
  for (const rule of SECRET_RULES) {
    for (const pattern of rule.patterns) {
      const m = pattern.exec(text);
      if (!m) continue;
      const match = m[0] || m[1] || '';
      if (match.length < 6) continue;
      const key = rule.id + '|' + match;
      if (seen.has(key)) continue;
      seen.add(key);
      const idx = m.index;
      const before = text.slice(Math.max(0, idx - 40), idx);
      const after = text.slice(idx + match.length, idx + match.length + 40);
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        match: match.slice(0, 100),
        masked: maskSecret(match),
        before: before.replace(/\n/g, ' ').trim(),
        after: after.replace(/\n/g, ' ').trim(),
        severity: rule.severity
      });
      if (findings.length >= 20) break;
    }
    if (findings.length >= 20) break;
  }
  return findings;
}

function buildUrl(path, baseUrl, mode) {
  if (mode === 'path') {
    const base = baseUrl.endsWith('/') ? baseUrl : baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
    return new URL(path.startsWith('/') ? path.slice(1) : path, base).href;
  }
  return new URL(path, baseUrl).href;
}

function mergeWordlistEntries(builtin, custom) {
  const map = new Map();
  for (const e of builtin) map.set(e.path, e);
  for (const e of custom) map.set(e.path, e);
  return Array.from(map.values());
}
