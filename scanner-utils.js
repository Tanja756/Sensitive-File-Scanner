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
  django_debug_data_exposed: { label: 'Режим отладки Django — раскрыты ключи/пароли', severity: 'critical' }
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
];

function extractDjangoDebugData(text) {
  if (!text) return [];
  const findings = [];
  const seen = new Set();

  for (const { key, pattern } of DJANGO_SECRET_PATTERNS) {
    const match = text.match(pattern);
    if (match && match[1]) {
      const val = match[1].trim();
      if (!seen.has(key)) {
        seen.add(key);
        findings.push({ key, value: val });
      }
    }
  }

  const broadPattern = /['"]([A-Z][A-Z0-9_]*(?:KEY|SECRET|PASSWORD|TOKEN|ACCESS|SALT|LOGIN))['"][:\s]*['"]([^'"]{4,})['"]/gi;
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

  return findings;
}

function isSoft404(result, baseline) {
  if (!baseline || baseline.error || result.status === 404) return result.status === 404;
  if (result.status !== 200 && result.status !== 403) return false;
  if (result.fingerprint && baseline.fingerprint && result.fingerprint === baseline.fingerprint) {
    return true;
  }
  return false;
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
