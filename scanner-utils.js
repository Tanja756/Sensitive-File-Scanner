// Shared utilities: wordlist parsing, categories, severity, signatures, baseline

const DEFAULT_PATHS = [
  "/.env", "/.git/config", "/.git/HEAD", "/.gitignore", "/backup.sql", "/dump.sql",
  "/.htpasswd", "/.htaccess", "/wp-config.php", "/phpinfo.php", "/info.php", "/admin/",
  "/.vscode/sftp.json", "/.idea/workspace.xml", "/debug.log", "/error.log",
  "/credentials", "/wwwroot.zip", "/robots.txt", "/.DS_Store", "/Thumbs.db",
  "/node_modules/", "/vendor/", "/composer.json", "/package.json", "/Dockerfile",
  "/docker-compose.yml", "/Jenkinsfile", "/.travis.yml", "/.circleci/config.yml"
];

const SECTION_CAT_RULES = [
  [/GIT|SVN|Mercurial|Bazaar|CVS|Fossil/i, 'git'],
  [/DOCKER/i, 'docker'],
  [/CI\/CD/i, 'cicd'],
  [/Облака|инфраструктур|ENV-файл/i, 'cloud'],
  [/CMS|Битрикс|WordPress|Typo3|Joomla|Drupal|Magento|Laravel/i, 'cms'],
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
  h2_console_exposed: { label: 'H2 Console', severity: 'critical' }
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
  if (p.includes('jenkins') || p.includes('gitlab-ci') || p.includes('travis') || p.includes('circleci') || p.includes('drone') || p.includes('pipelines')) return 'cicd';
  if (p.includes('.aws') || p.includes('.kube') || p.includes('terraform') || p.includes('.env') || p.includes('credentials') || p.includes('gcp') || p.includes('.azure')) return 'cloud';
  if (p.includes('wp-') || p.includes('bitrix') || p.includes('typo3') || p.includes('joomla') || p.includes('drupal') || p.includes('magento') || p.includes('phpinfo') || p.includes('/admin')) return 'cms';
  if (p.includes('backup') || p.includes('dump') || p.includes('.sql') || p.includes('.zip') || p.includes('.tar') || p.includes('.gz') || p.includes('wwwroot')) return 'backup';
  if (p.includes('.log') || p.includes('debug')) return 'logs';
  if (p.includes('.vscode') || p.includes('.idea') || p.includes('sftp.json')) return 'ide';
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
    '/console', 'actuator/env', 'actuator/heapdump'
  ];
  const high = [
    '.git/', 'phpinfo', 'backup.sql', 'dump.sql', 'db.sql', 'wwwroot.zip',
    'swagger', 'api-docs', 'server-status', '/admin/', 'web.config',
    'localconfiguration.php', 'sftp.json'
  ];
  if (critical.some(k => p.includes(k))) return 'critical';
  if (high.some(k => p.includes(k))) return 'high';
  if (p.includes('.log') || p.includes('debug')) return 'medium';
  if (p.includes('robots.txt') || p.includes('package.json') || p.includes('composer.json')) return 'low';
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
  { test: p => p.includes('actuator'), patterns: [/status|health|beans|env/i] }
];

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

function isSoft404(result, baseline) {
  if (!baseline || result.status === 404) return result.status === 404;
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
