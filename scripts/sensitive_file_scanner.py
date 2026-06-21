#!/usr/bin/env python3
"""
Sensitive File Scanner — Python CLI
Scans a web server for exposed sensitive files, configuration leaks,
debug endpoints, and vulnerable paths.

Usage:
    python scripts/sensitive_file_scanner.py -u https://example.com
    python scripts/sensitive_file_scanner.py -u https://example.com -w custom.txt -t 30
"""

import argparse
import concurrent.futures
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Missing dependency: requests")
    print("Install: pip install requests")
    sys.exit(1)


# ==============================================================
# Wordlist parsing
# ==============================================================

SECTION_CAT_RULES = [
    (r'GIT|SVN|Mercurial|Bazaar|CVS|Fossil', 'git'),
    (r'DOCKER', 'docker'),
    (r'CI/CD', 'cicd'),
    (r'Облака|инфраструктур|ENV-файл', 'cloud'),
    (r'CMS|phpMyAdmin|phpmyadmin|Битрикс|WordPress|Typo3|Joomla|Drupal|Magento|Laravel', 'cms'),
    (r'Резервн|дамп|backup|архив', 'backup'),
    (r'Лог|log', 'logs'),
    (r'IDE|редактор|vscode|idea', 'ide'),
    (r'Административ|веб-шелл|phpinfo|Actuator|Swagger|Spring|отладк', 'cms'),
    (r'Node|npm|composer|vendor', 'cms'),
]


def category_from_section_comment(line):
    for pattern, cat in SECTION_CAT_RULES:
        if re.search(pattern, line, re.IGNORECASE):
            return cat
    return None


def infer_category(path):
    p = path.lower()
    if any(x in p for x in ('.git', '.svn', '.hg', '/cvs')):
        return 'git'
    if 'docker' in p or p == '/dockerfile' or (len(p) > 8 and p.endswith('dockerfile')):
        return 'docker'
    if any(x in p for x in ('jenkins', 'hudson', 'gitlab-ci', 'travis', 'circleci')):
        return 'cicd'
    if any(x in p for x in ('.aws', '.kube', 'terraform', '.env', 'credentials', 'gcp', '.azure')):
        return 'cloud'
    if any(x in p for x in ('wp-', 'bitrix', 'typo3', 'joomla', 'drupal', 'magento', 'phpinfo', '/admin', 'phpmyadmin')):
        return 'cms'
    if any(x in p for x in ('backup', 'dump', '.sql', '.zip', '.tar', '.gz', 'wwwroot')):
        return 'backup'
    if '.log' in p or 'debug' in p:
        return 'logs'
    if any(x in p for x in ('.vscode', '.idea', 'sftp.json')):
        return 'ide'
    if any(x in p for x in ('/druid', '/solr', '/geoserver', '/v2/_catalog', '/actuator')):
        return 'cloud'
    if any(x in p for x in ('/hnap', '/cgi-bin', '/evox')):
        return 'cms'
    if any(x in p for x in ('/hudson', '/jenkins')):
        return 'cicd'
    if p.endswith('.js') and 'favicon' not in p:
        return 'cloud'
    return 'cloud'


def parse_wordlist(text):
    current_cat = None
    entries = []
    seen = set()
    for raw_line in text.splitlines():
        trimmed = raw_line.strip()
        if not trimmed:
            continue
        if trimmed.startswith('#') or trimmed.startswith('//') or trimmed.startswith('/*'):
            cat = category_from_section_comment(trimmed)
            if cat:
                current_cat = cat
            continue
        path = trimmed.split()[0]
        if not path.startswith('/'):
            continue
        if path in seen:
            continue
        seen.add(path)
        category = current_cat or infer_category(path)
        entries.append({'path': path, 'category': category})
    return entries


# ==============================================================
# Severity / signatures
# ==============================================================

def get_path_severity(path):
    p = path.lower()
    critical_keywords = [
        '.env', '.htpasswd', 'wp-config', 'dbconn.php', '.settings.php',
        'terraform.tfstate', '.aws/credentials', '.kube/config', 'credentials',
        'service-account.json', 'gcp-credentials', '/.git/config', 'license_key.php',
        'parameters.yml', 'secrets.yml', 'shell.php', 'c99.php', 'r57.php', 'b374k',
        '/console', 'actuator/env', 'actuator/heapdump',
        'secrets.json', 'eval-stdin.php', 'v2/_catalog', 'solr/admin',
        'druid/index.html', 'geoserver/web/', 'hnap1',
        'cgi-bin/authlogin.cgi', 'show+diagnostics',
        'connect', 'proxy tunnel', 'open_proxy',
        'config.inc.php', 'phpmyadmin/setup/index.php', '/phpmyadmin/config.inc',
    ]
    high_keywords = [
        '.git/', 'phpinfo', 'backup.sql', 'dump.sql', 'db.sql', 'wwwroot.zip',
        'swagger', 'api-docs', 'server-status', '/admin/', 'web.config',
        'localconfiguration.php', 'sftp.json', 'phpmyadmin', 'pgadmin',
        'hudson', 'jenkins', '/actuator', 'geoserver', 'druid/',
        'cgi-bin/authlogin.cgi', 'evox/about', 'webui/',
    ]
    if any(k in p for k in critical_keywords):
        return 'critical'
    if any(k in p for k in high_keywords):
        return 'high'
    if '.log' in p or 'debug' in p:
        return 'medium'
    if p in ('/robots.txt', '/package.json', '/composer.json'):
        return 'low'
    if p.endswith('.js') and 'favicon' not in p:
        return 'medium'
    return 'medium'


SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

SEVERITY_COLORS = {
    'critical': '\033[91m',  # red
    'high': '\033[93m',      # yellow
    'medium': '\033[94m',    # blue
    'low': '\033[92m',       # green
    'info': '\033[90m',      # grey
}
RESET = '\033[0m'
BOLD = '\033[1m'


def simple_fingerprint(text):
    if not text:
        return '0:0'
    sample = text[:512]
    h = 0
    for ch in sample:
        h = ((h << 5) - h) + ord(ch)
        h &= 0xFFFFFFFF
    return f'{len(text)}:{h}'


PATH_SIGNATURES = [
    ('env', lambda p: '.env' in p and '.example' not in p, [re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', re.M)]),
    ('git_config', lambda p: p.endswith('/.git/config') or p == '/.git/config', [re.compile(r'\[core\]', re.I), re.compile(r'\[remote', re.I)]),
    ('git_head', lambda p: p.endswith('/.git/HEAD') or p == '/.git/HEAD', [re.compile(r'^ref:', re.M)]),
    ('phpinfo', lambda p: 'phpinfo' in p, [re.compile(r'phpinfo\s*\(', re.I), re.compile(r'PHP Version', re.I)]),
    ('wp_config', lambda p: 'wp-config' in p, [re.compile(r'DB_NAME', re.I), re.compile(r'define\s*\(', re.I)]),
    ('htpasswd', lambda p: '.htpasswd' in p, [re.compile(r':\$apr1\$'), re.compile(r':\$2[aby]\$')]),
    ('swagger', lambda p: 'swagger' in p or 'api-docs' in p, [re.compile(r'swagger', re.I), re.compile(r'"openapi"', re.I), re.compile(r'"paths"\s*:', re.I)]),
    ('actuator', lambda p: 'actuator' in p, [re.compile(r'status|health|beans|env', re.I)]),
    ('eval_stdin', lambda p: 'eval-stdin' in p, [re.compile(r'php', re.I), re.compile(r'passthru|exec|shell_exec|system', re.I)]),
    ('secrets_json', lambda p: '/secrets.json' in p or '/credentials.json' in p, [re.compile(r'"[A-Za-z_]+"\s*:', re.M)]),
    ('js_bundle', lambda p: p.endswith('.js') and '.min.' not in p, [re.compile(r'require\(|import |export |module\.exports|from\s+[\'"]', re.I)]),
]

# Patterns that indicate a catch-all / error page (even when HTTP status is 200)
CATCH_ALL_PATTERNS = [
    re.compile(r'404\s+(Not\s+Found|Page|Error)', re.I),
    re.compile(r'<title>[^<]*(404|Not Found|Page not found|Access Denied)[^<]*</title>', re.I),
    re.compile(r'Page\s+not\s+found', re.I),
    re.compile(r'The requested URL was not found', re.I),
    re.compile(r'Object not found', re.I),
    re.compile(r'Error\s+404', re.I),
    re.compile(r'Access\s+Denied', re.I),
    re.compile(r'This\s+page\s+does\s+not\s+exist', re.I),
]


def requires_body_verification(path):
    return any(test(path) for _, test, _ in PATH_SIGNATURES)


def is_catch_all_page(text):
    if not text:
        return False
    return any(p.search(text) for p in CATCH_ALL_PATTERNS)


def matches_signature(path, text):
    rules = [(test, patterns) for _, test, patterns in PATH_SIGNATURES if test(path)]
    if not rules:
        return True
    for _, patterns in rules:
        if any(p.search(text) for p in patterns):
            return True
    return False


# ==============================================================
# Django debug detection
# ==============================================================

DJANGO_DEBUG_MARKERS = [
    'DEBUG = True', 'DJANGO_SETTINGS_MODULE',
    "You're seeing this error because you have DEBUG = True",
    'Traceback (most recent call last)', 'Request URL:', 'Django version:',
]

# Match both plain text `KEY: 'val'` and Django HTML debug table:
#   <th>KEY</th><td class="code"><pre>'val'</pre></td>
_VALUE_IN_HTML = re.compile(r"</th><td[^>]*><pre>['\"]?([^<]+?)['\"]?</pre></td>", re.DOTALL)

DJANGO_SECRET_PATTERNS = [
    ('SECRET_KEY', re.compile(r'SECRET_KEY(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('DATABASE_URL', re.compile(r'DATABASE_URL(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('DB_NAME', re.compile(r'(?:[\'"]NAME[\'"]|DB_NAME)(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('DB_USER', re.compile(r'(?:[\'"]USER[\'"]|DB_USER)(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('DB_PASSWORD', re.compile(r'(?:[\'"]PASSWORD[\'"]|DB_PASSWORD)(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('DB_HOST', re.compile(r'(?:[\'"]HOST[\'"]|DB_HOST)(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('DB_PORT', re.compile(r'(?:[\'"]PORT[\'"]|DB_PORT)(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('EMAIL_HOST', re.compile(r'EMAIL_HOST(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('EMAIL_HOST_PASSWORD', re.compile(r'EMAIL_HOST_PASSWORD(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('EMAIL_HOST_USER', re.compile(r'EMAIL_HOST_USER(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('AWS_ACCESS_KEY_ID', re.compile(r'AWS_ACCESS_KEY_ID(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('AWS_SECRET_ACCESS_KEY', re.compile(r'AWS_SECRET_ACCESS_KEY(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('AWS_STORAGE_BUCKET_NAME', re.compile(r'AWS_STORAGE_BUCKET_NAME(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('ADMINS', re.compile(r'ADMINS?(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('SENDGRID_API_KEY', re.compile(r'SENDGRID_API_KEY(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('SENTRY_DSN', re.compile(r'SENTRY_DSN(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('STRIPE_API_KEY', re.compile(r'STRIPE(?:_LIVE|_TEST|_SECRET|_PUBLISHABLE|_API)?_KEY(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('RECAPTCHA_SECRET', re.compile(r'(?:RECAPTCHA|NOCAPTCHA)_?(?:SECRET|SITE|PRIVATE)?_?KEY(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('JWT_SECRET', re.compile(r'(?:JWT|JWS)_?(?:SECRET|SIGNING|VERIFICATION)_?(?:KEY)?(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('OAUTH_TOKEN', re.compile(r'(?:SOCIAL_AUTH|OAUTH|OAUTH2)_?(?:[A-Z_]*_)?(?:TOKEN|SECRET|KEY)(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('CACHE_PASSWORD', re.compile(r'CACHE_PASSWORD(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('REDIS_PASSWORD', re.compile(r'REDIS(?:TOWER|_)?PASSWORD(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
    ('HASHIDS_SALT', re.compile(r'HASHIDS_SALT(?:[:\s]*[\'"]([^\'"]+)[\'"])?'), True),
]


def check_django_debug(text):
    if not text:
        return False
    return any(m in text for m in DJANGO_DEBUG_MARKERS)


def extract_django_data(text):
    if not text:
        return []
    findings = []
    seen = set()
    # Extract all setting→value pairs from HTML table first
    for m in _VALUE_IN_HTML.finditer(text):
        raw = m.group(1).strip()
        # contextual key name is the <th> text before this <td>
        pass  # we'll still rely on named patterns + catchall below

    for key, pattern, use_html in DJANGO_SECRET_PATTERNS:
        m = pattern.search(text)
        if m and m.group(1):
            if key not in seen:
                seen.add(key)
                findings.append({'key': key, 'value': m.group(1)})
        elif use_html:
            # Try HTML table context: find KEY<th>...</th><td>...<pre>VALUE</pre>
            html_pat = re.compile(
                re.escape(key) + r'</th><td[^>]*><pre>\s*[\'"]?([^<]+?)[\'"]?\s*</pre></td>',
                re.DOTALL | re.IGNORECASE
            )
            hm = html_pat.search(text)
            if hm and hm.group(1):
                val = hm.group(1).strip()
                if key not in seen and val:
                    seen.add(key)
                    findings.append({'key': key, 'value': val})

    # Catch‑all: anything ending with _KEY, _SECRET, _TOKEN, _PASSWORD not yet found
    catchall_pat = re.compile(
        r'<th>([A-Z][A-Z0-9_]*?(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_SALT|_DSN))</th>'
        r'<td[^>]*><pre>\s*[\'"]?([^<]+?)[\'"]?\s*</pre></td>',
        re.DOTALL | re.IGNORECASE
    )
    for cm in catchall_pat.finditer(text):
        ck = cm.group(1)
        cv = cm.group(2).strip()
        if ck not in seen and cv and len(cv) > 3:
            if not any(c in cv for c in '<>&"'):  # skip malformed
                seen.add(ck)
                findings.append({'key': ck, 'value': cv[:200]})

    findings.sort(key=lambda x: x['key'])
    return findings


# ==============================================================
# Technology detection
# ==============================================================

def detect_tech(results):
    tech = []
    found_paths = {r['path'] for r in results if r.get('status') == 200}

    cms_checks = [
        ('WordPress', ['/wp-admin/', '/wp-login.php', '/wp-includes/', '/wp-content/']),
        ('Joomla', ['/administrator/', '/templates/system/', '/language/en-GB/en-GB.ini']),
        ('Drupal', ['/sites/default/settings.php', '/misc/drupal.js']),
        ('Laravel', ['/artisan', '/vendor/', '/composer.json']),
        ('1C-Bitrix', ['/bitrix/admin/', '/bitrix/php_interface/dbconn.php']),
        ('Magento', ['/app/etc/env.php', '/downloader/']),
        ('TYPO3', ['/typo3/', '/typo3conf/', '/fileadmin/']),
        ('ASP.NET', ['/web.config', '/bin/', '/App_Code/']),
        ('Ghost', ['/ghost/', '/content/']),
        ('Strapi', ['/admin/', '/api/']),
        ('Apache Solr', ['/solr/admin/info/system', '/solr/admin/cores']),
        ('Apache Druid', ['/druid/index.html']),
        ('GeoServer', ['/geoserver/web/']),
        ('Jenkins/Hudson', ['/hudson', '/jenkins', '/jenkins/login']),
        ('Docker Registry', ['/v2/_catalog']),
    ]

    for name, paths in cms_checks:
        if any(p in found_paths for p in paths):
            tech.append({'name': name, 'confidence': 'high'})

    if results and any(r.get('debug_mode') for r in results):
        tech.append({'name': 'Django', 'confidence': 'high', 'debug': True})

    return tech


def detect_phpmyadmin(results):
    pma_paths = ['/phpmyadmin/', '/phpMyAdmin/', '/pma/']
    found = [r for r in results if r['path'] in pma_paths and r.get('status') == 200]
    if not found:
        return None
    vulns = []
    if any(r['path'] in ('/phpmyadmin/setup/', '/phpMyAdmin/setup/', '/pma/setup/') and r.get('status') == 200 for r in results):
        vulns.append('pma_setup_exposed')
    if any(r['path'] in ('/phpmyadmin/config.inc.php', '/phpMyAdmin/config.inc.php', '/pma/config.inc.php') and r.get('status') == 200 for r in results):
        vulns.append('pma_config_exposed')
    return {'name': 'phpMyAdmin', 'confidence': 'high', 'vulnerabilities': vulns}


def detect_iis(results):
    paths_200 = {r['path'] for r in results if r.get('status') == 200}
    has_webconfig = '/web.config' in paths_200
    if not has_webconfig and not any(p in paths_200 for p in ('/iisstart.htm', '/App_Code/', '/App_Data/', '/bin/', '/global.asax')):
        return None
    vulns = []
    if has_webconfig:
        vulns.append('iis_webconfig_exposed')
        for bak in ('/web.config.bak', '/web.config.old', '/web.config.save'):
            if bak in paths_200:
                vulns.append('iis_webconfig_backup')
                break
    if any(p in paths_200 for p in ('/Trace.axd', '/trace.axd')):
        vulns.append('iis_trace_enabled')
    if any(p in paths_200 for p in ('/elmah.axd', '/ELMAH/elmah.axd')):
        vulns.append('iis_elmah_exposed')
    if '/App_Code/' in paths_200 or '/App_Data/' in paths_200:
        vulns.append('iis_source_exposed')
    return {'name': 'IIS', 'confidence': 'high', 'vulnerabilities': vulns}


def detect_server_by_404(text, headers):
    lower_text = text.lower()
    server = headers.get('server', '').lower() if headers else ''
    checks = [
        (server, 'nginx', 'nginx'),
        (server, 'apache', 'Apache'),
        (server, 'microsoft-iis', 'IIS'),
        (server, 'tomcat', 'Apache Tomcat'),
        (server, 'jetty', 'Jetty'),
        (server, 'caddy', 'Caddy'),
        (server, 'openresty', 'OpenResty'),
        (server, 'werkzeug', 'Flask (Werkzeug)'),
    ]
    for src, keyword, name in checks:
        if keyword in src:
            return {'name': name, 'confidence': 'high'}

    body_checks = [
        ('<h1>404 not found</h1>', 'nginx', 'nginx'),
        ('the requested url was not found on this server.', 'Apache', 'Apache'),
        ('404 - file or directory not found.', 'IIS', 'IIS'),
        ('the requested url was not found on the server.', 'Flask (Werkzeug)', 'Flask (Werkzeug)', lambda t: 'on this server' not in t),
        ('the requested resource was not found on this server.', 'Django', 'Django'),
        ('laravel', 'Laravel', 'Laravel'),
        ('the server returned a "404 not found".', 'Symfony', 'Symfony'),
        ('cannot get /', 'Express.js', 'Express.js'),
        ('whitelabel error page', 'Spring Boot', 'Spring Boot'),
        ('sinatra doesn\'t know this ditty.', 'Sinatra', 'Sinatra'),
        ('the page you were looking for doesn\'t exist.', 'Ruby on Rails', 'Ruby on Rails'),
        ('the resource cannot be found.', 'ASP.NET', 'ASP.NET'),
    ]
    for entry in body_checks:
        keyword = entry[0]
        name = entry[1]
        label = entry[2]
        extra = entry[3] if len(entry) > 3 else None
        if keyword in lower_text or (isinstance(keyword, str) and keyword in lower_text):
            body_text = entry[0] if isinstance(entry[0], str) else ''
            if extra and not extra(lower_text):
                continue
            if body_text and body_text in lower_text:
                return {'name': label, 'confidence': 'high'}
            elif len(entry) > 3 and callable(entry[3]):
                if entry[3](lower_text):
                    return {'name': label, 'confidence': 'high'}
            elif lower_text.find(entry[0]) != -1:
                return {'name': label, 'confidence': 'high'}

    if server:
        parts = server.split('/')
        return {'name': parts[0].strip(), 'confidence': 'low'}
    return None


# ==============================================================
# Vulnerability analysis
# ==============================================================

VULN_LABELS = {
    'exposed_git': ('Открытый Git-репозиторий', 'critical'),
    'env_exposed': ('Файл .env доступен', 'critical'),
    'debug_mode': ('Режим отладки (DEBUG)', 'critical'),
    'phpinfo_exposed': ('phpinfo() раскрыт', 'high'),
    'status_exposed': ('Status-страница сервера', 'high'),
    'swagger_exposed': ('Swagger/OpenAPI раскрыт', 'high'),
    'actuator_exposed': ('Spring Boot Actuator', 'high'),
    'h2_console_exposed': ('H2 Console', 'critical'),
    'phpunit_rce': ('PHPUnit RCE (eval-stdin.php)', 'critical'),
    'solr_exposed': ('Apache Solr административная панель', 'critical'),
    'docker_registry_api': ('Docker Registry API открыт', 'critical'),
    'druid_exposed': ('Apache Druid UI доступен', 'high'),
    'geoserver_exposed': ('GeoServer web-панель доступна', 'high'),
    'jenkins_exposed': ('Jenkins/Hudson панель доступна', 'high'),
    'router_hnap': ('HNAP1 интерфейс роутера', 'high'),
    'cgi_exposed': ('CGI-бин/админка', 'high'),
    'phpmyadmin_exposed': ('phpMyAdmin доступен', 'high'),
    'pgadmin_exposed': ('pgAdmin доступен', 'high'),
    'adminer_exposed': ('Adminer.php доступен', 'high'),
    'secrets_exposed': ('Файл секретов (secrets/credentials)', 'critical'),
    'env_in_subdir': ('.env в подкаталоге', 'high'),
    'source_code_exposed': ('Исходный код JS (бандл) раскрыт', 'medium'),
    'phpunit_rce': ('PHPUnit RCE (eval-stdin.php)', 'critical'),
    'db_diagnostics': ('Диагностика БД (SHOW DIAGNOSTICS)', 'high'),
    'wp_xmlrpc_enabled': ('XML-RPC (xmlrpc.php) включён', 'high'),
    'wp_config_exposed': ('wp-config.php доступен (критично!)', 'critical'),
    'wp_install_accessible': ('WP установщик (install.php) доступен', 'high'),
    'wp_rest_users': ('REST API раскрывает список пользователей', 'high'),
    'wp_readme_exposed': ('readme.html раскрывает версию WP', 'low'),
    'wp_license_exposed': ('license.txt раскрывает информацию', 'low'),
    'wp_rest_api_exposed': ('WordPress REST API доступен', 'medium'),
    'iis_webconfig_exposed': ('web.config доступен (содержит ключи/строки подключения)', 'critical'),
    'iis_webconfig_backup': ('Бэкап web.config доступен', 'critical'),
    'iis_trace_enabled': ('ASP.NET Tracing (Trace.axd) включён', 'high'),
    'iis_elmah_exposed': ('ELMAH (elmah.axd) доступен — утечка ошибок', 'high'),
    'iis_source_exposed': ('Исходный код (App_Code/App_Data) доступен', 'critical'),
    'iis_webdav_enabled': ('WebDAV включён (риск загрузки/изменения файлов)', 'high'),
    'iis_aspnet_version_disclosure': ('Раскрыта версия ASP.NET через aspnet_client', 'medium'),
    'iis_appsettings_exposed': ('appsettings.json доступен (секреты .NET Core)', 'critical'),
    'django_debug_data_exposed': ('Режим отладки Django — раскрыты ключи/пароли', 'critical'),
}

# ==============================================================
# Secret detection rules (ported from ext/rules/default-rules.json)
# ==============================================================

SECRET_RULES = [
    # Cloud providers
    ('aws_access_key_id', 'AWS Access Key ID', re.compile(r'([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}'), 'critical'),
    ('aws_api_key', 'AWS API Key', re.compile(r'AKIA[0-9A-Z]{16}'), 'critical'),
    ('aws_s3_bucket', 'AWS S3 Bucket', re.compile(r'//s3[.-][a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+', re.I), 'medium'),
    ('google_api_key', 'Google API Key', re.compile(r'AIza[0-9A-Za-z\\-_]{35}'), 'high'),
    ('google_cloud_oauth', 'Google Cloud OAuth', re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), 'high'),
    ('google_service_account', 'Google Service Account', re.compile(r'"type":\s*"service_account"'), 'critical'),
    ('google_oauth_token', 'Google OAuth Token', re.compile(r'ya29\.[0-9A-Za-z\\-_]+'), 'high'),
    ('firebase', 'Firebase', re.compile(r'[a-z0-9.-]+\.(?:firebaseio|firebaseapp)\.com'), 'low'),

    # Payment processors
    ('stripe_api_key', 'Stripe API Key', re.compile(r'sk_live_[0-9a-zA-Z]{24}'), 'critical'),
    ('stripe_restricted_key', 'Stripe Restricted Key', re.compile(r'rk_live_[0-9a-zA-Z]{24}'), 'critical'),
    ('paypal_braintree', 'PayPal Braintree Token', re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'), 'high'),
    ('picatic_api_key', 'Picatic API Key', re.compile(r'sk_live_[0-9a-z]{32}'), 'high'),
    ('square_access_token', 'Square Access Token', re.compile(r'sq0atp-[0-9A-Za-z\\-_]{22}'), 'high'),
    ('square_oauth_secret', 'Square OAuth Secret', re.compile(r'sq0csp-[0-9A-Za-z\\-_]{43}'), 'high'),

    # Communication APIs
    ('slack_token', 'Slack Token', re.compile(r'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}'), 'high'),
    ('slack_webhook', 'Slack Webhook', re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'), 'high'),
    ('discord_bot_token', 'Discord Bot Token', re.compile(r'(?:M|N|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}'), 'high'),
    ('twilio_api_key', 'Twilio API Key', re.compile(r'SK[0-9a-fA-F]{32}'), 'high'),
    ('sendgrid_api_key', 'SendGrid API Key', re.compile(r'SG\.[a-zA-Z0-9_]{22}\.[a-zA-Z0-9_\-]{43}'), 'high'),
    ('mailgun_api_key', 'Mailgun API Key', re.compile(r'key-[0-9a-zA-Z]{32}'), 'high'),
    ('mailchimp_api_key', 'MailChimp API Key', re.compile(r'[0-9a-f]{32}-us[0-9]{1,2}'), 'high'),

    # Social media
    ('facebook_access_token', 'Facebook Access Token', re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'), 'high'),
    ('facebook_secret_key', 'Facebook Secret Key', re.compile(r'(?:facebook|fb).{0,20}?[\'"][0-9a-f]{32}', re.I), 'high'),
    ('twitter_access_token', 'Twitter Access Token', re.compile(r'twitter.*[1-9][0-9]+-[0-9a-zA-Z]{40}', re.I), 'high'),
    ('twitter_oauth', 'Twitter OAuth', re.compile(r'twitter.*[\'"][0-9a-zA-Z]{35,44}[\'"]', re.I), 'high'),

    # Developer tools
    ('github_access_token', 'GitHub Access Token', re.compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github\.com'), 'high'),
    ('github_token', 'GitHub Token', re.compile(r'github.*[\'"][0-9a-zA-Z]{35,40}[\'"]', re.I), 'high'),
    ('heroku_api_key', 'Heroku API Key', re.compile(r'heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', re.I), 'high'),
    ('sentry_dsn', 'Sentry DSN', re.compile(r'https?://(\w+)(:\w+)?@sentry\.io/[0-9]+'), 'low'),
    ('artifactory_token', 'Artifactory Token', re.compile(r'(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}'), 'high'),
    ('artifactory_password', 'Artifactory Password', re.compile(r'(?:\s|=|:|\"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}'), 'high'),
    ('dynatrace_token', 'Dynatrace Token', re.compile(r'dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}'), 'high'),

    # E-commerce
    ('shopify_access_token', 'Shopify Access Token', re.compile(r'sh(?:p[a-zA-Z0-9_]{32}|pat_[a-fA-F0-9]{32})'), 'high'),
    ('shopify_api_key', 'Shopify API Key', re.compile(r'shpca_[a-zA-Z0-9_]{32}'), 'high'),
    ('shopify_password', 'Shopify Password', re.compile(r'shppa_[a-zA-Z0-9_]{32}'), 'high'),
    ('shopify_secret_key', 'Shopify Secret Key', re.compile(r'shpss_[a-zA-Z0-9_]{32}'), 'high'),

    # Generic
    ('generic_api_key', 'API Key (generic)', re.compile(r'[aA][pP][iI]_?[kK][eE][yY].*[\'"][0-9a-zA-Z]{32,45}[\'"]'), 'high'),
    ('generic_secret', 'Secret (generic)', re.compile(r'[sS][eE][cC][rR][eE][tT].*[\'"][0-9a-zA-Z]{32,45}[\'"]'), 'high'),
    ('password_in_url', 'Password in URL', re.compile(r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}'), 'critical'),
    ('auth_basic', 'Basic Auth Header', re.compile(r'basic\s[a-zA-Z0-9_\-:.=]+', re.I), 'high'),
    ('auth_bearer', 'Bearer Token', re.compile(r'bearer\s[a-zA-Z0-9_\-:.=]+', re.I), 'high'),
    ('basic_auth_creds', 'Basic Auth Credentials', re.compile(r'://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+'), 'critical'),

    # Cloud services
    ('cloudinary_auth', 'Cloudinary Auth', re.compile(r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+'), 'high'),
    ('fcm_server_key', 'FCM Server Key', re.compile(r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}'), 'high'),

    # Private keys
    ('private_key', 'Private Key (SSH/RSA/DSA/EC/PGP)', re.compile(r'-----BEGIN (?:RSA |DSA |EC |PGP |OPENSSH )?(?:PRIVATE KEY|PRIVATE KEY BLOCK)-----'), 'critical'),
    ('ssh_key', 'SSH Public Key', re.compile(r'ssh-rsa AAAA'), 'high'),

    # Analytics
    ('intercom_api_key', 'Intercom API Key', re.compile(r'Intercom\.initialize\([\'"]?\w+[\'"]?,\s?[\'"]?\w+[\'"]?,\s?[\'"]?\w+[\'"]?\)'), 'low'),

    # Less critical / noisy
    ('ip_address', 'IP Address', re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), 'info'),
    ('firebase_url', 'Firebase URL', re.compile(r'[a-z0-9.-]+\.firebase(?:io|app)\.com'), 'info'),
]


def mask_secret(value):
    if not value:
        return ''
    if len(value) <= 8:
        return '*' * len(value)
    return value[:4] + '*' * (min(len(value) - 8, 20)) + value[-4:]


def scan_body_for_secrets(text):
    if not text:
        return []
    findings = []
    for rule_id, name, pattern, severity in SECRET_RULES:
        for match in pattern.finditer(text):
            matched = match.group(0)
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            before = text[start:match.start()].replace('\n', ' ').replace('\r', '')
            after = text[match.end():end].replace('\n', ' ').replace('\r', '')
            findings.append({
                'rule_id': rule_id,
                'rule_name': name,
                'match': matched,
                'masked': mask_secret(matched),
                'before': before.strip(),
                'after': after.strip(),
                'severity': severity,
            })
    return findings


def analyze_all(results, server_info=None):
    tech = detect_tech(results)
    pma = detect_phpmyadmin(results)
    if pma:
        tech.append({'name': pma['name'], 'confidence': pma['confidence']})
    iis = detect_iis(results)
    if iis:
        tech.append({'name': iis['name'], 'confidence': iis['confidence']})
    if server_info:
        tech.append(server_info)

    found_paths = {r['path'] for r in results if r.get('status') == 200}
    vulns = []

    if pma and pma.get('vulnerabilities'):
        vulns.extend(pma['vulnerabilities'])
    if iis and iis.get('vulnerabilities'):
        vulns.extend(iis['vulnerabilities'])

    if any(p.startswith('/.git/') for p in found_paths):
        vulns.append('exposed_git')
    if '/.env' in found_paths:
        vulns.append('env_exposed')
    if any(r.get('debug_mode') for r in results):
        vulns.append('debug_mode')
    if '/phpinfo.php' in found_paths:
        vulns.append('phpinfo_exposed')
    if any(p in found_paths for p in ('/status', '/server-status')):
        vulns.append('status_exposed')
    if any(p in found_paths for p in ('/swagger-ui.html', '/api-docs', '/api.json')):
        vulns.append('swagger_exposed')
    if any(p.startswith('/actuator/') for p in found_paths):
        vulns.append('actuator_exposed')
    if '/console' in found_paths:
        vulns.append('h2_console_exposed')
    if any('eval-stdin.php' in p for p in found_paths):
        vulns.append('phpunit_rce')
    if any('/solr/admin/' in p for p in found_paths):
        vulns.append('solr_exposed')
    if any('/v2/_catalog' in p for p in found_paths):
        vulns.append('docker_registry_api')
    if any('/druid/index.html' in p for p in found_paths):
        vulns.append('druid_exposed')
    if any('/geoserver/web/' in p for p in found_paths):
        vulns.append('geoserver_exposed')
    if any(p in found_paths for p in ('/hudson', '/jenkins', '/jenkins/login')):
        vulns.append('jenkins_exposed')
    if any(r.get('debug_data') for r in results):
        vulns.append('django_debug_data_exposed')
    if pma:
        vulns.append('phpmyadmin_exposed')
    if '/pgadmin/' in found_paths:
        vulns.append('pgadmin_exposed')
    if '/adminer.php' in found_paths:
        vulns.append('adminer_exposed')
    if '/HNAP1' in found_paths:
        vulns.append('router_hnap')
    if any('/cgi-bin/authlogin.cgi' in p for p in found_paths):
        vulns.append('cgi_exposed')
    if any(p in found_paths for p in ('/secrets.json', '/credentials.json')):
        vulns.append('secrets_exposed')
    env_subdirs = ['/app/.env', '/src/.env', '/config/.env', '/backend/.env', '/api/.env', '/laravel/.env', '/magento/.env']
    if any(p in found_paths for p in env_subdirs):
        vulns.append('env_in_subdir')
    source_files = ['/app.js', '/main.js', '/bundle.js', '/server.js', '/index.js', '/config.js']
    if any(p in found_paths for p in source_files):
        vulns.append('source_code_exposed')

    if '/xmlrpc.php' in found_paths:
        vulns.append('wp_xmlrpc_enabled')
    if '/wp-config.php' in found_paths:
        vulns.append('wp_config_exposed')
    if '/wp-admin/install.php' in found_paths:
        vulns.append('wp_install_accessible')
    if '/wp-json/wp/v2/users' in found_paths:
        vulns.append('wp_rest_users')
    if '/readme.html' in found_paths:
        vulns.append('wp_readme_exposed')
    if '/license.txt' in found_paths:
        vulns.append('wp_license_exposed')
    if '/wp-json/' in found_paths:
        vulns.append('wp_rest_api_exposed')

    return {
        'detectedTech': tech,
        'vulnerabilities': sorted(set(vulns), key=lambda v: SEVERITY_ORDER.get(VULN_LABELS.get(v, ('', 'info'))[1], 99))
    }


# ==============================================================
# HTTP helpers
# ==============================================================

def build_url(path, base_url, mode='site'):
    if mode == 'path':
        base = base_url if base_url.endswith('/') else base_url[:base_url.rfind('/') + 1]
        clean_path = path[1:] if path.startswith('/') else path
        return urllib.parse.urljoin(base, clean_path)
    return urllib.parse.urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))


def http_request(session, method, url, timeout):
    try:
        resp = session.request(
            method, url,
            timeout=timeout,
            allow_redirects=False,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SensitiveFileScanner/1.0)'}
        )
        return {
            'status': resp.status_code,
            'text': resp.text,
            'headers': dict(resp.headers),
            'response_url': resp.url,
        }
    except requests.exceptions.Timeout:
        return {'status': 'network_error', 'text': '', 'error': 'timeout'}
    except requests.exceptions.RequestException as e:
        return {'status': 'network_error', 'text': '', 'error': str(e)}


def fetch_baseline(session, base_url, mode, timeout):
    import random, string
    # Probe twice with different random paths to detect catch-all pages
    probes = []
    for _ in range(2):
        nonce = '_sfs_baseline_' + ''.join(random.choices(string.ascii_lowercase, k=8))
        probe_path = f'/{nonce}.html'
        url = build_url(probe_path, base_url, mode)
        res = http_request(session, 'GET', url, timeout)
        if res['status'] == 'network_error':
            return {'error': True, 'reason': res.get('error', 'network_error')}
        probes.append(res)

    fp0 = simple_fingerprint(probes[0]['text'])
    fp1 = simple_fingerprint(probes[1]['text'])
    same_page = fp0 == fp1 and len(probes[0].get('text', '') or '') > 0
    # If both probes returned identical content, server has a catch-all page
    catch_all = same_page
    res = probes[0]
    is_valid = catch_all or (res['status'] in (404, 410, 403) or (400 <= res['status'] < 500))
    return {
        'status': res['status'],
        'fingerprint': fp0,
        'size': len(res['text'] or ''),
        'text': res['text'] or '',
        'headers': res['headers'] or {},
        'valid': is_valid,
        'catch_all': catch_all,
    }


# Statuses that indicate a path might actually exist vs error pages
_EXISTENCE_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 406, 500, 502, 503}
# Statuses treated as "not found" for interesting logic
_NOT_FOUND_STATUSES = {404, 400, 410}

def is_soft404(result, baseline):
    if not baseline or baseline.get('error'):
        return result.get('status') in _NOT_FOUND_STATUSES
    if not baseline.get('valid'):
        return result.get('status') in _NOT_FOUND_STATUSES
    if result['status'] not in (200, 403):
        return False
    if result.get('fingerprint') and baseline.get('fingerprint') and result['fingerprint'] == baseline['fingerprint']:
        return True
    return False


def check_path(session, path, base_url, mode, timeout, baseline):
    full_url = build_url(path['path'], base_url, mode)
    display_path = path['path']
    need_body = requires_body_verification(display_path)
    use_head = not need_body

    if use_head:
        head = http_request(session, 'HEAD', full_url, timeout)
        if head['status'] == 'network_error':
            return {'path': display_path, 'status': 'network_error', 'size': 0, 'error': head.get('error')}
        if head['status'] in _NOT_FOUND_STATUSES:
            return {'path': display_path, 'status': head['status'], 'size': 0, 'interesting': False}
        if head['status'] in (405, 501):
            pass
        elif head['status'] not in _EXISTENCE_STATUSES:
            return {
                'path': display_path,
                'status': head['status'],
                'size': 0,
                'interesting': False,
                'severity': get_path_severity(display_path),
            }

    get_resp = http_request(session, 'GET', full_url, timeout)
    if get_resp['status'] == 'network_error':
        return {'path': display_path, 'status': 'network_error', 'size': 0, 'error': get_resp.get('error')}

    status = get_resp['status']
    text = get_resp.get('text', '')
    redirected = get_resp.get('response_url', full_url) != full_url

    if status in (301, 302) and get_resp.get('headers', {}).get('Location'):
        loc = get_resp['headers']['Location']
        try:
            loc_url = urllib.parse.urljoin(full_url, loc)
            orig_proto = urllib.parse.urlparse(full_url).scheme
            new_proto = urllib.parse.urlparse(loc_url).scheme
            if orig_proto != new_proto:
                return check_path(session, path, base_url, mode, timeout, baseline)
        except Exception:
            pass

    fingerprint = simple_fingerprint(text)
    debug_mode = check_django_debug(text)
    debug_data = extract_django_data(text) if debug_mode else None
    signature_ok = matches_signature(display_path, text)
    severity = get_path_severity(display_path)
    secrets = scan_body_for_secrets(text) if status == 200 and text else []

    result = {
        'path': display_path,
        'status': status,
        'size': len(text),
        'redirected': redirected,
        'debug_mode': debug_mode,
        'debug_data': debug_data if debug_data else None,
        'fingerprint': fingerprint,
        'signature_ok': signature_ok,
        'severity': severity,
        'secrets': secrets,
    }

    if is_soft404(result, baseline):
        result['interesting'] = False
        result['soft404'] = True
        return result

    if status in _NOT_FOUND_STATUSES:
        result['interesting'] = False
        return result

    if status == 200 and need_body and not signature_ok:
        result['interesting'] = False
        result['likely_false_positive'] = True
        return result

    if status == 200 and not signature_ok and is_catch_all_page(text):
        result['interesting'] = False
        result['likely_false_positive'] = True
        return result

    result['interesting'] = status in _EXISTENCE_STATUSES
    result['category'] = path.get('category', infer_category(display_path))
    return result


def deduplicate_by_fingerprint(results):
    fp_groups = {}
    for r in results:
        fp = r.get('fingerprint')
        if fp and r.get('interesting') and r.get('status') in (200, 403) and not r.get('signature_ok'):
            fp_groups.setdefault(fp, []).append(r)

    marked = 0
    for fp, group in fp_groups.items():
        if len(group) >= 2:
            for r in group:
                r['interesting'] = False
                r['catch_all_dup'] = True
            marked += len(group)
    return marked


# ==============================================================
# Output formatting
# ==============================================================

def color(text, severity):
    color_code = SEVERITY_COLORS.get(severity, '')
    return f'{color_code}{text}{RESET}'


def print_banner():
    L = [
        r' ____  _____ ____  ',
        r'/ ___||  ___/ ___| ',
        r'\___ \| |_  \___ \ ',
        r' ___) |  _|  ___) |',
        r'|____/|_|   |____/ ',
    ]
    print('=' * 60)
    for line in L:
        print(f'{BOLD}{color(line, "high")}{RESET}')
    print(f'{BOLD}Sensitive File Scanner v1.0{RESET}')
    print('=' * 60)


def print_finding(result):
    path = result['path']
    status = result['status']
    severity = result.get('severity', 'info')
    size = result.get('size', 0)
    secrets = result.get('secrets', [])

    sev_color = SEVERITY_COLORS.get(severity, '')

    status_str = str(status)
    if status == 200:
        status_str = color('200', 'critical') if severity in ('critical', 'high') else color('200', 'high')
    elif status == 403:
        status_str = color('403', 'medium')
    elif status == 301:
        status_str = color('301', 'low')
    elif status == 302:
        status_str = color('302', 'low')
    elif status == 401:
        status_str = color('401', 'medium')
    else:
        status_str = color(str(status), 'info')

    sev_label = f'{sev_color}[{severity.upper():>8}]{RESET}'
    size_str = f'({size} B)' if size > 0 else ''
    print(f'  {sev_label} {status_str} {path} {size_str}')

    if secrets:
        for s in secrets[:3]:
            c = SEVERITY_COLORS.get(s['severity'], '')
            print(f'         {c}⚑ {s["rule_name"]}: {s["masked"]}{RESET}')
        if len(secrets) > 3:
            print(f'         ... и ещё {len(secrets) - 3} секретов')


def print_analysis(analysis, results=None):
    tech = analysis.get('detectedTech', [])
    vulns = analysis.get('vulnerabilities', [])

    if tech:
        print(f'\n{BOLD}Обнаруженные технологии:{RESET}')
        for t in tech:
            conf = t.get('confidence', 'unknown')
            conf_color = SEVERITY_COLORS.get('high' if conf == 'high' else 'low', '')
            extra = ''
            if t.get('debug'):
                extra = color(' [DEBUG режим!]', 'critical')
            print(f'  {t["name"]} ({conf_color}{conf}{RESET}){extra}')

    if vulns:
        print(f'\n{BOLD}Найденные уязвимости:{RESET}')
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
        for v in vulns:
            label, sev = VULN_LABELS.get(v, (v, 'info'))
            by_severity.setdefault(sev, []).append((v, label))

        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            items = by_severity.get(sev, [])
            if not items:
                continue
            for vuln_id, label in items:
                c = SEVERITY_COLORS.get(sev, '')
                print(f'  {c}[{sev.upper():>8}]{RESET} {label} ({vuln_id})')

    # Show extracted debug data even if no individual path is "interesting"
    has_debug_vuln = any(v in ('debug_mode', 'django_debug_data_exposed') for v in vulns)
    if has_debug_vuln and results:
        aggregated = {}
        for r in results:
            dd = r.get('debug_data')
            if dd:
                for item in dd:
                    if item['key'] not in aggregated:
                        aggregated[item['key']] = item['value']
        if aggregated:
            print(f'\n{color("[!] ИЗВЛЕЧЁННЫЕ ДАННЫЕ (DEBUG):", "critical")}')
            for key in sorted(aggregated):
                val = aggregated[key][:150]
                if any(k in key.upper() for k in ('KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'SALT', 'ACCESS')):
                    print(f'    {color(key, "critical")} = {color(val, "critical")}')
                elif any(k in key.upper() for k in ('DB_', 'DATABASE', 'HOST', 'PORT', 'EMAIL')):
                    print(f'    {color(key, "high")} = {color(val, "high")}')
                else:
                    print(f'    {key} = {val}')

    # Show aggregated secrets across all findings
    if results:
        secret_counts = {}
        for r in results:
            for s in r.get('secrets', []):
                key = s['rule_id']
                if key not in secret_counts:
                    secret_counts[key] = {'name': s['rule_name'], 'count': 0, 'severity': s['severity'], 'paths': set()}
                secret_counts[key]['count'] += 1
                secret_counts[key]['paths'].add(r['path'])

        if secret_counts:
            print(f'\n{BOLD}Найденные секреты (токены/ключи):{RESET}')
            for sid in sorted(secret_counts, key=lambda k: secret_counts[k]['severity']):
                sc = secret_counts[sid]
                c = SEVERITY_COLORS.get(sc['severity'], '')
                paths_sample = ', '.join(sorted(sc['paths'])[:4])
                extra = f' ... и ещё {len(sc["paths"]) - 4}' if len(sc['paths']) > 4 else ''
                print(f'  {c}[{sc["severity"].upper():>8}]{RESET} {sc["name"]} ({sc["count"]} совпадений, paths: {paths_sample}{extra})')


# ==============================================================
# Main scan orchestrator
# ==============================================================

def scan_target(base_url, wordlist_path, mode='site', threads=20, timeout=10):
    # Load wordlist
    if not os.path.exists(wordlist_path):
        print(f'{color("[ERROR]", "critical")} Wordlist not found: {wordlist_path}')
        sys.exit(1)
    with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
        entries = parse_wordlist(f.read())
    print(f'{color("[*]", "info")} Загружено путей: {len(entries)}')

    base_url = base_url.rstrip('/')
    print(f'{color("[*]", "info")} Цель: {base_url}')
    print(f'{color("[*]", "info")} Режим: {mode}')
    print()

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (compatible; SensitiveFileScanner/1.0)',
        'Accept': '*/*',
    })

    # Fetch 404 baseline
    print(f'{color("[*]", "info")} Получение baseline... ', end='', flush=True)
    baseline = fetch_baseline(session, base_url, mode, timeout)
    if baseline.get('error'):
        print(color(f'ОШИБКА: {baseline["reason"]}', 'critical'))
        baseline = None
    elif baseline.get('catch_all'):
        print(color(f'catch-all (status={baseline["status"]}, size={baseline["size"]})', 'critical'))
        print(color(f'  [WARN] Сервер возвращает одинаковую страницу на все запросы — включаю фильтрацию подменных 200', 'medium'))
    elif not baseline.get('valid'):
        print(color(f'OK (status={baseline["status"]}, size={baseline["size"]})', 'critical'))
        print(color('  [WARN] Baseline не 404 — soft-404 детекция может работать неточно', 'medium'))
    else:
        print(color(f'OK (status={baseline["status"]}, size={baseline["size"]})', 'low'))
    print()

    # Scan
    results = []
    total = len(entries)
    start_time = time.time()
    completed = 0
    found_count = 0

    print(f'{BOLD}Сканирование...{RESET}')
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        fut_to_entry = {
            executor.submit(check_path, session, entry, base_url, mode, timeout, baseline): entry
            for entry in entries
        }

        for future in concurrent.futures.as_completed(fut_to_entry):
            completed += 1
            try:
                result = future.result()
                results.append(result)
                if result.get('interesting'):
                    found_count += 1
                    print_finding(result)
            except Exception as e:
                entry = fut_to_entry[future]
                results.append({'path': entry['path'], 'status': 'error', 'size': 0, 'interesting': False, 'error': str(e)})

            if completed % max(1, total // 20) == 0 or completed == total:
                elapsed = max(time.time() - start_time, 0.1)
                rate = completed / elapsed
                eta = (total - completed) / rate if rate > 0 else 0
                pct = int(completed / total * 100) if total > 0 else 0
                bar_len = 30
                filled = int(bar_len * completed / total) if total > 0 else 0
                bar = '█' * filled + '░' * (bar_len - filled)
                remaining = max(0, eta)
                print(f'\r  [{bar}] {completed}/{total} ({pct}%) | {rate:.0f} req/s | осталось ~{remaining:.0f}s', end='', flush=True)

    print()

    # Post-scan deduplication — mark identical fingerprints as false positives
    deduped = deduplicate_by_fingerprint(results)
    if deduped:
        found_count -= deduped
        print(f'{color(f"[*] Отфильтровано {deduped} дубликатов (catch-all страница)", "medium")}')

    # Analyze
    analysis = analyze_all(results)

    # Summary
    elapsed = time.time() - start_time
    print(f'\n{BOLD}{"="*60}{RESET}')
    print(f'{BOLD}Результаты:{RESET}')
    print(f'  Всего проверено: {completed}')
    print(f'  Найдено интересных: {color(str(found_count), "critical" if found_count > 0 else "low")}')
    print(f'  Время: {elapsed:.1f}s ({completed / max(elapsed, 0.1):.0f} req/s)')

    print_analysis(analysis, results)

    if found_count > 0:
        print(f'\n{BOLD}Подробные результаты (интересные находки):{RESET}')
        for r in results:
            if r.get('interesting'):
                print_finding(r)
                if r.get('debug_data'):
                    print(f'    {color("[!] DEBUG DATA:", "critical")}')
                    for d in r['debug_data'][:20]:
                        print(f'      {d["key"]} = {color(d["value"][:120], "high")}')
                if r.get('debug_data') and len(r['debug_data']) > 20:
                    print(f'    ... и ещё {len(r["debug_data"]) - 20} полей')
                if r.get('secrets') and len(r['secrets']) > 3:
                    for s in r['secrets'][3:]:
                        line = f'{color("⚑", s["severity"])} {s["rule_name"]}: {s["masked"]}'
                        print(f'       {line}')

    print(f'\n{color("[✓]", "low")} Готово.')
    return results, analysis


# ==============================================================
# CLI entrypoint
# ==============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Sensitive File Scanner — поиск уязвимых файлов на web-сервере',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com -w custom_wordlist.txt -t 30
  %(prog)s -u https://example.com/path/to/page -m path
        """
    )
    parser.add_argument('-u', '--url', required=True, help='Целевой URL')
    parser.add_argument('-w', '--wordlist', default=None, help='Путь к wordlist (по умолчанию встроенный)')
    parser.add_argument('-m', '--mode', default='site', choices=['site', 'path'], help='Режим сканирования (default: site)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Количество потоков (default: 20)')
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Таймаут запроса в секундах (default: 10)')
    parser.add_argument('--no-color', action='store_true', help='Отключить цветной вывод')

    args = parser.parse_args()

    if args.no_color:
        for k in SEVERITY_COLORS:
            SEVERITY_COLORS[k] = ''
        global RESET, BOLD
        RESET = ''
        BOLD = ''

    # Auto-prepend https:// if no scheme supplied
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    print_banner()

    # Determine wordlist path
    wordlist_path = args.wordlist
    if not wordlist_path:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(script_dir, '..', 'wordlist.txt')
        if not os.path.exists(wordlist_path):
            # Try current dir
            wordlist_path = os.path.join(os.getcwd(), 'wordlist.txt')

    scan_target(args.url, wordlist_path, args.mode, args.threads, args.timeout)


if __name__ == '__main__':
    main()
