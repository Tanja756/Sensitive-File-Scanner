// Detection Engine for Sensitive File Scanner
// Provides technology fingerprinting, API endpoint detection, and vulnerability analysis

// Technology detection rules
const TECHNOLOGY_RULES = {
  wordpress: {
    name: 'WordPress',
    files: ['/wp-config.php', '/wp-content/', '/xmlrpc.php', '/wp-includes/'],
    confidence: 0.8,
    minMatches: 2,
    icon: '📝'
  },
  django: {
    name: 'Django',
    files: ['/settings.pyc', '/manage.py'],
    confidence: 0.7,
    minMatches: 1,
    icon: '🐍'
  },
  laravel: {
    name: 'Laravel',
    files: ['/.env', '/artisan', '/storage/', '/bootstrap/'],
    confidence: 0.75,
    minMatches: 2,
    icon: '🎨'
  },
  nodejs: {
    name: 'Node.js',
    files: ['/package.json', '/package-lock.json', '/yarn.lock', '/node_modules/'],
    confidence: 0.7,
    minMatches: 1,
    icon: '🟢'
  },
  bitrix: {
    name: '1C-Bitrix',
    files: ['/bitrix/', '/bitrix/admin/', '/bitrix/php_interface/'],
    confidence: 0.85,
    minMatches: 1,
    icon: '🏢'
  },
  docker: {
    name: 'Docker',
    files: ['/Dockerfile', '/docker-compose.yml', '/.docker/'],
    confidence: 0.8,
    minMatches: 1,
    icon: '🐳'
  },
  jenkins: {
    name: 'Jenkins',
    files: ['/Jenkinsfile'],
    confidence: 0.9,
    minMatches: 1,
    icon: '⚙️'
  },
  gitlab: {
    name: 'GitLab CI',
    files: ['/.gitlab-ci.yml'],
    confidence: 0.9,
    minMatches: 1,
    icon: '🦊'
  },
  kubernetes: {
    name: 'Kubernetes',
    files: ['/.kube/config', '/k8s/', '/kubernetes/'],
    confidence: 0.85,
    minMatches: 1,
    icon: '☸️'
  },
  aws: {
    name: 'AWS',
    files: ['/.aws/credentials', '/.aws/config'],
    confidence: 0.9,
    minMatches: 1,
    icon: '☁️'
  },
  gcp: {
    name: 'Google Cloud',
    files: ['/gcp-credentials.json', '/.config/gcloud/'],
    confidence: 0.9,
    minMatches: 1,
    icon: '🔵'
  },
  terraform: {
    name: 'Terraform',
    files: ['/terraform.tfstate', '/.terraform/'],
    confidence: 0.9,
    minMatches: 1,
    icon: '🏗️'
  },
  php: {
    name: 'PHP',
    files: ['/composer.json', '/composer.lock', '/.htaccess'],
    confidence: 0.6,
    minMatches: 1,
    icon: '🐘'
  },
  python: {
    name: 'Python',
    files: ['/requirements.txt', '/Pipfile', '/poetry.lock'],
    confidence: 0.6,
    minMatches: 1,
    icon: '🐍'
  },
  ruby: {
    name: 'Ruby/Rails',
    files: ['/Gemfile', '/Gemfile.lock'],
    confidence: 0.7,
    minMatches: 1,
    icon: '💎'
  },
  svn: {
    name: 'SVN',
    files: ['/.svn/'],
    confidence: 0.95,
    minMatches: 1,
    icon: '📂'
  },
  mercurial: {
    name: 'Mercurial',
    files: ['/.hg/'],
    confidence: 0.95,
    minMatches: 1,
    icon: '📂'
  },
  git: {
    name: 'Git',
    files: ['/.git/', '/.gitignore', '/.gitmodules'],
    confidence: 0.95,
    minMatches: 1,
    icon: '📂'
  }
};

// API endpoint patterns
const API_PATTERNS = {
  rest: {
    name: 'REST API',
    patterns: ['/api/', '/v1/', '/v2/', '/rest/'],
    severity: 'medium'
  },
  graphql: {
    name: 'GraphQL',
    patterns: ['/graphql', '/graphiql'],
    severity: 'medium'
  },
  admin: {
    name: 'Admin Panel',
    patterns: ['/admin', '/administrator', '/wp-admin', '/bitrix/admin'],
    severity: 'high'
  },
  auth: {
    name: 'Auth Endpoint',
    patterns: ['/login', '/auth/', '/signin', '/oauth'],
    severity: 'medium'
  },
  debug: {
    name: 'Debug Endpoint',
    patterns: ['/debug', '/test', '/phpinfo', '/info'],
    severity: 'high'
  }
};

// Vulnerability patterns for content analysis
const VULN_PATTERNS = {
  credentials: {
    name: 'Exposed Credentials',
    severity: 'critical',
    patterns: [
      /API_KEY\s*[:=]\s*['"]\w+['"]/i,
      /SECRET\s*[:=]\s*['"]\w+['"]/i,
      /PASSWORD\s*[:=]\s*['"]\w+['"]/i,
      /TOKEN\s*[:=]\s*['"]\w+['"]/i,
      /ACCESS_KEY\s*[:=]\s*['"]\w+['"]/i,
      /PRIVATE_KEY\s*[:=]\s*['"]\w+['"]/i,
      /DB_PASSWORD\s*[:=]\s*['"]\w+['"]/i,
      /DATABASE_URL\s*[:=]\s*['"][^'"]+['"]/i,
      /REDIS_URL\s*[:=]\s*['"][^'"]+['"]/i,
      /MONGO_URI\s*[:=]\s*['"][^'"]+['"]/i
    ]
  },
  config: {
    name: 'Exposed Configuration',
    severity: 'high',
    patterns: [
      /DB_HOST\s*[:=]/i,
      /DB_USER\s*[:=]/i,
      /DB_NAME\s*[:=]/i,
      /SMTP_HOST\s*[:=]/i,
      /SMTP_USER\s*[:=]/i,
      /AWS_ACCESS_KEY\s*[:=]/i,
      /AWS_SECRET_KEY\s*[:=]/i
    ]
  },
  debug: {
    name: 'Debug Mode Enabled',
    severity: 'high',
    patterns: [
      /DEBUG\s*[:=]\s*True/i,
      /DEBUG\s*[:=]\s*1/i,
      /APP_ENV\s*[:=]\s*development/i,
      /APP_ENV\s*[:=]\s*dev/i,
      /NODE_ENV\s*[:=]\s*development/i
    ]
  },
  backup: {
    name: 'Exposed Backup',
    severity: 'medium',
    patterns: [
      /\.sql$/,
      /\.sql\.gz$/,
      /\.tar\.gz$/,
      /\.zip$/,
      /\.dump$/,
      /\.bak$/,
      /\.backup$/
    ]
  },
  log: {
    name: 'Exposed Log File',
    severity: 'low',
    patterns: [
      /\.log$/,
      /error\.log/,
      /access\.log/,
      /debug\.log/
    ]
  }
};

// Django debug markers (existing functionality)
const DJANGO_DEBUG_MARKERS = [
  'DEBUG = True',
  'DJANGO_SETTINGS_MODULE',
  "You're seeing this error because you have DEBUG = True",
  'Traceback (most recent call last)',
  'Request URL:',
  'Django version:'
];

// Detect technologies based on found files
function detectTechnologies(foundPaths) {
  const detected = [];
  const pathSet = new Set(foundPaths);

  for (const [key, rule] of Object.entries(TECHNOLOGY_RULES)) {
    let matches = 0;
    for (const file of rule.files) {
      if (pathSet.has(file) || foundPaths.some(p => p.includes(file))) {
        matches++;
      }
    }

    if (matches >= rule.minMatches) {
      detected.push({
        id: key,
        name: rule.name,
        confidence: Math.min(rule.confidence + (matches - rule.minMatches) * 0.05, 1.0),
        matches: matches,
        icon: rule.icon
      });
    }
  }

  return detected.sort((a, b) => b.confidence - a.confidence);
}

// Detect API endpoints from paths
function detectAPIEndpoints(paths) {
  const detected = [];

  for (const [key, pattern] of Object.entries(API_PATTERNS)) {
    const matches = paths.filter(p =>
      pattern.patterns.some(pat => p.includes(pat))
    );

    if (matches.length > 0) {
      detected.push({
        id: key,
        name: pattern.name,
        severity: pattern.severity,
        endpoints: matches
      });
    }
  }

  return detected;
}

// Analyze content for vulnerabilities
function analyzeVulnerabilities(path, content, status) {
  const vulnerabilities = [];

  if (!content || status === 404) {
    return vulnerabilities;
  }

  // Check for Django debug mode
  const isDjangoDebug = DJANGO_DEBUG_MARKERS.some(marker =>
    content.includes(marker)
  );
  if (isDjangoDebug) {
    vulnerabilities.push({
      type: 'debug',
      name: 'Django Debug Mode',
      severity: 'high',
      description: 'Django application is running with DEBUG = True'
    });
  }

  // Check for exposed credentials
  for (const pattern of VULN_PATTERNS.credentials.patterns) {
    if (pattern.test(content)) {
      vulnerabilities.push({
        type: 'credentials',
        name: VULN_PATTERNS.credentials.name,
        severity: VULN_PATTERNS.credentials.severity,
        description: 'File contains exposed credentials or API keys'
      });
      break;
    }
  }

  // Check for exposed configuration
  for (const pattern of VULN_PATTERNS.config.patterns) {
    if (pattern.test(content)) {
      vulnerabilities.push({
        type: 'config',
        name: VULN_PATTERNS.config.name,
        severity: VULN_PATTERNS.config.severity,
        description: 'File contains configuration data'
      });
      break;
    }
  }

  // Check for debug mode in config files
  if (path.includes('.env') || path.includes('config')) {
    for (const pattern of VULN_PATTERNS.debug.patterns) {
      if (pattern.test(content)) {
        vulnerabilities.push({
          type: 'debug',
          name: VULN_PATTERNS.debug.name,
          severity: VULN_PATTERNS.debug.severity,
          description: 'Application is running in development/debug mode'
        });
        break;
      }
    }
  }

  // Check for backup files
  for (const pattern of VULN_PATTERNS.backup.patterns) {
    if (pattern.test(path)) {
      vulnerabilities.push({
        type: 'backup',
        name: VULN_PATTERNS.backup.name,
        severity: VULN_PATTERNS.backup.severity,
        description: 'Backup file may contain sensitive data'
      });
      break;
    }
  }

  // Check for log files
  for (const pattern of VULN_PATTERNS.log.patterns) {
    if (pattern.test(path)) {
      vulnerabilities.push({
        type: 'log',
        name: VULN_PATTERNS.log.name,
        severity: VULN_PATTERNS.log.severity,
        description: 'Log file may contain sensitive information'
      });
      break;
    }
  }

  return vulnerabilities;
}

// Get severity color for UI
function getSeverityColor(severity) {
  const colors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#65a30d'
  };
  return colors[severity] || '#6b7280';
}

// Get severity label
function getSeverityLabel(severity) {
  const labels = {
    critical: '🔴 Критично',
    high: '🟠 Высокий',
    medium: '🟡 Средний',
    low: '🟢 Низкий'
  };
  return labels[severity] || '⚪ Неизвестно';
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectTechnologies,
    detectAPIEndpoints,
    analyzeVulnerabilities,
    getSeverityColor,
    getSeverityLabel,
    TECHNOLOGY_RULES,
    API_PATTERNS,
    VULN_PATTERNS
  };
}