# Logs et Monitoring

## Introduction

Le **logging** et le **monitoring** sont essentiels pour maintenir une API en production. Sans visibilité sur ce qui se passe dans votre système, vous ne pouvez pas diagnostiquer les problèmes, optimiser les performances ou assurer la sécurité. Dans ce chapitre, nous allons explorer les meilleures pratiques pour logger les événements, monitorer les métriques et créer des alertes proactives.

## Logging

### Niveaux de logs

```javascript
// ✅ Configuration des niveaux de logs
const logLevels = {
  ERROR: 0,    // Erreurs critiques
  WARN: 1,     // Avertissements
  INFO: 2,     // Informations générales
  DEBUG: 3,    // Debugging détaillé
  TRACE: 4     // Tracing complet
};

const logger = {
  error: (message, meta = {}) => {
    console.error(`[ERROR] ${message}`, meta);
    // Envoi vers un service de logging externe
  },

  warn: (message, meta = {}) => {
    console.warn(`[WARN] ${message}`, meta);
  },

  info: (message, meta = {}) => {
    console.info(`[INFO] ${message}`, meta);
  },

  debug: (message, meta = {}) => {
    if (process.env.NODE_ENV === 'development') {
      console.debug(`[DEBUG] ${message}`, meta);
    }
  },

  trace: (message, meta = {}) => {
    if (process.env.LOG_LEVEL === 'trace') {
      console.trace(`[TRACE] ${message}`, meta);
    }
  }
};
```

### Logging structuré

```javascript
// ✅ Logs structurés avec métadonnées
const logEvent = (level, message, req, res, additional = {}) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    request: {
      id: req.id || generateRequestId(),
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      correlationId: req.headers['x-correlation-id']
    },
    response: res.statusCode ? {
      statusCode: res.statusCode,
      responseTime: Date.now() - req.startTime
    } : undefined,
    ...additional
  };

  // Log selon le niveau
  console[level.toLowerCase()](JSON.stringify(logEntry));

  // Envoi vers un service externe si nécessaire
  if (level === 'ERROR' || additional.critical) {
    sendToExternalLogging(logEntry);
  }
};

// ✅ Middleware de logging
app.use((req, res, next) => {
  req.id = generateRequestId();
  req.startTime = Date.now();

  // Log de la requête
  logger.info('Request started', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip
  });

  // Log de la réponse
  res.on('finish', () => {
    logEvent(res.statusCode < 400 ? 'INFO' : 'WARN', 'Request completed', req, res, {
      duration: Date.now() - req.startTime
    });
  });

  next();
});
```

### Types de logs

#### 1. Logs d'authentification

```javascript
// ✅ Logging des événements d'authentification
app.post('/api/auth/login', async (req, res) => {
  const startTime = Date.now();

  try {
    const { email } = req.body;
    const user = await authenticateUser(email, req.body.password);

    // Log de succès
    logger.info('User login successful', {
      userId: user.id,
      email: user.email,
      method: 'password',
      ip: req.ip,
      duration: Date.now() - startTime
    });

    const token = generateJWT(user);
    res.json({ token, user });
  } catch (error) {
    // Log d'échec
    logger.warn('User login failed', {
      email: req.body.email,
      reason: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      duration: Date.now() - startTime
    });

    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

#### 2. Logs de sécurité

```javascript
// ✅ Logging des événements de sécurité
const securityLogger = {
  logAuthAttempt: (req, success, reason) => {
    logger.info(`Authentication attempt: ${success ? 'success' : 'failed'}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      email: req.body.email,
      success,
      reason,
      timestamp: new Date().toISOString()
    });
  },

  logSuspiciousActivity: (req, activity, severity) => {
    logger.warn('Suspicious activity detected', {
      ip: req.ip,
      userId: req.user?.id,
      activity,
      severity,
      endpoint: req.originalUrl,
      userAgent: req.get('User-Agent')
    });
  },

  logDataAccess: (req, resource, action, resourceId) => {
    logger.info('Data access', {
      userId: req.user?.id,
      resource,
      action,
      resourceId,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
  }
};
```

#### 3. Logs d'erreurs

```javascript
// ✅ Gestion des erreurs avec contexte
app.use((error, req, res, next) => {
  const errorId = generateErrorId();

  // Log détaillé de l'erreur
  logger.error('Unhandled error occurred', {
    errorId,
    message: error.message,
    stack: error.stack,
    request: {
      id: req.id,
      method: req.method,
      url: req.originalUrl,
      body: req.body,
      headers: req.headers
    },
    user: req.user,
    timestamp: new Date().toISOString()
  });

  // Réponse à l'utilisateur
  res.status(500).json({
    error: 'internal_server_error',
    message: 'An unexpected error occurred',
    errorId: errorId
  });
});
```

## Monitoring

### Métriques applicatives

```javascript
// ✅ Collecte de métriques
const metrics = {
  requests: {
    total: 0,
    successful: 0,
    failed: 0,
    byEndpoint: new Map(),
    byStatusCode: new Map()
  },

  responseTime: {
    average: 0,
    min: Infinity,
    max: 0,
    percentiles: {}
  },

  errors: {
    total: 0,
    byType: new Map(),
    byEndpoint: new Map()
  },

  cache: {
    hits: 0,
    misses: 0,
    hitRate: 0
  }
};

// ✅ Middleware de métriques
app.use((req, res, next) => {
  metrics.requests.total++;

  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    const endpoint = req.route?.path || req.path;

    // Métriques de requêtes
    metrics.requests.successful += res.statusCode < 400 ? 1 : 0;
    metrics.requests.failed += res.statusCode >= 400 ? 1 : 0;

    // Métriques par endpoint
    if (!metrics.requests.byEndpoint.has(endpoint)) {
      metrics.requests.byEndpoint.set(endpoint, { total: 0, errors: 0 });
    }
    const endpointMetrics = metrics.requests.byEndpoint.get(endpoint);
    endpointMetrics.total++;
    if (res.statusCode >= 400) {
      endpointMetrics.errors++;
    }

    // Métriques de temps de réponse
    metrics.responseTime.average =
      (metrics.responseTime.average * (metrics.requests.total - 1) + duration) / metrics.requests.total;

    metrics.responseTime.min = Math.min(metrics.responseTime.min, duration);
    metrics.responseTime.max = Math.max(metrics.responseTime.max, duration);

    // Codes de statut
    const statusCode = res.statusCode.toString();
    metrics.requests.byStatusCode.set(
      statusCode,
      (metrics.requests.byStatusCode.get(statusCode) || 0) + 1
    );
  });

  next();
});

// ✅ Endpoint de métriques
app.get('/api/metrics', (req, res) => {
  res.json({
    requests: {
      total: metrics.requests.total,
      successful: metrics.requests.successful,
      failed: metrics.requests.failed,
      successRate: metrics.requests.total > 0 ?
        (metrics.requests.successful / metrics.requests.total) * 100 : 0,
      byEndpoint: Object.fromEntries(metrics.requests.byEndpoint),
      byStatusCode: Object.fromEntries(metrics.requests.byStatusCode)
    },
    responseTime: metrics.responseTime,
    errors: {
      total: metrics.errors.total,
      byType: Object.fromEntries(metrics.errors.byType),
      byEndpoint: Object.fromEntries(metrics.errors.byEndpoint)
    },
    cache: {
      hits: metrics.cache.hits,
      misses: metrics.cache.misses,
      hitRate: metrics.cache.hitRate
    },
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
});
```

### Health checks

```javascript
// ✅ Health check complet
app.get('/api/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0',
    services: {}
  };

  // Vérification de la base de données
  try {
    await sequelize.authenticate();
    health.services.database = {
      status: 'healthy',
      responseTime: await measureQueryTime()
    };
  } catch (error) {
    health.status = 'degraded';
    health.services.database = {
      status: 'unhealthy',
      error: error.message
    };
  }

  // Vérification de Redis
  try {
    await redisClient.ping();
    health.services.redis = {
      status: 'healthy',
      responseTime: await measureRedisTime()
    };
  } catch (error) {
    health.status = 'degraded';
    health.services.redis = {
      status: 'unhealthy',
      error: error.message
    };
  }

  // Vérification des services externes
  const externalServices = [
    { name: 'payment-api', url: 'https://payment-api.com/health' },
    { name: 'email-service', url: 'https://email-service.com/health' }
  ];

  for (const service of externalServices) {
    try {
      const response = await fetch(service.url, { timeout: 5000 });
      health.services[service.name] = {
        status: response.ok ? 'healthy' : 'unhealthy',
        responseTime: response.headers.get('x-response-time')
      };
    } catch (error) {
      health.services[service.name] = {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  // Status code basé sur la santé globale
  const statusCode = health.status === 'healthy' ? 200 :
                    health.status === 'degraded' ? 200 : 503;

  res.status(statusCode).json(health);
});

// ✅ Health check détaillé pour les admins
app.get('/api/health/detailed', authenticateToken, requireRole(['admin']), async (req, res) => {
  const detailedHealth = await getDetailedHealth();

  res.json({
    ...detailedHealth,
    metrics: getCurrentMetrics(),
    recentErrors: getRecentErrors(),
    performance: getPerformanceMetrics()
  });
});
```

## Alertes et notifications

### Système d'alertes

```javascript
// ✅ Configuration des alertes
const alertConfig = {
  thresholds: {
    errorRate: 0.05,        // 5% d'erreurs max
    responseTime: 1000,     // 1 seconde max
    memoryUsage: 0.8,       // 80% de mémoire max
    diskUsage: 0.9,         // 90% de disque max
    cacheHitRate: 0.7       // 70% de hit rate min
  },

  channels: {
    email: ['admin@example.com', 'devops@example.com'],
    slack: process.env.SLACK_WEBHOOK_URL,
    pagerDuty: process.env.PAGERDUTY_INTEGRATION_KEY
  }
};

// ✅ Vérification des seuils
const checkThresholds = () => {
  const currentMetrics = getCurrentMetrics();

  // Vérifier le taux d'erreur
  const errorRate = currentMetrics.requests.failed / currentMetrics.requests.total;
  if (errorRate > alertConfig.thresholds.errorRate) {
    sendAlert('HIGH_ERROR_RATE', {
      currentRate: errorRate,
      threshold: alertConfig.thresholds.errorRate,
      failed: currentMetrics.requests.failed,
      total: currentMetrics.requests.total
    });
  }

  // Vérifier le temps de réponse
  if (currentMetrics.responseTime.average > alertConfig.thresholds.responseTime) {
    sendAlert('HIGH_RESPONSE_TIME', {
      averageTime: currentMetrics.responseTime.average,
      threshold: alertConfig.thresholds.responseTime
    });
  }

  // Vérifier l'utilisation mémoire
  const memoryUsage = process.memoryUsage().heapUsed / process.memoryUsage().heapTotal;
  if (memoryUsage > alertConfig.thresholds.memoryUsage) {
    sendAlert('HIGH_MEMORY_USAGE', {
      usage: memoryUsage,
      threshold: alertConfig.thresholds.memoryUsage,
      heapUsed: process.memoryUsage().heapUsed,
      heapTotal: process.memoryUsage().heapTotal
    });
  }
};

// ✅ Envoi d'alertes
const sendAlert = async (type, data) => {
  const alert = {
    type,
    timestamp: new Date().toISOString(),
    data,
    severity: getSeverity(type)
  };

  // Log de l'alerte
  logger.error(`ALERT: ${type}`, alert);

  // Envoi vers les canaux configurés
  if (alertConfig.channels.email) {
    await sendEmailAlert(alert);
  }

  if (alertConfig.channels.slack) {
    await sendSlackAlert(alert);
  }

  if (alertConfig.channels.pagerDuty && isCritical(type)) {
    await sendPagerDutyAlert(alert);
  }
};
```

### Webhooks de monitoring

```javascript
// ✅ Webhooks pour les services externes
app.post('/api/webhooks/health', (req, res) => {
  const { service, status, metrics } = req.body;

  logger.info(`Health webhook received`, {
    service,
    status,
    metrics
  });

  // Mettre à jour l'état du service
  updateServiceStatus(service, status, metrics);

  res.json({ received: true });
});

// ✅ Monitoring des endpoints critiques
const monitorCriticalEndpoints = () => {
  const criticalEndpoints = [
    '/api/health',
    '/api/auth/login',
    '/api/users',
    '/api/posts'
  ];

  criticalEndpoints.forEach(async (endpoint) => {
    try {
      const response = await fetch(`http://localhost:8000${endpoint}`);
      const responseTime = Date.now() - startTime;

      if (response.ok && responseTime < 1000) {
        logger.debug(`Critical endpoint healthy: ${endpoint}`, {
          responseTime,
          status: response.status
        });
      } else {
        sendAlert('CRITICAL_ENDPOINT_DOWN', {
          endpoint,
          responseTime,
          status: response.status
        });
      }
    } catch (error) {
      sendAlert('CRITICAL_ENDPOINT_ERROR', {
        endpoint,
        error: error.message
      });
    }
  });
};

// ✅ Monitoring continu
setInterval(monitorCriticalEndpoints, 5 * 60 * 1000); // Toutes les 5 minutes
setInterval(checkThresholds, 60 * 1000); // Toutes les minutes
```

## Debugging et tracing

### Request tracing

```javascript
// ✅ Tracing des requêtes
const traceRequest = (req, res, next) => {
  const traceId = req.headers['x-trace-id'] || generateTraceId();
  req.traceId = traceId;

  // Ajouter l'ID de trace dans la réponse
  res.set('X-Trace-Id', traceId);

  // Log avec l'ID de trace
  logger.info('Request started', {
    traceId,
    method: req.method,
    url: req.originalUrl,
    userId: req.user?.id
  });

  next();
};

// ✅ Middleware de tracing distribué
app.use(traceRequest);

// ✅ Propagation du trace ID
const makeRequestWithTrace = (url, options = {}) => {
  const traceId = getCurrentTraceId();

  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-Trace-Id': traceId
    }
  });
};
```

### Debugging tools

```javascript
// ✅ Middleware de debugging
const debugMiddleware = (req, res, next) => {
  if (process.env.NODE_ENV === 'development') {
    // Ajouter des informations de debug
    res.set('X-Debug-Info', JSON.stringify({
      requestId: req.id,
      traceId: req.traceId,
      user: req.user,
      query: req.query,
      params: req.params,
      startTime: req.startTime
    }));
  }

  next();
};

// ✅ Endpoint de debug pour les développeurs
app.get('/api/debug', authenticateToken, requireRole(['admin']), (req, res) => {
  res.json({
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    metrics: getCurrentMetrics(),
    recentLogs: getRecentLogs(),
    activeConnections: getActiveConnections(),
    databaseStatus: getDatabaseStatus(),
    cacheStatus: getCacheStatus()
  });
});
```

## Intégration avec services externes

### ELK Stack (Elasticsearch, Logstash, Kibana)

```javascript
// ✅ Configuration Logstash
const logstashConfig = {
  host: 'localhost',
  port: 5044,
  protocol: 'tcp'
};

// ✅ Envoi vers Logstash
const sendToLogstash = (logEntry) => {
  const client = net.createConnection(logstashConfig, () => {
    client.write(JSON.stringify(logEntry) + '\n');
    client.end();
  });

  client.on('error', (error) => {
    console.error('Logstash connection error:', error);
  });
};
```

### Configuration Sentry

```javascript
// ✅ Intégration Sentry
const Sentry = require('@sentry/node');

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0,
  integrations: [
    new Sentry.Integrations.Http({ tracing: true }),
    new Sentry.Integrations.Console(),
    new Sentry.Integrations.OnUncaughtException(),
    new Sentry.Integrations.OnUnhandledRejection()
  ]
});

// ✅ Capture des erreurs
app.use(Sentry.Handlers.requestHandler());
app.use(Sentry.Handlers.tracingHandler());

// ✅ Middleware de capture d'erreurs
app.use((error, req, res, next) => {
  Sentry.withScope((scope) => {
    scope.setUser({
      id: req.user?.id,
      email: req.user?.email
    });

    scope.setTag('endpoint', req.originalUrl);
    scope.setTag('method', req.method);
    scope.setTag('statusCode', res.statusCode);

    Sentry.captureException(error);
  });

  next(error);
});

// ✅ Performance monitoring
app.get('/api/users', async (req, res) => {
  const transaction = Sentry.startTransaction({
    name: 'getUsers',
    op: 'http.server'
  });

  try {
    const users = await User.findAll();
    res.json({ data: users });

    transaction.setStatus('ok');
  } catch (error) {
    transaction.setStatus('error');
    throw error;
  } finally {
    transaction.finish();
  }
});
```

## Configuration de production

### Logging en production

```javascript
// ✅ Configuration de logging de production
const winston = require('winston');

// Configuration Winston
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'blog-api' },
  transports: [
    // Fichier d'erreurs
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error'
    }),
    // Fichier général
    new winston.transports.File({
      filename: 'logs/combined.log'
    }),
    // Console en développement
    ...(process.env.NODE_ENV === 'development' ? [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      })
    ] : [])
  ]
});

// ✅ Rotation des logs
const logRotation = {
  size: '20m',    // 20MB max par fichier
  maxFiles: '14d' // Garder 14 jours
};
```

### Monitoring distribué

```javascript
// ✅ Tracing distribué avec OpenTelemetry
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-otlp-http');

// Configuration OpenTelemetry
const provider = new NodeTracerProvider({
  resource: {
    serviceName: 'blog-api',
    serviceVersion: '1.0.0'
  }
});

provider.addSpanProcessor(
  new BatchSpanProcessor(new OTLPTraceExporter({
    url: 'http://localhost:4318/v1/traces'
  }))
);

provider.register();

// ✅ Instrumentation automatique
registerInstrumentations({
  instrumentations: [getNodeAutoInstrumentations()]
});

// ✅ Tracing personnalisé
app.get('/api/posts/:id', async (req, res) => {
  const span = tracer.startSpan('getPost', {
    attributes: {
      'post.id': req.params.id,
      'user.id': req.user?.id
    }
  });

  try {
    const post = await getPostById(req.params.id);
    span.setStatus({ code: 1 }); // OK
    res.json(post);
  } catch (error) {
    span.setStatus({ code: 2, message: error.message }); // ERROR
    throw error;
  } finally {
    span.end();
  }
});
```

## Tests de monitoring

### Tests des health checks

```javascript
// tests/monitoring.test.js
describe('Health Checks', () => {
  test('should return healthy status', async () => {
    const response = await request(app)
      .get('/api/health')
      .expect(200);

    expect(response.body.status).toBe('healthy');
    expect(response.body).toHaveProperty('timestamp');
    expect(response.body).toHaveProperty('uptime');
    expect(response.body).toHaveProperty('version');
    expect(response.body.services).toHaveProperty('database');
    expect(response.body.services).toHaveProperty('redis');
  });

  test('should detect database issues', async () => {
    // Simuler une panne de base de données
    jest.spyOn(sequelize, 'authenticate').mockRejectedValue(new Error('DB down'));

    const response = await request(app)
      .get('/api/health')
      .expect(200); // 200 même si dégradé

    expect(response.body.status).toBe('degraded');
    expect(response.body.services.database.status).toBe('unhealthy');
  });
});
```

### Tests des métriques

```javascript
describe('Metrics', () => {
  test('should track request metrics', async () => {
    // Faire plusieurs requêtes
    await request(app).get('/api/users').expect(200);
    await request(app).get('/api/posts').expect(200);
    await request(app).get('/api/invalid').expect(404);

    const response = await request(app)
      .get('/api/metrics')
      .expect(200);

    expect(response.body.requests.total).toBe(3);
    expect(response.body.requests.successful).toBe(2);
    expect(response.body.requests.failed).toBe(1);
    expect(response.body.requests.successRate).toBeCloseTo(66.67, 1);
  });

  test('should track response times', async () => {
    await request(app).get('/api/users').expect(200);

    const response = await request(app)
      .get('/api/metrics')
      .expect(200);

    expect(response.body.responseTime).toHaveProperty('average');
    expect(response.body.responseTime).toHaveProperty('min');
    expect(response.body.responseTime).toHaveProperty('max');
  });
});
```

## Quiz du logging et monitoring

**Question 1** : Quels sont les niveaux de logs standards ?
**Réponse** : ERROR, WARN, INFO, DEBUG, TRACE

**Question 2** : Quand envoyer une alerte ?
**Réponse** : Pour les événements critiques (erreurs élevées, pannes, sécurité)

**Question 3** : Pourquoi utiliser le tracing distribué ?
**Réponse** : Pour suivre une requête à travers plusieurs services

## En résumé

### Types de logs
1. **Authentification** : Tentatives de connexion
2. **Sécurité** : Événements suspects
3. **Erreurs** : Exceptions avec contexte
4. **Performance** : Métriques et temps de réponse
5. **Audit** : Actions des utilisateurs

### Monitoring
- 📊 **Métriques** : Requêtes, temps de réponse, erreurs
- 🏥 **Health checks** : État des services
- 🚨 **Alertes** : Seuils dépassés
- 🔍 **Tracing** : Suivi des requêtes
- 📈 **APM** : Performance applicative

### Outils recommandés
- 📝 **Winston** : Logging structuré
- 🏥 **Health checks** : Surveillance de l'état
- 📊 **Prometheus** : Collecte de métriques
- 🚨 **Grafana** : Visualisation et alertes
- 🔍 **Jaeger** : Tracing distribué

### Configuration recommandée
```javascript
// Logging
{
  level: 'info',
  format: 'json',
  transports: ['file', 'console', 'external']
}

// Monitoring
{
  healthCheckInterval: 30,    // secondes
  metricsInterval: 60,        // secondes
  alertThresholds: {
    errorRate: 0.05,
    responseTime: 1000,
    memoryUsage: 0.8
  }
}
```

Dans le dernier chapitre de cette section, nous explorerons la **scalabilité** et les **microservices** !

---

**Prochain chapitre** : [04-Scalabilité-et-Microservices](04-Scalabilité-et-Microservices.md)
