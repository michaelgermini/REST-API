# CORS et Rate Limiting

## Introduction

L'authentification ne suffit pas à sécuriser une API. Il faut aussi protéger contre les **attaques externes** et **l'abus de l'API**. Dans ce chapitre, nous allons explorer **CORS** (Cross-Origin Resource Sharing) pour contrôler les origines autorisées, et le **Rate Limiting** pour prévenir les abus et les attaques par déni de service. Ces mécanismes sont essentiels pour la sécurité et la stabilité de votre API.

## CORS (Cross-Origin Resource Sharing)

### Qu'est-ce que CORS ?

CORS est un mécanisme de sécurité des navigateurs qui **restreint les requêtes cross-origin** (requêtes vers un domaine différent). Sans configuration CORS appropriée, votre API sera inaccessible depuis un frontend hébergé sur un domaine différent.

```javascript
// ❌ Requête bloquée par CORS
// Frontend: https://myapp.com
// API: https://api.example.com

fetch('https://api.example.com/users')
  .then(response => response.json())
  .catch(error => {
    console.log('CORS error:', error);
    // TypeError: Failed to fetch
  });
```

### Configuration CORS basique

```javascript
const cors = require('cors');
const express = require('express');
const app = express();

// ✅ Configuration CORS permissive (développement)
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

// ✅ Configuration CORS restrictive (production)
app.use(cors({
  origin: [
    'https://myapp.com',
    'https://www.myapp.com',
    'https://staging.myapp.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
```

### Headers CORS

```javascript
// ✅ Headers de réponse CORS
app.use('/api', cors({
  origin: 'https://myapp.com',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
  maxAge: 86400 // Cache préflight pendant 24h
}));

// Réponse avec headers CORS
app.get('/api/users', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': 'https://myapp.com',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400'
  });

  res.json(users);
});
```

### Preflight Requests

```javascript
// ✅ Gestion des requêtes OPTIONS (preflight)
app.options('/api/users', cors()); // Réponse automatique

// ✅ Ou manuellement
app.options('/api/users', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': 'https://myapp.com',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400'
  });

  res.status(204).send();
});

// ✅ Requête avec credentials
app.post('/api/users', (req, res) => {
  // Requête avec cookies ou Authorization header
  // Nécessite credentials: true dans CORS
  res.json(newUser);
});
```

### CORS avec authentification

```javascript
// ✅ CORS pour API authentifiée
const corsOptions = {
  origin: function (origin, callback) {
    // Liste des origines autorisées
    const allowedOrigins = [
      'https://myapp.com',
      'https://www.myapp.com',
      'https://staging.myapp.com'
    ];

    // Autoriser les requêtes sans origin (mobile apps, CLI)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Requested-With'],
  exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining']
};

app.use('/api', cors(corsOptions));

// ✅ Middleware d'authentification après CORS
app.use('/api', authenticateToken);
```

## Rate Limiting

### Qu'est-ce que le Rate Limiting ?

Le Rate Limiting consiste à **limiter le nombre de requêtes** qu'un client peut faire dans un intervalle de temps donné. Cela protège contre :

- 🚫 **Attaques DDoS** (Distributed Denial of Service)
- 🔄 **Scraping** de données
- 💸 **Abus** de l'API gratuite
- ⚡ **Surcharge** du serveur

```javascript
// ✅ Exemple de rate limiting
const rateLimit = require('express-rate-limit');

// Limite générale
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requêtes par fenêtre
  message: {
    error: 'too_many_requests',
    message: 'Too many requests, please try again later',
    retry_after: 900 // 15 minutes en secondes
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Limite stricte pour l'authentification
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 tentatives de connexion par 15 minutes
  message: {
    error: 'too_many_login_attempts',
    message: 'Too many login attempts, please try again later'
  },
  skipSuccessfulRequests: true, // Ne compter que les échecs
  skip: (req) => req.ip === 'admin-ip' // Exception pour admin
});

// Application des limites
app.use('/api', generalLimiter);
app.use('/api/auth/login', authLimiter);
```

### Types de Rate Limiting

#### 1. Par IP

```javascript
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  },
  message: 'Too many requests from this IP'
});
```

#### 2. Par utilisateur

```javascript
const userLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000, // Plus de requêtes pour les utilisateurs authentifiés
  keyGenerator: (req) => {
    return req.user ? req.user.id : req.ip;
  },
  skip: (req) => !req.user // Ne s'applique qu'aux utilisateurs connectés
});
```

#### 3. Par endpoint

```javascript
// Limites différentes selon les endpoints
const createUserLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 heure
  max: 3, // 3 créations d'utilisateur par heure
  message: 'Too many user creation attempts'
});

const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 recherches par minute
  message: 'Too many search requests'
});

app.post('/api/users', createUserLimiter, createUser);
app.get('/api/search', searchLimiter, search);
```

#### 4. Par tier (plan d'abonnement)

```javascript
const tierLimiters = {
  free: rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 100,
    message: 'Free tier limit reached'
  }),
  pro: rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10000,
    message: 'Pro tier limit reached'
  }),
  enterprise: rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 100000,
    message: 'Enterprise tier limit reached'
  })
};

const getUserTierLimiter = (req, res, next) => {
  const user = req.user;
  const tier = user ? user.tier : 'free';
  const limiter = tierLimiters[tier];

  return limiter(req, res, next);
};

app.use('/api', getUserTierLimiter);
```

### Headers Rate Limit

```javascript
// ✅ Headers informatifs
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'rate_limit_exceeded',
    message: 'Too many requests',
    retry_after: 900
  },
  standardHeaders: true, // Ajoute les headers X-RateLimit-*
  legacyHeaders: false,  // Désactive les headers deprecated
  handler: (req, res) => {
    res.set({
      'X-RateLimit-Limit': 100,
      'X-RateLimit-Remaining': 0,
      'X-RateLimit-Reset': Math.floor(Date.now() / 1000) + 900,
      'Retry-After': 900
    });

    res.status(429).json({
      error: 'rate_limit_exceeded',
      message: 'Too many requests',
      retry_after: 900
    });
  }
});
```

## Sécurité avancée

### Protection contre les bots

```javascript
// ✅ Captcha pour les endpoints sensibles
const captchaRequired = (req, res, next) => {
  const captchaToken = req.body['g-recaptcha-response'];

  if (!captchaToken) {
    return res.status(400).json({
      error: 'captcha_required',
      message: 'Please complete the captcha'
    });
  }

  // Vérifier le token captcha
  verifyCaptcha(captchaToken)
    .then(() => next())
    .catch(() => res.status(400).json({ error: 'Invalid captcha' }));
};

app.post('/api/auth/register', captchaRequired, registerUser);
```

### Validation des requêtes

```javascript
const Joi = require('joi');

// ✅ Schémas de validation
const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)')).required(),
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
  role: Joi.string().valid('user', 'admin').optional()
});

const validateUser = (req, res, next) => {
  const { error } = userSchema.validate(req.body);

  if (error) {
    return res.status(400).json({
      error: 'validation_error',
      message: 'Invalid request data',
      details: error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context.value
      }))
    });
  }

  next();
};

app.post('/api/users', validateUser, createUser);
```

### Sanitisation des données

```javascript
const DOMPurify = require('isomorphic-dompurify');

// ✅ Nettoyage des données HTML
const sanitizeHTML = (req, res, next) => {
  if (req.body.content) {
    req.body.content = DOMPurify.sanitize(req.body.content);
  }

  if (req.body.description) {
    req.body.description = DOMPurify.sanitize(req.body.description);
  }

  next();
};

// ✅ Validation des URLs
const validateURL = (req, res, next) => {
  const urlRegex = /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/;

  if (req.body.website && !urlRegex.test(req.body.website)) {
    return res.status(400).json({
      error: 'invalid_url',
      message: 'Website URL is not valid'
    });
  }

  next();
};
```

### Protection CSRF

```javascript
const csrf = require('csurf');

// ✅ Protection CSRF pour les formulaires
const csrfProtection = csrf({
  cookie: {
    key: '_csrf',
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
});

// ✅ Exception pour les API
const csrfAPIException = (req, res, next) => {
  if (req.headers['content-type']?.includes('application/json')) {
    return next(); // Pas de CSRF pour les APIs JSON
  }
  return csrfProtection(req, res, next);
};

app.use('/web', csrfProtection); // Protection pour les pages web
app.use('/api', csrfAPIException); // Pas de protection pour les APIs
```

## Monitoring et alertes

### Logs de sécurité

```javascript
// ✅ Middleware de logging sécurité
const securityLogger = (req, res, next) => {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent');
  const userId = req.user?.id || 'anonymous';

  const logEntry = {
    timestamp,
    ip,
    userAgent,
    userId,
    method: req.method,
    url: req.originalUrl,
    status: res.statusCode,
    responseTime: Date.now() - req.startTime
  };

  // Log des requêtes suspectes
  if (res.statusCode >= 400) {
    console.warn('Security event:', logEntry);
  }

  next();
};

// ✅ Monitoring des tentatives d'intrusion
const intrusionDetector = (req, res, next) => {
  const suspiciousPatterns = [
    /\.\.\//,  // Path traversal
    /<script/i, // XSS attempts
    /union.*select/i, // SQL injection
    /eval\(/i, // Code injection
    /javascript:/i // JavaScript URLs
  ];

  const requestData = JSON.stringify(req.body) + req.originalUrl + req.get('User-Agent');

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(requestData)) {
      // Alerter et bloquer
      securityLogger.log('INTRUSION_ATTEMPT', {
        ip: req.ip,
        pattern: pattern.toString(),
        request: requestData
      });

      return res.status(403).json({
        error: 'forbidden',
        message: 'Suspicious request detected'
      });
    }
  }

  next();
};
```

### Alertes en temps réel

```javascript
// ✅ Système d'alertes
const alertSystem = {
  rateLimitBreached: (req, limit, windowMs) => {
    console.error(`Rate limit breached by ${req.ip}: ${limit} requests in ${windowMs}ms`);

    // Envoyer une alerte
    sendAlert('RATE_LIMIT_BREACH', {
      ip: req.ip,
      limit,
      windowMs,
      endpoint: req.originalUrl,
      userAgent: req.get('User-Agent')
    });
  },

  suspiciousActivity: (req, activity) => {
    console.error(`Suspicious activity detected: ${activity}`);

    sendAlert('SUSPICIOUS_ACTIVITY', {
      ip: req.ip,
      activity,
      endpoint: req.originalUrl,
      timestamp: new Date().toISOString()
    });
  },

  authFailure: (req, reason) => {
    console.warn(`Authentication failure: ${reason}`);

    // Compter les échecs par IP
    const failures = getAuthFailures(req.ip) + 1;
    saveAuthFailure(req.ip, failures);

    if (failures >= 5) {
      // Bloquer l'IP temporairement
      blockIP(req.ip, 60 * 60 * 1000); // 1 heure
      sendAlert('BRUTE_FORCE_ATTACK', { ip: req.ip, failures });
    }
  }
};
```

## Configuration de production

### Environment de production

```javascript
// ✅ Configuration CORS production
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy violation'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  exposedHeaders: [
    'X-Total-Count',
    'X-Rate-Limit-Limit',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset'
  ],
  maxAge: 86400, // 24 heures
  optionsSuccessStatus: 200
};

app.use('/api', cors(corsOptions));
```

### Rate Limiting en production

```javascript
// ✅ Configuration rate limiting production
const createRateLimit = (options) => {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    message: {
      error: 'rate_limit_exceeded',
      message: 'Too many requests, please try again later',
      retry_after: Math.ceil(options.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      // Utiliser l'IP ou l'utilisateur
      return req.user?.id || req.ip || req.connection.remoteAddress;
    },
    skip: (req) => {
      // Exceptions pour les admins ou IPs de confiance
      const trustedIPs = process.env.TRUSTED_IPS?.split(',') || [];
      return trustedIPs.includes(req.ip);
    },
    onLimitReached: (req, res) => {
      // Logging et alertes
      console.warn(`Rate limit reached for ${req.ip} on ${req.originalUrl}`);
      sendAlert('RATE_LIMIT_REACHED', {
        ip: req.ip,
        endpoint: req.originalUrl,
        userId: req.user?.id
      });
    }
  });
};

// ✅ Limites par type d'utilisateur
const rateLimits = {
  anonymous: createRateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
  }),

  authenticated: createRateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000
  }),

  premium: createRateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10000
  }),

  admin: createRateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100000
  })
};

const getRateLimiter = (req) => {
  if (req.user?.role === 'admin') return rateLimits.admin;
  if (req.user?.tier === 'premium') return rateLimits.premium;
  if (req.user) return rateLimits.authenticated;
  return rateLimits.anonymous;
};

app.use('/api', (req, res, next) => {
  const limiter = getRateLimiter(req);
  limiter(req, res, next);
});
```

## Tests de sécurité

### Tests CORS

```javascript
// tests/cors.test.js
const request = require('supertest');
const app = require('../app');

describe('CORS', () => {
  test('should allow requests from allowed origins', async () => {
    const response = await request(app)
      .get('/api/users')
      .set('Origin', 'https://myapp.com')
      .expect(200);

    expect(response.headers['access-control-allow-origin']).toBe('https://myapp.com');
    expect(response.headers['access-control-allow-credentials']).toBe('true');
  });

  test('should reject requests from disallowed origins', async () => {
    const response = await request(app)
      .get('/api/users')
      .set('Origin', 'https://malicious.com')
      .expect(403); // Ou 200 avec Origin null

    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('should handle preflight requests', async () => {
    const response = await request(app)
      .options('/api/users')
      .set('Origin', 'https://myapp.com')
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'Content-Type, Authorization')
      .expect(204);

    expect(response.headers['access-control-allow-methods']).toContain('POST');
    expect(response.headers['access-control-allow-headers']).toContain('Authorization');
  });
});
```

### Tests Rate Limiting

```javascript
// tests/rate-limiting.test.js
describe('Rate Limiting', () => {
  test('should limit anonymous requests', async () => {
    // Faire max + 1 requêtes
    for (let i = 0; i <= 100; i++) {
      await request(app)
        .get('/api/users')
        .expect(i < 100 ? 200 : 429);
    }
  });

  test('should provide rate limit headers', async () => {
    const response = await request(app)
      .get('/api/users')
      .expect(200);

    expect(response.headers['x-ratelimit-limit']).toBeDefined();
    expect(response.headers['x-ratelimit-remaining']).toBeDefined();
    expect(response.headers['x-ratelimit-reset']).toBeDefined();
  });

  test('should not limit admin users', async () => {
    const adminToken = generateAdminToken();

    // Faire beaucoup de requêtes admin
    for (let i = 0; i < 1000; i++) {
      await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
    }
  });
});
```

## Quiz CORS et Rate Limiting

**Question 1** : Quand utiliser CORS ?
**Réponse** : Pour les requêtes cross-origin depuis les navigateurs

**Question 2** : Quelle est l'unité du Rate Limiting ?
**Réponse** : Nombre de requêtes par intervalle de temps (ex: 100 requêtes par 15 minutes)

**Question 3** : Comment protéger contre les attaques XSS ?
**Réponse** : Sanitisation des données HTML et validation des entrées

## En résumé

### CORS
- 🌐 **Cross-Origin** protection des navigateurs
- ✅ **Configuration** des origines autorisées
- 🔑 **Credentials** pour l'authentification
- 📋 **Preflight** pour les requêtes complexes
- 🛡️ **Sécurité** des APIs web

### Rate Limiting
- 🚦 **Contrôle** du trafic
- 🛡️ **Protection DDoS** et scraping
- 💰 **Plans tarifaires** différents
- 📊 **Monitoring** des abus
- ⚡ **Performance** du serveur

### Configuration recommandée
```javascript
// CORS sécurisé
{
  origin: ['https://myapp.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  maxAge: 86400
}

// Rate Limiting échelonné
{
  anonymous: 100/15min,
  user: 1000/15min,
  premium: 10000/15min,
  admin: 100000/15min
}
```

### Bonnes pratiques
- ✅ **HTTPS** obligatoire
- ✅ **Validation** de toutes les entrées
- ✅ **Rate Limiting** adaptatif
- ✅ **Logging** complet des événements
- ✅ **Alertes** automatiques

### Sécurité complète
```javascript
// Stack de sécurité complet
app.use(helmet());                    // Headers de sécurité
app.use(cors(corsOptions));           // CORS configuré
app.use(rateLimit(limiter));          // Rate limiting
app.use(sanitizeInput);               // Sanitisation
app.use(authenticate);                // Authentification
app.use(authorize);                   // Autorisation
```

Dans le prochain chapitre, nous explorerons le **chiffrement** et la sécurité du transport avec HTTPS et TLS !

---

**Prochain chapitre** : [04-Chiffrement-HTTPS-TLS](04-Chiffrement-HTTPS-TLS.md)
