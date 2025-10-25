# Statuts HTTP

## Introduction

Les **codes de statut HTTP** sont le langage que votre API utilise pour communiquer avec les clients. Bien plus que de simples numéros, ils portent une sémantique précise qui indique le résultat de chaque requête. Dans ce chapitre, nous allons explorer tous les codes de statut pertinents pour les APIs REST et apprendre à les utiliser correctement.

## Structure des codes de statut

Les codes de statut HTTP sont organisés en 5 classes principales :

```
┌─────────────────────────────────────────────────────────────┐
│                    Codes de statut HTTP                     │
├─────────────────────────────────────────────────────────────┤
│ 1xx Information    │ 2xx Succès    │ 3xx Redirection │ 4xx │
│ 100 Continue       │ 200 OK        │ 301 Moved       │ 400 │
│ 101 Switching      │ 201 Created   │ 302 Found       │ 401 │
│ 102 Processing     │ 202 Accepted  │ 304 Not Mod.    │ 403 │
│                    │ 204 No Content│                 │ 404 │
│                    │               │                 │ 422 │
├────────────────────┼───────────────┼─────────────────┼─────┤
│ 5xx Erreur serveur │               │                 │     │
│ 500 Internal Error │               │                 │     │
│ 502 Bad Gateway    │               │                 │     │
│ 503 Service Unav.  │               │                 │     │
└────────────────────┴───────────────┴─────────────────┴─────┘
```

## Codes 2xx : Succès

### 200 OK

**Le plus courant des codes de succès**

```javascript
// GET - Ressource trouvée
app.get('/api/users/123', (req, res) => {
  const user = getUserById(req.params.id);
  res.status(200).json(user);
});

// PUT - Ressource mise à jour
app.put('/api/users/123', (req, res) => {
  const updatedUser = updateUser(req.params.id, req.body);
  res.status(200).json(updatedUser);
});
```

### 201 Created

**Ressource créée avec succès**

```javascript
// POST - Nouvelle ressource
app.post('/api/users', (req, res) => {
  const newUser = createUser(req.body);
  res.status(201).json(newUser);
});

// Headers recommandés avec 201
app.post('/api/users', (req, res) => {
  const newUser = createUser(req.body);

  res.status(201)
     .header('Location', `/api/users/${newUser.id}`)
     .header('Content-Type', 'application/json')
     .json(newUser);
});
```

### 202 Accepted

**Requête acceptée pour traitement asynchrone**

```javascript
// Traitement en arrière-plan
app.post('/api/reports/generate', (req, res) => {
  // Démarrer la génération en asynchrone
  generateReportAsync(req.body)
    .then(reportId => {
      // Stocker l'état du job
      jobStatus[reportId] = 'processing';
    });

  res.status(202)
     .header('Location', `/api/reports/status/${reportId}`)
     .json({
       message: 'Report generation started',
       reportId: reportId,
       status: 'processing'
     });
});
```

### 204 No Content

**Succès sans contenu à retourner**

```javascript
// DELETE - Ressource supprimée
app.delete('/api/users/123', (req, res) => {
  deleteUser(req.params.id);
  res.status(204).send(); // Pas de body
});

// PUT - Mise à jour réussie
app.put('/api/users/123/preferences', (req, res) => {
  updateUserPreferences(req.params.id, req.body);
  res.status(204).send(); // Pas de body nécessaire
});
```

## Codes 3xx : Redirection

### 301 Moved Permanently

**Redirection permanente**

```javascript
// API déplacée définitivement
app.get('/api/v1/users', (req, res) => {
  res.redirect(301, '/api/v2/users');
});

// Ressource déplacée
app.get('/api/users/123', (req, res) => {
  // L'utilisateur a changé d'ID
  res.redirect(301, '/api/users/456');
});
```

### 302 Found

**Redirection temporaire**

```javascript
// Maintenance temporaire
app.get('/api/users', (req, res) => {
  if (isMaintenanceMode()) {
    return res.redirect(302, '/api/maintenance');
  }
  // Logique normale
});
```

### 304 Not Modified

**Ressource non modifiée (cache)**

```javascript
app.get('/api/users/123', (req, res) => {
  const user = getUserById(req.params.id);
  const lastModified = new Date(user.updatedAt);
  const ifModifiedSince = req.headers['if-modified-since'];

  if (ifModifiedSince && lastModified <= new Date(ifModifiedSince)) {
    return res.status(304).send(); // Pas de body
  }

  res.set('Last-Modified', lastModified.toUTCString());
  res.json(user);
});
```

## Codes 4xx : Erreur client

### 400 Bad Request

**Requête malformée**

```javascript
// Paramètres invalides
app.get('/api/users', (req, res) => {
  const limit = parseInt(req.query.limit);
  if (isNaN(limit) || limit < 0 || limit > 100) {
    return res.status(400).json({
      error: 'Invalid limit parameter',
      message: 'Limit must be between 0 and 100'
    });
  }
  // Logique normale
});

// Body JSON invalide
app.post('/api/users', (req, res) => {
  if (!req.body.name || typeof req.body.name !== 'string') {
    return res.status(400).json({
      error: 'Invalid user data',
      message: 'Name is required and must be a string'
    });
  }
  // Logique normale
});
```

### 401 Unauthorized

**Authentification requise**

```javascript
// Protection par authentification
app.get('/api/users', (req, res) => {
  if (!req.headers.authorization) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please provide a valid API key'
    });
  }

  // Vérifier le token
  const token = req.headers.authorization.replace('Bearer ', '');
  if (!verifyToken(token)) {
    return res.status(401).json({
      error: 'Invalid token',
      message: 'The provided token is not valid'
    });
  }
  // Logique normale
});
```

### 403 Forbidden

**Accès refusé (authentifié mais non autorisé)**

```javascript
// Autorisation basée sur les rôles
app.delete('/api/users/123', (req, res) => {
  const user = getCurrentUser(req);
  const targetUser = getUserById(req.params.id);

  if (user.role !== 'admin' && user.id !== targetUser.id) {
    return res.status(403).json({
      error: 'Access denied',
      message: 'You can only delete your own account'
    });
  }

  deleteUser(req.params.id);
  res.status(204).send();
});
```

### 404 Not Found

**Ressource inexistante**

```javascript
// Ressource non trouvée
app.get('/api/users/999', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({
      error: 'User not found',
      message: `No user found with id ${req.params.id}`
    });
  }
  res.json(user);
});

// Endpoint inexistant
app.get('/api/nonexistent', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: 'The requested endpoint does not exist'
  });
});
```

### 409 Conflict

**Conflit avec l'état actuel**

```javascript
// Ressource déjà existante
app.post('/api/users', (req, res) => {
  const existingUser = findUserByEmail(req.body.email);
  if (existingUser) {
    return res.status(409).json({
      error: 'User already exists',
      message: 'A user with this email already exists'
    });
  }

  const newUser = createUser(req.body);
  res.status(201).json(newUser);
});

// Version conflict
app.put('/api/users/123', (req, res) => {
  const currentVersion = getUserVersion(req.params.id);
  const clientVersion = req.headers['if-match'];

  if (clientVersion && clientVersion !== currentVersion) {
    return res.status(409).json({
      error: 'Version conflict',
      message: 'The resource has been modified since your last request'
    });
  }
  // Logique normale
});
```

### 422 Unprocessable Entity

**Entité non traitable (validation)**

```javascript
// Validation métier
app.post('/api/users', (req, res) => {
  const errors = validateUser(req.body);

  if (errors.length > 0) {
    return res.status(422).json({
      error: 'Validation failed',
      message: 'The provided data is not valid',
      details: errors
    });
  }

  const newUser = createUser(req.body);
  res.status(201).json(newUser);
});

// Exemple de fonction de validation
function validateUser(userData) {
  const errors = [];

  if (!userData.name || userData.name.length < 2) {
    errors.push({ field: 'name', message: 'Name must be at least 2 characters' });
  }

  if (!userData.email || !isValidEmail(userData.email)) {
    errors.push({ field: 'email', message: 'Valid email is required' });
  }

  if (userData.age && (userData.age < 13 || userData.age > 120)) {
    errors.push({ field: 'age', message: 'Age must be between 13 and 120' });
  }

  return errors;
}
```

## Codes 5xx : Erreur serveur

### 500 Internal Server Error

**Erreur interne générique**

```javascript
// Erreur non gérée
app.get('/api/users', (req, res) => {
  try {
    const users = getUsersFromDatabase();
    res.json(users);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An unexpected error occurred'
    });
  }
});
```

### 502 Bad Gateway

**Serveur proxy en erreur**

```javascript
// Proxy vers un autre service
app.get('/api/external-data', async (req, res) => {
  try {
    const response = await fetch('https://external-api.com/data');
    if (!response.ok) {
      return res.status(502).json({
        error: 'Bad gateway',
        message: 'External service returned an error'
      });
    }
    res.json(await response.json());
  } catch (error) {
    res.status(502).json({
      error: 'Bad gateway',
      message: 'Unable to reach external service'
    });
  }
});
```

### 503 Service Unavailable

**Service temporairement indisponible**

```javascript
// Maintenance programmée
app.use('/api', (req, res, next) => {
  if (isMaintenanceMode()) {
    return res.status(503).json({
      error: 'Service unavailable',
      message: 'API is currently under maintenance',
      retry_after: '2023-10-25T14:00:00Z'
    });
  }
  next();
});

// Surcharge du système
app.get('/api/users', (req, res) => {
  if (getCurrentLoad() > 0.9) {
    return res.status(503).json({
      error: 'Service unavailable',
      message: 'Server is currently overloaded',
      retry_after: 60
    });
  }
  // Logique normale
});
```

## Codes moins courants mais utiles

### 1xx : Information

```javascript
// 100 Continue
app.post('/api/large-upload', (req, res) => {
  if (req.headers['expect'] === '100-continue') {
    res.status(100).send();
  }
  // Continuer le traitement
});

// 101 Switching Protocols
app.get('/api/websocket', (req, res) => {
  if (req.headers.upgrade === 'websocket') {
    res.status(101).send();
    // Upgrade vers WebSocket
  }
});
```

### 405 Method Not Allowed

```javascript
// Méthode non supportée
app.get('/api/users/123', (req, res) => {
  res.set('Allow', 'GET, PUT, DELETE');
  res.status(405).json({
    error: 'Method not allowed',
    message: 'PUT method is not supported on this endpoint'
  });
});
```

### 410 Gone

**Ressource supprimée définitivement**

```javascript
// Ressource archivée
app.get('/api/users/123', (req, res) => {
  const user = getUserById(req.params.id);
  if (user && user.status === 'archived') {
    return res.status(410).json({
      error: 'Resource gone',
      message: 'This user has been permanently removed'
    });
  }
  // Logique normale
});
```

### 429 Too Many Requests

**Rate limiting**

```javascript
// Limitation du nombre de requêtes
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limite de 100 requêtes par fenêtre
  message: {
    error: 'Too many requests',
    message: 'You have exceeded the rate limit',
    retry_after: 900 // 15 minutes en secondes
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api', limiter);
```

## Bonnes pratiques

### 1. Soyez spécifique

```javascript
// ❌ Évitez les 500 génériques
app.get('/api/users/123', (req, res) => {
  try {
    const user = getUserById(req.params.id);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// ✅ Utilisez des codes appropriés
app.get('/api/users/123', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({
      error: 'User not found',
      message: `No user found with id ${req.params.id}`
    });
  }

  if (user.isBlocked) {
    return res.status(403).json({
      error: 'Access denied',
      message: 'This user account has been blocked'
    });
  }

  res.json(user);
});
```

### 2. Fournissez des messages d'erreur utiles

```javascript
// ✅ Messages d'erreur informatifs
res.status(400).json({
  error: 'Invalid request',
  message: 'The request contains invalid parameters',
  details: {
    email: 'Must be a valid email address',
    age: 'Must be between 13 and 120'
  }
});

// ❌ Messages d'erreur génériques
res.status(400).json({ error: 'Bad request' });
```

### 3. Utilisez les headers appropriés

```javascript
// Headers pour les redirections
res.status(301)
   .header('Location', '/api/v2/users')
   .header('Cache-Control', 'public, max-age=31536000')
   .send();

// Headers pour le cache
res.status(200)
   .header('Cache-Control', 'public, max-age=3600')
   .header('ETag', '"abc123"')
   .json(data);

// Headers pour la pagination
res.status(200)
   .header('X-Total-Count', totalUsers)
   .header('X-Page', page)
   .header('X-Per-Page', perPage)
   .json(users);
```

## Gestion des erreurs centralisée

```javascript
// Middleware de gestion d'erreurs
app.use((error, req, res, next) => {
  console.error('Error:', error);

  // Erreurs de validation
  if (error.name === 'ValidationError') {
    return res.status(422).json({
      error: 'Validation failed',
      message: 'The provided data is not valid',
      details: error.details
    });
  }

  // Erreurs d'authentification
  if (error.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Valid credentials are required'
    });
  }

  // Erreurs de base de données
  if (error.code === 'DATABASE_ERROR') {
    return res.status(503).json({
      error: 'Service unavailable',
      message: 'Database is currently unavailable'
    });
  }

  // Erreur générique
  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred'
  });
});
```

## Exemple d'API avec codes de statut

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// GET /api/users
app.get('/api/users', (req, res) => {
  const users = getUsers({
    limit: req.query.limit,
    offset: req.query.offset,
    search: req.query.search
  });

  res.status(200)
     .header('X-Total-Count', users.total)
     .json(users.data);
});

// GET /api/users/123
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({
      error: 'User not found',
      message: `No user found with id ${req.params.id}`
    });
  }
  res.status(200).json(user);
});

// POST /api/users
app.post('/api/users', (req, res) => {
  const errors = validateUser(req.body);
  if (errors.length > 0) {
    return res.status(422).json({
      error: 'Validation failed',
      details: errors
    });
  }

  const existingUser = findUserByEmail(req.body.email);
  if (existingUser) {
    return res.status(409).json({
      error: 'User already exists',
      message: 'A user with this email already exists'
    });
  }

  const newUser = createUser(req.body);
  res.status(201)
     .header('Location', `/api/users/${newUser.id}`)
     .json(newUser);
});

// PUT /api/users/123
app.put('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({
      error: 'User not found'
    });
  }

  const updatedUser = updateUser(req.params.id, req.body);
  res.status(200).json(updatedUser);
});

// DELETE /api/users/123
app.delete('/api/users/:id', (req, res) => {
  const deleted = deleteUser(req.params.id);
  if (!deleted) {
    return res.status(404).json({
      error: 'User not found'
    });
  }
  res.status(204).send();
});
```

## Quiz des statuts HTTP

**Question 1** : Quel code utiliser pour une ressource créée ?
**Réponse** : 201 Created

**Question 2** : Quelle est la différence entre 401 et 403 ?
**Réponse** : 401 = non authentifié, 403 = authentifié mais non autorisé

**Question 3** : Quand utiliser 204 au lieu de 200 ?
**Réponse** : Quand il n'y a pas de contenu à retourner (DELETE, PUT sans réponse)

## Tableau de référence rapide

| Code | Nom | Usage | Body |
|------|-----|-------|------|
| **200** | OK | Succès standard | ✅ |
| **201** | Created | Ressource créée | ✅ |
| **202** | Accepted | Traitement asynchrone | ✅ |
| **204** | No Content | Succès sans contenu | ❌ |
| **301** | Moved Permanently | Redirection permanente | ❌ |
| **304** | Not Modified | Cache valide | ❌ |
| **400** | Bad Request | Requête invalide | ✅ |
| **401** | Unauthorized | Authentification requise | ✅ |
| **403** | Forbidden | Accès refusé | ✅ |
| **404** | Not Found | Ressource inexistante | ✅ |
| **409** | Conflict | Conflit d'état | ✅ |
| **422** | Unprocessable Entity | Validation échouée | ✅ |
| **429** | Too Many Requests | Rate limit | ✅ |
| **500** | Internal Server Error | Erreur serveur | ✅ |
| **502** | Bad Gateway | Proxy en erreur | ✅ |
| **503** | Service Unavailable | Service indisponible | ✅ |

## En résumé

### Principes clés
1. **Utilisez le bon code** pour chaque situation
2. **Soyez spécifique** dans les messages d'erreur
3. **Respectez la sémantique** HTTP
4. **Fournissez des headers** utiles
5. **Gérez les erreurs** de manière centralisée

### Codes les plus courants
- ✅ **200** : Succès standard
- ✅ **201** : Création réussie
- ✅ **204** : Succès sans contenu
- ✅ **400** : Requête invalide
- ✅ **401** : Authentification requise
- ✅ **403** : Accès refusé
- ✅ **404** : Ressource introuvable
- ✅ **422** : Validation échouée
- ✅ **500** : Erreur serveur

### Bonnes pratiques
- 🔄 **Redirigez** avec 301/302 quand approprié
- 📦 **Cachez** les GET avec 304
- 🛡️ **Protégez** avec 401/403
- ✅ **Validez** avec 422
- 🚦 **Limitez** avec 429

Dans le prochain chapitre, nous explorerons les **formats de représentation** et comment structurer les données de votre API !

---

**Prochain chapitre** : [05-Représentation-et-Formats](05-Représentation-et-Formats.md)
