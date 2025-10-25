# Versionning de l'API

## Introduction

Les APIs évoluent avec le temps. De nouvelles fonctionnalités sont ajoutées, des bugs sont corrigés, et parfois des changements cassants sont nécessaires. Le **versionning** permet de gérer cette évolution tout en maintenant la **compatibilité** avec les clients existants. Dans ce chapitre, nous allons explorer les différentes stratégies de versionning et apprendre à faire évoluer votre API de manière responsable.

## Pourquoi versionner une API ?

### 1. Évolution inévitable

```javascript
// Version 1.0 - Initiale
GET /api/users/123
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com"
}

// Version 2.0 - Ajout de champs
GET /api/users/123
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "avatar": "https://...",
  "preferences": {...}
}
```

### 2. Clients existants

```javascript
// Client existant qui attend le format v1
const response = await fetch('/api/users/123');
const user = await response.json();

// ❌ Si format change sans versionning
// user.phone  // undefined - casse le client !

// ✅ Avec versionning
// Client peut migrer à son rythme vers v2
```

### 3. Expérimentation

```javascript
// Tester de nouvelles fonctionnalités
GET /api/v2/users/123/enhanced  // Version expérimentale
GET /api/beta/users/123          // Version beta
```

## Stratégies de versionning

### 1. Version dans l'URL

#### URI Versioning

```javascript
// ✅ Version explicite dans le path
GET /api/v1/users
GET /api/v2/users
GET /api/v2.1/users
GET /api/v3/users

// ✅ Avantages
✅ URLs claires et explicites
✅ Cache par version
✅ Migration progressive

// ✅ Inconvénients
❌ URLs "cassées" lors des upgrades
❌ Maintenance de multiples versions
❌ URLs plus longues
```

#### Implémentation
```javascript
// Express avec version dans l'URL
const express = require('express');
const app = express();

// Route v1
app.use('/api/v1', require('./routes/v1'));

// Route v2
app.use('/api/v2', require('./routes/v2'));

// Routes v1
const v1Routes = express.Router();
v1Routes.get('/users', getUsersV1);
v1Routes.get('/users/:id', getUserV1);

// Routes v2
const v2Routes = express.Router();
v2Routes.get('/users', getUsersV2);
v2Routes.get('/users/:id', getUserV2);
```

### 2. Version dans les headers

#### Accept Header Versioning

```javascript
// ✅ Version via header Accept
GET /api/users
Accept: application/vnd.api+json; version=1

GET /api/users
Accept: application/vnd.api+json; version=2

// ✅ Avantages
✅ URLs propres et stables
✅ Migration transparente
✅ Une seule URL active

// ✅ Inconvénients
❌ Moins visible pour les développeurs
❌ Configuration client plus complexe
❌ Cache plus difficile
```

#### Content-Type Versioning

```javascript
// Version dans le media type
GET /api/users
Accept: application/vnd.myapi.v1+json

GET /api/users
Accept: application/vnd.myapi.v2+json

// Format JSON API
GET /api/users
Accept: application/vnd.api+json;profile="https://example.com/v1"
```

#### Implémentation
```javascript
app.get('/api/users', (req, res) => {
  const version = extractVersionFromHeaders(req);
  const users = getUsers(version);

  if (version === 'v2') {
    res.set('Content-Type', 'application/vnd.myapi.v2+json');
    res.json(formatUsersV2(users));
  } else {
    res.set('Content-Type', 'application/vnd.myapi.v1+json');
    res.json(formatUsersV1(users));
  }
});

function extractVersionFromHeaders(req) {
  // Version dans Accept header
  const accept = req.headers.accept;
  const versionMatch = accept.match(/version=(\d+)/);
  if (versionMatch) return `v${versionMatch[1]}`;

  // Version dans Content-Type
  const contentType = req.headers['content-type'] || '';
  const mediaTypeMatch = contentType.match(/vnd\.myapi\.v(\d+)\+json/);
  if (mediaTypeMatch) return `v${mediaTypeMatch[1]}`;

  // Version par défaut
  return 'v1';
}
```

### 3. Version dans le query parameter

```javascript
// ❌ Éviter - pas recommandé
GET /api/users?version=1
GET /api/users?version=2

// ✅ Inconvénients
❌ Cache cassé
❌ URLs moins RESTful
❌ Pas standard
```

### 4. Version dans le subdomain

```javascript
// Version dans le sous-domaine
GET /v1/api/users
GET /v2/api/users

// Avantages :
✅ URLs claires
✅ Cache indépendant

// Inconvénients :
❌ Configuration DNS complexe
❌ Moins standard
```

## Gestion des changements

### Types de changements

#### 1. Changements non-cassants (Non-breaking)

```javascript
// ✅ Ajout de champs optionnels
{
  "id": 123,
  "name": "John Doe"
  // Nouveau champ
  "phone": "+1234567890"  // Optionnel
}

// ✅ Ajout d'endpoints
POST /api/users/123/verify  // Nouveau endpoint

// ✅ Ajout de query parameters
GET /api/users?include=profile  // Nouveau paramètre
```

#### 2. Changements cassants (Breaking)

```javascript
// ❌ Renommage de champs
{
  "id": 123,
  "fullName": "John Doe"  // Au lieu de "name"
}

// ❌ Suppression de champs
{
  "id": 123
  // Plus de "name" !
}

// ❌ Changement de type
{
  "id": "123"  // String au lieu de number
}
```

### Stratégie de compatibilité

```javascript
// ✅ Support temporaire des deux formats
app.get('/api/users/:id', (req, res) => {
  const version = req.headers['api-version'] || 'v1';
  const user = getUserById(req.params.id);

  if (version === 'v2') {
    // Format v2 (nouveau)
    res.json({
      id: user.id,
      fullName: `${user.firstName} ${user.lastName}`,
      emailAddress: user.email
    });
  } else {
    // Format v1 (legacy)
    res.json({
      id: user.id,
      name: user.name,
      email: user.email
    });
  }
});
```

## Cycle de vie des versions

### 1. Développement (Development)

```javascript
// Version en développement
GET /api/dev/users
GET /api/beta/users

// Marquage explicite
{
  "_meta": {
    "version": "beta",
    "stability": "experimental",
    "deprecation_date": "2024-06-01"
  }
}
```

### 2. Release (Production)

```javascript
// Version stable
GET /api/v1/users  // Actuelle
GET /api/v2/users  // Nouvelle

// Support des deux versions
app.use('/api/v1', v1Routes);
app.use('/api/v2', v2Routes);
```

### 3. Dépréciation (Deprecation)

```javascript
// Headers de dépréciation
app.get('/api/v1/users', (req, res) => {
  res.set({
    'Warning': '299 api.example.com "v1 API deprecated, migrate to v2"',
    'Sunset': 'Sun, 31 Dec 2023 23:59:59 GMT'
  });

  res.json(getUsersV1());
});
```

### 4. Retrait (Sunsetting)

```javascript
// Redirection vers nouvelle version
app.get('/api/v1/*', (req, res) => {
  res.status(301)
     .header('Location', req.path.replace('/v1/', '/v2/'))
     .json({
       error: 'API version deprecated',
       message: 'This API version has been removed. Please use v2.',
       migration_guide: 'https://docs.example.com/migration-v1-to-v2'
     });
});
```

## Migration entre versions

### Stratégie de migration progressive

```javascript
// 1. Annonce de la nouvelle version
app.get('/api/v1/users', (req, res) => {
  res.set({
    'API-Versions': 'v1, v2',
    'Recommended-Version': 'v2',
    'Migration-Guide': 'https://docs.example.com/migration'
  });

  res.json(getUsersV1());
});

// 2. Support temporaire des deux versions
app.get('/api/v2/users', (req, res) => {
  res.json(getUsersV2());
});

// 3. Migration forcée après délai
const GRACE_PERIOD = 6 * 30 * 24 * 60 * 60 * 1000; // 6 mois

app.use('/api/v1', (req, res, next) => {
  const deprecationDate = new Date('2023-07-01');
  const now = new Date();

  if (now > deprecationDate) {
    return res.status(410).json({
      error: 'API version removed',
      message: 'v1 API has been permanently removed',
      upgrade_to: '/api/v2'
    });
  }

  res.set('Warning', '299 "v1 API deprecated"');
  next();
});
```

### Outils de migration

```javascript
// Script de migration automatique
const migrateUserData = (userV1) => {
  return {
    // Mapping des champs v1 vers v2
    id: userV1.id,
    fullName: userV1.name,  // name → fullName
    emailAddress: userV1.email,  // email → emailAddress
    phoneNumber: userV1.phone || null,  // Nouveau champ

    // Transformation des relations
    profile: {
      bio: userV1.bio,
      avatarUrl: userV1.avatar
    }
  };
};
```

## Gestion des erreurs de version

### Version non supportée

```javascript
app.use('/api', (req, res, next) => {
  const version = extractVersion(req);

  if (!SUPPORTED_VERSIONS.includes(version)) {
    return res.status(406).json({
      error: 'Version not supported',
      message: `Version ${version} is not supported`,
      supported_versions: SUPPORTED_VERSIONS,
      latest_version: LATEST_VERSION
    });
  }

  next();
});
```

### Fallback automatique

```javascript
// Fallback vers version par défaut
app.get('/api/users', (req, res) => {
  const version = req.headers['api-version'] || 'v1';

  switch (version) {
    case 'v2':
      res.json(getUsersV2());
      break;
    case 'v1':
    default:
      res.json(getUsersV1());
      break;
  }
});
```

## Documentation des versions

### Changelog API

```json
// GET /api/versions
{
  "versions": [
    {
      "version": "v2.1",
      "release_date": "2023-10-25",
      "status": "current",
      "changes": [
        "Added phone field to users",
        "Added pagination metadata",
        "Fixed bug in user search"
      ]
    },
    {
      "version": "v2.0",
      "release_date": "2023-07-01",
      "status": "supported",
      "changes": [
        "Breaking: Changed name to fullName",
        "Breaking: Changed email to emailAddress",
        "Added profile embedding"
      ]
    },
    {
      "version": "v1.0",
      "release_date": "2023-01-01",
      "status": "deprecated",
      "sunset_date": "2023-12-31",
      "changes": [
        "Initial release"
      ]
    }
  ]
}
```

### Guide de migration

```json
// GET /api/migration/v1-to-v2
{
  "from_version": "v1",
  "to_version": "v2",
  "breaking_changes": [
    {
      "type": "field_renamed",
      "old_field": "name",
      "new_field": "fullName",
      "example": {
        "old": {"name": "John Doe"},
        "new": {"fullName": "John Doe"}
      }
    },
    {
      "type": "field_added",
      "new_field": "phone",
      "required": false,
      "description": "Optional phone number"
    }
  ],
  "migration_steps": [
    "Update your API calls to use /api/v2/",
    "Change 'name' to 'fullName' in your code",
    "Add 'phone' field if needed",
    "Test your integration"
  ],
  "testing_endpoint": "/api/v2/test"
}
```

## Exemple complet de versioning

### Structure des routes

```javascript
// routes/v1.js
const express = require('express');
const router = express.Router();

router.get('/users', getUsersV1);
router.get('/users/:id', getUserV1);
router.post('/users', createUserV1);

// routes/v2.js
const express = require('express');
const router = express.Router();

router.get('/users', getUsersV2);
router.get('/users/:id', getUserV2);
router.post('/users', createUserV2);

// routes/current.js (alias vers la version actuelle)
router.use('/api', require('./routes/v2'));
```

### Implémentation des versions

```javascript
// controllers/v1/users.js
const getUsersV1 = async (req, res) => {
  const users = await User.findAll({
    attributes: ['id', 'name', 'email', 'createdAt']
  });

  res.json({
    users: users,
    total: users.length
  });
};

// controllers/v2/users.js
const getUsersV2 = async (req, res) => {
  const { page, limit, include } = req.query;

  const options = {
    limit: parseInt(limit) || 10,
    offset: (parseInt(page) - 1) * parseInt(limit) || 0
  };

  if (include === 'profile') {
    options.include = [{
      model: Profile,
      attributes: ['bio', 'avatar']
    }];
  }

  const result = await User.findAndCountAll(options);

  res.json({
    data: result.rows,
    pagination: {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 10,
      total: result.count,
      total_pages: Math.ceil(result.count / (parseInt(limit) || 10))
    },
    _links: {
      self: `/api/v2/users?page=${page}&limit=${limit}`,
      next: getNextPageUrl(page, limit, result.count),
      prev: getPrevPageUrl(page, limit)
    }
  });
};
```

### Middleware de versioning

```javascript
// middleware/versioning.js
const SUPPORTED_VERSIONS = ['v1', 'v2'];
const DEFAULT_VERSION = 'v2';
const DEPRECATED_VERSIONS = ['v1'];

const versionMiddleware = (req, res, next) => {
  // Extraction de la version
  let version = req.headers['api-version'] ||
                req.headers['accept-version'] ||
                req.params.version ||
                DEFAULT_VERSION;

  // Nettoyage de la version
  version = version.replace('v', '').replace('/', '');

  // Validation
  if (!SUPPORTED_VERSIONS.includes(`v${version}`)) {
    return res.status(406).json({
      error: 'Version not supported',
      supported_versions: SUPPORTED_VERSIONS,
      requested_version: version
    });
  }

  // Headers de dépréciation
  if (DEPRECATED_VERSIONS.includes(`v${version}`)) {
    res.set({
      'Warning': `299 "Version v${version} is deprecated"`,
      'Sunset': 'Sun, 31 Dec 2023 23:59:59 GMT',
      'Link': `</api/migration/v${version}-to-v2>; rel="migration"`
    });
  }

  // Stockage de la version pour les contrôleurs
  req.apiVersion = `v${version}`;
  res.locals.apiVersion = `v${version}`;

  next();
};

module.exports = versionMiddleware;
```

### Tests par version

```javascript
// tests/v1/users.test.js
describe('Users API v1', () => {
  test('should return users in v1 format', async () => {
    const response = await request(app)
      .get('/api/v1/users')
      .expect(200);

    expect(response.body).toHaveProperty('users');
    expect(response.body).toHaveProperty('total');
    expect(response.body.users[0]).not.toHaveProperty('fullName');
  });
});

// tests/v2/users.test.js
describe('Users API v2', () => {
  test('should return users in v2 format', async () => {
    const response = await request(app)
      .get('/api/v2/users')
      .expect(200);

    expect(response.body).toHaveProperty('data');
    expect(response.body).toHaveProperty('pagination');
    expect(response.body.data[0]).toHaveProperty('fullName');
  });
});
```

## Bonnes pratiques de versionning

### 1. Planifiez à l'avance

```javascript
// ✅ Roadmap de versions
const VERSION_ROADMAP = {
  'v1': {
    status: 'deprecated',
    sunset_date: '2023-12-31',
    breaking_changes: []
  },
  'v2': {
    status: 'current',
    release_date: '2023-07-01',
    features: ['pagination', 'embedding', 'filtering']
  },
  'v3': {
    status: 'planned',
    release_date: '2024-01-01',
    features: ['graphql', 'realtime', 'advanced-search']
  }
};
```

### 2. Communiquez clairement

```javascript
// ✅ Headers informatifs
res.set({
  'API-Version': 'v2',
  'Supported-Versions': 'v1, v2',
  'Latest-Version': 'v2',
  'Deprecation-Info': 'v1 deprecated, use v2'
});
```

### 3. Testez les migrations

```javascript
// ✅ Tests de compatibilité
describe('Version Compatibility', () => {
  test('v1 to v2 migration should work', async () => {
    const v1Response = await getUsersV1();
    const v2Response = await getUsersV2();

    // Vérifier que la migration est possible
    expect(migrateV1toV2(v1Response)).toEqual(v2Response);
  });
});
```

### 4. Documentez tout

```yaml
# OpenAPI avec versions
openapi: 3.0.0
info:
  title: User API
  version: 2.0.0
  description: |
    User management API

    ## Version History
    - **v2.0** (Current): Added pagination and embedding
    - **v1.0** (Deprecated): Basic CRUD operations

paths:
  /api/v2/users:
    get:
      summary: Get users (v2)
      # ... spécification v2

  /api/v1/users:
    get:
      summary: Get users (v1) - DEPRECATED
      deprecated: true
      # ... spécification v1
```

## Quiz du versionning

**Question 1** : Quelle est la stratégie de versionning la plus recommandée ?
**Réponse** : Version dans l'URL pour la simplicité, headers pour la propreté

**Question 2** : Comment gérer un changement cassant ?
**Réponse** : Créer une nouvelle version, supporter l'ancienne temporairement

**Question 3** : Quand retirer une version dépréciée ?
**Réponse** : Après un délai raisonnable (3-6 mois) avec communication

## En résumé

### Stratégies de versionning
1. **URL Versioning** : `/api/v1/`, `/api/v2/`
2. **Header Versioning** : `Accept: version=1`
3. **Content-Type** : `application/vnd.api.v1+json`
4. **Subdomain** : `/v1/api/`

### Cycle de vie
1. **Development** : Versions beta/dev
2. **Production** : Versions stables
3. **Deprecation** : Annonce de suppression
4. **Sunsetting** : Retrait définitif

### Bonnes pratiques
- ✅ **Planifiez** les versions à l'avance
- ✅ **Communiquez** les changements
- ✅ **Supportez** temporairement les versions
- ✅ **Documentez** les migrations
- ✅ **Testez** la compatibilité

### Exemple de versioning réussi
```javascript
// Migration progressive
GET /api/v1/users  // Format legacy (deprecated)
GET /api/v2/users  // Format moderne (current)
GET /api/users     // Format actuel (v2 par défaut)
```

Dans le prochain chapitre, nous verrons comment **documenter** votre API avec OpenAPI et créer une documentation interactive pour vos développeurs !

---

**Prochain chapitre** : [05-Documentation-OpenAPI](05-Documentation-OpenAPI.md)
