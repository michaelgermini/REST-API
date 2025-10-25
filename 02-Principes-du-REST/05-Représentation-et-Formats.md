# Représentation et Formats

## Introduction

Dans le chapitre précédent, nous avons exploré les codes de statut HTTP. Maintenant, concentrons-nous sur le **contenu** des réponses : les **représentations** et les **formats de données**. Une API REST doit non seulement répondre correctement, mais aussi fournir des données dans des formats compréhensibles et efficaces pour les clients.

## Qu'est-ce qu'une représentation ?

### Définition

Une **représentation** est la façon dont une ressource est présentée au client. C'est la transformation d'une ressource interne en un format transmissible via HTTP.

```javascript
// Ressource interne (base de données)
const internalUser = {
  id: 123,
  firstName: "John",
  lastName: "Doe",
  emailAddress: "john@example.com",
  createdTimestamp: 1698172800000,
  isActiveFlag: true,
  roleId: 2
};

// Représentation externe (API)
const apiUser = {
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2023-10-25T10:30:00Z",
  "active": true,
  "role": "admin"
};
```

### Négociation de contenu

Le client peut spécifier le format souhaité via l'header `Accept` :

```http
# Client demande du JSON
GET /api/users/123
Accept: application/json

# Client demande du XML
GET /api/users/123
Accept: application/xml

# Client préfère JSON mais accepte HTML
GET /api/users/123
Accept: application/json, text/html
```

## Formats de données populaires

### 1. JSON (JavaScript Object Notation)

**Le format le plus utilisé pour les APIs REST**

```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "profile": {
    "avatar": "https://example.com/avatar.jpg",
    "bio": "Software developer"
  },
  "posts": [
    {
      "id": 1,
      "title": "Introduction à REST"
    },
    {
      "id": 2,
      "title": "API Design Best Practices"
    }
  ],
  "created_at": "2023-10-25T10:30:00Z"
}
```

#### Avantages du JSON
- ✅ **Lisible** par les humains
- ✅ **Léger** et compact
- ✅ **Support natif** dans JavaScript
- ✅ **Écosystème** riche (bibliothèques, outils)

#### Inconvénients du JSON
- ❌ **Pas de types** natifs
- ❌ **Pas de commentaires**
- ❌ **Pas de schémas** standards

### 2. XML (eXtensible Markup Language)

**Format plus ancien mais toujours utilisé**

```xml
<user id="123">
  <name>John Doe</name>
  <email>john@example.com</email>
  <profile>
    <avatar>https://example.com/avatar.jpg</avatar>
    <bio>Software developer</bio>
  </profile>
  <posts>
    <post id="1">
      <title>Introduction à REST</title>
    </post>
    <post id="2">
      <title>API Design Best Practices</title>
    </post>
  </posts>
  <created_at>2023-10-25T10:30:00Z</created_at>
</user>
```

#### Avantages du XML
- ✅ **Structure** explicite avec balises
- ✅ **Schémas** (XSD) pour validation
- ✅ **Espaces de noms** pour éviter les conflits
- ✅ **Métadonnées** riches

#### Inconvénients du XML
- ❌ **Verbeux** (plus de caractères)
- ❌ **Parsing** plus complexe
- ❌ **Moins populaire** pour les APIs modernes

### 3. YAML (YAML Ain't Markup Language)

**Format lisible pour la configuration**

```yaml
id: 123
name: John Doe
email: john@example.com
profile:
  avatar: https://example.com/avatar.jpg
  bio: Software developer
posts:
  - id: 1
    title: Introduction à REST
  - id: 2
    title: API Design Best Practices
created_at: 2023-10-25T10:30:00Z
```

### 4. MessagePack

**Format binaire compact**

```javascript
// MessagePack est binaire, mais conceptuellement :
const msgpackData = {
  id: 123,
  name: "John Doe",
  email: "john@example.com"
  // Encodé en binaire de manière compacte
};
```

## Content Negotiation

### Header Accept

```javascript
// Serveur qui supporte plusieurs formats
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  const accept = req.headers.accept;

  if (accept.includes('application/xml')) {
    res.set('Content-Type', 'application/xml');
    res.send(convertToXML(user));
  } else {
    res.set('Content-Type', 'application/json');
    res.json(user);
  }
});
```

### Header Content-Type

```javascript
// Client envoie du JSON
POST /api/users
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com"
}

// Client envoie du XML
POST /api/users
Content-Type: application/xml

<user>
  <name>John Doe</name>
  <email>john@example.com</email>
</user>
```

### Qualité des formats (q-values)

```http
# Préférences avec qualité
Accept: application/json, application/xml;q=0.8, text/html;q=0.5

# Signifie :
# - JSON préféré (qualité 1.0 par défaut)
# - XML acceptable (qualité 0.8)
# - HTML moins préféré (qualité 0.5)
```

## Design des représentations JSON

### 1. Structure cohérente

```json
// ✅ Cohérent
{
  "data": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com"
  }
}

// ❌ Incohérent
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com"
}
```

### 2. Nommage des propriétés

```javascript
// ✅ Conventions cohérentes
const user = {
  "id": 123,
  "first_name": "John",        // snake_case
  "lastName": "Doe",           // camelCase
  "createdAt": "2023-10-25",   // camelCase pour dates
  "is_active": true,           // snake_case pour booléens
  "profile_url": "..."         // snake_case pour URLs
};
```

### 3. Gestion des dates

```json
// ✅ Formats standardisés
{
  "created_at": "2023-10-25T10:30:00Z",
  "updated_at": "2023-10-25T10:30:00Z",
  "birthday": "1990-05-15"
}

// ❌ Formats ambigus
{
  "created": "10/25/2023",
  "timestamp": 1698172800
}
```

### 4. Gestion des relations

```json
// ✅ Embedding des relations
{
  "id": 123,
  "name": "John Doe",
  "posts": [
    {
      "id": 1,
      "title": "Mon post",
      "content": "..."
    }
  ]
}

// ✅ Liens vers les relations
{
  "id": 123,
  "name": "John Doe",
  "_links": {
    "posts": "/api/users/123/posts"
  }
}
```

## Pagination

### Pagination offset-based

```json
// Structure de pagination standard
{
  "data": [
    {"id": 1, "name": "User 1"},
    {"id": 2, "name": "User 2"}
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 25,
    "total_pages": 3
  },
  "_links": {
    "self": "/api/users?page=1&per_page=10",
    "next": "/api/users?page=2&per_page=10",
    "prev": null,
    "first": "/api/users?page=1&per_page=10",
    "last": "/api/users?page=3&per_page=10"
  }
}
```

### Pagination cursor-based

```json
// Pour les grandes collections
{
  "data": [
    {"id": 1, "name": "User 1"},
    {"id": 2, "name": "User 2"}
  ],
  "cursor": "eyJpZCI6MTB9",  // Encodé en base64
  "_links": {
    "self": "/api/users?cursor=eyJpZCI6MTB9",
    "next": "/api/users?cursor=eyJpZCI6MjB9"
  }
}
```

## Filtrage et tri

### Paramètres de requête

```javascript
// Filtrage
GET /api/users?role=admin&active=true
GET /api/users?created_after=2023-01-01
GET /api/users?age_min=18&age_max=65

// Tri
GET /api/users?sort=name&order=asc
GET /api/users?sort=created_at&order=desc

// Recherche
GET /api/users?search=john
GET /api/users?q=developer
```

### Structure de réponse avec filtres

```json
{
  "data": [...],
  "filters": {
    "role": "admin",
    "active": true,
    "created_after": "2023-01-01"
  },
  "sort": {
    "field": "name",
    "order": "asc"
  }
}
```

## Gestion des erreurs

### Format d'erreur standardisé

```json
// ✅ Format d'erreur cohérent
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "The provided data is not valid",
    "details": [
      {
        "field": "email",
        "message": "Must be a valid email address"
      },
      {
        "field": "age",
        "message": "Must be between 13 and 120"
      }
    ]
  }
}

// ❌ Format d'erreur incohérent
{
  "success": false,
  "errors": ["Invalid email", "Age must be positive"]
}
```

### Codes d'erreur spécifiques

```json
// Erreurs courantes
{
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "No user found with the specified ID"
  }
}

{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "The request contains invalid data"
  }
}

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests, please try again later"
  }
}
```

## HATEOAS (Hypermedia)

### Liens dans les réponses

```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "_links": {
    "self": "/api/users/123",
    "posts": "/api/users/123/posts",
    "update": "/api/users/123",
    "delete": "/api/users/123"
  },
  "_actions": {
    "update": {
      "method": "PUT",
      "href": "/api/users/123",
      "fields": ["name", "email"]
    },
    "delete": {
      "method": "DELETE",
      "href": "/api/users/123"
    }
  }
}
```

### Découvrabilité

```json
// API racine avec liens de découverte
{
  "_links": {
    "users": "/api/users",
    "posts": "/api/posts",
    "categories": "/api/categories",
    "search": "/api/search"
  }
}
```

## Versioning des représentations

### Version dans les media types

```javascript
// Version explicite dans le content-type
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  const accept = req.headers.accept;

  if (accept.includes('application/vnd.api+json')) {
    // Format JSON API
    res.set('Content-Type', 'application/vnd.api+json; version=1');
    res.json(formatAsJsonAPI(user));
  } else {
    // Format par défaut
    res.set('Content-Type', 'application/json');
    res.json(user);
  }
});
```

### Champs dépréciés

```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "deprecated_field": "old_value",
  "_meta": {
    "deprecated_fields": [
      {
        "field": "deprecated_field",
        "message": "This field will be removed in v2",
        "removal_version": "2.0"
      }
    ]
  }
}
```

## Performance et optimisation

### Compression

```javascript
// Activation de la compression
app.use(compression());

// Le serveur compresse automatiquement
GET /api/users
Accept-Encoding: gzip, deflate

// Réponse compressée
Content-Encoding: gzip
```

### Streaming pour les grandes données

```javascript
// Streaming JSON pour les grosses collections
app.get('/api/large-dataset', (req, res) => {
  res.set('Content-Type', 'application/json');

  res.write('{"data":[');

  let first = true;
  database.streamUsers((user) => {
    if (!first) res.write(',');
    res.write(JSON.stringify(user));
    first = false;
  }).then(() => {
    res.write(']}');
    res.end();
  });
});
```

## Standards et spécifications

### JSON API

```json
// Format JSON API standardisé
{
  "data": {
    "type": "users",
    "id": "123",
    "attributes": {
      "name": "John Doe",
      "email": "john@example.com"
    },
    "relationships": {
      "posts": {
        "data": [
          {"type": "posts", "id": "1"}
        ]
      }
    },
    "links": {
      "self": "/api/users/123"
    }
  },
  "included": [
    {
      "type": "posts",
      "id": "1",
      "attributes": {
        "title": "Mon post"
      }
    }
  ]
}
```

### HAL (Hypertext Application Language)

```json
{
  "_links": {
    "self": {"href": "/api/users/123"},
    "posts": {"href": "/api/users/123/posts"}
  },
  "id": 123,
  "name": "John Doe",
  "_embedded": {
    "posts": [
      {
        "_links": {"self": {"href": "/api/posts/1"}},
        "id": 1,
        "title": "Mon post"
      }
    ]
  }
}
```

## Exemple d'API complète

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// GET /api/users - Liste avec pagination
app.get('/api/users', (req, res) => {
  const { page = 1, per_page = 10, sort = 'name', order = 'asc' } = req.query;

  const users = getUsers({
    page: parseInt(page),
    per_page: parseInt(per_page),
    sort,
    order
  });

  res.status(200).json({
    data: users.data,
    pagination: {
      page: parseInt(page),
      per_page: parseInt(per_page),
      total: users.total,
      total_pages: Math.ceil(users.total / per_page)
    },
    _links: {
      self: `/api/users?page=${page}&per_page=${per_page}`,
      first: `/api/users?page=1&per_page=${per_page}`,
      last: `/api/users?page=${Math.ceil(users.total / per_page)}&per_page=${per_page}`
    }
  });
});

// GET /api/users/123 - Ressource individuelle
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({
      error: {
        code: 'USER_NOT_FOUND',
        message: `No user found with id ${req.params.id}`
      }
    });
  }

  res.status(200).json({
    data: user,
    _links: {
      self: `/api/users/${req.params.id}`,
      posts: `/api/users/${req.params.id}/posts`
    }
  });
});

// POST /api/users - Création
app.post('/api/users', (req, res) => {
  const errors = validateUser(req.body);
  if (errors.length > 0) {
    return res.status(422).json({
      error: {
        code: 'VALIDATION_FAILED',
        message: 'The provided data is not valid',
        details: errors
      }
    });
  }

  const newUser = createUser(req.body);
  res.status(201)
     .header('Location', `/api/users/${newUser.id}`)
     .json({
       data: newUser,
       _links: {
         self: `/api/users/${newUser.id}`
       }
     });
});

// PUT /api/users/123 - Mise à jour complète
app.put('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({
      error: {
        code: 'USER_NOT_FOUND',
        message: `No user found with id ${req.params.id}`
      }
    });
  }

  const updatedUser = updateUser(req.params.id, req.body);
  res.status(200).json({
    data: updatedUser,
    _links: {
      self: `/api/users/${req.params.id}`
    }
  });
});

// DELETE /api/users/123 - Suppression
app.delete('/api/users/:id', (req, res) => {
  const deleted = deleteUser(req.params.id);
  if (!deleted) {
    return res.status(404).json({
      error: {
        code: 'USER_NOT_FOUND',
        message: `No user found with id ${req.params.id}`
      }
    });
  }

  res.status(204).send();
});
```

## Quiz des représentations

**Question 1** : Quel header utilise le client pour spécifier le format souhaité ?
**Réponse** : Accept

**Question 2** : Quel est l'avantage principal de HATEOAS ?
**Réponse** : Découvrabilité de l'API

**Question 3** : Pourquoi utiliser la pagination ?
**Réponse** : Performance et utilisabilité pour les grandes collections

## Tableau de référence

| Format | Avantages | Inconvénients | Usage |
|--------|-----------|---------------|-------|
| **JSON** | Léger, lisible, populaire | Pas de types natifs | APIs modernes |
| **XML** | Structure explicite, schémas | Verbeux, complexe | APIs legacy |
| **YAML** | Très lisible | Moins standardisé | Configuration |
| **MessagePack** | Compact, rapide | Binaire, moins lisible | Performance critique |

## En résumé

### Principes clés
1. **Content Negotiation** : Support de plusieurs formats
2. **JSON** comme format principal
3. **Structure cohérente** des réponses
4. **Pagination** pour les collections
5. **HATEOAS** pour la découvrabilité

### Bonnes pratiques
- ✅ **JSON** comme format par défaut
- ✅ **Content-Type** et **Accept** headers
- ✅ **Pagination** pour les collections
- ✅ **Messages d'erreur** structurés
- ✅ **HATEOAS** pour la navigation

### Formats recommandés
- 📄 **JSON** : Format principal
- 📋 **JSON API** : Standard pour les APIs complexes
- 🔗 **HAL** : Pour les APIs avec hypermedia
- 📦 **MessagePack** : Pour la performance

### Structure typique
```json
{
  "data": {...},           // Données principales
  "pagination": {...},     // Pour les collections
  "error": {...},          // Pour les erreurs
  "_links": {...},         // Navigation HATEOAS
  "_meta": {...}           // Métadonnées
}
```

Félicitations ! Vous avez maintenant une compréhension complète des principes fondamentaux du REST. Dans la prochaine section, nous verrons comment **concevoir** une API REST de A à Z !

---

**Prochain chapitre** : [01-Modelisation-des-Ressources](03-Conception-d-une-API/01-Modelisation-des-Ressources.md)
