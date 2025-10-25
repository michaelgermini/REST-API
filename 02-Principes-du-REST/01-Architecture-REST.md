# Architecture REST

## Introduction

Bienvenue dans la section dédiée aux principes fondamentaux du REST ! Dans ce chapitre, nous allons explorer l'**architecture REST** telle que définie par Roy Fielding en 2000. Comprendre ces principes est essentiel pour concevoir des APIs robustes et évolutives.

## Qu'est-ce que REST ?

REST est l'acronyme de **Representational State Transfer** (Transfert d'État Représentationnel). Ce n'est pas un protocole ou une technologie spécifique, mais un **style architectural** pour les systèmes distribués.

### Citation de Roy Fielding

> "REST is intended for long-lived network-based applications that span multiple platforms and organizations on the Internet."

## Les 6 contraintes REST

Roy Fielding a défini 6 contraintes architecturales qui définissent le style REST. Plus une API respecte ces contraintes, plus elle est "RESTful".

### 1. Client-Serveur

#### Séparation des préoccupations

```javascript
// Client (Frontend)
const client = {
  async getUsers() {
    const response = await fetch('/api/users');
    return response.json();
  }
};

// Serveur (Backend)
const server = {
  getUsers(req, res) {
    const users = database.getUsers();
    res.json(users);
  }
};
```

#### Avantages
- ✅ **Indépendance** : Client et serveur évoluent séparément
- ✅ **Simplicité** : Chaque partie a une responsabilité claire
- ✅ **Évolutivité** : Possibilité de scaler client et serveur indépendamment

#### Exemple d'interface
```
┌─────────────┐    HTTP/HTTPS    ┌─────────────┐
│             │───────────────────│             │
│   Client    │                   │   Serveur   │
│             │                   │             │
└─────────────┘                   └─────────────┘
```

### 2. Stateless (Sans état)

#### Définition
Le serveur ne doit **jamais** stocker d'informations sur l'état du client entre les requêtes.

```javascript
// ❌ MAUVAIS : Le serveur stocke l'état
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  // Le serveur "se souvient" de la session
  const session = getSession(req);
  res.json(getUser(userId, session));
});

// ✅ BON : Tout dans la requête
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const authToken = req.headers.authorization;
  res.json(getUser(userId, authToken));
});
```

#### Avantages
- ✅ **Évolutivité** : Pas besoin de synchroniser l'état entre serveurs
- ✅ **Fiabilité** : Pas de perte d'état en cas de crash serveur
- ✅ **Performance** : Pas de stockage d'état en mémoire

#### Inconvénients
- ❌ **Overhead** : Plus de données dans chaque requête
- ❌ **Complexité** : L'état doit être géré côté client

### 3. Cache

#### Mise en cache des réponses

```http
# Le serveur indique que la réponse peut être mise en cache
GET /api/users/123 HTTP/1.1
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=3600
ETag: "abc123"

{
  "id": 123,
  "name": "John Doe"
}
```

```javascript
// Cache côté client
const cache = new Map();

async function getUser(userId) {
  if (cache.has(userId)) {
    return cache.get(userId);
  }

  const response = await fetch(`/api/users/${userId}`);
  const user = await response.json();

  // Mettre en cache pour 1 heure
  cache.set(userId, user);
  setTimeout(() => cache.delete(userId), 3600000);

  return user;
}
```

#### Avantages
- ✅ **Performance** : Réduction du trafic réseau
- ✅ **Charge serveur** : Moins de requêtes à traiter
- ✅ **Expérience utilisateur** : Réponses plus rapides

### 4. Interface uniforme

#### Les 4 contraintes de l'interface uniforme

##### 1. Identification des ressources
```javascript
// Ressources identifiées par des URLs
GET /api/users          // Collection de ressources
GET /api/users/123      // Ressource spécifique
GET /api/users/123/posts // Ressource liée
```

##### 2. Manipulation via représentations
```javascript
// Le client manipule des représentations, pas les ressources directement
const userRepresentation = {
  id: 123,
  name: "John Doe",
  email: "john@example.com"
};

PUT /api/users/123
Content-Type: application/json

{
  "name": "Jane Doe",
  "email": "jane@example.com"
}
```

##### 3. Messages auto-descriptifs
```http
# Requête complète avec métadonnées
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Accept: application/json
Content-Length: 45

{"name":"John","email":"john@example.com"}
```

##### 4. Hypermedia as the Engine of Application State (HATEOAS)

```json
{
  "id": 123,
  "name": "John Doe",
  "links": {
    "self": "/api/users/123",
    "posts": "/api/users/123/posts",
    "update": "/api/users/123",
    "delete": "/api/users/123"
  },
  "actions": {
    "update": {
      "method": "PUT",
      "href": "/api/users/123",
      "fields": ["name", "email"]
    }
  }
}
```

### 5. Système en couches

#### Architecture en couches

```javascript
// Couche 1 : Load Balancer
app.use('/api/*', proxyToAPI);

// Couche 2 : API Gateway
app.get('/api/users', authenticate, validate, proxyToService);

// Couche 3 : Service métier
app.get('/users', getUsersFromDatabase);

// Couche 4 : Base de données
const users = database.query('SELECT * FROM users');
```

#### Avantages
- ✅ **Sécurité** : Couches de protection (firewall, auth)
- ✅ **Performance** : Cache, compression, CDN
- ✅ **Évolutivité** : Services indépendants

### 6. Code-On-Demand (Optionnel)

#### Exécution de code côté client

```html
<!-- Le serveur peut envoyer du code exécutable -->
<script src="/api/users/123/behavior.js"></script>
```

```javascript
// Comportement spécifique à une ressource
const userBehavior = {
  canEdit: true,
  canDelete: false,
  customActions: ['promote', 'suspend']
};
```

> **Note** : Cette contrainte est optionnelle et peu utilisée dans les APIs REST modernes.

## Niveaux de RESTfulness

### Niveau 0 : HTTP comme transport
```javascript
// Utilise HTTP mais pas les principes REST
POST /api
Content-Type: application/xml

<methodCall>
  <methodName>getUser</methodName>
  <params><id>123</id></params>
</methodCall>
```

### Niveau 1 : Ressources
```javascript
// URLs identifient des ressources
GET /api/getUser?id=123
POST /api/createUser
POST /api/updateUser
POST /api/deleteUser
```

### Niveau 2 : Verbes HTTP
```javascript
// Utilise les verbes HTTP correctement
GET /api/users/123
POST /api/users
PUT /api/users/123
DELETE /api/users/123
```

### Niveau 3 : Hypermedia Controls (HATEOAS)
```json
{
  "id": 123,
  "name": "John Doe",
  "_links": {
    "self": { "href": "/api/users/123" },
    "posts": { "href": "/api/users/123/posts" }
  },
  "_actions": {
    "update": {
      "method": "PUT",
      "href": "/api/users/123"
    }
  }
}
```

## Richardson Maturity Model

Martin Fowler a popularisé le **Richardson Maturity Model** pour évaluer le niveau de RESTfulness d'une API :

| Niveau | Description | Exemple |
|--------|-------------|---------|
| **0** | HTTP comme transport | POST /getUser |
| **1** | Ressources identifiées | GET /users/123 |
| **2** | Verbes HTTP | PUT /users/123 |
| **3** | HATEOAS | Liens et actions |

## Exemple d'API RESTful complète

### Design d'une API Blog

```javascript
// Ressource : Articles
GET /api/articles           // Liste des articles
GET /api/articles/123       // Article spécifique
POST /api/articles          // Créer un article
PUT /api/articles/123       // Modifier un article
DELETE /api/articles/123    // Supprimer un article

// Ressource : Commentaires
GET /api/articles/123/comments     // Commentaires d'un article
POST /api/articles/123/comments    // Ajouter un commentaire
```

### Implémentation

```javascript
// Express.js API RESTful
const express = require('express');
const app = express();

app.use(express.json());

// ARTICLES
app.get('/api/articles', async (req, res) => {
  const articles = await Article.findAll({
    limit: req.query.limit,
    offset: req.query.offset
  });
  res.json({
    data: articles,
    _links: {
      self: req.originalUrl,
      next: getNextPageUrl(req)
    }
  });
});

app.get('/api/articles/:id', async (req, res) => {
  const article = await Article.findById(req.params.id);
  if (!article) {
    return res.status(404).json({ error: 'Article not found' });
  }

  res.json({
    data: article,
    _links: {
      self: req.originalUrl,
      comments: `/api/articles/${req.params.id}/comments`
    },
    _actions: {
      update: {
        method: 'PUT',
        href: req.originalUrl
      },
      delete: {
        method: 'DELETE',
        href: req.originalUrl
      }
    }
  });
});

app.post('/api/articles', async (req, res) => {
  const article = await Article.create(req.body);
  res.status(201).json({
    data: article,
    _links: {
      self: `/api/articles/${article.id}`
    }
  });
});
```

## Avantages de REST

### 1. **Évolutivité**
```javascript
// Ajout d'une nouvelle ressource sans impact
app.get('/api/categories', getCategories);
app.get('/api/categories/:id', getCategory);
```

### 2. **Performance**
```javascript
// Cache HTTP natif
GET /api/articles/123
Cache-Control: public, max-age=3600
```

### 3. **Interopérabilité**
```javascript
// Même API accessible depuis différents clients
const clients = [
  'Web Browser',    // fetch()
  'Mobile App',     // HTTP client
  'CLI Tool',       // curl
  'IoT Device'      // HTTP library
];
```

### 4. **Découvrabilité**
```json
// HATEOAS permet la découverte
{
  "_links": {
    "articles": "/api/articles",
    "categories": "/api/categories",
    "search": "/api/search"
  }
}
```

## Limites de REST

### 1. **Pas de type safety**
```javascript
// Le client ne sait pas la structure
fetch('/api/users/123')
  .then(r => r.json())
  .then(data => {
    // Que contient data ? Inconnu !
  });
```

### 2. **Over-fetching / Under-fetching**
```javascript
// Problème classique avec REST
GET /api/users/123    // → Retourne 20 champs
GET /api/users/123/posts  // → Requête séparée nécessaire
```

### 3. **Versioning difficile**
```
/api/v1/users
/api/v2/users
/api/v3/users
```

## REST vs RESTful

### REST (théorique)
- Style architectural défini par Roy Fielding
- 6 contraintes à respecter
- Idéal théorique

### RESTful (pratique)
- APIs qui suivent les principes REST
- Approximations des contraintes
- Utilisation pragmatique

```javascript
// API "RESTful" mais pas 100% REST
app.get('/api/users/search?q=john', searchUsers); // Pas vraiment REST
app.get('/api/users', getUsers);                   // RESTful
```

## Quiz de l'architecture REST

**Question 1** : Quelle contrainte REST impose que le serveur ne stocke pas l'état du client ?
**Réponse** : Stateless (sans état)

**Question 2** : Quel niveau du Richardson Maturity Model utilise HATEOAS ?
**Réponse** : Niveau 3

**Question 3** : Quelle contrainte REST permet la mise en cache ?
**Réponse** : Cache

## En résumé

L'architecture REST est définie par **6 contraintes** :

1. **Client-Serveur** : Séparation des responsabilités
2. **Stateless** : Pas d'état stocké sur le serveur
3. **Cache** : Possibilité de mise en cache
4. **Interface uniforme** : Ressources, représentations, HATEOAS
5. **Système en couches** : Architecture modulaire
6. **Code-On-Demand** : Code exécutable (optionnel)

Le **Richardson Maturity Model** nous aide à évaluer le niveau de RESTfulness d'une API :

- **Niveau 0** : HTTP comme transport
- **Niveau 1** : Ressources identifiées
- **Niveau 2** : Verbes HTTP
- **Niveau 3** : HATEOAS

Dans le prochain chapitre, nous explorerons comment identifier et nommer correctement les **ressources** dans une API REST !

---

**Prochain chapitre** : [02-Ressources-et-URI](02-Ressources-et-URI.md)
