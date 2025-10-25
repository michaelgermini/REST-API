# Ressources et URI

## Introduction

Dans le chapitre précédent, nous avons exploré l'architecture REST dans son ensemble. Maintenant, concentrons-nous sur l'un des concepts fondamentaux : les **ressources** et les **URI** (Uniform Resource Identifiers). Comprendre comment identifier et nommer les ressources est crucial pour concevoir une API REST intuitive et efficace.

## Qu'est-ce qu'une ressource ?

### Définition

Une **ressource** est toute entité identifiable dans votre système que les clients peuvent manipuler via l'API.

```javascript
// Exemples de ressources
const resources = {
  // Utilisateurs du système
  user: {
    id: 123,
    name: "John Doe",
    email: "john@example.com"
  },

  // Articles de blog
  article: {
    id: 456,
    title: "Introduction à REST",
    content: "...",
    authorId: 123
  },

  // Commandes e-commerce
  order: {
    id: 789,
    userId: 123,
    items: [...],
    total: 99.99
  }
};
```

### Caractéristiques d'une ressource

#### 1. **Identifiable**
```javascript
// Chaque ressource a une identité unique
GET /api/users/123      // Ressource user #123
GET /api/articles/456   // Ressource article #456
```

#### 2. **Manipulable**
```javascript
// CRUD operations sur les ressources
GET /api/users/123       // Read
POST /api/users          // Create
PUT /api/users/123       // Update
DELETE /api/users/123    // Delete
```

#### 3. **Représentable**
```json
// Ressource représentée en JSON
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2023-10-25T10:30:00Z"
}
```

## Nommage des ressources

### Principes de base

#### 1. **Utilisez des noms au pluriel**
```javascript
// ✅ BON
GET /api/users
GET /api/articles
GET /api/orders

// ❌ ÉVITEZ
GET /api/user
GET /api/article
GET /api/order
```

#### 2. **Soyez cohérent**
```javascript
// Cohérence dans la dénomination
/api/users
/api/user-profiles
/api/user-preferences

// ❌ Incohérent
/api/users
/api/profiles
/api/userprefs
```

#### 3. **Utilisez des tirets pour la lisibilité**
```javascript
// ✅ BON : URL lisible
GET /api/user-profiles
GET /api/blog-posts
GET /api/order-items

// ❌ ÉVITEZ : Moins lisible
GET /api/userprofiles
GET /api/blogposts
GET /api/orderitems
```

### Ressources composées

```javascript
// Ressource avec sous-ressources
GET /api/users/123/posts        // Posts de l'utilisateur 123
GET /api/users/123/preferences  // Préférences de l'utilisateur 123
GET /api/orders/456/items       // Items de la commande 456
```

## Design des URI

### Structure des URLs

#### 1. **Base URL**
```javascript
// Structure de base
https://api.example.com/v1/users/123

┌─────────┬────────────┬───┬─────┬───┐
│Protocol │    Host    │Ver│Resource│ID │
├─────────┼────────────┼───┼─────┼───┤
│https:// │api.example.com│/v1│/users│/123│
└─────────┴────────────┴───┴─────┴───┘
```

#### 2. **Versioning**
```javascript
// Version dans l'URL
/api/v1/users
/api/v2/users

// Version dans l'header
GET /api/users
API-Version: v1

// Version dans le content-type
GET /api/users
Accept: application/vnd.api+json; version=1
```

#### 3. **Paramètres de requête**
```javascript
// Filtrage et pagination
GET /api/users?role=admin&limit=10&offset=20
GET /api/articles?category=tech&published=true
GET /api/orders?status=pending&date_from=2023-01-01
```

### Hiérarchie des ressources

#### Ressources imbriquées
```javascript
// Hiérarchie logique
GET /api/users/123/posts/456      // Post 456 de l'utilisateur 123
GET /api/categories/789/articles  // Articles de la catégorie 789
GET /api/orders/456/items/123     // Item 123 de la commande 456
```

#### Collections vs Ressources individuelles
```javascript
// Collection (pluriel)
GET /api/users                    // Tous les utilisateurs
POST /api/users                   // Créer un utilisateur

// Ressource individuelle (singulier avec ID)
GET /api/users/123                // Utilisateur 123
PUT /api/users/123                // Modifier l'utilisateur 123
DELETE /api/users/123             // Supprimer l'utilisateur 123
```

## Types de ressources

### 1. Ressources entité

```javascript
// Ressource principale du domaine
GET /api/users/123
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "role": "admin"
}
```

### 2. Ressources collection

```javascript
// Collection de ressources
GET /api/users
{
  "data": [
    {"id": 1, "name": "John"},
    {"id": 2, "name": "Jane"},
    {"id": 3, "name": "Bob"}
  ],
  "total": 3,
  "page": 1,
  "per_page": 10
}
```

### 3. Ressources association

```javascript
// Ressource qui lie d'autres ressources
GET /api/users/123/posts
{
  "data": [
    {"id": 1, "title": "Mon premier post"},
    {"id": 2, "title": "REST API design"}
  ],
  "user_id": 123
}
```

### 4. Ressources document

```javascript
// Ressource qui représente un document
GET /api/contracts/456
{
  "id": 456,
  "title": "Contrat de service",
  "content": "Lorem ipsum...",
  "status": "signed",
  "parties": [
    {"id": 1, "name": "Company A"},
    {"id": 2, "name": "Company B"}
  ]
}
```

## Bonnes pratiques de nommage

### 1. Utilisez des noms descriptifs

```javascript
// ✅ BON : Clair et descriptif
GET /api/user-profiles
GET /api/blog-articles
GET /api/purchase-orders

// ❌ ÉVITEZ : Trop vague
GET /api/data
GET /api/items
GET /api/stuff
```

### 2. Évitez les verbes dans les URLs

```javascript
// ✅ BON : Ressources, pas actions
GET /api/users/123/posts
POST /api/users/123/posts

// ❌ ÉVITEZ : Verbes dans l'URL
GET /api/getUser/123
POST /api/createPost
PUT /api/updateUser/123
DELETE /api/removePost/456
```

### 3. Utilisez des conventions cohérentes

```javascript
// Cohérence dans la structure
/api/users/123/profile
/api/users/123/preferences
/api/users/123/notifications

// ❌ Incohérent
/api/users/123/profile
/api/user-preferences/123
/api/notifications?user=123
```

### 4. Gérez les ressources composées

```javascript
// Pour les noms composés
GET /api/user-accounts          // ✅ tiret
GET /api/user_accounts          // ✅ underscore
GET /api/userAccounts           // ✅ camelCase

// Choisissez une convention et tenez-vous-y !
```

## Gestion des relations

### 1. Relations one-to-many

```javascript
// Un utilisateur a plusieurs posts
GET /api/users/123/posts        // Posts de l'utilisateur
POST /api/users/123/posts       // Créer un post pour l'utilisateur

// Mais aussi :
GET /api/posts?author_id=123    // Alternative avec query parameter
```

### 2. Relations many-to-many

```javascript
// Articles et tags (many-to-many)
GET /api/articles/456/tags      // Tags de l'article
POST /api/articles/456/tags     // Ajouter un tag à l'article

GET /api/tags/789/articles      // Articles du tag
```

### 3. Relations one-to-one

```javascript
// Profil utilisateur (one-to-one)
GET /api/users/123/profile      // Profil de l'utilisateur
PUT /api/users/123/profile      // Modifier le profil
```

## Ressources spéciales

### 1. Ressources de recherche

```javascript
// Recherche comme ressource
GET /api/search?q=javascript&page=1
GET /api/articles/search?query=REST&category=tech

// Ou comme sous-ressource
GET /api/articles?q=REST
GET /api/users?search=john
```

### 2. Ressources d'upload

```javascript
// Upload de fichiers
POST /api/users/123/avatar      // Avatar de l'utilisateur
POST /api/articles/456/images   // Images de l'article

// Avec métadonnées
POST /api/uploads
Content-Type: multipart/form-data

{
  file: <file>,
  metadata: {
    category: "profile",
    user_id: 123
  }
}
```

### 3. Ressources de configuration

```javascript
// Configuration système
GET /api/configuration          // Config générale
GET /api/users/123/settings     // Settings utilisateur
PUT /api/system/preferences    // Modifier les préférences
```

## Gestion des versions

### 1. Version dans l'URL

```javascript
// Version explicite dans le path
GET /api/v1/users
GET /api/v2/users

// Avantages :
✅ URL claire et explicite
✅ Facile à router
✅ Cache par version

// Inconvénients :
❌ URLs "cassées" lors des migrations
❌ Multiples versions à maintenir
```

### 2. Version dans les headers

```javascript
// Version dans l'header Accept
GET /api/users
Accept: application/vnd.api+json; version=1

GET /api/users
Accept: application/vnd.api+json; version=2

// Avantages :
✅ URLs propres
✅ Migration progressive possible
✅ Une seule URL active

// Inconvénients :
❌ Moins visible
❌ Configuration client plus complexe
```

### 3. Version dans le content-type

```javascript
// Version dans le media type
GET /api/users
Accept: application/vnd.myapi.v1+json

GET /api/users
Accept: application/vnd.myapi.v2+json
```

## Exemple complet : API E-commerce

```javascript
// Design d'API e-commerce RESTful

// PRODUITS
GET /api/products                    // Liste des produits
GET /api/products/123                // Produit spécifique
POST /api/products                   // Créer un produit
PUT /api/products/123                // Modifier un produit
DELETE /api/products/123             // Supprimer un produit

// Avec filtrage
GET /api/products?category=electronics&price_min=10&price_max=100
GET /api/products?in_stock=true&sort=price&order=asc

// COMMANDES
GET /api/orders                      // Commandes de l'utilisateur connecté
GET /api/orders/456                  // Commande spécifique
POST /api/orders                     // Créer une commande

// Relation avec les produits
GET /api/orders/456/items            // Items de la commande
POST /api/orders/456/items           // Ajouter un item

// UTILISATEURS
GET /api/users/123                   // Profil utilisateur
GET /api/users/123/orders            // Commandes de l'utilisateur
GET /api/users/123/addresses         // Adresses de livraison

// CATÉGORIES
GET /api/categories                  // Toutes les catégories
GET /api/categories/789              // Catégorie spécifique
GET /api/categories/789/products     // Produits de la catégorie
```

## Implémentation Express.js

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// Routes pour les utilisateurs
app.get('/api/users', async (req, res) => {
  const users = await User.findAll({
    limit: req.query.limit || 10,
    offset: req.query.offset || 0,
    where: req.query.role ? { role: req.query.role } : {}
  });

  res.json({
    data: users,
    pagination: {
      limit: req.query.limit,
      offset: req.query.offset,
      total: await User.count()
    }
  });
});

app.get('/api/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json(user);
});

app.post('/api/users', async (req, res) => {
  try {
    const user = await User.create(req.body);
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Routes pour les posts des utilisateurs
app.get('/api/users/:userId/posts', async (req, res) => {
  const posts = await Post.findAll({
    where: { userId: req.params.userId },
    limit: req.query.limit,
    offset: req.query.offset
  });

  res.json(posts);
});

app.post('/api/users/:userId/posts', async (req, res) => {
  const post = await Post.create({
    ...req.body,
    userId: req.params.userId
  });

  res.status(201).json(post);
});
```

## Ressources vs Endpoints

### Ressource
- **Entité du domaine** (user, article, commande)
- **Identifiée par un nom** (users, articles, orders)
- **Manipulée via HTTP** (GET, POST, PUT, DELETE)

### Endpoint
- **Point d'accès technique** (URL + méthode HTTP)
- **Implémentation de l'API** (route dans le code)
- **Peut exposer plusieurs ressources**

```javascript
// Ressource : Utilisateurs
// Endpoints :
GET /api/users              // Liste des utilisateurs
GET /api/users/123          // Utilisateur spécifique
POST /api/users             // Créer un utilisateur
GET /api/users/123/posts    // Posts de l'utilisateur
```

## Quiz des ressources et URI

**Question 1** : Comment nommer une collection de ressources ?
**Réponse** : Au pluriel (users, articles, orders)

**Question 2** : Où placer les verbes dans une API REST ?
**Réponse** : Dans les méthodes HTTP, pas dans les URLs

**Question 3** : Comment gérer une relation one-to-many ?
**Réponse** : Avec des sous-ressources (/users/123/posts)

## En résumé

### Principes clés
1. **Ressources** = entités identifiables du domaine
2. **Collections** = groupes de ressources (pluriel)
3. **URI** = identifiants uniques des ressources
4. **Hiérarchie** = relations entre ressources

### Bonnes pratiques
- ✅ Noms au pluriel pour les collections
- ✅ Cohérence dans la dénomination
- ✅ Tirets pour la lisibilité
- ✅ Pas de verbes dans les URLs
- ✅ Versioning explicite

### Structure typique
```
/api/{version}/{resource}/{id}/{sub-resource}
```

### Exemple concret
```javascript
// API Blog RESTful
GET /api/v1/articles              // Articles
GET /api/v1/articles/123          // Article spécifique
GET /api/v1/articles/123/comments // Commentaires de l'article
POST /api/v1/articles/123/comments // Nouveau commentaire
```

Dans le prochain chapitre, nous explorerons comment utiliser correctement les **verbes HTTP** et leur sémantique !

---

**Prochain chapitre** : [03-Verbess-HTTP-et-Sémantique](03-Verbess-HTTP-et-Sémantique.md)
