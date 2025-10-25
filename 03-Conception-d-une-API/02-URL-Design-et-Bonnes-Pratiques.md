# URL Design et Bonnes Pratiques

## Introduction

La conception des **URLs** (Uniform Resource Locators) est l'un des aspects les plus visibles de votre API. Des URLs bien conçues rendent votre API intuitive, prévisible et facile à utiliser. Dans ce chapitre, nous allons explorer les meilleures pratiques pour concevoir des URLs RESTful et créer une expérience développeur exceptionnelle.

## Principes fondamentaux du design d'URLs

### 1. URLs lisibles et intuitives

```javascript
// ✅ URLs qui se lisent comme des phrases
GET /api/users/123/profile
GET /api/articles/456/comments
GET /api/orders/789/shipping-address

// ❌ URLs cryptiques
GET /api/u/123/p
GET /api/a/456/c
GET /api/o/789/sa
```

### 2. URLs prévisibles

```javascript
// ✅ Pattern cohérent
GET /api/users/123/posts
GET /api/categories/456/products
GET /api/orders/789/items

// ❌ Pattern incohérent
GET /api/users/123/posts
GET /api/category/456/items  // category au singulier !
GET /api/order/789/products  // products au lieu d'items !
```

### 3. URLs RESTful

```javascript
// ✅ Utilise les verbes HTTP dans les URLs
GET /api/users/123          // Récupérer utilisateur
POST /api/users             // Créer utilisateur
PUT /api/users/123          // Modifier utilisateur
DELETE /api/users/123       // Supprimer utilisateur

// ❌ Verbes dans les URLs (anti-pattern)
GET /api/getUser/123
POST /api/createUser
POST /api/updateUser/123
POST /api/deleteUser/123
```

## Structure des URLs

### Base URL

```javascript
// Structure complète d'une URL d'API
https://api.example.com/v1/users/123

┌─────────┬────────────┬───┬─────┬───┐
│Protocol │    Host    │Ver│Resource│ID │
├─────────┼────────────┼───┼─────┼───┤
│https:// │api.example.com│/v1│/users│/123│
└─────────┴────────────┴───┴─────┴───┘
```

#### Bonnes pratiques pour la base URL
```javascript
// ✅ Base URL claire
https://api.example.com/v1/
https://api.github.com/
https://api.stripe.com/v1/

// ❌ URLs ambiguës
https://example.com/api/
https://www.example.com/rest/
```

### Versioning dans les URLs

```javascript
// ✅ Version explicite
GET /api/v1/users
GET /api/v2/users

// ✅ Version dans subdomain
GET /v1/api/users
GET /v2/api/users

// ❌ Version dans query parameter
GET /api/users?version=1
```

### Ressources et sous-ressources

```javascript
// ✅ Hiérarchie claire
GET /api/users/123/posts/456
GET /api/categories/789/products
GET /api/orders/012/items/345

// ❌ Hiérarchie confuse
GET /api/users/posts/123/456
GET /api/categories/products/789
```

## Nommage des ressources

### Collections (pluriel)

```javascript
// ✅ Noms au pluriel pour les collections
GET /api/users
GET /api/products
GET /api/categories
GET /api/orders

// ❌ Singulier ou incohérent
GET /api/user
GET /api/item
GET /api/order
```

### Ressources individuelles

```javascript
// ✅ Ressource avec ID
GET /api/users/123
GET /api/products/456
GET /api/categories/789

// ✅ Ressource avec slug
GET /api/articles/getting-started-with-rest
GET /api/products/iphone-15-pro-max
```

### Noms composés

```javascript
// ✅ Conventions pour les noms composés
GET /api/user-profiles      // tirets (recommandé)
GET /api/user_profiles      // underscores
GET /api/userProfiles       // camelCase

// ✅ Ressources composées
GET /api/order-items
GET /api/shopping-carts
GET /api/product-categories
```

## Design patterns d'URLs

### Pattern CRUD standard

```javascript
// Ressource : Users
GET /api/users              // Liste
GET /api/users/123          // Détail
POST /api/users             // Créer
PUT /api/users/123          // Modifier
DELETE /api/users/123       // Supprimer

// Ressource : Posts
GET /api/posts              // Liste
GET /api/posts/456          // Détail
POST /api/posts             // Créer
PUT /api/posts/456          // Modifier
DELETE /api/posts/456       // Supprimer
```

### Pattern de relations

```javascript
// Relations one-to-many
GET /api/users/123/posts           // Posts de l'utilisateur 123
POST /api/users/123/posts          // Créer un post pour l'utilisateur 123

GET /api/posts/456/comments        // Commentaires du post 456
POST /api/posts/456/comments       // Ajouter un commentaire au post 456

// Relations many-to-many
GET /api/posts/456/tags            // Tags du post 456
POST /api/posts/456/tags           // Ajouter un tag au post 456
```

### Pattern de recherche et filtrage

```javascript
// ✅ Recherche comme ressource
GET /api/search?q=javascript
GET /api/articles/search?query=rest&category=tutorial

// ✅ Filtrage via query parameters
GET /api/users?role=admin&status=active
GET /api/products?category=electronics&price_max=1000
GET /api/orders?status=pending&date_from=2023-01-01
```

### Pattern d'actions

```javascript
// ✅ Actions comme sous-ressources
POST /api/users/123/activate
POST /api/users/123/deactivate
POST /api/orders/456/cancel
POST /api/orders/789/ship

// ✅ Actions avec paramètres
POST /api/users/123/change-password
POST /api/orders/456/update-shipping-address
```

## Paramètres de requête (Query Parameters)

### Pagination

```javascript
// ✅ Pagination standard
GET /api/users?page=2&per_page=20
GET /api/products?page=1&limit=10&offset=0

// ✅ Pagination cursor-based (pour les grandes collections)
GET /api/users?cursor=eyJpZCI6MTB9
GET /api/events?after=2023-10-25T10:30:00Z
```

### Filtrage

```javascript
// ✅ Filtres simples
GET /api/users?role=admin
GET /api/products?category=electronics
GET /api/orders?status=pending

// ✅ Filtres avancés
GET /api/users?created_after=2023-01-01&created_before=2023-12-31
GET /api/products?price_min=100&price_max=500&in_stock=true
GET /api/articles?tags=javascript,react&author=123
```

### Tri

```javascript
// ✅ Tri simple
GET /api/users?sort=name&order=asc
GET /api/products?sort=price&order=desc

// ✅ Tri multiple
GET /api/products?sort=category,price&order=asc,desc
```

### Recherche

```javascript
// ✅ Recherche textuelle
GET /api/users?search=john
GET /api/products?q=laptop

// ✅ Recherche avec options
GET /api/articles?search=rest+api&highlight=true&fuzzy=false
```

## Gestion des IDs et identifiants

### Types d'identifiants

```javascript
// ✅ UUID (recommandé)
GET /api/users/550e8400-e29b-41d4-a716-446655440000

// ✅ Numériques
GET /api/users/123

// ✅ Slugs lisibles
GET /api/articles/introduction-to-rest-apis
GET /api/products/iphone-15-pro-max

// ✅ Codes courts
GET /api/orders/ABC123
GET /api/invites/X7Y9Z2
```

### Consistance des IDs

```javascript
// ✅ Cohérence dans l'API
GET /api/users/123
GET /api/users/123/posts
GET /api/users/123/orders

// ❌ Incohérence
GET /api/users/123
GET /api/user-posts/123  // user-posts au lieu de users/123/posts
GET /api/orders?user_id=123  // query param au lieu de sous-ressource
```

## Design patterns avancés

### Ressources composites

```javascript
// ✅ Agrégation de données
GET /api/users/123/profile
{
  "user": {...},
  "statistics": {...},
  "preferences": {...}
}

GET /api/orders/456/full
{
  "order": {...},
  "items": [...],
  "shipping": {...},
  "billing": {...}
}
```

### Ressources de configuration

```javascript
// ✅ Configuration utilisateur
GET /api/users/123/settings
PUT /api/users/123/settings

// ✅ Configuration système
GET /api/system/configuration
PUT /api/system/settings

// ✅ Configuration par feature
GET /api/users/123/notifications/settings
GET /api/users/123/privacy/settings
```

### Ressources temporaires

```javascript
// ✅ Tokens et sessions
POST /api/auth/tokens
DELETE /api/auth/tokens/abc123

// ✅ Uploads temporaires
POST /api/uploads/temp
GET /api/uploads/temp/xyz789
DELETE /api/uploads/temp/xyz789
```

## Gestion des versions

### Version dans l'URL

```javascript
// ✅ Version explicite
GET /api/v1/users
GET /api/v2/users
GET /api/v2.1/users

// ✅ Avantages
✅ URLs claires et explicites
✅ Cache par version
✅ Migration progressive

// ✅ Inconvénients
❌ URLs "cassées" lors des upgrades
❌ Maintenance de multiples versions
```

### Version dans les headers

```javascript
// ✅ Version via Accept header
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
```

### Migration entre versions

```javascript
// ✅ Support temporaire des deux versions
app.get('/api/users', (req, res) => {
  const version = req.headers['api-version'] || 'v1';

  if (version === 'v2') {
    res.json(formatUsersV2(getUsers()));
  } else {
    res.json(getUsers()); // format v1
  }
});

// ✅ Redirection automatique
app.get('/api/v1/users', (req, res) => {
  res.redirect(301, '/api/v2/users');
});
```

## Bonnes pratiques de design

### 1. Utilisez des conventions cohérentes

```javascript
// ✅ Cohérence dans toute l'API
GET /api/users/123/posts
GET /api/categories/456/products
GET /api/orders/789/items

// ✅ Même pattern pour les actions
POST /api/users/123/activate
POST /api/orders/789/cancel
POST /api/products/456/publish
```

### 2. Évitez les URLs trop longues

```javascript
// ✅ URLs concises
GET /api/users/123/posts/456

// ❌ URLs trop longues
GET /api/e-commerce-platform/users/123/blog-posts/456

// ✅ Si nécessaire, utilisez des abbréviations standard
GET /api/users/123/posts/456  // posts au lieu de blog-posts
GET /api/cats/456/prods        // prods au lieu de products
```

### 3. Gérez les caractères spéciaux

```javascript
// ✅ Encodage URL
GET /api/users/123/posts?search=REST%20APIs
GET /api/products?category=Electronics%20%26%20Computers

// ✅ Évitez les caractères problématiques dans les IDs
GET /api/users/user@example.com  // ❌ @ dans l'URL
GET /api/users/user%40example.com // ✅ encodé
```

### 4. Préparez l'évolutivité

```javascript
// ✅ Structure extensible
GET /api/v1/users/123
GET /api/v1/users/123/posts
GET /api/v1/users/123/settings

// ✅ Pas de structure rigide
GET /api/users/123
GET /api/users/123/posts
GET /api/users/123/settings
```

## Exemple d'API complète : Blog Platform

```javascript
// Design d'API Blog RESTful

// USERS
GET /api/v1/users                    // Liste utilisateurs
GET /api/v1/users/123                // Profil utilisateur
POST /api/v1/users                   // Créer utilisateur
PUT /api/v1/users/123                // Modifier profil
DELETE /api/v1/users/123             // Supprimer compte

// Relations utilisateurs
GET /api/v1/users/123/posts          // Articles de l'utilisateur
GET /api/v1/users/123/followers      // Abonnés de l'utilisateur
GET /api/v1/users/123/following      // Utilisateurs suivis

// POSTS
GET /api/v1/posts                    // Liste articles
GET /api/v1/posts/456                // Article spécifique
POST /api/v1/posts                   // Créer article
PUT /api/v1/posts/456                // Modifier article
DELETE /api/v1/posts/456             // Supprimer article

// Recherche et filtrage posts
GET /api/v1/posts?author=123
GET /api/v1/posts?category=tech
GET /api/v1/posts?published=true
GET /api/v1/posts?sort=created_at&order=desc

// Relations posts
GET /api/v1/posts/456/comments       // Commentaires de l'article
GET /api/v1/posts/456/tags           // Tags de l'article
GET /api/v1/posts/456/likes          // Likes de l'article

// COMMENTS
GET /api/v1/comments                 // Tous commentaires
GET /api/v1/posts/456/comments       // Commentaires d'un article
POST /api/v1/posts/456/comments      // Ajouter commentaire
PUT /api/v1/comments/789             // Modifier commentaire
DELETE /api/v1/comments/789          // Supprimer commentaire

// CATEGORIES
GET /api/v1/categories               // Toutes catégories
GET /api/v1/categories/123           // Catégorie spécifique
GET /api/v1/categories/123/posts     // Articles de la catégorie

// TAGS
GET /api/v1/tags                     // Tous tags
GET /api/v1/tags/456                 // Tag spécifique
GET /api/v1/tags/456/posts           // Articles du tag

// SEARCH
GET /api/v1/search?q=javascript       // Recherche globale
GET /api/v1/posts/search?query=rest   // Recherche dans posts
GET /api/v1/users/search?query=john   // Recherche dans users

// ACTIONS
POST /api/v1/posts/456/publish       // Publier article
POST /api/v1/posts/456/unpublish     // Dépublier article
POST /api/v1/users/123/follow        // Suivre utilisateur
POST /api/v1/users/123/unfollow      // Ne plus suivre
POST /api/v1/posts/456/like          // Aimer article
POST /api/v1/posts/456/unlike        // Ne plus aimer
```

## Implémentation Express.js

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// Users routes
app.get('/api/v1/users', async (req, res) => {
  const { page, limit, search, role } = req.query;

  const whereClause = {};
  if (role) whereClause.role = role;
  if (search) whereClause.name = { [Op.like]: `%${search}%` };

  const users = await User.findAll({
    where: whereClause,
    limit: parseInt(limit) || 10,
    offset: (parseInt(page) - 1) * parseInt(limit) || 0
  });

  res.json({
    data: users,
    pagination: {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 10,
      total: await User.count({ where: whereClause })
    }
  });
});

app.get('/api/v1/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id, {
    include: [
      { model: Post, as: 'posts' },
      { model: User, as: 'followers' },
      { model: User, as: 'following' }
    ]
  });

  if (!user) {
    return res.status(404).json({
      error: 'User not found',
      message: `No user found with id ${req.params.id}`
    });
  }

  res.json(user);
});

// Posts routes with filtering
app.get('/api/v1/posts', async (req, res) => {
  const {
    page, limit, sort, order,
    author, category, published, search
  } = req.query;

  const whereClause = {};
  if (author) whereClause.authorId = author;
  if (category) whereClause.categoryId = category;
  if (published !== undefined) whereClause.published = published === 'true';

  let orderBy = [['createdAt', 'DESC']];
  if (sort) {
    orderBy = [[sort, order || 'ASC']];
  }

  const posts = await Post.findAll({
    where: whereClause,
    include: [
      { model: User, as: 'author' },
      { model: Category, as: 'category' },
      { model: Tag, as: 'tags' }
    ],
    limit: parseInt(limit) || 20,
    offset: (parseInt(page) - 1) * parseInt(limit) || 0,
    order: orderBy
  });

  res.json({
    data: posts,
    pagination: {
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 20,
      total: await Post.count({ where: whereClause })
    }
  });
});

// Search endpoint
app.get('/api/v1/search', async (req, res) => {
  const { q, type, limit } = req.query;

  if (!q) {
    return res.status(400).json({
      error: 'Query required',
      message: 'Search query parameter is required'
    });
  }

  const results = {
    users: [],
    posts: [],
    categories: []
  };

  if (!type || type === 'users') {
    results.users = await User.findAll({
      where: {
        [Op.or]: [
          { name: { [Op.like]: `%${q}%` } },
          { email: { [Op.like]: `%${q}%` } }
        ]
      },
      limit: parseInt(limit) || 5
    });
  }

  if (!type || type === 'posts') {
    results.posts = await Post.findAll({
      where: {
        [Op.or]: [
          { title: { [Op.like]: `%${q}%` } },
          { content: { [Op.like]: `%${q}%` } }
        ]
      },
      include: [{ model: User, as: 'author' }],
      limit: parseInt(limit) || 10
    });
  }

  res.json(results);
});

// Action endpoints
app.post('/api/v1/posts/:id/publish', async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }

  await post.update({ published: true, publishedAt: new Date() });

  res.json({
    message: 'Post published successfully',
    post: post
  });
});

app.post('/api/v1/users/:userId/follow', async (req, res) => {
  const { targetUserId } = req.body;

  if (!targetUserId) {
    return res.status(400).json({
      error: 'Target user ID required'
    });
  }

  const follow = await Follow.create({
    followerId: req.params.userId,
    followingId: targetUserId
  });

  res.status(201).json(follow);
});
```

## Documentation des URLs

### OpenAPI Documentation

```yaml
openapi: 3.0.0
info:
  title: Blog API
  version: 1.0.0

paths:
  /api/v1/users:
    get:
      summary: Get all users
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            minimum: 1
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
        - name: search
          in: query
          schema:
            type: string
        - name: role
          in: query
          schema:
            type: string
            enum: [admin, author, reader]
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'
                  pagination:
                    $ref: '#/components/schemas/Pagination'

  /api/v1/users/{id}:
    get:
      summary: Get user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: User details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '404':
          description: User not found
```

## Quiz du design d'URLs

**Question 1** : Comment nommer une collection de ressources ?
**Réponse** : Au pluriel (users, posts, categories)

**Question 2** : Où placer les verbes dans une API REST ?
**Réponse** : Dans les méthodes HTTP, pas dans les URLs

**Question 3** : Quand utiliser une sous-ressource ?
**Réponse** : Pour les relations (users/123/posts) et les aspects d'une ressource (users/123/profile)

## En résumé

### Principes fondamentaux
1. **URLs lisibles** et intuitives
2. **Conventions cohérentes** dans toute l'API
3. **Structure RESTful** avec les verbes HTTP
4. **Hiérarchie logique** des ressources
5. **Versioning explicite**

### Structure recommandée
```
/api/{version}/{collection}              // Collections
/api/{version}/{collection}/{id}         // Ressources individuelles
/api/{version}/{collection}/{id}/{sub}   // Sous-ressources
```

### Bonnes pratiques
- ✅ **Pluriel** pour les collections
- ✅ **Tirets** pour les noms composés
- ✅ **Query parameters** pour filtrage/tri
- ✅ **Actions** comme endpoints POST
- ✅ **Version** dans l'URL ou headers

### Anti-patterns à éviter
- ❌ Verbes dans les URLs
- ❌ Singulier pour collections
- ❌ Incohérence dans les patterns
- ❌ URLs trop longues
- ❌ Caractères spéciaux non encodés

### Exemple d'URLs bien conçues
```javascript
// API E-commerce intuitive
GET /api/v1/products?category=electronics&price_max=1000
GET /api/v1/users/123/orders
POST /api/v1/orders/456/ship
GET /api/v1/search?q=laptop
```

Dans le prochain chapitre, nous explorerons les **relations entre ressources** et comment les modéliser avec des diagrammes ERD !

---

**Prochain chapitre** : [03-ERD-et-Relations](03-ERD-et-Relations.md)
