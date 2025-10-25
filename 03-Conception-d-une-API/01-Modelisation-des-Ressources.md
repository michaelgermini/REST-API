# Modélisation des Ressources

## Introduction

Maintenant que nous maîtrisons les principes fondamentaux du REST, il est temps de passer à la **conception pratique** d'une API. Dans ce chapitre, nous allons apprendre comment **modéliser les ressources** de votre domaine métier et les transformer en une API REST cohérente et intuitive.

## Qu'est-ce que la modélisation ?

### Définition

La **modélisation des ressources** consiste à identifier et structurer les entités principales de votre système, puis à définir comment elles s'exposent via une API REST.

```javascript
// Exemple de domaine : Blog
const domainModel = {
  // Entités principales
  User: {
    id: "UUID",
    name: "string",
    email: "string",
    posts: "Post[]" // relation
  },

  Post: {
    id: "UUID",
    title: "string",
    content: "string",
    author: "User", // relation
    comments: "Comment[]"
  },

  Comment: {
    id: "UUID",
    content: "string",
    post: "Post",
    author: "User"
  }
};
```

## Étapes de la modélisation

### 1. Identifier les entités du domaine

#### Questions à se poser

```javascript
// Questions pour identifier les ressources

// 1. Quelles sont les NOUNS (noms) de votre domaine ?
const nouns = [
  "Utilisateur", "Article", "Commande", "Produit",
  "Catégorie", "Commentaire", "Panier", "Adresse"
];

// 2. Quelles sont les entités que les utilisateurs manipulent ?
const userActions = [
  "Créer un compte utilisateur",
  "Publier un article",
  "Passer une commande",
  "Laisser un commentaire"
];

// 3. Quelles données stockez-vous en base ?
const databaseTables = [
  "users", "posts", "orders", "products",
  "categories", "comments", "carts"
];
```

#### Ressources candidates

```javascript
// Domaine E-commerce
const resources = [
  "users",        // Utilisateurs
  "products",     // Produits
  "categories",   // Catégories
  "orders",       // Commandes
  "order-items",  // Lignes de commande
  "carts",        // Paniers
  "addresses",    // Adresses
  "reviews",      // Avis
  "payments",     // Paiements
  "shipments"     // Expéditions
];
```

### 2. Définir les propriétés de chaque ressource

```javascript
// Modèle User détaillé
const User = {
  // Identifiant unique
  id: "string (UUID)",

  // Informations de base
  firstName: "string",
  lastName: "string",
  email: "string",
  phone: "string",

  // Métadonnées
  createdAt: "datetime",
  updatedAt: "datetime",
  lastLoginAt: "datetime",

  // Statut
  status: "enum (active, inactive, suspended)",
  role: "enum (customer, admin, vendor)",

  // Relations
  addresses: "Address[]",
  orders: "Order[]",
  cart: "Cart"
};
```

### 3. Identifier les relations entre ressources

#### Types de relations

```javascript
// 1. One-to-One (1:1)
const UserProfile = {
  userId: "UUID (FK)",
  bio: "string",
  avatar: "string",
  website: "string"
};

// 2. One-to-Many (1:N)
const User = {
  id: "UUID",
  posts: "Post[]" // Un user a plusieurs posts
};

const Post = {
  id: "UUID",
  authorId: "UUID (FK)", // Un post a un auteur
  title: "string"
};

// 3. Many-to-Many (N:N)
const Post = {
  id: "UUID",
  tags: "Tag[]" // Un post a plusieurs tags
};

const Tag = {
  id: "UUID",
  posts: "Post[]" // Un tag a plusieurs posts
};
```

## Design des endpoints

### Ressources principales

```javascript
// CRUD complet pour chaque ressource

// USERS
GET /api/users              // Liste des utilisateurs
GET /api/users/{id}         // Utilisateur spécifique
POST /api/users             // Créer un utilisateur
PUT /api/users/{id}         // Modifier un utilisateur
DELETE /api/users/{id}      // Supprimer un utilisateur

// PRODUCTS
GET /api/products           // Liste des produits
GET /api/products/{id}      // Produit spécifique
POST /api/products          // Créer un produit
PUT /api/products/{id}      // Modifier un produit
DELETE /api/products/{id}   // Supprimer un produit
```

### Ressources liées

```javascript
// Relations one-to-many

// Posts d'un utilisateur
GET /api/users/{userId}/posts
POST /api/users/{userId}/posts

// Commentaires d'un post
GET /api/posts/{postId}/comments
POST /api/posts/{postId}/comments

// Commandes d'un utilisateur
GET /api/users/{userId}/orders
POST /api/users/{userId}/orders
```

### Ressources many-to-many

```javascript
// Via une table de liaison
GET /api/posts/{postId}/tags
POST /api/posts/{postId}/tags
DELETE /api/posts/{postId}/tags/{tagId}

// Ou via les deux sens
GET /api/tags/{tagId}/posts
```

## Nommage et conventions

### Collections vs Ressources individuelles

```javascript
// ✅ Collection (pluriel)
GET /api/users                    // Tous les utilisateurs
POST /api/users                   // Créer un utilisateur

// ✅ Ressource individuelle
GET /api/users/{id}               // Utilisateur spécifique
PUT /api/users/{id}               // Modifier l'utilisateur
DELETE /api/users/{id}            // Supprimer l'utilisateur
```

### Noms composés

```javascript
// ✅ Conventions pour les noms composés
GET /api/user-profiles           // tirets
GET /api/user_profiles           // underscores
GET /api/userProfiles            // camelCase

// Choisissez une convention et tenez-vous-y !
```

### Ressources spéciales

```javascript
// ✅ Ressources dérivées
GET /api/users/{id}/profile      // Profil de l'utilisateur
GET /api/users/{id}/preferences  // Préférences utilisateur
GET /api/users/{id}/statistics   // Stats utilisateur

// ✅ Actions spéciales (comme ressources)
POST /api/users/{id}/activate    // Activation
POST /api/users/{id}/deactivate  // Désactivation
POST /api/users/{id}/verify      // Vérification email
```

## Gestion des relations complexes

### 1. Agrégation de données

```javascript
// Profile utilisateur enrichi
GET /api/users/{id}/profile
{
  "user": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com"
  },
  "statistics": {
    "totalOrders": 15,
    "totalSpent": 1250.00,
    "lastOrderDate": "2023-10-20"
  },
  "preferences": {
    "newsletter": true,
    "language": "fr",
    "currency": "EUR"
  }
}
```

### 2. Ressources composites

```javascript
// Panier avec produits
GET /api/carts/{id}
{
  "id": 456,
  "userId": 123,
  "items": [
    {
      "productId": 789,
      "productName": "iPhone 15",
      "quantity": 1,
      "price": 999.00
    },
    {
      "productId": 012,
      "productName": "AirPods",
      "quantity": 2,
      "price": 179.00
    }
  ],
  "total": 1357.00,
  "itemCount": 3
}
```

### 3. Ressources de recherche

```javascript
// Recherche comme ressource
GET /api/search?q=laptop&category=electronics
GET /api/products/search?query=gaming&price_max=1000

// Ou comme endpoint spécialisé
GET /api/products?search=laptop&filters=category:electronics,price:0-1000
```

## Exemple complet : API E-commerce

### Modèle de domaine

```javascript
// Domain Model
const ECommerceAPI = {
  // Ressources principales
  User: {
    id: "UUID",
    email: "string",
    firstName: "string",
    lastName: "string",
    addresses: "Address[]",
    orders: "Order[]"
  },

  Product: {
    id: "UUID",
    name: "string",
    description: "string",
    price: "decimal",
    category: "Category",
    reviews: "Review[]"
  },

  Order: {
    id: "UUID",
    user: "User",
    items: "OrderItem[]",
    total: "decimal",
    status: "OrderStatus",
    shippingAddress: "Address"
  },

  // Ressources de support
  Category: {
    id: "UUID",
    name: "string",
    products: "Product[]"
  },

  Address: {
    id: "UUID",
    street: "string",
    city: "string",
    postalCode: "string",
    country: "string"
  }
};
```

### Design des endpoints

```javascript
// API Endpoints Design

// USERS
GET /api/users                    // Liste utilisateurs
GET /api/users/{id}               // Profil utilisateur
POST /api/users                   // Créer utilisateur
PUT /api/users/{id}               // Modifier profil
DELETE /api/users/{id}            // Supprimer compte

// Relations utilisateur
GET /api/users/{id}/orders        // Commandes utilisateur
GET /api/users/{id}/addresses     // Adresses utilisateur

// PRODUCTS
GET /api/products                 // Liste produits
GET /api/products/{id}            // Produit spécifique
POST /api/products                // Créer produit (admin)
PUT /api/products/{id}            // Modifier produit (admin)
DELETE /api/products/{id}         // Supprimer produit (admin)

// Recherche et filtrage produits
GET /api/products?category=electronics&q=laptop
GET /api/products?price_min=100&price_max=500
GET /api/products?in_stock=true&sort=price&order=asc

// CATEGORIES
GET /api/categories               // Toutes catégories
GET /api/categories/{id}          // Catégorie spécifique
GET /api/categories/{id}/products // Produits de la catégorie

// ORDERS
GET /api/orders                   // Commandes (utilisateur connecté)
GET /api/orders/{id}              // Commande spécifique
POST /api/orders                  // Créer commande
PUT /api/orders/{id}              // Modifier commande

// Gestion commande
GET /api/orders/{id}/items        // Items de la commande
POST /api/orders/{id}/cancel      // Annuler commande
POST /api/orders/{id}/ship        // Expédier commande

// CART
GET /api/cart                     // Panier utilisateur
POST /api/cart/items              // Ajouter au panier
PUT /api/cart/items/{id}          // Modifier quantité
DELETE /api/cart/items/{id}       // Retirer du panier
DELETE /api/cart                  // Vider panier

// REVIEWS
GET /api/products/{id}/reviews    // Avis produit
POST /api/products/{id}/reviews   // Créer avis
PUT /api/reviews/{id}             // Modifier avis
DELETE /api/reviews/{id}          // Supprimer avis
```

## Implémentation avec Express

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// Users endpoints
app.get('/api/users', async (req, res) => {
  const users = await User.findAll({
    limit: req.query.limit || 10,
    offset: req.query.offset || 0,
    where: req.query.status ? { status: req.query.status } : {}
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
  const user = await User.findByPk(req.params.id, {
    include: [
      { model: Address },
      { model: Order }
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

app.post('/api/users', async (req, res) => {
  try {
    const newUser = await User.create(req.body);
    res.status(201)
       .header('Location', `/api/users/${newUser.id}`)
       .json(newUser);
  } catch (error) {
    res.status(400).json({
      error: 'Validation failed',
      message: error.message
    });
  }
});

// Products endpoints
app.get('/api/products', async (req, res) => {
  const whereClause = {};

  if (req.query.category) {
    whereClause.categoryId = req.query.category;
  }

  if (req.query.price_min || req.query.price_max) {
    whereClause.price = {};
    if (req.query.price_min) {
      whereClause.price[Op.gte] = req.query.price_min;
    }
    if (req.query.price_max) {
      whereClause.price[Op.lte] = req.query.price_max;
    }
  }

  const products = await Product.findAll({
    where: whereClause,
    limit: req.query.limit || 20,
    offset: req.query.offset || 0,
    order: [[req.query.sort || 'name', req.query.order || 'ASC']]
  });

  res.json({
    data: products,
    pagination: {
      total: await Product.count({ where: whereClause }),
      limit: req.query.limit,
      offset: req.query.offset
    }
  });
});

// Relations
app.get('/api/users/:userId/orders', async (req, res) => {
  const orders = await Order.findAll({
    where: { userId: req.params.userId },
    include: [{ model: OrderItem, include: [Product] }]
  });

  res.json(orders);
});

app.post('/api/users/:userId/orders', async (req, res) => {
  const user = await User.findByPk(req.params.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const newOrder = await Order.create({
    ...req.body,
    userId: req.params.userId
  });

  res.status(201)
     .header('Location', `/api/orders/${newOrder.id}`)
     .json(newOrder);
});
```

## Gestion des versions

### Stratégie de versioning

```javascript
// 1. Version dans l'URL
GET /api/v1/users
GET /api/v2/users

// 2. Version dans les headers
GET /api/users
Accept: application/vnd.api+json; version=1

// 3. Version dans le content-type
GET /api/users
Accept: application/vnd.myapi.v1+json
```

### Migration entre versions

```javascript
// Support des deux versions pendant la transition
app.get('/api/users', (req, res) => {
  const apiVersion = req.headers['api-version'] || 'v1';

  if (apiVersion === 'v2') {
    // Format v2
    res.json(formatUsersV2(getUsers()));
  } else {
    // Format v1 (par défaut)
    res.json(getUsers());
  }
});
```

## Documentation des ressources

### OpenAPI/Swagger

```yaml
openapi: 3.0.0
info:
  title: E-Commerce API
  version: 1.0.0

paths:
  /api/users:
    get:
      summary: Get all users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
        - name: offset
          in: query
          schema:
            type: integer
            minimum: 0
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
```

### Schéma des composants

```yaml
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        firstName:
          type: string
        lastName:
          type: string
        email:
          type: string
          format: email
        createdAt:
          type: string
          format: date-time
      required:
        - id
        - email
        - createdAt

    Pagination:
      type: object
      properties:
        page:
          type: integer
        per_page:
          type: integer
        total:
          type: integer
        total_pages:
          type: integer
```

## Quiz de modélisation

**Question 1** : Comment identifier les ressources de votre domaine ?
**Réponse** : Cherchez les noms (nouns) et les entités que les utilisateurs manipulent

**Question 2** : Quand utiliser une sous-ressource vs un query parameter ?
**Réponse** : Sous-ressource pour les relations (users/123/posts), query pour les filtres (products?category=tech)

**Question 3** : Comment gérer les relations many-to-many ?
**Réponse** : Via des sous-ressources des deux côtés ou une table de liaison

## En résumé

### Étapes de modélisation
1. **Identifier** les entités du domaine
2. **Définir** les propriétés de chaque ressource
3. **Cartographier** les relations entre ressources
4. **Designer** les endpoints REST
5. **Implémenter** avec les bonnes conventions

### Conventions importantes
- ✅ **Collections** au pluriel
- ✅ **Ressources** individuelles avec ID
- ✅ **Relations** via sous-ressources
- ✅ **Actions** comme endpoints POST spécialisés
- ✅ **Versioning** explicite

### Structure recommandée
```
/api/{version}/{resource}              // Collections
/api/{version}/{resource}/{id}         // Ressources individuelles
/api/{version}/{resource}/{id}/{sub}   // Sous-ressources
```

### Exemple concret
```javascript
// API Blog bien modélisée
GET /api/v1/posts              // Articles
GET /api/v1/posts/123          // Article spécifique
GET /api/v1/posts/123/comments // Commentaires de l'article
POST /api/v1/posts/123/publish // Publier l'article
GET /api/v1/users/456/posts    // Articles de l'utilisateur
```

Dans le prochain chapitre, nous verrons comment concevoir des **URLs** et appliquer les **bonnes pratiques** de design d'API !

---

**Prochain chapitre** : [02-URL-Design-et-Bonnes-Pratiques](02-URL-Design-et-Bonnes-Pratiques.md)
