# Verbes HTTP et Sémantique

## Introduction

Maintenant que nous maîtrisons les concepts de ressources et d'URI, il est temps d'explorer l'un des piliers de REST : les **verbes HTTP**. Ces verbes ne sont pas de simples commandes techniques, mais portent une sémantique riche qui définit comment les clients interagissent avec les ressources. Comprendre cette sémantique est essentiel pour concevoir des APIs REST intuitives.

## Les verbes HTTP principaux

HTTP définit 9 verbes (méthodes), mais en pratique, **4 verbes** couvrent 95% des cas d'usage d'une API REST :

| Verbe | CRUD | Description | Exemple |
|-------|------|-------------|---------|
| **GET** | Read | Récupérer une ressource | `GET /api/users/123` |
| **POST** | Create | Créer une nouvelle ressource | `POST /api/users` |
| **PUT** | Update | Remplacer complètement une ressource | `PUT /api/users/123` |
| **DELETE** | Delete | Supprimer une ressource | `DELETE /api/users/123` |

## GET - Récupération des ressources

### Sémantique de GET

**GET** est l'opération de lecture. Elle doit être :
- ✅ **Safe** : Ne modifie pas l'état du serveur
- ✅ **Idempotent** : Résultat identique à chaque appel
- ✅ **Cacheable** : Peut être mise en cache

### Utilisation de GET

```javascript
// 1. Récupérer une collection
app.get('/api/users', (req, res) => {
  const users = getUsersFromDatabase();
  res.json(users);
});

// 2. Récupérer une ressource spécifique
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});

// 3. Récupérer une sous-ressource
app.get('/api/users/:userId/posts', (req, res) => {
  const posts = getPostsByUserId(req.params.userId);
  res.json(posts);
});
```

### Codes de réponse GET

```javascript
// Réponses courantes pour GET
GET /api/users/123
→ 200 OK : Ressource trouvée
→ 404 Not Found : Ressource inexistante
→ 400 Bad Request : Paramètres invalides

GET /api/users
→ 200 OK : Collection retournée
→ 204 No Content : Collection vide
```

### GET avec paramètres

```javascript
// Filtrage
GET /api/users?role=admin&active=true

// Pagination
GET /api/users?page=2&limit=10

// Tri
GET /api/users?sort=name&order=desc

// Recherche
GET /api/users?search=john
```

## POST - Création de ressources

### Sémantique de POST

**POST** est l'opération de création. Elle :
- ❌ **N'est pas safe** : Modifie l'état du serveur
- ❌ **N'est pas idempotent** : Chaque appel crée une nouvelle ressource
- ❌ **N'est pas cacheable** : Pas de mise en cache

### Utilisation de POST

```javascript
// 1. Créer dans une collection
app.post('/api/users', (req, res) => {
  const newUser = createUser(req.body);
  res.status(201).json(newUser);
});

// 2. Créer une sous-ressource
app.post('/api/users/:userId/posts', (req, res) => {
  const newPost = createPostForUser(req.params.userId, req.body);
  res.status(201).json(newPost);
});

// 3. Actions spéciales (non-RESTful mais courantes)
app.post('/api/users/:userId/activate', (req, res) => {
  activateUser(req.params.userId);
  res.status(200).json({ message: 'User activated' });
});
```

### Codes de réponse POST

```javascript
// Réponses courantes pour POST
POST /api/users
→ 201 Created : Ressource créée avec succès
→ 400 Bad Request : Données invalides
→ 409 Conflict : Ressource déjà existante
→ 422 Unprocessable Entity : Validation échouée
```

### POST vs PUT pour la création

```javascript
// POST : Le serveur choisit l'ID
POST /api/users
{
  "name": "John Doe",
  "email": "john@example.com"
}
// Réponse :
// Location: /api/users/12345
// {"id": 12345, "name": "John Doe", ...}

// PUT : Le client choisit l'ID
PUT /api/users/12345
{
  "name": "John Doe",
  "email": "john@example.com"
}
// Réponse : 201 Created ou 204 No Content
```

## PUT - Mise à jour complète

### Sémantique de PUT

**PUT** est l'opération de remplacement complet. Elle :
- ❌ **N'est pas safe** : Modifie l'état du serveur
- ✅ **Est idempotent** : Même résultat à chaque appel
- ❌ **N'est pas cacheable** : Pas de mise en cache

### Utilisation de PUT

```javascript
// 1. Remplacer complètement une ressource
app.put('/api/users/:id', (req, res) => {
  const updatedUser = updateUser(req.params.id, req.body);
  if (!updatedUser) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(updatedUser);
});

// 2. PUT vs PATCH : PUT remplace TOUT
PUT /api/users/123
{
  "name": "Jane Doe",
  "email": "jane@example.com"
  // Doit inclure TOUS les champs
}
```

### Codes de réponse PUT

```javascript
// Réponses courantes pour PUT
PUT /api/users/123
→ 200 OK : Ressource mise à jour
→ 201 Created : Ressource créée (si elle n'existait pas)
→ 204 No Content : Mise à jour réussie, pas de contenu
→ 404 Not Found : Ressource inexistante
→ 400 Bad Request : Données invalides
```

### Idempotence de PUT

```javascript
// PUT est idempotent
PUT /api/users/123
{"name": "Jane Doe"}

PUT /api/users/123   // Même appel
{"name": "Jane Doe"}

// Résultat identique à chaque fois !
```

## DELETE - Suppression de ressources

### Sémantique de DELETE

**DELETE** est l'opération de suppression. Elle :
- ❌ **N'est pas safe** : Modifie l'état du serveur
- ✅ **Est idempotent** : Suppression d'une ressource déjà supprimée = OK
- ❌ **N'est pas cacheable** : Pas de mise en cache

### Utilisation de DELETE

```javascript
// 1. Supprimer une ressource
app.delete('/api/users/:id', (req, res) => {
  const deleted = deleteUser(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.status(204).send(); // No Content
});

// 2. Supprimer une sous-ressource
app.delete('/api/users/:userId/posts/:postId', (req, res) => {
  const deleted = deletePost(req.params.userId, req.params.postId);
  if (!deleted) {
    return res.status(404).json({ error: 'Post not found' });
  }
  res.status(204).send();
});
```

### Codes de réponse DELETE

```javascript
// Réponses courantes pour DELETE
DELETE /api/users/123
→ 204 No Content : Ressource supprimée
→ 404 Not Found : Ressource inexistante
→ 202 Accepted : Suppression en cours (asynchrone)
→ 409 Conflict : Ressource ne peut pas être supprimée
```

### Idempotence de DELETE

```javascript
// DELETE est idempotent
DELETE /api/users/123  // Supprime l'utilisateur
DELETE /api/users/123  // L'utilisateur est déjà supprimé

// Les deux appels retournent 204 No Content !
```

## Les verbes HTTP moins courants

### HEAD - Métadonnées

```javascript
// HEAD : Comme GET mais sans le body
app.head('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).end();
  }

  res.set('Content-Length', JSON.stringify(user).length);
  res.set('Last-Modified', user.updatedAt);
  res.status(200).end();
});
```

### OPTIONS - Capacités du serveur

```javascript
// OPTIONS : Méthodes supportées
app.options('/api/users/:id', (req, res) => {
  res.set('Allow', 'GET, PUT, DELETE, OPTIONS');
  res.set('Access-Control-Allow-Methods', 'GET, PUT, DELETE, OPTIONS');
  res.status(200).end();
});
```

### PATCH - Mise à jour partielle

```javascript
// PATCH : Modifier seulement certains champs
app.patch('/api/users/:id', (req, res) => {
  const updatedUser = patchUser(req.params.id, req.body);
  if (!updatedUser) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(updatedUser);
});

// Exemple de requête
PATCH /api/users/123
{
  "email": "newemail@example.com"
  // Seulement les champs modifiés
}
```

## Sémantique vs Implémentation

### Ce que disent les specs HTTP

```http
GET /api/users/123
- RFC 7231 : "Transfer a current representation of the target resource"

POST /api/users
- RFC 7231 : "Perform resource-specific processing on the request payload"

PUT /api/users/123
- RFC 7231 : "Replace all current representations of the target resource"

DELETE /api/users/123
- RFC 7231 : "Remove the association between the target resource and its current functionality"
```

### Ce que font les développeurs (parfois)

```javascript
// ❌ Anti-patterns courants
GET /api/users/123/delete    // GET ne devrait pas supprimer
POST /api/users/123/update   // POST pour update au lieu de PUT/PATCH
PUT /api/users                // PUT sur collection au lieu de POST
```

## Design patterns avec les verbes HTTP

### Pattern 1 : CRUD standard

```javascript
// Ressource User
GET /api/users              // Liste des utilisateurs
GET /api/users/123          // Utilisateur spécifique
POST /api/users             // Créer un utilisateur
PUT /api/users/123          // Remplacer l'utilisateur
DELETE /api/users/123       // Supprimer l'utilisateur
```

### Pattern 2 : Ressources contrôlées

```javascript
// Ressource avec états
GET /api/orders/123/status   // Statut de la commande
POST /api/orders/123/cancel // Annuler la commande
POST /api/orders/123/ship   // Expédier la commande
```

### Pattern 3 : Actions composites

```javascript
// Actions qui affectent plusieurs ressources
POST /api/users/123/promote  // Promouvoir l'utilisateur (change role + permissions)
POST /api/orders/123/fulfill // Traiter la commande (change status + stock)
```

## Gestion des erreurs

### Codes d'erreur sémantiques

```javascript
// Erreurs liées aux verbes HTTP

// GET
GET /api/users/999
→ 404 Not Found : Ressource inexistante
→ 400 Bad Request : Paramètres invalides

// POST
POST /api/users
→ 201 Created : Succès
→ 400 Bad Request : Données invalides
→ 409 Conflict : Ressource déjà existante

// PUT
PUT /api/users/123
→ 200 OK : Mise à jour réussie
→ 404 Not Found : Ressource inexistante
→ 422 Unprocessable Entity : Validation échouée

// DELETE
DELETE /api/users/123
→ 204 No Content : Suppression réussie
→ 404 Not Found : Ressource inexistante
→ 409 Conflict : Ressource en cours d'utilisation
```

## Exemple d'API complète

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// GET - Récupération
app.get('/api/users', (req, res) => {
  const users = getUsers({
    limit: req.query.limit,
    offset: req.query.offset,
    search: req.query.search
  });
  res.json(users);
});

app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});

// POST - Création
app.post('/api/users', (req, res) => {
  try {
    const newUser = createUser(req.body);
    res.status(201).json(newUser);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// PUT - Mise à jour complète
app.put('/api/users/:id', (req, res) => {
  try {
    const updatedUser = updateUser(req.params.id, req.body);
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(updatedUser);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE - Suppression
app.delete('/api/users/:id', (req, res) => {
  const deleted = deleteUser(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.status(204).send();
});

// PATCH - Mise à jour partielle
app.patch('/api/users/:id', (req, res) => {
  const updatedUser = patchUser(req.params.id, req.body);
  if (!updatedUser) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(updatedUser);
});
```

## Quiz des verbes HTTP

**Question 1** : Quel verbe HTTP est idempotent mais pas safe ?
**Réponse** : PUT et DELETE

**Question 2** : Quand utiliser POST au lieu de PUT ?
**Réponse** : Quand le serveur doit générer l'ID de la ressource

**Question 3** : Quelle est la différence entre PUT et PATCH ?
**Réponse** : PUT remplace complètement, PATCH modifie partiellement

## Tableau récapitulatif

| Verbe | Safe | Idempotent | Cacheable | CRUD | Usage principal |
|-------|------|------------|-----------|------|-----------------|
| **GET** | ✅ | ✅ | ✅ | Read | Récupérer des données |
| **POST** | ❌ | ❌ | ❌ | Create | Créer de nouvelles ressources |
| **PUT** | ❌ | ✅ | ❌ | Update | Remplacer complètement |
| **DELETE** | ❌ | ✅ | ❌ | Delete | Supprimer des ressources |
| **PATCH** | ❌ | ❌ | ❌ | Update | Modifier partiellement |
| **HEAD** | ✅ | ✅ | ✅ | Read | Récupérer métadonnées |
| **OPTIONS** | ✅ | ✅ | ❌ | Read | Découvrir les capacités |

## En résumé

### Sémantique des verbes HTTP
1. **GET** : Lecture, safe, idempotent, cacheable
2. **POST** : Création, non-safe, non-idempotent
3. **PUT** : Remplacement complet, non-safe, idempotent
4. **DELETE** : Suppression, non-safe, idempotent
5. **PATCH** : Modification partielle, non-safe, non-idempotent

### Bonnes pratiques
- ✅ Respecter la sémantique HTTP
- ✅ Utiliser les bons codes de réponse
- ✅ Rendre GET cacheable quand possible
- ✅ Garder PUT et DELETE idempotents
- ✅ Documenter les exceptions aux standards

### Pattern recommandé
```javascript
// CRUD standard avec verbes HTTP
GET /api/users          // Collection
GET /api/users/123      // Ressource spécifique
POST /api/users         // Créer
PUT /api/users/123      // Remplacer
PATCH /api/users/123    // Modifier partiellement
DELETE /api/users/123   // Supprimer
```

Dans le prochain chapitre, nous explorerons les **codes de statut HTTP** et leur signification précise !

---

**Prochain chapitre** : [04-Statuts-HTTP](04-Statuts-HTTP.md)
