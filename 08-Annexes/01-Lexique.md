# Lexique

## Introduction

Ce lexique contient les **termes techniques** et **concepts** essentiels du développement d'APIs REST. Il sert de référence rapide pour comprendre la terminologie utilisée dans ce livre et dans l'industrie.

## A

### API (Application Programming Interface)
Interface de programmation qui permet à deux applications de communiquer entre elles.

**Exemple :**
```javascript
// API REST
GET /api/users/123
POST /api/users
```

### API Gateway
Point d'entrée unique pour toutes les requêtes API, qui gère le routage, l'authentification et la limitation du trafic.

**Exemple :**
```javascript
// API Gateway routes vers différents services
GET /api/users → User Service
GET /api/posts → Post Service
GET /api/orders → Order Service
```

### API Key
Clé d'identification unique utilisée pour authentifier les requêtes vers une API.

**Exemple :**
```http
GET /api/data
X-API-Key: your-api-key-here
```

### Authentication (Authentification)
Processus de vérification de l'identité d'un utilisateur ou d'un système.

**Exemple :**
```javascript
// Vérification email/mot de passe
const user = await authenticateUser(email, password);
```

### Authorization (Autorisation)
Processus de contrôle des permissions et des accès après l'authentification.

**Exemple :**
```javascript
// Vérification des permissions
if (user.role === 'admin') {
  // Accès autorisé
}
```

## B

### BOLA (Broken Object Level Authorization)
Vulnérabilité où un utilisateur peut accéder à des ressources qui ne lui appartiennent pas.

**Exemple :**
```javascript
// Vulnérabilité BOLA
GET /api/users/123  // Accès aux données d'un autre utilisateur
```

### Bearer Token
Type de token d'authentification utilisé avec JWT.

**Exemple :**
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## C

### Cache
Stockage temporaire de données pour améliorer les performances.

**Exemple :**
```javascript
// Cache HTTP
Cache-Control: public, max-age=3600
```

### CDN (Content Delivery Network)
Réseau de serveurs distribués qui accélère la livraison de contenu.

**Exemple :**
```javascript
// CloudFlare, AWS CloudFront, etc.
```

### CORS (Cross-Origin Resource Sharing)
Mécanisme de sécurité qui contrôle les requêtes cross-origin.

**Exemple :**
```javascript
app.use(cors({
  origin: 'https://myapp.com',
  credentials: true
}));
```

### CRUD (Create, Read, Update, Delete)
Opérations de base pour manipuler les données.

**Exemple :**
```javascript
// CRUD operations
POST /api/users    // Create
GET /api/users     // Read
PUT /api/users/123 // Update
DELETE /api/users/123 // Delete
```

## D

### DDoS (Distributed Denial of Service)
Attaque visant à rendre un service indisponible en le submergeant de trafic.

**Exemple :**
```javascript
// Protection DDoS
const rateLimit = require('express-rate-limit');
app.use(rateLimit({ max: 100, windowMs: 900000 }));
```

## E

### Endpoint
URL spécifique d'une API qui correspond à une ressource ou une action.

**Exemple :**
```javascript
// Endpoints API
GET /api/users          // Liste des utilisateurs
GET /api/users/123      // Utilisateur spécifique
POST /api/users         // Créer un utilisateur
```

### ETag
Identifiant unique d'une version de ressource pour la validation de cache.

**Exemple :**
```http
ETag: "abc123"
If-None-Match: "abc123"
```

## F

### Forward Proxy
Serveur intermédiaire qui fait des requêtes au nom du client.

**Exemple :**
```javascript
// Proxy vers un service externe
const response = await fetch('https://external-api.com/data', {
  proxy: 'http://proxy.example.com:8080'
});
```

## G

### GraphQL
Langage de requête pour APIs qui permet de demander exactement les données nécessaires.

**Exemple :**
```graphql
query {
  user(id: "123") {
    name
    email
    posts {
      title
    }
  }
}
```

## H

### HATEOAS (Hypertext As The Engine Of Application State)
Principe REST où les réponses contiennent des liens vers les actions possibles.

**Exemple :**
```json
{
  "id": 123,
  "name": "John Doe",
  "_links": {
    "self": "/api/users/123",
    "posts": "/api/users/123/posts"
  }
}
```

### Header HTTP
Métadonnées envoyées avec les requêtes et réponses HTTP.

**Exemple :**
```http
GET /api/users HTTP/1.1
Host: api.example.com
Authorization: Bearer token
Content-Type: application/json
```

### HTTP Status Codes
Codes numériques indiquant le résultat d'une requête HTTP.

**Exemple :**
```javascript
// Codes de statut courants
200 OK           // Succès
201 Created      // Ressource créée
400 Bad Request  // Requête invalide
401 Unauthorized // Non authentifié
404 Not Found    // Ressource introuvable
500 Internal Error // Erreur serveur
```

## I

### Idempotent
Opération qui produit le même résultat peu importe le nombre d'exécutions.

**Exemple :**
```javascript
// Opérations idempotentes
GET /api/users/123    // Idempotent
PUT /api/users/123    // Idempotent
DELETE /api/users/123 // Idempotent

// Opération non-idempotente
POST /api/users       // Non-idempotent (crée à chaque fois)
```

### Injection SQL (SQL Injection)
Attaque où du code SQL malveillant est injecté dans une requête.

**Exemple :**
```javascript
// ❌ Vulnérabilité SQL injection
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ✅ Requête paramétrée
const query = 'SELECT * FROM users WHERE email = ?';
const users = await db.query(query, [email]);
```

## J

### JSON (JavaScript Object Notation)
Format de données léger et lisible pour l'échange de données.

**Exemple :**
```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2023-10-25T10:30:00Z"
}
```

### JWT (JSON Web Token)
Standard pour les tokens d'authentification auto-contenus.

**Exemple :**
```javascript
const token = jwt.sign(
  { userId: 123, role: 'admin' },
  secret,
  { expiresIn: '1h' }
);
```

## L

### Load Balancer
Serveur qui distribue le trafic entre plusieurs serveurs backend.

**Exemple :**
```nginx
# Configuration Nginx
upstream backend {
  least_conn;
  server backend1:8000;
  server backend2:8000;
  server backend3:8000;
}
```

## M

### Microservices
Architecture où une application est divisée en services indépendants.

**Exemple :**
```javascript
// Services séparés
user-service:8001     // Gestion des utilisateurs
post-service:8002     // Gestion des posts
notification-service:8003 // Notifications
```

### Middleware
Fonction qui traite les requêtes avant qu'elles n'atteignent le contrôleur.

**Exemple :**
```javascript
// Middleware d'authentification
app.use('/api', authenticateToken);
app.use('/api', cors());
app.use('/api', rateLimit());
```

## N

### Nginx
Serveur web et reverse proxy populaire.

**Exemple :**
```nginx
server {
  listen 80;
  server_name api.example.com;

  location /api/ {
    proxy_pass http://backend_servers;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
  }
}
```

## O

### OAuth 2.0
Standard d'autorisation pour l'accès délégué.

**Exemple :**
```javascript
// Flux OAuth
1. Redirection vers provider
2. Consentement utilisateur
3. Échange du code
4. Récupération du token
```

### OpenAPI (Swagger)
Spécification pour documenter les APIs REST.

**Exemple :**
```yaml
openapi: 3.0.0
info:
  title: My API
  version: 1.0.0
paths:
  /users:
    get:
      summary: Get users
```

## P

### Pagination
Technique pour diviser les grandes collections de données.

**Exemple :**
```javascript
// Pagination offset
GET /api/users?page=2&limit=20

// Pagination curseur
GET /api/posts?cursor=eyJpZCI6MTB9&limit=20
```

### POSTMAN
Outil pour tester et documenter les APIs.

**Exemple :**
```javascript
// Test Postman
pm.test("Status code is 200", function () {
  pm.response.to.have.status(200);
});
```

## Q

### Query Parameters
Paramètres passés dans l'URL après le point d'interrogation.

**Exemple :**
```http
GET /api/users?role=admin&page=1&limit=20
```

## R

### Rate Limiting
Limitation du nombre de requêtes par utilisateur dans un intervalle de temps.

**Exemple :**
```javascript
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requêtes max
  message: 'Too many requests'
});
```

### REST (Representational State Transfer)
Style architectural pour les APIs web.

**Exemple :**
```javascript
// API RESTful
GET /api/users      // Ressource
POST /api/users     // Création
PUT /api/users/123  // Mise à jour
DELETE /api/users/123 // Suppression
```

### Reverse Proxy
Serveur qui agit comme intermédiaire entre les clients et les serveurs backend.

**Exemple :**
```nginx
location /api/ {
  proxy_pass http://backend;
  proxy_set_header Host $host;
}
```

## S

### SOAP (Simple Object Access Protocol)
Protocole XML pour l'échange de messages structurés.

**Exemple :**
```xml
<soap:Envelope>
  <soap:Body>
    <getUser>
      <id>123</id>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

### SSL/TLS
Protocoles de chiffrement pour sécuriser les communications.

**Exemple :**
```javascript
// Configuration HTTPS
const httpsOptions = {
  key: fs.readFileSync('private.key'),
  cert: fs.readFileSync('certificate.crt')
};
```

## T

### Token
Chaîne de caractères utilisée pour l'authentification.

**Exemple :**
```javascript
// JWT Token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## U

### URI (Uniform Resource Identifier)
Chaîne de caractères qui identifie une ressource.

**Exemple :**
```javascript
// URIs d'API
/api/users
/api/users/123
/api/users/123/posts
```

### URL (Uniform Resource Locator)
Type d'URI qui spécifie l'emplacement d'une ressource.

**Exemple :**
```http
https://api.example.com/v1/users/123
```

## V

### Validation
Processus de vérification que les données d'entrée sont correctes.

**Exemple :**
```javascript
const validateUser = (userData) => {
  const errors = [];

  if (!userData.email || !isValidEmail(userData.email)) {
    errors.push('Invalid email');
  }

  if (!userData.password || userData.password.length < 8) {
    errors.push('Password too short');
  }

  return errors;
};
```

## W

### Webhook
Callback HTTP déclenché par un événement.

**Exemple :**
```javascript
// Webhook Stripe
app.post('/webhooks/stripe', (req, res) => {
  const event = req.body;

  switch (event.type) {
    case 'payment_intent.succeeded':
      handleSuccessfulPayment(event.data.object);
      break;
  }

  res.json({ received: true });
});
```

### WebSocket
Protocole pour les communications bidirectionnelles en temps réel.

**Exemple :**
```javascript
// Socket.IO
const io = require('socket.io')(server);

io.on('connection', (socket) => {
  socket.on('message', (data) => {
    socket.emit('reply', { message: 'received' });
  });
});
```

## X

### XSS (Cross-Site Scripting)
Attaque où du code malveillant est injecté dans une page web.

**Exemple :**
```html
<!-- ❌ XSS vulnerability -->
<div>{{ userInput }}</div>

<!-- ✅ XSS prevention -->
<div>{{ sanitize(userInput) }}</div>
```

## Termes par catégorie

### Authentification et Sécurité
- **API Key** : Clé d'identification
- **Bearer Token** : Token d'accès
- **JWT** : Token auto-contenu
- **OAuth 2.0** : Autorisation déléguée
- **Rate Limiting** : Limitation du trafic
- **CORS** : Contrôle cross-origin
- **BOLA** : Vulnérabilité d'autorisation

### Performance
- **Cache** : Stockage temporaire
- **CDN** : Distribution de contenu
- **Pagination** : Division des données
- **Compression** : Réduction de taille
- **Load Balancer** : Distribution de charge

### Architecture
- **REST** : Style architectural
- **Microservices** : Services indépendants
- **API Gateway** : Point d'entrée
- **GraphQL** : Langage de requête
- **HATEOAS** : Navigation hypermédia

### Outils
- **Postman** : Test d'APIs
- **OpenAPI** : Documentation
- **Nginx** : Serveur web
- **Docker** : Containerisation
- **ELK Stack** : Logging et monitoring

## Conclusion

Ce lexique couvre les **termes essentiels** du développement d'APIs REST. Utilisez-le comme référence pour clarifier les concepts et améliorer votre compréhension. Pour plus de détails sur chaque terme, consultez les chapitres correspondants du livre.

---

**Prochain chapitre** : [02-HTTP-Cheatsheet](02-HTTP-Cheatsheet.md)
