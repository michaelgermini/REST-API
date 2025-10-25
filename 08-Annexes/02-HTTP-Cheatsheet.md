# HTTP Cheatsheet

## Introduction

Cette **cheatsheet HTTP** contient toutes les informations essentielles sur le protocole HTTP : **codes de statut**, **méthodes**, **headers**, et **bonnes pratiques**. C'est une référence rapide pour développer et déboguer des APIs REST.

## Méthodes HTTP

| Méthode | CRUD | Description | Exemple | Idempotent | Cacheable |
|---------|------|-------------|---------|------------|-----------|
| **GET** | Read | Récupérer une ressource | `GET /api/users` | ✅ | ✅ |
| **POST** | Create | Créer une nouvelle ressource | `POST /api/users` | ❌ | ❌ |
| **PUT** | Update | Remplacer complètement | `PUT /api/users/123` | ✅ | ❌ |
| **PATCH** | Update | Modifier partiellement | `PATCH /api/users/123` | ❌ | ❌ |
| **DELETE** | Delete | Supprimer une ressource | `DELETE /api/users/123` | ✅ | ❌ |
| **HEAD** | Read | Récupérer les headers | `HEAD /api/users/123` | ✅ | ✅ |
| **OPTIONS** | Read | Découvrir les capacités | `OPTIONS /api/users` | ✅ | ❌ |

## Codes de statut HTTP

### 2xx - Succès

| Code | Nom | Description | Usage |
|------|-----|-------------|-------|
| **200** | OK | Requête traitée avec succès | Réponse standard |
| **201** | Created | Ressource créée | Après POST |
| **202** | Accepted | Requête acceptée pour traitement | Traitement asynchrone |
| **204** | No Content | Succès sans contenu | Après DELETE/PUT |

### 3xx - Redirection

| Code | Nom | Description | Usage |
|------|-----|-------------|-------|
| **301** | Moved Permanently | Redirection permanente | Changement d'URL définitif |
| **302** | Found | Redirection temporaire | Maintenance temporaire |
| **304** | Not Modified | Ressource non modifiée | Cache valide |

### 4xx - Erreur client

| Code | Nom | Description | Usage |
|------|-----|-------------|-------|
| **400** | Bad Request | Requête malformée | Données invalides |
| **401** | Unauthorized | Authentification requise | Token manquant/invalide |
| **403** | Forbidden | Accès refusé | Permissions insuffisantes |
| **404** | Not Found | Ressource inexistante | URL incorrecte |
| **409** | Conflict | Conflit d'état | Ressource déjà existante |
| **422** | Unprocessable Entity | Validation échouée | Données métier invalides |
| **429** | Too Many Requests | Rate limit dépassé | Limitation de trafic |

### 5xx - Erreur serveur

| Code | Nom | Description | Usage |
|------|-----|-------------|-------|
| **500** | Internal Server Error | Erreur interne | Erreur non gérée |
| **502** | Bad Gateway | Proxy en erreur | Service externe indisponible |
| **503** | Service Unavailable | Service indisponible | Maintenance ou surcharge |
| **504** | Gateway Timeout | Timeout proxy | Service externe lent |

## Headers HTTP

### Headers de requête

#### Authentification
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
X-API-Key: your-api-key-here
```

#### Content-Type
```http
Content-Type: application/json
Content-Type: application/xml
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
```

#### Accept
```http
Accept: application/json
Accept: application/xml
Accept: text/html
Accept: */*
```

#### Cache
```http
If-None-Match: "abc123"
If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: no-cache
```

### Headers de réponse

#### Cache
```http
Cache-Control: public, max-age=3600
ETag: "abc123"
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Expires: Wed, 21 Oct 2015 07:28:00 GMT
```

#### Sécurité
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

#### CORS
```http
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
```

#### Rate Limiting
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 50
X-RateLimit-Reset: 1609459200
Retry-After: 3600
```

## Format des requêtes

### GET Request
```http
GET /api/users?page=1&limit=20 HTTP/1.1
Host: api.example.com
Authorization: Bearer token
Accept: application/json
```

### POST Request
```http
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer token

{
  "email": "user@example.com",
  "password": "password123",
  "firstName": "John",
  "lastName": "Doe"
}
```

### PUT Request
```http
PUT /api/users/123 HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer token

{
  "firstName": "Jane",
  "lastName": "Smith"
}
```

### DELETE Request
```http
DELETE /api/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer token
```

## Format des réponses

### Réponse JSON standard
```json
{
  "data": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com"
  },
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100
  },
  "_links": {
    "self": "/api/users/123",
    "posts": "/api/users/123/posts"
  }
}
```

### Réponse d'erreur
```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "The provided data is not valid",
    "details": [
      {
        "field": "email",
        "message": "Valid email is required"
      }
    ]
  }
}
```

## Cache HTTP

### Cache-Control directives

| Directive | Description | Exemple |
|-----------|-------------|---------|
| **public** | Cacheable par tous | `public, max-age=3600` |
| **private** | Cache navigateur seulement | `private, max-age=300` |
| **no-cache** | Validation requise | `no-cache` |
| **no-store** | Pas de cache | `no-store` |
| **max-age** | Durée de cache (secondes) | `max-age=3600` |
| **s-maxage** | Durée cache CDN | `s-maxage=7200` |

### ETag et validation
```http
# Requête avec ETag
GET /api/users/123 HTTP/1.1
If-None-Match: "abc123"

# Réponse 304 si non modifié
HTTP/1.1 304 Not Modified

# Réponse avec nouvel ETag
HTTP/1.1 200 OK
ETag: "def456"
```

## Content Negotiation

### Accept header
```http
# Demande JSON
Accept: application/json

# Demande XML
Accept: application/xml

# Préférence avec qualité
Accept: application/json, application/xml;q=0.8
```

### Content-Type header
```http
# Envoi JSON
Content-Type: application/json

# Envoi formulaire
Content-Type: application/x-www-form-urlencoded

# Envoi fichier
Content-Type: multipart/form-data
```

## Sécurité HTTP

### HTTPS obligatoire
```http
# Redirection automatique
HTTP/1.1 301 Moved Permanently
Location: https://api.example.com/users
```

### Headers de sécurité
```http
# HSTS
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Protection XSS
X-XSS-Protection: 1; mode=block

# Protection clickjacking
X-Frame-Options: DENY

# Protection MIME sniffing
X-Content-Type-Options: nosniff
```

## Tests HTTP

### cURL
```bash
# GET request
curl -X GET "https://api.example.com/users" \
  -H "Authorization: Bearer token" \
  -H "Accept: application/json"

# POST request
curl -X POST "https://api.example.com/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token" \
  -d '{"email":"user@example.com","password":"password"}'

# Request avec verbose
curl -v -X GET "https://api.example.com/users/123" \
  -H "Authorization: Bearer token"
```

### Postman
```javascript
// Test de statut
pm.test("Status code is 200", function () {
  pm.response.to.have.status(200);
});

// Test de structure JSON
pm.test("Response has required fields", function () {
  const jsonData = pm.response.json();
  pm.expect(jsonData).to.have.property('data');
  pm.expect(jsonData.data).to.have.property('id');
  pm.expect(jsonData.data).to.have.property('email');
});

// Test de performance
pm.test("Response time is less than 500ms", function () {
  pm.expect(pm.response.responseTime).to.be.below(500);
});
```

## Codes de statut détaillés

### 200 OK
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600

{
  "data": {
    "id": 123,
    "name": "John Doe"
  }
}
```

### 201 Created
```http
HTTP/1.1 201 Created
Content-Type: application/json
Location: /api/users/456

{
  "data": {
    "id": 456,
    "name": "Jane Doe"
  },
  "message": "User created successfully"
}
```

### 400 Bad Request
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "The request contains invalid data",
    "details": [
      {
        "field": "email",
        "message": "Valid email is required"
      }
    ]
  }
}
```

### 401 Unauthorized
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer

{
  "error": {
    "code": "AUTHENTICATION_REQUIRED",
    "message": "Valid authentication credentials are required"
  }
}
```

### 404 Not Found
```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found"
  }
}
```

### 429 Too Many Requests
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1609459200
Retry-After: 3600

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests, please try again later",
    "retry_after": 3600
  }
}
```

## Bonnes pratiques HTTP

### RESTful URLs
```javascript
// ✅ URLs RESTful
GET /api/users              // Collection
GET /api/users/123          // Ressource
POST /api/users             // Création
PUT /api/users/123          // Mise à jour
DELETE /api/users/123       // Suppression

// ✅ Relations
GET /api/users/123/posts    // Posts de l'utilisateur
GET /api/posts/456/comments // Commentaires du post
```

### Headers cohérents
```javascript
// ✅ Headers standards
const standardHeaders = {
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${token}`,
  'Accept': 'application/json',
  'User-Agent': 'MyApp/1.0',
  'X-Request-ID': generateRequestId(),
  'Idempotency-Key': generateIdempotencyKey()
};
```

### Gestion des erreurs
```javascript
// ✅ Structure d'erreur cohérente
const errorResponse = {
  error: {
    code: 'ERROR_CODE',
    message: 'Human readable message',
    details: {}, // Informations supplémentaires
    path: '/api/users/123', // Endpoint en erreur
    timestamp: '2023-10-25T10:30:00Z'
  }
};
```

### Pagination standard
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "total_pages": 5,
    "has_next": true,
    "has_prev": false
  },
  "_links": {
    "self": "/api/users?page=1&limit=20",
    "next": "/api/users?page=2&limit=20",
    "prev": null,
    "first": "/api/users?page=1&limit=20",
    "last": "/api/users?page=5&limit=20"
  }
}
```

## Outils HTTP

### cURL
```bash
# Requêtes courantes
curl -X GET "https://api.example.com/users"
curl -X POST "https://api.example.com/users" -d '{"name":"John"}'
curl -X PUT "https://api.example.com/users/123" -d '{"name":"Jane"}'
curl -X DELETE "https://api.example.com/users/123"

# Avec headers
curl -H "Authorization: Bearer token" -H "Content-Type: application/json" \
  -X POST "https://api.example.com/users" \
  -d '{"email":"user@example.com","password":"password"}'

# Suivi des redirections
curl -L "http://api.example.com/users"

# Timeout
curl --max-time 10 "https://api.example.com/users"
```

### HTTPie
```bash
# Installation
pip install httpie

# Usage
http GET api.example.com/users
http POST api.example.com/users email=user@example.com password=password
http PUT api.example.com/users/123 name="Jane Doe"
http DELETE api.example.com/users/123
```

### Wireshark
```bash
# Capture de trafic HTTP
sudo tcpdump -i any -A -s 0 port 80 or port 443

# Ou avec Wireshark GUI
wireshark
```

## Debugging HTTP

### Logs de serveur
```javascript
// Logging des requêtes
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} - ${new Date().toISOString()}`);
  next();
});

// Logging détaillé
app.use(morgan('combined'));
```

### Tests de connectivité
```bash
# Test de connectivité
telnet api.example.com 80
curl -I https://api.example.com

# Test de performance
curl -o /dev/null -s -w "%{http_code}\n%{time_total}\n" https://api.example.com/users

# Test avec verbose
curl -v https://api.example.com/users
```

## Conclusion

Cette **cheatsheet HTTP** contient toutes les informations essentielles pour développer et déboguer des APIs REST. Utilisez-la comme référence rapide pour :

- ✅ **Codes de statut** appropriés
- ✅ **Headers** de sécurité et cache
- ✅ **Format** des requêtes et réponses
- ✅ **Tests** avec cURL et Postman
- ✅ **Debugging** des problèmes HTTP

Pour plus de détails sur l'implémentation, consultez les chapitres correspondants du livre.

---

**Prochain chapitre** : [03-Outils-et-Ressources](03-Outils-et-Ressources.md)
