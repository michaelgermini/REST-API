# Cache et CDN

## Introduction

La **performance** est un facteur critique pour le succès d'une API. Les utilisateurs attendent des réponses **rapides** et **fiables**. Dans ce chapitre, nous allons explorer les stratégies de **cache** pour réduire la latence et les **CDN** (Content Delivery Networks) pour distribuer le contenu efficacement. Ces optimisations peuvent améliorer les performances de votre API de manière significative.

## Cache HTTP

### Qu'est-ce que le cache HTTP ?

Le cache HTTP stocke temporairement les réponses des requêtes pour éviter de refaire les mêmes calculs ou requêtes vers la base de données.

```javascript
// ✅ Cache HTTP natif
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);

  res.set({
    'Cache-Control': 'public, max-age=3600',  // Cache pendant 1 heure
    'ETag': `"${user.updatedAt.getTime()}"`, // Version de la ressource
    'Last-Modified': user.updatedAt.toUTCString()
  });

  res.json(user);
});
```

### Stratégies de cache

#### 1. Cache-Control

```javascript
// ✅ Différentes stratégies de cache
app.get('/api/users/:id', (req, res) => {
  res.set('Cache-Control', 'public, max-age=3600'); // 1 heure
  res.json(getUserById(req.params.id));
});

app.get('/api/posts', (req, res) => {
  res.set('Cache-Control', 'public, max-age=1800, s-maxage=3600'); // 30min navigateur, 1h CDN
  res.json(getPosts());
});

app.get('/api/user/profile', (req, res) => {
  res.set('Cache-Control', 'private, max-age=300'); // 5 minutes, seulement navigateur
  res.json(getUserProfile(req.user.id));
});

app.get('/api/admin/stats', (req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate'); // Pas de cache
  res.json(getAdminStats());
});
```

#### 2. ETags

```javascript
// ✅ ETags pour la validation de cache
app.get('/api/articles/:id', (req, res) => {
  const article = getArticleById(req.params.id);
  const etag = `"${article.id}-${article.updatedAt.getTime()}"`;

  // Vérifier If-None-Match
  if (req.headers['if-none-match'] === etag) {
    return res.status(304).send(); // Not Modified
  }

  res.set({
    'ETag': etag,
    'Cache-Control': 'public, max-age=3600'
  });

  res.json(article);
});

// ✅ ETags faibles pour le contenu sémantique
app.get('/api/articles/:id', (req, res) => {
  const article = getArticleById(req.params.id);
  const weakEtag = `W/"${article.contentHash}"`;

  if (req.headers['if-none-match'] === weakEtag) {
    return res.status(304).send();
  }

  res.set({
    'ETag': weakEtag,
    'Cache-Control': 'public, max-age=3600'
  });

  res.json(formatArticle(article));
});
```

#### 3. Last-Modified

```javascript
// ✅ Validation basée sur la date de modification
app.get('/api/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  const lastModified = user.updatedAt;

  // Vérifier If-Modified-Since
  const ifModifiedSince = req.headers['if-modified-since'];
  if (ifModifiedSince && new Date(lastModified) <= new Date(ifModifiedSince)) {
    return res.status(304).send();
  }

  res.set({
    'Last-Modified': lastModified.toUTCString(),
    'Cache-Control': 'public, max-age=3600'
  });

  res.json(user);
});
```

### Cache côté serveur

#### Redis

```javascript
// ✅ Configuration Redis
const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD
});

client.on('error', (err) => {
  console.error('Redis error:', err);
});

// ✅ Middleware de cache Redis
const cacheMiddleware = (duration = 3600) => {
  return async (req, res, next) => {
    const key = `cache:${req.originalUrl}`;

    try {
      const cached = await client.get(key);
      if (cached) {
        const data = JSON.parse(cached);
        return res.json(data);
      }

      // Stocker la réponse originale
      const originalSend = res.send;
      res.send = function(data) {
        // Mettre en cache si c'est une réponse JSON 200
        if (res.statusCode === 200 && res.get('Content-Type')?.includes('application/json')) {
          client.setex(key, duration, JSON.stringify(JSON.parse(data)));
        }
        originalSend.call(this, data);
      };

      next();
    } catch (error) {
      // En cas d'erreur Redis, continuer sans cache
      next();
    }
  };
};

// ✅ Usage
app.get('/api/users', cacheMiddleware(1800), getUsers); // 30 minutes
app.get('/api/posts', cacheMiddleware(3600), getPosts);  // 1 heure
```

#### Memcached

```javascript
// ✅ Configuration Memcached
const memcached = require('memcached');
const memcache = new memcached('localhost:11211');

// ✅ Cache avec Memcached
const cacheWithMemcached = (key, ttl, fn) => {
  return new Promise((resolve, reject) => {
    memcache.get(key, (err, data) => {
      if (data) {
        resolve(data);
        return;
      }

      fn().then(result => {
        memcache.set(key, result, ttl, (err) => {
          if (err) reject(err);
          else resolve(result);
        });
      }).catch(reject);
    });
  });
};

// ✅ Usage
app.get('/api/users/:id', async (req, res) => {
  const user = await cacheWithMemcached(
    `user:${req.params.id}`,
    3600, // 1 heure
    () => getUserById(req.params.id)
  );

  res.json(user);
});
```

## CDN (Content Delivery Network)

### Configuration CloudFlare

```javascript
// ✅ Configuration CloudFlare
const cloudflareConfig = {
  // Cache rules dans CloudFlare dashboard
  cacheRules: [
    {
      url: '/api/users/*',
      cacheLevel: 'Cache Everything',
      edgeCacheTTL: 1800, // 30 minutes
      browserCacheTTL: 3600 // 1 heure
    },
    {
      url: '/api/posts/*',
      cacheLevel: 'Cache Everything',
      edgeCacheTTL: 3600, // 1 heure
      browserCacheTTL: 7200 // 2 heures
    },
    {
      url: '/api/auth/*',
      cacheLevel: 'Bypass', // Pas de cache pour l'auth
      edgeCacheTTL: 0
    }
  ]
};

// ✅ Headers pour CloudFlare
app.use('/api', (req, res, next) => {
  res.set({
    'CF-Cache-Status': 'DYNAMIC', // Pour le debugging
    'CDN-Cache-Control': 'public, max-age=3600'
  });
  next();
});
```

### Cache Edge

```javascript
// ✅ Configuration Edge Cache (CloudFlare Workers)
const edgeCacheHandler = async (request) => {
  const url = new URL(request.url);
  const cacheKey = url.pathname;

  // Vérifier le cache edge
  const cached = await caches.match(cacheKey);
  if (cached) {
    return cached;
  }

  // Faire la requête vers l'origine
  const response = await fetch(request);

  // Mettre en cache si c'est cacheable
  if (response.status === 200 && isCacheable(url.pathname)) {
    const cacheResponse = response.clone();
    await caches.put(cacheKey, cacheResponse);
  }

  return response;
};
```

## Cache d'application

### Cache en mémoire (Node.js)

```javascript
// ✅ Cache en mémoire simple
class MemoryCache {
  constructor() {
    this.cache = new Map();
  }

  set(key, value, ttl = 3600000) { // 1 heure par défaut
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttl
    });
  }

  get(key) {
    const item = this.cache.get(key);

    if (!item) return null;

    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return item.value;
  }

  delete(key) {
    return this.cache.delete(key);
  }

  clear() {
    this.cache.clear();
  }

  size() {
    return this.cache.size;
  }
}

// ✅ Instance globale
const cache = new MemoryCache();

// ✅ Usage avec cache d'application
app.get('/api/users/:id', async (req, res) => {
  const cacheKey = `user:${req.params.id}`;

  // Vérifier le cache
  let user = cache.get(cacheKey);
  if (user) {
    res.set('X-Cache', 'HIT');
    return res.json(user);
  }

  // Récupérer depuis la base de données
  user = await getUserById(req.params.id);
  if (user) {
    cache.set(cacheKey, user, 3600000); // 1 heure
    res.set('X-Cache', 'MISS');
  }

  res.json(user);
});
```

### Cache distribué

```javascript
// ✅ Configuration Redis distribué
const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD,
  db: 1, // Base de données Redis séparée
  retryDelayOnFailover: 100,
  enableReadyCheck: false,
  maxRetriesPerRequest: 3
};

const redisClient = redis.createClient(redisConfig);

// ✅ Cache distribué avec Redis
const distributedCache = {
  async get(key) {
    try {
      const data = await redisClient.getAsync(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  },

  async set(key, value, ttl = 3600) {
    try {
      const data = JSON.stringify(value);
      await redisClient.setexAsync(key, ttl, data);
    } catch (error) {
      console.error('Cache set error:', error);
    }
  },

  async delete(key) {
    try {
      await redisClient.delAsync(key);
    } catch (error) {
      console.error('Cache delete error:', error);
    }
  },

  async clear(pattern = '*') {
    try {
      const keys = await redisClient.keysAsync(pattern);
      if (keys.length > 0) {
        await redisClient.delAsync(keys);
      }
    } catch (error) {
      console.error('Cache clear error:', error);
    }
  }
};

// ✅ Usage
app.get('/api/posts', async (req, res) => {
  const cacheKey = `posts:${JSON.stringify(req.query)}`;

  let posts = await distributedCache.get(cacheKey);
  if (posts) {
    res.set('X-Cache', 'HIT');
    return res.json(posts);
  }

  posts = await getPostsFromDatabase(req.query);
  await distributedCache.set(cacheKey, posts, 1800); // 30 minutes

  res.set('X-Cache', 'MISS');
  res.json(posts);
});
```

## Optimisation des requêtes

### Pagination intelligente

```javascript
// ✅ Pagination basée sur le curseur
app.get('/api/posts', async (req, res) => {
  const { cursor, limit = 20 } = req.query;

  let query = Post.query();

  if (cursor) {
    // Décoder le curseur (timestamp + id)
    const [timestamp, id] = cursor.split(':');
    query = query.where('created_at', '<', timestamp)
                 .orWhere(function(q) {
                   q.where('created_at', '=', timestamp)
                    .where('id', '<', id);
                 });
  }

  const posts = await query.orderBy('created_at', 'desc')
                          .orderBy('id', 'desc')
                          .limit(limit + 1)
                          .get();

  const hasMore = posts.length > limit;
  if (hasMore) {
    posts.pop(); // Retirer l'élément extra
  }

  // Générer le prochain curseur
  const nextCursor = hasMore ?
    `${posts[posts.length - 1].created_at}:${posts[posts.length - 1].id}` :
    null;

  res.json({
    data: posts,
    pagination: {
      has_more: hasMore,
      next_cursor: nextCursor,
      limit: parseInt(limit)
    }
  });
});
```

### Index de base de données

```sql
-- ✅ Index optimisés pour les APIs

-- Index pour la pagination
CREATE INDEX idx_posts_created_at_id ON posts (created_at DESC, id DESC);

-- Index pour les filtres courants
CREATE INDEX idx_posts_status_published ON posts (status, published_at DESC);
CREATE INDEX idx_users_role_active ON users (role, is_active, created_at DESC);

-- Index composés
CREATE INDEX idx_posts_author_status ON posts (author_id, status, published_at DESC);
CREATE INDEX idx_comments_post_author ON comments (post_id, author_id, created_at DESC);

-- Index partiels (PostgreSQL)
CREATE INDEX idx_posts_published_recent ON posts (published_at DESC)
WHERE status = 'published' AND published_at > NOW() - INTERVAL '30 days';
```

### Query optimization

```javascript
// ✅ Optimisation des requêtes Sequelize
app.get('/api/users', async (req, res) => {
  const { page = 1, limit = 20, include, sort, order } = req.query;

  const offset = (parseInt(page) - 1) * parseInt(limit);

  // ✅ Sélectionner seulement les champs nécessaires
  const attributes = ['id', 'firstName', 'lastName', 'email', 'createdAt'];

  // ✅ Inclure les relations de manière optimisée
  const includeOptions = [];
  if (include === 'posts') {
    includeOptions.push({
      model: Post,
      as: 'posts',
      attributes: ['id', 'title', 'status'],
      limit: 5, // Limiter le nombre de posts
      order: [['createdAt', 'DESC']]
    });
  }

  // ✅ Tri optimisé
  const orderBy = sort ? [[sort, order || 'ASC']] : [['createdAt', 'DESC']];

  const users = await User.findAll({
    attributes,
    include: includeOptions,
    limit: Math.min(parseInt(limit), 100),
    offset,
    order: orderBy,
    // ✅ Logging pour le debugging
    logging: (sql) => console.log('Query:', sql)
  });

  res.json({
    data: users,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: await User.count() // À optimiser avec une estimation
    }
  });
});
```

## Compression

### Compression Gzip

```javascript
// ✅ Compression automatique
const compression = require('compression');

app.use(compression({
  level: 6, // Niveau de compression (1-9)
  threshold: 1024, // Seuil en octets
  filter: (req, res) => {
    // Ne pas compresser les réponses déjà compressées
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// ✅ Vérification de la compression
app.get('/api/data', (req, res) => {
  const data = generateLargeDataSet();

  res.set('Content-Encoding', 'gzip');
  res.json(data);
});
```

### Brotli

```javascript
// ✅ Compression Brotli (plus efficace que Gzip)
const express = require('express');
const compression = require('compression');

app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    // Préférer Brotli si supporté
    if (req.headers['accept-encoding']?.includes('br')) {
      res.set('Content-Encoding', 'br');
      return false; // Laisser Express gérer
    }
    return compression.filter(req, res);
  }
}));
```

## Monitoring des performances

### Métriques de cache

```javascript
// ✅ Monitoring du cache
const cacheMetrics = {
  hits: 0,
  misses: 0,
  errors: 0,

  recordHit() {
    this.hits++;
  },

  recordMiss() {
    this.misses++;
  },

  recordError() {
    this.errors++;
  },

  getHitRate() {
    const total = this.hits + this.misses;
    return total > 0 ? (this.hits / total) * 100 : 0;
  },

  getStats() {
    return {
      hits: this.hits,
      misses: this.misses,
      errors: this.errors,
      hitRate: this.getHitRate(),
      total: this.hits + this.misses + this.errors
    };
  }
};

// ✅ Middleware de métriques
app.use('/api', (req, res, next) => {
  res.on('finish', () => {
    if (res.get('X-Cache') === 'HIT') {
      cacheMetrics.recordHit();
    } else {
      cacheMetrics.recordMiss();
    }
  });
  next();
});

// ✅ Endpoint de métriques
app.get('/api/metrics/cache', (req, res) => {
  res.json(cacheMetrics.getStats());
});
```

### APM (Application Performance Monitoring)

```javascript
// ✅ Configuration New Relic
const newrelic = require('newrelic');

// ✅ Monitoring personnalisé
const monitorAPI = (req, res, next) => {
  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const endpoint = req.route?.path || req.path;

    // Enregistrer les métriques
    if (duration > 1000) {
      console.warn(`Slow request: ${req.method} ${endpoint} - ${duration}ms`);
    }

    // Métriques par endpoint
    const metricsKey = `${req.method}:${endpoint}`;
    updateEndpointMetrics(metricsKey, duration, res.statusCode);
  });

  next();
};

app.use('/api', monitorAPI);
```

## Configuration de production

### Cache multi-niveaux

```javascript
// ✅ Stratégie de cache multi-niveaux
const cacheStrategy = {
  // Niveau 1: Cache en mémoire (rapide, volatile)
  memory: new MemoryCache(),

  // Niveau 2: Redis (rapide, distribué)
  redis: distributedCache,

  // Niveau 3: Base de données (lent, persistant)
  database: getDataFromDatabase
};

// ✅ Middleware de cache intelligent
const smartCache = (ttl = 3600) => {
  return async (req, res, next) => {
    const cacheKey = `api:${req.method}:${req.originalUrl}`;

    // 1. Vérifier le cache mémoire
    let data = cacheStrategy.memory.get(cacheKey);
    if (data) {
      res.set('X-Cache-Layer', 'memory');
      return res.json(data);
    }

    // 2. Vérifier Redis
    data = await cacheStrategy.redis.get(cacheKey);
    if (data) {
      // Promouvoir dans le cache mémoire
      cacheStrategy.memory.set(cacheKey, data, 300); // 5 minutes
      res.set('X-Cache-Layer', 'redis');
      return res.json(data);
    }

    // 3. Récupérer depuis la base de données
    const originalSend = res.send;
    res.send = function(data) {
      try {
        const jsonData = JSON.parse(data);

        // Mettre en cache Redis
        cacheStrategy.redis.set(cacheKey, jsonData, ttl);

        // Mettre en cache mémoire (court)
        cacheStrategy.memory.set(cacheKey, jsonData, 300);

        res.set('X-Cache-Layer', 'database');
      } catch (error) {
        // Erreur de parsing JSON
      }

      originalSend.call(this, data);
    };

    next();
  };
};
```

### Configuration CDN

```javascript
// ✅ Configuration CloudFlare
const cdnConfig = {
  // Cache rules
  cacheRules: [
    {
      pattern: '/api/users/*',
      ttl: 1800, // 30 minutes
      cacheLevel: 'cache_everything'
    },
    {
      pattern: '/api/posts/*',
      ttl: 3600, // 1 heure
      cacheLevel: 'cache_everything'
    },
    {
      pattern: '/api/auth/*',
      ttl: 0, // Pas de cache
      cacheLevel: 'bypass'
    }
  ],

  // Cache invalidation
  invalidateCache: async (patterns) => {
    const response = await fetch('https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        files: patterns
      })
    });

    return response.json();
  }
};

// ✅ Invalidation automatique du cache
app.post('/api/posts/:id/publish', async (req, res) => {
  const post = await getPostById(req.params.id);

  // Publier le post
  await post.publish();

  // Invalider le cache
  await cdnConfig.invalidateCache([
    `/api/posts/${post.id}`,
    `/api/posts?author=${post.authorId}`,
    '/api/posts' // Invalider la liste aussi
  ]);

  res.json({ message: 'Post published and cache invalidated' });
});
```

## Tests de performance

### Tests avec Artillery

```yaml
# artillery.yml
config:
  target: 'http://localhost:8000'
  phases:
    - duration: 60
      arrivalRate: 10
    - duration: 120
      arrivalRate: 50
    - duration: 60
      arrivalRate: 100
  defaults:
    headers:
      Content-Type: 'application/json'

scenarios:
  - name: 'Get users'
    requests:
      - get:
          url: '/api/users'
          expect:
            - statusCode: [200]

  - name: 'Get user profile'
    requests:
      - get:
          url: '/api/users/123'
          headers:
            Authorization: 'Bearer {{ accessToken }}'
          expect:
            - statusCode: [200]

  - name: 'Create post'
    requests:
      - post:
          url: '/api/posts'
          headers:
            Authorization: 'Bearer {{ accessToken }}'
          json:
            title: 'Test Post'
            content: 'Test content'
          expect:
            - statusCode: [201]
```

### Tests avec K6

```javascript
// k6-performance-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '30s', target: 50 },   // Ramp up to 50 users
    { duration: '1m', target: 100 },   // Ramp up to 100 users
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% des requêtes < 500ms
    http_req_failed: ['rate<0.05'],    // Taux d'erreur < 5%
    http_reqs: ['rate>100'],           // Plus de 100 req/s
  },
};

export default function () {
  const baseUrl = 'http://localhost:8000/api';

  // Test sans cache
  const response1 = http.get(`${baseUrl}/users/123`);
  check(response1, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
    'cache miss': (r) => r.headers['X-Cache'] === 'MISS',
  });

  // Test avec cache
  const response2 = http.get(`${baseUrl}/users/123`);
  check(response2, {
    'status is 200': (r) => r.status === 200,
    'cache hit': (r) => r.headers['X-Cache'] === 'HIT',
    'response time < 50ms': (r) => r.timings.duration < 50,
  });

  sleep(1);
}
```

## Quiz du cache et CDN

**Question 1** : Quelle est la différence entre cache et CDN ?
**Réponse** : Le cache stocke les données près du serveur, le CDN les distribue globalement

**Question 2** : Quand utiliser ETags vs Last-Modified ?
**Réponse** : ETags pour la validation de contenu, Last-Modified pour les dates

**Question 3** : Comment invalider le cache après une mise à jour ?
**Réponse** : Supprimer les clés de cache ou utiliser des tags d'invalidation

## En résumé

### Stratégies de cache
1. **HTTP Cache** : Cache-Control, ETags, Last-Modified
2. **Cache serveur** : Redis, Memcached, cache en mémoire
3. **Cache edge** : CDN comme CloudFlare
4. **Cache application** : Cache intelligent multi-niveaux

### Optimisations
- ✅ **Pagination** avec curseurs
- ✅ **Index** de base de données optimisés
- ✅ **Compression** Gzip/Brotli
- ✅ **Monitoring** des performances
- ✅ **Tests de charge** automatisés

### Configuration recommandée
```javascript
// Cache multi-niveaux
{
  memory: 5 * 60 * 1000,    // 5 minutes
  redis: 30 * 60 * 1000,    // 30 minutes
  cdn: 60 * 60 * 1000       // 1 heure
}

// Headers de cache
{
  'Cache-Control': 'public, max-age=3600',
  'ETag': 'unique-version',
  'Last-Modified': 'timestamp'
}
```

### Performance monitoring
- 📊 **Métriques** de cache (hit rate, miss rate)
- ⏱️ **Temps de réponse** par endpoint
- 🔄 **Taux d'utilisation** du cache
- 🚨 **Alertes** de performance

Dans le prochain chapitre, nous explorerons la **pagination**, le **filtrage** et l'**optimisation des requêtes** !

---

**Prochain chapitre** : [02-Pagination-et-Filtrage](02-Pagination-et-Filtrage.md)
