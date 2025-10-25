# Pagination et Filtrage

## Introduction

Les APIs modernes doivent gérer de **grandes quantités de données**. Sans **pagination** et **filtrage** appropriés, les réponses peuvent devenir énormes et ralentir votre application. Dans ce chapitre, nous allons explorer les meilleures pratiques pour implémenter une pagination efficace, des filtres avancés et des mécanismes de tri qui maintiennent les performances de votre API.

## Pagination

### Types de pagination

#### 1. Pagination offset-based

```javascript
// ✅ Pagination par offset (classique)
app.get('/api/users', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const offset = (page - 1) * limit;

  const users = await User.findAll({
    limit,
    offset,
    order: [['createdAt', 'DESC']]
  });

  const total = await User.count();

  res.json({
    data: users,
    pagination: {
      current_page: page,
      per_page: limit,
      total,
      total_pages: Math.ceil(total / limit),
      from: offset + 1,
      to: offset + users.length,
      has_more: page < Math.ceil(total / limit)
    },
    _links: {
      self: `/api/users?page=${page}&limit=${limit}`,
      first: `/api/users?page=1&limit=${limit}`,
      last: `/api/users?page=${Math.ceil(total / limit)}&limit=${limit}`,
      next: page < Math.ceil(total / limit) ? `/api/users?page=${page + 1}&limit=${limit}` : null,
      prev: page > 1 ? `/api/users?page=${page - 1}&limit=${limit}` : null
    }
  });
});
```

#### 2. Pagination cursor-based

```javascript
// ✅ Pagination par curseur (performante pour les grandes collections)
app.get('/api/posts', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const cursor = req.query.cursor;

  let query = Post.query().orderBy('created_at', 'desc').orderBy('id', 'desc');

  if (cursor) {
    // Décoder le curseur (base64 de timestamp:id)
    const [timestamp, id] = Buffer.from(cursor, 'base64').toString().split(':');
    query = query.where('created_at', '<', timestamp)
                 .orWhere(function(q) {
                   q.where('created_at', '=', timestamp)
                    .where('id', '<', id);
                 });
  }

  const posts = await query.limit(limit + 1).get();
  const hasMore = posts.length > limit;

  if (hasMore) {
    posts.pop(); // Retirer l'élément extra
  }

  // Générer le prochain curseur
  const nextCursor = hasMore ?
    Buffer.from(`${posts[posts.length - 1].created_at}:${posts[posts.length - 1].id}`).toString('base64') :
    null;

  res.json({
    data: posts,
    pagination: {
      limit,
      has_more: hasMore,
      next_cursor: nextCursor,
      count: posts.length
    },
    _links: {
      self: `/api/posts?limit=${limit}${cursor ? `&cursor=${cursor}` : ''}`,
      next: nextCursor ? `/api/posts?limit=${limit}&cursor=${nextCursor}` : null
    }
  });
});
```

#### 3. Pagination basée sur le temps

```javascript
// ✅ Pagination par timestamp (pour les flux temps réel)
app.get('/api/events', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 500);
  const before = req.query.before; // Timestamp
  const after = req.query.after;   // Timestamp

  let query = Event.query().orderBy('created_at', 'desc');

  if (before) {
    query = query.where('created_at', '<', new Date(before));
  }

  if (after) {
    query = query.where('created_at', '>', new Date(after));
  }

  const events = await query.limit(limit).get();

  res.json({
    data: events,
    pagination: {
      limit,
      before: events.length > 0 ? events[0].created_at : null,
      after: events.length > 0 ? events[events.length - 1].created_at : null
    },
    _links: {
      self: `/api/events?limit=${limit}${before ? `&before=${before}` : ''}${after ? `&after=${after}` : ''}`
    }
  });
});
```

## Filtrage avancé

### Filtres de base

```javascript
// ✅ Filtres simples
app.get('/api/users', async (req, res) => {
  const filters = {};

  // Filtres par statut
  if (req.query.active !== undefined) {
    filters.isActive = req.query.active === 'true';
  }

  // Filtres par rôle
  if (req.query.role) {
    filters.role = req.query.role;
  }

  // Filtres par date
  if (req.query.created_after) {
    filters.createdAt = {
      [Op.gte]: new Date(req.query.created_after)
    };
  }

  if (req.query.created_before) {
    filters.createdAt = {
      ...filters.createdAt,
      [Op.lte]: new Date(req.query.created_before)
    };
  }

  const users = await User.findAll({
    where: filters,
    order: [['createdAt', 'DESC']]
  });

  res.json({ data: users });
});
```

### Filtres complexes

```javascript
// ✅ Filtres avancés avec opérateurs
app.get('/api/products', async (req, res) => {
  const filters = {};

  // Filtres de prix
  if (req.query.price_min || req.query.price_max) {
    filters.price = {};
    if (req.query.price_min) {
      filters.price[Op.gte] = parseFloat(req.query.price_min);
    }
    if (req.query.price_max) {
      filters.price[Op.lte] = parseFloat(req.query.price_max);
    }
  }

  // Filtres par catégorie
  if (req.query.category_id) {
    filters.categoryId = req.query.category_id;
  }

  // Filtres par tags (many-to-many)
  if (req.query.tags) {
    const tagIds = req.query.tags.split(',').map(id => parseInt(id));
    filters['$tags.id$'] = { [Op.in]: tagIds };
  }

  // Filtres géographiques
  if (req.query.lat && req.query.lng && req.query.radius) {
    const { lat, lng, radius } = req.query;
    // Calcul de distance avec PostGIS ou approximation
    filters.latitude = {
      [Op.between]: [lat - radius, lat + radius]
    };
    filters.longitude = {
      [Op.between]: [lng - radius, lng + radius]
    };
  }

  // Recherche textuelle
  if (req.query.search) {
    filters[Op.or] = [
      { name: { [Op.iLike]: `%${req.query.search}%` } },
      { description: { [Op.iLike]: `%${req.query.search}%` } }
    ];
  }

  const products = await Product.findAll({
    where: filters,
    include: [
      { model: Category, as: 'category' },
      { model: Tag, as: 'tags' }
    ]
  });

  res.json({ data: products });
});
```

### Filtres dynamiques

```javascript
// ✅ Système de filtres configurable
const filterConfig = {
  users: {
    active: { type: 'boolean', field: 'isActive' },
    role: { type: 'enum', field: 'role', values: ['admin', 'user', 'moderator'] },
    created_after: { type: 'date', field: 'createdAt', operator: 'gte' },
    created_before: { type: 'date', field: 'createdAt', operator: 'lte' },
    age_min: { type: 'number', field: 'age', operator: 'gte' },
    age_max: { type: 'number', field: 'age', operator: 'lte' }
  },
  posts: {
    status: { type: 'enum', field: 'status', values: ['draft', 'published', 'archived'] },
    author: { type: 'relation', field: 'authorId' },
    category: { type: 'relation', field: 'categoryId' },
    published_after: { type: 'date', field: 'publishedAt', operator: 'gte' },
    tags: { type: 'array', relation: 'tags', field: 'id' }
  }
};

const applyFilters = (model, filters, config) => {
  const whereClause = {};

  for (const [key, value] of Object.entries(filters)) {
    if (config[key]) {
      const filterConfig = config[key];

      switch (filterConfig.type) {
        case 'boolean':
          whereClause[filterConfig.field] = value === 'true';
          break;

        case 'enum':
          if (filterConfig.values.includes(value)) {
            whereClause[filterConfig.field] = value;
          }
          break;

        case 'date':
          whereClause[filterConfig.field] = {
            [Op[filterConfig.operator || 'eq']]: new Date(value)
          };
          break;

        case 'number':
          whereClause[filterConfig.field] = {
            [Op[filterConfig.operator || 'eq']]: parseFloat(value)
          };
          break;

        case 'relation':
          whereClause[filterConfig.field] = value;
          break;

        case 'array':
          // Pour les relations many-to-many
          break;
      }
    }
  }

  return whereClause;
};
```

## Tri et recherche

### Tri multiple

```javascript
// ✅ Tri sur plusieurs champs
app.get('/api/users', async (req, res) => {
  const sortFields = req.query.sort ? req.query.sort.split(',') : ['createdAt'];
  const sortOrders = req.query.order ? req.query.order.split(',') : ['DESC'];

  // Validation des champs de tri autorisés
  const allowedSortFields = ['id', 'firstName', 'lastName', 'email', 'createdAt', 'updatedAt'];
  const validSortFields = sortFields.filter(field => allowedSortFields.includes(field));

  // Construction de l'ordre de tri
  const order = validSortFields.map((field, index) => [
    field,
    sortOrders[index]?.toUpperCase() === 'ASC' ? 'ASC' : 'DESC'
  ]);

  const users = await User.findAll({
    order,
    // Autres options...
  });

  res.json({ data: users });
});
```

### Recherche full-text

```javascript
// ✅ Recherche full-text avec PostgreSQL
app.get('/api/articles/search', async (req, res) => {
  const { q, limit = 20 } = req.query;

  if (!q || q.length < 2) {
    return res.status(400).json({
      error: 'invalid_query',
      message: 'Search query must be at least 2 characters'
    });
  }

  // Recherche avec ILIKE (PostgreSQL)
  const articles = await Article.findAll({
    where: {
      [Op.or]: [
        { title: { [Op.iLike]: `%${q}%` } },
        { content: { [Op.iLike]: `%${q}%` } },
        { excerpt: { [Op.iLike]: `%${q}%` } }
      ],
      status: 'published' // Seulement les articles publiés
    },
    order: [
      // Tri par pertinence (plus de matches = plus pertinent)
      [sequelize.literal(`(
        CASE
          WHEN title ILIKE '%${q}%' THEN 3
          WHEN excerpt ILIKE '%${q}%' THEN 2
          WHEN content ILIKE '%${q}%' THEN 1
          ELSE 0
        END
      )`), 'DESC'],
      ['publishedAt', 'DESC']
    ],
    limit: Math.min(parseInt(limit), 100)
  });

  res.json({
    data: articles,
    query: q,
    total: articles.length
  });
});
```

### Recherche Elasticsearch

```javascript
// ✅ Configuration Elasticsearch
const elasticsearch = require('elasticsearch');

const esClient = new elasticsearch.Client({
  host: 'localhost:9200',
  log: 'trace'
});

// ✅ Recherche avec Elasticsearch
app.get('/api/search', async (req, res) => {
  const { q, type, limit = 20, offset = 0 } = req.query;

  if (!q) {
    return res.status(400).json({
      error: 'query_required',
      message: 'Search query is required'
    });
  }

  const searchBody = {
    query: {
      multi_match: {
        query: q,
        fields: ['title^3', 'content^2', 'excerpt', 'tags.name'],
        fuzziness: 'AUTO'
      }
    },
    highlight: {
      fields: {
        title: {},
        content: {},
        excerpt: {}
      }
    },
    sort: [
      { _score: { order: 'desc' } },
      { created_at: { order: 'desc' } }
    ],
    size: limit,
    from: offset
  };

  // Filtrage par type
  if (type) {
    searchBody.query = {
      bool: {
        must: searchBody.query,
        filter: {
          term: { type: type }
        }
      }
    };
  }

  const result = await esClient.search({
    index: 'blog_content',
    body: searchBody
  });

  res.json({
    data: result.hits.hits.map(hit => ({
      ...hit._source,
      highlights: hit.highlight
    })),
    total: result.hits.total,
    query: q,
    pagination: {
      limit: parseInt(limit),
      offset: parseInt(offset)
    }
  });
});
```

## Optimisation des requêtes

### Index de base de données avancés

```sql
-- ✅ Index pour la recherche
CREATE INDEX CONCURRENTLY idx_articles_search ON articles
USING gin (to_tsvector('english', title || ' ' || content || ' ' || excerpt));

-- ✅ Index pour les filtres
CREATE INDEX idx_posts_category_status ON posts (category_id, status, published_at DESC);
CREATE INDEX idx_users_role_active ON users (role, is_active, created_at DESC);

-- ✅ Index partiels pour les requêtes courantes
CREATE INDEX idx_posts_published_recent ON posts (published_at DESC, id DESC)
WHERE status = 'published' AND published_at > NOW() - INTERVAL '30 days';

-- ✅ Index pour les relations
CREATE INDEX idx_post_tags_post_id ON post_tags (post_id, tag_id);
CREATE INDEX idx_post_tags_tag_id ON post_tags (tag_id, post_id);
```

### Query optimization

```javascript
// ✅ Optimisation avec includes sélectifs
app.get('/api/posts', async (req, res) => {
  const { include, fields } = req.query;

  // Inclure seulement si demandé
  const includeOptions = [];
  if (include === 'author') {
    includeOptions.push({
      model: User,
      as: 'author',
      attributes: ['id', 'firstName', 'lastName', 'avatar']
    });
  }

  if (include === 'comments') {
    includeOptions.push({
      model: Comment,
      as: 'comments',
      attributes: ['id', 'content', 'createdAt'],
      limit: 5,
      order: [['createdAt', 'DESC']]
    });
  }

  // Sélectionner seulement les champs demandés
  const defaultFields = ['id', 'title', 'excerpt', 'status', 'publishedAt', 'createdAt'];
  const requestedFields = fields ? fields.split(',') : defaultFields;
  const allowedFields = ['id', 'title', 'content', 'excerpt', 'status', 'publishedAt', 'createdAt', 'updatedAt', 'authorId'];

  const attributes = requestedFields.filter(field => allowedFields.includes(field));

  const posts = await Post.findAll({
    attributes,
    include: includeOptions,
    where: buildFilters(req.query),
    order: buildOrder(req.query),
    limit: getLimit(req.query),
    offset: getOffset(req.query)
  });

  res.json({ data: posts });
});
```

### Aggrégations et facettes

```javascript
// ✅ Facettes pour le filtrage
app.get('/api/products/facets', async (req, res) => {
  const facets = await Product.findAll({
    attributes: [
      'categoryId',
      [sequelize.fn('COUNT', sequelize.col('id')), 'count']
    ],
    include: [{
      model: Category,
      as: 'category',
      attributes: ['id', 'name']
    }],
    group: ['categoryId', 'category.id'],
    raw: true
  });

  // Prix min/max
  const priceStats = await Product.findOne({
    attributes: [
      [sequelize.fn('MIN', sequelize.col('price')), 'minPrice'],
      [sequelize.fn('MAX', sequelize.col('price')), 'maxPrice'],
      [sequelize.fn('AVG', sequelize.col('price')), 'avgPrice']
    ],
    raw: true
  });

  res.json({
    facets: {
      categories: facets,
      price: {
        min: parseFloat(priceStats.minPrice),
        max: parseFloat(priceStats.maxPrice),
        avg: parseFloat(priceStats.avgPrice)
      }
    }
  });
});
```

## API de recherche avancée

### Recherche avec filtres

```javascript
// ✅ Recherche avec filtres dynamiques
app.get('/api/search', async (req, res) => {
  const { q, type, filters, sort, order } = req.query;

  let query = {};

  // Recherche textuelle
  if (q) {
    query[Op.or] = [
      { title: { [Op.iLike]: `%${q}%` } },
      { content: { [Op.iLike]: `%${q}%` } },
      { description: { [Op.iLike]: `%${q}%` } }
    ];
  }

  // Filtres par type
  if (type) {
    query.type = type;
  }

  // Filtres dynamiques
  if (filters) {
    const parsedFilters = JSON.parse(filters);
    Object.assign(query, parsedFilters);
  }

  const results = await SearchableContent.findAll({
    where: query,
    order: sort ? [[sort, order || 'ASC']] : [['createdAt', 'DESC']],
    limit: Math.min(parseInt(req.query.limit) || 20, 100)
  });

  res.json({
    data: results,
    query: q,
    filters: filters ? JSON.parse(filters) : {},
    total: results.length
  });
});
```

### Suggestions de recherche

```javascript
// ✅ Autocomplétion
app.get('/api/search/suggest', async (req, res) => {
  const { q, limit = 10 } = req.query;

  if (!q || q.length < 2) {
    return res.json({ suggestions: [] });
  }

  // Suggestions depuis différentes sources
  const [articleSuggestions, tagSuggestions, userSuggestions] = await Promise.all([
    // Suggestions d'articles
    Article.findAll({
      where: {
        [Op.or]: [
          { title: { [Op.iLike]: `${q}%` } },
          { title: { [Op.iLike]: `% ${q}%` } }
        ],
        status: 'published'
      },
      attributes: ['title'],
      limit: Math.floor(limit / 3)
    }),

    // Suggestions de tags
    Tag.findAll({
      where: {
        name: { [Op.iLike]: `${q}%` }
      },
      attributes: ['name'],
      limit: Math.floor(limit / 3)
    }),

    // Suggestions d'utilisateurs
    User.findAll({
      where: {
        [Op.or]: [
          { firstName: { [Op.iLike]: `${q}%` } },
          { lastName: { [Op.iLike]: `${q}%` } }
        ]
      },
      attributes: ['firstName', 'lastName'],
      limit: Math.floor(limit / 3)
    })
  ]);

  const suggestions = [
    ...articleSuggestions.map(a => ({ type: 'article', text: a.title })),
    ...tagSuggestions.map(t => ({ type: 'tag', text: t.name })),
    ...userSuggestions.map(u => ({ type: 'user', text: u.getFullName() }))
  ].slice(0, limit);

  res.json({ suggestions, query: q });
});
```

## Gestion des performances

### Monitoring des requêtes lentes

```javascript
// ✅ Middleware de monitoring
const queryMonitor = (req, res, next) => {
  const startTime = Date.now();
  const originalSend = res.send;

  res.send = function(data) {
    const duration = Date.now() - startTime;

    // Log des requêtes lentes
    if (duration > 1000) {
      console.warn(`Slow query: ${req.method} ${req.originalUrl} - ${duration}ms`);
    }

    // Métriques par endpoint
    recordEndpointMetrics(req.route?.path || req.path, duration, res.statusCode);

    originalSend.call(this, data);
  };

  next();
};

app.use('/api', queryMonitor);
```

### Optimisation des N+1 queries

```javascript
// ❌ Problème N+1
app.get('/api/posts', async (req, res) => {
  const posts = await Post.findAll();

  // N+1 : Une requête par post pour récupérer l'auteur
  for (const post of posts) {
    post.author = await User.findByPk(post.authorId);
  }

  res.json({ data: posts });
});

// ✅ Solution avec includes
app.get('/api/posts', async (req, res) => {
  const posts = await Post.findAll({
    include: [{
      model: User,
      as: 'author',
      attributes: ['id', 'firstName', 'lastName', 'avatar']
    }]
  });

  res.json({ data: posts });
});
```

## Tests de performance

### Tests avec Artillery

```yaml
# artillery-pagination-test.yml
config:
  target: 'http://localhost:8000'
  phases:
    - duration: 60
      arrivalRate: 20
    - duration: 120
      arrivalRate: 100
  defaults:
    headers:
      Content-Type: 'application/json'

scenarios:
  - name: 'Pagination test'
    requests:
      - get:
          url: '/api/posts?page=1&limit=20'
          expect:
            - statusCode: [200]
            - hasProperty: 'data'
            - hasProperty: 'pagination'

      - get:
          url: '/api/posts?page=100&limit=20'
          expect:
            - statusCode: [200]

      - get:
          url: '/api/posts?cursor={{ cursor }}&limit=20'
          expect:
            - statusCode: [200]

  - name: 'Filtering test'
    requests:
      - get:
          url: '/api/posts?status=published&limit=20'
          expect:
            - statusCode: [200]

      - get:
          url: '/api/posts?author_id=123&limit=20'
          expect:
            - statusCode: [200]

  - name: 'Search test'
    requests:
      - get:
          url: '/api/posts?search=javascript&limit=20'
          expect:
            - statusCode: [200]
```

### Tests avec K6

```javascript
// k6-pagination-test.js
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  scenarios: {
    constant_load: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 100,
      maxVUs: 200,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.1'],
  },
};

export default function () {
  const baseUrl = 'http://localhost:8000/api';

  // Test pagination offset
  const offsetResponse = http.get(`${baseUrl}/users?page=5&limit=20`);
  check(offsetResponse, {
    'offset pagination status 200': (r) => r.status === 200,
    'offset pagination has data': (r) => JSON.parse(r.body).data.length > 0,
    'offset pagination has pagination': (r) => JSON.parse(r.body).pagination !== undefined,
  });

  // Test pagination curseur
  const cursorResponse = http.get(`${baseUrl}/posts?limit=20`);
  check(cursorResponse, {
    'cursor pagination status 200': (r) => r.status === 200,
    'cursor pagination has data': (r) => JSON.parse(r.body).data.length > 0,
  });

  // Test filtrage
  const filterResponse = http.get(`${baseUrl}/posts?status=published&limit=20`);
  check(filterResponse, {
    'filter status 200': (r) => r.status === 200,
    'filter has results': (r) => JSON.parse(r.body).data.length >= 0,
  });

  // Test recherche
  const searchResponse = http.get(`${baseUrl}/search?q=test&limit=20`);
  check(searchResponse, {
    'search status 200': (r) => r.status === 200,
    'search has results': (r) => JSON.parse(r.body).data.length >= 0,
  });
}
```

## Quiz de la pagination et du filtrage

**Question 1** : Quelle est la différence entre pagination offset et curseur ?
**Réponse** : Offset peut causer des problèmes de performance avec les grandes collections, curseur est plus stable

**Question 2** : Quand utiliser la recherche full-text ?
**Réponse** : Pour la recherche dans le contenu textuel avec pertinence et highlighting

**Question 3** : Comment optimiser les requêtes avec relations ?
**Réponse** : Utiliser includes sélectifs et éviter les N+1 queries

## En résumé

### Types de pagination
1. **Offset-based** : Classique mais peut être lent
2. **Cursor-based** : Stable pour les grandes collections
3. **Time-based** : Pour les flux chronologiques

### Filtres et recherche
- 🔍 **Filtres** : Par statut, date, relations
- 📝 **Recherche** : Full-text avec PostgreSQL/Elasticsearch
- 📊 **Facettes** : Agrégations pour le filtrage
- 🔄 **Autocomplétion** : Suggestions en temps réel

### Optimisations
- ✅ **Index** optimisés pour les requêtes courantes
- ✅ **Includes sélectifs** pour éviter N+1
- ✅ **Validation** des paramètres de requête
- ✅ **Monitoring** des performances
- ✅ **Tests de charge** automatisés

### Configuration recommandée
```javascript
// Pagination
{
  page: 1,
  limit: 20,
  maxLimit: 100,
  defaultSort: 'created_at',
  defaultOrder: 'desc'
}

// Cache
{
  users: 1800,      // 30 minutes
  posts: 3600,      // 1 heure
  search: 300       // 5 minutes
}
```

Dans le prochain chapitre, nous explorerons le **logging**, le **monitoring** et les outils de **debugging** !

---

**Prochain chapitre** : [03-Logs-et-Monitoring](03-Logs-et-Monitoring.md)
