# Scalabilité et Microservices

## Introduction

La **scalabilité** est la capacité d'une API à gérer une **charge croissante** sans dégradation des performances. Les **microservices** sont une architecture qui permet de construire des systèmes distribués et scalables. Dans ce chapitre, nous allons explorer les stratégies de scalabilité, la conception de microservices et les outils pour gérer une architecture distribuée.

## Scalabilité horizontale vs verticale

### Scalabilité verticale

```javascript
// ✅ Augmentation des ressources serveur
const serverConfig = {
  // Serveur plus puissant
  cpu: '16 cores',
  memory: '64GB RAM',
  storage: '1TB SSD',
  network: '10Gbps'
};

// ✅ Optimisation du serveur unique
app.use('/api', (req, res, next) => {
  // Optimisations pour serveur unique
  res.set('X-Served-By', 'main-server');
  next();
});
```

### Scalabilité horizontale

```javascript
// ✅ Load balancing avec Nginx
const nginxConfig = `
upstream api_servers {
    server api1.example.com:8000;
    server api2.example.com:8000;
    server api3.example.com:8000;
}

server {
    listen 80;
    server_name api.example.com;

    location /api/ {
        proxy_pass http://api_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;

// ✅ Session sticky pour la gestion d'état
const stickyConfig = `
upstream api_servers {
    ip_hash;  # Session sticky par IP
    server api1.example.com:8000;
    server api2.example.com:8000;
    server api3.example.com:8000;
}
`;
```

## Architecture microservices

### Décomposition en services

```javascript
// ✅ Services identifiés
const services = {
  'user-service': {
    port: 8001,
    endpoints: ['/users', '/auth', '/profile'],
    database: 'users_db',
    responsibilities: ['Authentication', 'User management', 'Permissions']
  },

  'post-service': {
    port: 8002,
    endpoints: ['/posts', '/comments', '/tags'],
    database: 'posts_db',
    responsibilities: ['Post management', 'Comments', 'Search']
  },

  'notification-service': {
    port: 8003,
    endpoints: ['/notifications', '/email', '/push'],
    database: 'notifications_db',
    responsibilities: ['Email sending', 'Push notifications', 'SMS']
  },

  'api-gateway': {
    port: 8000,
    endpoints: ['/api/*'],
    responsibilities: ['Routing', 'Authentication', 'Rate limiting']
  }
};
```

### API Gateway

```javascript
// ✅ Configuration API Gateway avec Express
const express = require('express');
const proxy = require('express-http-proxy');
const app = express();

// ✅ Route vers les services
app.use('/api/users', proxy('http://user-service:8001', {
  proxyReqPathResolver: (req) => req.originalUrl.replace('/api/users', ''),
  proxyErrorHandler: (err, res, next) => {
    console.error('User service error:', err);
    res.status(503).json({ error: 'User service unavailable' });
  }
}));

app.use('/api/posts', proxy('http://post-service:8002', {
  proxyReqPathResolver: (req) => req.originalUrl.replace('/api/posts', ''),
  proxyErrorHandler: (err, res, next) => {
    console.error('Post service error:', err);
    res.status(503).json({ error: 'Post service unavailable' });
  }
}));

app.use('/api/notifications', proxy('http://notification-service:8003', {
  proxyReqPathResolver: (req) => req.originalUrl.replace('/api/notifications', ''),
  proxyErrorHandler: (err, res, next) => {
    console.error('Notification service error:', err);
    res.status(503).json({ error: 'Notification service unavailable' });
  }
}));

// ✅ Middleware global
app.use('/api', authenticateToken);
app.use('/api', rateLimitMiddleware);

// ✅ Health check du gateway
app.get('/api/health', async (req, res) => {
  const services = [
    'http://user-service:8001/health',
    'http://post-service:8002/health',
    'http://notification-service:8003/health'
  ];

  const health = { status: 'healthy', services: {} };

  for (const service of services) {
    try {
      const response = await fetch(service);
      health.services[service] = {
        status: response.ok ? 'healthy' : 'unhealthy',
        responseTime: response.headers.get('x-response-time')
      };
    } catch (error) {
      health.services[service] = {
        status: 'unhealthy',
        error: error.message
      };
      health.status = 'degraded';
    }
  }

  res.status(health.status === 'healthy' ? 200 : 503).json(health);
});
```

### Communication inter-services

#### 1. REST API

```javascript
// ✅ Communication REST entre services
const callUserService = async (endpoint, options = {}) => {
  const response = await fetch(`http://user-service:8001${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${getServiceToken()}`,
      'Content-Type': 'application/json',
      ...options.headers
    },
    ...options
  });

  if (!response.ok) {
    throw new Error(`User service error: ${response.status}`);
  }

  return response.json();
};

// ✅ Usage dans un autre service
app.post('/api/posts', async (req, res) => {
  try {
    // Vérifier que l'utilisateur existe
    const user = await callUserService(`/api/users/${req.body.authorId}`);

    // Créer le post
    const post = await createPost({
      ...req.body,
      author: user.data
    });

    res.status(201).json(post);
  } catch (error) {
    if (error.message.includes('404')) {
      return res.status(404).json({ error: 'Author not found' });
    }
    res.status(500).json({ error: 'Service error' });
  }
});
```

#### 2. Message Queue (RabbitMQ)

```javascript
// ✅ Configuration RabbitMQ
const amqp = require('amqplib');
const queueConfig = {
  url: 'amqp://localhost:5672',
  queues: {
    userCreated: 'user.created',
    postPublished: 'post.published',
    emailSend: 'email.send'
  }
};

// ✅ Publication de messages
const publishMessage = async (queue, message) => {
  const connection = await amqp.connect(queueConfig.url);
  const channel = await connection.createChannel();

  await channel.assertQueue(queue, { durable: true });
  await channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)), {
    persistent: true
  });

  await channel.close();
  await connection.close();
};

// ✅ Consommation de messages
const consumeMessages = async (queue, handler) => {
  const connection = await amqp.connect(queueConfig.url);
  const channel = await connection.createChannel();

  await channel.assertQueue(queue, { durable: true });

  channel.consume(queue, async (msg) => {
    try {
      const data = JSON.parse(msg.content.toString());
      await handler(data);
      channel.ack(msg);
    } catch (error) {
      console.error('Message processing error:', error);
      channel.nack(msg, false, false); // Ne pas requeue
    }
  });

  process.on('SIGINT', () => {
    channel.close();
    connection.close();
  });
};
```

#### 3. gRPC

```javascript
// ✅ Configuration gRPC
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

// Chargement du proto
const userProto = grpc.loadPackageDefinition(
  protoLoader.loadSync('./proto/user.proto')
);

// ✅ Client gRPC
const userClient = new userProto.UserService(
  'user-service:50051',
  grpc.credentials.createInsecure()
);

// ✅ Appels gRPC
const getUserById = (userId) => {
  return new Promise((resolve, reject) => {
    userClient.GetUser({ id: userId }, (error, response) => {
      if (error) {
        reject(error);
      } else {
        resolve(response.user);
      }
    });
  });
};

// ✅ Serveur gRPC
const server = new grpc.Server();

server.addService(userProto.UserService.service, {
  GetUser: async (call, callback) => {
    try {
      const user = await User.findByPk(call.request.id);
      callback(null, { user });
    } catch (error) {
      callback(error);
    }
  }
});

server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
  console.log('gRPC server running on port 50051');
});
```

## Gestion d'état distribué

### Sessions distribuées

```javascript
// ✅ Redis pour les sessions
const redis = require('redis');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

const redisClient = redis.createClient({
  host: 'redis-cluster',
  port: 6379,
  password: process.env.REDIS_PASSWORD
});

// ✅ Configuration des sessions distribuées
app.use(session({
  store: new RedisStore({
    client: redisClient,
    ttl: 24 * 60 * 60 // 24 heures
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));
```

### Cache distribué

```javascript
// ✅ Configuration Redis Cluster
const Redis = require('ioredis');

const redisCluster = new Redis.Cluster([
  { host: 'redis-node-1', port: 6379 },
  { host: 'redis-node-2', port: 6379 },
  { host: 'redis-node-3', port: 6379 }
], {
  redisOptions: {
    password: process.env.REDIS_PASSWORD,
    db: 0
  },
  clusterRetryDelay: 100,
  enableReadyCheck: false,
  maxRetriesPerRequest: 3
});

// ✅ Cache distribué
class DistributedCache {
  async get(key) {
    try {
      const data = await redisCluster.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, value, ttl = 3600) {
    try {
      await redisCluster.setex(key, ttl, JSON.stringify(value));
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  async delete(key) {
    try {
      await redisCluster.del(key);
    } catch (error) {
      console.error('Cache delete error:', error);
    }
  }

  async invalidatePattern(pattern) {
    try {
      const keys = await redisCluster.keys(pattern);
      if (keys.length > 0) {
        await redisCluster.del(keys);
      }
    } catch (error) {
      console.error('Cache pattern invalidation error:', error);
    }
  }
}

const cache = new DistributedCache();
```

## Load Balancing

### Configuration Nginx

```nginx
# nginx.conf
upstream api_backend {
    least_conn;  # Load balancing par nombre de connexions
    server api1.example.com:8000 weight=3;
    server api2.example.com:8000 weight=2;
    server api3.example.com:8000 weight=1;
    server api4.example.com:8000 backup;  # Serveur de secours
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/api.example.com.crt;
    ssl_certificate_key /etc/ssl/private/api.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location /api/ {
        proxy_pass http://api_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;

        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_next_upstream_tries 3;
        proxy_next_upstream_timeout 30s;
    }
}
```

### Configuration HAProxy

```haproxy
# haproxy.cfg
frontend api_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/api.example.com.pem

    # ACL pour le routing
    acl is_auth path_beg /api/auth
    acl is_users path_beg /api/users
    acl is_posts path_beg /api/posts

    # Routing vers les services
    use_backend auth_backend if is_auth
    use_backend user_backend if is_users
    use_backend post_backend if is_posts

    default_backend api_backend

backend auth_backend
    balance roundrobin
    server auth1 auth-service-1:8001 check
    server auth2 auth-service-2:8001 check

backend user_backend
    balance leastconn
    server user1 user-service-1:8002 check
    server user2 user-service-2:8002 check
    server user3 user-service-3:8002 check

backend post_backend
    balance source  # Session sticky par IP
    server post1 post-service-1:8003 check
    server post2 post-service-2:8003 check

backend api_backend
    balance roundrobin
    server api1 api-server-1:8000 check
    server api2 api-server-2:8000 check
    server api3 api-server-3:8000 check
```

## Service Discovery

### Configuration Consul

```javascript
// ✅ Configuration Consul
const consul = require('consul');
const serviceConfig = {
  name: 'post-service',
  port: 8002,
  healthCheck: {
    http: 'http://localhost:8002/api/health',
    interval: '10s',
    timeout: '5s'
  }
};

// ✅ Enregistrement du service
const registerService = async () => {
  const consulClient = consul();

  await consulClient.agent.service.register({
    name: serviceConfig.name,
    address: 'post-service',
    port: serviceConfig.port,
    check: serviceConfig.healthCheck
  });

  console.log(`Service ${serviceConfig.name} registered with Consul`);
};

// ✅ Découverte de services
const discoverService = async (serviceName) => {
  const consulClient = consul();

  const services = await consulClient.health.service(serviceName);
  const healthyServices = services.filter(service => service.Checks.every(check => check.Status === 'passing'));

  return healthyServices.map(service => ({
    address: service.Service.Address,
    port: service.Service.Port
  }));
};

// ✅ Client avec découverte automatique
class ServiceClient {
  constructor(serviceName) {
    this.serviceName = serviceName;
    this.instances = [];
  }

  async getHealthyInstance() {
    if (this.instances.length === 0) {
      this.instances = await discoverService(this.serviceName);
    }

    // Round-robin
    const instance = this.instances.shift();
    this.instances.push(instance);

    return instance;
  }

  async call(endpoint, options = {}) {
    const instance = await this.getHealthyInstance();

    const response = await fetch(`http://${instance.address}:${instance.port}${endpoint}`, options);

    if (!response.ok) {
      throw new Error(`Service ${this.serviceName} error: ${response.status}`);
    }

    return response.json();
  }
}
```

## Circuit Breaker

### Pattern Circuit Breaker

```javascript
// ✅ Implémentation Circuit Breaker
class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.recoveryTimeout = options.recoveryTimeout || 60000; // 1 minute
    this.monitoringPeriod = options.monitoringPeriod || 10000; // 10 secondes

    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failures = 0;
    this.lastFailureTime = null;
    this.nextAttempt = null;
  }

  async execute(request) {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        throw new Error('Circuit breaker is OPEN');
      }
      this.state = 'HALF_OPEN';
    }

    try {
      const result = await request();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.recoveryTimeout;
    }
  }

  getState() {
    return {
      state: this.state,
      failures: this.failures,
      nextAttempt: this.nextAttempt
    };
  }
}

// ✅ Usage avec les services
const userServiceBreaker = new CircuitBreaker({
  failureThreshold: 3,
  recoveryTimeout: 30000
});

const callUserService = async (endpoint) => {
  return userServiceBreaker.execute(async () => {
    const response = await fetch(`http://user-service:8001${endpoint}`);

    if (!response.ok) {
      throw new Error(`User service error: ${response.status}`);
    }

    return response.json();
  });
};
```

### Retry et Fallback

```javascript
// ✅ Pattern Retry
const retry = async (fn, maxAttempts = 3, delay = 1000) => {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt === maxAttempts) {
        throw error;
      }

      console.warn(`Attempt ${attempt} failed, retrying in ${delay}ms:`, error.message);
      await new Promise(resolve => setTimeout(resolve, delay));
      delay *= 2; // Backoff exponentiel
    }
  }
};

// ✅ Usage avec retry
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await retry(
      () => callUserService(`/api/users/${req.params.id}`),
      3,  // 3 tentatives
      1000 // 1 seconde de délai initial
    );

    res.json(user);
  } catch (error) {
    res.status(503).json({
      error: 'Service temporarily unavailable',
      message: 'User service is currently unavailable'
    });
  }
});

// ✅ Pattern Fallback
const getUserWithFallback = async (userId) => {
  try {
    return await callUserService(`/api/users/${userId}`);
  } catch (error) {
    // Fallback vers la base de données locale
    return await getUserFromLocalDB(userId);
  }
};
```

## Monitoring distribué

### Métriques inter-services

```javascript
// ✅ Collecte de métriques distribuées
const distributedMetrics = {
  services: new Map(),

  recordCall: (service, endpoint, duration, success) => {
    if (!this.services.has(service)) {
      this.services.set(service, {
        calls: 0,
        errors: 0,
        totalDuration: 0,
        endpoints: new Map()
      });
    }

    const serviceMetrics = this.services.get(service);
    serviceMetrics.calls++;
    serviceMetrics.totalDuration += duration;

    if (!success) {
      serviceMetrics.errors++;
    }

    // Métriques par endpoint
    if (!serviceMetrics.endpoints.has(endpoint)) {
      serviceMetrics.endpoints.set(endpoint, {
        calls: 0,
        errors: 0,
        avgDuration: 0
      });
    }

    const endpointMetrics = serviceMetrics.endpoints.get(endpoint);
    endpointMetrics.calls++;
    endpointMetrics.avgDuration =
      (endpointMetrics.avgDuration * (endpointMetrics.calls - 1) + duration) / endpointMetrics.calls;

    if (!success) {
      endpointMetrics.errors++;
    }
  },

  getStats: () => {
    const stats = {};

    for (const [service, metrics] of this.services) {
      stats[service] = {
        ...metrics,
        avgDuration: metrics.calls > 0 ? metrics.totalDuration / metrics.calls : 0,
        successRate: metrics.calls > 0 ? ((metrics.calls - metrics.errors) / metrics.calls) * 100 : 0,
        endpoints: Object.fromEntries(metrics.endpoints)
      };
    }

    return stats;
  }
};

// ✅ Middleware de métriques
const metricsMiddleware = (req, res, next) => {
  const service = req.headers['x-service-name'] || 'unknown';
  const endpoint = req.route?.path || req.path;
  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const success = res.statusCode < 400;

    distributedMetrics.recordCall(service, endpoint, duration, success);
  });

  next();
};
```

## Déploiement et orchestration

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  api-gateway:
    build: ./api-gateway
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379
      - USER_SERVICE_URL=http://user-service:8001
      - POST_SERVICE_URL=http://post-service:8002
    depends_on:
      - redis
      - user-service
      - post-service
    networks:
      - api-network

  user-service:
    build: ./services/user-service
    ports:
      - "8001:8000"
    environment:
      - DATABASE_URL=postgresql://user:password@postgres:5432/users
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=your-secret
    depends_on:
      - postgres
      - redis
    networks:
      - api-network

  post-service:
    build: ./services/post-service
    ports:
      - "8002:8000"
    environment:
      - DATABASE_URL=postgresql://user:password@postgres:5432/posts
      - REDIS_URL=redis://redis:6379
      - USER_SERVICE_URL=http://user-service:8001
    depends_on:
      - postgres
      - redis
      - user-service
    networks:
      - api-network

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=api
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - api-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - api-network

networks:
  api-network:
    driver: bridge

volumes:
  postgres_data:
```

### Kubernetes

```yaml
# k8s/api-gateway-deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: api-gateway:latest
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        - name: USER_SERVICE_URL
          value: "http://user-service:8000"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
spec:
  selector:
    app: api-gateway
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

## Tests distribués

### Tests d'intégration inter-services

```javascript
// tests/integration.test.js
describe('Inter-service Integration', () => {
  test('user registration triggers notifications', async () => {
    // 1. Créer un utilisateur via le gateway
    const registerResponse = await request('http://api-gateway:8000')
      .post('/api/auth/register')
      .send({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User'
      })
      .expect(201);

    const userId = registerResponse.body.user.id;

    // 2. Vérifier que le service de notifications a été appelé
    await waitForMessage('user.created', { userId });

    // 3. Vérifier que l'email de bienvenue a été envoyé
    expect(emailServiceMock.sendWelcomeEmail).toHaveBeenCalledWith('test@example.com');
  });

  test('post creation updates user stats', async () => {
    // 1. Créer un utilisateur
    const user = await createTestUser();

    // 2. Créer un post
    const postResponse = await request('http://api-gateway:8000')
      .post('/api/posts')
      .set('Authorization', `Bearer ${user.token}`)
      .send({
        title: 'Test Post',
        content: 'Test content'
      })
      .expect(201);

    // 3. Vérifier que les stats utilisateur ont été mises à jour
    const userResponse = await request('http://api-gateway:8000')
      .get(`/api/users/${user.id}`)
      .set('Authorization', `Bearer ${user.token}`)
      .expect(200);

    expect(userResponse.body.data.postCount).toBe(1);
  });
});
```

## Quiz de la scalabilité

**Question 1** : Quelle est la différence entre scalabilité horizontale et verticale ?
**Réponse** : Verticale = plus de puissance par serveur, Horizontale = plus de serveurs

**Question 2** : Quand utiliser un circuit breaker ?
**Réponse** : Pour éviter la cascade de pannes dans une architecture distribuée

**Question 3** : Quel est le rôle d'un API Gateway ?
**Réponse** : Router les requêtes, authentifier, limiter le trafic

## En résumé

### Stratégies de scalabilité
1. **Horizontale** : Load balancing, microservices
2. **Verticale** : Serveurs plus puissants
3. **Cache** : Réduction de la charge
4. **Base de données** : Réplication, sharding

### Architecture microservices
- 🌐 **API Gateway** : Point d'entrée unique
- 🔄 **Communication** : REST, gRPC, Message Queue
- 🔍 **Service Discovery** : Consul, Kubernetes
- ⚡ **Circuit Breaker** : Tolérance aux pannes
- 📊 **Monitoring** : Métriques distribuées

### Outils recommandés
- 🐳 **Docker** : Containerisation
- ☸️ **Kubernetes** : Orchestration
- 🔄 **Nginx/HAProxy** : Load balancing
- 📊 **Prometheus** : Monitoring
- 🚨 **Grafana** : Alertes et visualisation

### Configuration recommandée
```yaml
# Microservices
services:
  api-gateway: 3 replicas
  user-service: 2 replicas
  post-service: 2 replicas
  notification-service: 1 replica

# Load balancing
balance: least_conn
health_check: enabled
timeout: 30s
```

Félicitations ! Vous avez maintenant une compréhension complète des **performances** et de la **scalabilité**. Dans la prochaine section, nous verrons des **cas pratiques** concrets d'APIs REST !

---

**Prochain chapitre** : [01-API-TodoList](07-Cas-Pratiques/01-API-TodoList.md)
