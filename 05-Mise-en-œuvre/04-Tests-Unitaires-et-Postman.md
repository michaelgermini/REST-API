# Tests Unitaires et Postman

## Introduction

Les **tests** sont essentiels pour garantir la **qualité** et la **fiabilité** de votre API. Dans ce chapitre, nous allons explorer les **tests unitaires** pour valider la logique métier et **Postman** pour tester l'API de bout en bout. Une API bien testée est une API robuste, maintenable et prête pour la production.

## Tests unitaires

### Configuration des tests

#### Node.js et Jest

```json
// package.json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:ci": "jest --ci --coverage --watchAll=false"
  },
  "jest": {
    "testEnvironment": "node",
    "collectCoverageFrom": [
      "src/**/*.{js,ts}",
      "!src/**/*.test.{js,ts}",
      "!src/**/index.{js,ts}"
    ],
    "coverageDirectory": "coverage",
    "coverageReporters": ["text", "lcov", "html"],
    "setupFilesAfterEnv": ["<rootDir>/src/tests/setup.js"]
  }
}
```

```javascript
// src/tests/setup.js
const { sequelize } = require('../config/database');

// Configuration des tests
beforeAll(async () => {
  // Synchroniser la base de données de test
  await sequelize.sync({ force: true });
});

afterAll(async () => {
  // Fermer la connexion
  await sequelize.close();
});

afterEach(async () => {
  // Nettoyer les données entre les tests
  await sequelize.truncate({ cascade: true });
});
```

#### Python et pytest

```toml
# pyproject.toml
[tool.poetry.dev-dependencies]
pytest = "^7.4.0"
pytest-asyncio = "^0.21.0"
httpx = "^0.24.0"
pytest-cov = "^4.1.0"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "-v --tb=short --strict-markers"
markers = [
    "unit: Unit tests",
    "integration: Integration tests",
    "slow: Slow tests"
]
```

```python
# tests/conftest.py
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.database import Base

# Configuration de la base de données de test
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost/testdb"

async_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)

@pytest_asyncio.fixture
async def db_session():
    async with AsyncSessionLocal() as session:
        # Créer les tables
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        yield session

        # Nettoyer après le test
        await session.rollback()
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
def test_client():
    from app.main import app
    return TestClient(app)
```

#### PHP et PHPUnit

```xml
<!-- phpunit.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="https://schema.phpunit.de/10.2/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true"
         cacheDirectory=".phpunit.cache">
    <testsuites>
        <testsuite name="Feature">
            <directory suffix="Test.php">./tests/Feature</directory>
        </testsuite>
        <testsuite name="Unit">
            <directory suffix="Test.php">./tests/Unit</directory>
        </testsuite>
    </testsuites>

    <coverage>
        <report>
            <html outputDirectory="coverage/html"/>
            <text outputFile="coverage.txt"/>
            <clover outputFile="coverage.xml"/>
        </report>
    </coverage>

    <php>
        <env name="APP_ENV" value="testing"/>
        <env name="DB_CONNECTION" value="sqlite"/>
        <env name="DB_DATABASE" value=":memory:"/>
    </php>
</phpunit>
```

```php
// tests/TestCase.php
<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    use CreatesApplication;

    protected function setUp(): void
    {
        parent::setUp();

        // Configuration pour les tests API
        $this->withoutMiddleware([
            \App\Http\Middleware\VerifyCsrfToken::class,
        ]);

        // Utiliser la base de données de test
        $this->artisan('migrate:fresh');
        $this->artisan('db:seed');
    }
}
```

### Tests d'authentification

#### Node.js

```javascript
// tests/auth.test.js
const request = require('supertest');
const app = require('../src/app');
const { User } = require('../src/models');

describe('Authentication', () => {
  beforeEach(async () => {
    // Nettoyer la base de données
    await User.destroy({ where: {} });
  });

  describe('POST /api/auth/register', () => {
    test('should register a new user', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('message', 'Account created successfully');
      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('tokens');
      expect(response.body.user).toHaveProperty('email', userData.email);
    });

    test('should reject invalid data', async () => {
      const invalidData = {
        email: 'invalid-email',
        password: '123', // Trop court
        firstName: 'T'  // Trop court
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(invalidData)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'validation_error');
      expect(response.body).toHaveProperty('details');
    });

    test('should reject duplicate email', async () => {
      const userData = {
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User'
      };

      // Créer un utilisateur
      await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      // Tenter de créer le même utilisateur
      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(409);

      expect(response.body).toHaveProperty('error', 'user_exists');
    });
  });

  describe('POST /api/auth/login', () => {
    test('should login with valid credentials', async () => {
      // Créer un utilisateur
      await User.create({
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        passwordHash: await bcrypt.hash('password123', 12)
      });

      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(200);

      expect(response.body).toHaveProperty('message', 'Login successful');
      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('tokens');
    });

    test('should reject invalid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        })
        .expect(401);

      expect(response.body).toHaveProperty('error', 'invalid_credentials');
    });
  });

  describe('GET /api/profile (protected)', () => {
    test('should access profile with valid token', async () => {
      const user = await User.create({
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        passwordHash: await bcrypt.hash('password123', 12)
      });

      const token = generateJWT(user);

      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toHaveProperty('email', user.email);
    });

    test('should reject access without token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .expect(401);

      expect(response.body).toHaveProperty('error', 'access_token_required');
    });

    test('should reject access with invalid token', async () => {
      const response = await request(app)
        .get('/api/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(403);

      expect(response.body).toHaveProperty('error', 'invalid_token');
    });
  });
});
```

#### Python

```python
# tests/test_auth.py
import pytest
from httpx import AsyncClient
from app.main import app
from app.core.security import verify_password

@pytest.mark.asyncio
class TestAuth:
    async def test_register_user(self, test_client: AsyncClient):
        user_data = {
            "email": "test@example.com",
            "password": "SecurePass123!",
            "first_name": "Test",
            "last_name": "User"
        }

        response = await test_client.post("/api/auth/register", json=user_data)

        assert response.status_code == 201
        assert "access_token" in response.json()
        assert "refresh_token" in response.json()
        assert response.json()["user"]["email"] == user_data["email"]

    async def test_register_invalid_data(self, test_client: AsyncClient):
        invalid_data = {
            "email": "invalid-email",
            "password": "123",  # Trop court
            "first_name": "T"   # Trop court
        }

        response = await test_client.post("/api/auth/register", json=invalid_data)

        assert response.status_code == 422  # Validation error
        assert "detail" in response.json()

    async def test_login_user(self, test_client: AsyncClient, db_session):
        from app.models.user import User
        from app.core.security import get_password_hash

        # Créer un utilisateur
        user = User(
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )
        user.set_password("password123")
        db_session.add(user)
        await db_session.commit()

        # Se connecter
        login_data = {
            "email": "test@example.com",
            "password": "password123"
        }

        response = await test_client.post("/api/auth/login", json=login_data)

        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["user"]["email"] == "test@example.com"

    async def test_login_invalid_credentials(self, test_client: AsyncClient):
        response = await test_client.post("/api/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        })

        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect email or password"

    async def test_access_protected_route(self, test_client: AsyncClient):
        # Se connecter
        login_response = await test_client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "password123"
        })

        token = login_response.json()["access_token"]

        # Accéder à une route protégée
        response = await test_client.get(
            "/api/users/1",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200

    async def test_unauthorized_access(self, test_client: AsyncClient):
        response = await test_client.get("/api/users/1")

        assert response.status_code == 401
        assert "detail" in response.json()
```

#### PHP

```php
// tests/Feature/AuthTest.php
<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_register()
    {
        $response = $this->postJson('/api/auth/register', [
            'email' => 'test@example.com',
            'password' => 'SecurePass123!',
            'password_confirmation' => 'SecurePass123!',
            'first_name' => 'Test',
            'last_name' => 'User'
        ]);

        $response->assertStatus(201)
                ->assertJsonStructure([
                    'message',
                    'user' => ['id', 'email', 'first_name', 'last_name'],
                    'access_token',
                    'refresh_token'
                ]);
    }

    public function test_user_can_login()
    {
        $user = User::factory()->create([
            'email' => 'test@example.com',
            'password' => bcrypt('password123')
        ]);

        $response = $this->postJson('/api/auth/login', [
            'email' => 'test@example.com',
            'password' => 'password123'
        ]);

        $response->assertStatus(200)
                ->assertJsonStructure([
                    'message',
                    'user',
                    'access_token',
                    'refresh_token'
                ]);
    }

    public function test_user_can_access_protected_route()
    {
        $user = User::factory()->create();
        $token = JWTAuth::fromUser($user);

        $response = $this->getJson('/api/users/' . $user->id, [
            'Authorization' => 'Bearer ' . $token
        ]);

        $response->assertStatus(200)
                ->assertJsonStructure([
                    'data' => ['id', 'first_name', 'last_name', 'email']
                ]);
    }

    public function test_unauthorized_access_is_denied()
    {
        $response = $this->getJson('/api/users/1');

        $response->assertStatus(401)
                ->assertJson([
                    'error' => 'token_invalid'
                ]);
    }
}
```

### Tests de sécurité

```javascript
// tests/security.test.js
describe('Security Tests', () => {
  describe('BOLA Prevention', () => {
    test('should prevent access to other users data', async () => {
      const user1 = await createTestUser({ email: 'user1@example.com' });
      const user2 = await createTestUser({ email: 'user2@example.com' });

      const token = generateJWT(user1);

      const response = await request(app)
        .get(`/api/users/${user2.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'access_denied');
    });
  });

  describe('Rate Limiting', () => {
    test('should limit login attempts', async () => {
      const responses = [];

      // Faire plus de tentatives que la limite
      for (let i = 0; i < 10; i++) {
        responses.push(
          request(app)
            .post('/api/auth/login')
            .send({
              email: 'test@example.com',
              password: 'wrongpassword'
            })
        );
      }

      const results = await Promise.all(responses);

      // Au moins une réponse devrait être 429
      const rateLimited = results.filter(r => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });

  describe('Input Validation', () => {
    test('should reject XSS attempts', async () => {
      const xssPayload = {
        email: 'test@example.com',
        bio: '<script>alert("xss")</script>',
        website: 'javascript:alert("xss")'
      };

      const response = await request(app)
        .post('/api/users')
        .send(xssPayload)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'validation_error');
    });

    test('should sanitize HTML content', async () => {
      const user = await createTestUser({
        email: 'test@example.com',
        bio: '<p>Safe content</p><script>alert("xss")</script>'
      });

      const response = await request(app)
        .get(`/api/users/${user.id}`)
        .expect(200);

      // Le script devrait être supprimé
      expect(response.body.data.bio).not.toContain('<script>');
    });
  });
});
```

## Tests avec Postman

### Configuration de Postman

#### 1. Collections

```json
{
  "info": {
    "name": "Blog API",
    "description": "Complete REST API testing suite",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:8000/api",
      "type": "string"
    },
    {
      "key": "accessToken",
      "value": "",
      "type": "string"
    },
    {
      "key": "refreshToken",
      "value": "",
      "type": "string"
    }
  ],
  "item": [
    {
      "name": "Authentication",
      "item": [
        {
          "name": "Register User",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/json"
              }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"SecurePass123!\",\n  \"firstName\": \"Test\",\n  \"lastName\": \"User\"\n}"
            },
            "url": {
              "raw": "{{baseUrl}}/auth/register",
              "host": ["{{baseUrl}}"],
              "path": ["auth", "register"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "if (pm.response.code === 201) {",
                  "    const response = pm.response.json();",
                  "    pm.collectionVariables.set('accessToken', response.access_token);",
                  "    pm.collectionVariables.set('refreshToken', response.refresh_token);",
                  "}"
                ]
              }
            }
          ]
        }
      ]
    }
  ]
}
```

#### 2. Tests automatisés

```javascript
// Tests Postman pour l'authentification
pm.test("Status code is 201", function () {
    pm.response.to.have.status(201);
});

pm.test("Response has required fields", function () {
    const response = pm.response.json();

    pm.expect(response).to.have.property('message');
    pm.expect(response).to.have.property('user');
    pm.expect(response).to.have.property('access_token');
    pm.expect(response).to.have.property('refresh_token');

    pm.expect(response.user).to.have.property('id');
    pm.expect(response.user).to.have.property('email');
    pm.expect(response.user).to.have.property('firstName');
    pm.expect(response.user).to.have.property('lastName');
});

pm.test("User data is correct", function () {
    const response = pm.response.json();

    pm.expect(response.user.email).to.eql("test@example.com");
    pm.expect(response.user.firstName).to.eql("Test");
    pm.expect(response.user.lastName).to.eql("User");
});

pm.test("Tokens are valid JWT format", function () {
    const response = pm.response.json();

    // Vérifier que c'est un JWT (3 parties séparées par des points)
    pm.expect(response.access_token).to.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/);
    pm.expect(response.refresh_token).to.match(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/);
});
```

### Tests d'intégration

#### Tests BOLA

```javascript
// Test BOLA dans Postman
pm.test("BOLA prevention - cannot access other users", function () {
    // Supposons que nous sommes connectés en tant qu'utilisateur 1
    // Tentative d'accès aux données de l'utilisateur 2

    if (pm.response.code === 403) {
        const response = pm.response.json();
        pm.expect(response.error).to.eql("access_denied");
        pm.expect(response.message).to.contain("own profile");
    }
});

pm.test("Admin can access all users", function () {
    // Test avec un token admin
    if (pm.response.code === 200) {
        const response = pm.response.json();
        pm.expect(response).to.have.property('data');
        pm.expect(response.data).to.have.property('email'); // Info sensible visible pour admin
    }
});
```

#### Tests de sécurité

```javascript
// Tests de sécurité Postman
pm.test("Rate limiting is enforced", function () {
    // Faire plusieurs requêtes rapides
    if (pm.response.code === 429) {
        pm.expect(pm.response.headers.valueOf('X-RateLimit-Remaining')).to.eql('0');
        pm.expect(pm.response.json()).to.have.property('error', 'too_many_requests');
    }
});

pm.test("CORS headers are present", function () {
    if (pm.request.headers.get('Origin')) {
        pm.expect(pm.response.headers.get('Access-Control-Allow-Origin')).to.not.be.null;
        pm.expect(pm.response.headers.get('Access-Control-Allow-Credentials')).to.eql('true');
    }
});

pm.test("Security headers are present", function () {
    pm.expect(pm.response.headers.get('X-Content-Type-Options')).to.eql('nosniff');
    pm.expect(pm.response.headers.get('X-Frame-Options')).to.eql('DENY');
    pm.expect(pm.response.headers.get('X-XSS-Protection')).to.eql('1; mode=block');
});
```

### Tests de performance

#### Newman (CLI Postman)

```bash
# Installation de Newman
npm install -g newman

# Exécution des tests
newman run Blog\ API.postman_collection.json \
  --environment Blog\ API.postman_environment.json \
  --reporters cli,json \
  --reporter-json-export results.json

# Tests de charge
newman run Blog\ API.postman_collection.json \
  --environment Blog\ API.postman_environment.json \
  --reporters cli \
  --timeout 10000 \
  --delay 1000 \
  --iteration-count 100
```

#### Tests de charge avec K6

```javascript
// k6-load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 50 },    // Ramp up to 50 users
    { duration: '30s', target: 50 },   // Stay at 50 users
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% des requêtes < 500ms
    http_req_failed: ['rate<0.1'],    // Erreur rate < 10%
  },
};

export default function () {
  const baseUrl = 'http://localhost:8000/api';

  // Test d'authentification
  const loginResponse = http.post(
    `${baseUrl}/auth/login`,
    JSON.stringify({
      email: 'test@example.com',
      password: 'password123'
    }),
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );

  check(loginResponse, {
    'login status is 200': (r) => r.status === 200,
    'has access token': (r) => JSON.parse(r.body).access_token !== undefined,
  });

  if (loginResponse.status === 200) {
    const token = JSON.parse(loginResponse.body).access_token;

    // Test de l'API protégée
    const usersResponse = http.get(
      `${baseUrl}/users`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      }
    );

    check(usersResponse, {
      'users status is 200': (r) => r.status === 200,
      'response time < 500ms': (r) => r.timings.duration < 500,
    });
  }

  sleep(1);
}
```

## Tests d'intégration

### Tests end-to-end

```javascript
// tests/integration.test.js
describe('API Integration Tests', () => {
  describe('User Registration and Authentication Flow', () => {
    test('complete user flow', async () => {
      // 1. Inscription
      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'integration@example.com',
          password: 'SecurePass123!',
          firstName: 'Integration',
          lastName: 'Test'
        })
        .expect(201);

      const { accessToken, user } = registerResponse.body;

      // 2. Connexion
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'integration@example.com',
          password: 'SecurePass123!'
        })
        .expect(200);

      // 3. Accès aux données
      const profileResponse = await request(app)
        .get('/api/profile')
        .set('Authorization', `Bearer ${loginResponse.body.access_token}`)
        .expect(200);

      expect(profileResponse.body.data.email).toBe('integration@example.com');

      // 4. Modification du profil
      const updateResponse = await request(app)
        .put(`/api/users/${user.id}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          firstName: 'Updated',
          lastName: 'Name'
        })
        .expect(200);

      expect(updateResponse.body.data.firstName).toBe('Updated');
    });
  });

  describe('Post Creation and Management', () => {
    test('complete post workflow', async () => {
      // 1. Créer un utilisateur
      const userResponse = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'author@example.com',
          password: 'SecurePass123!',
          firstName: 'Post',
          lastName: 'Author'
        })
        .expect(201);

      const token = userResponse.body.access_token;

      // 2. Créer un article
      const postResponse = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${token}`)
        .send({
          title: 'Test Article',
          content: 'This is a test article content',
          status: 'draft'
        })
        .expect(201);

      const postId = postResponse.body.data.id;

      // 3. Publier l'article
      await request(app)
        .post(`/api/posts/${postId}/publish`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      // 4. Récupérer l'article publié
      const publishedResponse = await request(app)
        .get(`/api/posts/${postId}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(publishedResponse.body.data.status).toBe('published');
      expect(publishedResponse.body.data.publishedAt).toBeDefined();
    });
  });
});
```

## Mock et fixtures

### Fixtures de test

```javascript
// tests/fixtures/users.js
const userFixtures = {
  validUser: {
    email: 'test@example.com',
    password: 'SecurePass123!',
    firstName: 'Test',
    lastName: 'User'
  },

  adminUser: {
    email: 'admin@example.com',
    password: 'AdminPass123!',
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin'
  },

  invalidUser: {
    email: 'invalid-email',
    password: '123', // Trop court
    firstName: 'T'   // Trop court
  }
};

const createTestUser = async (overrides = {}) => {
  const userData = { ...userFixtures.validUser, ...overrides };

  const response = await request(app)
    .post('/api/auth/register')
    .send(userData);

  if (response.status !== 201) {
    throw new Error(`Failed to create test user: ${response.body.message}`);
  }

  return response.body;
};

module.exports = {
  userFixtures,
  createTestUser
};
```

### Mock des services externes

```javascript
// tests/mocks/emailService.js
const emailServiceMock = {
  sendWelcomeEmail: jest.fn().mockResolvedValue(true),
  sendPasswordReset: jest.fn().mockResolvedValue(true),
  sendNotification: jest.fn().mockResolvedValue(true)
};

// Remplacer le service email par le mock
jest.mock('../../src/services/emailService', () => emailServiceMock);

// Test avec mock
test('should send welcome email on registration', async () => {
  await request(app)
    .post('/api/auth/register')
    .send(userFixtures.validUser)
    .expect(201);

  expect(emailServiceMock.sendWelcomeEmail).toHaveBeenCalledWith(
    userFixtures.validUser.email
  );
});
```

## CI/CD avec tests

### GitHub Actions

```yaml
# .github/workflows/tests.yml
name: API Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_DB: testdb
          POSTGRES_USER: testuser
          POSTGRES_PASSWORD: testpass
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    - uses: actions/checkout@v3

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Run database migrations
      run: npm run migrate:test
      env:
        DATABASE_URL: postgresql://testuser:testpass@localhost:5432/testdb

    - name: Run tests
      run: npm run test:ci
      env:
        DATABASE_URL: postgresql://testuser:testpass@localhost:5432/testdb
        JWT_SECRET: test-secret-key

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        flags: unittests
        name: codecov-umbrella
```

### Pipeline de déploiement

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  release:
    types: [published]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Run tests
      run: npm run test:ci

    - name: Build application
      run: npm run build

    - name: Deploy to server
      uses: appleboy/ssh-action@master
      with:
        host: ${{ secrets.SERVER_HOST }}
        username: ${{ secrets.SERVER_USER }}
        key: ${{ secrets.SERVER_SSH_KEY }}
        script: |
          cd /var/www/blog-api
          git pull origin main
          npm ci --production
          npm run migrate:production
          pm2 restart blog-api
```

## Quiz des tests

**Question 1** : Quelle est l'importance des tests unitaires ?
**Réponse** : Valider la logique métier indépendamment des dépendances externes

**Question 2** : Quand utiliser Postman vs tests automatisés ?
**Réponse** : Postman pour l'exploration et les tests manuels, tests automatisés pour la validation continue

**Question 3** : Comment tester la sécurité d'une API ?
**Réponse** : Tests BOLA, injection, XSS, rate limiting, et validation d'entrée

## En résumé

### Stratégies de test
1. **Tests unitaires** : Logique métier isolée
2. **Tests d'intégration** : Interaction entre composants
3. **Tests end-to-end** : Flux complet utilisateur
4. **Tests de sécurité** : Vulnérabilités et attaques
5. **Tests de performance** : Charge et performance

### Outils recommandés
- 🧪 **Jest/Pytest/PHPUnit** : Tests unitaires
- 📮 **Postman/Newman** : Tests API manuels et automatisés
- 🚀 **K6** : Tests de charge
- 📊 **Coverage** : Mesure de la couverture de code
- 🔄 **CI/CD** : Intégration continue

### Bonnes pratiques
- ✅ **Tests automatisés** avant chaque déploiement
- ✅ **Couverture de code** > 80%
- ✅ **Tests de sécurité** dans la pipeline CI
- ✅ **Environnements** de test isolés
- ✅ **Mocking** des services externes
- ✅ **Validation** des contrats API

### Structure de tests
```javascript
// Tests organisés
tests/
├── unit/           // Tests isolés
├── integration/    // Tests d'intégration
├── security/       // Tests de sécurité
├── performance/    // Tests de performance
├── fixtures/       // Données de test
└── mocks/          // Services mockés
```

### Pipeline complète
```bash
# Tests complets
✅ Linting (ESLint, Prettier)
✅ Tests unitaires (Jest, Pytest, PHPUnit)
✅ Tests d'intégration (Supertest, httpx)
✅ Tests de sécurité (OWASP checks)
✅ Tests de performance (K6, Artillery)
✅ Couverture de code
✅ Déploiement automatique
```

Félicitations ! Vous avez maintenant toutes les compétences pour créer, sécuriser et tester des APIs REST complètes. Dans la prochaine section, nous explorerons les **performances** et l'**optimisation** !

---

**Prochain chapitre** : [01-Cache-et-CDN](06-Performances-et-Optimisation/01-Cache-et-CDN.md)
