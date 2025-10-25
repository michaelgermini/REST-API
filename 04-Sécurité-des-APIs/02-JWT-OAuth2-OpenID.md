# JWT, OAuth 2.0 et OpenID Connect

## Introduction

Dans le chapitre précédent, nous avons exploré les concepts fondamentaux de l'authentification. Maintenant, concentrons-nous sur les **standards modernes** : **JWT** (JSON Web Tokens), **OAuth 2.0** et **OpenID Connect**. Ces technologies sont devenues les piliers de l'authentification moderne dans les APIs REST. Comprendre leur fonctionnement est essentiel pour sécuriser vos applications.

## JSON Web Tokens (JWT)

### Structure d'un JWT

Un JWT est composé de **3 parties** séparées par des points :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

```javascript
// Décomposition d'un JWT
const [header, payload, signature] = token.split('.');

// Header (encodé en base64)
const headerDecoded = JSON.parse(atob(header));
/*
{
  "alg": "HS256",        // Algorithme de signature
  "typ": "JWT"           // Type de token
}
*/

// Payload (encodé en base64)
const payloadDecoded = JSON.parse(atob(payload));
/*
{
  "sub": "1234567890",   // Subject (utilisateur)
  "name": "John Doe",    // Nom de l'utilisateur
  "iat": 1516239022,     // Issued at (date d'émission)
  "exp": 1516242622,     // Expiration
  "iss": "my-api",       // Issuer
  "aud": "my-clients"    // Audience
}
*/

// Signature (cryptographique)
const signature = // HMAC-SHA256(header + "." + payload, secret)
```

### Types de JWT

#### 1. Access Tokens

```javascript
// Token d'accès court (15 minutes à 1 heure)
const accessToken = jwt.sign(
  {
    userId: user.id,
    type: 'access',
    permissions: user.permissions
  },
  process.env.JWT_SECRET,
  {
    expiresIn: '15m',
    issuer: 'my-api',
    audience: 'my-clients'
  }
);

// Usage
app.get('/api/protected', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (decoded.type === 'access') {
    res.json({ message: 'Access granted', user: decoded });
  } else {
    res.status(401).json({ error: 'Invalid token type' });
  }
});
```

#### 2. Refresh Tokens

```javascript
// Token de rafraîchissement long (7 jours à 30 jours)
const refreshToken = jwt.sign(
  {
    userId: user.id,
    type: 'refresh',
    tokenId: generateTokenId() // Pour la révocation
  },
  process.env.JWT_REFRESH_SECRET,
  {
    expiresIn: '7d',
    issuer: 'my-api'
  }
);

// Endpoint de rafraîchissement
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    // Vérifier que le token n'est pas révoqué
    if (isTokenRevoked(decoded.tokenId)) {
      throw new Error('Token revoked');
    }

    const user = getUserById(decoded.userId);
    const newTokens = generateTokens(user);

    res.json(newTokens);
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});
```

### Claims JWT standards

```javascript
// Claims standards (selon RFC 7519)
const standardClaims = {
  // Identificateurs
  'iss': 'my-api',                    // Issuer
  'sub': '1234567890',                // Subject (user ID)
  'aud': 'my-clients',                // Audience
  'exp': 1516242622,                  // Expiration Time
  'nbf': 1516239022,                  // Not Before
  'iat': 1516239022,                  // Issued At
  'jti': 'unique-token-id',           // JWT ID

  // Informations utilisateur
  'name': 'John Doe',
  'email': 'john@example.com',
  'preferred_username': 'johndoe',
  'profile': 'https://example.com/profile',
  'picture': 'https://example.com/avatar.jpg',

  // Autorisations
  'scope': 'read write admin',
  'roles': ['user', 'admin'],
  'permissions': ['read:profile', 'write:posts']
};
```

### Sécurité JWT

```javascript
// Génération sécurisée
const generateSecureJWT = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    // Sécurité
    expiresIn: '15m',
    notBefore: Math.floor(Date.now() / 1000), // Pas avant maintenant
    issuer: 'https://my-api.com',
    audience: 'https://my-app.com',

    // Protection contre les attaques
    jwtid: generateUniqueId(), // Unique ID pour révocation

    // Headers de sécurité
    header: {
      'alg': 'HS256',
      'typ': 'JWT',
      'kid': 'key-id-1' // Key ID pour rotation
    }
  });
};

// Vérification stricte
const verifyJWT = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET, {
    issuer: 'https://my-api.com',
    audience: 'https://my-app.com',
    algorithms: ['HS256'], // Seulement HS256
    maxAge: '15m' // Refuser les tokens trop anciens
  });
};
```

## OAuth 2.0

### Flux d'autorisation

#### 1. Authorization Code Flow (recommandé)

```javascript
// Étape 1: Redirection vers le provider
app.get('/api/auth/oauth', (req, res) => {
  const clientId = process.env.OAUTH_CLIENT_ID;
  const redirectUri = encodeURIComponent(`${process.env.BASE_URL}/api/auth/callback`);
  const state = generateSecureState(); // Protection CSRF

  const authUrl = `https://provider.com/oauth/authorize?` +
    `client_id=${clientId}&` +
    `redirect_uri=${redirectUri}&` +
    `response_type=code&` +
    `scope=openid profile email&` +
    `state=${state}`;

  // Sauvegarder le state pour vérification
  saveState(state, { userId: req.user?.id });

  res.redirect(authUrl);
});

// Étape 2: Callback avec code d'autorisation
app.get('/api/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // Vérifier le state
  if (!verifyState(state)) {
    return res.status(400).json({ error: 'Invalid state' });
  }

  if (error) {
    return res.status(400).json({ error: 'OAuth error', details: error });
  }

  try {
    // Étape 3: Échange du code contre des tokens
    const tokens = await exchangeCodeForTokens(code);

    // Étape 4: Récupération des infos utilisateur
    const userInfo = await getUserInfo(tokens.access_token);

    // Étape 5: Création de l'utilisateur local
    const user = await findOrCreateUser(userInfo);

    // Étape 6: Génération du JWT local
    const jwtToken = generateJWT(user);

    // Redirection vers le frontend avec le token
    res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${jwtToken}`);
  } catch (error) {
    res.status(500).json({ error: 'OAuth authentication failed' });
  }
});
```

#### 2. Implicit Flow (obsolète)

```javascript
// ❌ ÉVITER - Pas recommandé pour les APIs serveur
GET /oauth/authorize?
  client_id=123&
  redirect_uri=https://client.com/callback&
  response_type=token&
  scope=read

// Retourne directement le token dans l'URL
https://client.com/callback#access_token=abc123&token_type=bearer
```

#### 3. Resource Owner Password Credentials

```javascript
// Pour les clients de confiance (applications mobiles)
app.post('/api/auth/token', async (req, res) => {
  const { username, password, client_id, client_secret } = req.body;

  // Vérifier les credentials du client
  if (!verifyClientCredentials(client_id, client_secret)) {
    return res.status(401).json({ error: 'Invalid client' });
  }

  // Authentifier l'utilisateur
  const user = authenticateUser(username, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Générer le token
  const token = generateJWT(user);
  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600
  });
});
```

### Configuration OAuth 2.0

```javascript
// Configuration du client OAuth
const oauthConfig = {
  // Identifiants du client
  clientId: process.env.OAUTH_CLIENT_ID,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,

  // URLs du provider
  authorizationUrl: 'https://accounts.google.com/oauth/authorize',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',

  // Scopes demandés
  scopes: ['openid', 'profile', 'email'],

  // Redirections
  redirectUri: `${process.env.BASE_URL}/api/auth/callback`
};

// Échange du code d'autorisation
const exchangeCodeForTokens = async (code) => {
  const response = await fetch(oauthConfig.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      client_id: oauthConfig.clientId,
      client_secret: oauthConfig.clientSecret,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: oauthConfig.redirectUri
    })
  });

  return response.json();
};
```

## OpenID Connect

### Découverte des endpoints

```javascript
// Récupération de la configuration OpenID Connect
const getOIDCDiscovery = async (issuer) => {
  const response = await fetch(`${issuer}/.well-known/openid_configuration`);
  const config = await response.json();

  return {
    authorizationEndpoint: config.authorization_endpoint,
    tokenEndpoint: config.token_endpoint,
    userInfoEndpoint: config.userinfo_endpoint,
    endSessionEndpoint: config.end_session_endpoint,
    supportedScopes: config.scopes_supported,
    supportedClaims: config.claims_supported
  };
};

// Utilisation
const googleConfig = await getOIDCDiscovery('https://accounts.google.com');
```

### ID Token

```javascript
// Structure d'un ID Token OpenID Connect
const idToken = jwt.decode(token); // Pas de vérification de signature ici

/*
{
  "iss": "https://accounts.google.com",    // Issuer
  "sub": "123456789",                      // Subject (user ID unique)
  "aud": "my-client-id",                   // Audience
  "exp": 1516242622,                       // Expiration
  "iat": 1516239022,                       // Issued at

  // Claims OpenID Connect
  "email": "john@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://...",
  "locale": "fr-FR",

  // Claims personnalisés
  "custom_claim": "value"
}
*/

// Vérification complète de l'ID Token
const verifyIDToken = async (idToken) => {
  const decoded = jwt.decode(idToken, { complete: true });

  // Vérifier l'header
  if (decoded.header.alg !== 'RS256') {
    throw new Error('Invalid algorithm');
  }

  // Récupérer les clés publiques du provider
  const keys = await getPublicKeys(decoded.header.kid);

  // Vérifier la signature
  const verified = jwt.verify(idToken, keys.publicKey, {
    issuer: 'https://accounts.google.com',
    audience: process.env.OAUTH_CLIENT_ID,
    algorithms: ['RS256']
  });

  return verified;
};
```

### Claims OpenID Connect

```javascript
// Claims standards OpenID Connect
const standardClaims = {
  // Profil
  'name': 'John Doe',
  'given_name': 'John',
  'family_name': 'Doe',
  'middle_name': 'William',
  'nickname': 'Johnny',
  'preferred_username': 'john.doe',
  'profile': 'https://example.com/profile',
  'picture': 'https://example.com/avatar.jpg',
  'website': 'https://example.com',
  'email': 'john@example.com',
  'email_verified': true,
  'gender': 'male',
  'birthdate': '1990-01-01',
  'zoneinfo': 'Europe/Paris',
  'locale': 'fr-FR',
  'phone_number': '+33123456789',
  'phone_number_verified': false,

  // Adresse
  'address': {
    'formatted': '123 Main St, Paris, France',
    'street_address': '123 Main St',
    'locality': 'Paris',
    'region': 'Île-de-France',
    'postal_code': '75001',
    'country': 'FR'
  },

  // Mise à jour
  'updated_at': 1516239022
};
```

## Implémentation complète

### Serveur d'authentification

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// Configuration
const config = {
  jwtSecret: process.env.JWT_SECRET,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
  oauthClientId: process.env.OAUTH_CLIENT_ID,
  oauthClientSecret: process.env.OAUTH_CLIENT_SECRET,
  frontendUrl: process.env.FRONTEND_URL
};

// Génération des tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      type: 'access'
    },
    config.jwtSecret,
    {
      expiresIn: '15m',
      issuer: 'my-api',
      audience: 'my-clients'
    }
  );

  const refreshToken = jwt.sign(
    {
      userId: user.id,
      type: 'refresh',
      tokenId: generateUniqueId()
    },
    config.jwtRefreshSecret,
    {
      expiresIn: '7d',
      issuer: 'my-api'
    }
  );

  return { accessToken, refreshToken };
};

// Connexion locale
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await authenticateUser(email, password);
    const tokens = generateTokens(user);

    res.json({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(401).json({
      error: 'authentication_failed',
      message: 'Invalid email or password'
    });
  }
});

// OAuth 2.0 Authorization Code Flow
app.get('/api/auth/oauth', (req, res) => {
  const state = generateSecureState();
  const redirectUri = encodeURIComponent(`${config.frontendUrl}/auth/callback`);

  const authUrl = `https://accounts.google.com/oauth/authorize?` +
    `client_id=${config.oauthClientId}&` +
    `redirect_uri=${redirectUri}&` +
    `response_type=code&` +
    `scope=openid profile email&` +
    `state=${state}&` +
    `access_type=offline&` +
    `prompt=consent`;

  saveState(state);
  res.redirect(authUrl);
});

// Callback OAuth
app.get('/api/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!verifyState(state)) {
    return res.status(400).json({ error: 'Invalid state' });
  }

  try {
    // Échange du code
    const tokenResponse = await exchangeCodeForTokens(code);

    // Récupération des infos utilisateur
    const userInfo = await getUserInfo(tokenResponse.access_token);

    // Création/mise à jour utilisateur
    const user = await findOrCreateUser(userInfo);

    // Génération des tokens locaux
    const tokens = generateTokens(user);

    // Redirection avec tokens
    const redirectUrl = `${config.frontendUrl}/auth/callback?` +
      `access_token=${tokens.accessToken}&` +
      `refresh_token=${tokens.refreshToken}&` +
      `user=${encodeURIComponent(JSON.stringify(user))}`;

    res.redirect(redirectUrl);
  } catch (error) {
    res.status(500).json({ error: 'OAuth failed' });
  }
});

// Rafraîchissement des tokens
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;

  try {
    const decoded = jwt.verify(refreshToken, config.jwtRefreshSecret);

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const user = getUserById(decoded.userId);
    const tokens = generateTokens(user);

    res.json({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      token_type: 'Bearer',
      expires_in: 900
    });
  } catch (error) {
    res.status(401).json({
      error: 'invalid_refresh_token',
      message: 'The refresh token is invalid or expired'
    });
  }
});

// Déconnexion
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (token) {
    // Révoquer le token
    revokeToken(token);
  }

  res.json({ message: 'Logged out successfully' });
});
```

### Middleware d'authentification

```javascript
// Middleware JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'access_token_required',
      message: 'Please provide a valid access token'
    });
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret, {
      issuer: 'my-api',
      audience: 'my-clients',
      algorithms: ['HS256']
    });

    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'token_expired',
        message: 'Your access token has expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    res.status(403).json({
      error: 'invalid_token',
      message: 'The provided token is not valid'
    });
  }
};

// Middleware d'autorisation
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'insufficient_permissions',
        message: `Required roles: ${roles.join(', ')}`
      });
    }

    next();
  };
};

// Middleware de permissions
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = req.user.permissions || [];
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({
        error: 'insufficient_permissions',
        message: `Required permission: ${permission}`
      });
    }

    next();
  };
};
```

### Routes protégées

```javascript
// Routes avec authentification
app.get('/api/profile', authenticateJWT, getUserProfile);
app.put('/api/profile', authenticateJWT, updateUserProfile);

// Routes avec autorisation
app.get('/api/admin/users', authenticateJWT, requireRole(['admin']), getAllUsers);
app.delete('/api/posts/:id', authenticateJWT, requirePermission('delete:posts'), deletePost);

// Routes OAuth
app.get('/api/auth/google', initiateGoogleAuth);
app.get('/api/auth/google/callback', handleGoogleCallback);
app.get('/api/auth/facebook', initiateFacebookAuth);
app.get('/api/auth/facebook/callback', handleFacebookCallback);
```

## Gestion des clés et secrets

### Rotation des clés

```javascript
// Configuration avec rotation
const jwtConfig = {
  secrets: [
    {
      id: 'key-1',
      secret: process.env.JWT_SECRET_1,
      algorithm: 'HS256',
      expiresAt: new Date('2023-12-31')
    },
    {
      id: 'key-2',
      secret: process.env.JWT_SECRET_2,
      algorithm: 'HS256',
      expiresAt: new Date('2024-06-30')
    }
  ],
  currentKeyId: 'key-2'
};

// Génération avec key ID
const generateJWT = (payload) => {
  const currentKey = jwtConfig.secrets.find(k => k.id === jwtConfig.currentKeyId);

  return jwt.sign(payload, currentKey.secret, {
    algorithm: currentKey.algorithm,
    keyid: currentKey.id,
    expiresIn: '15m'
  });
};

// Vérification avec rotation
const verifyJWT = (token) => {
  const decoded = jwt.decode(token, { complete: true });
  const keyId = decoded.header.kid;

  const key = jwtConfig.secrets.find(k => k.id === keyId);
  if (!key || key.expiresAt < new Date()) {
    throw new Error('Invalid or expired key');
  }

  return jwt.verify(token, key.secret, {
    algorithms: [key.algorithm]
  });
};
```

### Stockage sécurisé des secrets

```javascript
// Variables d'environnement
JWT_SECRET=your-super-secret-key-here
JWT_REFRESH_SECRET=your-refresh-secret-key-here
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret

// Rotation automatique
const rotateSecrets = () => {
  // Générer de nouvelles clés
  const newSecret = generateRandomSecret(64);
  const newRefreshSecret = generateRandomSecret(64);

  // Mettre à jour la configuration
  process.env.JWT_SECRET = newSecret;
  process.env.JWT_REFRESH_SECRET = newRefreshSecret;

  // Redémarrer l'application ou recharger la config
  console.log('JWT secrets rotated successfully');
};

// Rotation programmée (tous les 30 jours)
setInterval(rotateSecrets, 30 * 24 * 60 * 60 * 1000);
```

## Tests et validation

### Tests JWT

```javascript
// tests/auth.test.js
const jwt = require('jsonwebtoken');

describe('JWT Authentication', () => {
  test('should generate valid JWT', () => {
    const user = { id: 123, email: 'test@example.com' };
    const token = generateJWT(user);

    expect(token).toBeDefined();
    expect(typeof token).toBe('string');

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    expect(decoded.userId).toBe(user.id);
    expect(decoded.email).toBe(user.email);
  });

  test('should reject expired tokens', () => {
    const expiredToken = jwt.sign(
      { userId: 123 },
      process.env.JWT_SECRET,
      { expiresIn: '-1h' }
    );

    expect(() => {
      jwt.verify(expiredToken, process.env.JWT_SECRET);
    }).toThrow('jwt expired');
  });

  test('should reject tokens with wrong signature', () => {
    const wrongToken = jwt.sign(
      { userId: 123 },
      'wrong-secret'
    );

    expect(() => {
      jwt.verify(wrongToken, process.env.JWT_SECRET);
    }).toThrow('invalid signature');
  });
});
```

### Tests OAuth

```javascript
describe('OAuth 2.0 Flow', () => {
  test('should initiate OAuth flow', async () => {
    const response = await request(app)
      .get('/api/auth/oauth')
      .expect(302); // Redirection

    expect(response.headers.location).toContain('accounts.google.com');
    expect(response.headers.location).toContain('client_id=');
    expect(response.headers.location).toContain('state=');
  });

  test('should handle OAuth callback', async () => {
    // Mock OAuth provider
    const mockTokens = {
      access_token: 'mock-access-token',
      id_token: 'mock-id-token',
      refresh_token: 'mock-refresh-token'
    };

    // Simuler le callback
    const response = await request(app)
      .get('/api/auth/callback')
      .query({
        code: 'mock-code',
        state: 'valid-state'
      });

    expect(response.status).toBe(302); // Redirection vers frontend
    expect(response.headers.location).toContain('/auth/callback');
    expect(response.headers.location).toContain('access_token=');
  });
});
```

## Quiz JWT et OAuth

**Question 1** : Quelle est la structure d'un JWT ?
**Réponse** : Header.Payload.Signature (3 parties encodées en base64)

**Question 2** : Pourquoi utiliser des refresh tokens ?
**Réponse** : Pour avoir des sessions longues avec des tokens d'accès courts

**Question 3** : Quelle est la différence entre OAuth 2.0 et OpenID Connect ?
**Réponse** : OAuth 2.0 gère l'autorisation, OpenID Connect ajoute l'authentification et l'identité

## En résumé

### JWT
- 🔑 **3 parties** : Header, Payload, Signature
- ⏱️ **Tokens courts** avec refresh tokens
- 🔒 **Auto-contenu** et stateless
- 🛡️ **Signature cryptographique** pour la sécurité

### OAuth 2.0
- 🔄 **Flux d'autorisation** : Authorization Code, Implicit, etc.
- 🏢 **Délégation d'accès** à des tiers
- 🔐 **Scopes et permissions** granulaires
- 📱 **Intégration** avec Google, Facebook, etc.

### OpenID Connect
- 🆔 **Identité numérique** standardisée
- 📋 **Claims** pour les informations utilisateur
- 🔍 **Découverte** automatique des endpoints
- ✅ **ID Token** pour l'authentification

### Bonnes pratiques
- ✅ **Tokens courts** (15min-1h) avec refresh
- ✅ **HTTPS obligatoire** pour OAuth
- ✅ **State parameter** pour la protection CSRF
- ✅ **Validation stricte** des tokens
- ✅ **Rotation** des secrets de signature

### Configuration recommandée
```javascript
// JWT sécurisé
{
  expiresIn: '15m',
  issuer: 'your-domain.com',
  audience: 'your-app.com',
  algorithm: 'HS256'
}

// OAuth avec PKCE
{
  codeChallenge: 'S256',
  accessType: 'offline',
  prompt: 'consent'
}
```

Dans le prochain chapitre, nous explorerons les **mécanismes de protection** comme CORS, Rate Limiting et la sécurité transport !

---

**Prochain chapitre** : [03-CORS-et-Rate-Limiting](03-CORS-et-Rate-Limiting.md)
