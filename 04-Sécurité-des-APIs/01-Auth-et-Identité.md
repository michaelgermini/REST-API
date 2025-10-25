# Authentification et Identité

## Introduction

La **sécurité** est l'un des aspects les plus critiques d'une API. Sans authentification et autorisation appropriées, votre API est vulnérable aux attaques et aux abus. Dans ce chapitre, nous allons explorer les concepts fondamentaux de l'**authentification** (vérifier l'identité) et de l'**autorisation** (contrôler l'accès), et apprendre à implémenter des mécanismes de sécurité robustes.

## Qu'est-ce que l'authentification ?

### Définition

L'**authentification** est le processus de vérification de l'identité d'un utilisateur ou d'un système. C'est la première ligne de défense de votre API.

```javascript
// Exemple d'authentification basique
const authenticateUser = (email, password) => {
  const user = findUserByEmail(email);

  if (!user) {
    throw new Error('User not found');
  }

  if (!verifyPassword(password, user.passwordHash)) {
    throw new Error('Invalid password');
  }

  return user;
};
```

### Types d'authentification

#### 1. Authentification par mot de passe

```javascript
// Stockage sécurisé des mots de passe
const hashPassword = (password) => {
  return bcrypt.hash(password, 12); // 12 rounds = ~4096 itérations
};

const verifyPassword = (password, hash) => {
  return bcrypt.compare(password, hash);
};

// Inscription
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;

  const passwordHash = await hashPassword(password);
  const user = await createUser(email, passwordHash);

  res.status(201).json({
    message: 'User created successfully',
    userId: user.id
  });
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await authenticateUser(email, password);
    const token = generateJWT(user);

    res.json({
      message: 'Login successful',
      token: token,
      user: { id: user.id, email: user.email }
    });
  } catch (error) {
    res.status(401).json({
      error: 'Authentication failed',
      message: error.message
    });
  }
});
```

#### 2. Authentification par token

```javascript
// JWT (JSON Web Token)
const jwt = require('jsonwebtoken');

const generateJWT = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '24h', // Expiration dans 24 heures
      issuer: 'my-api',
      audience: 'my-clients'
    }
  );
};

const verifyJWT = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid access token'
    });
  }

  try {
    const decoded = verifyJWT(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({
      error: 'Invalid token',
      message: 'The provided token is not valid or has expired'
    });
  }
};
```

#### 3. Authentification API Key

```javascript
// Clé API pour les intégrations système
const authenticateAPIKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'API key required'
    });
  }

  const user = findUserByAPIKey(apiKey);
  if (!user) {
    return res.status(403).json({
      error: 'Invalid API key'
    });
  }

  req.user = user;
  next();
};

// Usage
app.get('/api/data', authenticateAPIKey, (req, res) => {
  res.json({ data: 'sensitive information' });
});
```

## Autorisation et contrôle d'accès

### Définition

L'**autorisation** détermine ce qu'un utilisateur authentifié peut faire. C'est la deuxième ligne de défense.

```javascript
// Middleware d'autorisation
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Access denied',
        message: `Required roles: ${roles.join(', ')}`
      });
    }

    next();
  };
};

// Usage
app.delete('/api/users/:id', authenticateToken, requireRole(['admin']), deleteUser);
app.get('/api/reports', authenticateToken, requireRole(['admin', 'manager']), getReports);
```

### Contrôle d'accès basé sur les rôles (RBAC)

```javascript
// Définition des rôles et permissions
const ROLES = {
  GUEST: [],
  USER: ['read:profile', 'write:profile', 'read:posts'],
  AUTHOR: ['read:profile', 'write:profile', 'read:posts', 'write:posts', 'read:comments'],
  EDITOR: ['read:profile', 'write:profile', 'read:posts', 'write:posts', 'delete:posts', 'read:comments', 'write:comments'],
  ADMIN: ['*'] // Toutes les permissions
};

const PERMISSIONS = {
  'read:profile': { resource: 'profile', action: 'read' },
  'write:profile': { resource: 'profile', action: 'write' },
  'read:posts': { resource: 'posts', action: 'read' },
  'write:posts': { resource: 'posts', action: 'write' },
  'delete:posts': { resource: 'posts', action: 'delete' }
};

// Middleware de permissions
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = ROLES[req.user.role] || [];
    if (!userPermissions.includes(permission) && !userPermissions.includes('*')) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `Required permission: ${permission}`
      });
    }

    next();
  };
};
```

### Contrôle d'accès basé sur les attributs (ABAC)

```javascript
// Autorisation basée sur les attributs de l'utilisateur et de la ressource
const authorizeAccess = (user, resource, action) => {
  // Exemples de règles ABAC
  const rules = [
    // Les utilisateurs peuvent modifier leur propre profil
    {
      condition: (user, resource) => user.id === resource.userId,
      permissions: ['read', 'write', 'delete']
    },
    // Les admins peuvent tout faire
    {
      condition: (user) => user.role === 'admin',
      permissions: ['*']
    },
    // Les modérateurs peuvent gérer les commentaires
    {
      condition: (user, resource) => user.role === 'moderator' && resource.type === 'comment',
      permissions: ['read', 'write', 'delete']
    }
  ];

  for (const rule of rules) {
    if (rule.condition(user, resource)) {
      if (rule.permissions.includes('*') || rule.permissions.includes(action)) {
        return true;
      }
    }
  }

  return false;
};
```

## Sessions et tokens

### Sessions traditionnelles

```javascript
// Sessions avec cookies
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // Pas accessible via JavaScript
    maxAge: 24 * 60 * 60 * 1000 // 24 heures
  }
}));

// Connexion avec sessions
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  const user = authenticateUser(email, password);
  if (user) {
    req.session.userId = user.id;
    req.session.role = user.role;

    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email }
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Middleware de session
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    req.user = getUserById(req.session.userId);
    next();
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
};
```

### JWT (JSON Web Tokens)

```javascript
// Structure d'un JWT
// Header.Payload.Signature
const token = jwt.sign(
  {
    userId: user.id,
    email: user.email,
    role: user.role,
    permissions: user.permissions
  },
  process.env.JWT_SECRET,
  {
    expiresIn: '1h',
    issuer: 'my-api',
    audience: 'my-clients',
    subject: user.id.toString()
  }
);

// Vérification du token
const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'my-api',
      audience: 'my-clients'
    });
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

// Middleware JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};
```

### Refresh Tokens

```javascript
// Tokens d'accès courts + refresh tokens longs
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { userId: user.id, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: '15m' } // Court
  );

  const refreshToken = jwt.sign(
    { userId: user.id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' } // Long
  );

  return { accessToken, refreshToken };
};

// Endpoint de refresh
app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const user = getUserById(decoded.userId);
    const tokens = generateTokens(user);

    res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});
```

## OAuth 2.0 et OpenID Connect

### Flux OAuth 2.0

```javascript
// Configuration OAuth
const oauthConfig = {
  clientId: process.env.OAUTH_CLIENT_ID,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,
  authorizationUrl: 'https://provider.com/oauth/authorize',
  tokenUrl: 'https://provider.com/oauth/token',
  userInfoUrl: 'https://provider.com/userinfo'
};

// Initiation de l'authentification
app.get('/api/auth/oauth', (req, res) => {
  const state = generateRandomState();
  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/callback`;

  const authUrl = `${oauthConfig.authorizationUrl}?` +
    `client_id=${oauthConfig.clientId}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `response_type=code&` +
    `state=${state}&` +
    `scope=openid profile email`;

  res.redirect(authUrl);
});

// Callback OAuth
app.get('/api/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!verifyState(state)) {
    return res.status(400).json({ error: 'Invalid state' });
  }

  try {
    // Échange du code contre un token
    const tokenResponse = await exchangeCodeForToken(code);

    // Récupération des infos utilisateur
    const userInfo = await getUserInfo(tokenResponse.access_token);

    // Création/mise à jour de l'utilisateur local
    const user = await findOrCreateUser(userInfo);

    // Génération du JWT local
    const jwtToken = generateJWT(user);

    res.json({
      token: jwtToken,
      user: { id: user.id, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ error: 'OAuth authentication failed' });
  }
});
```

### OpenID Connect

```javascript
// Décodage du token ID OpenID Connect
const decodeIDToken = (idToken) => {
  const parts = idToken.split('.');
  const payload = JSON.parse(atob(parts[1]));

  // Vérification du token
  if (payload.iss !== 'https://accounts.google.com') {
    throw new Error('Invalid issuer');
  }

  if (payload.aud !== process.env.OAUTH_CLIENT_ID) {
    throw new Error('Invalid audience');
  }

  return payload;
};

// Récupération des informations utilisateur
const getUserInfo = async (accessToken) => {
  const response = await fetch(oauthConfig.userInfoUrl, {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });

  return response.json();
};
```

## Authentification multi-facteurs (MFA)

### TOTP (Time-based One-Time Password)

```javascript
const speakeasy = require('speakeasy');

// Génération du secret TOTP
const generateTOTPSecret = (user) => {
  return speakeasy.generateSecret({
    name: `MyApp (${user.email})`,
    issuer: 'MyApp'
  });
};

// Activation MFA
app.post('/api/auth/mfa/setup', authenticateToken, (req, res) => {
  const secret = generateTOTPSecret(req.user);
  const qrCodeUrl = speakeasy.otpauthURL({
    secret: secret.base32,
    label: `MyApp:${req.user.email}`,
    issuer: 'MyApp'
  });

  // Sauvegarder le secret (chiffré !)
  saveUserMFASecret(req.user.id, secret.base32);

  res.json({
    secret: secret.base32,
    qrCodeUrl: qrCodeUrl
  });
});

// Vérification MFA
app.post('/api/auth/mfa/verify', authenticateToken, (req, res) => {
  const { token } = req.body;
  const secret = getUserMFASecret(req.user.id);

  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2 // Tolérance de 2 périodes (1 minute)
  });

  if (verified) {
    // Marquer MFA comme activé
    updateUserMFAStatus(req.user.id, true);
    res.json({ message: 'MFA verified successfully' });
  } else {
    res.status(400).json({ error: 'Invalid MFA token' });
  }
});
```

### Backup Codes

```javascript
// Génération de codes de secours
const generateBackupCodes = () => {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    codes.push(generateRandomCode(8)); // 8 caractères alphanumériques
  }
  return codes;
};

// Vérification avec backup code
app.post('/api/auth/mfa/backup', authenticateToken, (req, res) => {
  const { backupCode } = req.body;
  const userBackupCodes = getUserBackupCodes(req.user.id);

  const codeIndex = userBackupCodes.indexOf(backupCode);
  if (codeIndex > -1) {
    // Supprimer le code utilisé
    userBackupCodes.splice(codeIndex, 1);
    saveUserBackupCodes(req.user.id, userBackupCodes);

    res.json({ message: 'Backup code accepted' });
  } else {
    res.status(400).json({ error: 'Invalid backup code' });
  }
});
```

## Gestion des sessions

### Expiration automatique

```javascript
// Middleware de vérification d'expiration
const checkSessionExpiry = (req, res, next) => {
  if (req.session.lastActivity) {
    const now = Date.now();
    const timeSinceActivity = now - req.session.lastActivity;
    const maxInactivity = 30 * 60 * 1000; // 30 minutes

    if (timeSinceActivity > maxInactivity) {
      req.session.destroy();
      return res.status(401).json({
        error: 'Session expired',
        message: 'Your session has expired due to inactivity'
      });
    }
  }

  req.session.lastActivity = Date.now();
  next();
};
```

### Invalidation de session

```javascript
// Déconnexion
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (token) {
    // Invalider le token (blacklist)
    blacklistToken(token);
  }

  // Détruire la session si elle existe
  if (req.session) {
    req.session.destroy();
  }

  res.json({ message: 'Logged out successfully' });
});

// Blacklist des tokens
const tokenBlacklist = new Set();

const blacklistToken = (token) => {
  tokenBlacklist.add(token);

  // Nettoyer la blacklist après expiration
  setTimeout(() => {
    tokenBlacklist.delete(token);
  }, 24 * 60 * 60 * 1000); // 24 heures
};
```

## Sécurité des mots de passe

### Hachage sécurisé

```javascript
const bcrypt = require('bcrypt');

// Hachage avec salt automatique
const hashPassword = async (password) => {
  const saltRounds = 12; // Plus c'est élevé, plus c'est sécurisé
  return bcrypt.hash(password, saltRounds);
};

// Vérification
const verifyPassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

// Force du mot de passe
const validatePasswordStrength = (password) => {
  const requirements = {
    minLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password)
  };

  const score = Object.values(requirements).filter(Boolean).length;

  if (score < 3) {
    throw new Error('Password too weak');
  }

  return requirements;
};
```

### Réinitialisation de mot de passe

```javascript
// Demande de réinitialisation
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = findUserByEmail(email);

  if (user) {
    const resetToken = generateResetToken();
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    // Sauvegarder le token avec expiration
    savePasswordResetToken(user.id, resetToken, Date.now() + 3600000); // 1 heure

    // Envoyer l'email
    await sendPasswordResetEmail(email, resetUrl);
  }

  // Toujours retourner succès pour éviter l'enumération
  res.json({
    message: 'If an account with this email exists, a reset link has been sent'
  });
});

// Réinitialisation du mot de passe
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  const resetData = findPasswordResetToken(token);
  if (!resetData || resetData.expiresAt < Date.now()) {
    return res.status(400).json({
      error: 'Invalid or expired reset token'
    });
  }

  // Valider la force du nouveau mot de passe
  validatePasswordStrength(newPassword);

  // Mettre à jour le mot de passe
  const newHash = await hashPassword(newPassword);
  updateUserPassword(resetData.userId, newHash);

  // Supprimer le token de réinitialisation
  deletePasswordResetToken(token);

  res.json({ message: 'Password reset successfully' });
});
```

## Quiz de l'authentification

**Question 1** : Quelle est la différence entre authentification et autorisation ?
**Réponse** : Authentification = vérifier l'identité, Autorisation = contrôler l'accès

**Question 2** : Pourquoi utiliser des refresh tokens ?
**Réponse** : Pour avoir des tokens d'accès courts et des sessions plus longues

**Question 3** : Quand utiliser OAuth 2.0 ?
**Réponse** : Pour l'authentification tierce (Google, Facebook, GitHub)

## En résumé

### Types d'authentification
1. **Mot de passe** : Classique mais nécessite hachage sécurisé
2. **JWT** : Tokens auto-contenus et stateless
3. **API Key** : Pour les intégrations système
4. **OAuth 2.0** : Pour l'authentification tierce
5. **MFA** : Double facteur pour la sécurité

### Bonnes pratiques
- ✅ **Hachage sécurisé** des mots de passe (bcrypt)
- ✅ **Tokens courts** avec refresh tokens
- ✅ **Sessions avec expiration**
- ✅ **Validation** de la force des mots de passe
- ✅ **MFA** pour les comptes sensibles

### Sécurité essentielle
- 🔐 **HTTPS** obligatoire
- 🛡️ **Rate limiting** sur les tentatives de connexion
- 🚫 **Blacklist** des tokens invalides
- 🔄 **Rotation** des secrets
- 📝 **Logs** des tentatives d'authentification

### Structure typique
```javascript
// Middleware d'authentification
const authMiddleware = [authenticateToken, requireRole(['user'])];

// Routes protégées
app.get('/api/profile', authMiddleware, getProfile);
app.put('/api/profile', authMiddleware, updateProfile);
```

Dans le prochain chapitre, nous explorerons les **standards JWT, OAuth 2.0 et OpenID Connect** en détail !

---

**Prochain chapitre** : [02-JWT-OAuth2-OpenID](02-JWT-OAuth2-OpenID.md)
