# API avec Node.js et Express

## Introduction

**Node.js** et **Express** sont la **stack la plus populaire** pour développer des APIs REST en JavaScript. Express est un framework minimaliste et flexible qui fournit des fonctionnalités robustes pour les applications web et les APIs. Dans ce chapitre, nous allons créer une API REST complète avec Node.js, Express, et toutes les bonnes pratiques que nous avons apprises.

## Configuration du projet

### Initialisation

```bash
# Créer un nouveau projet
mkdir blog-api
cd blog-api
npm init -y

# Installer les dépendances
npm install express cors helmet express-rate-limit express-validator
npm install jsonwebtoken bcryptjs multer dotenv
npm install --save-dev nodemon jest supertest
```

### Structure du projet

```
blog-api/
├── src/
│   ├── controllers/
│   │   ├── users.js
│   │   ├── posts.js
│   │   └── auth.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── validation.js
│   │   └── errorHandler.js
│   ├── models/
│   │   ├── User.js
│   │   └── Post.js
│   ├── routes/
│   │   ├── users.js
│   │   ├── posts.js
│   │   └── auth.js
│   ├── config/
│   │   └── database.js
│   ├── utils/
│   │   └── jwt.js
│   └── app.js
├── tests/
│   ├── users.test.js
│   ├── posts.test.js
│   └── auth.test.js
├── .env
├── package.json
└── README.md
```

### Package.json

```json
{
  "name": "blog-api",
  "version": "1.0.0",
  "description": "REST API for a blog platform",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "dev": "nodemon src/app.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "lint": "eslint src/",
    "format": "prettier --write src/"
  },
  "dependencies": {
    "express": "^4.18.0",
    "cors": "^2.8.5",
    "helmet": "^6.0.1",
    "express-rate-limit": "^6.7.0",
    "express-validator": "^7.0.1",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "multer": "^1.4.5-lts.1",
    "dotenv": "^16.0.3"
  },
  "devDependencies": {
    "nodemon": "^2.0.22",
    "jest": "^29.5.0",
    "supertest": "^6.3.3",
    "eslint": "^8.40.0",
    "prettier": "^2.8.8"
  },
  "keywords": ["rest", "api", "express", "nodejs"],
  "author": "Your Name",
  "license": "MIT"
}
```

## Configuration de base

### Variables d'environnement

```bash
# .env
NODE_ENV=development
PORT=3000
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-refresh-secret-key-here
DATABASE_URL=postgresql://user:password@localhost:5432/blogdb
CORS_ORIGIN=http://localhost:3000
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
```

### Application principale

```javascript
// src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const postRoutes = require('./routes/posts');

const errorHandler = require('./middleware/errorHandler');
const { authenticateToken } = require('./middleware/auth');

const app = express();

// ✅ Sécurité de base
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

// ✅ CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200
}));

// ✅ Rate limiting
const limiter = rateLimit({
  windowMs: (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX || 100,
  message: {
    error: 'too_many_requests',
    message: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', limiter);

// ✅ Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ✅ Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// ✅ API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/posts', authenticateToken, postRoutes);

// ✅ 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'not_found',
    message: `Route ${req.originalUrl} not found`
  });
});

// ✅ Error handler
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`📚 API docs: http://localhost:${PORT}/api/docs`);
});

module.exports = app;
```

## Middleware de sécurité

### Authentification

```javascript
// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// ✅ Génération des tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions
    },
    JWT_SECRET,
    {
      expiresIn: '15m',
      issuer: 'blog-api',
      audience: 'blog-clients'
    }
  );

  const refreshToken = jwt.sign(
    {
      userId: user.id,
      type: 'refresh'
    },
    JWT_REFRESH_SECRET,
    {
      expiresIn: '7d',
      issuer: 'blog-api'
    }
  );

  return { accessToken, refreshToken };
};

// ✅ Middleware d'authentification
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'access_token_required',
      message: 'Please provide a valid access token'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'blog-api',
      audience: 'blog-clients'
    });

    // Vérifier que l'utilisateur existe toujours
    const user = await User.findByPk(decoded.userId);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }

    req.user = user;
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

// ✅ Middleware d'autorisation
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

module.exports = {
  generateTokens,
  authenticateToken,
  requireRole,
  requirePermission
};
```

### Validation

```javascript
// src/middleware/validation.js
const { body, param, query, validationResult } = require('express-validator');

// ✅ Gestion des erreurs de validation
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'validation_error',
      message: 'The request contains invalid data',
      details: errors.array().map(error => ({
        field: error.path,
        message: error.msg,
        value: error.value
      }))
    });
  }

  next();
};

// ✅ Validations communes
const validateUserRegistration = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must be at least 8 characters with uppercase, lowercase, and number'),
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  handleValidationErrors
];

const validateUserLogin = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

const validateUUID = [
  param('id')
    .isUUID()
    .withMessage('Invalid ID format'),
  handleValidationErrors
];

const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  handleValidationErrors
];

module.exports = {
  handleValidationErrors,
  validateUserRegistration,
  validateUserLogin,
  validateUUID,
  validatePagination
};
```

### Gestion des erreurs

```javascript
// src/middleware/errorHandler.js
const errorHandler = (error, req, res, next) => {
  console.error('Error:', error);

  // Erreurs JWT
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'invalid_token',
      message: 'The provided token is not valid'
    });
  }

  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'token_expired',
      message: 'Your access token has expired'
    });
  }

  // Erreurs de validation
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      error: 'validation_error',
      message: 'The request contains invalid data',
      details: error.details
    });
  }

  // Erreurs de base de données
  if (error.code === '23505') { // Unique constraint violation
    return res.status(409).json({
      error: 'duplicate_entry',
      message: 'A record with this information already exists'
    });
  }

  // Erreur par défaut
  res.status(500).json({
    error: 'internal_server_error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'An unexpected error occurred'
  });
};

module.exports = errorHandler;
```

## Modèles de données

### Configuration de la base de données

```javascript
// src/config/database.js
const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  pool: {
    max: 20,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  define: {
    timestamps: true,
    underscored: true,
    paranoid: true // Soft delete
  }
});

// Test de connexion
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established');
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    process.exit(1);
  }
};

module.exports = {
  sequelize,
  testConnection
};
```

### Modèle User

```javascript
// src/models/User.js
const { DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const { sequelize } = require('../config/database');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  passwordHash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  firstName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [2, 50]
    }
  },
  lastName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [2, 50]
    }
  },
  role: {
    type: DataTypes.ENUM('user', 'author', 'admin'),
    defaultValue: 'user'
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  lastLoginAt: {
    type: DataTypes.DATE
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  updatedAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  indexes: [
    { unique: true, fields: ['email'] },
    { fields: ['role'] },
    { fields: ['isActive'] }
  ]
});

// ✅ Méthodes d'instance
User.prototype.setPassword = async function(password) {
  this.passwordHash = await bcrypt.hash(password, 12);
};

User.prototype.checkPassword = async function(password) {
  return bcrypt.compare(password, this.passwordHash);
};

User.prototype.getFullName = function() {
  return `${this.firstName} ${this.lastName}`;
};

User.prototype.getPermissions = function() {
  const permissions = {
    user: ['read:profile', 'write:profile', 'read:posts'],
    author: ['read:profile', 'write:profile', 'read:posts', 'write:posts', 'delete:own-posts'],
    admin: ['*']
  };

  return permissions[this.role] || [];
};

// ✅ Associations
User.associate = (models) => {
  User.hasMany(models.Post, {
    foreignKey: 'authorId',
    as: 'posts'
  });

  User.hasMany(models.Comment, {
    foreignKey: 'authorId',
    as: 'comments'
  });
};

module.exports = User;
```

### Modèle Post

```javascript
// src/models/Post.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Post = sequelize.define('Post', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [3, 200]
    }
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  excerpt: {
    type: DataTypes.STRING,
    validate: {
      len: [0, 300]
    }
  },
  status: {
    type: DataTypes.ENUM('draft', 'published', 'archived'),
    defaultValue: 'draft'
  },
  publishedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  viewCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  authorId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  updatedAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  indexes: [
    { fields: ['status'] },
    { fields: ['publishedAt'] },
    { fields: ['authorId'] },
    { fields: ['title'] },
    { fields: ['status', 'publishedAt'] }
  ]
});

// ✅ Méthodes d'instance
Post.prototype.publish = async function() {
  this.status = 'published';
  this.publishedAt = new Date();
  await this.save();
};

Post.prototype.unpublish = async function() {
  this.status = 'draft';
  this.publishedAt = null;
  await this.save();
};

Post.prototype.isPublished = function() {
  return this.status === 'published' && this.publishedAt;
};

// ✅ Associations
Post.associate = (models) => {
  Post.belongsTo(models.User, {
    foreignKey: 'authorId',
    as: 'author'
  });

  Post.hasMany(models.Comment, {
    foreignKey: 'postId',
    as: 'comments'
  });

  Post.belongsToMany(models.Tag, {
    through: 'PostTags',
    foreignKey: 'postId',
    otherKey: 'tagId',
    as: 'tags'
  });
};

module.exports = Post;
```

## Contrôleurs

### Contrôleur d'authentification

```javascript
// src/controllers/auth.js
const User = require('../models/User');
const { generateTokens } = require('../middleware/auth');
const { validationResult } = require('express-validator');

// ✅ Inscription
const register = async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(409).json({
        error: 'user_exists',
        message: 'An account with this email already exists'
      });
    }

    // Créer l'utilisateur
    const user = await User.create({
      email,
      firstName,
      lastName,
      role: 'user'
    });

    await user.setPassword(password);
    await user.save();

    // Générer les tokens
    const tokens = generateTokens(user);

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
      },
      tokens
    });
  } catch (error) {
    res.status(500).json({
      error: 'registration_failed',
      message: error.message
    });
  }
};

// ✅ Connexion
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Trouver l'utilisateur
    const user = await User.findOne({ where: { email } });
    if (!user || !await user.checkPassword(password)) {
      return res.status(401).json({
        error: 'invalid_credentials',
        message: 'Invalid email or password'
      });
    }

    // Vérifier que l'utilisateur est actif
    if (!user.isActive) {
      return res.status(401).json({
        error: 'account_inactive',
        message: 'Your account has been deactivated'
      });
    }

    // Mettre à jour la dernière connexion
    user.lastLoginAt = new Date();
    await user.save();

    // Générer les tokens
    const tokens = generateTokens(user);

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role
      },
      tokens
    });
  } catch (error) {
    res.status(500).json({
      error: 'login_failed',
      message: error.message
    });
  }
};

// ✅ Actualisation des tokens
const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    const user = await User.findByPk(decoded.userId);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }

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
};

module.exports = {
  register,
  login,
  refreshToken
};
```

### Contrôleur des utilisateurs

```javascript
// src/controllers/users.js
const User = require('../models/User');
const Post = require('../models/Post');

// ✅ Récupérer tous les utilisateurs
const getUsers = async (req, res) => {
  try {
    const { page = 1, limit = 20, search, role } = req.query;

    const whereClause = {};
    if (role) whereClause.role = role;
    if (search) {
      whereClause[Op.or] = [
        { firstName: { [Op.iLike]: `%${search}%` } },
        { lastName: { [Op.iLike]: `%${search}%` } },
        { email: { [Op.iLike]: `%${search}%` } }
      ];
    }

    const offset = (parseInt(page) - 1) * parseInt(limit);

    const { rows: users, count: total } = await User.findAndCountAll({
      where: whereClause,
      attributes: ['id', 'firstName', 'lastName', 'email', 'role', 'createdAt'],
      limit: Math.min(parseInt(limit), 100),
      offset: offset,
      order: [['createdAt', 'DESC']]
    });

    res.json({
      data: users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        total_pages: Math.ceil(total / parseInt(limit))
      },
      _links: {
        self: `/api/users?page=${page}&limit=${limit}`,
        first: `/api/users?page=1&limit=${limit}`,
        last: `/api/users?page=${Math.ceil(total / parseInt(limit))}&limit=${limit}`
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_users_failed',
      message: error.message
    });
  }
};

// ✅ Récupérer un utilisateur
const getUser = async (req, res) => {
  try {
    const userId = req.params.id;
    const requestingUser = req.user;

    // Vérification BOLA
    if (userId !== requestingUser.id && requestingUser.role !== 'admin') {
      return res.status(403).json({
        error: 'access_denied',
        message: 'You can only access your own profile'
      });
    }

    const user = await User.findByPk(userId, {
      attributes: ['id', 'firstName', 'lastName', 'email', 'role', 'createdAt', 'lastLoginAt']
    });

    if (!user) {
      return res.status(404).json({
        error: 'user_not_found',
        message: 'No user found with this ID'
      });
    }

    res.json({
      data: user,
      _links: {
        self: `/api/users/${userId}`,
        posts: `/api/users/${userId}/posts`
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_user_failed',
      message: error.message
    });
  }
};

// ✅ Modifier un utilisateur
const updateUser = async (req, res) => {
  try {
    const userId = req.params.id;
    const requestingUser = req.user;
    const { firstName, lastName, email } = req.body;

    // Vérification BOLA
    if (userId !== requestingUser.id && requestingUser.role !== 'admin') {
      return res.status(403).json({
        error: 'access_denied',
        message: 'You can only modify your own profile'
      });
    }

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({
        error: 'user_not_found',
        message: 'No user found with this ID'
      });
    }

    // Vérifier l'unicité de l'email
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(409).json({
          error: 'email_exists',
          message: 'This email is already in use'
        });
      }
    }

    await user.update({
      firstName: firstName || user.firstName,
      lastName: lastName || user.lastName,
      email: email || user.email
    });

    res.json({
      message: 'User updated successfully',
      data: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'update_user_failed',
      message: error.message
    });
  }
};

module.exports = {
  getUsers,
  getUser,
  updateUser
};
```

## Quiz de Node.js et Express

**Question 1** : Quel middleware Express utiliser pour la sécurité de base ?
**Réponse** : helmet() pour les headers de sécurité

**Question 2** : Comment implémenter la pagination avec Sequelize ?
**Réponse** : Utiliser limit, offset et findAndCountAll()

**Question 3** : Comment gérer les erreurs de validation Express ?
**Réponse** : Avec validationResult() et un middleware handleValidationErrors

## En résumé

### Structure recommandée
```
src/
├── controllers/     # Logique métier
├── middleware/      # Auth, validation, erreurs
├── models/         # Modèles Sequelize
├── routes/         # Définition des routes
├── config/         # Configuration DB
├── utils/          # Fonctions utilitaires
└── app.js          # Point d'entrée
```

### Bonnes pratiques
- ✅ **Validation** de toutes les entrées
- ✅ **Authentification** JWT robuste
- ✅ **Autorisation** par rôle et permissions
- ✅ **Pagination** et **rate limiting**
- ✅ **Logging** et **monitoring**
- ✅ **Tests** automatisés

### Configuration de sécurité
```javascript
// Sécurité complète
✅ Helmet pour headers
✅ CORS configuré
✅ Rate limiting
✅ Validation d'entrée
✅ Authentification JWT
✅ Autorisation RBAC
✅ Logging de sécurité
✅ Tests de sécurité
```

### Exemple d'API complète
```javascript
// API Blog RESTful
GET /api/users          // Liste utilisateurs
GET /api/users/123      // Profil utilisateur
POST /api/auth/login    // Connexion
POST /api/auth/register // Inscription
GET /api/posts          // Articles (authentifié)
POST /api/posts         // Créer article (authentifié)
```

Dans le prochain chapitre, nous verrons comment implémenter une API avec **Python et FastAPI**, un framework moderne et performant !

---

**Prochain chapitre** : [02-API-avec-Python-FastAPI](02-API-avec-Python-FastAPI.md)
