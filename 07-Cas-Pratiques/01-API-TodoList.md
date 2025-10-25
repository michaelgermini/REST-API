# API TodoList

## Introduction

Commençons par un **cas pratique simple** mais complet : une API pour gérer une **liste de tâches** (TodoList). Ce projet va nous permettre d'appliquer tous les concepts que nous avons vus dans les chapitres précédents : authentification, CRUD, pagination, validation, tests, et documentation. C'est l'exemple parfait pour comprendre comment assembler tous les éléments.

## Analyse des besoins

### Fonctionnalités requises

```javascript
// ✅ Fonctionnalités de l'API TodoList
const features = {
  authentication: {
    register: 'Création de compte',
    login: 'Connexion',
    logout: 'Déconnexion',
    profile: 'Gestion du profil'
  },

  todos: {
    create: 'Créer une tâche',
    read: 'Lire les tâches',
    update: 'Modifier une tâche',
    delete: 'Supprimer une tâche',
    list: 'Lister les tâches',
    search: 'Rechercher des tâches',
    filter: 'Filtrer par statut/priorité'
  },

  categories: {
    create: 'Créer une catégorie',
    read: 'Lire les catégories',
    update: 'Modifier une catégorie',
    delete: 'Supprimer une catégorie'
  },

  sharing: {
    share: 'Partager une liste',
    collaborate: 'Collaboration'
  }
};
```

### Entités du domaine

```javascript
// ✅ Modèle de données
const domainModel = {
  User: {
    id: "UUID",
    email: "string",
    passwordHash: "string",
    firstName: "string",
    lastName: "string",
    createdAt: "datetime",
    todos: "Todo[]"
  },

  Todo: {
    id: "UUID",
    title: "string",
    description: "string",
    status: "enum (pending, in_progress, completed, cancelled)",
    priority: "enum (low, medium, high, urgent)",
    dueDate: "datetime",
    userId: "UUID (FK)",
    categoryId: "UUID (FK)",
    createdAt: "datetime",
    updatedAt: "datetime"
  },

  Category: {
    id: "UUID",
    name: "string",
    color: "string",
    userId: "UUID (FK)",
    createdAt: "datetime"
  }
};
```

## Configuration du projet

### Structure du projet

```
todolist-api/
├── src/
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── todoController.js
│   │   └── categoryController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── validation.js
│   │   └── errorHandler.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Todo.js
│   │   └── Category.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── todos.js
│   │   └── categories.js
│   ├── config/
│   │   └── database.js
│   ├── utils/
│   │   └── jwt.js
│   └── app.js
├── tests/
│   ├── auth.test.js
│   ├── todos.test.js
│   └── categories.test.js
├── .env
├── package.json
└── README.md
```

### Configuration de base

```javascript
// src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { sequelize } = require('./config/database');

const authRoutes = require('./routes/auth');
const todoRoutes = require('./routes/todos');
const categoryRoutes = require('./routes/categories');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// ✅ Sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'too_many_requests',
    message: 'Too many requests, please try again later'
  }
});

app.use('/api', limiter);

// ✅ Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ✅ Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ✅ Routes
app.use('/api/auth', authRoutes);
app.use('/api/todos', todoRoutes);
app.use('/api/categories', categoryRoutes);

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

// ✅ Synchronisation DB et démarrage
sequelize.sync({ force: process.env.NODE_ENV === 'test' })
  .then(() => {
    console.log('✅ Database synchronized');
    app.listen(PORT, () => {
      console.log(`🚀 TodoList API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
    });
  })
  .catch(error => {
    console.error('❌ Database sync failed:', error);
    process.exit(1);
  });

module.exports = app;
```

## Modèles de données

### Configuration base de données

```javascript
// src/config/database.js
const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: process.env.NODE_ENV === 'test' ? ':memory:' : './database.sqlite',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  define: {
    timestamps: true,
    underscored: true,
    paranoid: false
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

if (require.main === module) {
  testConnection();
}

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
    { unique: true, fields: ['email'] }
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

// ✅ Associations
User.associate = (models) => {
  User.hasMany(models.Todo, {
    foreignKey: 'userId',
    as: 'todos'
  });

  User.hasMany(models.Category, {
    foreignKey: 'userId',
    as: 'categories'
  });
};

module.exports = User;
```

### Modèle Todo

```javascript
// src/models/Todo.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Todo = sequelize.define('Todo', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [1, 200]
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  status: {
    type: DataTypes.ENUM('pending', 'in_progress', 'completed', 'cancelled'),
    defaultValue: 'pending'
  },
  priority: {
    type: DataTypes.ENUM('low', 'medium', 'high', 'urgent'),
    defaultValue: 'medium'
  },
  dueDate: {
    type: DataTypes.DATE,
    allowNull: true
  },
  completedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  categoryId: {
    type: DataTypes.UUID,
    allowNull: true,
    references: {
      model: 'Categories',
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
    { fields: ['priority'] },
    { fields: ['dueDate'] },
    { fields: ['userId'] },
    { fields: ['categoryId'] },
    { fields: ['userId', 'status'] },
    { fields: ['userId', 'dueDate'] }
  ]
});

// ✅ Méthodes d'instance
Todo.prototype.markCompleted = async function() {
  this.status = 'completed';
  this.completedAt = new Date();
  await this.save();
};

Todo.prototype.markInProgress = async function() {
  this.status = 'in_progress';
  await this.save();
};

Todo.prototype.isOverdue = function() {
  return this.dueDate && new Date(this.dueDate) < new Date() && this.status !== 'completed';
};

Todo.prototype.getDaysUntilDue = function() {
  if (!this.dueDate) return null;

  const now = new Date();
  const due = new Date(this.dueDate);
  const diffTime = due - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  return diffDays;
};

// ✅ Associations
Todo.associate = (models) => {
  Todo.belongsTo(models.User, {
    foreignKey: 'userId',
    as: 'user'
  });

  Todo.belongsTo(models.Category, {
    foreignKey: 'categoryId',
    as: 'category'
  });
};

module.exports = Todo;
```

### Modèle Category

```javascript
// src/models/Category.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Category = sequelize.define('Category', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [1, 50]
    }
  },
  color: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      is: /^#[0-9A-F]{6}$/i // Code couleur hexadécimal
    }
  },
  userId: {
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
    { fields: ['userId'] },
    { fields: ['userId', 'name'] }
  ]
});

// ✅ Associations
Category.associate = (models) => {
  Category.belongsTo(models.User, {
    foreignKey: 'userId',
    as: 'user'
  });

  Category.hasMany(models.Todo, {
    foreignKey: 'categoryId',
    as: 'todos'
  });
};

module.exports = Category;
```

## Authentification et autorisation

### Middleware d'authentification

```javascript
// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET;

// ✅ Génération des tokens
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    {
      userId: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: '24h',
      issuer: 'todolist-api',
      audience: 'todolist-clients'
    }
  );

  return { accessToken };
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
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findByPk(decoded.userId);
    if (!user) {
      throw new Error('User not found');
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({
      error: 'invalid_token',
      message: 'The provided token is not valid'
    });
  }
};

module.exports = {
  generateTokens,
  authenticateToken
};
```

### Contrôleur d'authentification

```javascript
// src/controllers/authController.js
const User = require('../models/User');
const { generateTokens } = require('../middleware/auth');

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
      lastName
    });

    await user.setPassword(password);
    await user.save();

    // Générer le token
    const tokens = generateTokens(user);

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      },
      accessToken: tokens.accessToken
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

    const user = await User.findOne({ where: { email } });
    if (!user || !await user.checkPassword(password)) {
      return res.status(401).json({
        error: 'invalid_credentials',
        message: 'Invalid email or password'
      });
    }

    const tokens = generateTokens(user);

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      },
      accessToken: tokens.accessToken
    });
  } catch (error) {
    res.status(500).json({
      error: 'login_failed',
      message: error.message
    });
  }
};

module.exports = {
  register,
  login
};
```

## CRUD des tâches

### Contrôleur Todo

```javascript
// src/controllers/todoController.js
const Todo = require('../models/Todo');
const Category = require('../models/Category');

// ✅ Récupérer toutes les tâches
const getTodos = async (req, res) => {
  try {
    const { page = 1, limit = 20, status, priority, categoryId, search } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const whereClause = { userId: req.user.id };

    // Filtres
    if (status) whereClause.status = status;
    if (priority) whereClause.priority = priority;
    if (categoryId) whereClause.categoryId = categoryId;

    // Recherche
    if (search) {
      whereClause[require('sequelize').Op.or] = [
        { title: { [require('sequelize').Op.iLike]: `%${search}%` } },
        { description: { [require('sequelize').Op.iLike]: `%${search}%` } }
      ];
    }

    const todos = await Todo.findAll({
      where: whereClause,
      include: [{
        model: Category,
        as: 'category',
        attributes: ['id', 'name', 'color']
      }],
      order: [
        ['priority', 'DESC'],
        ['dueDate', 'ASC'],
        ['createdAt', 'DESC']
      ],
      limit: Math.min(parseInt(limit), 100),
      offset
    });

    const total = await Todo.count({ where: whereClause });

    res.json({
      data: todos,
      pagination: {
        current_page: parseInt(page),
        per_page: parseInt(limit),
        total,
        total_pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_todos_failed',
      message: error.message
    });
  }
};

// ✅ Créer une tâche
const createTodo = async (req, res) => {
  try {
    const { title, description, status, priority, dueDate, categoryId } = req.body;

    // Vérifier que la catégorie appartient à l'utilisateur
    if (categoryId) {
      const category = await Category.findOne({
        where: { id: categoryId, userId: req.user.id }
      });

      if (!category) {
        return res.status(404).json({
          error: 'category_not_found',
          message: 'Category not found or does not belong to you'
        });
      }
    }

    const todo = await Todo.create({
      title,
      description,
      status: status || 'pending',
      priority: priority || 'medium',
      dueDate,
      userId: req.user.id,
      categoryId
    });

    await todo.reload({
      include: [{
        model: Category,
        as: 'category'
      }]
    });

    res.status(201).json({
      message: 'Todo created successfully',
      data: todo
    });
  } catch (error) {
    res.status(500).json({
      error: 'create_todo_failed',
      message: error.message
    });
  }
};

// ✅ Modifier une tâche
const updateTodo = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, status, priority, dueDate, categoryId } = req.body;

    // Vérifier que la tâche appartient à l'utilisateur
    const todo = await Todo.findOne({
      where: { id, userId: req.user.id }
    });

    if (!todo) {
      return res.status(404).json({
        error: 'todo_not_found',
        message: 'Todo not found or does not belong to you'
      });
    }

    // Vérifier la catégorie
    if (categoryId) {
      const category = await Category.findOne({
        where: { id: categoryId, userId: req.user.id }
      });

      if (!category) {
        return res.status(404).json({
          error: 'category_not_found',
          message: 'Category not found or does not belong to you'
        });
      }
    }

    // Mettre à jour si status passe à completed
    if (status === 'completed' && todo.status !== 'completed') {
      todo.completedAt = new Date();
    }

    await todo.update({
      title,
      description,
      status,
      priority,
      dueDate,
      categoryId
    });

    await todo.reload({
      include: [{
        model: Category,
        as: 'category'
      }]
    });

    res.json({
      message: 'Todo updated successfully',
      data: todo
    });
  } catch (error) {
    res.status(500).json({
      error: 'update_todo_failed',
      message: error.message
    });
  }
};

// ✅ Supprimer une tâche
const deleteTodo = async (req, res) => {
  try {
    const { id } = req.params;

    const todo = await Todo.findOne({
      where: { id, userId: req.user.id }
    });

    if (!todo) {
      return res.status(404).json({
        error: 'todo_not_found',
        message: 'Todo not found or does not belong to you'
      });
    }

    await todo.destroy();

    res.status(204).send();
  } catch (error) {
    res.status(500).json({
      error: 'delete_todo_failed',
      message: error.message
    });
  }
};

module.exports = {
  getTodos,
  createTodo,
  updateTodo,
  deleteTodo
};
```

## Routes API

### Routes d'authentification

```javascript
// src/routes/auth.js
const express = require('express');
const { body } = require('express-validator');
const rateLimit = require('express-rate-limit');

const authController = require('../controllers/authController');
const { handleValidationErrors } = require('../middleware/validation');

const router = express.Router();

// ✅ Rate limiting pour l'authentification
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 tentatives par 15 minutes
  message: {
    error: 'too_many_attempts',
    message: 'Too many authentication attempts'
  }
});

// ✅ Inscription
router.post('/register', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').trim().isLength({ min: 2 }),
  body('lastName').trim().isLength({ min: 2 }),
  handleValidationErrors
], authController.register);

// ✅ Connexion
router.post('/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  handleValidationErrors
], authController.login);

module.exports = router;
```

### Routes des tâches

```javascript
// src/routes/todos.js
const express = require('express');
const { body, param, query } = require('express-validator');
const todoController = require('../controllers/todoController');
const { authenticateToken } = require('../middleware/auth');
const { handleValidationErrors } = require('../middleware/validation');

const router = express.Router();

// ✅ Toutes les routes protégées
router.use(authenticateToken);

// ✅ Récupérer les tâches
router.get('/', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('status').optional().isIn(['pending', 'in_progress', 'completed', 'cancelled']),
  query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  query('categoryId').optional().isUUID(),
  query('search').optional().isLength({ min: 1 }),
  handleValidationErrors
], todoController.getTodos);

// ✅ Créer une tâche
router.post('/', [
  body('title').trim().isLength({ min: 1, max: 200 }),
  body('description').optional().isLength({ max: 1000 }),
  body('status').optional().isIn(['pending', 'in_progress', 'completed', 'cancelled']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  body('dueDate').optional().isISO8601(),
  body('categoryId').optional().isUUID(),
  handleValidationErrors
], todoController.createTodo);

// ✅ Modifier une tâche
router.put('/:id', [
  param('id').isUUID(),
  body('title').optional().trim().isLength({ min: 1, max: 200 }),
  body('description').optional().isLength({ max: 1000 }),
  body('status').optional().isIn(['pending', 'in_progress', 'completed', 'cancelled']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  body('dueDate').optional().isISO8601(),
  body('categoryId').optional().isUUID(),
  handleValidationErrors
], todoController.updateTodo);

// ✅ Supprimer une tâche
router.delete('/:id', [
  param('id').isUUID(),
  handleValidationErrors
], todoController.deleteTodo);

module.exports = router;
```

## Tests complets

### Tests d'authentification

```javascript
// tests/auth.test.js
const request = require('supertest');
const app = require('../src/app');
const { User } = require('../src/models');

describe('Authentication', () => {
  beforeEach(async () => {
    await User.destroy({ where: {} });
  });

  describe('POST /api/auth/register', () => {
    test('should register a new user', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!',
          firstName: 'Test',
          lastName: 'User'
        })
        .expect(201);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('accessToken');
      expect(response.body.user.email).toBe('test@example.com');
    });

    test('should reject invalid data', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'invalid-email',
          password: '123',
          firstName: 'T'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error', 'validation_error');
    });
  });

  describe('POST /api/auth/login', () => {
    test('should login with valid credentials', async () => {
      // Créer un utilisateur
      const user = await User.create({
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User'
      });
      await user.setPassword('password123');

      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(200);

      expect(response.body).toHaveProperty('accessToken');
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
});
```

### Tests des tâches

```javascript
// tests/todos.test.js
const request = require('supertest');
const app = require('../src/app');
const { User, Todo, Category } = require('../src/models');

describe('Todos', () => {
  let user, token, category;

  beforeEach(async () => {
    // Créer un utilisateur de test
    user = await User.create({
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User'
    });
    await user.setPassword('password123');

    // Générer un token
    const { generateTokens } = require('../src/middleware/auth');
    const tokens = generateTokens(user);
    token = tokens.accessToken;

    // Créer une catégorie
    category = await Category.create({
      name: 'Work',
      color: '#FF5733',
      userId: user.id
    });

    // Nettoyer les todos
    await Todo.destroy({ where: {} });
  });

  describe('GET /api/todos', () => {
    test('should return user todos', async () => {
      // Créer des todos de test
      await Todo.create({
        title: 'Test Todo 1',
        description: 'Description 1',
        userId: user.id,
        status: 'pending'
      });

      await Todo.create({
        title: 'Test Todo 2',
        description: 'Description 2',
        userId: user.id,
        status: 'completed'
      });

      const response = await request(app)
        .get('/api/todos')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body).toHaveProperty('data');
      expect(response.body).toHaveProperty('pagination');
      expect(response.body.data).toHaveLength(2);
    });

    test('should filter todos by status', async () => {
      await Todo.create({
        title: 'Pending Todo',
        userId: user.id,
        status: 'pending'
      });

      await Todo.create({
        title: 'Completed Todo',
        userId: user.id,
        status: 'completed'
      });

      const response = await request(app)
        .get('/api/todos?status=pending')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].status).toBe('pending');
    });
  });

  describe('POST /api/todos', () => {
    test('should create a new todo', async () => {
      const todoData = {
        title: 'New Todo',
        description: 'Todo description',
        priority: 'high',
        categoryId: category.id
      };

      const response = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${token}`)
        .send(todoData)
        .expect(201);

      expect(response.body).toHaveProperty('data');
      expect(response.body.data.title).toBe(todoData.title);
      expect(response.body.data.priority).toBe(todoData.priority);
    });

    test('should reject todo with invalid category', async () => {
      const todoData = {
        title: 'New Todo',
        categoryId: '550e8400-e29b-41d4-a716-446655440000' // UUID invalide
      };

      const response = await request(app)
        .post('/api/todos')
        .set('Authorization', `Bearer ${token}`)
        .send(todoData)
        .expect(404);

      expect(response.body).toHaveProperty('error', 'category_not_found');
    });
  });

  describe('PUT /api/todos/:id', () => {
    test('should update user todo', async () => {
      const todo = await Todo.create({
        title: 'Original Todo',
        userId: user.id
      });

      const updateData = {
        title: 'Updated Todo',
        status: 'completed'
      };

      const response = await request(app)
        .put(`/api/todos/${todo.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send(updateData)
        .expect(200);

      expect(response.body.data.title).toBe(updateData.title);
      expect(response.body.data.status).toBe(updateData.status);
    });

    test('should prevent updating other users todos', async () => {
      const otherUser = await User.create({
        email: 'other@example.com',
        firstName: 'Other',
        lastName: 'User'
      });

      const otherTodo = await Todo.create({
        title: 'Other Todo',
        userId: otherUser.id
      });

      const response = await request(app)
        .put(`/api/todos/${otherTodo.id}`)
        .set('Authorization', `Bearer ${token}`)
        .send({ title: 'Hacked Todo' })
        .expect(404);

      expect(response.body).toHaveProperty('error', 'todo_not_found');
    });
  });

  describe('DELETE /api/todos/:id', () => {
    test('should delete user todo', async () => {
      const todo = await Todo.create({
        title: 'Todo to delete',
        userId: user.id
      });

      await request(app)
        .delete(`/api/todos/${todo.id}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(204);

      // Vérifier que la todo est supprimée
      const deletedTodo = await Todo.findByPk(todo.id);
      expect(deletedTodo).toBeNull();
    });
  });
});
```

## Documentation OpenAPI

### Configuration Swagger

```javascript
// src/app.js (ajout de la documentation)
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Configuration OpenAPI
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'TodoList API',
      version: '1.0.0',
      description: 'REST API for managing todo lists',
      contact: {
        name: 'API Support',
        email: 'support@example.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000/api',
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  },
  apis: ['./src/routes/*.js']
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Documentation Swagger
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
```

### Annotations dans les routes

```javascript
// src/routes/todos.js (avec annotations)
/**
 * @swagger
 * components:
 *   schemas:
 *     Todo:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *           format: uuid
 *         title:
 *           type: string
 *           maxLength: 200
 *         description:
 *           type: string
 *           maxLength: 1000
 *         status:
 *           type: string
 *           enum: [pending, in_progress, completed, cancelled]
 *         priority:
 *           type: string
 *           enum: [low, medium, high, urgent]
 *         dueDate:
 *           type: string
 *           format: date-time
 *         categoryId:
 *           type: string
 *           format: uuid
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 *       required:
 *         - title
 *         - userId
 */

/**
 * @swagger
 * /api/todos:
 *   get:
 *     summary: Get user todos
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: page
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *       - name: limit
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *       - name: status
 *         in: query
 *         schema:
 *           type: string
 *           enum: [pending, in_progress, completed, cancelled]
 *       - name: priority
 *         in: query
 *         schema:
 *           type: string
 *           enum: [low, medium, high, urgent]
 *       - name: search
 *         in: query
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of todos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Todo'
 *                 pagination:
 *                   $ref: '#/components/schemas/Pagination'
 */
router.get('/', todoController.getTodos);
```

## Déploiement

### Dockerfile

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Installation des dépendances
COPY package*.json ./
RUN npm ci --only=production

# Copie du code source
COPY . .

# Exposition du port
EXPOSE 3000

# Commande de démarrage
CMD ["npm", "start"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - JWT_SECRET=your-production-secret
      - CORS_ORIGIN=https://yourdomain.com
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped

  db:
    image: sqlite:3-alpine
    volumes:
      - ./data:/data
    restart: unless-stopped
```

## Quiz TodoList API

**Question 1** : Quelles sont les fonctionnalités principales d'une API TodoList ?
**Réponse** : CRUD des tâches, authentification, catégories, filtrage et recherche

**Question 2** : Comment implémenter la sécurité BOLA dans les todos ?
**Réponse** : Vérifier que l'utilisateur ne peut accéder qu'à ses propres tâches

**Question 3** : Pourquoi utiliser des UUIDs pour les IDs ?
**Réponse** : Pour éviter l'énumération et améliorer la sécurité

## En résumé

### Fonctionnalités implémentées
- ✅ **Authentification** JWT complète
- ✅ **CRUD** des tâches avec validation
- ✅ **Catégories** pour organiser les tâches
- ✅ **Filtrage** par statut, priorité, date
- ✅ **Recherche** textuelle
- ✅ **Pagination** et **tri**
- ✅ **Tests** unitaires complets
- ✅ **Documentation** OpenAPI
- ✅ **Sécurité** (BOLA, validation, rate limiting)

### Architecture
```
✅ MVC avec Express
✅ ORM Sequelize
✅ JWT Authentication
✅ Rate Limiting
✅ Input Validation
✅ Error Handling
✅ Logging
✅ Tests automatisés
✅ Documentation API
✅ Containerisation
```

### Points clés
- 🔐 **Sécurité** : Authentification, BOLA, validation
- 📊 **Performance** : Pagination, cache, index DB
- 🧪 **Qualité** : Tests complets, linting
- 📚 **Documentation** : OpenAPI/Swagger
- 🚀 **Déploiement** : Docker, monitoring

Cette API TodoList démontre l'application complète des concepts REST que nous avons vus. Dans le prochain chapitre, nous verrons un cas plus complexe avec une API **E-commerce** !

---

**Prochain chapitre** : [02-API-E-Commerce](02-API-E-Commerce.md)
