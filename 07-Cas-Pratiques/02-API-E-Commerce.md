# API E-Commerce

## Introduction

L'**e-commerce** est l'un des cas d'usage les plus complexes et complets pour une API REST. Une API e-commerce doit gérer des **produits**, des **commandes**, des **paiements**, des **utilisateurs**, des **inventaires**, et bien plus. Dans ce chapitre, nous allons créer une API e-commerce complète qui illustre tous les concepts avancés : relations complexes, transactions, webhooks, et intégrations tierces.

## Analyse des besoins

### Fonctionnalités requises

```javascript
// ✅ Fonctionnalités de l'API E-commerce
const features = {
  catalog: {
    products: 'Gestion des produits',
    categories: 'Catégories et filtres',
    search: 'Recherche avancée',
    reviews: 'Avis et notations'
  },

  cart: {
    add: 'Ajouter au panier',
    update: 'Modifier le panier',
    remove: 'Retirer du panier',
    checkout: 'Validation du panier'
  },

  orders: {
    create: 'Créer une commande',
    track: 'Suivi de commande',
    cancel: 'Annulation',
    history: 'Historique des commandes'
  },

  payments: {
    process: 'Traitement des paiements',
    refund: 'Remboursements',
    webhooks: 'Notifications de paiement'
  },

  users: {
    profile: 'Gestion du profil',
    addresses: 'Adresses de livraison',
    wishlist: 'Liste de souhaits'
  },

  admin: {
    inventory: 'Gestion des stocks',
    analytics: 'Analytiques',
    coupons: 'Codes promo'
  }
};
```

### Entités du domaine

```javascript
// ✅ Modèle de données e-commerce
const domainModel = {
  User: {
    id: "UUID",
    email: "string",
    passwordHash: "string",
    firstName: "string",
    lastName: "string",
    addresses: "Address[]",
    orders: "Order[]",
    wishlist: "Product[]",
    reviews: "Review[]"
  },

  Product: {
    id: "UUID",
    name: "string",
    description: "string",
    price: "decimal",
    sku: "string",
    stock: "integer",
    category: "Category",
    images: "ProductImage[]",
    variants: "ProductVariant[]",
    reviews: "Review[]"
  },

  Order: {
    id: "UUID",
    user: "User",
    items: "OrderItem[]",
    total: "decimal",
    status: "OrderStatus",
    shippingAddress: "Address",
    paymentMethod: "PaymentMethod"
  },

  Category: {
    id: "UUID",
    name: "string",
    parent: "Category",
    products: "Product[]"
  }
};
```

## Configuration du projet

### Structure du projet

```
ecommerce-api/
├── src/
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── productController.js
│   │   ├── orderController.js
│   │   ├── cartController.js
│   │   └── paymentController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── validation.js
│   │   └── cors.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Product.js
│   │   ├── Order.js
│   │   ├── Category.js
│   │   └── Cart.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── products.js
│   │   ├── orders.js
│   │   ├── cart.js
│   │   └── webhooks.js
│   ├── services/
│   │   ├── paymentService.js
│   │   ├── emailService.js
│   │   └── inventoryService.js
│   ├── config/
│   │   └── database.js
│   └── app.js
├── tests/
│   ├── auth.test.js
│   ├── products.test.js
│   ├── orders.test.js
│   └── payments.test.js
├── .env
├── package.json
└── README.md
```

### Configuration avancée

```javascript
// src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const { sequelize } = require('./config/database');

const authRoutes = require('./routes/auth');
const productRoutes = require('./routes/products');
const orderRoutes = require('./routes/orders');
const cartRoutes = require('./routes/cart');
const webhookRoutes = require('./routes/webhooks');
const errorHandler = require('./middleware/errorHandler');

const app = express();

// ✅ Sécurité renforcée
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.stripe.com"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: [
    'https://yourstore.com',
    'https://admin.yourstore.com',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'Idempotency-Key']
}));

// ✅ Compression
app.use(compression({
  level: 6,
  threshold: 1024
}));

// ✅ Rate limiting par type d'utilisateur
const createRateLimit = (max, windowMs) => rateLimit({
  windowMs,
  max,
  message: {
    error: 'rate_limit_exceeded',
    message: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Limites différentes selon les endpoints
app.use('/api/auth', createRateLimit(5, 15 * 60 * 1000));     // 5/min pour auth
app.use('/api/products', createRateLimit(100, 15 * 60 * 1000)); // 100/min pour produits
app.use('/api/cart', createRateLimit(50, 15 * 60 * 1000));     // 50/min pour panier
app.use('/api/orders', createRateLimit(20, 15 * 60 * 1000));   // 20/min pour commandes

// ✅ Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ✅ Health check
app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    services: {}
  };

  try {
    await sequelize.authenticate();
    health.services.database = 'healthy';
  } catch (error) {
    health.status = 'degraded';
    health.services.database = 'unhealthy';
  }

  res.status(health.status === 'healthy' ? 200 : 503).json(health);
});

// ✅ Routes
app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/webhooks', webhookRoutes);

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

// ✅ Synchronisation et démarrage
sequelize.sync({ force: process.env.NODE_ENV === 'test' })
  .then(async () => {
    console.log('✅ Database synchronized');

    // Créer les rôles et permissions
    await setupRolesAndPermissions();

    app.listen(PORT, () => {
      console.log(`🚀 E-commerce API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
      console.log(`📚 API docs: http://localhost:${PORT}/api/docs`);
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
  dialect: 'postgresql',
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'ecommerce',
  username: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
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
    paranoid: true
  }
});

module.exports = {
  sequelize
};
```

### Modèle Product

```javascript
// src/models/Product.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Product = sequelize.define('Product', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [2, 200]
    }
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  shortDescription: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      len: [0, 500]
    }
  },
  price: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0
    }
  },
  compareAtPrice: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: true,
    validate: {
      min: 0
    }
  },
  sku: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  stock: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  stockStatus: {
    type: DataTypes.VIRTUAL,
    get() {
      if (this.stock > 10) return 'in_stock';
      if (this.stock > 0) return 'low_stock';
      return 'out_of_stock';
    }
  },
  weight: {
    type: DataTypes.DECIMAL(8, 2),
    allowNull: true
  },
  dimensions: {
    type: DataTypes.JSON,
    allowNull: true
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  isFeatured: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  seoTitle: {
    type: DataTypes.STRING,
    allowNull: true
  },
  seoDescription: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  categoryId: {
    type: DataTypes.UUID,
    allowNull: false,
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
    { fields: ['isActive'] },
    { fields: ['isFeatured'] },
    { fields: ['categoryId'] },
    { fields: ['price'] },
    { fields: ['stock'] },
    { fields: ['name'] },
    { fields: ['sku'], unique: true },
    { fields: ['isActive', 'stock'] },
    { fields: ['isActive', 'isFeatured'] }
  ]
});

// ✅ Méthodes d'instance
Product.prototype.getDiscountPercentage = function() {
  if (!this.compareAtPrice || this.compareAtPrice <= this.price) return 0;

  return Math.round(((this.compareAtPrice - this.price) / this.compareAtPrice) * 100);
};

Product.prototype.isOnSale = function() {
  return this.compareAtPrice && this.compareAtPrice > this.price;
};

Product.prototype.getFormattedPrice = function() {
  return new Intl.NumberFormat('fr-FR', {
    style: 'currency',
    currency: 'EUR'
  }).format(this.price);
};

// ✅ Associations
Product.associate = (models) => {
  Product.belongsTo(models.Category, {
    foreignKey: 'categoryId',
    as: 'category'
  });

  Product.hasMany(models.ProductImage, {
    foreignKey: 'productId',
    as: 'images'
  });

  Product.hasMany(models.ProductVariant, {
    foreignKey: 'productId',
    as: 'variants'
  });

  Product.hasMany(models.Review, {
    foreignKey: 'productId',
    as: 'reviews'
  });

  Product.belongsToMany(models.Order, {
    through: models.OrderItem,
    foreignKey: 'productId',
    otherKey: 'orderId'
  });
};

module.exports = Product;
```

### Modèle Order

```javascript
// src/models/Order.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Order = sequelize.define('Order', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  orderNumber: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  status: {
    type: DataTypes.ENUM(
      'pending',
      'confirmed',
      'processing',
      'shipped',
      'delivered',
      'cancelled',
      'refunded'
    ),
    defaultValue: 'pending'
  },
  subtotal: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0
    }
  },
  taxAmount: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  shippingAmount: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  discountAmount: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  total: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false,
    validate: {
      min: 0
    }
  },
  currency: {
    type: DataTypes.STRING,
    defaultValue: 'EUR'
  },
  paymentStatus: {
    type: DataTypes.ENUM('pending', 'paid', 'failed', 'refunded'),
    defaultValue: 'pending'
  },
  paymentMethod: {
    type: DataTypes.STRING,
    allowNull: true
  },
  paymentIntentId: {
    type: DataTypes.STRING,
    allowNull: true
  },
  shippingAddress: {
    type: DataTypes.JSON,
    allowNull: false
  },
  billingAddress: {
    type: DataTypes.JSON,
    allowNull: true
  },
  notes: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  trackingNumber: {
    type: DataTypes.STRING,
    allowNull: true
  },
  shippedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  deliveredAt: {
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
    { fields: ['paymentStatus'] },
    { fields: ['userId'] },
    { fields: ['orderNumber'], unique: true },
    { fields: ['createdAt'] },
    { fields: ['userId', 'status'] },
    { fields: ['paymentIntentId'] }
  ]
});

// ✅ Méthodes d'instance
Order.prototype.calculateTotal = function() {
  this.total = this.subtotal + this.taxAmount + this.shippingAmount - this.discountAmount;
  return this.total;
};

Order.prototype.canBeCancelled = function() {
  return ['pending', 'confirmed'].includes(this.status);
};

Order.prototype.canBeShipped = function() {
  return this.status === 'processing' && this.paymentStatus === 'paid';
};

// ✅ Associations
Order.associate = (models) => {
  Order.belongsTo(models.User, {
    foreignKey: 'userId',
    as: 'user'
  });

  Order.hasMany(models.OrderItem, {
    foreignKey: 'orderId',
    as: 'items'
  });
};

module.exports = Order;
```

### Modèle Cart

```javascript
// src/models/Cart.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Cart = sequelize.define('Cart', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  sessionId: {
    type: DataTypes.STRING,
    allowNull: true // Pour les paniers anonymes
  },
  items: {
    type: DataTypes.JSON,
    defaultValue: []
  },
  total: {
    type: DataTypes.DECIMAL(10, 2),
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  itemCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    validate: {
      min: 0
    }
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
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
    { fields: ['sessionId'] },
    { fields: ['expiresAt'] },
    { fields: ['userId', 'expiresAt'] }
  ]
});

// ✅ Méthodes d'instance
Cart.prototype.addItem = function(productId, quantity, variant = null) {
  const existingItemIndex = this.items.findIndex(
    item => item.productId === productId && item.variant === variant
  );

  if (existingItemIndex >= 0) {
    this.items[existingItemIndex].quantity += quantity;
  } else {
    this.items.push({
      productId,
      variant,
      quantity,
      addedAt: new Date()
    });
  }

  this.updateTotals();
};

Cart.prototype.removeItem = function(productId, variant = null) {
  this.items = this.items.filter(
    item => !(item.productId === productId && item.variant === variant)
  );

  this.updateTotals();
};

Cart.prototype.updateTotals = function() {
  this.itemCount = this.items.reduce((total, item) => total + item.quantity, 0);

  // Calcul du total (simplifié)
  this.total = this.items.reduce((total, item) => {
    // Ici, récupérer le prix du produit depuis la base
    return total + (item.price * item.quantity);
  }, 0);
};

Cart.prototype.isExpired = function() {
  return new Date() > this.expiresAt;
};

// ✅ Associations
Cart.associate = (models) => {
  Cart.belongsTo(models.User, {
    foreignKey: 'userId',
    as: 'user'
  });
};

module.exports = Cart;
```

## Gestion du panier

### Contrôleur Cart

```javascript
// src/controllers/cartController.js
const Cart = require('../models/Cart');
const Product = require('../models/Product');

// ✅ Récupérer le panier
const getCart = async (req, res) => {
  try {
    let cart;

    if (req.user) {
      // Panier utilisateur connecté
      cart = await Cart.findOne({
        where: { userId: req.user.id },
        include: [{
          model: Product,
          as: 'products',
          through: { attributes: ['quantity', 'variant'] }
        }]
      });

      if (!cart) {
        // Créer un panier vide
        cart = await Cart.create({
          userId: req.user.id,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 jours
        });
      }
    } else {
      // Panier de session anonyme
      const sessionId = req.headers['x-session-id'] || generateSessionId();

      cart = await Cart.findOne({
        where: { sessionId },
        include: [{
          model: Product,
          as: 'products'
        }]
      });

      if (!cart) {
        cart = await Cart.create({
          sessionId,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 heures
        });
      }

      res.set('X-Session-Id', sessionId);
    }

    // Enrichir avec les détails des produits
    const enrichedItems = await Promise.all(
      cart.items.map(async (item) => {
        const product = await Product.findByPk(item.productId, {
          attributes: ['id', 'name', 'price', 'stock']
        });

        return {
          ...item,
          product: product ? {
            id: product.id,
            name: product.name,
            price: product.price,
            inStock: product.stock > 0
          } : null
        };
      })
    );

    res.json({
      id: cart.id,
      items: enrichedItems,
      total: cart.total,
      itemCount: cart.itemCount,
      expiresAt: cart.expiresAt
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_cart_failed',
      message: error.message
    });
  }
};

// ✅ Ajouter au panier
const addToCart = async (req, res) => {
  try {
    const { productId, quantity, variant } = req.body;

    // Validation
    if (!productId || !quantity) {
      return res.status(400).json({
        error: 'invalid_data',
        message: 'Product ID and quantity are required'
      });
    }

    // Vérifier que le produit existe et est en stock
    const product = await Product.findByPk(productId);
    if (!product || !product.isActive) {
      return res.status(404).json({
        error: 'product_not_found',
        message: 'Product not found or inactive'
      });
    }

    if (product.stock === 0) {
      return res.status(400).json({
        error: 'out_of_stock',
        message: 'Product is out of stock'
      });
    }

    // Récupérer ou créer le panier
    let cart = await getOrCreateCart(req.user, req.headers['x-session-id']);

    // Ajouter l'item
    cart.addItem(productId, quantity, variant);

    // Vérifier la disponibilité
    const requestedQuantity = cart.items.find(
      item => item.productId === productId && item.variant === variant
    )?.quantity || 0;

    if (requestedQuantity > product.stock) {
      return res.status(400).json({
        error: 'insufficient_stock',
        message: `Only ${product.stock} items available in stock`
      });
    }

    await cart.save();

    res.status(201).json({
      message: 'Item added to cart',
      cart: {
        id: cart.id,
        itemCount: cart.itemCount,
        total: cart.total
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'add_to_cart_failed',
      message: error.message
    });
  }
};

// ✅ Mettre à jour le panier
const updateCartItem = async (req, res) => {
  try {
    const { productId, quantity, variant } = req.body;

    if (quantity < 0) {
      return res.status(400).json({
        error: 'invalid_quantity',
        message: 'Quantity cannot be negative'
      });
    }

    // Récupérer le panier
    const cart = await getOrCreateCart(req.user, req.headers['x-session-id']);

    if (quantity === 0) {
      cart.removeItem(productId, variant);
    } else {
      // Vérifier la disponibilité
      const product = await Product.findByPk(productId);
      if (!product || product.stock === 0) {
        return res.status(400).json({
          error: 'product_unavailable',
          message: 'Product is not available'
        });
      }

      if (quantity > product.stock) {
        return res.status(400).json({
          error: 'insufficient_stock',
          message: `Only ${product.stock} items available`
        });
      }

      cart.addItem(productId, quantity - getCurrentQuantity(cart, productId, variant), variant);
    }

    await cart.save();

    res.json({
      message: 'Cart updated successfully',
      cart: {
        id: cart.id,
        itemCount: cart.itemCount,
        total: cart.total
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'update_cart_failed',
      message: error.message
    });
  }
};

// ✅ Vider le panier
const clearCart = async (req, res) => {
  try {
    const cart = await getOrCreateCart(req.user, req.headers['x-session-id']);
    cart.items = [];
    cart.total = 0;
    cart.itemCount = 0;
    await cart.save();

    res.json({
      message: 'Cart cleared successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'clear_cart_failed',
      message: error.message
    });
  }
};

module.exports = {
  getCart,
  addToCart,
  updateCartItem,
  clearCart
};
```

## Gestion des commandes

### Contrôleur Order

```javascript
// src/controllers/orderController.js
const Order = require('../models/Order');
const OrderItem = require('../models/OrderItem');
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const { sequelize } = require('../config/database');

// ✅ Créer une commande
const createOrder = async (req, res) => {
  const transaction = await sequelize.transaction();

  try {
    const { shippingAddress, billingAddress, paymentMethod, notes } = req.body;

    // Récupérer le panier
    const cart = await Cart.findOne({
      where: req.user ? { userId: req.user.id } : { sessionId: req.headers['x-session-id'] }
    });

    if (!cart || cart.items.length === 0) {
      await transaction.rollback();
      return res.status(400).json({
        error: 'empty_cart',
        message: 'Your cart is empty'
      });
    }

    // Vérifier la disponibilité des produits
    for (const item of cart.items) {
      const product = await Product.findByPk(item.productId, { transaction });

      if (!product || product.stock < item.quantity) {
        await transaction.rollback();
        return res.status(400).json({
          error: 'insufficient_stock',
          message: `Product "${product?.name || 'Unknown'}" is out of stock`
        });
      }
    }

    // Calculer les totaux
    const subtotal = cart.total;
    const taxAmount = calculateTax(subtotal, shippingAddress);
    const shippingAmount = calculateShipping(subtotal, shippingAddress);
    const total = subtotal + taxAmount + shippingAmount;

    // Créer la commande
    const order = await Order.create({
      orderNumber: generateOrderNumber(),
      subtotal,
      taxAmount,
      shippingAmount,
      total,
      status: 'pending',
      paymentStatus: 'pending',
      paymentMethod,
      shippingAddress,
      billingAddress: billingAddress || shippingAddress,
      notes,
      userId: req.user?.id
    }, { transaction });

    // Créer les items de commande
    for (const item of cart.items) {
      await OrderItem.create({
        orderId: order.id,
        productId: item.productId,
        variant: item.variant,
        quantity: item.quantity,
        price: item.price,
        total: item.price * item.quantity
      }, { transaction });

      // Mettre à jour le stock
      await Product.decrement('stock', {
        by: item.quantity,
        where: { id: item.productId },
        transaction
      });
    }

    // Vider le panier
    await cart.destroy({ transaction });

    await transaction.commit();

    // Envoyer la confirmation par email
    await sendOrderConfirmation(order);

    res.status(201).json({
      message: 'Order created successfully',
      order: {
        id: order.id,
        orderNumber: order.orderNumber,
        total: order.total,
        status: order.status,
        estimatedDelivery: calculateEstimatedDelivery()
      }
    });
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({
      error: 'create_order_failed',
      message: error.message
    });
  }
};

// ✅ Récupérer les commandes
const getOrders = async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const whereClause = { userId: req.user.id };
    if (status) whereClause.status = status;

    const orders = await Order.findAll({
      where: whereClause,
      include: [{
        model: OrderItem,
        as: 'items',
        include: [{
          model: Product,
          as: 'product',
          attributes: ['id', 'name', 'sku']
        }]
      }],
      order: [['createdAt', 'DESC']],
      limit: Math.min(parseInt(limit), 50),
      offset
    });

    const total = await Order.count({ where: whereClause });

    res.json({
      data: orders,
      pagination: {
        current_page: parseInt(page),
        per_page: parseInt(limit),
        total,
        total_pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_orders_failed',
      message: error.message
    });
  }
};

// ✅ Annuler une commande
const cancelOrder = async (req, res) => {
  const transaction = await sequelize.transaction();

  try {
    const { id } = req.params;

    const order = await Order.findOne({
      where: { id, userId: req.user.id }
    });

    if (!order) {
      await transaction.rollback();
      return res.status(404).json({
        error: 'order_not_found',
        message: 'Order not found or does not belong to you'
      });
    }

    if (!order.canBeCancelled()) {
      await transaction.rollback();
      return res.status(400).json({
        error: 'cannot_cancel',
        message: 'This order cannot be cancelled'
      });
    }

    // Remettre les produits en stock
    const orderItems = await OrderItem.findAll({
      where: { orderId: order.id },
      transaction
    });

    for (const item of orderItems) {
      await Product.increment('stock', {
        by: item.quantity,
        where: { id: item.productId },
        transaction
      });
    }

    // Mettre à jour la commande
    await order.update({
      status: 'cancelled'
    }, { transaction });

    await transaction.commit();

    // Envoyer la notification d'annulation
    await sendOrderCancellation(order);

    res.json({
      message: 'Order cancelled successfully',
      order: {
        id: order.id,
        status: order.status
      }
    });
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({
      error: 'cancel_order_failed',
      message: error.message
    });
  }
};

module.exports = {
  createOrder,
  getOrders,
  cancelOrder
};
```

## Intégration des paiements

### Service de paiement Stripe

```javascript
// src/services/paymentService.js
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// ✅ Créer une intention de paiement
const createPaymentIntent = async (order) => {
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(order.total * 100), // Stripe utilise les centimes
      currency: order.currency.toLowerCase(),
      metadata: {
        orderId: order.id,
        userId: order.userId
      },
      automatic_payment_methods: {
        enabled: true
      }
    });

    // Mettre à jour la commande
    await order.update({
      paymentIntentId: paymentIntent.id,
      paymentStatus: 'pending'
    });

    return paymentIntent;
  } catch (error) {
    console.error('Payment intent creation failed:', error);
    throw error;
  }
};

// ✅ Confirmer le paiement
const confirmPayment = async (paymentIntentId) => {
  try {
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status === 'succeeded') {
      // Mettre à jour la commande
      const order = await Order.findOne({
        where: { paymentIntentId }
      });

      if (order) {
        await order.update({
          paymentStatus: 'paid',
          status: 'confirmed'
        });

        // Envoyer la confirmation
        await sendPaymentConfirmation(order);
      }
    }

    return paymentIntent;
  } catch (error) {
    console.error('Payment confirmation failed:', error);
    throw error;
  }
};

// ✅ Remboursement
const refundPayment = async (paymentIntentId, amount = null) => {
  try {
    const refund = await stripe.refunds.create({
      payment_intent: paymentIntentId,
      amount: amount ? Math.round(amount * 100) : undefined, // Remboursement partiel
      reason: 'requested_by_customer'
    });

    // Mettre à jour la commande
    const order = await Order.findOne({
      where: { paymentIntentId }
    });

    if (order) {
      await order.update({
        paymentStatus: 'refunded',
        status: 'refunded'
      });
    }

    return refund;
  } catch (error) {
    console.error('Refund failed:', error);
    throw error;
  }
};
```

### Webhooks Stripe

```javascript
// src/controllers/paymentController.js
const stripe = require('stripe')(process.env.STRIPE_WEBHOOK_SECRET);

// ✅ Webhook Stripe
const handleStripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    console.error('Webhook signature verification failed:', error);
    return res.status(400).send('Webhook signature verification failed');
  }

  try {
    switch (event.type) {
      case 'payment_intent.succeeded':
        await confirmPayment(event.data.object.id);
        break;

      case 'payment_intent.payment_failed':
        await handleFailedPayment(event.data.object);
        break;

      case 'payment_intent.canceled':
        await handleCancelledPayment(event.data.object);
        break;

      default:
        console.log(`Unhandled event type: ${event.type}`);
    }

    res.json({ received: true });
  } catch (error) {
    console.error('Webhook processing failed:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
};
```

## Quiz API E-Commerce

**Question 1** : Quelles sont les entités principales d'une API e-commerce ?
**Réponse** : Users, Products, Orders, Categories, Cart, Payments

**Question 2** : Comment gérer les transactions dans les commandes ?
**Réponse** : Utiliser les transactions de base de données pour garantir la cohérence

**Question 3** : Pourquoi utiliser des webhooks pour les paiements ?
**Réponse** : Pour recevoir les notifications de paiement en temps réel de manière sécurisée

## En résumé

### Fonctionnalités implémentées
- ✅ **Catalogue** de produits avec catégories
- ✅ **Panier** avec gestion de session
- ✅ **Commandes** avec transactions
- ✅ **Paiements** Stripe intégrés
- ✅ **Webhooks** pour les notifications
- ✅ **Stock** et inventaire
- ✅ **Authentification** et autorisation
- ✅ **Sécurité** complète (BOLA, validation, rate limiting)

### Architecture
```
✅ Services modulaires
✅ Base de données relationnelle
✅ Transactions distribuées
✅ Intégrations tierces (Stripe)
✅ Webhooks sécurisés
✅ Cache et performance
✅ Tests complets
✅ Documentation API
```

### Points clés
- 💰 **Paiements** : Intégration Stripe avec webhooks
- 📦 **Stock** : Gestion des inventaires en temps réel
- 🚚 **Commandes** : Workflow complet avec tracking
- 🔒 **Sécurité** : Transactions et validation
- 📊 **Performance** : Cache et pagination
- 🧪 **Tests** : Couverture complète

Cette API e-commerce démontre l'application de tous les concepts avancés que nous avons vus. Dans le prochain chapitre, nous verrons un cas avec une API de **réseau social** !

---

**Prochain chapitre** : [03-API-Social-Network](03-API-Social-Network.md)
