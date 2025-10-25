# API Réseau Social

## Introduction

Les **réseaux sociaux** sont parmi les APIs les plus complexes et intéressantes à concevoir. Une API de réseau social doit gérer des **relations sociales**, du **contenu généré par les utilisateurs**, du **temps réel**, et des **recommandations**. Dans ce chapitre, nous allons créer une API de réseau social complète qui illustre les concepts avancés comme les relations many-to-many, les flux d'activité, et les notifications push.

## Analyse des besoins

### Fonctionnalités requises

```javascript
// ✅ Fonctionnalités de l'API Social Network
const features = {
  profiles: {
    create: 'Création de profil',
    update: 'Modification du profil',
    view: 'Visualisation des profils',
    search: 'Recherche d'utilisateurs'
  },

  posts: {
    create: 'Création de posts',
    timeline: 'Fil d'actualité',
    like: 'Aimer des posts',
    comment: 'Commenter des posts',
    share: 'Partager des posts'
  },

  relationships: {
    follow: 'Suivre des utilisateurs',
    unfollow: 'Ne plus suivre',
    friends: 'Liste d'amis',
    suggestions: 'Suggestions d'amis'
  },

  messaging: {
    send: 'Envoyer des messages',
    inbox: 'Boîte de réception',
    realtime: 'Messagerie temps réel'
  },

  notifications: {
    push: 'Notifications push',
    email: 'Notifications email',
    inapp: 'Notifications in-app'
  }
};
```

### Entités du domaine

```javascript
// ✅ Modèle de données réseau social
const domainModel = {
  User: {
    id: "UUID",
    username: "string",
    email: "string",
    firstName: "string",
    lastName: "string",
    bio: "string",
    avatar: "string",
    isVerified: "boolean",
    followers: "User[]",
    following: "User[]",
    posts: "Post[]"
  },

  Post: {
    id: "UUID",
    content: "string",
    media: "Media[]",
    author: "User",
    likes: "User[]",
    comments: "Comment[]",
    shares: "Share[]",
    visibility: "enum (public, friends, private)"
  },

  Comment: {
    id: "UUID",
    content: "string",
    author: "User",
    post: "Post",
    parent: "Comment"
  },

  Message: {
    id: "UUID",
    content: "string",
    sender: "User",
    recipient: "User",
    conversation: "Conversation",
    isRead: "boolean"
  }
};
```

## Configuration du projet

### Structure du projet

```
social-api/
├── src/
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── userController.js
│   │   ├── postController.js
│   │   ├── messageController.js
│   │   └── notificationController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── rateLimit.js
│   │   └── validation.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Post.js
│   │   ├── Comment.js
│   │   ├── Message.js
│   │   └── Notification.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── users.js
│   │   ├── posts.js
│   │   ├── messages.js
│   │   └── notifications.js
│   ├── services/
│   │   ├── realtimeService.js
│   │   ├── notificationService.js
│   │   └── recommendationService.js
│   ├── config/
│   │   └── database.js
│   └── app.js
├── tests/
│   ├── auth.test.js
│   ├── posts.test.js
│   ├── relationships.test.js
│   └── realtime.test.js
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
const { createServer } = require('http');
const { Server } = require('socket.io');

const { sequelize } = require('./config/database');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const postRoutes = require('./routes/posts');
const messageRoutes = require('./routes/messages');
const notificationRoutes = require('./routes/notifications');

const app = express();
const server = createServer(app);

// ✅ Socket.IO pour le temps réel
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// ✅ Middleware de sécurité renforcée
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https:", "wss:", "ws:"],
      mediaSrc: ["'self'", "blob:", "data:"]
    }
  }
}));

app.use(cors({
  origin: [
    'https://socialapp.com',
    'https://admin.socialapp.com',
    'http://localhost:3000'
  ],
  credentials: true
}));

// ✅ Rate limiting intelligent
const createRateLimit = (max, windowMs, options = {}) => rateLimit({
  windowMs,
  max,
  message: {
    error: 'rate_limit_exceeded',
    message: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false,
  ...options
});

app.use('/api/auth', createRateLimit(10, 15 * 60 * 1000));      // 10/min pour auth
app.use('/api/posts', createRateLimit(50, 15 * 60 * 1000));     // 50/min pour posts
app.use('/api/messages', createRateLimit(100, 15 * 60 * 1000)); // 100/min pour messages

// ✅ Compression
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// ✅ Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ✅ Socket.IO middleware
app.set('socketio', io);

// ✅ Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    services: {
      database: 'healthy',
      websocket: 'healthy'
    }
  });
});

// ✅ Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/posts', postRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/notifications', notificationRoutes);

// ✅ 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'not_found',
    message: `Route ${req.originalUrl} not found`
  });
});

// ✅ WebSocket handlers
require('./services/realtimeService')(io);

// ✅ Démarrage
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Social API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`📚 API docs: http://localhost:${PORT}/api/docs`);
});

module.exports = { app, server, io };
```

## Modèles de données

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
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      len: [3, 30],
      is: /^[a-zA-Z0-9_]+$/
    }
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
  bio: {
    type: DataTypes.TEXT,
    allowNull: true,
    validate: {
      len: [0, 500]
    }
  },
  avatar: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      isUrl: true
    }
  },
  coverImage: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      isUrl: true
    }
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  isPrivate: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  lastSeenAt: {
    type: DataTypes.DATE,
    allowNull: true
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
    { unique: true, fields: ['username'] },
    { unique: true, fields: ['email'] },
    { fields: ['isVerified'] },
    { fields: ['createdAt'] }
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

User.prototype.getDisplayName = function() {
  return this.username || this.getFullName();
};

User.prototype.canViewProfile = function(viewer) {
  if (!this.isPrivate) return true;
  if (!viewer) return false;
  if (this.id === viewer.id) return true;

  // Vérifier si viewer suit this user
  return this.followers.some(follower => follower.id === viewer.id);
};

// ✅ Associations
User.associate = (models) => {
  // Relations d'abonnement (many-to-many)
  User.belongsToMany(models.User, {
    through: 'UserFollows',
    foreignKey: 'followerId',
    otherKey: 'followingId',
    as: 'following'
  });

  User.belongsToMany(models.User, {
    through: 'UserFollows',
    foreignKey: 'followingId',
    otherKey: 'followerId',
    as: 'followers'
  });

  // Posts
  User.hasMany(models.Post, {
    foreignKey: 'authorId',
    as: 'posts'
  });

  // Messages
  User.hasMany(models.Message, {
    foreignKey: 'senderId',
    as: 'sentMessages'
  });

  User.hasMany(models.Message, {
    foreignKey: 'recipientId',
    as: 'receivedMessages'
  });

  // Notifications
  User.hasMany(models.Notification, {
    foreignKey: 'recipientId',
    as: 'notifications'
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
  content: {
    type: DataTypes.TEXT,
    allowNull: false,
    validate: {
      len: [1, 2000]
    }
  },
  media: {
    type: DataTypes.JSON,
    defaultValue: [],
    validate: {
      isValidMedia(value) {
        if (!Array.isArray(value)) return false;
        return value.every(item =>
          item.type && ['image', 'video', 'audio'].includes(item.type) &&
          item.url && typeof item.url === 'string'
        );
      }
    }
  },
  visibility: {
    type: DataTypes.ENUM('public', 'friends', 'private'),
    defaultValue: 'public'
  },
  location: {
    type: DataTypes.JSON,
    allowNull: true
  },
  mentions: {
    type: DataTypes.JSON,
    defaultValue: []
  },
  hashtags: {
    type: DataTypes.JSON,
    defaultValue: []
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
    { fields: ['authorId'] },
    { fields: ['visibility'] },
    { fields: ['createdAt'] },
    { fields: ['authorId', 'createdAt'] },
    { fields: ['visibility', 'createdAt'] }
  ]
});

// ✅ Méthodes d'instance
Post.prototype.isVisibleTo = function(user) {
  if (this.visibility === 'public') return true;
  if (!user) return false;
  if (this.authorId === user.id) return true;

  switch (this.visibility) {
    case 'friends':
      // Vérifier si user suit author ou vice versa
      return this.author.followers.some(follower => follower.id === user.id) ||
             this.author.following.some(following => following.id === user.id);

    case 'private':
      return this.authorId === user.id;

    default:
      return false;
  }
};

Post.prototype.extractMentions = function() {
  const mentionRegex = /@([a-zA-Z0-9_]+)/g;
  const mentions = [];
  let match;

  while ((match = mentionRegex.exec(this.content)) !== null) {
    mentions.push(match[1]);
  }

  return [...new Set(mentions)]; // Supprimer les doublons
};

Post.prototype.extractHashtags = function() {
  const hashtagRegex = /#([a-zA-Z0-9_]+)/g;
  const hashtags = [];
  let match;

  while ((match = hashtagRegex.exec(this.content)) !== null) {
    hashtags.push(match[1]);
  }

  return [...new Set(hashtags)];
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

  Post.hasMany(models.Like, {
    foreignKey: 'postId',
    as: 'likes'
  });

  Post.hasMany(models.Share, {
    foreignKey: 'postId',
    as: 'shares'
  });
};

module.exports = Post;
```

## Gestion des relations sociales

### Contrôleur User

```javascript
// src/controllers/userController.js
const User = require('../models/User');

// ✅ Récupérer le profil utilisateur
const getUserProfile = async (req, res) => {
  try {
    const { username } = req.params;
    const requestingUser = req.user;

    const user = await User.findOne({
      where: { username },
      attributes: [
        'id', 'username', 'firstName', 'lastName', 'bio', 'avatar',
        'coverImage', 'isVerified', 'createdAt'
      ]
    });

    if (!user) {
      return res.status(404).json({
        error: 'user_not_found',
        message: 'User not found'
      });
    }

    // Vérifier la visibilité du profil
    if (!user.canViewProfile(requestingUser)) {
      return res.status(403).json({
        error: 'profile_private',
        message: 'This profile is private'
      });
    }

    // Statistiques du profil
    const stats = await getUserStats(user.id);

    res.json({
      profile: user,
      stats: {
        posts: stats.postCount,
        followers: stats.followerCount,
        following: stats.followingCount
      },
      isFollowing: requestingUser ?
        await isFollowing(requestingUser.id, user.id) : false,
      isOwnProfile: requestingUser?.id === user.id
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_profile_failed',
      message: error.message
    });
  }
};

// ✅ Suivre un utilisateur
const followUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUser = req.user;

    // Vérifier que l'utilisateur existe
    const targetUser = await User.findByPk(userId);
    if (!targetUser) {
      return res.status(404).json({
        error: 'user_not_found',
        message: 'User not found'
      });
    }

    // Vérifier qu'on ne suit pas soi-même
    if (userId === currentUser.id) {
      return res.status(400).json({
        error: 'cannot_follow_self',
        message: 'You cannot follow yourself'
      });
    }

    // Vérifier qu'on ne suit pas déjà
    const alreadyFollowing = await isFollowing(currentUser.id, userId);
    if (alreadyFollowing) {
      return res.status(400).json({
        error: 'already_following',
        message: 'You are already following this user'
      });
    }

    // Créer la relation
    await currentUser.addFollowing(targetUser);

    // Créer une notification
    await createNotification({
      type: 'follow',
      senderId: currentUser.id,
      recipientId: targetUser.id
    });

    res.status(201).json({
      message: 'User followed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'follow_user_failed',
      message: error.message
    });
  }
};

// ✅ Ne plus suivre
const unfollowUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUser = req.user;

    const targetUser = await User.findByPk(userId);
    if (!targetUser) {
      return res.status(404).json({
        error: 'user_not_found',
        message: 'User not found'
      });
    }

    // Supprimer la relation
    await currentUser.removeFollowing(targetUser);

    res.json({
      message: 'User unfollowed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'unfollow_user_failed',
      message: error.message
    });
  }
};

// ✅ Suggestions d'amis
const getSuggestions = async (req, res) => {
  try {
    const currentUser = req.user;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);

    // Utilisateurs que l'utilisateur pourrait connaître
    const suggestions = await getFriendSuggestions(currentUser.id, limit);

    res.json({
      suggestions: suggestions.map(user => ({
        id: user.id,
        username: user.username,
        fullName: user.getFullName(),
        avatar: user.avatar,
        mutualFriends: user.mutualFriendCount || 0
      }))
    });
  } catch (error) {
    res.status(500).json({
      error: 'get_suggestions_failed',
      message: error.message
    });
  }
};

module.exports = {
  getUserProfile,
  followUser,
  unfollowUser,
  getSuggestions
};
```

## Gestion du fil d'actualité

### Contrôleur Post

```javascript
// src/controllers/postController.js
const Post = require('../models/Post');
const Like = require('../models/Like');
const Comment = require('../models/Comment');

// ✅ Créer un post
const createPost = async (req, res) => {
  try {
    const { content, media, visibility, location } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({
        error: 'content_required',
        message: 'Post content is required'
      });
    }

    // Extraire les mentions et hashtags
    const mentions = extractMentions(content);
    const hashtags = extractHashtags(content);

    const post = await Post.create({
      content: content.trim(),
      media: media || [],
      visibility: visibility || 'public',
      location,
      mentions,
      hashtags,
      authorId: req.user.id
    });

    // Notifier les mentions
    if (mentions.length > 0) {
      await notifyMentions(post, mentions);
    }

    // Recharger avec les relations
    await post.reload({
      include: [{
        model: User,
        as: 'author',
        attributes: ['id', 'username', 'firstName', 'lastName', 'avatar']
      }]
    });

    res.status(201).json({
      message: 'Post created successfully',
      post: post
    });
  } catch (error) {
    res.status(500).json({
      error: 'create_post_failed',
      message: error.message
    });
  }
};

// ✅ Fil d'actualité
const getTimeline = async (req, res) => {
  try {
    const currentUser = req.user;
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Récupérer les posts des utilisateurs suivis
    const followingIds = await getFollowingIds(currentUser.id);
    followingIds.push(currentUser.id); // Inclure ses propres posts

    const posts = await Post.findAll({
      where: {
        authorId: { [require('sequelize').Op.in]: followingIds }
      },
      include: [
        {
          model: User,
          as: 'author',
          attributes: ['id', 'username', 'firstName', 'lastName', 'avatar', 'isVerified']
        },
        {
          model: Like,
          as: 'likes',
          include: [{
            model: User,
            as: 'user',
            attributes: ['id', 'username', 'avatar']
          }]
        },
        {
          model: Comment,
          as: 'comments',
          limit: 3,
          order: [['createdAt', 'DESC']],
          include: [{
            model: User,
            as: 'author',
            attributes: ['id', 'username', 'avatar']
          }]
        }
      ],
      order: [['createdAt', 'DESC']],
      limit: Math.min(parseInt(limit), 50),
      offset
    });

    // Filtrer par visibilité
    const visiblePosts = posts.filter(post => post.isVisibleTo(currentUser));

    const total = visiblePosts.length; // Simplifié

    res.json({
      posts: visiblePosts,
      pagination: {
        current_page: parseInt(page),
        per_page: parseInt(limit),
        total
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_timeline_failed',
      message: error.message
    });
  }
};

// ✅ Aimer un post
const likePost = async (req, res) => {
  try {
    const { postId } = req.params;
    const currentUser = req.user;

    // Vérifier que le post existe et est visible
    const post = await Post.findByPk(postId);
    if (!post || !post.isVisibleTo(currentUser)) {
      return res.status(404).json({
        error: 'post_not_found',
        message: 'Post not found or not visible'
      });
    }

    // Vérifier qu'on n'aime pas déjà
    const existingLike = await Like.findOne({
      where: {
        postId,
        userId: currentUser.id
      }
    });

    if (existingLike) {
      return res.status(400).json({
        error: 'already_liked',
        message: 'You have already liked this post'
      });
    }

    // Créer le like
    const like = await Like.create({
      postId,
      userId: currentUser.id
    });

    // Créer une notification
    if (post.authorId !== currentUser.id) {
      await createNotification({
        type: 'like',
        senderId: currentUser.id,
        recipientId: post.authorId,
        postId
      });
    }

    res.status(201).json({
      message: 'Post liked successfully',
      like: like
    });
  } catch (error) {
    res.status(500).json({
      error: 'like_post_failed',
      message: error.message
    });
  }
};

module.exports = {
  createPost,
  getTimeline,
  likePost
};
```

## Messagerie temps réel

### Contrôleur Message

```javascript
// src/controllers/messageController.js
const Message = require('../models/Message');
const Conversation = require('../models/Conversation');

// ✅ Envoyer un message
const sendMessage = async (req, res) => {
  try {
    const { recipientId, content, conversationId } = req.body;
    const sender = req.user;

    // Vérifier que le destinataire existe
    const recipient = await User.findByPk(recipientId);
    if (!recipient) {
      return res.status(404).json({
        error: 'recipient_not_found',
        message: 'Recipient not found'
      });
    }

    // Vérifier qu'on n'envoie pas à soi-même
    if (recipientId === sender.id) {
      return res.status(400).json({
        error: 'cannot_message_self',
        message: 'You cannot send messages to yourself'
      });
    }

    let conversation;

    if (conversationId) {
      // Utiliser une conversation existante
      conversation = await Conversation.findByPk(conversationId);
      if (!conversation || !conversation.participants.includes(sender.id) ||
          !conversation.participants.includes(recipientId)) {
        return res.status(404).json({
          error: 'conversation_not_found',
          message: 'Conversation not found'
        });
      }
    } else {
      // Créer une nouvelle conversation
      conversation = await Conversation.create({
        type: 'direct',
        participants: [sender.id, recipientId]
      });
    }

    // Créer le message
    const message = await Message.create({
      content,
      senderId: sender.id,
      recipientId,
      conversationId: conversation.id
    });

    // Recharger avec les relations
    await message.reload({
      include: [
        {
          model: User,
          as: 'sender',
          attributes: ['id', 'username', 'firstName', 'lastName', 'avatar']
        }
      ]
    });

    // Créer une notification
    await createNotification({
      type: 'message',
      senderId: sender.id,
      recipientId,
      messageId: message.id
    });

    // Émettre via Socket.IO
    const io = req.app.get('socketio');
    io.to(`user_${recipientId}`).emit('new_message', {
      message,
      conversationId: conversation.id
    });

    res.status(201).json({
      message: 'Message sent successfully',
      data: {
        message,
        conversationId: conversation.id
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'send_message_failed',
      message: error.message
    });
  }
};

// ✅ Récupérer les conversations
const getConversations = async (req, res) => {
  try {
    const currentUser = req.user;
    const { page = 1, limit = 20 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const conversations = await Conversation.findAll({
      where: {
        participants: { [require('sequelize').Op.contains]: [currentUser.id] }
      },
      include: [
        {
          model: User,
          as: 'participants',
          attributes: ['id', 'username', 'firstName', 'lastName', 'avatar'],
          where: {
            id: { [require('sequelize').Op.ne]: currentUser.id }
          }
        },
        {
          model: Message,
          as: 'lastMessage',
          limit: 1,
          order: [['createdAt', 'DESC']]
        }
      ],
      order: [
        [require('sequelize').literal('MAX(messages.created_at)'), 'DESC']
      ],
      limit: Math.min(parseInt(limit), 50),
      offset
    });

    const total = await Conversation.count({
      where: {
        participants: { [require('sequelize').Op.contains]: [currentUser.id] }
      }
    });

    res.json({
      conversations: conversations.map(conv => ({
        id: conv.id,
        participants: conv.participants,
        lastMessage: conv.lastMessage?.[0] || null,
        unreadCount: conv.unreadCount || 0,
        updatedAt: conv.updatedAt
      })),
      pagination: {
        current_page: parseInt(page),
        per_page: parseInt(limit),
        total
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'fetch_conversations_failed',
      message: error.message
    });
  }
};

module.exports = {
  sendMessage,
  getConversations
};
```

## Service temps réel

### Socket.IO

```javascript
// src/services/realtimeService.js
const socketAuth = require('../middleware/auth').authenticateToken;

module.exports = (io) => {
  // ✅ Middleware d'authentification Socket.IO
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token ||
                    socket.handshake.headers.authorization?.split(' ')[1];

      if (!token) {
        return next(new Error('Authentication required'));
      }

      // Vérifier le token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findByPk(decoded.userId);

      if (!user) {
        return next(new Error('User not found'));
      }

      socket.user = user;
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    console.log(`User ${socket.user.username} connected`);

    // ✅ Rejoindre la room personnelle
    socket.join(`user_${socket.user.id}`);

    // ✅ Rejoindre les rooms des conversations
    socket.on('join_conversation', async (conversationId) => {
      const conversation = await Conversation.findByPk(conversationId);

      if (conversation && conversation.participants.includes(socket.user.id)) {
        socket.join(`conversation_${conversationId}`);
        socket.emit('joined_conversation', { conversationId });
      }
    });

    // ✅ Envoyer un message
    socket.on('send_message', async (data) => {
      try {
        const { recipientId, content, conversationId } = data;

        // Créer le message (logique dupliquée pour le temps réel)
        const message = await Message.create({
          content,
          senderId: socket.user.id,
          recipientId,
          conversationId: conversationId || null
        });

        // Émettre vers le destinataire
        socket.to(`user_${recipientId}`).emit('new_message', {
          message: {
            id: message.id,
            content: message.content,
            senderId: socket.user.id,
            createdAt: message.createdAt
          },
          conversationId
        });

        // Confirmer à l'expéditeur
        socket.emit('message_sent', {
          messageId: message.id,
          timestamp: message.createdAt
        });
      } catch (error) {
        socket.emit('error', {
          type: 'send_message_failed',
          message: error.message
        });
      }
    });

    // ✅ Marquer les messages comme lus
    socket.on('mark_messages_read', async (conversationId) => {
      try {
        await Message.update(
          { isRead: true },
          {
            where: {
              conversationId,
              recipientId: socket.user.id,
              isRead: false
            }
          }
        );

        // Notifier les autres participants
        socket.to(`conversation_${conversationId}`).emit('messages_read', {
          userId: socket.user.id,
          conversationId
        });
      } catch (error) {
        socket.emit('error', {
          type: 'mark_read_failed',
          message: error.message
        });
      }
    });

    // ✅ Gestion de la déconnexion
    socket.on('disconnect', () => {
      console.log(`User ${socket.user.username} disconnected`);

      // Mettre à jour lastSeenAt
      socket.user.update({ lastSeenAt: new Date() });

      // Quitter toutes les rooms
      socket.leaveAll();
    });

    // ✅ Gestion des erreurs
    socket.on('error', (error) => {
      console.error('Socket error:', error);
      socket.disconnect();
    });
  });
};
```

## Tests complets

### Tests des relations sociales

```javascript
// tests/relationships.test.js
const request = require('supertest');
const app = require('../src/app');
const { User } = require('../src/models');

describe('Social Relationships', () => {
  let user1, user2, token1, token2;

  beforeEach(async () => {
    user1 = await createTestUser({
      username: 'user1',
      email: 'user1@example.com'
    });

    user2 = await createTestUser({
      username: 'user2',
      email: 'user2@example.com'
    });

    token1 = generateJWT(user1);
    token2 = generateJWT(user2);
  });

  describe('POST /api/users/:username/follow', () => {
    test('should follow another user', async () => {
      const response = await request(app)
        .post(`/api/users/${user2.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(201);

      expect(response.body).toHaveProperty('message', 'User followed successfully');
    });

    test('should prevent following yourself', async () => {
      const response = await request(app)
        .post(`/api/users/${user1.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'cannot_follow_self');
    });

    test('should prevent duplicate follows', async () => {
      // Suivre une première fois
      await request(app)
        .post(`/api/users/${user2.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(201);

      // Tenter de suivre à nouveau
      const response = await request(app)
        .post(`/api/users/${user2.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'already_following');
    });
  });

  describe('DELETE /api/users/:username/follow', () => {
    test('should unfollow a user', async () => {
      // D'abord suivre
      await request(app)
        .post(`/api/users/${user2.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(201);

      // Puis ne plus suivre
      const response = await request(app)
        .delete(`/api/users/${user2.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body).toHaveProperty('message', 'User unfollowed successfully');
    });
  });

  describe('Profile Visibility', () => {
    test('should show public profiles to everyone', async () => {
      const response = await request(app)
        .get(`/api/users/${user2.username}`)
        .expect(200);

      expect(response.body).toHaveProperty('profile');
      expect(response.body).toHaveProperty('isFollowing', false);
    });

    test('should hide private profiles from non-followers', async () => {
      // Rendre le profil privé
      await user2.update({ isPrivate: true });

      const response = await request(app)
        .get(`/api/users/${user2.username}`)
        .expect(403);

      expect(response.body).toHaveProperty('error', 'profile_private');
    });

    test('should show private profiles to followers', async () => {
      // Profil privé
      await user2.update({ isPrivate: true });

      // Suivre l'utilisateur
      await request(app)
        .post(`/api/users/${user2.username}/follow`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(201);

      // Accéder au profil
      const response = await request(app)
        .get(`/api/users/${user2.username}`)
        .set('Authorization', `Bearer ${token1}`)
        .expect(200);

      expect(response.body).toHaveProperty('profile');
    });
  });
});
```

## Quiz API Réseau Social

**Question 1** : Quelles sont les entités principales d'un réseau social ?
**Réponse** : Users, Posts, Comments, Messages, Notifications, Relations

**Question 2** : Comment implémenter la visibilité des posts ?
**Réponse** : Avec un champ visibility et une méthode isVisibleTo()

**Question 3** : Pourquoi utiliser Socket.IO ?
**Réponse** : Pour les fonctionnalités temps réel (messagerie, notifications)

## En résumé

### Fonctionnalités implémentées
- ✅ **Profils** avec visibilité (public/privé)
- ✅ **Relations sociales** (suivre/ne plus suivre)
- ✅ **Fil d'actualité** personnalisé
- ✅ **Posts** avec mentions et hashtags
- ✅ **Likes** et **commentaires**
- ✅ **Messagerie** temps réel
- ✅ **Notifications** push et in-app
- ✅ **Suggestions** d'amis

### Architecture temps réel
```
✅ Socket.IO pour WebSockets
✅ Rooms par utilisateur/conversation
✅ Middleware d'authentification
✅ Gestion des connexions
✅ Notifications push
```

### Points clés
- 👥 **Relations sociales** : Many-to-many complexes
- 🔒 **Visibilité** : Contrôle d'accès granulaire
- 💬 **Temps réel** : Socket.IO pour la messagerie
- 🔔 **Notifications** : Système d'alertes
- 📱 **Mobile-friendly** : API optimisée

Cette API de réseau social illustre l'application de tous les concepts avancés pour une plateforme sociale moderne !

---

**Conclusion du livre** : Vous avez maintenant une compréhension complète des APIs REST, de leur conception à leur implémentation en production !
