# Documentation OpenAPI

## Introduction

Une API sans documentation est comme une bibliothèque sans catalogue : inutilisable ! La **documentation** est l'interface entre votre API et vos développeurs. **OpenAPI** (anciennement Swagger) est le standard le plus populaire pour documenter les APIs REST. Dans ce chapitre, nous allons apprendre à créer une documentation complète, interactive et automatiquement générée pour votre API.

## Qu'est-ce qu'OpenAPI ?

### Définition

**OpenAPI** est une spécification standard pour décrire les APIs REST. Elle permet de :

- ✅ Définir les endpoints et leurs paramètres
- ✅ Documenter les formats de requête/réponse
- ✅ Générer du code client automatiquement
- ✅ Tester l'API interactivement
- ✅ Valider la conformité

```yaml
# Exemple de spécification OpenAPI simple
openapi: 3.0.0
info:
  title: Blog API
  version: 1.0.0
  description: API pour gérer un blog

paths:
  /api/users:
    get:
      summary: Récupérer la liste des utilisateurs
      responses:
        '200':
          description: Succès
          content:
            application/json:
              schema:
                type: object
                properties:
                  users:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'
```

## Structure d'un document OpenAPI

### 1. Métadonnées (Info)

```yaml
openapi: 3.0.0
info:
  title: E-Commerce API
  description: |
    API REST pour une plateforme e-commerce

    ## Fonctionnalités
    - Gestion des utilisateurs
    - Catalogue produits
    - Gestion des commandes
    - Paiements intégrés
  version: 1.0.0
  contact:
    name: API Support
    url: https://support.example.com
    email: api@example.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT
  termsOfService: https://example.com/terms
```

### 2. Serveurs (Servers)

```yaml
servers:
  - url: https://api.example.com/v1
    description: Production server
  - url: https://staging-api.example.com/v1
    description: Staging server
  - url: http://localhost:3000/api/v1
    description: Development server
```

### 3. Sécurité (Security)

```yaml
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    apiKey:
      type: apiKey
      in: header
      name: X-API-Key
    basicAuth:
      type: http
      scheme: basic

security:
  - bearerAuth: []
  - apiKey: []
```

### 4. Chemins (Paths)

```yaml
paths:
  /api/users:
    get:
      summary: Liste des utilisateurs
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
        - name: offset
          in: query
          schema:
            type: integer
            minimum: 0
      responses:
        '200':
          description: Liste des utilisateurs
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UsersResponse'
```

## Définition des schémas

### Schémas de données

```yaml
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
          description: Identifiant unique de l'utilisateur
        email:
          type: string
          format: email
          description: Adresse email de l'utilisateur
        firstName:
          type: string
          description: Prénom de l'utilisateur
        lastName:
          type: string
          description: Nom de famille de l'utilisateur
        createdAt:
          type: string
          format: date-time
          description: Date de création du compte
        role:
          type: string
          enum: [customer, admin, vendor]
          description: Rôle de l'utilisateur
      required:
        - id
        - email
        - createdAt

    UsersResponse:
      type: object
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/User'
        pagination:
          $ref: '#/components/schemas/Pagination'
        _links:
          $ref: '#/components/schemas/Links'

    Pagination:
      type: object
      properties:
        page:
          type: integer
          description: Page actuelle
        per_page:
          type: integer
          description: Nombre d'éléments par page
        total:
          type: integer
          description: Nombre total d'éléments
        total_pages:
          type: integer
          description: Nombre total de pages
```

### Réutilisation des schémas

```yaml
components:
  schemas:
    # Schéma de base
    BaseEntity:
      type: object
      properties:
        id:
          type: string
          format: uuid
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time

    # Extension du schéma de base
    User:
      allOf:
        - $ref: '#/components/schemas/BaseEntity'
        - type: object
          properties:
            email:
              type: string
              format: email
            firstName:
              type: string
            lastName:
              type: string
            role:
              type: string
              enum: [customer, admin]

    Product:
      allOf:
        - $ref: '#/components/schemas/BaseEntity'
        - type: object
          properties:
            name:
              type: string
            price:
              type: number
              format: float
            category:
              type: string
```

## Documentation des endpoints

### GET endpoints

```yaml
paths:
  /api/users/{id}:
    get:
      summary: Récupérer un utilisateur par ID
      description: |
        Récupère les informations détaillées d'un utilisateur spécifique.

        ## Permissions
        - Authentification requise
        - L'utilisateur peut voir son propre profil
        - Les admins peuvent voir tous les profils
      parameters:
        - name: id
          in: path
          required: true
          description: Identifiant unique de l'utilisateur
          schema:
            type: string
            format: uuid
        - name: include
          in: query
          description: Relations à inclure
          schema:
            type: string
            enum: [posts, orders, profile]
      responses:
        '200':
          description: Utilisateur trouvé
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    $ref: '#/components/schemas/User'
                  _links:
                    $ref: '#/components/schemas/UserLinks'
        '404':
          description: Utilisateur non trouvé
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '401':
          description: Non authentifié
        '403':
          description: Accès refusé
```

### POST endpoints

```yaml
paths:
  /api/users:
    post:
      summary: Créer un nouvel utilisateur
      description: |
        Crée un nouveau compte utilisateur.

        ## Validation
        - Email doit être unique
        - Mot de passe minimum 8 caractères
        - Tous les champs requis doivent être fournis
      requestBody:
        required: true
        description: Données de l'utilisateur à créer
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  description: Adresse email unique
                password:
                  type: string
                  format: password
                  minLength: 8
                  description: Mot de passe sécurisé
                firstName:
                  type: string
                  description: Prénom
                lastName:
                  type: string
                  description: Nom de famille
              required:
                - email
                - password
                - firstName
                - lastName
            example:
              email: john.doe@example.com
              password: securePassword123
              firstName: John
              lastName: Doe
      responses:
        '201':
          description: Utilisateur créé avec succès
          headers:
            Location:
              description: URL du nouvel utilisateur
              schema:
                type: string
                format: uri
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    $ref: '#/components/schemas/User'
                  message:
                    type: string
                    example: "Utilisateur créé avec succès"
        '400':
          description: Données invalides
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ValidationError'
        '409':
          description: Email déjà utilisé
```

## Gestion des erreurs

### Schémas d'erreur

```yaml
components:
  schemas:
    Error:
      type: object
      properties:
        error:
          type: object
          properties:
            code:
              type: string
              description: Code d'erreur unique
              example: "USER_NOT_FOUND"
            message:
              type: string
              description: Message d'erreur lisible
              example: "Aucun utilisateur trouvé avec cet ID"
            details:
              type: object
              description: Détails supplémentaires de l'erreur
              additionalProperties: true
        _links:
          $ref: '#/components/schemas/ErrorLinks'

    ValidationError:
      allOf:
        - $ref: '#/components/schemas/Error'
        - type: object
          properties:
            error:
              type: object
              properties:
                details:
                  type: array
                  items:
                    type: object
                    properties:
                      field:
                        type: string
                        description: Champ en erreur
                      message:
                        type: string
                        description: Message d'erreur pour ce champ
                      code:
                        type: string
                        description: Code de validation
                  example:
                    - field: email
                      message: "Format d'email invalide"
                      code: "INVALID_EMAIL"
                    - field: password
                      message: "Mot de passe trop court"
                      code: "PASSWORD_TOO_SHORT"
```

### Codes d'erreur dans les réponses

```yaml
paths:
  /api/users/{id}:
    get:
      responses:
        '200':
          description: Utilisateur trouvé
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          description: Requête invalide
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
              example:
                error:
                  code: "INVALID_ID"
                  message: "L'ID fourni n'est pas un UUID valide"
        '401':
          description: Non authentifié
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
              example:
                error:
                  code: "AUTHENTICATION_REQUIRED"
                  message: "Authentification requise pour accéder à cette ressource"
        '404':
          description: Utilisateur non trouvé
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
              example:
                error:
                  code: "USER_NOT_FOUND"
                  message: "Aucun utilisateur trouvé avec l'ID spécifié"
        '500':
          description: Erreur serveur
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
              example:
                error:
                  code: "INTERNAL_SERVER_ERROR"
                  message: "Une erreur interne s'est produite"
```

## Outils OpenAPI

### 1. Swagger Editor

```yaml
# Édition en ligne
# https://editor.swagger.io/
openapi: 3.0.0
info:
  title: My API
  version: 1.0.0
```

### 2. Swagger UI

```html
<!-- Intégration HTML -->
<!DOCTYPE html>
<html>
<head>
  <title>API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
  <script>
    const ui = SwaggerUIBundle({
      url: '/api/docs/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.presets.standalone
      ]
    });
  </script>
</body>
</html>
```

### 3. Génération automatique avec Express

```javascript
const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();

// Configuration OpenAPI
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Blog API',
      version: '1.0.0',
      description: 'API pour gérer un blog',
      contact: {
        name: 'API Support',
        email: 'api@example.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000/api/v1',
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
  apis: ['./routes/*.js', './models/*.js'] // fichiers à analyser
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Route de documentation
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Servir la spec OpenAPI
app.get('/api/openapi.json', (req, res) => {
  res.json(swaggerSpec);
});
```

### 4. Annotations dans le code

```javascript
// routes/users.js
const express = require('express');
const router = express.Router();

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Récupérer la liste des utilisateurs
 *     tags: [Users]
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           minimum: 0
 *     responses:
 *       200:
 *         description: Liste des utilisateurs
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/User'
 */
router.get('/users', getUsers);

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Récupérer un utilisateur par ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Utilisateur trouvé
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         description: Utilisateur non trouvé
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get('/users/:id', getUserById);
```

## Exemple complet d'API documentée

### Spécification OpenAPI complète

```yaml
openapi: 3.0.0
info:
  title: Blog API
  description: |
    API REST complète pour une plateforme de blog

    ## Fonctionnalités
    - Gestion des utilisateurs et authentification
    - Création et gestion des articles
    - Système de commentaires
    - Catégorisation et tags
    - Recherche et filtrage
  version: 1.0.0
  contact:
    name: API Support
    url: https://support.example.com
    email: api@example.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: https://api.example.com/v1
    description: Production server
  - url: https://staging-api.example.com/v1
    description: Staging server
  - url: http://localhost:3000/api/v1
    description: Development server

security:
  - bearerAuth: []

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
          description: Identifiant unique
        email:
          type: string
          format: email
          description: Adresse email
        firstName:
          type: string
          description: Prénom
        lastName:
          type: string
          description: Nom de famille
        role:
          type: string
          enum: [admin, author, reader]
          description: Rôle utilisateur
        createdAt:
          type: string
          format: date-time
          description: Date de création
        updatedAt:
          type: string
          format: date-time
          description: Date de modification
      required:
        - id
        - email
        - createdAt

    Post:
      type: object
      properties:
        id:
          type: string
          format: uuid
        title:
          type: string
          description: Titre de l'article
        content:
          type: string
          description: Contenu de l'article
        published:
          type: boolean
          description: Statut de publication
        publishedAt:
          type: string
          format: date-time
          description: Date de publication
        authorId:
          type: string
          format: uuid
          description: ID de l'auteur
        categoryId:
          type: string
          format: uuid
          description: ID de la catégorie
        author:
          $ref: '#/components/schemas/User'
        category:
          $ref: '#/components/schemas/Category'
        tags:
          type: array
          items:
            $ref: '#/components/schemas/Tag'
        comments:
          type: array
          items:
            $ref: '#/components/schemas/Comment'
      required:
        - id
        - title
        - content
        - authorId

    Error:
      type: object
      properties:
        error:
          type: object
          properties:
            code:
              type: string
              description: Code d'erreur
            message:
              type: string
              description: Message d'erreur
            details:
              type: object
              additionalProperties: true
              description: Détails supplémentaires

paths:
  /api/users:
    get:
      summary: Liste des utilisateurs
      description: |
        Récupère la liste paginée des utilisateurs.

        ## Permissions
        - Les admins voient tous les utilisateurs
        - Les utilisateurs voient leur profil uniquement
      security:
        - bearerAuth: []
      parameters:
        - name: page
          in: query
          description: Numéro de page
          schema:
            type: integer
            minimum: 1
            default: 1
        - name: limit
          in: query
          description: Nombre d'éléments par page
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 10
        - name: search
          in: query
          description: Recherche textuelle
          schema:
            type: string
        - name: role
          in: query
          description: Filtre par rôle
          schema:
            type: string
            enum: [admin, author, reader]
      responses:
        '200':
          description: Liste des utilisateurs
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'
                  pagination:
                    type: object
                    properties:
                      page:
                        type: integer
                      limit:
                        type: integer
                      total:
                        type: integer
                      total_pages:
                        type: integer
        '401':
          description: Non authentifié
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '403':
          description: Accès refusé

    post:
      summary: Créer un utilisateur
      description: |
        Crée un nouveau compte utilisateur.

        ## Validation
        - Email doit être unique
        - Mot de passe minimum 8 caractères
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  description: Adresse email unique
                password:
                  type: string
                  format: password
                  minLength: 8
                  description: Mot de passe sécurisé
                firstName:
                  type: string
                  description: Prénom
                lastName:
                  type: string
                  description: Nom de famille
              required:
                - email
                - password
                - firstName
                - lastName
            example:
              email: john.doe@example.com
              password: securePassword123
              firstName: John
              lastName: Doe
      responses:
        '201':
          description: Utilisateur créé
          headers:
            Location:
              description: URL du nouvel utilisateur
              schema:
                type: string
                format: uri
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    $ref: '#/components/schemas/User'
                  message:
                    type: string
                    example: "Utilisateur créé avec succès"
        '400':
          description: Données invalides
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '409':
          description: Email déjà utilisé
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
```

### Interface interactive

```html
<!-- Swagger UI intégré -->
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: '/api/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true,
                requestInterceptor: function(request) {
                    // Ajouter automatiquement le token d'auth
                    const token = localStorage.getItem('auth_token');
                    if (token) {
                        request.headers.Authorization = 'Bearer ' + token;
                    }
                    return request;
                }
            });
        };
    </script>
</body>
</html>
```

## Intégration avec les tests

### Tests automatisés

```javascript
// tests/openapi.test.js
const request = require('supertest');
const app = require('../app');
const swaggerSpec = require('../openapi.json');

describe('OpenAPI Compliance', () => {
  test('should match OpenAPI specification', async () => {
    // Vérifier que tous les endpoints documentés existent
    for (const path in swaggerSpec.paths) {
      for (const method in swaggerSpec.paths[path]) {
        const response = await request(app)
          [method.toLowerCase()](path)
          .expect((res) => {
            // Vérifier que la réponse correspond au schéma
            expect(res.status).toBeLessThan(500);
          });
      }
    }
  });
});
```

## Bonnes pratiques de documentation

### 1. Descriptions claires et complètes

```yaml
# ✅ Descriptions détaillées
get:
  summary: Récupérer un utilisateur
  description: |
    Récupère les informations complètes d'un utilisateur spécifique.

    ## Permissions requises
    - Authentification JWT obligatoire
    - L'utilisateur peut accéder à son propre profil
    - Les administrateurs peuvent accéder à tous les profils

    ## Paramètres optionnels
    - `include`: inclure les relations (posts, comments)
    - `fields`: sélectionner uniquement certains champs

    ## Exemples d'usage
    ```bash
    # Profil de base
    GET /api/users/123

    # Avec relations
    GET /api/users/123?include=posts,comments

    # Champs spécifiques
    GET /api/users/123?fields=id,email,firstName
    ```
```

### 2. Exemples concrets

```yaml
responses:
  '200':
    description: Utilisateur trouvé
    content:
      application/json:
        schema:
          $ref: '#/components/schemas/User'
        examples:
          basic:
            summary: Profil utilisateur de base
            value:
              id: "550e8400-e29b-41d4-a716-446655440000"
              email: "john.doe@example.com"
              firstName: "John"
              lastName: "Doe"
              role: "author"
              createdAt: "2023-10-25T10:30:00Z"
          with_relations:
            summary: Profil avec relations
            value:
              id: "550e8400-e29b-41d4-a716-446655440000"
              email: "john.doe@example.com"
              firstName: "John"
              lastName: "Doe"
              role: "author"
              createdAt: "2023-10-25T10:30:00Z"
              posts:
                - id: "123"
                  title: "Mon premier article"
                  published: true
              comments:
                - id: "456"
                  content: "Super article !"
```

### 3. Tests interactifs

```yaml
# Activer les tests dans Swagger UI
servers:
  - url: https://api.example.com/v1
    description: Production

# Dans Swagger UI, les développeurs peuvent tester directement
# - Authentification
# - Envoi de requêtes
# - Visualisation des réponses
```

## Quiz de la documentation OpenAPI

**Question 1** : Quels sont les 3 composants principaux d'OpenAPI ?
**Réponse** : Info (métadonnées), Paths (endpoints), Components (schémas)

**Question 2** : Comment documenter une erreur 404 ?
**Réponse** : Dans la section responses avec le code 404 et le schéma d'erreur

**Question 3** : Pourquoi utiliser des exemples dans la documentation ?
**Réponse** : Pour montrer aux développeurs le format exact des requêtes/réponses

## En résumé

### Structure OpenAPI
1. **Info** : Métadonnées de l'API
2. **Servers** : URLs des serveurs
3. **Security** : Schémas d'authentification
4. **Paths** : Endpoints et paramètres
5. **Components** : Schémas réutilisables

### Bonnes pratiques
- ✅ **Descriptions** détaillées et claires
- ✅ **Exemples** concrets de requêtes/réponses
- ✅ **Gestion** complète des erreurs
- ✅ **Tests** interactifs activés
- ✅ **Maintenance** de la documentation

### Outils recommandés
- 🔧 **Swagger Editor** : Édition en ligne
- 📖 **Swagger UI** : Interface interactive
- 🤖 **swagger-jsdoc** : Génération depuis le code
- ✅ **Tests automatisés** : Validation de conformité

### Exemple d'URL documentée
```yaml
# Documentation complète d'un endpoint
get:
  summary: Récupérer un utilisateur
  description: Récupère les informations d'un utilisateur
  parameters:
    - name: id
      in: path
      required: true
      schema:
        type: string
        format: uuid
  responses:
    '200':
      description: Utilisateur trouvé
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/User'
    '404':
      description: Utilisateur non trouvé
```

Félicitations ! Vous avez maintenant toutes les bases pour concevoir une API REST complète. Dans les prochaines sections, nous explorerons la **sécurité**, la **mise en œuvre** et les **performances** !

---

**Prochain chapitre** : [01-Auth-et-Identité](04-Sécurité-des-APIs/01-Auth-et-Identité.md)
