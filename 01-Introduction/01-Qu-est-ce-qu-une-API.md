# Qu'est-ce qu'une API ?

## Introduction

Bienvenue dans ce premier chapitre ! Avant de plonger dans les concepts complexes du REST, il est essentiel de comprendre ce qu'est une API et pourquoi elle est si importante dans le développement moderne.

> **API** est l'acronyme d'**Application Programming Interface** (Interface de Programmation d'Application).

## Définition d'une API

Une API est un ensemble de règles et de protocoles qui permet à différentes applications de communiquer entre elles. Elle définit les méthodes et les formats de données que les applications peuvent utiliser pour demander et échanger des informations.

### Analogy du restaurant

Imaginez que vous êtes dans un restaurant. La **carte** du restaurant représente l'API - elle liste tous les plats disponibles avec leurs descriptions et prix. Le **serveur** agit comme l'implémentation de l'API - il prend votre commande et vous apporte ce que vous avez demandé. Les **cuisiniers** sont les serveurs backend qui préparent réellement les plats.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │      API        │    │    Serveurs     │
│     Client      │───▶│   (Serveur)     │───▶│    Backend      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Types d'APIs

### 1. APIs Web
- **REST APIs** : Utilisent les verbes HTTP (GET, POST, PUT, DELETE)
- **SOAP APIs** : Protocole XML-based plus ancien
- **GraphQL APIs** : Langage de requête pour APIs

### 2. APIs de Système d'exploitation
- **APIs Windows** : Win32 API, .NET API
- **APIs Unix/Linux** : POSIX API, System calls

### 3. APIs de Bibliothèques
- **APIs JavaScript** : DOM API, Canvas API
- **APIs Python** : Requests, Flask, Django

## Pourquoi les APIs sont-elles importantes ?

### 1. **Réutilisabilité**
```javascript
// Une API permet de réutiliser du code
const apiResponse = await fetch('/api/users/123');
const userData = await apiResponse.json();
```

### 2. **Séparation des préoccupations**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Frontend   │    │     API     │    │  Database   │
│   (React)   │◀──▶│   (REST)    │◀──▶│ (PostgreSQL)│
└─────────────┘    └─────────────┘    └─────────────┘
```

### 3. **Évolutivité**
Les APIs permettent aux équipes de développer indépendamment :
- Équipe Frontend ↔ Équipe Backend
- Applications mobiles ↔ Services web

## Exemple concret d'API

### API REST simple
```bash
# Récupérer un utilisateur
GET /api/users/123

# Créer un nouvel utilisateur
POST /api/users
Content-Type: application/json
{
  "name": "John Doe",
  "email": "john@example.com"
}

# Mettre à jour un utilisateur
PUT /api/users/123
{
  "name": "Jane Doe"
}

# Supprimer un utilisateur
DELETE /api/users/123
```

### Réponse JSON typique
```json
{
  "id": 123,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2023-10-25T10:30:00Z"
}
```

## Les APIs dans la vie quotidienne

### 1. **Applications mobiles**
- Uber utilise des APIs pour localiser les chauffeurs
- Instagram API pour partager du contenu
- PayPal API pour les paiements

### 2. **Internet des objets (IoT)**
```javascript
// API pour un thermostat connecté
GET /api/thermostat/temperature    // 22°C
POST /api/thermostat/set-target
{ "temperature": 24 }
```

### 3. **Services Cloud**
- AWS API Gateway
- Google Maps API
- Stripe Payment API

## Concepts clés à retenir

### 1. **Endpoints**
Les URLs spécifiques où l'API est accessible :
- `/api/users` - Gestion des utilisateurs
- `/api/products` - Gestion des produits
- `/api/orders` - Gestion des commandes

### 2. **Méthodes HTTP**
- **GET** : Récupérer des données
- **POST** : Créer de nouvelles ressources
- **PUT** : Mettre à jour des ressources
- **DELETE** : Supprimer des ressources

### 3. **Formats de données**
- **JSON** : Le plus populaire (JavaScript Object Notation)
- **XML** : Plus ancien mais toujours utilisé
- **YAML** : Plus lisible pour la configuration

## Quiz rapide

**Question** : Quelle méthode HTTP utiliseriez-vous pour :
1. Récupérer la liste des utilisateurs ? **GET**
2. Créer un nouveau produit ? **POST**
3. Mettre à jour le prix d'un produit ? **PUT**
4. Supprimer un commentaire ? **DELETE**

## En résumé

Une API est comme un contrat entre applications. Elle définit :
- ✅ **Comment** communiquer (protocoles)
- ✅ **Quelles** données échanger (formats)
- ✅ **Quelles** actions sont possibles (méthodes)

Dans le prochain chapitre, nous explorerons l'histoire fascinante des APIs et comment nous en sommes arrivés aux standards actuels !

---

**Prochain chapitre** : [02-Histoire-des-APIs](02-Histoire-des-APIs.md)
