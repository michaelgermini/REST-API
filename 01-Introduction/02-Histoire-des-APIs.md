# Histoire des APIs

## Introduction

Les APIs n'ont pas toujours existé sous la forme que nous connaissons aujourd'hui. Leur évolution est intimement liée au développement du web et des technologies de communication. Dans ce chapitre, nous allons voyager dans le temps pour comprendre comment les APIs sont devenues l'épine dorsale de l'Internet moderne.

## Les origines : Années 1960-1970

### L'ère des mainframes
Au début de l'informatique, les systèmes étaient **monolithiques**. Chaque ordinateur était une île isolée :

```
┌─────────────────────────────────────┐
│           Mainframe IBM             │
│  ┌─────────────────────────────────┐ │
│  │         Application             │ │
│  │      (Tout en un)              │ │
│  └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### L'apparition des systèmes modulaires
Dans les années 1960, l'idée de **modularité** émerge :
- **1968** : Douglas McIlroy propose les "composants logiciels"
- **1969** : ARPANET, précurseur d'Internet, est créé
- **1970s** : Développement d'Unix avec sa philosophie modulaire

## Les années 1980-1990 : L'essor du réseau

### Le protocole TCP/IP
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Application │    │ Application │    │ Application │
│    Client   │◀──▶│   Serveur   │    │   Serveur   │
└─────────────┘    └─────────────┘    └─────────────┘
```

### L'API de Berkeley Sockets (1983)
```c
// Exemple d'API socket en C
int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
send(socket_fd, "Hello", 5, 0);
```

### Le World Wide Web (1989-1991)
**Tim Berners-Lee** invente le Web au CERN :
- **HTML** pour le contenu
- **HTTP** pour la communication
- **URLs** pour l'adressage

## Les années 1990 : SOAP et les Web Services

### SOAP : Simple Object Access Protocol (1998)
```xml
<!-- Exemple de requête SOAP -->
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUserRequest>
      <userId>123</userId>
    </getUserRequest>
  </soap:Body>
</soap:Envelope>
```

### Problèmes de SOAP
- **Complexité** : XML verbeux
- **Performance** : Overhead important
- **Couplage** : Contrats WSDL rigides

## Les années 2000 : La révolution REST

### Roy Fielding et sa thèse (2000)
**Roy Fielding**, co-auteur de HTTP/1.1, définit REST dans sa thèse de doctorat :

> "REST is an architectural style for distributed hypermedia systems"

### Les principes REST (2000-2005)
1. **Ressources** identifiées par des URLs
2. **Interface uniforme** avec les verbes HTTP
3. **Stateless** (sans état)
4. **Cacheable**
5. **Architecture en couches**

### JSON devient populaire (2001-2006)
```json
// Plus simple que XML !
{
  "user": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

## 2006-2010 : L'explosion des APIs Web

### L'API Twitter (2006)
```bash
# Première API Twitter
GET /statuses/public_timeline.xml
```

### SalesForce API et le modèle SaaS
- **2000** : SalesForce lance son API
- **2002** : Amazon Web Services (AWS)
- **2004** : Flickr API avec REST

### eBay et PayPal APIs
```javascript
// API PayPal (2004)
const paypalResponse = await fetch('https://api.paypal.com/v1/payments', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + accessToken
  },
  body: JSON.stringify(paymentData)
});
```

## 2010-2015 : L'ère des APIs mobiles

### L'essor des smartphones
```
┌─────────────┐    ┌─────────────┐
│ Application │    │     API     │
│   Mobile    │◀──▶│   RESTful   │
│ (iOS/Android)   │    │   Server    │
└─────────────┘    └─────────────┘
```

### APIs de géolocalisation
```javascript
// Google Maps API (2010)
navigator.geolocation.getCurrentPosition(function(position) {
  const lat = position.coords.latitude;
  const lng = position.coords.longitude;
  // Afficher la carte
});
```

### OAuth 2.0 (2012)
```javascript
// Flux OAuth pour l'authentification
GET /oauth/authorize?client_id=123&redirect_uri=https://app.com/callback
POST /oauth/token
Authorization: Basic <base64(client_id:client_secret)>
```

## 2015-2020 : Microservices et API-First

### Architecture microservices
```
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│ Service │  │ Service │  │ Service │  │ Service │
│ Users   │◀▶│ Orders  │◀▶│Payment  │◀▶│Shipping │
└─────────┘  └─────────┘  └─────────┘  └─────────┘
```

### OpenAPI Specification (2015)
```yaml
# Specification OpenAPI 3.0
openapi: 3.0.0
info:
  title: User API
  version: 1.0.0
paths:
  /users:
    get:
      summary: Get all users
      responses:
        '200':
          description: Success
```

### GraphQL (2015)
```graphql
# Requête GraphQL
query {
  user(id: "123") {
    name
    email
    posts {
      title
      content
    }
  }
}
```

## 2020-Aujourd'hui : L'ère des APIs modernes

### Serverless et APIs
```javascript
// AWS Lambda + API Gateway
exports.handler = async (event) => {
  const userId = event.pathParameters.id;
  // Logique métier
  return {
    statusCode: 200,
    body: JSON.stringify(user)
  };
};
```

### API as a Product
- **Design-First** : Concevoir l'API avant le code
- **Developer Experience** : Documentation interactive
- **Monétisation** : APIs payantes (Stripe, Twilio)

### Tendances actuelles
1. **AsyncAPI** pour les APIs temps réel
2. **Webhooks** pour les notifications
3. **API Versioning** automatique
4. **API Security** (OAuth 2.1, JWT)

## Ligne du temps récapitulative

```
1960s    │ Modularité, Unix
1970s    │ ARPANET, TCP/IP
1980s    │ Sockets API
1990s    │ HTTP, SOAP
2000s    │ REST, JSON, AWS
2010s    │ Mobile, OAuth, Microservices
2020s    │ Serverless, GraphQL, API-First
```

## Personnages clés

### 1. **Tim Berners-Lee** (1955-)
- Inventeur du World Wide Web
- Créateur de HTTP et HTML
- "Father of the Web"

### 2. **Roy Fielding** (1965-)
- Co-auteur de HTTP/1.1
- Inventeur du style architectural REST
- Auteur de la thèse "Architectural Styles"

### 3. **Douglas Crockford** (1955-)
- "Father of JSON"
- Développeur chez Yahoo!
- Auteur de "JavaScript: The Good Parts"

## Leçons de l'histoire

### 1. **Simplification progressive**
- **SOAP** → **REST** : Moins de complexité
- **XML** → **JSON** : Moins de verbosité
- **Monolithique** → **Microservices** : Plus de modularité

### 2. **Standardisation**
- **HTTP** comme protocole universel
- **JSON** comme format de données standard
- **OAuth** pour l'authentification

### 3. **Évolution continue**
Les APIs évoluent avec les besoins :
- **Performance** : JSON vs XML
- **Sécurité** : HTTPS, OAuth
- **Évolutivité** : Microservices, Serverless

## Quiz de l'histoire

**Question 1** : Qui a inventé REST ?
**Réponse** : Roy Fielding dans sa thèse de 2000

**Question 2** : Quel format a remplacé XML pour les APIs ?
**Réponse** : JSON (devenu populaire vers 2006)

**Question 3** : Quelle année marque la création du Web ?
**Réponse** : 1989 (proposition de Tim Berners-Lee)

## En résumé

L'histoire des APIs est une histoire de **simplification** et de **standardisation** :

1. **1960-1980** : Naissance de la modularité
2. **1990-2000** : Web et SOAP
3. **2000-2010** : REST et JSON
4. **2010-2020** : Mobile et microservices
5. **2020+** : Serverless et API-First

Cette évolution montre comment les APIs sont passées d'un concept technique à un élément fondamental du développement moderne !

---

**Prochain chapitre** : [03-REST-vs-SOAP-vs-GraphQL](03-REST-vs-SOAP-vs-GraphQL.md)
