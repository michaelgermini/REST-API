# Cas d'usage des APIs REST

## Introduction

Maintenant que nous comprenons ce qu'est une API et que nous avons exploré les différentes architectures disponibles, concentrons-nous sur les **APIs REST**. Dans ce chapitre, nous allons découvrir les nombreux cas d'usage concrets où REST excelle, du développement web aux applications mobiles en passant par l'Internet des Objets.

## 1. Applications Web modernes

### SPAs (Single Page Applications)

Les applications web modernes comme React, Vue.js ou Angular communiquent massivement avec des APIs REST.

```javascript
// Exemple avec React
const UserProfile = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/users/123')
      .then(response => response.json())
      .then(data => {
        setUser(data);
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Loading...</div>;
  return <div>Welcome, {user.name}!</div>;
};
```

### Backend-for-Frontend (BFF)

```javascript
// API dédiée pour le frontend mobile
app.get('/api/mobile/users/:id', (req, res) => {
  // Format optimisé pour mobile
  const user = getOptimizedUserData(req.params.id);
  res.json({
    id: user.id,
    displayName: user.name,
    avatar: user.profilePicture.thumbnail,
    lastSeen: user.lastActivity
  });
});
```

## 2. Applications mobiles

### APIs pour iOS et Android

```swift
// iOS avec URLSession
func fetchUser(userId: String, completion: @escaping (User?) -> Void) {
    let url = URL(string: "https://api.example.com/users/\(userId)")!

    URLSession.shared.dataTask(with: url) { data, response, error in
        guard let data = data else {
            completion(nil)
            return
        }

        let user = try? JSONDecoder().decode(User.self, from: data)
        completion(user)
    }.resume()
}
```

```kotlin
// Android avec Retrofit
interface UserApi {
    @GET("users/{id}")
    suspend fun getUser(@Path("id") userId: String): User
}

class UserRepository(private val api: UserApi) {
    suspend fun getUser(userId: String): User {
        return api.getUser(userId)
    }
}
```

### Gestion offline et synchronisation

```javascript
// Service Worker pour le cache
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/api/')) {
    event.respondWith(
      caches.match(event.request)
        .then(response => {
          if (response) {
            return response;
          }
          return fetch(event.request)
            .then(response => {
              // Mettre en cache pour offline
              const responseClone = response.clone();
              caches.open('api-cache')
                .then(cache => cache.put(event.request, responseClone));
              return response;
            });
        })
    );
  }
});
```

## 3. Internet des Objets (IoT)

### APIs pour objets connectés

```javascript
// API pour un thermostat connecté
const thermostatAPI = {
  // Récupérer la température actuelle
  getCurrentTemp: () => fetch('/api/thermostat/temperature'),

  // Régler la température cible
  setTargetTemp: (temp) => fetch('/api/thermostat/target', {
    method: 'POST',
    body: JSON.stringify({ temperature: temp })
  }),

  // Programmer une schedule
  setSchedule: (schedule) => fetch('/api/thermostat/schedule', {
    method: 'PUT',
    body: JSON.stringify(schedule)
  })
};
```

### Protocoles légers pour IoT

```javascript
// CoAP (Constrained Application Protocol) pour objets contraints
// Plus léger que HTTP pour les capteurs
GET /sensors/temperature
Content-Format: application/json

// MQTT pour la communication temps réel
Topic: home/thermostat/temperature
Payload: {"value": 22.5, "unit": "celsius"}
```

## 4. Microservices

### Architecture microservices

```javascript
// Service Users
app.get('/users/:id', (req, res) => {
  const user = getUserFromDatabase(req.params.id);
  res.json(user);
});

// Service Orders
app.post('/orders', (req, res) => {
  const order = createOrder(req.body);
  // Appeler le service Users pour validation
  fetch(`http://user-service/users/${req.body.userId}`)
    .then(userResponse => userResponse.json())
    .then(user => {
      if (user.active) {
        res.json(order);
      } else {
        res.status(403).json({ error: 'User inactive' });
      }
    });
});
```

### Communication inter-services

```javascript
// Service Gateway avec circuit breaker
const circuitBreaker = new CircuitBreaker();

app.get('/api/user-orders/:userId', async (req, res) => {
  try {
    // Récupérer user et orders en parallèle
    const [user, orders] = await Promise.all([
      circuitBreaker.call('user-service', `/users/${req.params.userId}`),
      circuitBreaker.call('order-service', `/orders?userId=${req.params.userId}`)
    ]);

    res.json({ user, orders });
  } catch (error) {
    res.status(503).json({ error: 'Service unavailable' });
  }
});
```

## 5. Intégrations tierces

### APIs pour l'e-commerce

```javascript
// Intégration avec Stripe pour les paiements
app.post('/api/payments', async (req, res) => {
  const paymentIntent = await stripe.paymentIntents.create({
    amount: req.body.amount,
    currency: 'eur',
    metadata: {
      orderId: req.body.orderId
    }
  });

  res.json({ clientSecret: paymentIntent.client_secret });
});
```

### Webhooks pour les notifications

```javascript
// Webhook pour les paiements Stripe
app.post('/webhooks/stripe', (req, res) => {
  const signature = req.headers['stripe-signature'];

  if (verifyStripeSignature(req.body, signature)) {
    const event = req.body;

    switch (event.type) {
      case 'payment_intent.succeeded':
        handleSuccessfulPayment(event.data.object);
        break;
      case 'payment_intent.payment_failed':
        handleFailedPayment(event.data.object);
        break;
    }

    res.json({ received: true });
  } else {
    res.status(400).json({ error: 'Invalid signature' });
  }
});
```

## 6. APIs publiques et Open Data

### APIs gouvernementales

```javascript
// API data.gouv.fr
const publicDataAPI = {
  // Données démographiques
  getPopulation: (city) => fetch(`https://api.data.gouv.fr/population/${city}`),

  // Statistiques économiques
  getEconomicData: (region) => fetch(`https://api.data.gouv.fr/economic/${region}`),

  // Données environnementales
  getAirQuality: (location) => fetch(`https://api.data.gouv.fr/air-quality/${location}`)
};
```

### Exemple d'utilisation

```javascript
// Application de visualisation de données
const Dashboard = () => {
  const [population, setPopulation] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Récupérer les données de plusieurs APIs
    Promise.all([
      fetch('https://api.data.gouv.fr/population/france'),
      fetch('https://api.data.gouv.fr/economic/france')
    ])
    .then(responses => Promise.all(responses.map(r => r.json())))
    .then(([popData, ecoData]) => {
      setPopulation(popData);
      setLoading(false);
    });
  }, []);

  // Visualiser les données avec Chart.js
  return (
    <div>
      <h2>Tableau de bord France</h2>
      <PopulationChart data={population} />
    </div>
  );
};
```

## 7. APIs en temps réel

### WebSockets avec REST

```javascript
// API REST pour la configuration
app.get('/api/chat/rooms/:id', (req, res) => {
  const room = getChatRoom(req.params.id);
  res.json(room);
});

// WebSocket pour les messages temps réel
io.on('connection', (socket) => {
  socket.on('join-room', (roomId) => {
    socket.join(roomId);
  });

  socket.on('send-message', (data) => {
    // Sauvegarder en base via API REST
    fetch('/api/messages', {
      method: 'POST',
      body: JSON.stringify(data)
    });

    // Diffuser à tous les clients de la room
    io.to(data.roomId).emit('new-message', data);
  });
});
```

### Server-Sent Events (SSE)

```javascript
// API pour les notifications temps réel
app.get('/api/notifications/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  // Envoyer des notifications périodiquement
  const interval = setInterval(() => {
    const notification = {
      id: Date.now(),
      message: 'Nouveau message reçu',
      timestamp: new Date().toISOString()
    };

    res.write(`data: ${JSON.stringify(notification)}\n\n`);
  }, 5000);

  req.on('close', () => {
    clearInterval(interval);
  });
});
```

## 8. Machine Learning et APIs

### APIs pour modèles ML

```python
# Flask API pour un modèle de classification
from flask import Flask, request, jsonify
import joblib

app = Flask(__name__)
model = joblib.load('model.pkl')

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json()
    prediction = model.predict([data['features']])
    probability = model.predict_proba([data['features']])

    return jsonify({
        'prediction': int(prediction[0]),
        'probability': float(max(probability[0])),
        'confidence': float(max(probability[0]) * 100)
    })
```

### Exemple d'utilisation

```javascript
// Interface web pour le modèle ML
const MLInterface = () => {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handlePrediction = async (features) => {
    setLoading(true);
    try {
      const response = await fetch('/api/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ features })
      });

      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error('Prediction failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <FeatureInput onPredict={handlePrediction} />
      {loading && <div>Calcul en cours...</div>}
      {result && (
        <ResultDisplay
          prediction={result.prediction}
          confidence={result.confidence}
        />
      )}
    </div>
  );
};
```

## 9. APIs pour les jeux vidéo

### APIs de gaming

```javascript
// API pour un jeu multijoueur
const gameAPI = {
  // Gestion des joueurs
  getPlayer: (playerId) => fetch(`/api/players/${playerId}`),
  updatePlayer: (playerId, data) => fetch(`/api/players/${playerId}`, {
    method: 'PUT',
    body: JSON.stringify(data)
  }),

  // Gestion des parties
  createGame: (gameData) => fetch('/api/games', {
    method: 'POST',
    body: JSON.stringify(gameData)
  }),
  joinGame: (gameId) => fetch(`/api/games/${gameId}/join`, {
    method: 'POST'
  }),

  // Classements et statistiques
  getLeaderboard: () => fetch('/api/leaderboard'),
  getStats: (playerId) => fetch(`/api/players/${playerId}/stats`)
};
```

### Real-time gaming avec WebSockets

```javascript
// WebSocket pour le gameplay temps réel
const ws = new WebSocket('wss://api.game.com/game/123');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  switch (data.type) {
    case 'player_joined':
      addPlayerToGame(data.player);
      break;
    case 'player_moved':
      updatePlayerPosition(data.playerId, data.position);
      break;
    case 'game_event':
      handleGameEvent(data.event);
      break;
  }
};

// Envoyer les actions du joueur
const sendAction = (action) => {
  ws.send(JSON.stringify({
    type: 'player_action',
    action: action
  }));
};
```

## 10. APIs pour l'administration

### APIs de monitoring

```javascript
// API pour le monitoring système
const monitoringAPI = {
  // Métriques serveur
  getServerMetrics: () => fetch('/api/metrics/server'),
  getDatabaseMetrics: () => fetch('/api/metrics/database'),

  // Logs et erreurs
  getLogs: (level, limit) => fetch(`/api/logs?level=${level}&limit=${limit}`),
  getErrors: (since) => fetch(`/api/errors?since=${since}`),

  // Health checks
  getHealth: () => fetch('/api/health'),
  getDependenciesHealth: () => fetch('/api/health/dependencies')
};
```

### Dashboard d'administration

```javascript
// Interface d'administration
const AdminDashboard = () => {
  const [metrics, setMetrics] = useState({});
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    // Récupérer les métriques toutes les 30 secondes
    const fetchMetrics = () => {
      fetch('/api/metrics/server')
        .then(r => r.json())
        .then(data => setMetrics(data));
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 30000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="admin-dashboard">
      <ServerMetrics metrics={metrics} />
      <LogsViewer logs={logs} />
      <HealthStatus />
    </div>
  );
};
```

## Tendances et avenir

### APIs composables

```javascript
// Composition d'APIs pour créer de nouvelles fonctionnalités
const composeAPI = {
  // Profil utilisateur enrichi
  getUserProfile: async (userId) => {
    const [user, orders, preferences] = await Promise.all([
      fetch(`/api/users/${userId}`),
      fetch(`/api/orders?userId=${userId}`),
      fetch(`/api/preferences/${userId}`)
    ]).then(responses => Promise.all(responses.map(r => r.json())));

    return {
      ...user,
      orderHistory: orders,
      preferences: preferences
    };
  }
};
```

### API as a Service

```javascript
// Services API tiers
const thirdPartyAPIs = {
  // Géolocalisation
  getLocation: (address) => fetch(`https://maps.googleapis.com/geocode?address=${address}`),

  // Météo
  getWeather: (lat, lng) => fetch(`https://api.weather.com/forecast?lat=${lat}&lng=${lng}`),

  // Traduction
  translate: (text, from, to) => fetch(`https://translate.googleapis.com/translate`, {
    method: 'POST',
    body: JSON.stringify({ text, from, to })
  })
};
```

## Bonnes pratiques par cas d'usage

### 1. **Pour les applications mobiles**
- ✅ Optimiser les réponses (pagination, filtrage)
- ✅ Utiliser HTTP/2 pour le multiplexing
- ✅ Implémenter le cache offline
- ✅ Compresser les réponses

### 2. **Pour l'IoT**
- ✅ Utiliser des protocoles légers (CoAP, MQTT)
- ✅ Implémenter la QoS (Quality of Service)
- ✅ Gérer les connexions intermittentes
- ✅ Optimiser la consommation énergétique

### 3. **Pour les microservices**
- ✅ Utiliser des timeouts et circuit breakers
- ✅ Implémenter la traçabilité distribuée
- ✅ Gérer les versions d'API
- ✅ Documenter les contrats inter-services

### 4. **Pour les APIs publiques**
- ✅ Implémenter rate limiting
- ✅ Fournir une documentation claire
- ✅ Gérer les quotas et facturation
- ✅ Supporter CORS

## Quiz des cas d'usage

**Question 1** : Quel protocole est recommandé pour l'IoT ?
**Réponse** : CoAP ou MQTT (plus légers que HTTP)

**Question 2** : Pour une application mobile, que faut-il optimiser ?
**Réponse** : La taille des réponses et le cache offline

**Question 3** : Quelle architecture pour un jeu multijoueur ?
**Réponse** : WebSockets + REST API

## En résumé

Les APIs REST sont utilisées dans une multitude de contextes :

1. **Web moderne** : SPAs, BFF, SSR
2. **Mobile** : iOS, Android, React Native
3. **IoT** : Objets connectés, capteurs
4. **Microservices** : Communication inter-services
5. **Intégrations** : Paiements, webhooks, tiers
6. **Open Data** : APIs publiques, gouvernementales
7. **Real-time** : WebSockets, SSE
8. **Machine Learning** : Modèles prédictifs
9. **Gaming** : Multijoueur, leaderboards
10. **Administration** : Monitoring, métriques

Le succès de REST vient de sa **simplicité**, sa **flexibilité** et sa **large adoption**. Dans les prochains chapitres, nous plongerons dans les principes fondamentaux de REST pour comprendre comment concevoir des APIs robustes et efficaces !

---

**Prochain chapitre** : [01-Architecture-REST](02-Principes-du-REST/01-Architecture-REST.md)
