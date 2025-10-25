# Chiffrement HTTPS et TLS

## Introduction

Le **chiffrement** est la base de la sécurité sur Internet. Sans HTTPS et TLS, toutes les données transitent en **clair** sur le réseau, exposées aux interceptions et modifications. Dans ce chapitre, nous allons explorer les protocoles **HTTPS** (HTTP Secure) et **TLS** (Transport Layer Security), apprendre à configurer des certificats et à implémenter une sécurité transport robuste.

## HTTP vs HTTPS

### HTTP non sécurisé

```javascript
// ❌ HTTP en clair
GET /api/users/123 HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "email": "user@example.com",
  "password": "secret123"  // Visible par tous !
}
```

### HTTPS sécurisé

```javascript
// ✅ HTTPS chiffré
GET /api/users/123 HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "email": "user@example.com"
  // Données chiffrées pendant le transit
}
```

## TLS (Transport Layer Security)

### Qu'est-ce que TLS ?

TLS est le protocole de **chiffrement** qui sécurise la communication entre le client et le serveur. Il succède à SSL (Secure Sockets Layer) et est maintenant le standard pour la sécurité transport.

```javascript
// ✅ Handshake TLS
Client                                    Serveur
  │                                          │
  ├── ClientHello (versions, cipher suites) ──►│
  │                                          │
  │◄── ServerHello (version, cipher suite) ───┤
  │                                          │
  │◄── Certificate (certificat serveur) ─────┤
  │                                          │
  │◄── ServerHelloDone ──────────────────────┤
  │                                          │
  ├── ClientKeyExchange (clé de session) ───►│
  │                                          │
  ├── ChangeCipherSpec ─────────────────────►│
  │                                          │
  ├── Finished (vérification) ──────────────►│
  │                                          │
  │◄── ChangeCipherSpec ─────────────────────┤
  │◄── Finished (vérification) ──────────────┤
  │                                          │
  │========== COMMUNICATION CHIFFRÉE =========│
```

### Versions de TLS

```javascript
// ✅ Versions TLS supportées
const tlsVersions = {
  'TLS 1.3': {
    year: 2018,
    security: 'Excellent',
    performance: 'Excellent',
    compatibility: 'Modern browsers'
  },
  'TLS 1.2': {
    year: 2008,
    security: 'Good',
    performance: 'Good',
    compatibility: 'All browsers'
  },
  'TLS 1.1': {
    year: 2006,
    security: 'Deprecated',
    performance: 'Poor',
    compatibility: 'Legacy'
  },
  'TLS 1.0': {
    year: 1999,
    security: 'Insecure',
    performance: 'Poor',
    compatibility: 'Very legacy'
  }
};

// ✅ Configuration recommandée
const tlsConfig = {
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
  ciphers: [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384'
  ],
  secureProtocol: 'TLSv1_2_method',
  secureOptions: require('constants').SSL_OP_NO_TLSv1 | require('constants').SSL_OP_NO_TLSv1_1
};
```

## Certificats SSL/TLS

### Types de certificats

#### 1. Certificats DV (Domain Validation)

```javascript
// ✅ Validation de domaine
const dvCert = {
  type: 'Domain Validated',
  validation: 'Email ou DNS',
  cost: 'Gratuit à 20€/an',
  security: 'Basique',
  trust: 'Navigateur uniquement',
  usage: 'Sites personnels, blogs'
};
```

#### 2. Certificats OV (Organization Validation)

```javascript
// ✅ Validation d'organisation
const ovCert = {
  type: 'Organization Validated',
  validation: 'Documents légaux',
  cost: '50€ à 200€/an',
  security: 'Moyen',
  trust: 'Affiche le nom de l'organisation',
  usage: 'Entreprises, sites professionnels'
};
```

#### 3. Certificats EV (Extended Validation)

```javascript
// ✅ Validation étendue
const evCert = {
  type: 'Extended Validation',
  validation: 'Vérification approfondie',
  cost: '100€ à 500€/an',
  security: 'Élevé',
  trust: 'Barre d'adresse verte',
  usage: 'Banques, e-commerce, services financiers'
};
```

#### 4. Certificats Wildcard

```javascript
// ✅ Certificats génériques
const wildcardCert = {
  domain: '*.example.com',
  coverage: [
    'api.example.com',
    'app.example.com',
    'admin.example.com'
  ],
  limitations: 'Ne couvre pas example.com lui-même',
  cost: 'Premium',
  usage: 'Multiple sous-domaines'
};
```

### Obtention d'un certificat

#### Let's Encrypt (gratuit)

```bash
# Installation de Certbot
sudo apt install certbot

# Génération du certificat
sudo certbot certonly \
  --standalone \
  --agree-tos \
  --register-unsafely-without-email \
  -d api.example.com \
  -d www.api.example.com

# Renouvellement automatique
sudo crontab -e
# Ajouter :
0 12 * * * /usr/bin/certbot renew --quiet
```

#### Configuration Express avec HTTPS

```javascript
const express = require('express');
const https = require('https');
const fs = require('fs');
const app = express();

// ✅ Configuration HTTPS
const httpsOptions = {
  key: fs.readFileSync('/etc/letsencrypt/live/api.example.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/api.example.com/cert.pem'),
  ca: fs.readFileSync('/etc/letsencrypt/live/api.example.com/chain.pem'),

  // Options de sécurité
  secureOptions: require('constants').SSL_OP_NO_TLSv1 | require('constants').SSL_OP_NO_TLSv1_1,
  ciphers: [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256'
  ],
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3'
};

// Serveur HTTPS
const httpsServer = https.createServer(httpsOptions, app);

httpsServer.listen(443, () => {
  console.log('HTTPS server running on port 443');
});
```

## Configuration avancée TLS

### Cipher Suites

```javascript
// ✅ Cipher suites recommandées (2023)
const recommendedCiphers = [
  // TLS 1.3
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',

  // TLS 1.2 (fallback)
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',

  // Legacy (si nécessaire)
  'ECDHE-RSA-AES128-SHA256',
  'ECDHE-RSA-AES256-SHA384'
];

// ❌ Cipher suites à éviter
const badCiphers = [
  'TLS_RSA_WITH_AES_128_CBC_SHA',      // Pas de PFS
  'TLS_RSA_WITH_AES_256_CBC_SHA',      // Pas de PFS
  'SSL_RSA_WITH_3DES_EDE_CBC_SHA',     // Faible
  'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'   // DH faible
];
```

### Perfect Forward Secrecy (PFS)

```javascript
// ✅ PFS avec ECDHE
const pfsCiphers = [
  'ECDHE-RSA-AES128-GCM-SHA256',      // PFS + AES-GCM
  'ECDHE-RSA-AES256-GCM-SHA384',      // PFS + AES-GCM
  'ECDHE-ECDSA-AES128-GCM-SHA256',    // PFS + AES-GCM + ECDSA
  'ECDHE-ECDSA-AES256-GCM-SHA384'     // PFS + AES-GCM + ECDSA
];

// ✅ Configuration PFS
const tlsOptions = {
  ciphers: pfsCiphers.join(':'),
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
  secureProtocol: 'TLSv1_2_method',

  // Options de sécurité
  secureOptions: require('constants').SSL_OP_NO_TLSv1 |
                 require('constants').SSL_OP_NO_TLSv1_1 |
                 require('constants').SSL_OP_NO_SSLv3,

  // PFS requis
  requirePerfectForwardSecrecy: true,

  // Renégociation désactivée
  rejectUnauthorized: true
};
```

### Headers de sécurité

```javascript
const helmet = require('helmet');

// ✅ Headers de sécurité HTTP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.example.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },

  hsts: {
    maxAge: 31536000, // 1 an
    includeSubDomains: true,
    preload: true
  },

  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ✅ Headers manuels
app.use('/api', (req, res, next) => {
  res.set({
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin'
  });
  next();
});
```

## Chiffrement des données

### Chiffrement au repos

```javascript
const crypto = require('crypto');

// ✅ Chiffrement AES-256
const encryptData = (data, key) => {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher(algorithm, key);

  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
};

const decryptData = (encryptedData, key) => {
  const { encrypted, iv, authTag } = encryptedData;
  const algorithm = 'aes-256-gcm';

  const decipher = crypto.createDecipher(algorithm, key);
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  decipher.setIV(Buffer.from(iv, 'hex'));

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return JSON.parse(decrypted);
};

// ✅ Usage
const sensitiveData = {
  creditCard: '4111111111111111',
  ssn: '123-45-6789',
  medicalInfo: 'confidential'
};

const encryptionKey = process.env.DATA_ENCRYPTION_KEY;
const encryptedData = encryptData(sensitiveData, encryptionKey);

// Stockage en base de données
await db.sensitiveData.create({
  userId: 123,
  data: JSON.stringify(encryptedData)
});
```

### Chiffrement en transit

```javascript
// ✅ HSTS (HTTP Strict Transport Security)
app.use(helmet.hsts({
  maxAge: 31536000, // 1 an
  includeSubDomains: true,
  preload: true
}));

// ✅ Redirection automatique HTTP → HTTPS
app.use((req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
});

// ✅ Configuration TLS stricte
const tlsOptions = {
  // Chiffrement fort uniquement
  ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:!RC4:!MD5:!DSS',
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',

  // Sécurité renforcée
  secureProtocol: 'TLSv1_2_method',
  secureOptions: require('constants').SSL_OP_NO_SSLv3 |
                 require('constants').SSL_OP_NO_TLSv1 |
                 require('constants').SSL_OP_NO_TLSv1_1,

  // Vérification du certificat client
  requestCert: true,
  rejectUnauthorized: true,

  // OCSP Stapling
  stapling: true
};
```

## Configuration de production

### Serveur HTTPS complet

```javascript
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const app = express();

// ✅ Configuration HTTPS
const httpsOptions = {
  key: fs.readFileSync('/etc/ssl/private/api.example.com.key'),
  cert: fs.readFileSync('/etc/ssl/certs/api.example.com.crt'),
  ca: fs.readFileSync('/etc/ssl/certs/ca.crt'),

  // Options de sécurité TLS
  secureOptions: require('constants').SSL_OP_NO_TLSv1 |
                 require('constants').SSL_OP_NO_TLSv1_1 |
                 require('constants').SSL_OP_NO_SSLv3,
  ciphers: [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384'
  ].join(':'),
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',

  // Sécurité renforcée
  requirePerfectForwardSecrecy: true,
  sessionTimeout: 300, // 5 minutes
  requestCert: false,
  rejectUnauthorized: false
};

// ✅ Middleware de sécurité
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// ✅ Redirection HTTP vers HTTPS
const redirectToHttps = (req, res, next) => {
  if (req.header('x-forwarded-proto') !== 'https') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    next();
  }
};

app.use(redirectToHttps);

// ✅ Routes de l'API
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// ✅ Serveurs HTTP et HTTPS
const httpServer = http.createServer(app);
const httpsServer = https.createServer(httpsOptions, app);

// ✅ Démarrage des serveurs
httpServer.listen(80, () => {
  console.log('HTTP server running on port 80 (redirects to HTTPS)');
});

httpsServer.listen(443, () => {
  console.log('HTTPS server running on port 443');
});
```

### Load Balancer avec SSL Termination

```javascript
// ✅ Configuration derrière un load balancer
const behindProxy = process.env.BEHIND_PROXY === 'true';

if (behindProxy) {
  // Trust proxy headers
  app.set('trust proxy', 1);

  // Configuration CORS pour proxy
  app.use(cors({
    origin: 'https://myapp.com',
    credentials: true,
    optionsSuccessStatus: 200
  }));
} else {
  // Configuration directe HTTPS
  const httpsServer = https.createServer(httpsOptions, app);
  httpsServer.listen(443);
}

// ✅ Headers de sécurité pour proxy
app.use((req, res, next) => {
  res.set({
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  next();
});
```

## Tests et validation

### Tests HTTPS

```javascript
// tests/https.test.js
const request = require('supertest');
const app = require('../app');
const https = require('https');

describe('HTTPS Configuration', () => {
  test('should redirect HTTP to HTTPS', async () => {
    // Test de redirection (si serveur HTTP configuré)
    const response = await request(app)
      .get('/api/health')
      .expect(302); // Redirection

    expect(response.headers.location).toMatch(/^https:\/\//);
  });

  test('should serve content over HTTPS', async () => {
    // Test HTTPS direct
    const agent = new https.Agent({
      rejectUnauthorized: false // Pour les tests
    });

    const response = await request(app)
      .get('/api/health')
      .agent(agent)
      .expect(200);

    expect(response.body.status).toBe('healthy');
  });

  test('should have security headers', async () => {
    const response = await request(app)
      .get('/api/health')
      .expect(200);

    expect(response.headers['strict-transport-security']).toBeDefined();
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-frame-options']).toBe('DENY');
    expect(response.headers['x-xss-protection']).toBe('1; mode=block');
  });
});
```

### Tests de configuration TLS

```javascript
// tests/tls.test.js
const tls = require('tls');
const fs = require('fs');

describe('TLS Configuration', () => {
  test('should support TLS 1.2 and 1.3', () => {
    const options = {
      host: 'api.example.com',
      port: 443,
      rejectUnauthorized: false
    };

    const socket = tls.connect(options, () => {
      const authorized = socket.authorized;
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();

      expect(protocol).toMatch(/TLSv1\.[23]/);
      expect(['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384'])
        .toContain(cipher.name);

      socket.end();
    });
  });

  test('should reject weak ciphers', () => {
    const options = {
      host: 'api.example.com',
      port: 443,
      ciphers: 'RC4-SHA', // Cipher faible
      rejectUnauthorized: false
    };

    expect(() => {
      tls.connect(options);
    }).toThrow(); // Devrait échouer
  });

  test('should have valid certificate', () => {
    const options = {
      host: 'api.example.com',
      port: 443,
      rejectUnauthorized: false
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();

      expect(cert.subject.CN).toBe('api.example.com');
      expect(cert.issuer.CN).toBeDefined();
      expect(new Date(cert.valid_to)).toBeAfter(new Date());

      socket.end();
    });
  });
});
```

## Monitoring et maintenance

### Surveillance SSL

```javascript
// ✅ Monitoring des certificats
const checkSSLCertificates = () => {
  const certificates = [
    {
      domain: 'api.example.com',
      certPath: '/etc/ssl/certs/api.example.com.crt',
      keyPath: '/etc/ssl/private/api.example.com.key'
    }
  ];

  certificates.forEach(cert => {
    const certInfo = getCertificateInfo(cert.certPath);

    // Vérifier l'expiration
    const daysUntilExpiry = Math.floor((certInfo.validTo - new Date()) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry <= 30) {
      sendAlert('SSL_CERTIFICATE_EXPIRING', {
        domain: cert.domain,
        daysUntilExpiry,
        expiryDate: certInfo.validTo
      });
    }

    // Vérifier la validité
    if (!certInfo.valid) {
      sendAlert('SSL_CERTIFICATE_INVALID', {
        domain: cert.domain,
        error: certInfo.error
      });
    }
  });
};

// ✅ Renouvellement automatique
const renewCertificates = async () => {
  try {
    await exec('certbot renew --quiet');

    if (certbotExitCode === 0) {
      console.log('SSL certificates renewed successfully');
      reloadWebServer();
    } else {
      sendAlert('SSL_RENEWAL_FAILED', { error: 'Certbot failed' });
    }
  } catch (error) {
    sendAlert('SSL_RENEWAL_ERROR', { error: error.message });
  }
};

// ✅ Surveillance continue
setInterval(checkSSLCertificates, 24 * 60 * 60 * 1000); // Quotidienne
setInterval(renewCertificates, 7 * 24 * 60 * 60 * 1000); // Hebdomadaire
```

### Logs de sécurité

```javascript
// ✅ Middleware de logging SSL
const sslLogger = (req, res, next) => {
  const sslInfo = {
    timestamp: new Date().toISOString(),
    protocol: req.protocol,
    cipher: req.connection.getCipher?.()?.name,
    tlsVersion: req.connection.getProtocol?.(),
    clientCert: req.connection.getPeerCertificate?.()?.fingerprint,
    userAgent: req.get('User-Agent')
  };

  // Log des connexions sécurisées
  if (req.protocol === 'https') {
    console.log('Secure connection:', sslInfo);
  }

  next();
};

// ✅ Monitoring des tentatives d'accès non sécurisé
const insecureAccessLogger = (req, res, next) => {
  if (req.protocol === 'http' && req.method !== 'GET') {
    console.warn('Insecure access attempt:', {
      ip: req.ip,
      method: req.method,
      url: req.originalUrl,
      userAgent: req.get('User-Agent')
    });

    sendAlert('INSECURE_ACCESS_ATTEMPT', {
      ip: req.ip,
      method: req.method,
      url: req.originalUrl
    });
  }

  next();
};
```

## Quiz HTTPS et TLS

**Question 1** : Quelle est la différence entre TLS et SSL ?
**Réponse** : TLS est le successeur de SSL, plus sécurisé et moderne

**Question 2** : Pourquoi utiliser Perfect Forward Secrecy ?
**Réponse** : Pour que le décryptage d'une session ne compromette pas les autres

**Question 3** : Quand utiliser un certificat EV ?
**Réponse** : Pour les sites sensibles (banques, e-commerce) qui nécessitent une confiance maximale

## En résumé

### Protocoles de sécurité
- 🔒 **TLS 1.3** : Standard moderne, performance et sécurité
- 🔐 **TLS 1.2** : Large compatibilité, encore acceptable
- ❌ **TLS 1.1 et antérieurs** : Obsolètes et dangereux

### Configuration recommandée
```javascript
// TLS moderne
{
  minVersion: 'TLSv1.2',
  ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:!RC4:!MD5',
  secureProtocol: 'TLSv1_2_method',
  requirePerfectForwardSecrecy: true
}

// Headers de sécurité
{
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
}
```

### Certificats
- ✅ **Let's Encrypt** : Gratuit et automatique
- 🏢 **OV/EV** : Pour les entreprises
- 🌐 **Wildcard** : Pour les sous-domaines
- 🔄 **Renouvellement automatique** : Essentiel

### Bonnes pratiques
- ✅ **HTTPS obligatoire** pour toutes les APIs
- ✅ **HSTS** pour forcer HTTPS
- ✅ **TLS 1.2+** minimum
- ✅ **PFS** pour la sécurité des sessions
- ✅ **Monitoring** des certificats

### Stack de sécurité complet
```javascript
// Sécurité transport + application
✅ HTTPS / TLS 1.3
✅ Headers de sécurité (HSTS, CSP, etc.)
✅ Authentification JWT
✅ Autorisation RBAC/ABAC
✅ Rate Limiting
✅ Validation et sanitisation
✅ Logging et monitoring
```

Dans le dernier chapitre de cette section, nous explorerons les **vulnérabilités courantes** et les bonnes pratiques de sécurité selon OWASP !

---

**Prochain chapitre** : [05-Vulnérabilités-OWASP-API](05-Vulnérabilités-OWASP-API.md)
