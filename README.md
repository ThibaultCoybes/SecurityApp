# Security App

Application web Flask sécurisée avec authentification, détection d'injections SQL, audit logging et interface moderne.

## 🚀 Fonctionnalités

- **Authentification sécurisée** : Connexion et inscription avec hachage bcrypt
- **Protection contre les injections SQL** : Détection automatique des tentatives d'injection
- **Audit logging** : Journalisation de tous les événements de sécurité
- **Rate limiting** : Protection contre les attaques par force brute
- **Validation des données** : Validation stricte des entrées utilisateur
- **Interface moderne** : Design épuré style Apple
- **Détection d'outils** : Identification des outils d'automatisation et scanners

## 📋 Prérequis

- Docker et Docker Compose
- Python 3.x (pour développement local)

## 🛠️ Installation

### Avec Docker (recommandé)

1. Clonez le repository :
```bash
git clone <url-du-repo>
cd security_app
```

2. Lancez l'application avec Docker Compose :
```bash
docker-compose up --build
```

3. L'application sera accessible sur `http://localhost:5001`

### Installation locale

1. Installez les dépendances :
```bash
pip install -r requirements.txt
```

2. Configurez les variables d'environnement :
```bash
export MYSQL_HOST=localhost
export MYSQL_USER=root
export MYSQL_PASSWORD=root
export MYSQL_DB=security_db
export FLASK_SECRET=your-secret-key
```

3. Lancez l'application :
```bash
python app.py
```

## 📁 Structure du projet

```
security_app/
├── app.py                 # Application Flask principale
├── security/
│   ├── authentication.py  # Gestion de l'authentification
│   ├── authorization.py   # Gestion des autorisations
│   ├── audit.py           # Système d'audit logging
│   ├── detection.py       # Détection d'injections SQL et outils
│   └── validation.py      # Validation des données
├── templates/             # Templates HTML
├── static/               # Fichiers statiques (CSS)
├── requirements.txt      # Dépendances Python
├── Dockerfile           # Configuration Docker
└── docker-compose.yml   # Configuration Docker Compose
```

## 🔐 Sécurité

- **Hachage des mots de passe** : Utilisation de bcrypt avec salt automatique
- **Protection CSRF** : Sessions Flask sécurisées
- **Rate limiting** : Limitation des requêtes par IP
- **Détection d'injections** : Détection automatique des tentatives SQL injection
- **Audit logging** : Tous les événements sont journalisés dans `logs/audit.log`
- **Blocage après échecs** : Blocage après 5 tentatives de connexion échouées

### Hachage des mots de passe

Les mots de passe sont hachés avec **bcrypt** :
- Génération automatique d'un salt unique pour chaque mot de passe
- Algorithme : bcrypt (coût par défaut)
- Format : `$2b$[cost]$[salt][hash]`
- Les mots de passe en clair ne sont jamais stockés en base de données

### Validations des inputs

#### Nom d'utilisateur (`username`)
- **Format** : Alphanumérique uniquement (lettres et chiffres)
- **Longueur** : Entre 3 et 20 caractères
- **Pattern** : `^[A-Za-z0-9]{3,20}$`
- **Exemples valides** : `user123`, `admin`, `testuser`
- **Exemples invalides** : `user_123` (underscore non autorisé), `ab` (trop court), `user@name` (caractères spéciaux non autorisés)

#### Email
- **Format** : Format email standard RFC
- **Pattern** : `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
- **Exemples valides** : `user@example.com`, `test.user@domain.co.uk`
- **Exemples invalides** : `invalid.email`, `user@`, `@domain.com`

#### Mot de passe (`password`)
- **Longueur** : Entre 8 et 20 caractères
- **Exigences** :
  - Au moins une lettre minuscule (`a-z`)
  - Au moins une lettre majuscule (`A-Z`)
  - Au moins un chiffre (`0-9`)
  - Au moins un caractère spécial parmi : `@$!%*?&`
- **Pattern** : `^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$`
- **Confirmation** : Le mot de passe et sa confirmation doivent être identiques
- **Exemples valides** : `Password123!`, `MyP@ssw0rd`
- **Exemples invalides** : `password` (pas de majuscule/chiffre/caractère spécial), `PASSWORD123` (pas de minuscule/caractère spécial), `Pass1` (trop court)

#### Sanitization
- Tous les inputs sont sanitizés avec `markupsafe.escape()` pour prévenir les attaques XSS
- Les caractères HTML spéciaux sont échappés avant stockage

## 🎨 Interface

L'application dispose d'une interface moderne et épurée inspirée du design Apple, avec :
- Formulaires élégants
- Animations fluides
- Design responsive
- Feedback visuel clair

## 📝 Routes disponibles

- `/` - Page de connexion
- `/login` - Connexion (GET/POST)
- `/register` - Inscription (GET/POST)
- `/dashboard` - Tableau de bord (authentification requise)
- `/logout` - Déconnexion

## 🔍 Logs d'audit

Les logs sont enregistrés dans `logs/audit.log` au format JSON et incluent :
- Tentatives de connexion
- Détections d'injections SQL
- Accès refusés
- Erreurs de base de données
- Visites de routes

### Voir les logs dans Docker

#### Logs de l'application Flask
```bash
# Voir les logs du conteneur web
docker logs flask_app

# Suivre les logs en temps réel
docker logs -f flask_app

# Voir les dernières 100 lignes
docker logs --tail 100 flask_app
```

#### Logs d'audit (fichier audit.log)
```bash
# Accéder au conteneur
docker exec -it flask_app bash

# Voir les logs d'audit
cat logs/audit.log

# Suivre les logs d'audit en temps réel
tail -f logs/audit.log

# Voir les dernières 50 lignes
tail -n 50 logs/audit.log
```

#### Logs de la base de données MySQL
```bash
# Voir les logs du conteneur MySQL
docker logs mysql_db

# Suivre les logs en temps réel
docker logs -f mysql_db
```

#### Copier les logs depuis le conteneur
```bash
# Copier le fichier audit.log sur votre machine
docker cp flask_app:/app/logs/audit.log ./audit.log
```

#### Format des logs d'audit
Chaque ligne est un objet JSON avec la structure suivante :
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "event_type": "LOGIN_ATTEMPT",
  "user": "username",
  "ip_address": "192.168.1.1",
  "severity": "INFO",
  "details": {
    "route": "/login",
    "success": true,
    "tool": null,
    "ua": "Mozilla/5.0..."
  }
}
```

## 🧪 Développement

Pour le développement, vous pouvez modifier les variables d'environnement dans `docker-compose.yml` ou utiliser un fichier `.env`.

## 📄 Licence

Ce projet est un exemple éducatif de sécurité web.

## 👤 Auteur

Projet de démonstration des bonnes pratiques de sécurité web.

