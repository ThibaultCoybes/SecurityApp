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

- **Hachage des mots de passe** : Utilisation de bcrypt
- **Protection CSRF** : Sessions Flask sécurisées
- **Rate limiting** : Limitation des requêtes par IP
- **Détection d'injections** : Détection automatique des tentatives SQL injection
- **Audit logging** : Tous les événements sont journalisés dans `logs/audit.log`
- **Blocage après échecs** : Blocage après 5 tentatives de connexion échouées

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

## 🧪 Développement

Pour le développement, vous pouvez modifier les variables d'environnement dans `docker-compose.yml` ou utiliser un fichier `.env`.

## 📄 Licence

Ce projet est un exemple éducatif de sécurité web.

## 👤 Auteur

Projet de démonstration des bonnes pratiques de sécurité web.

