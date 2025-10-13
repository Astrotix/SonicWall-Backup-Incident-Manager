# 📁 Structure du projet SonicWall Management Console

## 📂 Fichiers principaux

```
SonicWall_Backup/
│
├── 📄 app.py                    # Application Flask principale
├── 📄 models.py                 # Modèles de base de données + chiffrement
├── 📄 requirements.txt          # Dépendances Python
│
├── 📁 templates/
│   └── 📄 index.html            # Interface web complète
│
├── 📁 instance/                 # Créé automatiquement
│   └── 📄 firewalls.db          # Base de données SQLite
│
├── 🔑 encryption.key            # Clé de chiffrement AES-256 (CRITIQUE)
│
├── 📁 backups/                  # Créé par backup_db.py
│   ├── firewalls_YYYYMMDD_HHMMSS.db
│   └── encryption_YYYYMMDD_HHMMSS.key
│
├── 📄 backup_db.py              # Script de backup
├── 📄 DATABASE_SECURITY.md      # Documentation sécurité
├── 📄 STRUCTURE.md              # Ce fichier
├── 📄 README.md                 # Documentation principale
├── 📄 API_ENDPOINTS.md          # Liste des endpoints SonicWall
├── 📄 .gitignore                # Exclusions Git (DB, clés, backups)
└── 📄 start.bat                 # Script de démarrage Windows
```

---

## 🔐 Fichiers sensibles (NE PAS COMMITTER)

| Fichier | Type | Danger | Protection |
|---------|------|--------|------------|
| `encryption.key` | Clé AES-256 | 🔴 CRITIQUE | `.gitignore` ✅ |
| `instance/firewalls.db` | Base de données | 🟠 Sensible | `.gitignore` ✅ |
| `backups/` | Sauvegardes | 🟠 Sensible | `.gitignore` ✅ |

---

## 🏗️ Architecture technique

### Backend (Python/Flask)

```python
app.py
├── Routes principales
│   ├── GET  /                              # Interface web
│   ├── GET  /api/firewalls                 # Liste des firewalls
│   ├── POST /api/firewalls                 # Ajouter un firewall
│   ├── PUT  /api/firewalls/<id>            # Modifier un firewall
│   └── DELETE /api/firewalls/<id>          # Supprimer un firewall
│
├── Routes de test
│   └── POST /api/test-connection           # Tester connexion SonicWall
│
├── Routes de monitoring
│   ├── POST /api/wan-management            # WAN Management
│   ├── POST /api/active-directory          # LDAP/AD config
│   ├── POST /api/local-users               # Utilisateurs locaux
│   ├── POST /api/radius-config             # RADIUS servers
│   ├── POST /api/tacacs-config             # TACACS+ servers
│   ├── POST /api/sso-config                # SSO configuration
│   ├── POST /api/ipsec-vpn                 # IPSEC VPN tunnels
│   └── POST /api/ssl-vpn                   # SSL VPN config
│
└── Routes d'actions
    ├── POST /api/local-users/force-password-change
    └── POST /api/local-users/unbind-totp/<username>
```

### Frontend (HTML/CSS/JavaScript)

```
index.html
├── Navigation
│   ├── 🛡️ Firewalls
│   ├── 🌐 WAN Management
│   ├── 👥 Users (groupe)
│   │   ├── 🔑 LOCAL Users
│   │   ├── 📁 LDAP
│   │   ├── 📡 RADIUS
│   │   ├── 🔐 TACACS+
│   │   └── 🔗 SSO
│   ├── 🔒 IPSEC VPN
│   ├── 🔓 SSL VPN
│   └── 📊 System Info
│
├── Fonctionnalités
│   ├── Ajout/Modification/Suppression de firewalls
│   ├── Migration automatique depuis localStorage
│   ├── Auto-chargement des données par onglet
│   ├── Alertes de sécurité (WAN, TOTP, VPN, etc.)
│   ├── Filtres et recherche
│   └── Sélection multiple (LOCAL Users)
│
└── Animations & UI/UX
    ├── Accordions expand/collapse
    ├── Badges colorés (success/warning/danger)
    ├── Animations CSS (slideInUp, fadeIn, pulse)
    └── Système de couleurs pour les risques
```

### Base de données (SQLite)

```sql
Table: firewalls
├── id (INTEGER PRIMARY KEY)
├── name (VARCHAR 100)
├── ip (VARCHAR 50, UNIQUE)
├── username (VARCHAR 100)
├── password_encrypted (BLOB)        -- Chiffré AES-256
├── otp (BOOLEAN)
├── status (VARCHAR 20)
├── last_checked (DATETIME)
├── created_at (DATETIME)
└── updated_at (DATETIME)
```

---

## 🔄 Flux de données

### Ajout d'un firewall

```
1. User remplit le formulaire
   ↓
2. Frontend teste la connexion (/api/test-connection)
   ↓
3. Si OK, Frontend envoie à /api/firewalls (POST)
   ↓
4. Backend chiffre le password avec AES-256
   ↓
5. Backend sauvegarde en DB (instance/firewalls.db)
   ↓
6. Frontend recharge depuis /api/firewalls (GET)
   ↓
7. Affichage mis à jour
```

### Chargement au démarrage

```
1. Page charge (DOMContentLoaded)
   ↓
2. Frontend appelle /api/firewalls (GET)
   ↓
3. Backend déchiffre les passwords
   ↓
4. Frontend stocke en mémoire (variable `firewalls`)
   ↓
5. Migration auto depuis localStorage si nécessaire
   ↓
6. Affichage des firewalls
```

---

## 🔐 Sécurité

### Chiffrement

```
Password en clair
    ↓
Fernet.encrypt() avec encryption.key
    ↓
Stockage en DB (BLOB)
    ↓
Fernet.decrypt() avec encryption.key
    ↓
Password en clair (en mémoire uniquement)
```

### Protection des données

| Donnée | Stockage | Chiffrement | Exposition |
|--------|----------|-------------|------------|
| Password | DB (BLOB) | ✅ AES-256 | ❌ Jamais en clair en DB |
| IP | DB (VARCHAR) | ❌ | ✅ Nécessaire pour fonctionner |
| Username | DB (VARCHAR) | ❌ | ✅ Considéré comme public |
| Name | DB (VARCHAR) | ❌ | ✅ Métadonnée |
| encryption.key | Fichier local | - | 🔴 NE JAMAIS PARTAGER |

---

## 🚀 Démarrage rapide

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer l'application
python app.py

# 3. Ouvrir le navigateur
http://localhost:5000

# 4. (Optionnel) Créer un backup
python backup_db.py
```

---

## 📊 Technologies utilisées

| Composant | Technologie | Version |
|-----------|-------------|---------|
| **Backend** | Flask | 3.0.0 |
| **Database** | SQLite + SQLAlchemy | 3.1.1 |
| **Encryption** | Cryptography (Fernet) | 41.0.7 |
| **HTTP Client** | Requests | 2.31.0 |
| **Frontend** | HTML5 + CSS3 + Vanilla JS | - |
| **Auth** | HTTP Digest Authentication | - |

---

## 📈 Modules disponibles

### Gestion
- 🛡️ **Firewalls** : Ajout, modification, suppression
- 🌐 **WAN Management** : Règles d'accès avec détection de risques

### Utilisateurs & Auth
- 🔑 **LOCAL Users** : Gestion TOTP et passwords
- 📁 **LDAP** : Configuration Active Directory
- 📡 **RADIUS** : Serveurs d'authentification
- 🔐 **TACACS+** : Serveurs TACACS+
- 🔗 **SSO** : Agents SSO et Terminal Services

### VPN
- 🔒 **IPSEC VPN** : Tunnels avec détection aggressive mode
- 🔓 **SSL VPN** : Configuration et zones d'accès

### Système
- 📊 **System Info** : Informations système (à implémenter)

---

## 🎨 Interface

- **Design moderne** : Cards, accordions, badges
- **Animations** : Transitions fluides, pulse, bounce
- **Responsive** : Adaptatif pour différentes résolutions
- **Couleurs sémantiques** :
  - 🔴 Rouge : Risques critiques (TOTP, WAN, Aggressive VPN)
  - 🟠 Orange : Warnings (Shared secrets, Bind passwords)
  - 🟢 Vert : OK / Actif
  - ⚪ Gris : Neutre / Inactif

---

## 🔧 Maintenance

### Nettoyer la base de données

```bash
# Supprimer la DB et la clé (réinitialisation complète)
rm instance/firewalls.db
rm encryption.key

# Redémarrer l'app
python app.py

# Note: Vous perdrez tous vos firewalls !
```

### Restaurer depuis un backup

```bash
# Copier les fichiers de backup
cp backups/firewalls_YYYYMMDD_HHMMSS.db instance/firewalls.db
cp backups/encryption_YYYYMMDD_HHMMSS.key encryption.key

# Redémarrer l'app
python app.py
```

---

## 📞 Support & Documentation

- 📖 [README.md](README.md) - Documentation principale
- 🔐 [DATABASE_SECURITY.md](DATABASE_SECURITY.md) - Sécurité détaillée
- 📡 [API_ENDPOINTS.md](API_ENDPOINTS.md) - Endpoints SonicWall


