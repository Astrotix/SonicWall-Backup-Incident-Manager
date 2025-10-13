# Console de Management SonicWall

Une application web légère pour gérer et surveiller vos firewalls SonicWall de manière centralisée.

## 🚀 Caractéristiques

- ✅ **Installation minimale** : Seulement Python et quelques packages
- 🔐 **Chiffrement AES-256** : Mots de passe chiffrés en base de données
- 💾 **Base de données SQLite** : Stockage persistant (survit aux redémarrages)
- 🔐 **Support de l'authentification 2FA** : Compatible avec les firewalls nécessitant une authentification à deux facteurs
- 📊 **Gestion centralisée** : Gérez plusieurs firewalls depuis une seule interface
- 🔄 **Test de connexion** : Vérifiez l'état de connexion de vos firewalls en temps réel
- 🎨 **Interface moderne** : Interface utilisateur intuitive et responsive
- 👥 **Gestion des utilisateurs** : LOCAL Users, LDAP, RADIUS, TACACS+, SSO
- 🌐 **WAN Management** : Surveillance des règles d'accès avec alertes de sécurité
- 🔒 **VPN Monitoring** : IPSEC et SSL VPN avec détection des modes dangereux

## 📋 Prérequis

- Python 3.7 ou supérieur
- Accès réseau aux firewalls SonicWall via leurs IP publiques

## ⚙️ Installation

### 1. Installation de Python (si nécessaire)

Téléchargez et installez Python depuis [python.org](https://www.python.org/downloads/)

### 2. Installation des dépendances

Ouvrez un terminal/PowerShell dans le dossier de l'application et exécutez :

```bash
pip install -r requirements.txt
```

## 🎯 Utilisation

### Démarrage de l'application

1. Ouvrez un terminal/PowerShell dans le dossier de l'application
2. Exécutez la commande :

```bash
python app.py
```

3. Ouvrez votre navigateur web et accédez à : `http://localhost:5000`

### Ajout d'un firewall

1. Dans le formulaire de gauche, entrez :
   - **IP Publique** : L'adresse IP ou URL du firewall (ex: `192.168.1.1` ou `https://firewall.example.com`)
   - **Nom d'utilisateur** : Votre identifiant d'administration
   - **Mot de passe** : Votre mot de passe

2. Cliquez sur **"Ajouter le Firewall"**

3. Si le firewall nécessite une authentification 2FA :
   - Un champ apparaîtra pour entrer le code 2FA
   - Entrez le code et validez à nouveau

### Gestion des firewalls

- **Tester la connexion** : Vérifiez si le firewall est accessible
- **Supprimer** : Retirez un firewall de la liste
- **Statut** : Visualisez l'état de connexion (Connecté/Déconnecté)

## 🔒 Sécurité

### 🔐 Chiffrement des mots de passe

- ✅ **Chiffrement AES-256** : Tous les mots de passe sont chiffrés en base de données
- ✅ **Clé unique** : Générée automatiquement au premier lancement (`encryption.key`)
- ✅ **Aucun mot de passe en clair** : Impossible de lire les mots de passe sans la clé
- ⚠️ **SAUVEGARDEZ `encryption.key`** : Sans ce fichier, vous ne pourrez pas déchiffrer vos mots de passe !

### 💾 Backup de la configuration

Pour sauvegarder vos firewalls :

```bash
python backup_db.py
```

Cela créera un backup horodaté dans le dossier `backups/` :
- `firewalls_YYYYMMDD_HHMMSS.db` (base de données)
- `encryption_YYYYMMDD_HHMMSS.key` (clé de chiffrement)

### Important en production

- ✅ Mots de passe chiffrés (déjà fait)
- 🔧 Utiliser HTTPS (recommandé)
- 🔧 Implémenter une authentification pour accéder à la console (recommandé)
- 🔧 Limiter l'accès réseau à l'application (firewall/VPN)

### Certificats SSL

L'application désactive la vérification SSL par défaut pour faciliter l'utilisation avec des certificats auto-signés. Si vous utilisez des certificats valides, modifiez le paramètre `verify=False` en `verify=True` dans `app.py`.

## 📚 API SonicWall

L'application utilise l'API REST SonicOS. Pour plus d'informations :
- [Documentation officielle SonicWall API](https://www.sonicwall.com/support/knowledge-base/introduction-to-sonicos-api/200818060121313)

### Endpoints utilisés

- `POST /api/sonicos/auth` : Authentification standard
- `POST /api/sonicos/tfa` : Authentification avec 2FA
- `POST /api/sonicos/config-mode` : Démarrage de session de management

## 🛠️ Dépannage

### Le firewall ne se connecte pas

1. Vérifiez que l'IP est correcte et accessible
2. Vérifiez les identifiants
3. Assurez-vous que l'API est activée sur le firewall SonicWall
4. Vérifiez les règles de pare-feu qui pourraient bloquer l'accès

### Erreur de timeout

- Vérifiez la connectivité réseau
- Augmentez le timeout dans `app.py` si nécessaire

### Erreur de certificat SSL

- L'application accepte les certificats auto-signés par défaut
- Vérifiez que le firewall est accessible via HTTPS

## 📝 Configuration avancée

### Changer le port de l'application

Modifiez la dernière ligne de `app.py` :

```python
app.run(debug=True, host='0.0.0.0', port=5000)  # Changez 5000 par le port désiré
```

### Accès depuis d'autres machines

L'application est configurée pour accepter les connexions depuis n'importe quelle machine (`host='0.0.0.0'`). 

Accédez à l'application depuis une autre machine via : `http://[IP_DU_SERVEUR]:5000`

## 📞 Support

Pour toute question concernant l'API SonicWall, consultez la documentation officielle ou contactez le support SonicWall.

## 📄 Licence

Cette application est fournie à titre d'exemple. Utilisez-la à vos propres risques.

---

**Note** : Cette application est conçue pour faciliter la gestion de firewalls SonicWall. Assurez-vous de respecter les bonnes pratiques de sécurité lors de son déploiement en environnement de production.


