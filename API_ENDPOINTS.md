# SonicWall API Endpoints Documentation

## 📋 Endpoints API SonicWall Utilisés

### 🔐 Authentification
- **POST** `/api/sonicos/auth` - Authentification standard
- **POST** `/api/sonicos/tfa` - Authentification avec 2FA
- **POST** `/api/sonicos/config-mode` - Démarrage de session de management

### 🌐 WAN Management
- **GET** `/api/sonicos/config/management` - Configuration du management
- **GET** `/api/sonicos/config/access-rules` - Règles d'accès
- **GET** `/api/sonicos/config/network/interfaces` - Interfaces réseau

### 👥 Active Directory
- **GET** `/api/sonicos/config/authentication/active-directory` - Configuration AD
- **GET** `/api/sonicos/config/authentication/servers` - Serveurs d'authentification
- **GET** `/api/sonicos/config/authentication/groups` - Groupes d'authentification

### 🔐 IPSEC VPN
- **GET** `/api/sonicos/vpn/policies/ipv4/site-to-site` - Configuration VPN site-to-site IPv4
- **GET** `/api/sonicos/vpn/policies/ipv4/group-vpn` - Configuration VPN de groupe IPv4
- **GET** `/api/sonicos/status/vpn/ipsec` - Statut des tunnels IPSEC

## 🚀 Endpoints de l'Application

### 🔍 Test de Connexion
- **POST** `/api/test-connection` - Tester la connexion à un firewall

### 🌐 WAN Management
- **POST** `/api/wan-management` - Vérifier le management WAN

### 👥 Active Directory
- **POST** `/api/active-directory` - Vérifier la configuration AD

### 🔐 IPSEC VPN
- **POST** `/api/ipsec-vpn` - Vérifier les tunnels VPN

### ⚙️ Commandes Génériques
- **POST** `/api/execute-command` - Exécuter une commande API générique

## 📊 Structure des Réponses

### WAN Management Response
```json
{
  "success": true,
  "wan_management_enabled": true,
  "wan_to_wan_rules": [
    {
      "name": "WAN-to-WAN Management",
      "enabled": true,
      "source": "WAN",
      "destination": "WAN"
    }
  ],
  "message": "WAN management check completed"
}
```

### Active Directory Response
```json
{
  "success": true,
  "ad_enabled": true,
  "bind_password": "••••••••",
  "domain": "example.com",
  "server": "192.168.1.10",
  "message": "Active Directory check completed"
}
```

### IPSEC VPN Response
```json
{
  "success": true,
  "tunnels": [
    {
      "name": "Site-to-Site VPN",
      "enabled": true,
      "mode": "main",
      "primary_gateway": "203.0.113.1",
      "secondary_gateway": "203.0.113.2",
      "shared_secret": "Manual Key Configured",
      "encryption_key": "Not available",
      "auth_key": "Not available",
      "local_network": "Any",
      "remote_network": "Configured",
      "keep_alive": true,
      "anti_replay": true,
      "status": "active"
    }
  ],
  "message": "IPSEC VPN check completed"
}
```

## 🔧 Configuration Requise

### Activation de l'API SonicOS
1. Accéder à l'interface de gestion du firewall
2. Naviguer vers `Device > Settings > Administration - Audit/SonicOS API`
3. Activer l'option `SonicOS API`

### Authentification
- Utiliser l'authentification HTTP Basic Access
- Format : `username:password` en base64
- Headers requis : `Authorization: Basic <base64_credentials>`

### Ports et Protocoles
- **HTTPS** : Port 443 (par défaut)
- **HTTP** : Port 80 (non recommandé)
- **Ports personnalisés** : Supportés (ex: 8443, 8080)

## 🛠️ Utilisation avec Postman

### Configuration de Base
1. **Method** : GET/POST
2. **URL** : `https://<firewall_ip>:443/api/sonicos/<endpoint>`
3. **Authorization** : Basic Auth
4. **Headers** : `Content-Type: application/json`

### Exemple de Requête
```http
GET https://192.168.1.1:443/api/sonicos/config/management
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Content-Type: application/json
```

## 📝 Notes Importantes

### Sécurité
- Toujours utiliser HTTPS
- Changer les mots de passe par défaut
- Limiter l'accès à l'API par IP
- Utiliser des certificats SSL valides

### Limitations
- Certains endpoints peuvent nécessiter des privilèges élevés
- Les réponses peuvent varier selon la version de SonicOS
- Certaines configurations peuvent être en lecture seule

### Dépannage
- Vérifier que l'API est activée
- Confirmer les identifiants
- Vérifier la connectivité réseau
- Consulter les logs du firewall

## 🔗 Ressources Utiles

- [Documentation officielle SonicWall API](https://www.sonicwall.com/support/knowledge-base/introduction-to-sonicos-api/200818060121313)
- [Guide d'authentification Postman](https://www.sonicwall.com/support/knowledge-base/authenticating-to-sonicwall-firewall-api-using-postman/220830164502210)
- [Bibliothèque Python sonicwall-api-client](https://pypi.org/project/sonicwall-api-client/)

---

**Note** : Cette documentation est basée sur les endpoints API SonicWall standard. Certains endpoints peuvent varier selon la version de SonicOS et la configuration du firewall.
