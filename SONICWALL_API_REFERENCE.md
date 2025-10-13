# SonicWall API - Référence Complète

## 🔐 Authentification & Sessions

### POST /api/sonicos/auth
**Login avec username et password dans le header HTTP d'authentification**

**Request Body:**
```json
{
  "override": true
}
```

**Response:**
```json
{
  "status": {
    "success": true,
    "info": [
      {
        "level": "info",
        "code": "E_OK",
        "message": "Success."
      }
    ]
  }
}
```

### POST /api/sonicos/start-management
**Démarrer une session de management**

**Parameters:** Aucun

**Response:**
```json
{
  "status": {
    "success": true,
    "info": [
      {
        "level": "info",
        "code": "E_OK",
        "message": "Success."
      }
    ]
  }
}
```

### POST /api/sonicos/config/pending
**Commit toutes les configurations en attente (non sauvegardées)**

**Request Body:**
```json
{}
```

**Response:**
```json
{
  "status": {
    "success": true,
    "info": [
      {
        "level": "info",
        "code": "E_OK",
        "message": "Success."
      }
    ]
  }
}
```

---

## 🌐 Objets d'adresse

### POST /api/sonicos/address-objects/ipv4
**Créer un nouvel objet d'adresse IPv4**

**Request Body:**
```json
{
  "address_objects": [
    {
      "ipv4": {
        "name": "string",
        "zone": "string",
        "host": {
          "ip": "string"
        }
      }
    }
  ]
}
```

**Response:**
```json
{
  "status": {
    "success": true,
    "info": [
      {
        "level": "info",
        "code": "E_OK",
        "message": "Success."
      }
    ]
  }
}
```

---

## 🔐 VPN IPSEC - Site-to-Site

### GET /api/sonicos/vpn/policies/ipv4/site-to-site
**Récupérer la configuration des politiques VPN IPv4 site-to-site**

**Response 200:**
```json
{
  "vpn": {
    "policy": [
      {
        "ipv4": {
          "site_to_site": {
            "name": "string",
            "enable": true,
            "auth_method": {
              "manual_key": true
            },
            "gateway": {
              "primary": "string",
              "secondary": "string"
            },
            "proposal": {
              "ike": {
                "exchange": "main",
                "encryption": "des",
                "authentication": "md5",
                "prf": "hmac-md5",
                "dh_group": 1,
                "lifetime": 0
              },
              "ipsec": {
                "protocol": "esp",
                "encryption": {
                  "des": true
                },
                "authentication": {
                  "md5": true
                },
                "perfect_forward_secrecy": {
                  "dh_group": 1
                },
                "lifetime": 0,
                "lifebytes": 0,
                "in_spi": "string",
                "out_spi": "string",
                "encryption_key": "string",
                "authentication_key": "string"
              }
            },
            "network": {
              "local": {
                "any": true
              },
              "remote": {
                "any": true
              }
            },
            "keep_alive": true,
            "suppress_auto_add_rule": true,
            "require_xauth": "string",
            "anti_replay": true,
            "netbios": true,
            "multicast": true,
            "permit_acceleration": true,
            "wxa_group": "string",
            "apply_nat": true,
            "translated_network": {
              "local": {
                "original": true
              },
              "remote": {
                "original": true
              }
            },
            "ocsp_checking": true,
            "responder_url": "string",
            "management": {
              "http": true,
              "https": true,
              "ssh": true,
              "snmp": true
            },
            "user_login": {
              "http": true,
              "https": true
            },
            "default_lan_gateway": "string",
            "bound_to": {
              "zone": "string"
            },
            "preempt_secondary_gateway": {
              "interval": 0
            },
            "suppress_trigger_packet": true,
            "accept_hash": true,
            "send_hash": "string",
            "allow_sonicpointn_layer3": true
          }
        }
      }
    ]
  }
}
```

### PATCH /api/sonicos/vpn/policies/ipv4/site-to-site
**Modifier la configuration VPN IPv4 site-to-site**

**Request Body:** Même structure que GET

---

## 🔒 SSL VPN

### GET /api/sonicos/ssl-vpn/server/base
**Récupérer la configuration du serveur SSL VPN**

**Response 200:**
```json
{
  "ssl_vpn": {
    "server": {
      "port": 0,
      "certificate": {
        "use_self_signed": true
      },
      "auth_type": "password",
      "client_certificate_username_attribute": "common-name",
      "client_certificate_issuer": "string",
      "client_certificate_user_group_method": "local-configured",
      "use_radius": {
        "mschap": true
      },
      "user_domain": "string",
      "management": {
        "web": true,
        "ssh": true
      },
      "session_timeout": 0,
      "mouse_inactivity_check": true,
      "auto_rule": true,
      "download_url": {
        "default": true
      }
    }
  }
}
```

### GET /api/sonicos/ssl-vpn/server/accesses
**Récupérer la configuration des accès du serveur SSL VPN**

**Response 200:**
```json
{
  "ssl_vpn": {
    "server": {
      "access": [
        {
          "enable": true,
          "zone": "string"
        }
      ]
    }
  }
}
```

### GET /api/sonicos/ssl-vpn/device-profiles
**Récupérer la configuration des profils de device SSL VPN**

**Response 200:**
```json
{
  "ssl_vpn": {
    "profile": {
      "device_profile": [
        {
          "name": "string",
          "description": "string",
          "enable": true,
          "action": "allow",
          "network_address": {
            "ipv6": {
              "name": {
                "name": "string",
                "zone": "string"
              }
            },
            "ipv4": {
              "name": {
                "name": "string",
                "zone": "string"
              }
            }
          },
          "wlan_tunnel_interface": "string",
          "client": {
            "dns": {
              "primary": {
                "value": "string"
              },
              "secondary": {
                "value": "string"
              },
              "search_lists": true,
              "search_list": [
                {
                  "search_list": "string"
                }
              ]
            },
            "wins": {
              "primary": {
                "value": "string"
              },
              "secondary": {
                "value": "string"
              }
            },
            "auto_update": true,
            "exit_after_disconnect": true,
            "netbios_over_sslvpn": true,
            "touch_id_authentication": true,
            "fingerprint_authentication": true,
            "uninstall_after_exit": true,
            "create_connection_profile": true,
            "cache": {
              "user_name_only": true
            }
          },
          "routes": {
            "tunnel_all": true,
            "route": [
              {
                "ipv4": {
                  "name": "string"
                }
              },
              {
                "ipv6": {
                  "name": "string"
                }
              }
            ]
          }
        }
      ]
    }
  }
}
```

---

## 👥 Utilisateurs Locaux

### GET /api/sonicos/user/local/base
**Récupérer la configuration de base des utilisateurs locaux**

**Response 200:**
```json
{
  "user": {
    "local": {
      "apply_password_constraints": true,
      "prune_on_expiry": true,
      "inactivity_timeout": 0,
      "prune_on_inactive": true,
      "domain_name_display_format": {
        "name_at_domain": true
      }
    }
  }
}
```

### GET /api/sonicos/user/local/users
**Récupérer tous les utilisateurs locaux**

**Response 200:**
```json
{
  "user": {
    "local": {
      "user": [
        {
          "name": "string",
          "domain": "string",
          "uuid": "string",
          "display_name": "string",
          "password": "string",
          "comment": "string",
          "force_password_change": true,
          "one_time_password": {
            "otp": true
          },
          "account_lifetime": {
            "minutes": 0
          },
          "expiration": {
            "date": "string",
            "time": "string"
          },
          "prune_on_expiry": true,
          "quota_cycle": {
            "day": true
          },
          "session_lifetime": {
            "minutes": 0
          },
          "limit": {
            "receive": 0,
            "transmit": 0
          },
          "email_address": "string",
          "guest_login_uniqueness": true,
          "guest_idle_timeout": {
            "minutes": 0
          },
          "member_of": [
            {
              "name": "string"
            }
          ],
          "vpn_client_access": [
            {
              "name": "string"
            },
            {
              "group": "string"
            }
          ],
          "bookmark": [
            {
              "name": "string",
              "host": "string",
              "service": {
                "rdp": {
                  "screen_size": "640x480",
                  "colors": 256,
                  "application_path": "string",
                  "start_in_folder": "string",
                  "automatic_login": {
                    "ssl_vpn": true
                  },
                  "redirect_clipboard": true,
                  "redirect_audio": true,
                  "auto_reconnection": true,
                  "desktop_background": true,
                  "window_drag": true,
                  "animation": true,
                  "display_on_mobile": true
                },
                "vnc": {
                  "view_only": true,
                  "share_desktop": true,
                  "display_on_mobile": true
                },
                "telnet": {
                  "display_on_mobile": true
                },
                "sshv2": {
                  "automatic_accept_host_key": true,
                  "display_on_mobile": true
                }
              }
            }
          ],
          "restrict_until_password_reset": {
            "block_remote_access": true
          }
        }
      ]
    }
  }
}
```

### PATCH /api/sonicos/user/local/users
**Modifier la configuration des utilisateurs locaux**

**Request Body:**
```json
{
  "user": {
    "local": {
      "user": [
        {
          "name": "string",
          "domain": "string",
          "display_name": "string",
          "password": "string",
          "comment": "string",
          "force_password_change": true,
          "one_time_password": {
            "otp": true
          },
          "account_lifetime": {
            "minutes": 0
          },
          "expiration": {
            "date": "string",
            "time": "string"
          },
          "prune_on_expiry": true,
          "quota_cycle": {
            "day": true
          },
          "session_lifetime": {
            "minutes": 0
          },
          "limit": {
            "receive": 0,
            "transmit": 0
          },
          "email_address": "string",
          "guest_login_uniqueness": true,
          "guest_idle_timeout": {
            "minutes": 0
          },
          "member_of": [
            {
              "name": "string"
            }
          ],
          "vpn_client_access": [
            {
              "name": "string"
            },
            {
              "group": "string"
            }
          ],
          "bookmark": [
            {
              "name": "string",
              "host": "string"
            }
          ],
          "restrict_until_password_reset": {
            "block_remote_access": true
          }
        }
      ]
    }
  }
}
```

### POST /api/sonicos/user/local/unbind-totp-key/{NAME}
**Délier la clé TOTP d'un utilisateur spécifique**

**Parameters:**
- `NAME` (path, required): Nom de l'utilisateur - Format: WORD ou "QUOTED STRING"

**Request Body:**
```json
{}
```

**Response:**
```json
{
  "status": {
    "success": true,
    "info": [
      {
        "level": "info",
        "code": "E_OK",
        "message": "Success."
      }
    ]
  }
}
```

### POST /api/sonicos/user/local/unbind-totp-key/{NAME}/domain/{DOMAIN}
**Délier la clé TOTP d'un utilisateur dans un domaine spécifique**

**Parameters:**
- `NAME` (path, required): Nom de l'utilisateur
- `DOMAIN` (path, required): Nom du domaine

**Request Body:**
```json
{}
```

### POST /api/sonicos/user/local/force-users-password-change
**Forcer plusieurs utilisateurs à changer leur mot de passe au prochain login**

**Request Body:**
```json
{
  "user": {
    "local": {
      "force_users_password_change": {
        "for_admin": true,
        "for_admin_users": true,
        "for_general_users": true
      }
    }
  }
}
```

**Response:**
```json
{
  "status": {
    "success": true,
    "info": [
      {
        "level": "info",
        "code": "E_OK",
        "message": "Success."
      }
    ]
  }
}
```

---

## 📡 LDAP/Active Directory

### GET /api/sonicos/user/ldap/servers
**Récupérer la configuration des serveurs LDAP**

**Structure de réponse:**
```json
{
  "user": {
    "ldap": {
      "server": [
        {
          "host": "192.168.1.1",
          "port": 389,
          "enable": true,
          "use_tls": false,
          "directory": {
            "primary_domain": "domain.lan"
          },
          "bind": {
            "acct": {
              "name": "ldapbind",
              "location": "domain.lan"
            }
          },
          "schema": "microsoft-active-directory"
        }
      ]
    }
  }
}
```

---

## 🔐 RADIUS

### GET /api/sonicos/user/radius
**Récupérer la configuration RADIUS**

**Structure de réponse:**
```json
{
  "user": {
    "radius": {
      "server": [
        {
          "enable": true,
          "host": "192.168.1.241",
          "port": 1812,
          "send_through_vpn_tunnel": false,
          "shared_secret": "encrypted_value",
          "user_name_format": {
            "user_name": true
          }
        }
      ]
    }
  }
}
```

---

## 🔐 TACACS+

### GET /api/sonicos/user/tacacs
**Récupérer la configuration TACACS+**

**Structure de réponse (similaire à RADIUS):**
```json
{
  "user": {
    "tacacs": {
      "server": [
        {
          "enable": true,
          "host": "string",
          "port": 49,
          "shared_secret": "encrypted_value"
        }
      ]
    }
  }
}
```

---

## 🔑 SSO (Single Sign-On)

### GET /api/sonicos/user/sso/base
**Configuration de base SSO**

### GET /api/sonicos/user/sso/agents
**Liste des agents SSO**

**Response:**
```json
{
  "user": {
    "sso": {
      "agent": [
        {
          "name": "string",
          "ip": "string",
          "shared_key": "encrypted_value"
        }
      ]
    }
  }
}
```

### GET /api/sonicos/user/sso/terminal-services-agents
**Liste des agents Terminal Services**

**Response:**
```json
{
  "user": {
    "sso": {
      "terminal_services_agent": [
        {
          "name": "string",
          "shared_key": "encrypted_value"
        }
      ]
    }
  }
}
```

### GET /api/sonicos/user/sso/radius-accounting-clients
**Liste des clients RADIUS Accounting**

**Response:**
```json
{
  "user": {
    "sso": {
      "radius_accounting_client": [
        {
          "name": "string",
          "shared_secret": "encrypted_value"
        }
      ]
    }
  }
}
```

---

## 🌐 WAN Management

### GET /api/sonicos/config/management
**Configuration du management**

### GET /api/sonicos/access-rules/ipv4
**Règles d'accès IPv4**

### GET /api/sonicos/config/network/interfaces
**Interfaces réseau**

---

## 📞 PPPoE/PPTP/L2TP

### GET /api/sonicos/user/ppp
**Configuration PPP (PPPoE/PPTP/L2TP)**

---

## ☁️ Cloud Secure Edge (CSE)

### GET /api/sonicos/cloud-secure-edge/base
**Configuration de base CSE**

### GET /api/sonicos/cloud-secure-edge/connectors
**Liste des connecteurs CSE**

**Response:**
```json
{
  "cloud_secure_edge": {
    "connector": [
      {
        "name": "string",
        "enable": true
      }
    ]
  }
}
```

---

## 📝 Notes d'implémentation

### Authentification
- Utiliser **HTTPDigestAuth** pour toutes les requêtes
- Format: `HTTPDigestAuth(username, password)`
- Certificats auto-signés: utiliser `verify=False`

### Gestion d'URL
- Port par défaut: **443** (HTTPS)
- Format: `https://{ip}:{port}/api/sonicos/{endpoint}`
- Gérer les IP avec ou sans port

### Extraction de données
La plupart des réponses suivent cette structure:
```json
{
  "parent_key": {
    "config_type": {
      "item_or_items": [...] ou {...}
    }
  }
}
```

**Attention:** 
- Les listes peuvent être des objets uniques
- Toujours vérifier le type avec `isinstance()`
- Les clés imbriquées peuvent être absentes

### Gestion d'erreurs typiques

#### Code 400 - Bad Request
- Endpoint incorrect
- Structure de données invalide
- Essayer des endpoints alternatifs

#### Code 401 - Unauthorized  
- Credentials incorrects
- API non activée sur le firewall
- Session expirée

#### Code 404 - Not Found
- Endpoint n'existe pas dans cette version de SonicOS
- Route non implémentée

---

## 🛠️ Endpoints alternatifs testés

### RADIUS
- `/api/sonicos/user/radius` ✅
- `/api/sonicos/user/radius/servers`
- `/api/sonicos/config/authentication/radius`

### TACACS+
- `/api/sonicos/user/tacacs` ✅
- `/api/sonicos/user/tacacs/servers`
- `/api/sonicos/config/authentication/tacacs`

### SSL VPN
- `/api/sonicos/ssl-vpn/server/base` ✅
- `/api/sonicos/ssl-vpn/settings`
- `/api/sonicos/ssl-vpn`
- `/api/sonicos/vpn/ssl`

### PPPoE/PPTP/L2TP
- `/api/sonicos/user/ppp` ✅
- `/api/sonicos/pppoe`
- `/api/sonicos/config/ppp`

---

## 💡 Bonnes pratiques

1. **Toujours tester plusieurs endpoints** si l'un échoue
2. **Vérifier les types de données** avant `.get()`
3. **Gérer les listes ET objets uniques** (ex: 1 serveur = objet, plusieurs = liste)
4. **Utiliser des timeouts** (15s recommandé)
5. **Logger les erreurs** pour debugging
6. **Retourner des structures vides** plutôt que des erreurs si non configuré

---

## 📚 Ressources

- [Documentation officielle SonicWall API](https://www.sonicwall.com/support/knowledge-base/introduction-to-sonicos-api/200818060121313)
- [Guide Postman](https://www.sonicwall.com/support/knowledge-base/authenticating-to-sonicwall-firewall-api-using-postman/220830164502210)

