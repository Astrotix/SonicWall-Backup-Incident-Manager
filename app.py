from flask import Flask, render_template, request, jsonify, send_file
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import json
import urllib3
from models import db, Firewall, ModuleResolutionStatus, RemediationAction, StateVerification, CSERemediationTimer
import os
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect, Circle, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics import renderPDF
from reportlab.graphics.widgets.markers import makeMarker
import io
from datetime import datetime, timedelta

# Désactiver les avertissements SSL pour les certificats auto-signés
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# Helper function pour authentification et requêtes SonicWall
def sw_authenticated_request(base_url, username, password, endpoint, method='GET', data=None):
    """
    Authentifie, exécute une requête, et commit si c'est une modification
    Returns: (response, status_code) ou (None, error_code)
    """
    try:
        print(f"[AUTH] Step 1: Authentification vers {base_url}/api/sonicos/auth")
        # 1. Authentification
        auth_url = f'{base_url}/api/sonicos/auth'
        auth_resp = requests.post(auth_url, auth=HTTPDigestAuth(username, password), verify=False, timeout=10)
        print(f"[AUTH] Auth status: {auth_resp.status_code}")
        if auth_resp.status_code not in [200, 201]:
            return None, auth_resp.status_code
        
        cookies = auth_resp.cookies
        
        # 2. Mode config si c'est une modification
        if method in ['PATCH', 'PUT', 'POST', 'DELETE']:
            print(f"[AUTH] Step 2: Entering config mode")
            config_url = f'{base_url}/api/sonicos/config-mode'
            config_resp = requests.post(config_url, auth=HTTPDigestAuth(username, password), cookies=cookies, verify=False, timeout=10)
            print(f"[AUTH] Config mode status: {config_resp.status_code}")
        
        # 3. Requête principale
        print(f"[AUTH] Step 3: {method} request to {endpoint}")
        url = f'{base_url}/api/sonicos/{endpoint}'
        kwargs = {'auth': HTTPDigestAuth(username, password), 'cookies': cookies, 'verify': False, 'timeout': 15}
        
        if method == 'GET':
            resp = requests.get(url, **kwargs)
        elif method == 'POST':
            # Ne pas envoyer json= si data est None ou {}
            if data:
                resp = requests.post(url, json=data, **kwargs)
            else:
                resp = requests.post(url, **kwargs)
        elif method == 'PATCH':
            if data:
                resp = requests.patch(url, json=data, **kwargs)
            else:
                resp = requests.patch(url, **kwargs)
        elif method == 'PUT':
            resp = requests.put(url, json=data, **kwargs)
        else:
            resp = requests.delete(url, **kwargs)
        
        print(f"[AUTH] Main request status: {resp.status_code}")
        
        # Debug : afficher la réponse si erreur
        if resp.status_code >= 400:
            try:
                error_text = resp.text
                print(f"[AUTH] ERROR Response: {error_text[:500]}")
            except:
                print(f"[AUTH] ERROR Response: Could not read response text")
        
        # 4. Commit si modification réussie
        if method in ['PATCH', 'PUT', 'POST', 'DELETE'] and resp.status_code in [200, 201, 204]:
            print(f"[AUTH] Step 4: Committing changes")
            pending_url = f'{base_url}/api/sonicos/config/pending'
            pending_resp = requests.post(pending_url, json={}, auth=HTTPDigestAuth(username, password), cookies=cookies, verify=False, timeout=10)
            print(f"[AUTH] Commit status: {pending_resp.status_code}")
        
        return resp, resp.status_code
    except Exception as e:
        print(f"ERREUR dans sw_authenticated_request: {e}")
        import traceback
        traceback.print_exc()
        return None, 500



# Helper function pour créer une session authentifiée
def create_authenticated_session(base_url, username, password):
    """
    Créer une session authentifiée avec le firewall SonicWall
    Retourne (session, success, error_message)
    """
    try:
        session = requests.Session()
        session.auth = HTTPDigestAuth(username, password)
        session.verify = False
        
        # S'authentifier
        auth_url = f'{base_url}/api/sonicos/auth'
        auth_response = session.post(auth_url, timeout=10)
        
        if auth_response.status_code in [200, 201]:
            return session, True, None
        else:
            return None, False, f"Auth failed: {auth_response.status_code}"
    except Exception as e:
        return None, False, str(e)

def get_base_url(ip):
    """
    Construire l'URL de base pour l'API SonicWall
    Gère les IP avec ou sans port
    """
    ip = ip.strip()
    if not ip.startswith('http'):
        base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
    else:
        base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
    return base_url

# Configuration de la base de données
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'firewalls.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialiser la base de données
db.init_app(app)

# Activer les contraintes de clés étrangères pour SQLite
from sqlalchemy import event
from sqlalchemy.engine import Engine

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# Créer les tables si elles n'existent pas
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

# ========================================
# Routes API pour la gestion des firewalls
# ========================================

@app.route('/api/firewalls', methods=['GET'])
def get_firewalls():
    """
    Récupérer tous les firewalls de la base de données
    """
    try:
        firewalls = Firewall.query.all()
        return jsonify({
            'success': True,
            'firewalls': [firewall.to_dict() for firewall in firewalls]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erreur lors de la récupération des firewalls: {str(e)}'
        }), 500

@app.route('/api/firewalls', methods=['POST'])
def add_firewall():
    """
    Ajouter un nouveau firewall à la base de données
    """
    try:
        data = request.json
        name = data.get('name')
        ip = data.get('ip')
        username = data.get('username')
        password = data.get('password')
        otp = data.get('otp', False)
        
        if not all([name, ip, username, password]):
            return jsonify({
                'success': False,
                'message': 'Tous les champs sont requis'
            }), 400
        
        # Vérifier si le firewall existe déjà
        existing = Firewall.query.filter_by(ip=ip).first()
        if existing:
            return jsonify({
                'success': False,
                'message': 'Un firewall avec cette adresse IP existe déjà'
            }), 400
        
        firewall = Firewall(
            name=name,
            ip=ip,
            username=username,
            password=password,
            otp=otp
        )
        
        db.session.add(firewall)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Firewall ajouté avec succès',
            'firewall': firewall.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Erreur lors de l\'ajout du firewall: {str(e)}'
        }), 500

@app.route('/api/firewalls/<int:firewall_id>', methods=['PUT'])
def update_firewall(firewall_id):
    """
    Mettre à jour un firewall existant
    """
    try:
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({
                'success': False,
                'message': 'Firewall non trouvé'
            }), 404
        
        data = request.json
        firewall.name = data.get('name', firewall.name)
        firewall.username = data.get('username', firewall.username)
        firewall.otp = data.get('otp', firewall.otp)
        
        if data.get('password'):
            firewall.set_password(data['password'])
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Firewall mis à jour avec succès',
            'firewall': firewall.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Erreur lors de la mise à jour: {str(e)}'
        }), 500

@app.route('/api/firewalls/<int:firewall_id>', methods=['DELETE'])
def delete_firewall(firewall_id):
    """
    Supprimer un firewall et tous ses enregistrements liés
    """
    try:
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({
                'success': False,
                'message': 'Firewall non trouvé'
            }), 404
        
        # Supprimer d'abord tous les enregistrements liés
        from models import ModuleResolutionStatus, RemediationAction, StateVerification, CSERemediationTimer
        
        # Supprimer les statuts de résolution
        ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id).delete()
        
        # Supprimer les actions de remédiation
        RemediationAction.query.filter_by(firewall_id=firewall_id).delete()
        
        # Supprimer les vérifications d'état
        StateVerification.query.filter_by(firewall_id=firewall_id).delete()
        
        # Supprimer les timers CSE
        CSERemediationTimer.query.filter_by(firewall_id=firewall_id).delete()
        
        # Maintenant supprimer le firewall
        db.session.delete(firewall)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Firewall et toutes ses données supprimés avec succès'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Erreur lors de la suppression: {str(e)}'
        }), 500

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """
    Tester la connexion à un firewall SonicWall
    """
    try:
        data = request.json
        ip = data.get('ip')
        username = data.get('username')
        password = data.get('password')
        otp_code = data.get('otp_code', '')
        
        if not ip or not username or not password:
            return jsonify({
                'success': False,
                'message': 'IP, username et password sont requis'
            }), 400
        
        # Nettoyer l'IP et construire l'URL de base
        ip = ip.strip()
        if not ip.startswith('http'):
            # Si l'IP contient un port, l'utiliser, sinon utiliser le port par défaut 443
            if ':' in ip and not ip.endswith(':443'):
                base_url = f'https://{ip}'
            else:
                base_url = f'https://{ip}:443'
        else:
            base_url = ip
            
        # Si OTP/2FA est fourni, utiliser l'endpoint /tfa
        if otp_code:
            url = f'{base_url}/api/sonicos/tfa'
            payload = {
                'user': username,
                'password': password,
                'tfa': otp_code,
                'override': True
            }
            
            print(f"Authentification avec OTP pour {ip}")
            
            response = requests.post(
                url,
                json=payload,
                verify=False,
                timeout=10
            )
        else:
            # Authentification standard avec Basic Auth
            url = f'{base_url}/api/sonicos/auth'
            
            print(f"Authentification standard pour {ip}")
            
            response = requests.post(
                url,
                auth=HTTPDigestAuth(username, password),
                verify=False,
                timeout=10
            )
        
        # Vérifier la réponse
        if response.status_code in [200, 201]:
            # Essayer de démarrer une session de management
            session = response.cookies if hasattr(response, 'cookies') else None
            
            config_mode_url = f'{base_url}/api/sonicos/config-mode'
            config_response = requests.post(
                config_mode_url,
                auth=HTTPDigestAuth(username, password),
                cookies=session,
                verify=False,
                timeout=10
            )
            
            response_data = response.json() if response.content else {}
            
            return jsonify({
                'success': True,
                'message': 'Connexion réussie',
                'requires_2fa': False,
                'data': response_data
            })
        elif response.status_code == 401:
            # Vérifier si 2FA est requis
            try:
                error_data = response.json()
                error_message = str(error_data)
                
                if '2fa' in error_message.lower() or 'two-factor' in error_message.lower():
                    return jsonify({
                        'success': False,
                        'message': 'Authentification à deux facteurs requise',
                        'requires_2fa': True
                    })
            except:
                pass
            
            return jsonify({
                'success': False,
                'message': 'Authentification échouée - Vérifiez les identifiants',
                'requires_2fa': False
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Erreur de connexion: {response.status_code}',
                'requires_2fa': False
            })
            
    except requests.exceptions.Timeout:
        return jsonify({
            'success': False,
            'message': 'Timeout - Le firewall ne répond pas'
        }), 504
    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'message': 'Erreur de connexion - Vérifiez l\'IP du firewall'
        }), 503
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@app.route('/api/execute-command', methods=['POST'])
def execute_command():
    """
    Exécuter une commande API sur un firewall SonicWall
    """
    try:
        data = request.json
        ip = data.get('ip')
        username = data.get('username')
        password = data.get('password')
        endpoint = data.get('endpoint')
        method = data.get('method', 'GET').upper()
        payload = data.get('payload')
        
        if not ip or not username or not password or not endpoint:
            return jsonify({
                'success': False,
                'message': 'Paramètres manquants'
            }), 400
        
        # Construire l'URL
        ip = ip.strip()
        if not ip.startswith('http'):
            # Si l'IP contient un port, l'utiliser, sinon utiliser le port par défaut 443
            if ':' in ip and not ip.endswith(':443'):
                base_url = f'https://{ip}'
            else:
                base_url = f'https://{ip}:443'
        else:
            base_url = ip
            
        url = f'{base_url}/api/sonicos/{endpoint}'
        
        # Préparer la requête
        kwargs = {
            'auth': HTTPDigestAuth(username, password),
            'verify': False,
            'timeout': 30
        }
        
        if payload and method in ['POST', 'PUT', 'PATCH']:
            kwargs['json'] = payload
        
        # Exécuter la requête
        if method == 'GET':
            response = requests.get(url, **kwargs)
        elif method == 'POST':
            response = requests.post(url, **kwargs)
        elif method == 'PUT':
            response = requests.put(url, **kwargs)
        elif method == 'DELETE':
            response = requests.delete(url, **kwargs)
        elif method == 'PATCH':
            response = requests.patch(url, **kwargs)
        else:
            return jsonify({
                'success': False,
                'message': f'Méthode HTTP non supportée: {method}'
            }), 400
        
        # Retourner la réponse
        try:
            response_data = response.json()
        except:
            response_data = response.text
        
        return jsonify({
            'success': response.status_code in [200, 201, 202, 204],
            'status_code': response.status_code,
            'data': response_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erreur: {str(e)}'
        }), 500

@app.route('/api/wan-management', methods=['POST'])
def check_wan_management():
    """
    Vérifier le statut du management WAN et les règles WAN-to-WAN
    """
    try:
        data = request.json
        ip = data.get('ip')
        username = data.get('username')
        password = data.get('password')
        
        if not ip or not username or not password:
            return jsonify({
                'success': False,
                'message': 'Paramètres manquants'
            }), 400
        
        # Construire l'URL
        ip = ip.strip()
        if not ip.startswith('http'):
            if ':' in ip and not ip.endswith(':443'):
                base_url = f'https://{ip}'
            else:
                base_url = f'https://{ip}:443'
        else:
            base_url = ip
        
        # Endpoints à vérifier pour le management WAN
        endpoints = [
            'config/management',
            'access-rules/ipv4',
            'config/network/interfaces'
        ]
        
        wan_management_enabled = False
        wan_to_wan_rules = []
        https_source = 'Not configured'
        
        for endpoint in endpoints:
            try:
                # Utiliser sw_authenticated_request
                response, status = sw_authenticated_request(base_url, username, password, endpoint, 'GET')
                
                if response and status == 200:
                    data = response.json()
                    
                    # Vérifier si le management WAN est activé et récupérer la source HTTPS
                    if 'management' in endpoint:
                        management_config = data.get('management', {})
                        wan_management_enabled = management_config.get('wan_management_enabled', False)
                        
                        # Extraire la source HTTPS management
                        https_source = None
                        try:
                            interface_config = management_config.get('interface', {})
                            ipv4_config = interface_config.get('ipv4', {})
                            management_config_detail = ipv4_config.get('management', {})
                            https_config = management_config_detail.get('https', {})
                            source_config = https_config.get('source', {})
                            https_source = source_config.get('name', 'Not configured')
                        except:
                            https_source = 'Not configured'
                    
                    # Récupérer et filtrer les règles d'accès WAN-to-WAN HTTPS Management
                    if 'access-rules/ipv4' in endpoint:
                        rules = data.get('access_rules', [])
                        wan_to_wan_rules = []
                        
                        for rule in rules:
                            ipv4_rule = rule.get('ipv4', {})
                            
                            # Debug: Afficher la structure complète d'une règle
                            if ipv4_rule.get('management', False):
                                print(f"Management rule found: {ipv4_rule.get('name', 'Unnamed')}")
                                print(f"Full rule structure: {ipv4_rule}")
                            
                            # Vérifier si c'est une règle WAN-to-WAN
                            from_zone = ipv4_rule.get('from', '')
                            to_zone = ipv4_rule.get('to', '')
                            
                            if from_zone == 'WAN' and to_zone == 'WAN':
                                # Vérifier si c'est une règle de management HTTPS
                                service = ipv4_rule.get('service', {})
                                management = ipv4_rule.get('management', False)
                                
                                # Debug: Afficher la structure du service
                                print(f"Service structure: {service}")
                                
                                # Exclure les règles GMS Addresses
                                source_address = ipv4_rule.get('source', {}).get('address', {})
                                source_name = source_address.get('name', '')
                                source_group = source_address.get('group', '')
                                
                                # Debug: Afficher la structure complète de l'adresse source
                                print(f"Source address structure: {source_address}")
                                print(f"Source name: {source_name}")
                                print(f"Source group: {source_group}")
                                
                                # Exclure les règles GMS Addresses (vérifier dans name ET group)
                                is_gms = ('gms' in source_name.lower() or 'gms' in source_group.lower())
                                
                                if management and not is_gms:
                                    # Extraire correctement l'adresse source
                                    if source_address.get('any', False):
                                        source_display = 'Any'
                                    elif source_address.get('group'):
                                        source_display = source_address.get('group')
                                    elif source_address.get('name'):
                                        source_display = source_address.get('name')
                                    elif source_address.get('ipv4'):
                                        # Adresse IP directe
                                        ipv4 = source_address.get('ipv4', {})
                                        if ipv4.get('host'):
                                            source_display = ipv4.get('host')
                                        elif ipv4.get('network'):
                                            source_display = ipv4.get('network')
                                        else:
                                            source_display = 'Any'
                                    else:
                                        source_display = 'Any'
                                    
                                    # Extraire correctement l'adresse destination
                                    dest_address = ipv4_rule.get('destination', {}).get('address', {})
                                    print(f"Destination address structure: {dest_address}")
                                    
                                    if dest_address.get('any', False):
                                        dest_display = 'Any'
                                    elif dest_address.get('group'):
                                        dest_display = dest_address.get('group')
                                    elif dest_address.get('name'):
                                        dest_display = dest_address.get('name')
                                    elif dest_address.get('ipv4'):
                                        # Adresse IP directe
                                        ipv4 = dest_address.get('ipv4', {})
                                        if ipv4.get('host'):
                                            dest_display = ipv4.get('host')
                                        elif ipv4.get('network'):
                                            dest_display = ipv4.get('network')
                                        else:
                                            dest_display = 'Any'
                                    else:
                                        dest_display = 'Any'
                                    
                                    # Extraire correctement le service
                                    if service.get('any', False):
                                        service_display = 'Any'
                                    elif service.get('name'):
                                        service_display = service.get('name')
                                    elif service.get('group'):
                                        service_display = service.get('group')
                                    elif service.get('tcp') or service.get('udp'):
                                        # Service TCP/UDP avec port
                                        if service.get('tcp'):
                                            tcp = service.get('tcp', {})
                                            port = tcp.get('port', '')
                                            service_display = f"TCP:{port}" if port else 'TCP'
                                        elif service.get('udp'):
                                            udp = service.get('udp', {})
                                            port = udp.get('port', '')
                                            service_display = f"UDP:{port}" if port else 'UDP'
                                    else:
                                        service_display = 'HTTPS Management'  # Fallback
                                    
                                    # FILTRE IMPORTANT: Ne garder QUE les règles HTTP/HTTPS Management
                                    # Exclure SSLVPN, SSO Agents, IKE, Ping, etc.
                                    is_http_https_management = (
                                        'http' in service_display.lower() and 'management' in service_display.lower()
                                    )
                                    
                                    # Ne traiter que les règles HTTP/HTTPS Management
                                    if not is_http_https_management:
                                        continue
                                    
                                    # Déterminer si la règle est à risque (source ANY)
                                    is_at_risk = source_address.get('any', False)
                                    
                                    rule_uuid = ipv4_rule.get('uuid', '')
                                    print(f"[WAN MANAGEMENT] Rule: {ipv4_rule.get('name', 'Unnamed')}, UUID: {rule_uuid}, At Risk: {is_at_risk}")
                                    
                                    rule_info = {
                                        'name': ipv4_rule.get('name', 'Unnamed Rule'),
                                        'enabled': ipv4_rule.get('enable', False),
                                        'from_zone': from_zone,
                                        'to_zone': to_zone,
                                        'source_address': source_display,
                                        'destination_address': dest_display,
                                        'service': service_display,
                                        'action': ipv4_rule.get('action', 'allow'),
                                        'comment': ipv4_rule.get('comment', ''),
                                        'uuid': rule_uuid,
                                        'is_at_risk': is_at_risk
                                    }
                                    wan_to_wan_rules.append(rule_info)
                                    
                                    # Si on trouve au moins une règle WAN-to-WAN active, considérer le WAN Management comme activé
                                    if ipv4_rule.get('enable', False):
                                        wan_management_enabled = True
                        
            except Exception as e:
                print(f"Erreur lors de la vérification de {endpoint}: {str(e)}")
                continue
        
        return jsonify({
            'success': True,
            'wan_management_enabled': wan_management_enabled,
            'https_source': https_source,
            'wan_to_wan_rules': wan_to_wan_rules,
            'message': 'WAN management check completed'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erreur lors de la vérification WAN: {str(e)}'
        }), 500

@app.route('/api/local-users', methods=['POST'])
def check_local_users():
    """Récupérer les utilisateurs locaux d'un firewall"""
    try:
        data = request.json
        ip = data.get('ip')
        username = data.get('username')
        password = data.get('password')
        
        if not ip or not username or not password:
            return jsonify({'success': False, 'message': 'IP, username et password requis'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Utiliser sw_authenticated_request
        response, status = sw_authenticated_request(base_url, username, password, 'user/local/users', 'GET')
        
        if response and status == 200:
            data = response.json()
            
            # Extraire les utilisateurs de la structure imbriquée
            users = []
            if isinstance(data, dict):
                # Structure typique: {user: {local: {user: [...]}}}
                user_data = data.get('user', {})
                local_data = user_data.get('local', {})
                users_list = local_data.get('user', [])
                
                # Si users_list n'est pas une liste, le mettre dans une liste
                if isinstance(users_list, list):
                    users = users_list
                elif users_list:
                    users = [users_list]
            elif isinstance(data, list):
                users = data
            
            return jsonify({'success': True, 'users': users})
        else:
            return jsonify({'success': False, 'message': f'Erreur API: {response.status_code}', 'users': []})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'users': []}), 500

@app.route('/api/active-directory', methods=['POST'])
def check_active_directory():
    """Vérifier la configuration LDAP/Active Directory"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Utiliser sw_authenticated_request
        response, status = sw_authenticated_request(base_url, username, password, 'user/ldap/servers', 'GET')
        
        if response and status == 200:
            ldap_data = response.json()
            servers = ldap_data.get('user', {}).get('ldap', {}).get('server', [])
            ldap_config = {'enabled': len(servers) > 0, 'servers': []}
            
            for server in servers:
                bind_info = server.get('bind', {})
                bind_user = 'Not configured'
                if 'acct' in bind_info:
                    acct = bind_info['acct']
                    name, location = acct.get('name', ''), acct.get('location', '')
                    bind_user = f"{name}@{location}" if name and location else name if name else 'Not configured'
                elif 'distinguished_name' in bind_info:
                    bind_user = bind_info['distinguished_name']
                
                ldap_config['servers'].append({
                    'host': server.get('host', 'Unknown'),
                    'port': server.get('port', 389),
                    'enabled': server.get('enable', False),
                    'use_tls': server.get('use_tls', False),
                    'base_dn': server.get('directory', {}).get('primary_domain', 'Not configured'),
                    'bind_user': bind_user,
                    'schema': server.get('schema', 'microsoft-active-directory')
                })
            return jsonify({'success': True, 'ldap_config': ldap_config})
        else:
            return jsonify({'success': False, 'message': f'Erreur API: {status}', 'ldap_config': {'enabled': False, 'servers': []}})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'ldap_config': {'enabled': False, 'servers': []}}), 500

@app.route('/api/radius-config', methods=['POST'])
def check_radius_config():
    """Vérifier la configuration RADIUS"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Essayer plusieurs endpoints possibles pour RADIUS avec sw_authenticated_request
        endpoints = ['user/radius/servers', 'user/radius', 'config/authentication/radius']
        
        radius_config = {}
        response_status = None
        
        for endpoint in endpoints:
            response, status = sw_authenticated_request(base_url, username, password, endpoint, 'GET')
            if response and status == 200:
                radius_config = response.json()
                response_status = 200
                break
        
        if response_status == 200:
            return jsonify({'success': True, 'radius_config': radius_config})
        else:
            # Si aucun endpoint ne fonctionne, retourner une config vide (RADIUS peut ne pas être configuré)
            return jsonify({'success': True, 'radius_config': {}, 'message': 'RADIUS non configuré ou endpoint non disponible'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'radius_config': {}}), 500

@app.route('/api/tacacs-config', methods=['POST'])
def check_tacacs_config():
    """Vérifier la configuration TACACS+"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Essayer plusieurs endpoints possibles pour TACACS avec sw_authenticated_request
        endpoints = ['user/tacacs/servers', 'user/tacacs', 'config/authentication/tacacs']
        
        tacacs_config = {}
        response_status = None
        
        for endpoint in endpoints:
            response, status = sw_authenticated_request(base_url, username, password, endpoint, 'GET')
            if response and status == 200:
                tacacs_config = response.json()
                response_status = 200
                break
        
        if response_status == 200:
            return jsonify({'success': True, 'tacacs_config': tacacs_config})
        else:
            # Si aucun endpoint ne fonctionne, retourner une config vide (TACACS peut ne pas être configuré)
            return jsonify({'success': True, 'tacacs_config': {}, 'message': 'TACACS non configuré ou endpoint non disponible'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'tacacs_config': {}}), 500

@app.route('/api/sso-config', methods=['POST'])
def check_sso_config():
    """Vérifier la configuration SSO"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Utiliser sw_authenticated_request pour chaque appel
        sso_response, sso_status = sw_authenticated_request(base_url, username, password, 'user/sso/base', 'GET')
        agents_response, agents_status = sw_authenticated_request(base_url, username, password, 'user/sso/agents', 'GET')
        ts_response, ts_status = sw_authenticated_request(base_url, username, password, 'user/sso/terminal-services-agents', 'GET')
        radius_response, radius_status = sw_authenticated_request(base_url, username, password, 'user/sso/radius-accounting-clients', 'GET')
        
        sso_config = sso_response.json() if sso_response and sso_status == 200 else {}
        if agents_response and agents_status == 200:
            sso_config.setdefault('user', {}).setdefault('sso', {})['agents'] = agents_response.json().get('user', {}).get('sso', {}).get('agent', [])
        if ts_response and ts_status == 200:
            sso_config.setdefault('user', {}).setdefault('sso', {})['ts_agents'] = ts_response.json().get('user', {}).get('sso', {}).get('terminal_services_agent', [])
        if radius_response and radius_status == 200:
            sso_config.setdefault('user', {}).setdefault('sso', {})['radius_clients'] = radius_response.json().get('user', {}).get('sso', {}).get('radius_accounting_client', [])
        
        keys_count = 0
        if 'agents' in sso_config.get('user', {}).get('sso', {}):
            keys_count += len([a for a in sso_config['user']['sso']['agents'] if a.get('shared_key')])
        if 'ts_agents' in sso_config.get('user', {}).get('sso', {}):
            keys_count += len([a for a in sso_config['user']['sso']['ts_agents'] if a.get('shared_key')])
        if 'radius_clients' in sso_config.get('user', {}).get('sso', {}):
            keys_count += len([a for a in sso_config['user']['sso']['radius_clients'] if a.get('shared_secret')])
        
        sso_config.setdefault('user', {}).setdefault('sso', {})['keys_count'] = keys_count
        return jsonify({'success': True, 'sso_config': sso_config})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'sso_config': {}}), 500

@app.route('/api/cse-config', methods=['POST'])
def check_cse_config():
    """Vérifier la configuration Cloud Secure Edge"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Utiliser sw_authenticated_request
        base_response, base_status = sw_authenticated_request(base_url, username, password, 'cloud-secure-edge/base', 'GET')
        connectors_response, conn_status = sw_authenticated_request(base_url, username, password, 'cloud-secure-edge/connectors', 'GET')
        
        cse_config = {'base': {}, 'connectors': []}
        if base_response and base_status == 200:
            cse_config['base'] = base_response.json()
        if connectors_response and conn_status == 200:
            cse_config['connectors'] = connectors_response.json().get('cloud_secure_edge', {}).get('connector', [])
        
        return jsonify({'success': True, 'cse_config': cse_config})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'cse_config': {'base': {}, 'connectors': []}}), 500

@app.route('/api/cse-config', methods=['PUT'])
def update_cse_config():
    """Mettre à jour la configuration Cloud Secure Edge"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        cloud_secure_edge = data.get('cloud_secure_edge', {})
        
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Mettre à jour la configuration CSE
        response, status = sw_authenticated_request(base_url, username, password, 'cloud-secure-edge/base', 'PUT', {
            'cloud_secure_edge': cloud_secure_edge
        })
        
        if response and status in [200, 201, 204]:
            return jsonify({'success': True, 'message': 'CSE configuration updated successfully'})
        else:
            return jsonify({'success': False, 'message': f'Error updating CSE config: {status}'}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/ipsec-vpn', methods=['POST'])
def check_ipsec_vpn():
    """Vérifier la configuration VPN IPSEC (site-to-site et tunnel-interface)"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        base_url = get_base_url(ip)
        
        tunnels = []
        
        # 1. Récupérer les politiques VPN site-to-site
        response, status = sw_authenticated_request(base_url, username, password, 'vpn/policies/ipv4/site-to-site', 'GET')
        
        if response and status == 200:
            vpn_data = response.json()
            
            try:
                vpn = vpn_data.get('vpn', {})
                policies = vpn.get('policy', [])
                
                if isinstance(policies, list):
                    for policy_wrapper in policies:
                        if isinstance(policy_wrapper, dict):
                            ipv4_data = policy_wrapper.get('ipv4', {})
                            if isinstance(ipv4_data, dict):
                                site_to_site = ipv4_data.get('site_to_site', {})
                                if isinstance(site_to_site, dict):
                                    gateway_data = site_to_site.get('gateway', {})
                                    auth_method = site_to_site.get('auth_method', {})
                                    shared_secret = auth_method.get('shared_secret', {})
                                    proposal = site_to_site.get('proposal', {})
                                    ike = proposal.get('ike', {})
                                    
                                    is_enabled = site_to_site.get('enable', False)
                                    ike_mode = ike.get('exchange', 'ikev1')
                                    
                                    # IMPORTANT: Ne signaler que les tunnels ACTIFS en mode Aggressive
                                    is_at_risk = is_enabled and ike_mode == 'aggressive'
                                    
                                    tunnels.append({
                                        'name': site_to_site.get('name', 'Unnamed'),
                                        'enabled': is_enabled,
                                        'primary_gateway': gateway_data.get('primary', 'Not configured'),
                                        'secondary_gateway': gateway_data.get('secondary', '0.0.0.0'),
                                        'shared_secret': 'Configured' if shared_secret.get('shared_secret') else 'Not configured',
                                        'mode': ike_mode,
                                        'local_network': site_to_site.get('network', {}).get('local', {}).get('name', 'Unknown'),
                                        'remote_network': site_to_site.get('network', {}).get('remote', {}).get('destination_network', {}).get('name', 'Unknown'),
                                        'type': 'site-to-site',
                                        'is_at_risk': is_at_risk
                                    })
            except Exception as e:
                print(f"Error parsing site-to-site VPN data: {e}")
        
        # 2. Récupérer les politiques VPN tunnel-interface
        response_ti, status_ti = sw_authenticated_request(base_url, username, password, 'vpn/policies/ipv4/tunnel-interface', 'GET')
        
        if response_ti and status_ti == 200:
            vpn_data_ti = response_ti.json()
            
            try:
                vpn_ti = vpn_data_ti.get('vpn', {})
                policies_ti = vpn_ti.get('policy', [])
                
                if isinstance(policies_ti, list):
                    for policy_wrapper in policies_ti:
                        if isinstance(policy_wrapper, dict):
                            ipv4_data = policy_wrapper.get('ipv4', {})
                            if isinstance(ipv4_data, dict):
                                tunnel_interface = ipv4_data.get('tunnel_interface', {})
                                if isinstance(tunnel_interface, dict):
                                    gateway_data = tunnel_interface.get('gateway', {})
                                    auth_method = tunnel_interface.get('auth_method', {})
                                    shared_secret = auth_method.get('shared_secret', {})
                                    proposal = tunnel_interface.get('proposal', {})
                                    ike = proposal.get('ike', {})
                                    
                                    is_enabled = tunnel_interface.get('enable', False)
                                    ike_mode = ike.get('exchange', 'ikev1')
                                    
                                    # IMPORTANT: Ne signaler que les tunnels ACTIFS en mode Aggressive
                                    is_at_risk = is_enabled and ike_mode == 'aggressive'
                                    
                                    tunnels.append({
                                        'name': tunnel_interface.get('name', 'Unnamed'),
                                        'enabled': is_enabled,
                                        'primary_gateway': gateway_data.get('primary', 'Not configured'),
                                        'secondary_gateway': 'N/A',
                                        'shared_secret': 'Configured' if shared_secret.get('shared_secret') else 'Not configured',
                                        'mode': ike_mode,
                                        'local_network': 'Tunnel Interface',
                                        'remote_network': 'Tunnel Interface',
                                        'type': 'tunnel-interface',
                                        'is_at_risk': is_at_risk
                                    })
            except Exception as e:
                print(f"Error parsing tunnel-interface VPN data: {e}")
        
        return jsonify({'success': True, 'tunnels': tunnels})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'tunnels': []}), 500

@app.route('/api/ssl-vpn', methods=['POST'])
def check_ssl_vpn():
    """Vérifier la configuration SSL VPN et déterminer le status de sécurité"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        firewall_id = data.get('firewall_id')  # Optionnel pour récupérer les status
        
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        base_url = get_base_url(ip)
        
        # 1. Récupérer la configuration SSL VPN de base
        response, status = sw_authenticated_request(base_url, username, password, 'ssl-vpn/server/base', 'GET')
        
        if not response or status != 200:
            return jsonify({'success': False, 'message': 'Impossible de récupérer la configuration SSL VPN', 'ssl_vpn_config': {}})
        
        ssl_config = response.json()
        server_config = ssl_config.get('ssl_vpn', {}).get('server', {})
        
        # 2. Récupérer les accesses (zones autorisées)
        accesses_response, acc_status = sw_authenticated_request(base_url, username, password, 'ssl-vpn/server/accesses', 'GET')
        
        wan_enabled = False
        if accesses_response and acc_status == 200:
            accesses_data = accesses_response.json()
            accesses = accesses_data.get('ssl_vpn', {}).get('server', {}).get('access', [])
            
            # Vérifier si le WAN est activé
            for access in accesses:
                if access.get('enable', False):
                    zone = access.get('zone', '').upper()
                    if 'WAN' in zone or 'X1' in zone:
                        wan_enabled = True
                        break
        
        # 2.5. Récupérer la méthode d'authentification configurée
        auth_method_response, auth_status = sw_authenticated_request(base_url, username, password, 'user/authentication/methods', 'GET')
        
        auth_method = 'local'  # Par défaut
        auth_methods_configured = []
        
        if auth_method_response and auth_status == 200:
            auth_data = auth_method_response.json()
            auth_method = auth_data.get('user', {}).get('auth', {}).get('auth_method', 'local')
            
            # Déterminer quelles méthodes sont configurées
            auth_method_lower = auth_method.lower()
            
            if auth_method_lower == 'local':
                auth_methods_configured = ['local_users']
            elif auth_method_lower == 'radius':
                auth_methods_configured = ['radius']
            elif auth_method_lower == 'ldap':
                auth_methods_configured = ['ldap']
            elif auth_method_lower == 'tacacs':
                auth_methods_configured = ['tacacs']
            else:
                # Méthodes combinées (ex: "ldap-local", "ldap + local", "radius-local", etc.)
                if 'local' in auth_method_lower:
                    auth_methods_configured.append('local_users')
                if 'radius' in auth_method_lower:
                    auth_methods_configured.append('radius')
                if 'ldap' in auth_method_lower:
                    auth_methods_configured.append('ldap')
                if 'tacacs' in auth_method_lower:
                    auth_methods_configured.append('tacacs')
        
        # 3. Si firewall_id est fourni, vérifier les status selon les méthodes configurées
        auth_statuses = {}
        all_configured_resolved = True
        
        if firewall_id:
            from models import ModuleResolutionStatus
            
            # Vérifier le status de chaque méthode configurée
            for method in auth_methods_configured:
                status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name=method).first()
                is_resolved = status_rec.is_resolved if status_rec else False
                auth_statuses[method] = {
                    'resolved': is_resolved,
                    'configured': status_rec is not None
                }
                
                if not is_resolved:
                    all_configured_resolved = False
        
        # 4. Déterminer le status de sécurité
        is_secure = False
        security_status = 'at_risk'
        security_message = ''
        
        if not wan_enabled:
            # Option A : WAN désactivé → VERT
            is_secure = True
            security_status = 'secure'
            security_message = '✅ SSL VPN désactivé sur WAN'
        else:
            # Option B : WAN activé → vérifier les conditions selon les méthodes configurées
            if len(auth_methods_configured) == 0:
                # Aucune méthode configurée → ROUGE
                security_status = 'at_risk'
                security_message = '🔴 À RISQUE - SSL VPN actif sur WAN mais aucune méthode d\'authentification configurée'
            elif all_configured_resolved and len(auth_methods_configured) > 0:
                # Toutes les méthodes configurées sont résolues → VERT
                is_secure = True
                security_status = 'secure'
                resolved_methods = [method for method, status in auth_statuses.items() if status['resolved']]
                security_message = f'✅ SSL VPN sécurisé - Méthodes résolues: {", ".join(resolved_methods)}'
            else:
                # Vérifier si partiellement résolu ou complètement à risque
                resolved_count = sum(1 for status in auth_statuses.values() if status['resolved'])
                total_count = len(auth_methods_configured)
                
                if resolved_count == 0:
                    # Aucune méthode résolue → ROUGE
                    security_status = 'at_risk'
                    security_message = f'🔴 À RISQUE - SSL VPN actif sur WAN mais aucune méthode d\'authentification résolue ({resolved_count}/{total_count})'
                else:
                    # Partiellement résolu → ORANGE
                    security_status = 'partial'
                    security_message = f'🟠 PARTIEL - {resolved_count}/{total_count} méthodes d\'authentification résolues'
        
        return jsonify({
            'success': True, 
            'ssl_vpn_config': ssl_config,
            'wan_enabled': wan_enabled,
            'is_secure': is_secure,
            'security_status': security_status,
            'security_message': security_message,
            'auth_method': auth_method,
            'auth_methods_configured': auth_methods_configured,
            'auth_statuses': auth_statuses,
            'all_configured_resolved': all_configured_resolved
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'ssl_vpn_config': {}}), 500

@app.route('/api/remediation/ssl-vpn/disable-wan', methods=['POST'])
def disable_ssl_vpn_wan():
    """Désactiver SSL VPN sur les zones WAN (action optionnelle)"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        
        if not firewall_id:
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        # Récupérer le firewall
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username = firewall.username
        password = firewall.get_password()
        
        print(f"[SSL VPN REMEDIATION] Disabling SSL VPN on WAN for {firewall.name}")
        
        # 1. Récupérer les accesses actuels
        accesses_response, acc_status = sw_authenticated_request(base_url, username, password, 'ssl-vpn/server/accesses', 'GET')
        
        if not accesses_response or acc_status != 200:
            return jsonify({'success': False, 'message': 'Impossible de récupérer les accesses SSL VPN'}), 500
        
        accesses_data = accesses_response.json()
        accesses = accesses_data.get('ssl_vpn', {}).get('server', {}).get('access', [])
        
        # 2. Désactiver les zones WAN
        modified_accesses = []
        for access in accesses:
            zone = access.get('zone', '').upper()
            if 'WAN' in zone or 'X1' in zone:
                access['enable'] = False
                print(f"[SSL VPN REMEDIATION] Disabling zone: {zone}")
            modified_accesses.append(access)
        
        # 3. Envoyer la modification
        payload = {
            'ssl_vpn': {
                'server': {
                    'access': modified_accesses
                }
            }
        }
        
        put_response, put_status = sw_authenticated_request(base_url, username, password, 'ssl-vpn/server/accesses', 'PUT', payload)
        
        if not put_response or put_status not in [200, 201, 202]:
            return jsonify({'success': False, 'message': 'Erreur lors de la désactivation du SSL VPN sur WAN'}), 500
        
        # 4. Enregistrer l'action
        remediation_action = RemediationAction(
            firewall_id=firewall_id,
            module_name='ssl_vpn',
            action_type='disable_wan',
            result_message='SSL VPN désactivé sur les zones WAN',
            executed_at=datetime.utcnow(),
            success=True
        )
        db.session.add(remediation_action)
        db.session.commit()
        
        # 5. Mettre à jour le statut
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='ssl_vpn').first()
        if not status_rec:
            status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='ssl_vpn')
            db.session.add(status_rec)
        
        status_rec.is_resolved = True
        status_rec.verification_method = 'wan_disabled'
        status_rec.notes = '✅ SSL VPN désactivé sur WAN'
        status_rec.resolved_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': '✅ SSL VPN désactivé sur WAN avec succès'})
        
    except Exception as e:
        db.session.rollback()
        print(f"ERROR in disable_ssl_vpn_wan: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/pppoe-pptp-l2tp', methods=['POST'])
def check_pppoe_pptp_l2tp():
    """Vérifier la configuration PPPoE/PPTP/L2TP dans les interfaces WAN"""
    try:
        data = request.json
        ip, username, password = data.get('ip'), data.get('username'), data.get('password')
        firewall_id = data.get('firewall_id')  # Optionnel pour récupérer les status
        
        if not all([ip, username, password]):
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        base_url = get_base_url(ip)
        
        # Récupérer les interfaces IPv4 avec sw_authenticated_request
        response, status = sw_authenticated_request(base_url, username, password, 'interfaces/ipv4', 'GET')
        
        if response and status == 200:
            interfaces_data = response.json()
            interfaces = interfaces_data.get('interfaces', [])
            
            # Filtrer les interfaces WAN avec PPPoE/PPTP/L2TP
            wan_ppp_interfaces = []
            total_interfaces = 0
            risk_interfaces = 0
            
            for iface in interfaces:
                ipv4_config = iface.get('ipv4', {})
                ip_assignment = ipv4_config.get('ip_assignment', {})
                zone = ip_assignment.get('zone', '')
                mode = ip_assignment.get('mode', {})
                
                # Vérifier si c'est une zone WAN avec mode PPPoE/PPTP/L2TP
                if 'WAN' in zone.upper() or 'X1' in zone.upper():
                    if 'pppoe' in mode or 'pptp' in mode or 'l2tp' in mode:
                        protocol_mode = list(mode.keys())[0] if mode else 'unknown'
                        is_risk_protocol = protocol_mode in ['pppoe', 'pptp', 'l2tp']
                        management_config = ipv4_config.get('management', {})
                        
                        total_interfaces += 1
                        if is_risk_protocol:
                            risk_interfaces += 1
                        
                        wan_ppp_interfaces.append({
                            'name': ipv4_config.get('name', 'Unknown'),
                            'zone': zone,
                            'mode': protocol_mode,
                            'is_risk': is_risk_protocol,
                            'mtu': ipv4_config.get('mtu', 1500),
                            'management': {
                                'http': management_config.get('http', False),
                                'https': management_config.get('https', False),
                                'ping': management_config.get('ping', False),
                                'snmp': management_config.get('snmp', False),
                                'ssh': management_config.get('ssh', False)
                            }
                        })
            
            # Déterminer le status de sécurité
            is_secure = (risk_interfaces == 0)
            security_status = 'secure' if is_secure else 'at_risk'
            security_message = f'✅ SÉCURISÉ - Aucune interface PPPoE/PPTP/L2TP détectée' if is_secure else f'🔴 À RISQUE - {risk_interfaces}/{total_interfaces} interface(s) avec protocoles à risque'
            
            # Vérifier le status de remediation si firewall_id fourni
            remediation_status = None
            if firewall_id:
                from models import ModuleResolutionStatus
                status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='pppoe_pptp_l2tp').first()
                if status_rec:
                    remediation_status = {
                        'is_resolved': status_rec.is_resolved,
                        'resolution_date': status_rec.resolved_at.isoformat() if status_rec.resolved_at else None,
                        'notes': status_rec.notes
                    }
                    # Si résolu, override le status
                    if status_rec.is_resolved:
                        is_secure = True
                        security_status = 'secure'
                        security_message = f'✅ RÉSOLU - {status_rec.notes or "Interfaces PPPoE/PPTP/L2TP sécurisées"}'
                    elif status_rec.notes:
                        # Partiellement résolu : au moins une interface modifiée mais pas toutes
                        import re
                        match = re.search(r'\((\d+)/(\d+)\)', status_rec.notes)
                        if match:
                            modified_count = int(match.group(1))
                            total_count = int(match.group(2))
                            if modified_count > 0 and modified_count < total_count:
                                is_secure = False
                                security_status = 'partial'
                                security_message = f'🟠 PARTIEL - {modified_count}/{total_count} interface(s) sécurisée(s)'
            
            return jsonify({
                'success': True, 
                'ppp_config': {
                    'interfaces': wan_ppp_interfaces,
                    'count': len(wan_ppp_interfaces),
                    'total_interfaces': total_interfaces,
                    'risk_interfaces': risk_interfaces
                },
                'is_secure': is_secure,
                'security_status': security_status,
                'security_message': security_message,
                'remediation_status': remediation_status
            })
        else:
            return jsonify({'success': False, 'message': f'Erreur API: status {status}', 'ppp_config': {}})
    except Exception as e:
        print(f"ERROR in check_pppoe_pptp_l2tp: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e), 'ppp_config': {}}), 500

@app.route('/api/remediation/pppoe-pptp-l2tp/change-credentials', methods=['POST'])
def fix_pppoe_pptp_l2tp_credentials():
    """Changer les credentials PPPoE/PPTP/L2TP pour sécuriser les connexions"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        interfaces_to_fix = data.get('interfaces', [])  # Liste des interfaces à modifier
        
        if not firewall_id or not interfaces_to_fix:
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        # Récupérer le firewall
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username = firewall.username
        password = firewall.get_password()
        
        print(f"[PPPOE REMEDIATION] Starting remediation for firewall {firewall.name} ({firewall.ip})")
        print(f"[PPPOE REMEDIATION] Interfaces to fix: {len(interfaces_to_fix)}")
        
        modified_interfaces = []
        
        # Traiter chaque interface
        for interface_data in interfaces_to_fix:
            interface_name = interface_data.get('name')
            new_username = interface_data.get('new_username')
            new_password = interface_data.get('new_password')
            new_shared_secret = interface_data.get('new_shared_secret', '')  # Pour L2TP
            
            if not all([interface_name, new_username, new_password]):
                continue
            
            try:
                # Récupérer la configuration actuelle de l'interface
                current_response, current_status = sw_authenticated_request(base_url, username, password, f'interfaces/ipv4/name/{interface_name}', 'GET')
                
                if current_response and current_status == 200:
                    current_data = current_response.json()
                    interfaces = current_data.get('interfaces', [])
                    
                    if interfaces:
                        interface = interfaces[0]
                        ipv4_config = interface.get('ipv4', {})
                        
                        # Récupérer la configuration complète
                        ip_assignment = ipv4_config.get('ip_assignment', {})
                        zone = ip_assignment.get('zone', '')
                        mode = ip_assignment.get('mode', {})
                        
                        # Debug: afficher la configuration actuelle
                        print(f"[PPPOE REMEDIATION] Current interface {interface_name} config:")
                        print(f"  Zone: {zone}")
                        print(f"  Mode: {mode}")
                        print(f"  Full ip_assignment: {ip_assignment}")
                        
                        # Créer une structure avec zone et mode
                        patch_data = {
                            'interfaces': [{
                                'ipv4': {
                                    'name': interface_name,
                                    'ip_assignment': {
                                        'zone': zone,
                                        'mode': {}
                                    }
                                }
                            }]
                        }
                        
                        # Modifier les credentials selon le protocole
                        if 'pppoe' in mode:
                            patch_data['interfaces'][0]['ipv4']['ip_assignment']['mode']['pppoe'] = {
                                **mode['pppoe'],
                                'user_name': new_username,
                                'password': new_password
                            }
                        elif 'pptp' in mode:
                            patch_data['interfaces'][0]['ipv4']['ip_assignment']['mode']['pptp'] = {
                                **mode['pptp'],
                                'user_name': new_username,
                                'password': new_password
                            }
                        elif 'l2tp' in mode:
                            # Pour L2TP, on doit aussi modifier le shared_secret
                            l2tp_config = mode['l2tp'].copy()
                            l2tp_config['user_name'] = new_username
                            l2tp_config['password'] = new_password
                            # Utiliser le shared_secret fourni par l'utilisateur
                            if new_shared_secret:
                                l2tp_config['shared_secret'] = f"6,{new_shared_secret}"
                            
                            patch_data['interfaces'][0]['ipv4']['ip_assignment']['mode']['l2tp'] = l2tp_config
                        
                        # Debug: afficher ce qu'on envoie
                        import json
                        print(f"[PPPOE REMEDIATION] PATCH data for {interface_name}:")
                        print(json.dumps(patch_data, indent=2))
                        
                        # Envoyer la modification
                        patch_response, patch_status = sw_authenticated_request(base_url, username, password, 'interfaces/ipv4', 'PATCH', data=patch_data)
                        
                        if patch_response and patch_status == 200:
                            modified_interfaces.append(interface_name)
                            print(f"[PPPOE REMEDIATION] Successfully modified interface: {interface_name}")
                        else:
                            print(f"[PPPOE REMEDIATION] Failed to modify interface {interface_name}: {patch_status}")
                
            except Exception as e:
                print(f"[PPPOE REMEDIATION] Error processing interface {interface_name}: {str(e)}")
                continue
        
        # Les changements sont automatiquement committés par sw_authenticated_request
        print(f"[PPPOE REMEDIATION] Successfully modified {len(modified_interfaces)} interface(s)")
        
        # Enregistrer l'action de remediation
        remediation_action = RemediationAction(
            firewall_id=firewall_id,
            module_name='pppoe_pptp_l2tp',
            action_type='change_credentials',
            parameters={'modified_interfaces': modified_interfaces},
            result_message=f'Credentials modifiés pour {len(modified_interfaces)} interface(s): {", ".join(modified_interfaces)}',
            executed_at=datetime.utcnow(),
            success=len(modified_interfaces) > 0
        )
        db.session.add(remediation_action)
        
        # Récupérer les interfaces modifiées précédemment depuis la DB
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='pppoe_pptp_l2tp').first()
        
        # Combiner les interfaces déjà modifiées avec les nouvelles
        already_modified = []
        if status_rec and status_rec.notes:
            # Parser les notes pour extraire les interfaces déjà modifiées
            import re
            match = re.search(r'Interfaces modifiées: \[(.*?)\]', status_rec.notes)
            if match:
                already_modified = [iface.strip() for iface in match.group(1).split(',') if iface.strip()]
        
        # Combiner toutes les interfaces modifiées (anciennes + nouvelles)
        all_modified = list(set(already_modified + modified_interfaces))
        
        # Vérifier combien d'interfaces à risque il reste à modifier
        # Récupérer à nouveau la config pour voir toutes les interfaces à risque
        response, status = sw_authenticated_request(base_url, username, password, 'interfaces/ipv4', 'GET')
        
        total_risk_interfaces = 0
        if response and status == 200:
            interfaces_data = response.json()
            interfaces = interfaces_data.get('interfaces', [])
            
            for iface in interfaces:
                ipv4_config = iface.get('ipv4', {})
                ip_assignment = ipv4_config.get('ip_assignment', {})
                zone = ip_assignment.get('zone', '')
                mode = ip_assignment.get('mode', {})
                
                if 'WAN' in zone.upper() or 'X1' in zone.upper():
                    if 'pppoe' in mode or 'pptp' in mode or 'l2tp' in mode:
                        total_risk_interfaces += 1
        
        # Déterminer si tout est résolu
        all_resolved = (len(all_modified) >= total_risk_interfaces and total_risk_interfaces > 0)
        
        print(f"[PPPOE REMEDIATION] Total risk interfaces: {total_risk_interfaces}, Modified: {len(all_modified)}, All resolved: {all_resolved}")
        
        if len(modified_interfaces) > 0:
            if not status_rec:
                status_rec = ModuleResolutionStatus(
                    firewall_id=firewall_id,
                    module_name='pppoe_pptp_l2tp',
                    is_resolved=all_resolved,
                    resolved_at=datetime.utcnow() if all_resolved else None,
                    notes=f'Interfaces modifiées: [{", ".join(all_modified)}] ({len(all_modified)}/{total_risk_interfaces})'
                )
                db.session.add(status_rec)
            else:
                status_rec.is_resolved = all_resolved
                if all_resolved:
                    status_rec.resolved_at = datetime.utcnow()
                status_rec.notes = f'Interfaces modifiées: [{", ".join(all_modified)}] ({len(all_modified)}/{total_risk_interfaces})'
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Credentials modifiés avec succès pour {len(modified_interfaces)} interface(s)',
            'modified_interfaces': modified_interfaces
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"ERROR in fix_pppoe_pptp_l2tp_credentials: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/local-users/unbind-totp/<user_to_unbind>', methods=['POST'])
@app.route('/api/remediation/local-users/unbind-totp', methods=['POST'])
def unbind_totp(user_to_unbind=None):
    """Délier TOTP pour les utilisateurs locaux"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        print(f"DEBUG unbind_totp called: user_to_unbind={user_to_unbind}, body={data}")
        
        # Accepter firewall_id OU ip/username/password
        firewall_id = data.get('firewall_id')
        if firewall_id:
            firewall = Firewall.query.get(firewall_id)
            if not firewall:
                return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
            ip = firewall.ip
            username = firewall.username
            password = firewall.get_password()
        else:
            ip = data.get('ip')
            username = data.get('username')
            password = data.get('password')
            if not all([ip, username, password]):
                return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
            # Essayer de retrouver le firewall_id à partir de l'IP
            firewall = Firewall.query.filter_by(ip=ip).first()
            firewall_id = firewall.id if firewall else None
        
        # Si user_to_unbind est dans l'URL, l'utiliser
        if user_to_unbind:
            users = [user_to_unbind]
        else:
            # Accepter 'users' OU 'usernames'
            users = data.get('users', data.get('usernames', []))
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        results = []
        success_count = 0
        
        for user in users:
            try:
                # Utiliser sw_authenticated_request pour unbind TOTP (body vide)
                response, status = sw_authenticated_request(base_url, username, password, f'user/local/unbind-totp-key/{user}', 'POST', None)
                
                success = response and status in [200, 204]
                if success:
                    success_count += 1
                
                results.append({
                    'user': user,
                    'success': success,
                    'message': 'TOTP unbound' if success else f'Error: {status}'
                })
            except Exception as e:
                results.append({'user': user, 'success': False, 'message': str(e)})
        
        # Mettre à jour la DB si firewall_id est fourni
        if firewall_id and success_count > 0:
            # Créer ou mettre à jour RemediationAction
            action = RemediationAction(
                firewall_id=firewall_id,
                module_name='local_users',
                action_type='unbind_totp',
                result_message=f'TOTP unbinded for {success_count} user(s)',
                executed_at=datetime.utcnow(),
                success=True
            )
            db.session.add(action)
            
            # Vérifier combien de types d'actions ont été faites
            totp_actions = RemediationAction.query.filter_by(
                firewall_id=firewall_id,
                module_name='local_users',
                action_type='unbind_totp',
                success=True
            ).count()
            
            pwd_actions = RemediationAction.query.filter_by(
                firewall_id=firewall_id,
                module_name='local_users',
                action_type='force_password_change',
                success=True
            ).count()
            
            # Mettre à jour le statut de résolution
            status_record = ModuleResolutionStatus.query.filter_by(
                firewall_id=firewall_id,
                module_name='local_users'
            ).first()
            
            if not status_record:
                status_record = ModuleResolutionStatus(
                    firewall_id=firewall_id,
                    module_name='local_users'
                )
                db.session.add(status_record)
            
            # Si les 2 types d'actions sont faites → Vert, sinon Orange
            has_totp = totp_actions > 0 or action.action_type == 'unbind_totp'
            has_pwd = pwd_actions > 0
            status_record.is_resolved = has_totp and has_pwd
            status_record.verification_method = 'totp_unbind_action'
            
            # Notes compatibles avec le frontend
            notes_parts = []
            if has_totp:
                notes_parts.append('TOTP délié')
            if has_pwd:
                notes_parts.append('Changement MDP forcé')
            status_record.notes = ', '.join(notes_parts) if notes_parts else 'Actions en cours'
            
            if status_record.is_resolved:
                status_record.resolved_at = datetime.utcnow()
            
            db.session.commit()
        
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/local-users/force-password-change', methods=['POST'])
@app.route('/api/remediation/local-users/force-password-change', methods=['POST'])
def force_password_change():
    """Forcer le changement de mot de passe pour les utilisateurs locaux"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        
        # Accepter firewall_id OU ip/username/password
        firewall_id = data.get('firewall_id')
        if firewall_id:
            firewall = Firewall.query.get(firewall_id)
            if not firewall:
                return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
            ip = firewall.ip
            username = firewall.username
            password = firewall.get_password()
        else:
            ip = data.get('ip')
            username = data.get('username')
            password = data.get('password')
            if not all([ip, username, password]):
                return jsonify({'success': False, 'message': 'Paramètres manquants (firewall_id OU ip/username/password requis)'}), 400
        
        users = data.get('users', [])
        force_all = data.get('force_all', False)
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # Si force_all est True, utiliser l'endpoint global
        if force_all or not users:
            try:
                post_data = {
                    'user': {
                        'local': {
                            'force_users_password_change': {
                                'for_admin_users': True,
                                'for_general_users': True
                            }
                        }
                    }
                }
                print(f"DEBUG: Envoi vers force-users-password-change avec payload: {post_data}")
                response, status = sw_authenticated_request(base_url, username, password, 'user/local/force-users-password-change', 'POST', post_data)
                
                if response:
                    try:
                        resp_text = response.text
                        print(f"DEBUG: Réponse status={status}, text={resp_text[:200]}")
                    except:
                        print(f"DEBUG: Réponse status={status}, response object exists")
                else:
                    print(f"DEBUG: Réponse status={status}, response=None (erreur dans sw_authenticated_request)")
                
                if response and status in [200, 204]:
                    # Mettre à jour la DB si firewall_id est fourni
                    if firewall_id:
                        # Créer RemediationAction
                        action = RemediationAction(
                            firewall_id=firewall_id,
                            module_name='local_users',
                            action_type='force_password_change',
                            result_message='Password change forced for all users',
                            executed_at=datetime.utcnow(),
                            success=True
                        )
                        db.session.add(action)
                        
                        # Vérifier combien de types d'actions ont été faites
                        totp_actions = RemediationAction.query.filter_by(
                            firewall_id=firewall_id,
                            module_name='local_users',
                            action_type='unbind_totp',
                            success=True
                        ).count()
                        
                        pwd_actions = RemediationAction.query.filter_by(
                            firewall_id=firewall_id,
                            module_name='local_users',
                            action_type='force_password_change',
                            success=True
                        ).count()
                        
                        # Mettre à jour le statut de résolution
                        status_record = ModuleResolutionStatus.query.filter_by(
                            firewall_id=firewall_id,
                            module_name='local_users'
                        ).first()
                        
                        if not status_record:
                            status_record = ModuleResolutionStatus(
                                firewall_id=firewall_id,
                                module_name='local_users'
                            )
                            db.session.add(status_record)
                        
                        # Si les 2 types d'actions sont faites → Vert, sinon Orange
                        has_totp = totp_actions > 0
                        has_pwd = pwd_actions > 0 or action.action_type == 'force_password_change'
                        status_record.is_resolved = has_totp and has_pwd
                        status_record.verification_method = 'force_password_action'
                        
                        # Notes compatibles avec le frontend
                        notes_parts = []
                        if has_totp:
                            notes_parts.append('TOTP délié')
                        if has_pwd:
                            notes_parts.append('Changement MDP forcé')
                        status_record.notes = ', '.join(notes_parts) if notes_parts else 'Actions en cours'
                        
                        if status_record.is_resolved:
                            status_record.resolved_at = datetime.utcnow()
                        
                        db.session.commit()
                    
                    return jsonify({'success': True, 'message': 'Password change forced for all users', 'results': []})
                else:
                    return jsonify({'success': False, 'message': f'Error: {status}', 'results': []})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e), 'results': []})
        
        # Sinon, forcer pour des utilisateurs spécifiques via PATCH
        results = []
        for user in users:
            try:
                # Utiliser PATCH pour modifier un utilisateur spécifique
                url = f'{base_url}/api/sonicos/user/local/users'
                patch_data = {
                    'user': {
                        'local': {
                            'user': [{
                                'name': user,
                                'force_password_change': True
                            }]
                        }
                    }
                }
                response = requests.patch(url, json=patch_data, auth=HTTPDigestAuth(username, password), verify=False, timeout=15)
                
                results.append({
                    'user': user,
                    'success': response.status_code in [200, 204],
                    'message': 'Password change forced' if response.status_code in [200, 204] else f'Error: {response.status_code}'
                })
            except Exception as e:
                results.append({'user': user, 'success': False, 'message': str(e)})
        
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/wan-management/fix-rules', methods=['POST'])
def fix_wan_management_rules():
    """Corriger les règles WAN management en créant un objet IPv4 et en modifiant les règles"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        object_name = data.get('object_name')
        object_ip = data.get('object_ip')
        rule_uuids = data.get('rule_uuids', [])
        
        print(f"[WAN REMEDIATION] Received request:")
        print(f"  - firewall_id: {firewall_id}")
        print(f"  - object_name: {object_name}")
        print(f"  - object_ip: {object_ip}")
        print(f"  - rule_uuids: {rule_uuids}")
        print(f"  - rule_uuids type: {type(rule_uuids)}")
        print(f"  - rule_uuids length: {len(rule_uuids) if isinstance(rule_uuids, list) else 'N/A'}")
        
        if not firewall_id:
            return jsonify({'success': False, 'message': 'firewall_id requis'}), 400
        
        if not object_name or not object_ip:
            return jsonify({'success': False, 'message': 'Nom d\'objet et IP requis'}), 400
        
        if not rule_uuids or len(rule_uuids) == 0:
            return jsonify({'success': False, 'message': 'Aucune règle sélectionnée'}), 400
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username, password = firewall.username, firewall.get_password()
        
        # 1. Créer l'objet IPv4 address
        address_object_data = {
            "address_objects": [{
                "ipv4": {
                    "name": object_name,
                    "zone": "WAN",
                    "host": {
                        "ip": object_ip
                    }
                }
            }]
        }
        
        print(f"[WAN REMEDIATION] Creating IPv4 object: {object_name} = {object_ip}")
        create_resp, create_status = sw_authenticated_request(base_url, username, password, 'address-objects/ipv4', 'POST', address_object_data)
        
        if not create_resp or create_status not in [200, 201]:
            error_msg = f"Erreur création objet IPv4: {create_status}"
            if create_resp:
                try:
                    error_msg += f" - {create_resp.json()}"
                except:
                    error_msg += f" - {create_resp.text}"
            return jsonify({'success': False, 'message': error_msg}), 500
        
        print(f"[WAN REMEDIATION] IPv4 object created successfully")
        
        # 2. Récupérer toutes les règles d'accès pour trouver celles à modifier
        rules_resp, rules_status = sw_authenticated_request(base_url, username, password, 'access-rules/ipv4', 'GET')
        
        if not rules_resp or rules_status != 200:
            return jsonify({'success': False, 'message': f'Erreur récupération règles: {rules_status}'}), 500
        
        rules_data = rules_resp.json()
        all_rules = rules_data.get('access_rules', [])
        
        print(f"[WAN REMEDIATION] Total rules retrieved: {len(all_rules)}")
        
        # 3. Modifier chaque règle ciblée
        rules_modified = 0
        for rule in all_rules:
            rule_ipv4 = rule.get('ipv4', {})
            rule_uuid = rule_ipv4.get('uuid')
            
            print(f"[WAN REMEDIATION] Checking rule: {rule_ipv4.get('name', 'Unnamed')}, UUID: {rule_uuid}, Match: {rule_uuid in rule_uuids}")
            
            if rule_uuid in rule_uuids:
                print(f"[WAN REMEDIATION] Modifying rule: {rule_ipv4.get('name', 'Unnamed')} (UUID: {rule_uuid})")
                
                # Créer une copie modifiée de la règle
                modified_rule = dict(rule_ipv4)
                
                print(f"[WAN REMEDIATION] Rule before modification:")
                print(f"  - UUID: {rule_uuid}")
                print(f"  - Source before: {modified_rule.get('source', {}).get('address', {})}")
                
                # Remplacer source ANY par l'objet créé
                if 'source' not in modified_rule:
                    modified_rule['source'] = {}
                if 'address' not in modified_rule['source']:
                    modified_rule['source']['address'] = {}
                
                # Supprimer 'any' et ajouter 'name'
                modified_rule['source']['address'].pop('any', None)
                modified_rule['source']['address']['name'] = object_name
                
                print(f"  - Source after: {modified_rule.get('source', {}).get('address', {})}")
                
                # PUT avec UUID dans l'URL (endpoint spécifique pour modifier une règle existante)
                put_data = {
                    "access_rules": [{
                        "ipv4": modified_rule
                    }]
                }
                
                # Utiliser l'endpoint avec UUID dans l'URL
                endpoint_with_uuid = f'access-rules/ipv4/uuid/{rule_uuid}'
                print(f"[WAN REMEDIATION] Sending PUT to: {endpoint_with_uuid}")
                put_resp, put_status = sw_authenticated_request(base_url, username, password, endpoint_with_uuid, 'PUT', put_data)
                
                if put_resp and put_status in [200, 201, 204]:
                    rules_modified += 1
                    print(f"[WAN REMEDIATION] Rule modified successfully with PUT /uuid/{rule_uuid}")
                else:
                    error_msg = f"Erreur modification règle {rule_ipv4.get('name')}: {put_status}"
                    if put_resp:
                        try:
                            error_json = put_resp.json()
                            print(f"[WAN REMEDIATION] Error response: {error_json}")
                            error_msg += f" - {error_json}"
                        except:
                            error_text = put_resp.text
                            print(f"[WAN REMEDIATION] Error response: {error_text}")
                            error_msg += f" - {error_text}"
                    print(f"[WAN REMEDIATION] {error_msg}")
        
        if rules_modified == 0:
            return jsonify({'success': False, 'message': 'Aucune règle n\'a pu être modifiée'}), 500
        
        # 4. Re-vérifier s'il reste encore des règles à risque
        print(f"[WAN REMEDIATION] Checking if any rules at risk remain...")
        check_resp, check_status = sw_authenticated_request(base_url, username, password, 'access-rules/ipv4', 'GET')
        
        remaining_at_risk = 0
        if check_resp and check_status == 200:
            check_rules_data = check_resp.json()
            check_all_rules = check_rules_data.get('access_rules', [])
            
            for rule in check_all_rules:
                rule_ipv4 = rule.get('ipv4', {})
                from_zone = rule_ipv4.get('from', '')
                to_zone = rule_ipv4.get('to', '')
                management = rule_ipv4.get('management', False)
                
                if from_zone == 'WAN' and to_zone == 'WAN' and management:
                    source_address = rule_ipv4.get('source', {}).get('address', {})
                    source_name = source_address.get('name', '')
                    source_group = source_address.get('group', '')
                    is_gms = ('gms' in source_name.lower() or 'gms' in source_group.lower())
                    
                    # Vérifier aussi le service (ne compter que HTTP/HTTPS Management)
                    service = rule_ipv4.get('service', {})
                    service_name = service.get('name', '').lower()
                    is_http_https_management = 'http' in service_name and 'management' in service_name
                    
                    if source_address.get('any', False) and not is_gms and is_http_https_management:
                        remaining_at_risk += 1
                        print(f"[WAN REMEDIATION] Rule still at risk: {rule_ipv4.get('name', 'Unnamed')}")
        
        # Déterminer si tout est résolu
        all_resolved = (remaining_at_risk == 0)
        print(f"[WAN REMEDIATION] Remaining rules at risk: {remaining_at_risk}")
        print(f"[WAN REMEDIATION] All resolved: {all_resolved}")
        
        # 5. Enregistrer l'action dans la DB
        action = RemediationAction(
            firewall_id=firewall_id,
            module_name='wan_management',
            action_type='secure_rules',
            result_message=f'Objet {object_name} créé et {rules_modified} règle(s) sécurisée(s)',
            executed_at=datetime.utcnow(),
            success=True
        )
        db.session.add(action)
        
        # 6. Mettre à jour le statut
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='wan_management').first()
        if not status_rec:
            status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='wan_management')
            db.session.add(status_rec)
        
        status_rec.is_resolved = all_resolved
        status_rec.verification_method = 'source_any_replaced'
        
        if all_resolved:
            status_rec.notes = f'✅ Toutes les règles sécurisées - Objet {object_name} ({object_ip}) créé'
            status_rec.resolved_at = datetime.utcnow()
        else:
            status_rec.notes = f'⚠️ {rules_modified} règle(s) sécurisée(s) - {remaining_at_risk} règle(s) restante(s) à sécuriser'
            status_rec.resolved_at = None
        
        db.session.commit()
        
        success_message = f'✅ Remédiation réussie: Objet {object_name} créé et {rules_modified} règle(s) sécurisée(s)'
        if not all_resolved:
            success_message += f' - ⚠️ {remaining_at_risk} règle(s) restante(s) à sécuriser'
        
        return jsonify({
            'success': True, 
            'message': success_message,
            'all_resolved': all_resolved,
            'remaining_at_risk': remaining_at_risk
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"ERROR in fix_wan_management_rules: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/ipsec-vpn/fix-tunnels', methods=['POST'])
def fix_ipsec_vpn_tunnels():
    """Corriger les tunnels IPSEC VPN en mode aggressive avec changement de passphrase"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        action = data.get('action')  # 'disable', 'convert_to_main', ou 'change_passphrase'
        tunnels_data = data.get('tunnels', [])  # Liste de {name, type, new_passphrase (optionnel)}
        
        if not firewall_id or not action or not tunnels_data:
            return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
        
        # Récupérer les informations du firewall
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username = firewall.username
        password = firewall.get_password()  # Décrypter le mot de passe
        
        print(f"[IPSEC REMEDIATION] Starting remediation for firewall {firewall.name} ({firewall.ip})")
        print(f"[IPSEC REMEDIATION] Action: {action}, Tunnels count: {len(tunnels_data)}")
        
        tunnels_modified = 0
        tunnels_errors = []
        
        # Traiter chaque tunnel selon son type (site-to-site ou tunnel-interface)
        for tunnel_info in tunnels_data:
            tunnel_name = tunnel_info.get('name')
            tunnel_type = tunnel_info.get('type', 'site-to-site')
            new_passphrase = tunnel_info.get('new_passphrase', '')
            
            try:
                print(f"[IPSEC REMEDIATION] Processing {tunnel_type} tunnel: {tunnel_name}")
                
                # Construire l'endpoint selon le type de tunnel
                if tunnel_type == 'site-to-site':
                    get_endpoint = 'vpn/policies/ipv4/site-to-site'
                    patch_endpoint = f'vpn/policies/ipv4/site-to-site/name/{tunnel_name}'
                    tunnel_key = 'site_to_site'
                else:  # tunnel-interface
                    get_endpoint = 'vpn/policies/ipv4/tunnel-interface'
                    patch_endpoint = f'vpn/policies/ipv4/tunnel-interface'
                    tunnel_key = 'tunnel_interface'
                
                # 1. Récupérer la configuration actuelle du tunnel
                vpn_resp, vpn_status = sw_authenticated_request(base_url, username, password, get_endpoint, 'GET')
                
                if not vpn_resp or vpn_status != 200:
                    tunnels_errors.append(f"Impossible de récupérer la configuration pour '{tunnel_name}'")
                    continue
                
                vpn_data = vpn_resp.json()
                vpn = vpn_data.get('vpn', {})
                policies = vpn.get('policy', [])
                
                # 2. Trouver le tunnel spécifique
                tunnel_to_modify = None
                for policy_wrapper in policies:
                    if isinstance(policy_wrapper, dict):
                        ipv4_data = policy_wrapper.get('ipv4', {})
                        if isinstance(ipv4_data, dict):
                            tunnel_config = ipv4_data.get(tunnel_key, {})
                            if tunnel_config.get('name') == tunnel_name:
                                tunnel_to_modify = tunnel_config
                                break
                
                if not tunnel_to_modify:
                    tunnels_errors.append(f"Tunnel '{tunnel_name}' non trouvé")
                    continue
                
                # 3. Préparer la modification selon l'action
                modified_tunnel = {
                    'vpn': {
                        'policy': [
                            {
                                'ipv4': {
                                    tunnel_key: tunnel_to_modify.copy()
                                }
                            }
                        ]
                    }
                }
                
                tunnel_config = modified_tunnel['vpn']['policy'][0]['ipv4'][tunnel_key]
                
                # Appliquer les modifications selon l'action
                if action == 'change_passphrase' and new_passphrase:
                    # Changer la passphrase
                    if 'auth_method' not in tunnel_config:
                        tunnel_config['auth_method'] = {}
                    if 'shared_secret' not in tunnel_config['auth_method']:
                        tunnel_config['auth_method']['shared_secret'] = {}
                    
                    tunnel_config['auth_method']['shared_secret']['shared_secret'] = new_passphrase
                    print(f"[IPSEC REMEDIATION] Changing passphrase for tunnel: {tunnel_name}")
                    
                elif action == 'convert_to_main':
                    # Convertir en mode Main (IKEv2)
                    if 'proposal' not in tunnel_config:
                        tunnel_config['proposal'] = {}
                    if 'ike' not in tunnel_config['proposal']:
                        tunnel_config['proposal']['ike'] = {}
                    
                    tunnel_config['proposal']['ike']['exchange'] = 'main'
                    tunnel_config['enable'] = True
                    print(f"[IPSEC REMEDIATION] Converting tunnel to Main mode: {tunnel_name}")
                    
                elif action == 'disable':
                    # Désactiver le tunnel
                    tunnel_config['enable'] = False
                    print(f"[IPSEC REMEDIATION] Disabling tunnel: {tunnel_name}")
                
                # 4. Envoyer la modification via PATCH
                patch_resp, patch_status = sw_authenticated_request(
                    base_url, username, password, 
                    patch_endpoint, 
                    'PATCH', modified_tunnel
                )
                
                if patch_resp and patch_status in [200, 201, 202]:
                    tunnels_modified += 1
                    print(f"[IPSEC REMEDIATION] Successfully modified tunnel: {tunnel_name}")
                else:
                    error_msg = f"Erreur lors de la modification du tunnel '{tunnel_name}'"
                    if patch_resp:
                        try:
                            error_data = patch_resp.json()
                            error_msg += f" - {error_data}"
                        except:
                            error_msg += f" - {patch_resp.text}"
                    tunnels_errors.append(error_msg)
                    print(f"[IPSEC REMEDIATION] {error_msg}")
                    
            except Exception as e:
                error_msg = f"Erreur lors du traitement du tunnel '{tunnel_name}': {str(e)}"
                tunnels_errors.append(error_msg)
                print(f"[IPSEC REMEDIATION] {error_msg}")
                import traceback
                traceback.print_exc()
        
        if tunnels_modified == 0:
            return jsonify({'success': False, 'message': 'Aucun tunnel n\'a pu être modifié', 'errors': tunnels_errors}), 500
        
        # 5. Récupérer la liste des tunnels qui ont déjà été modifiés (depuis la DB)
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='ipsec_vpn').first()
        already_modified_tunnels = []
        if status_rec and status_rec.notes:
            # Extraire les noms de tunnels depuis les notes (format: "tunnel1,tunnel2,tunnel3")
            try:
                import re
                match = re.search(r'Tunnels modifiés: \[(.*?)\]', status_rec.notes)
                if match:
                    already_modified_tunnels = [t.strip() for t in match.group(1).split(',') if t.strip()]
            except:
                pass
        
        # 6. Ajouter les tunnels qui viennent d'être modifiés
        newly_modified = [t['name'] for t in tunnels_data]
        all_modified_tunnels = list(set(already_modified_tunnels + newly_modified))
        
        # 7. Re-vérifier combien de tunnels actifs restent à modifier
        print(f"[IPSEC REMEDIATION] Checking remaining active tunnels...")
        
        total_active_tunnels = 0
        remaining_to_modify = 0
        
        # Vérifier site-to-site
        check_resp_s2s, check_status_s2s = sw_authenticated_request(base_url, username, password, 'vpn/policies/ipv4/site-to-site', 'GET')
        if check_resp_s2s and check_status_s2s == 200:
            check_vpn_data = check_resp_s2s.json()
            check_vpn = check_vpn_data.get('vpn', {})
            check_policies = check_vpn.get('policy', [])
            
            for policy_wrapper in check_policies:
                if isinstance(policy_wrapper, dict):
                    ipv4_data = policy_wrapper.get('ipv4', {})
                    if isinstance(ipv4_data, dict):
                        site_to_site = ipv4_data.get('site_to_site', {})
                        if site_to_site.get('enable', False):
                            total_active_tunnels += 1
                            tunnel_name = site_to_site.get('name')
                            if tunnel_name not in all_modified_tunnels:
                                remaining_to_modify += 1
        
        # Vérifier tunnel-interface
        check_resp_ti, check_status_ti = sw_authenticated_request(base_url, username, password, 'vpn/policies/ipv4/tunnel-interface', 'GET')
        if check_resp_ti and check_status_ti == 200:
            check_vpn_data_ti = check_resp_ti.json()
            check_vpn_ti = check_vpn_data_ti.get('vpn', {})
            check_policies_ti = check_vpn_ti.get('policy', [])
            
            for policy_wrapper in check_policies_ti:
                if isinstance(policy_wrapper, dict):
                    ipv4_data = policy_wrapper.get('ipv4', {})
                    if isinstance(ipv4_data, dict):
                        tunnel_interface = ipv4_data.get('tunnel_interface', {})
                        if tunnel_interface.get('enable', False):
                            total_active_tunnels += 1
                            tunnel_name = tunnel_interface.get('name')
                            if tunnel_name not in all_modified_tunnels:
                                remaining_to_modify += 1
        
        # Déterminer le status
        modified_count = len(all_modified_tunnels)
        all_resolved = (remaining_to_modify == 0 and total_active_tunnels > 0)
        partially_resolved = (modified_count > 0 and remaining_to_modify > 0)
        
        print(f"[IPSEC REMEDIATION] Total active: {total_active_tunnels}, Modified: {modified_count}, Remaining: {remaining_to_modify}")
        print(f"[IPSEC REMEDIATION] All resolved: {all_resolved}, Partially resolved: {partially_resolved}")
        
        # 8. Enregistrer l'action de remediation
        action_desc = f"IPSEC VPN passphrases changed for {tunnels_modified} tunnel(s): {', '.join(newly_modified)}"
        
        if tunnels_errors:
            action_desc += f" - Errors: {'; '.join(tunnels_errors)}"
        
        remediation_action = RemediationAction(
            firewall_id=firewall_id,
            module_name='ipsec_vpn',
            action_type='change_passphrase',
            result_message=action_desc,
            executed_at=datetime.utcnow(),
            success=True
        )
        db.session.add(remediation_action)
        db.session.commit()  # Commit immédiatement pour avoir l'ID
        
        # 9. Mettre à jour le statut
        if not status_rec:
            status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='ipsec_vpn')
            db.session.add(status_rec)
        
        status_rec.is_resolved = all_resolved
        status_rec.verification_method = 'passphrases_changed'
        
        # Créer la note avec la liste des tunnels modifiés
        tunnels_list = ', '.join(all_modified_tunnels)
        
        if all_resolved:
            status_rec.notes = f'✅ RÉSOLU - Tous les tunnels actifs ont été sécurisés ({modified_count}/{total_active_tunnels}) | Tunnels modifiés: [{tunnels_list}]'
            status_rec.resolved_at = datetime.utcnow()
        elif partially_resolved:
            status_rec.notes = f'🟠 PARTIEL - {modified_count}/{total_active_tunnels} tunnel(s) modifié(s), {remaining_to_modify} restant(s) | Tunnels modifiés: [{tunnels_list}]'
            status_rec.resolved_at = None
        else:
            status_rec.notes = f'⚠️ {modified_count} tunnel(s) modifié(s) sur {total_active_tunnels} actif(s) | Tunnels modifiés: [{tunnels_list}]'
            status_rec.resolved_at = None
        
        db.session.commit()
        
        # Message de succès
        if all_resolved:
            success_message = f'✅ RÉSOLU ! Tous les {modified_count} tunnels actifs ont été sécurisés'
        elif partially_resolved:
            success_message = f'🟠 PARTIEL : {tunnels_modified} tunnel(s) modifié(s) - {remaining_to_modify} tunnel(s) restant(s) à sécuriser'
        else:
            success_message = f'✅ {tunnels_modified} tunnel(s) modifié(s) avec succès'
        
        if tunnels_errors:
            success_message += f' - ⚠️ {len(tunnels_errors)} erreur(s)'
        
        return jsonify({
            'success': True, 
            'message': success_message,
            'all_resolved': all_resolved,
            'partially_resolved': partially_resolved,
            'remaining_to_modify': remaining_to_modify,
            'total_active': total_active_tunnels,
            'modified_count': modified_count,
            'tunnels_modified': tunnels_modified,
            'errors': tunnels_errors
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"ERROR in fix_ipsec_vpn_tunnels: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/ldap/change-bind-password', methods=['POST'])
def change_ldap_bind_password():
    """Changer le mot de passe LDAP bind"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        
        # Accepter firewall_id OU ip/username/password
        firewall_id = data.get('firewall_id')
        if firewall_id:
            firewall = Firewall.query.get(firewall_id)
            if not firewall:
                return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
            ip = firewall.ip
            username = firewall.username
            password = firewall.get_password()
        else:
            ip = data.get('ip')
            username = data.get('username')
            password = data.get('password')
            if not all([ip, username, password]):
                return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
            firewall = Firewall.query.filter_by(ip=ip).first()
            firewall_id = firewall.id if firewall else None
        
        new_bind_password = data.get('bind_password') or data.get('new_bind_password') or data.get('new_password') or data.get('newPassword')
        
        print(f"DEBUG LDAP: data keys={list(data.keys())}, new_bind_password={'***' if new_bind_password else None}")
        
        if not new_bind_password:
            return jsonify({'success': False, 'message': f'Nouveau mot de passe requis. Reçu: {list(data.keys())}'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # 1. Récupérer la config LDAP actuelle
        ldap_resp, ldap_status = sw_authenticated_request(base_url, username, password, 'user/ldap/servers', 'GET')
        
        if not ldap_resp or ldap_status != 200:
            return jsonify({'success': False, 'message': f'Impossible de récupérer la config LDAP: {ldap_status}'}), 500
        
        ldap_data = ldap_resp.json()
        servers = ldap_data.get('user', {}).get('ldap', {}).get('server', [])
        
        if isinstance(servers, dict):
            servers = [servers]
        
        if not servers:
            return jsonify({'success': False, 'message': 'Aucun serveur LDAP configuré'}), 400
        
        # 2. Modifier le bind_password du premier serveur
        first_server = dict(servers[0])
        first_server['bind_password'] = new_bind_password
        
        # 3. Envoyer PATCH
        patch_data = {'user': {'ldap': {'server': [first_server]}}}
        response, status = sw_authenticated_request(base_url, username, password, 'user/ldap/servers', 'PATCH', patch_data)
        
        if response and status in [200, 201, 204]:
            # 4. Mettre à jour la DB
            if firewall_id:
                action = RemediationAction(
                    firewall_id=firewall_id,
                    module_name='ldap',
                    action_type='change_bind_password',
                    result_message='Bind password changé avec succès',
                    executed_at=datetime.utcnow(),
                    success=True
                )
                db.session.add(action)
                
                # Mettre à jour le statut de résolution
                status_record = ModuleResolutionStatus.query.filter_by(
                    firewall_id=firewall_id,
                    module_name='ldap'
                ).first()
                
                if not status_record:
                    status_record = ModuleResolutionStatus(
                        firewall_id=firewall_id,
                        module_name='ldap'
                    )
                    db.session.add(status_record)
                
                # LDAP = 1 seule action → Vert directement
                status_record.is_resolved = True
                status_record.verification_method = 'bind_password_changed'
                status_record.notes = 'Bind password changé'
                status_record.resolved_at = datetime.utcnow()
                
                db.session.commit()
            
            return jsonify({'success': True, 'message': 'Bind password changé avec succès'})
        else:
            return jsonify({'success': False, 'message': f'Erreur: {status}'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/radius/change-secrets', methods=['POST'])
def change_radius_secrets():
    """Changer les secrets RADIUS"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        
        # Accepter firewall_id OU ip/username/password
        firewall_id = data.get('firewall_id')
        if firewall_id:
            firewall = Firewall.query.get(firewall_id)
            if not firewall:
                return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
            ip = firewall.ip
            username = firewall.username
            password = firewall.get_password()
        else:
            ip = data.get('ip')
            username = data.get('username')
            password = data.get('password')
            if not all([ip, username, password]):
                return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
            firewall = Firewall.query.filter_by(ip=ip).first()
            firewall_id = firewall.id if firewall else None
        
        # Le frontend peut envoyer soit 'secrets' (array) soit 'new_secret' (string)
        secrets_array = data.get('secrets', [])
        new_secret = data.get('new_secret') or data.get('shared_secret') or data.get('secret')
        
        print(f"DEBUG RADIUS SECRET: secrets_array={secrets_array}, type={type(secrets_array)}")
        
        # Si secrets array, prendre le premier
        if secrets_array and len(secrets_array) > 0:
            new_secret = secrets_array[0].get('secret') if isinstance(secrets_array[0], dict) else None
            print(f"DEBUG RADIUS SECRET: extracted new_secret={new_secret}")
        
        if not new_secret:
            return jsonify({'success': False, 'message': f'Nouveau secret requis. Reçu: {list(data.keys())}, secrets={secrets_array}'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # 1. Récupérer la config RADIUS actuelle
        radius_resp, radius_status = sw_authenticated_request(base_url, username, password, 'user/radius/servers', 'GET')
        print(f"DEBUG RADIUS: Tentative 1 (user/radius/servers) status={radius_status}")
        
        if not radius_resp or radius_status != 200:
            radius_resp, radius_status = sw_authenticated_request(base_url, username, password, 'user/radius', 'GET')
            print(f"DEBUG RADIUS: Tentative 2 (user/radius) status={radius_status}")
        
        if not radius_resp or radius_status != 200:
            return jsonify({'success': False, 'message': f'Impossible de récupérer la config RADIUS: {radius_status}'}), 500
        
        radius_data = radius_resp.json()
        print(f"DEBUG RADIUS: radius_data={radius_data}")
        
        servers = radius_data.get('user', {}).get('radius', {}).get('server', [])
        print(f"DEBUG RADIUS: servers found={len(servers) if isinstance(servers, list) else ('1' if servers else '0')}")
        
        if isinstance(servers, dict):
            servers = [servers]
        
        if not servers:
            return jsonify({'success': False, 'message': f'Aucun serveur RADIUS trouvé. Structure reçue: {list(radius_data.keys())}'}), 400
        
        # 2. Modifier le shared_secret du premier serveur
        first_server = dict(servers[0])
        first_server['shared_secret'] = new_secret
        
        # 3. Envoyer PATCH
        patch_data = {'user': {'radius': {'server': [first_server]}}}
        response, status = sw_authenticated_request(base_url, username, password, 'user/radius/servers', 'PATCH', patch_data)
        
        if response and status in [200, 201, 204]:
            # 4. Mettre à jour la DB
            if firewall_id:
                action = RemediationAction(
                    firewall_id=firewall_id,
                    module_name='radius',
                    action_type='change_shared_secret',
                    result_message='Shared secret changé avec succès',
                    executed_at=datetime.utcnow(),
                    success=True
                )
                db.session.add(action)
                
                status_record = ModuleResolutionStatus.query.filter_by(
                    firewall_id=firewall_id,
                    module_name='radius'
                ).first()
                
                if not status_record:
                    status_record = ModuleResolutionStatus(
                        firewall_id=firewall_id,
                        module_name='radius'
                    )
                    db.session.add(status_record)
                
                # RADIUS = 1 seule action → Vert directement
                status_record.is_resolved = True
                status_record.verification_method = 'shared_secret_changed'
                status_record.notes = 'Shared secret changé'
                status_record.resolved_at = datetime.utcnow()
                
                db.session.commit()
            
            return jsonify({'success': True, 'message': 'Shared secret changé avec succès'})
        else:
            return jsonify({'success': False, 'message': f'Erreur: {status}'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/tacacs/change-secrets', methods=['POST'])
def change_tacacs_secrets():
    """Changer les secrets TACACS+"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        
        # Accepter firewall_id OU ip/username/password
        firewall_id = data.get('firewall_id')
        if firewall_id:
            firewall = Firewall.query.get(firewall_id)
            if not firewall:
                return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
            ip = firewall.ip
            username = firewall.username
            password = firewall.get_password()
        else:
            ip = data.get('ip')
            username = data.get('username')
            password = data.get('password')
            if not all([ip, username, password]):
                return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
            firewall = Firewall.query.filter_by(ip=ip).first()
            firewall_id = firewall.id if firewall else None
        
        # Le frontend peut envoyer soit 'secrets' (array) soit 'new_secret' (string)
        secrets_array = data.get('secrets', [])
        new_secret = data.get('new_secret') or data.get('shared_secret') or data.get('secret')
        
        print(f"DEBUG TACACS SECRET: secrets_array={secrets_array}, type={type(secrets_array)}")
        
        # Si secrets array, prendre le premier
        if secrets_array and len(secrets_array) > 0:
            new_secret = secrets_array[0].get('secret') if isinstance(secrets_array[0], dict) else None
            print(f"DEBUG TACACS SECRET: extracted new_secret={'***' if new_secret else None}")
        
        if not new_secret:
            return jsonify({'success': False, 'message': f'Nouveau secret requis. Reçu: {list(data.keys())}, secrets={secrets_array}'}), 400
        
        ip = ip.strip()
        if not ip.startswith('http'):
            base_url = f'https://{ip}' if ':' in ip else f'https://{ip}:443'
        else:
            base_url = ip.rstrip('/').split('/api/sonicos')[0] if '/api/sonicos' in ip else ip.rstrip('/')
        
        # 1. Récupérer la config TACACS actuelle
        tacacs_resp, tacacs_status = sw_authenticated_request(base_url, username, password, 'user/tacacs/servers', 'GET')
        if not tacacs_resp or tacacs_status != 200:
            tacacs_resp, tacacs_status = sw_authenticated_request(base_url, username, password, 'user/tacacs', 'GET')
        
        if not tacacs_resp or tacacs_status != 200:
            return jsonify({'success': False, 'message': f'Impossible de récupérer la config TACACS: {tacacs_status}'}), 500
        
        tacacs_data = tacacs_resp.json()
        servers = tacacs_data.get('user', {}).get('tacacs', {}).get('server', [])
        
        if isinstance(servers, dict):
            servers = [servers]
        
        if not servers:
            return jsonify({'success': False, 'message': 'Aucun serveur TACACS configuré'}), 400
        
        # 2. Modifier le shared_secret du premier serveur
        first_server = dict(servers[0])
        first_server['shared_secret'] = new_secret
        
        # 3. Envoyer PATCH
        patch_data = {'user': {'tacacs': {'server': [first_server]}}}
        response, status = sw_authenticated_request(base_url, username, password, 'user/tacacs/servers', 'PATCH', patch_data)
        
        if response and status in [200, 201, 204]:
            # 4. Mettre à jour la DB
            if firewall_id:
                action = RemediationAction(
                    firewall_id=firewall_id,
                    module_name='tacacs',
                    action_type='change_shared_secret',
                    result_message='Shared secret changé avec succès',
                    executed_at=datetime.utcnow(),
                    success=True
                )
                db.session.add(action)
                
                status_record = ModuleResolutionStatus.query.filter_by(
                    firewall_id=firewall_id,
                    module_name='tacacs'
                ).first()
                
                if not status_record:
                    status_record = ModuleResolutionStatus(
                        firewall_id=firewall_id,
                        module_name='tacacs'
                    )
                    db.session.add(status_record)
                
                # TACACS = 1 seule action → Vert directement
                status_record.is_resolved = True
                status_record.verification_method = 'shared_secret_changed'
                status_record.notes = 'Shared secret changé'
                status_record.resolved_at = datetime.utcnow()
                
                db.session.commit()
            
            return jsonify({'success': True, 'message': 'Shared secret changé avec succès'})
        else:
            return jsonify({'success': False, 'message': f'Erreur: {status}'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/sso/change-agent-keys', methods=['POST'])
def change_sso_agent_keys():
    """Changer les shared keys des SSO Agents"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        
        if not firewall_id:
            return jsonify({'success': False, 'message': 'firewall_id requis'}), 400
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username, password = firewall.username, firewall.get_password()
        
        secrets_array = data.get('secrets', [])
        if not secrets_array or len(secrets_array) == 0:
            return jsonify({'success': False, 'message': 'Au moins un secret requis'}), 400
        
        new_key = secrets_array[0].get('secret') if isinstance(secrets_array[0], dict) else None
        if not new_key:
            return jsonify({'success': False, 'message': 'Secret invalide'}), 400
        
        # Récupérer config SSO agents
        resp, status = sw_authenticated_request(base_url, username, password, 'user/sso/agents', 'GET')
        if not resp or status != 200:
            return jsonify({'success': False, 'message': f'Erreur récupération config: {status}'}), 500
        
        sso_data = resp.json()
        agents = sso_data.get('user', {}).get('sso', {}).get('agent', [])
        if isinstance(agents, dict):
            agents = [agents]
        if not agents:
            return jsonify({'success': False, 'message': 'Aucun agent SSO configuré'}), 400
        
        # Modifier shared_key
        first_agent = dict(agents[0])
        first_agent['shared_key'] = new_key
        
        patch_data = {'user': {'sso': {'agent': [first_agent]}}}
        response, status = sw_authenticated_request(base_url, username, password, 'user/sso/agents', 'PATCH', patch_data)
        
        if response and status in [200, 201, 204]:
            # Enregistrer l'action
            action = RemediationAction(
                firewall_id=firewall_id,
                module_name='sso_agent',
                action_type='change_shared_key',
                result_message='SSO Agent key changé',
                executed_at=datetime.utcnow(),
                success=True
            )
            db.session.add(action)
            
            # Commit l'action d'abord
            db.session.commit()
            
            # Récupérer config SSO complète pour déterminer combien de types sont configurés
            agents_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/agents', 'GET')
            ts_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/terminal-services-agents', 'GET')
            radius_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/radius-accounting-clients', 'GET')
            
            has_agent = agents_resp and agents_resp.status_code == 200 and len(agents_resp.json().get('user', {}).get('sso', {}).get('agent', [])) > 0
            has_ts = ts_resp and ts_resp.status_code == 200 and len(ts_resp.json().get('user', {}).get('sso', {}).get('terminal_services_agent', [])) > 0
            has_radius = radius_resp and radius_resp.status_code == 200 and len(radius_resp.json().get('user', {}).get('sso', {}).get('radius_accounting_client', [])) > 0
            
            # Compter combien de types sont patchés
            agent_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_agent', success=True).count() > 0
            ts_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_ts', success=True).count() > 0
            radius_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_radius', success=True).count() > 0
            
            total_configured = sum([has_agent, has_ts, has_radius])
            total_patched = sum([agent_patched, ts_patched, radius_patched])
            
            # Mettre à jour le statut de sso_agent (ce qui vient d'être patché)
            status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_agent').first()
            if not status_rec:
                status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_agent')
                db.session.add(status_rec)
            
            status_rec.is_resolved = True  # Ce module est résolu
            status_rec.verification_method = 'shared_key_changed'
            status_rec.notes = f'SSO Agent patché - Total: {total_patched}/{total_configured} types SSO patchés'
            status_rec.resolved_at = datetime.utcnow()
            
            # Mettre à jour les statuts des autres modules (ne pas les marquer comme résolus si non configurés)
            if has_ts:
                ts_status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_ts').first()
                if not ts_status:
                    ts_status = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_ts', is_resolved=False)
                    db.session.add(ts_status)
                if not ts_status.is_resolved:
                    ts_status.notes = f'TS Agent non patché - Total: {total_patched}/{total_configured} types SSO patchés'
                    ts_status.verification_method = 'shared_key_changed'
            
            if has_radius:
                radius_status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_radius').first()
                if not radius_status:
                    radius_status = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_radius', is_resolved=False)
                    db.session.add(radius_status)
                if not radius_status.is_resolved:
                    radius_status.notes = f'RADIUS non patché - Total: {total_patched}/{total_configured} types SSO patchés'
                    radius_status.verification_method = 'shared_key_changed'
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'SSO Agent key changé avec succès'})
        else:
            return jsonify({'success': False, 'message': f'Erreur: {status}'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/sso/change-ts-keys', methods=['POST'])
def change_sso_ts_keys():
    """Changer les shared keys des SSO Terminal Services"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        
        if not firewall_id:
            return jsonify({'success': False, 'message': 'firewall_id requis'}), 400
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username, password = firewall.username, firewall.get_password()
        
        secrets_array = data.get('secrets', [])
        if not secrets_array or len(secrets_array) == 0:
            return jsonify({'success': False, 'message': 'Au moins un secret requis'}), 400
        
        new_key = secrets_array[0].get('secret') if isinstance(secrets_array[0], dict) else None
        if not new_key:
            return jsonify({'success': False, 'message': 'Secret invalide'}), 400
        
        # Récupérer config Terminal Services
        resp, status = sw_authenticated_request(base_url, username, password, 'user/sso/terminal-services-agents', 'GET')
        if not resp or status != 200:
            return jsonify({'success': False, 'message': f'Erreur récupération config: {status}'}), 500
        
        sso_data = resp.json()
        ts_agents = sso_data.get('user', {}).get('sso', {}).get('terminal_services_agent', [])
        if isinstance(ts_agents, dict):
            ts_agents = [ts_agents]
        if not ts_agents:
            return jsonify({'success': False, 'message': 'Aucun TS agent configuré'}), 400
        
        # Modifier shared_key
        first_agent = dict(ts_agents[0])
        first_agent['shared_key'] = new_key
        
        patch_data = {'user': {'sso': {'terminal_services_agent': [first_agent]}}}
        response, status = sw_authenticated_request(base_url, username, password, 'user/sso/terminal-services-agents', 'PATCH', patch_data)
        
        if response and status in [200, 201, 204]:
            action = RemediationAction(
                firewall_id=firewall_id,
                module_name='sso_ts',
                action_type='change_shared_key',
                result_message='SSO TS Agent key changé',
                executed_at=datetime.utcnow(),
                success=True
            )
            db.session.add(action)
            
            # Commit l'action d'abord
            db.session.commit()
            
            # Récupérer config SSO complète
            agents_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/agents', 'GET')
            ts_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/terminal-services-agents', 'GET')
            radius_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/radius-accounting-clients', 'GET')
            
            has_agent = agents_resp and agents_resp.status_code == 200 and len(agents_resp.json().get('user', {}).get('sso', {}).get('agent', [])) > 0
            has_ts = ts_resp and ts_resp.status_code == 200 and len(ts_resp.json().get('user', {}).get('sso', {}).get('terminal_services_agent', [])) > 0
            has_radius = radius_resp and radius_resp.status_code == 200 and len(radius_resp.json().get('user', {}).get('sso', {}).get('radius_accounting_client', [])) > 0
            
            agent_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_agent', success=True).count() > 0
            ts_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_ts', success=True).count() > 0
            radius_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_radius', success=True).count() > 0
            
            total_configured = sum([has_agent, has_ts, has_radius])
            total_patched = sum([agent_patched, ts_patched, radius_patched])
            
            # Mettre à jour le statut de sso_ts (ce qui vient d'être patché)
            status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_ts').first()
            if not status_rec:
                status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_ts')
                db.session.add(status_rec)
            
            status_rec.is_resolved = True  # Ce module est résolu
            status_rec.verification_method = 'shared_key_changed'
            status_rec.notes = f'TS Agent patché - Total: {total_patched}/{total_configured} types SSO patchés'
            status_rec.resolved_at = datetime.utcnow()
            
            # Mettre à jour les statuts des autres modules (ne pas les marquer comme résolus si non configurés)
            if has_agent:
                agent_status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_agent').first()
                if not agent_status:
                    agent_status = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_agent', is_resolved=False)
                    db.session.add(agent_status)
                if not agent_status.is_resolved:
                    agent_status.notes = f'SSO Agent non patché - Total: {total_patched}/{total_configured} types SSO patchés'
                    agent_status.verification_method = 'shared_key_changed'
            
            if has_radius:
                radius_status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_radius').first()
                if not radius_status:
                    radius_status = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_radius', is_resolved=False)
                    db.session.add(radius_status)
                if not radius_status.is_resolved:
                    radius_status.notes = f'RADIUS non patché - Total: {total_patched}/{total_configured} types SSO patchés'
                    radius_status.verification_method = 'shared_key_changed'
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'SSO TS Agent key changé avec succès'})
        else:
            return jsonify({'success': False, 'message': f'Erreur: {status}'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/sso/change-radius-secrets', methods=['POST'])
def change_sso_radius_secrets():
    """Changer les shared secrets des SSO RADIUS Accounting"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        data = request.json
        firewall_id = data.get('firewall_id')
        
        if not firewall_id:
            return jsonify({'success': False, 'message': 'firewall_id requis'}), 400
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        base_url = get_base_url(firewall.ip)
        username, password = firewall.username, firewall.get_password()
        
        secrets_array = data.get('secrets', [])
        if not secrets_array or len(secrets_array) == 0:
            return jsonify({'success': False, 'message': 'Au moins un secret requis'}), 400
        
        new_secret = secrets_array[0].get('secret') if isinstance(secrets_array[0], dict) else None
        if not new_secret:
            return jsonify({'success': False, 'message': 'Secret invalide'}), 400
        
        # Récupérer config RADIUS Accounting
        resp, status = sw_authenticated_request(base_url, username, password, 'user/sso/radius-accounting-clients', 'GET')
        if not resp or status != 200:
            return jsonify({'success': False, 'message': f'Erreur récupération config: {status}'}), 500
        
        sso_data = resp.json()
        radius_clients = sso_data.get('user', {}).get('sso', {}).get('radius_accounting_client', [])
        if isinstance(radius_clients, dict):
            radius_clients = [radius_clients]
        if not radius_clients:
            return jsonify({'success': False, 'message': 'Aucun RADIUS accounting configuré'}), 400
        
        # Modifier shared_secret
        first_client = dict(radius_clients[0])
        first_client['shared_secret'] = new_secret
        
        patch_data = {'user': {'sso': {'radius_accounting_client': [first_client]}}}
        response, status = sw_authenticated_request(base_url, username, password, 'user/sso/radius-accounting-clients', 'PATCH', patch_data)
        
        if response and status in [200, 201, 204]:
            action = RemediationAction(
                firewall_id=firewall_id,
                module_name='sso_radius',
                action_type='change_shared_secret',
                result_message='SSO RADIUS Accounting secret changé',
                executed_at=datetime.utcnow(),
                success=True
            )
            db.session.add(action)
            
            # Commit l'action d'abord
            db.session.commit()
            
            # Récupérer config SSO complète
            agents_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/agents', 'GET')
            ts_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/terminal-services-agents', 'GET')
            radius_resp, _ = sw_authenticated_request(base_url, username, password, 'user/sso/radius-accounting-clients', 'GET')
            
            has_agent = agents_resp and agents_resp.status_code == 200 and len(agents_resp.json().get('user', {}).get('sso', {}).get('agent', [])) > 0
            has_ts = ts_resp and ts_resp.status_code == 200 and len(ts_resp.json().get('user', {}).get('sso', {}).get('terminal_services_agent', [])) > 0
            has_radius = radius_resp and radius_resp.status_code == 200 and len(radius_resp.json().get('user', {}).get('sso', {}).get('radius_accounting_client', [])) > 0
            
            agent_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_agent', success=True).count() > 0
            ts_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_ts', success=True).count() > 0
            radius_patched = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name='sso_radius', success=True).count() > 0
            
            total_configured = sum([has_agent, has_ts, has_radius])
            total_patched = sum([agent_patched, ts_patched, radius_patched])
            
            # Mettre à jour le statut de sso_radius (ce qui vient d'être patché)
            status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_radius').first()
            if not status_rec:
                status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_radius')
                db.session.add(status_rec)
            
            status_rec.is_resolved = True  # Ce module est résolu
            status_rec.verification_method = 'shared_key_changed'
            status_rec.notes = f'RADIUS patché - Total: {total_patched}/{total_configured} types SSO patchés'
            status_rec.resolved_at = datetime.utcnow()
            
            # Mettre à jour les statuts des autres modules (ne pas les marquer comme résolus si non configurés)
            if has_agent:
                agent_status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_agent').first()
                if not agent_status:
                    agent_status = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_agent', is_resolved=False)
                    db.session.add(agent_status)
                if not agent_status.is_resolved:
                    agent_status.notes = f'SSO Agent non patché - Total: {total_patched}/{total_configured} types SSO patchés'
                    agent_status.verification_method = 'shared_key_changed'
            
            if has_ts:
                ts_status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='sso_ts').first()
                if not ts_status:
                    ts_status = ModuleResolutionStatus(firewall_id=firewall_id, module_name='sso_ts', is_resolved=False)
                    db.session.add(ts_status)
                if not ts_status.is_resolved:
                    ts_status.notes = f'TS Agent non patché - Total: {total_patched}/{total_configured} types SSO patchés'
                    ts_status.verification_method = 'shared_key_changed'
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'SSO RADIUS Accounting secret changé avec succès'})
        else:
            return jsonify({'success': False, 'message': f'Erreur: {status}'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# CSE Remediation Routes
@app.route('/api/remediation/start/<int:firewall_id>/cse', methods=['POST'])
def start_cse_remediation(firewall_id):
    """Démarrer la remediation CSE"""
    try:
        from models import ModuleResolutionStatus, RemediationAction, CSERemediationTimer
        from datetime import datetime
        
        data = request.json
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Vérifier s'il y a déjà un timer actif
        existing_timer = CSERemediationTimer.query.filter_by(firewall_id=firewall_id, is_active=True).first()
        if existing_timer:
            return jsonify({'success': False, 'message': 'CSE remediation timer already active'}), 400
        
        # Créer le timer de 30 secondes (pour les tests)
        timer = CSERemediationTimer(
            firewall_id=firewall_id,
            duration_seconds=30  # 30 secondes pour les tests
        )
        db.session.add(timer)
        
        # Créer l'action de remediation
        action = RemediationAction(
            firewall_id=firewall_id,
            module_name='cse',
            action_type='start_remediation',
            result_message='CSE remediation started - Manual action required in MySonicWall',
            executed_at=datetime.utcnow(),
            success=True
        )
        db.session.add(action)
        
        # Marquer le statut comme non résolu
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='cse').first()
        if not status_rec:
            status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='cse')
            db.session.add(status_rec)
        
        status_rec.is_resolved = False
        status_rec.verification_method = 'manual_dissociation_required'
        status_rec.notes = 'CSE remediation started - Manual dissociation required in MySonicWall'
        status_rec.resolved_at = None
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'CSE remediation started successfully', 'timer': timer.to_dict()})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/timer/<int:firewall_id>/cse', methods=['GET'])
def get_cse_timer_status(firewall_id):
    """Récupérer le statut du timer CSE"""
    try:
        from models import CSERemediationTimer, ModuleResolutionStatus
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Vérifier s'il y a un timer actif
        active_timer = CSERemediationTimer.query.filter_by(firewall_id=firewall_id, is_active=True).first()
        
        # Vérifier s'il y a un statut "en attente de réactivation"
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='cse').first()
        is_waiting_reactivation = status_rec and status_rec.verification_method == 'timer_expired_waiting_reactivation'
        
        print(f"DEBUG CSE Timer - Firewall {firewall_id}:")
        print(f"  - active_timer: {active_timer}")
        print(f"  - status_rec: {status_rec}")
        print(f"  - is_waiting_reactivation: {is_waiting_reactivation}")
        if status_rec:
            print(f"  - verification_method: {status_rec.verification_method}")
            print(f"  - is_resolved: {status_rec.is_resolved}")
        
        if active_timer:
            # Vérifier si le timer est expiré
            if active_timer.is_expired():
                active_timer.complete()
                
                # Créer un statut "en attente de réactivation" si ce n'est pas déjà fait
                if not status_rec or status_rec.is_resolved:
                    if not status_rec:
                        status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='cse')
                        db.session.add(status_rec)
                    
                    status_rec.is_resolved = False
                    status_rec.verification_method = 'timer_expired_waiting_reactivation'
                    status_rec.notes = 'CSE remediation timer expired - Waiting for manual reactivation'
                    status_rec.resolved_at = None
                
                db.session.commit()
                return jsonify({'success': True, 'timer': None, 'expired': True})
            else:
                return jsonify({'success': True, 'timer': active_timer.to_dict(), 'expired': False})
        elif is_waiting_reactivation:
            # Timer expiré mais statut persistant existe
            return jsonify({'success': True, 'timer': None, 'expired': True})
        else:
            return jsonify({'success': True, 'timer': None, 'expired': False})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/can-reactivate/<int:firewall_id>/cse', methods=['GET'])
def can_reactivate_cse(firewall_id):
    """Vérifier si on peut réactiver CSE (timer expiré)"""
    try:
        from models import CSERemediationTimer, ModuleResolutionStatus
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Vérifier s'il y a un timer expiré (même inactif)
        expired_timer = CSERemediationTimer.query.filter_by(firewall_id=firewall_id, is_active=False).first()
        
        # Vérifier s'il y a un statut "en attente de réactivation"
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='cse').first()
        is_waiting_reactivation = status_rec and status_rec.verification_method == 'timer_expired_waiting_reactivation'
        
        can_reactivate = (expired_timer is not None) or is_waiting_reactivation
        
        return jsonify({
            'success': True, 
            'can_reactivate': can_reactivate,
            'expired_timer': expired_timer.to_dict() if expired_timer else None,
            'waiting_reactivation': is_waiting_reactivation
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/resolve/<int:firewall_id>/cse', methods=['POST'])
def resolve_cse_remediation(firewall_id):
    """Marquer la remediation CSE comme résolue"""
    try:
        from models import ModuleResolutionStatus, RemediationAction, CSERemediationTimer
        from datetime import datetime
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Marquer le timer comme terminé s'il existe
        timer = CSERemediationTimer.query.filter_by(firewall_id=firewall_id, is_active=True).first()
        if timer:
            timer.complete()
        
        # Créer l'action de résolution
        action = RemediationAction(
            firewall_id=firewall_id,
            module_name='cse',
            action_type='resolve_remediation',
            result_message='CSE remediation completed successfully',
            executed_at=datetime.utcnow(),
            success=True
        )
        db.session.add(action)
        
        # Marquer le statut comme résolu
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='cse').first()
        if not status_rec:
            status_rec = ModuleResolutionStatus(firewall_id=firewall_id, module_name='cse')
            db.session.add(status_rec)
        
        status_rec.is_resolved = True
        status_rec.verification_method = 'cse_reactivated'
        status_rec.notes = 'CSE remediation completed - CSE reactivated successfully'
        status_rec.resolved_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'CSE remediation marked as resolved'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/reset/<int:firewall_id>/cse', methods=['POST'])
def reset_cse_remediation(firewall_id):
    """Reset le statut de remediation CSE"""
    try:
        from models import ModuleResolutionStatus, CSERemediationTimer
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Supprimer le timer existant
        timer = CSERemediationTimer.query.filter_by(firewall_id=firewall_id).first()
        if timer:
            db.session.delete(timer)
        
        # Supprimer le statut existant
        status_rec = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name='cse').first()
        if status_rec:
            db.session.delete(status_rec)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'CSE remediation status reset'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation-status/<int:firewall_id>/<module_name>', methods=['GET'])
@app.route('/api/remediation/status/<int:firewall_id>/<module_name>', methods=['GET'])
def get_remediation_status(firewall_id, module_name):
    """Récupérer le statut de remediation"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        
        status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name=module_name).first()
        actions = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name=module_name).order_by(RemediationAction.executed_at.desc()).all()
        
        if status:
            return jsonify({
                'success': True,
                'status': {
                    'is_resolved': status.is_resolved,
                    'resolution_date': status.resolved_at.isoformat() if status.resolved_at else None,
                    'notes': status.notes,
                    'verification_method': status.verification_method
                },
                'actions': [{'action_type': a.action_type, 'action_date': a.executed_at.isoformat(), 'details': a.result_message or ''} for a in actions]
            })
        else:
            return jsonify({'success': True, 'status': None, 'actions': []})
    except Exception as e:
        print(f"ERROR in get_remediation_status: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/resolve/<int:firewall_id>/<module_name>', methods=['POST'])
def resolve_module_remediation(firewall_id, module_name):
    """Marquer n'importe quel module comme résolu"""
    try:
        print(f"DEBUG: Resolving module {module_name} for firewall {firewall_id}")
        from models import ModuleResolutionStatus, RemediationAction
        from datetime import datetime
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            print(f"DEBUG: Firewall {firewall_id} not found")
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Vérifier si le statut existe déjà
        print(f"DEBUG: Checking existing status for {module_name}")
        status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name=module_name).first()
        
        if status:
            print(f"DEBUG: Updating existing status for {module_name}")
            # Mettre à jour le statut existant
            status.is_resolved = True
            status.resolved_at = datetime.utcnow()
            status.verification_method = request.json.get('verification_method', 'manual_resolution')
            status.notes = request.json.get('notes', 'Résolu manuellement depuis l\'audit')
        else:
            print(f"DEBUG: Creating new status for {module_name}")
            # Créer un nouveau statut
            status = ModuleResolutionStatus(
                firewall_id=firewall_id,
                module_name=module_name,
                is_resolved=True,
                resolved_at=datetime.utcnow(),
                verification_method=request.json.get('verification_method', 'manual_resolution'),
                notes=request.json.get('notes', 'Résolu manuellement depuis l\'audit')
            )
            db.session.add(status)
        
        # Créer l'action de résolution
        action = RemediationAction(
            firewall_id=firewall_id,
            module_name=module_name,
            action_type='resolve_remediation',
            result_message=f'{module_name} remediation completed successfully',
            executed_at=datetime.utcnow()
        )
        db.session.add(action)
        
        print(f"DEBUG: Committing changes for {module_name}")
        db.session.commit()
        print(f"DEBUG: Successfully resolved {module_name}")
        
        return jsonify({'success': True, 'message': f'{module_name} remediation marked as resolved'})
        
    except Exception as e:
        print(f"ERROR in resolve_module_remediation for {module_name}: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/remediation/reset/<int:firewall_id>/<module_name>', methods=['DELETE'])
def reset_module_remediation(firewall_id, module_name):
    """Supprimer le statut de résolution d'un module"""
    try:
        from models import ModuleResolutionStatus, RemediationAction
        
        firewall = Firewall.query.get(firewall_id)
        if not firewall:
            return jsonify({'success': False, 'message': 'Firewall non trouvé'}), 404
        
        # Supprimer le statut de résolution
        status = ModuleResolutionStatus.query.filter_by(firewall_id=firewall_id, module_name=module_name).first()
        if status:
            db.session.delete(status)
        
        # Supprimer les actions de remediation
        actions = RemediationAction.query.filter_by(firewall_id=firewall_id, module_name=module_name).all()
        for action in actions:
            db.session.delete(action)
        
        db.session.commit()
        return jsonify({'success': True, 'message': f'{module_name} remediation status reset'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/generate-pdf-report', methods=['POST'])
def generate_pdf_report():
    """
    Génère un rapport PDF stylé avec les données de sécurité et remédiation
    """
    try:
        data = request.json
        firewall_ids = data.get('firewall_ids', [])
        report_type = data.get('report_type', 'security_intervention')
        include_remediation_history = data.get('include_remediation_history', True)
        include_score_analysis = data.get('include_score_analysis', True)
        
        if not firewall_ids:
            return jsonify({'success': False, 'message': 'Aucun firewall sélectionné'}), 400
        
        # Récupérer les firewalls sélectionnés
        firewalls = Firewall.query.filter(Firewall.id.in_(firewall_ids)).all()
        if not firewalls:
            return jsonify({'success': False, 'message': 'Aucun firewall trouvé'}), 404
        
        # Générer le PDF
        pdf_buffer = generate_security_report_pdf(
            firewalls=firewalls,
            report_type=report_type,
            include_remediation_history=include_remediation_history,
            include_score_analysis=include_score_analysis
        )
        
        # Retourner le PDF
        pdf_buffer.seek(0)
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'rapport_securite_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
            mimetype='application/pdf'
        )
        
    except Exception as e:
        print(f"Erreur génération PDF: {str(e)}")
        return jsonify({'success': False, 'message': f'Erreur génération PDF: {str(e)}'}), 500

def create_modern_chart(data, chart_type='pie'):
    """Crée un graphique moderne avec ReportLab"""
    try:
        drawing = Drawing(400, 300)
        
        # Vérifier et normaliser les données
        if not isinstance(data, dict) or 'values' not in data or 'labels' not in data:
            print(f"Données invalides: {data}")
            return create_error_chart("Données invalides")
        
        values = data['values']
        labels = data['labels']
        
        # S'assurer que values est une liste
        if not isinstance(values, list):
            values = [values] if isinstance(values, (int, float)) else []
        
        # S'assurer que labels est une liste
        if not isinstance(labels, list):
            labels = [labels] if isinstance(labels, str) else []
        
        if chart_type == 'pie':
            pie = Pie()
            pie.x = 150
            pie.y = 50
            pie.width = 200
            pie.height = 200
            
            if not values or sum(values) == 0:
                # Graphique vide stylé
                empty_circle = Circle(250, 150, 80)
                empty_circle.fillColor = colors.HexColor('#E8E8E8')
                empty_circle.strokeColor = colors.HexColor('#CCCCCC')
                empty_circle.strokeWidth = 3
                drawing.add(empty_circle)
                
                empty_text = String(250, 150, "Aucune donnée", textAnchor='middle')
                empty_text.fontName = 'Helvetica-Bold'
                empty_text.fontSize = 14
                empty_text.fillColor = colors.HexColor('#666666')
                drawing.add(empty_text)
                return drawing
            
            pie.data = values
            pie.labels = labels
            pie.slices.strokeWidth = 3
            pie.slices.strokeColor = colors.white
            
            # Couleurs modernes et vives
            modern_colors = [
                colors.HexColor('#00C851'),  # Vert moderne
                colors.HexColor('#FF4444'),  # Rouge moderne
                colors.HexColor('#FF8800'),  # Orange moderne
                colors.HexColor('#33B5E5'),  # Bleu moderne
                colors.HexColor('#AA66CC'),  # Violet moderne
                colors.HexColor('#FFBB33'),  # Jaune moderne
            ]
            
            for i, color in enumerate(modern_colors[:len(values)]):
                if i < len(pie.slices):
                    pie.slices[i].fillColor = color
            
            drawing.add(pie)
            
            # Titre moderne
            title = String(250, 280, data.get('title', 'Security Status'), textAnchor='middle')
            title.fontName = 'Helvetica-Bold'
            title.fontSize = 16
            title.fillColor = colors.HexColor('#2E3440')
            drawing.add(title)
        
        elif chart_type == 'bar':
            chart = VerticalBarChart()
            chart.x = 50
            chart.y = 50
            chart.width = 300
            chart.height = 200
            
            if not values or max(values) == 0:
                # Graphique vide stylé
                empty_text = String(200, 150, "Aucune donnée disponible", textAnchor='middle')
                empty_text.fontName = 'Helvetica-Bold'
                empty_text.fontSize = 14
                empty_text.fillColor = colors.HexColor('#666666')
                drawing.add(empty_text)
                return drawing
            
            chart.data = values
            chart.categoryAxis.categoryNames = labels
            chart.valueAxis.valueMin = 0
            chart.valueAxis.valueMax = max(values) * 1.3 if max(values) > 0 else 1
            
            # Couleurs modernes pour les barres
            modern_colors = [
                colors.HexColor('#00C851'),  # Vert moderne
                colors.HexColor('#FF4444'),  # Rouge moderne
                colors.HexColor('#FF8800'),  # Orange moderne
                colors.HexColor('#33B5E5'),  # Bleu moderne
            ]
            
            for i in range(len(values)):
                if i < len(chart.bars):
                    chart.bars[i].fillColor = modern_colors[i % len(modern_colors)]
            
            drawing.add(chart)
            
            # Titre moderne
            title = String(200, 280, data.get('title', 'Security Metrics'), textAnchor='middle')
            title.fontName = 'Helvetica-Bold'
            title.fontSize = 16
            title.fillColor = colors.HexColor('#2E3440')
            drawing.add(title)
        
        return drawing
    except Exception as e:
        print(f"Erreur création graphique moderne: {str(e)}")
        return create_error_chart(f"Erreur: {str(e)}")

def create_error_chart(message):
    """Crée un graphique d'erreur"""
    error_drawing = Drawing(400, 300)
    error_text = String(200, 150, message, textAnchor='middle')
    error_text.fontName = 'Helvetica-Bold'
    error_text.fontSize = 12
    error_text.fillColor = colors.HexColor('#FF4444')
    error_drawing.add(error_text)
    return error_drawing

def create_modern_progress_bar(value, max_value=100, width=300, height=30):
    """Crée une barre de progression moderne et stylée"""
    try:
        drawing = Drawing(width + 60, height + 20)
        
        # Fond moderne avec coins arrondis (simulé)
        bg_rect = Rect(0, 0, width, height)
        bg_rect.fillColor = colors.HexColor('#E8E8E8')
        bg_rect.strokeColor = colors.HexColor('#CCCCCC')
        bg_rect.strokeWidth = 2
        drawing.add(bg_rect)
        
        # Barre de progression moderne
        progress_width = (value / max_value) * width
        progress_rect = Rect(0, 0, progress_width, height)
        
        # Couleurs modernes basées sur la valeur
        if value >= 80:
            progress_rect.fillColor = colors.HexColor('#00C851')  # Vert moderne
        elif value >= 60:
            progress_rect.fillColor = colors.HexColor('#FF8800')  # Orange moderne
        else:
            progress_rect.fillColor = colors.HexColor('#FF4444')  # Rouge moderne
        
        drawing.add(progress_rect)
        
        # Texte moderne avec ombre
        text = String(width/2, height/2 - 2, f"{value:.1f}%", textAnchor='middle')
        text.fontName = 'Helvetica-Bold'
        text.fontSize = 14
        text.fillColor = colors.white
        drawing.add(text)
        
        # Bordure brillante
        border_rect = Rect(0, 0, width, height)
        border_rect.fillColor = None
        border_rect.strokeColor = colors.HexColor('#FFFFFF')
        border_rect.strokeWidth = 1
        drawing.add(border_rect)
        
        return drawing
    except Exception as e:
        print(f"Erreur création barre moderne: {str(e)}")
        error_drawing = Drawing(width + 60, height + 20)
        error_text = String(width/2, height/2, f"Erreur: {str(e)}", textAnchor='middle')
        error_text.fontName = 'Helvetica'
        error_text.fontSize = 8
        error_text.fillColor = colors.red
        error_drawing.add(error_text)
        return error_drawing

def generate_security_report_pdf(firewalls, report_type='security_intervention', include_remediation_history=True, include_score_analysis=True):
    """
    Génère un rapport PDF simple avec graphiques fonctionnels
    """
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch, leftMargin=0.5*inch, rightMargin=0.5*inch)
        
        # Styles simples
        styles = getSampleStyleSheet()
        
        # Style titre principal
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.darkblue,
            fontName='Helvetica-Bold'
        )
        
        # Style sous-titre
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=15,
            textColor=colors.darkred,
            fontName='Helvetica-Bold'
        )
        
        # Style section
        section_style = ParagraphStyle(
            'Section',
            parent=styles['Heading3'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.darkgreen,
            fontName='Helvetica-Bold'
        )
        
        # Style texte normal
        normal_style = ParagraphStyle(
            'Normal',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=8,
            textColor=colors.black,
            fontName='Helvetica'
        )
        
        # Style tableau simple
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ])
        
        story = []
        
        # En-tête du rapport
        story.append(Paragraph("RAPPORT D'INTERVENTION SECURITE", title_style))
        story.append(Paragraph("SonicWall Backup Incident Manager", subtitle_style))
        story.append(Paragraph(f"Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}", normal_style))
        story.append(Spacer(1, 30))
        
        # Calculer les statistiques globales
        total_firewalls = len(firewalls)
        total_remediation_actions = 0
        total_resolved_modules = 0
        total_pending_modules = 0
        avg_security_score = 0
        
        for firewall in firewalls:
            remediation_actions = RemediationAction.query.filter_by(firewall_id=firewall.id).all()
            total_remediation_actions += len(remediation_actions)
            
            resolved_modules = ModuleResolutionStatus.query.filter_by(firewall_id=firewall.id, is_resolved=True).all()
            total_resolved_modules += len(resolved_modules)
            
            pending_modules = ModuleResolutionStatus.query.filter_by(firewall_id=firewall.id, is_resolved=False).all()
            total_pending_modules += len(pending_modules)
            
            # Calculer le score de sécurité
            total_modules = len(resolved_modules) + len(pending_modules)
            if total_modules > 0:
                firewall_score = (len(resolved_modules) / total_modules) * 100
                avg_security_score += firewall_score
        
        if total_firewalls > 0:
            avg_security_score = avg_security_score / total_firewalls
        
        # Résumé exécutif
        story.append(Paragraph("RESUME EXECUTIF", section_style))
        
        summary_data = [
            ['METRIQUES CLES', 'VALEURS'],
            ['Firewalls analyses', str(total_firewalls)],
            ['Actions de remediation', str(total_remediation_actions)],
            ['Modules resolus', str(total_resolved_modules)],
            ['Modules en attente', str(total_pending_modules)],
            ['Score securite moyen', f'{avg_security_score:.1f}%'],
            ['Taux de resolution', f'{round((total_resolved_modules / (total_resolved_modules + total_pending_modules)) * 100, 1) if (total_resolved_modules + total_pending_modules) > 0 else 0}%']
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(table_style)
        story.append(summary_table)
        story.append(Spacer(1, 25))
        
        # Graphiques simples
        story.append(Paragraph("ANALYSE VISUELLE", section_style))
        
        # Graphique en secteurs simple
        try:
            chart_data = {
                'title': 'Repartition des Modules',
                'labels': ['Modules Resolus', 'Modules en Attente'],
                'values': [total_resolved_modules, total_pending_modules]
            }
            
            pie_chart = create_modern_chart(chart_data, 'pie')
            story.append(pie_chart)
            story.append(Spacer(1, 20))
        except Exception as e:
            print(f"Erreur graphique secteurs: {str(e)}")
            story.append(Paragraph(f"Erreur graphique: {str(e)}", normal_style))
        
        # Barre de progression simple
        try:
            story.append(Paragraph("Score de Securite Global", normal_style))
            progress_bar = create_modern_progress_bar(avg_security_score)
            story.append(progress_bar)
            story.append(Spacer(1, 20))
        except Exception as e:
            print(f"Erreur barre progression: {str(e)}")
            story.append(Paragraph(f"Erreur barre progression: {str(e)}", normal_style))
        
        # Recommandations
        story.append(Paragraph("RECOMMANDATIONS", section_style))
        
        recommendations = []
        if avg_security_score < 70:
            recommendations.append("Score de securite critique - Actions immediates requises")
        elif avg_security_score < 85:
            recommendations.append("Score de securite moyen - Ameliorations recommandees")
        else:
            recommendations.append("Score de securite excellent - Maintenance preventive")
        
        if total_pending_modules > total_resolved_modules:
            recommendations.append("Nombre eleve de modules en attente - Prioriser les remediations")
        
        if total_remediation_actions == 0:
            recommendations.append("Aucune action de remediation - Verifier la configuration")
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", normal_style))
        
        story.append(Spacer(1, 25))
        
        # Détail par firewall simple
        for i, firewall in enumerate(firewalls):
            if i > 0:
                story.append(PageBreak())
            
            # En-tête du firewall
            story.append(Paragraph(f"FIREWALL: {firewall.name or 'Sans nom'}", subtitle_style))
            story.append(Paragraph(f"IP: {firewall.ip} | Utilisateur: {firewall.username}", normal_style))
            story.append(Paragraph(f"Statut: {firewall.status.upper()}", normal_style))
            story.append(Spacer(1, 20))
            
            # Calculer le score de sécurité pour ce firewall
            resolved_modules = ModuleResolutionStatus.query.filter_by(firewall_id=firewall.id, is_resolved=True).all()
            pending_modules = ModuleResolutionStatus.query.filter_by(firewall_id=firewall.id, is_resolved=False).all()
            total_modules = len(resolved_modules) + len(pending_modules)
            firewall_score = (len(resolved_modules) / total_modules) * 100 if total_modules > 0 else 0
            
            # Score de sécurité avec barre simple
            story.append(Paragraph(f"Score de Securite: {firewall_score:.1f}%", normal_style))
            try:
                firewall_progress = create_modern_progress_bar(firewall_score)
                story.append(firewall_progress)
            except Exception as e:
                print(f"Erreur barre progression firewall: {str(e)}")
                story.append(Paragraph(f"Erreur barre progression: {str(e)}", normal_style))
            story.append(Spacer(1, 15))
            
            # Informations générales
            story.append(Paragraph("INFORMATIONS GENERALES", section_style))
            
            firewall_data = [
                ['Propriete', 'Valeur'],
                ['Nom', firewall.name or 'Non defini'],
                ['Adresse IP', firewall.ip],
                ['Utilisateur', firewall.username],
                ['Statut', firewall.status],
                ['Derniere verification', firewall.last_checked.strftime('%d/%m/%Y %H:%M') if firewall.last_checked else 'Jamais'],
                ['Cree le', firewall.created_at.strftime('%d/%m/%Y %H:%M') if firewall.created_at else 'Inconnu'],
                ['Score securite', f'{firewall_score:.1f}%']
            ]
            
            firewall_table = Table(firewall_data, colWidths=[2*inch, 3*inch])
            firewall_table.setStyle(table_style)
            story.append(firewall_table)
            story.append(Spacer(1, 25))
            
            # Historique des remédiations
            if include_remediation_history:
                story.append(Paragraph("HISTORIQUE DES REMEDIATIONS", section_style))
                
                remediation_actions = RemediationAction.query.filter_by(firewall_id=firewall.id).order_by(RemediationAction.executed_at.desc()).all()
                
                if remediation_actions:
                    remediation_data = [['Date', 'Module', 'Action', 'Succes', 'Details']]
                    
                    for action in remediation_actions:
                        success_text = "OUI" if action.success else "NON"
                        module_name = action.module_name.replace('_', ' ').title()
                        action_type = action.action_type.replace('_', ' ').title()
                        
                        remediation_data.append([
                            action.executed_at.strftime('%d/%m/%Y %H:%M') if action.executed_at else 'Inconnu',
                            module_name,
                            action_type,
                            success_text,
                            action.result_message[:50] + '...' if action.result_message and len(action.result_message) > 50 else action.result_message or 'N/A'
                        ])
                    
                    remediation_table = Table(remediation_data, colWidths=[1.2*inch, 1.2*inch, 1.5*inch, 0.8*inch, 2.3*inch])
                    remediation_table.setStyle(table_style)
                    story.append(remediation_table)
                else:
                    story.append(Paragraph("Aucune action de remediation enregistree.", normal_style))
                
                story.append(Spacer(1, 25))
            
            # Statut des modules avec graphique
            story.append(Paragraph("STATUT DES MODULES DE SECURITE", section_style))
            
            module_statuses = ModuleResolutionStatus.query.filter_by(firewall_id=firewall.id).all()
            
            # Graphique des modules
            try:
                if module_statuses:
                    module_names = [status.module_name.replace('_', ' ').title() for status in module_statuses]
                    module_values = [1 if status.is_resolved else 0 for status in module_statuses]
                else:
                    module_names = ['Aucun module']
                    module_values = [0]
                
                module_chart_data = {
                    'title': 'Statut des Modules',
                    'labels': module_names,
                    'values': module_values
                }
                
                module_chart = create_modern_chart(module_chart_data, 'bar')
                story.append(module_chart)
                story.append(Spacer(1, 20))
            except Exception as e:
                print(f"Erreur graphique modules: {str(e)}")
                story.append(Paragraph(f"Erreur graphique modules: {str(e)}", normal_style))
            
            # Tableau détaillé des modules
            if module_statuses:
                module_data = [['Module', 'Statut', 'Resolu le', 'Methode', 'Notes']]
                
                for status in module_statuses:
                    status_text = "Resolu" if status.is_resolved else "En attente"
                    
                    module_data.append([
                        status.module_name.replace('_', ' ').title(),
                        status_text,
                        status.resolved_at.strftime('%d/%m/%Y %H:%M') if status.resolved_at else 'N/A',
                        status.verification_method or 'N/A',
                        status.notes[:30] + '...' if status.notes and len(status.notes) > 30 else status.notes or 'N/A'
                    ])
                
                module_table = Table(module_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 1.3*inch, 2*inch])
                module_table.setStyle(table_style)
                story.append(module_table)
            else:
                story.append(Paragraph("Aucun statut de module enregistre.", normal_style))
            
            story.append(Spacer(1, 25))
            
            # Vérifications d'état
            story.append(Paragraph("VERIFICATIONS D'ETAT", section_style))
            
            state_verifications = StateVerification.query.filter_by(firewall_id=firewall.id).order_by(StateVerification.verified_at.desc()).limit(10).all()
            
            if state_verifications:
                verification_data = [['Date', 'Module', 'Resolu', 'Notes']]
                
                for verification in state_verifications:
                    resolved_text = "OUI" if verification.was_resolved else "NON"
                    
                    verification_data.append([
                        verification.verified_at.strftime('%d/%m/%Y %H:%M') if verification.verified_at else 'Inconnu',
                        verification.module_name.replace('_', ' ').title(),
                        resolved_text,
                        verification.notes[:40] + '...' if verification.notes and len(verification.notes) > 40 else verification.notes or 'N/A'
                    ])
                
                verification_table = Table(verification_data, colWidths=[1.5*inch, 1.5*inch, 0.8*inch, 2.2*inch])
                verification_table.setStyle(table_style)
                story.append(verification_table)
            else:
                story.append(Paragraph("Aucune verification d'etat enregistree.", normal_style))
        
        # Pied de page
        story.append(Spacer(1, 30))
        story.append(Paragraph("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", normal_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Rapport genere automatiquement par SonicWall Backup Incident Manager", normal_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Ce rapport contient des informations sensibles - A traiter de maniere confidentielle", normal_style))
        
        # Construire le PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        print(f"Erreur generation PDF: {str(e)}")
        # Retourner un PDF d'erreur simple
        error_buffer = io.BytesIO()
        error_doc = SimpleDocTemplate(error_buffer, pagesize=A4)
        error_story = []
        error_story.append(Paragraph("ERREUR GENERATION RAPPORT", getSampleStyleSheet()['Heading1']))
        error_story.append(Paragraph(f"Erreur: {str(e)}", getSampleStyleSheet()['Normal']))
        error_doc.build(error_story)
        error_buffer.seek(0)
        return error_buffer

if __name__ == '__main__':
    print("=" * 60)
    print("Console de Management SonicWall")
    print("=" * 60)
    print("\nApplication démarrée sur: http://localhost:5000")
    print("\nOuvrez cette URL dans votre navigateur web.")
    print("\nAppuyez sur Ctrl+C pour arrêter l'application.")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)

