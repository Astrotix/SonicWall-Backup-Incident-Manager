from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.fernet import Fernet
import os
import base64

db = SQLAlchemy()

# Générer ou charger la clé de chiffrement
def get_encryption_key():
    """
    Récupère ou génère la clé de chiffrement
    La clé est stockée dans un fichier .env ou générée si elle n'existe pas
    """
    key_file = 'encryption.key'
    
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Générer une nouvelle clé
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        print("Nouvelle cle de chiffrement generee et sauvegardee dans " + key_file)
        print("IMPORTANT: Sauvegardez ce fichier! Sans lui, vous ne pourrez pas dechiffrer vos mots de passe.")
        return key

# Instance Fernet pour chiffrement/déchiffrement
cipher = Fernet(get_encryption_key())

class Firewall(db.Model):
    """
    Modèle pour stocker les informations de firewall
    Les mots de passe sont automatiquement chiffrés en base
    """
    __tablename__ = 'firewalls'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(50), nullable=False, unique=True)
    username = db.Column(db.String(100), nullable=False)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)  # Mot de passe chiffré
    otp = db.Column(db.Boolean, default=False)  # Indique si OTP est utilisé
    status = db.Column(db.String(20), default='connected')
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, name, ip, username, password, otp=False, status='connected'):
        self.name = name
        self.ip = ip
        self.username = username
        self.set_password(password)
        self.otp = otp
        self.status = status
    
    def set_password(self, password):
        """
        Chiffre et stocke le mot de passe
        """
        if isinstance(password, str):
            password = password.encode()
        self.password_encrypted = cipher.encrypt(password)
    
    def get_password(self):
        """
        Déchiffre et retourne le mot de passe en clair
        """
        if self.password_encrypted:
            return cipher.decrypt(self.password_encrypted).decode()
        return None
    
    def to_dict(self, include_password=True):
        """
        Convertit le modèle en dictionnaire pour l'API
        """
        result = {
            'id': self.id,
            'name': self.name,
            'ip': self.ip,
            'username': self.username,
            'otp': self.otp,
            'status': self.status,
            'lastChecked': self.last_checked.isoformat() if self.last_checked else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        # Inclure le mot de passe déchiffré si demandé
        if include_password:
            result['password'] = self.get_password()
        
        return result
    
    def __repr__(self):
        return f'<Firewall {self.name} ({self.ip})>'

class ModuleResolutionStatus(db.Model):
    """
    État de résolution des problèmes de sécurité par module et firewall
    """
    __tablename__ = 'module_resolution_status'
    
    id = db.Column(db.Integer, primary_key=True)
    firewall_id = db.Column(db.Integer, db.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)  # 'local_users', 'ldap', etc.
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    last_verified_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_method = db.Column(db.String(100))  # 'manual_action', 'api_verification', etc.
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relation avec Firewall
    firewall = db.relationship('Firewall', backref=db.backref('resolution_statuses', lazy=True, passive_deletes=True))
    
    def __repr__(self):
        return f'<ModuleResolutionStatus {self.firewall_id} - {self.module_name}: {"RESOLVED" if self.is_resolved else "PENDING"}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'firewall_id': self.firewall_id,
            'module_name': self.module_name,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'last_verified_at': self.last_verified_at.isoformat() if self.last_verified_at else None,
            'verification_method': self.verification_method,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class RemediationAction(db.Model):
    """
    Actions de remédiation exécutées
    """
    __tablename__ = 'remediation_actions'
    
    id = db.Column(db.Integer, primary_key=True)
    firewall_id = db.Column(db.Integer, db.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)
    action_type = db.Column(db.String(100), nullable=False)  # 'reset_passwords', 'unbind_totp', etc.
    parameters = db.Column(db.JSON)  # Paramètres de l'action (utilisateurs, etc.)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    result_message = db.Column(db.Text)
    requires_verification = db.Column(db.Boolean, default=True)
    verified_at = db.Column(db.DateTime)
    
    # Relation avec Firewall
    firewall = db.relationship('Firewall', backref=db.backref('remediation_actions', lazy=True, passive_deletes=True))
    
    def __repr__(self):
        return f'<RemediationAction {self.firewall_id} - {self.action_type}: {"SUCCESS" if self.success else "FAILED"}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'firewall_id': self.firewall_id,
            'module_name': self.module_name,
            'action_type': self.action_type,
            'action_date': self.executed_at.isoformat() if self.executed_at else None,
            'details': self.result_message,
            'parameters': self.parameters,
            'success': self.success,
            'requires_verification': self.requires_verification,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None
        }

class StateVerification(db.Model):
    """
    Vérifications d'état pour tracking des changements
    """
    __tablename__ = 'state_verifications'
    
    id = db.Column(db.Integer, primary_key=True)
    firewall_id = db.Column(db.Integer, db.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False)
    module_name = db.Column(db.String(50), nullable=False)
    verified_at = db.Column(db.DateTime, default=datetime.utcnow)
    current_state = db.Column(db.JSON)  # État actuel détecté
    was_resolved = db.Column(db.Boolean)  # Si le problème était résolu
    notes = db.Column(db.Text)
    
    # Relation avec Firewall
    firewall = db.relationship('Firewall', backref=db.backref('state_verifications', lazy=True, passive_deletes=True))
    
    def __repr__(self):
        return f'<StateVerification {self.firewall_id} - {self.module_name}: {"RESOLVED" if self.was_resolved else "PENDING"}>'

class CSERemediationTimer(db.Model):
    """
    Timer pour la remediation CSE - persiste le countdown après rafraîchissement
    """
    __tablename__ = 'cse_remediation_timers'
    
    id = db.Column(db.Integer, primary_key=True)
    firewall_id = db.Column(db.Integer, db.ForeignKey('firewalls.id', ondelete='CASCADE'), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    duration_seconds = db.Column(db.Integer, default=600, nullable=False)  # 10 minutes par défaut
    is_active = db.Column(db.Boolean, default=True)
    completed_at = db.Column(db.DateTime)
    
    # Relation avec Firewall
    firewall = db.relationship('Firewall', backref=db.backref('cse_timers', lazy=True, passive_deletes=True))
    
    def __repr__(self):
        return f'<CSERemediationTimer {self.firewall_id}: {"ACTIVE" if self.is_active else "COMPLETED"}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'firewall_id': self.firewall_id,
            'started_at': self.started_at.isoformat(),
            'duration_seconds': self.duration_seconds,
            'is_active': self.is_active,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'remaining_seconds': self.get_remaining_seconds()
        }
    
    def get_remaining_seconds(self):
        """Calcule le temps restant en secondes"""
        if not self.is_active:
            return 0
        
        elapsed = (datetime.utcnow() - self.started_at).total_seconds()
        remaining = self.duration_seconds - elapsed
        return max(0, int(remaining))
    
    def is_expired(self):
        """Vérifie si le timer est expiré"""
        return self.get_remaining_seconds() <= 0
    
    def complete(self):
        """Marque le timer comme terminé"""
        self.is_active = False
        self.completed_at = datetime.utcnow()

