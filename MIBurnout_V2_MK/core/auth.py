"""
auth.py - Système d'authentification et gestion des utilisateurs
Base de données SQLite chiffrée avec gestion des rôles et permissions.
"""

import sqlite3
import os
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

# Chiffrement
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# CONSTANTES
# =============================================================================

# Rôles disponibles
ROLES = {
    "admin": {
        "level": 100,
        "description": "Administrateur - Accès complet",
        "permissions": ["all"]
    },
    "analyst": {
        "level": 50,
        "description": "Analyste - Lecture et analyse",
        "permissions": ["view_packets", "view_devices", "view_stats", "export_data", "view_behavior"]
    },
    "operator": {
        "level": 30,
        "description": "Opérateur - Capture et visualisation",
        "permissions": ["view_packets", "view_devices", "start_capture", "stop_capture"]
    },
    "viewer": {
        "level": 10,
        "description": "Lecteur - Visualisation seule",
        "permissions": ["view_packets", "view_stats"]
    }
}

# Permissions disponibles
PERMISSIONS = {
    "all": "Accès complet à toutes les fonctionnalités",
    "view_packets": "Voir les paquets capturés",
    "view_devices": "Voir les appareils découverts",
    "view_stats": "Voir les statistiques",
    "view_behavior": "Voir l'analyse comportementale",
    "start_capture": "Démarrer une capture",
    "stop_capture": "Arrêter une capture",
    "export_data": "Exporter les données",
    "manage_users": "Gérer les utilisateurs",
    "manage_config": "Gérer la configuration",
    "manage_whitelist": "Gérer les whitelists",
    "view_logs": "Voir les logs d'audit"
}


# =============================================================================
# GESTIONNAIRE D'AUTHENTIFICATION
# =============================================================================

class AuthManager:
    """
    Gestionnaire d'authentification avec base de données chiffrée.
    
    Fonctionnalités:
    - Authentification par username/password
    - Gestion des rôles (admin, analyst, operator, viewer)
    - Gestion des permissions granulaires
    - Sessions avec tokens
    - Logs d'audit
    - Verrouillage après tentatives échouées
    """
    
    # Colonnes sensibles à chiffrer
    ENCRYPTED_COLUMNS = ["email", "full_name", "notes"]
    
    def __init__(self, db_file: str = "config/users.db"):
        """
        Initialise le gestionnaire d'authentification.
        
        Args:
            db_file: Chemin vers la base de données des utilisateurs
        """
        self.db_file = db_file
        self.connection = None
        self.cursor = None
        self.cipher = None
        self.encryption_enabled = False
        
        # Configuration sécurité
        self.max_login_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        self.session_duration = 3600  # 1 heure
        self.password_min_length = 6
        
        # Session courante
        self.current_user = None
        self.current_session = None
        
        # Initialisation
        self._init_encryption()
        self._init_database()
    
    def _init_encryption(self):
        """Initialise le chiffrement."""
        if not CRYPTO_AVAILABLE:
            print("[!] Module cryptography non disponible - Mode non chiffré")
            return
        
        # Utiliser SNIFFER_KEY ou générer une clé dédiée
        key_str = os.getenv("SNIFFER_KEY") or os.getenv("AUTH_KEY")
        
        if key_str:
            try:
                self.cipher = Fernet(key_str.encode())
                self.encryption_enabled = True
            except Exception as e:
                print(f"[!] Clé invalide: {e}")
        else:
            # Générer une clé basée sur un secret machine
            self._generate_machine_key()
    
    def _generate_machine_key(self):
        """Génère une clé basée sur l'identifiant machine."""
        try:
            # Utiliser des infos système pour créer une clé stable
            machine_id = str(os.getuid()) + os.path.expanduser("~") + "MIBurnout"
            
            # Dériver une clé avec PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"MIBurnoutAuthSalt",
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
            self.cipher = Fernet(key)
            self.encryption_enabled = True
        except Exception as e:
            print(f"[!] Impossible de générer la clé: {e}")
    
    def _encrypt(self, data: str) -> str:
        """Chiffre une donnée."""
        if not self.encryption_enabled or not self.cipher or data is None:
            return data
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except:
            return data
    
    def _decrypt(self, data: str) -> str:
        """Déchiffre une donnée."""
        if not self.encryption_enabled or not self.cipher or data is None:
            return data
        try:
            return self.cipher.decrypt(data.encode()).decode()
        except:
            return data
    
    def _hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """
        Hash un mot de passe avec PBKDF2.
        
        Returns:
            Tuple (hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(32)
        
        # PBKDF2 avec SHA256
        hash_obj = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            iterations=100000
        )
        password_hash = hash_obj.hex()
        
        return password_hash, salt
    
    def _verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Vérifie un mot de passe."""
        computed_hash, _ = self._hash_password(password, salt)
        return secrets.compare_digest(computed_hash, stored_hash)
    
    def _open(self):
        """Ouvre la connexion à la base."""
        if self.connection is None:
            os.makedirs(os.path.dirname(self.db_file) or ".", exist_ok=True)
            self.connection = sqlite3.connect(self.db_file, check_same_thread=False)
            self.cursor = self.connection.cursor()
    
    def _close(self):
        """Ferme la connexion."""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None
    
    def _init_database(self):
        """Initialise les tables de la base de données."""
        self._open()
        
        # Table des utilisateurs
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            email TEXT,
            full_name TEXT,
            role TEXT DEFAULT 'viewer',
            permissions TEXT,
            is_active INTEGER DEFAULT 1,
            is_locked INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            created_by INTEGER,
            notes TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )''')
        
        # Table des sessions
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        # Table des logs d'audit
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        # Table des préférences utilisateur
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            theme TEXT DEFAULT 'dark',
            language TEXT DEFAULT 'fr',
            notifications INTEGER DEFAULT 1,
            dashboard_layout TEXT,
            custom_settings TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        # Table des tickets (demandes utilisateurs)
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            ticket_type TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT,
            status TEXT DEFAULT 'pending',
            priority TEXT DEFAULT 'normal',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME,
            resolved_by INTEGER,
            admin_response TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resolved_by) REFERENCES users(id)
        )''')
        
        self.connection.commit()
        
        # Créer l'utilisateur admin par défaut s'il n'existe pas
        self._create_default_admin()
        
        self._close()
    
    def _create_default_admin(self):
        """Crée l'utilisateur admin par défaut."""
        self.cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if self.cursor.fetchone() is None:
            password_hash, salt = self._hash_password("admin")
            
            self.cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, role, 
                                   full_name, email, permissions)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                "admin",
                password_hash,
                salt,
                "admin",
                self._encrypt("Administrateur"),
                self._encrypt("admin@miburnout.local"),
                json.dumps(["all"])
            ))
            
            self.connection.commit()
            print("[+] Utilisateur admin créé (mot de passe: admin)")
    
    def _log_audit(self, action: str, details: str = None, success: bool = True, 
                   user_id: int = None, username: str = None):
        """Enregistre une action dans les logs d'audit."""
        self._open()
        try:
            self.cursor.execute('''
                INSERT INTO audit_logs (user_id, username, action, details, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                user_id or (self.current_user.get("id") if self.current_user else None),
                username or (self.current_user.get("username") if self.current_user else None),
                action,
                details,
                1 if success else 0
            ))
            self.connection.commit()
        except Exception as e:
            print(f"[!] Erreur log audit: {e}")
        finally:
            self._close()
    
    # =========================================================================
    # AUTHENTIFICATION
    # =========================================================================
    
    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Authentifie un utilisateur.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
        
        Returns:
            Tuple (success, message, user_data)
        """
        self._open()
        try:
            # Récupérer l'utilisateur
            self.cursor.execute('''
                SELECT id, username, password_hash, password_salt, role, permissions,
                       is_active, is_locked, failed_attempts, locked_until, full_name, email
                FROM users WHERE username = ?
            ''', (username,))
            
            row = self.cursor.fetchone()
            
            if not row:
                self._log_audit("login_failed", f"Utilisateur inconnu: {username}", 
                               success=False, username=username)
                return False, "Utilisateur ou mot de passe incorrect", None
            
            user_id, uname, pwd_hash, salt, role, perms, is_active, is_locked, \
                failed_attempts, locked_until, full_name, email = row
            
            # Vérifier si le compte est actif
            if not is_active:
                self._log_audit("login_failed", "Compte désactivé", 
                               success=False, user_id=user_id, username=username)
                return False, "Ce compte a été désactivé", None
            
            # Vérifier si le compte est verrouillé
            if is_locked and locked_until:
                lock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < lock_time:
                    remaining = int((lock_time - datetime.now()).total_seconds())
                    self._log_audit("login_failed", "Compte verrouillé", 
                                   success=False, user_id=user_id, username=username)
                    return False, f"Compte verrouillé. Réessayez dans {remaining}s", None
                else:
                    # Débloquer le compte
                    self.cursor.execute('''
                        UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL
                        WHERE id = ?
                    ''', (user_id,))
                    self.connection.commit()
            
            # Vérifier le mot de passe
            if not self._verify_password(password, pwd_hash, salt):
                # Incrémenter les tentatives échouées
                failed_attempts += 1
                
                if failed_attempts >= self.max_login_attempts:
                    lock_until = datetime.now() + timedelta(seconds=self.lockout_duration)
                    self.cursor.execute('''
                        UPDATE users SET failed_attempts = ?, is_locked = 1, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, lock_until.isoformat(), user_id))
                    self._log_audit("account_locked", f"Trop de tentatives ({failed_attempts})", 
                                   success=False, user_id=user_id, username=username)
                else:
                    self.cursor.execute('''
                        UPDATE users SET failed_attempts = ? WHERE id = ?
                    ''', (failed_attempts, user_id))
                
                self.connection.commit()
                self._log_audit("login_failed", "Mot de passe incorrect", 
                               success=False, user_id=user_id, username=username)
                
                remaining = self.max_login_attempts - failed_attempts
                if remaining > 0:
                    return False, f"Mot de passe incorrect ({remaining} tentatives restantes)", None
                else:
                    return False, "Compte verrouillé pour 5 minutes", None
            
            # Connexion réussie - réinitialiser les tentatives
            self.cursor.execute('''
                UPDATE users SET failed_attempts = 0, is_locked = 0, 
                                 locked_until = NULL, last_login = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), user_id))
            
            # Créer une session
            token = secrets.token_urlsafe(32)
            expires = datetime.now() + timedelta(seconds=self.session_duration)
            
            self.cursor.execute('''
                INSERT INTO sessions (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token, expires.isoformat()))
            
            self.connection.commit()
            
            # Construire les données utilisateur
            user_data = {
                "id": user_id,
                "username": uname,
                "role": role,
                "permissions": json.loads(perms) if perms else [],
                "full_name": self._decrypt(full_name),
                "email": self._decrypt(email),
                "token": token,
                "expires_at": expires.isoformat()
            }
            
            self.current_user = user_data
            self.current_session = token
            
            self._log_audit("login_success", None, success=True, 
                           user_id=user_id, username=username)
            
            return True, "Connexion réussie", user_data
            
        except Exception as e:
            return False, f"Erreur: {str(e)}", None
        finally:
            self._close()
    
    def logout(self) -> bool:
        """Déconnecte l'utilisateur courant."""
        if not self.current_session:
            return True
        
        self._open()
        try:
            self.cursor.execute('''
                UPDATE sessions SET is_active = 0 WHERE token = ?
            ''', (self.current_session,))
            self.connection.commit()
            
            self._log_audit("logout", None, success=True)
            
            self.current_user = None
            self.current_session = None
            
            return True
        except Exception as e:
            print(f"[!] Erreur logout: {e}")
            return False
        finally:
            self._close()
    
    def validate_session(self, token: str) -> Optional[Dict]:
        """Valide un token de session et retourne les données utilisateur."""
        self._open()
        try:
            self.cursor.execute('''
                SELECT s.user_id, s.expires_at, u.username, u.role, u.permissions,
                       u.full_name, u.email, u.is_active
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ? AND s.is_active = 1
            ''', (token,))
            
            row = self.cursor.fetchone()
            if not row:
                return None
            
            user_id, expires_at, username, role, perms, full_name, email, is_active = row
            
            # Vérifier l'expiration
            if datetime.now() > datetime.fromisoformat(expires_at):
                self.cursor.execute("UPDATE sessions SET is_active = 0 WHERE token = ?", (token,))
                self.connection.commit()
                return None
            
            if not is_active:
                return None
            
            user_data = {
                "id": user_id,
                "username": username,
                "role": role,
                "permissions": json.loads(perms) if perms else [],
                "full_name": self._decrypt(full_name),
                "email": self._decrypt(email),
                "token": token
            }
            
            self.current_user = user_data
            self.current_session = token
            
            return user_data
            
        finally:
            self._close()
    
    def has_permission(self, permission: str) -> bool:
        """Vérifie si l'utilisateur courant a une permission."""
        if not self.current_user:
            return False
        
        user_perms = self.current_user.get("permissions", [])
        
        # Admin a tous les droits
        if "all" in user_perms:
            return True
        
        return permission in user_perms
    
    def require_permission(self, permission: str) -> bool:
        """Vérifie une permission et lève une exception si non autorisé."""
        if not self.has_permission(permission):
            raise PermissionError(f"Permission requise: {permission}")
        return True
    
    # =========================================================================
    # GESTION DES UTILISATEURS (Admin)
    # =========================================================================
    
    def create_user(self, username: str, password: str, role: str = "viewer",
                    email: str = None, full_name: str = None, 
                    permissions: List[str] = None) -> Tuple[bool, str]:
        """
        Crée un nouvel utilisateur.
        
        Args:
            username: Nom d'utilisateur unique
            password: Mot de passe
            role: Rôle (admin, analyst, operator, viewer)
            email: Email optionnel
            full_name: Nom complet optionnel
            permissions: Liste de permissions personnalisées
        
        Returns:
            Tuple (success, message)
        """
        # Vérifier les permissions
        if not self.has_permission("manage_users") and not self.has_permission("all"):
            return False, "Permission insuffisante"
        
        # Valider le rôle
        if role not in ROLES:
            return False, f"Rôle invalide. Valides: {', '.join(ROLES.keys())}"
        
        # Valider le mot de passe
        if len(password) < self.password_min_length:
            return False, f"Mot de passe trop court (min {self.password_min_length} caractères)"
        
        # Permissions par défaut du rôle si non spécifiées
        if permissions is None:
            permissions = ROLES[role]["permissions"]
        
        self._open()
        try:
            # Vérifier si l'utilisateur existe déjà
            self.cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if self.cursor.fetchone():
                return False, "Ce nom d'utilisateur existe déjà"
            
            # Hasher le mot de passe
            password_hash, salt = self._hash_password(password)
            
            # Créer l'utilisateur
            self.cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, role, 
                                   email, full_name, permissions, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                username,
                password_hash,
                salt,
                role,
                self._encrypt(email) if email else None,
                self._encrypt(full_name) if full_name else None,
                json.dumps(permissions),
                self.current_user.get("id") if self.current_user else None
            ))
            
            self.connection.commit()
            
            self._log_audit("user_created", f"Utilisateur créé: {username} (rôle: {role})")
            
            return True, f"Utilisateur '{username}' créé avec succès"
            
        except Exception as e:
            return False, f"Erreur: {str(e)}"
        finally:
            self._close()
    
    def update_user(self, user_id: int, **kwargs) -> Tuple[bool, str]:
        """
        Met à jour un utilisateur.
        
        Args:
            user_id: ID de l'utilisateur
            **kwargs: Champs à modifier (password, role, email, full_name, 
                      permissions, is_active, notes)
        
        Returns:
            Tuple (success, message)
        """
        if not self.has_permission("manage_users") and not self.has_permission("all"):
            # Un utilisateur peut modifier son propre profil (sauf rôle et permissions)
            if self.current_user and self.current_user.get("id") == user_id:
                allowed_fields = ["password", "email", "full_name"]
                if any(k not in allowed_fields for k in kwargs.keys()):
                    return False, "Vous ne pouvez modifier que votre email, nom et mot de passe"
            else:
                return False, "Permission insuffisante"
        
        self._open()
        try:
            updates = []
            values = []
            
            if "password" in kwargs:
                if len(kwargs["password"]) < self.password_min_length:
                    return False, f"Mot de passe trop court (min {self.password_min_length})"
                pwd_hash, salt = self._hash_password(kwargs["password"])
                updates.extend(["password_hash = ?", "password_salt = ?"])
                values.extend([pwd_hash, salt])
            
            if "role" in kwargs:
                if kwargs["role"] not in ROLES:
                    return False, "Rôle invalide"
                updates.append("role = ?")
                values.append(kwargs["role"])
            
            if "email" in kwargs:
                updates.append("email = ?")
                values.append(self._encrypt(kwargs["email"]))
            
            if "full_name" in kwargs:
                updates.append("full_name = ?")
                values.append(self._encrypt(kwargs["full_name"]))
            
            if "permissions" in kwargs:
                updates.append("permissions = ?")
                values.append(json.dumps(kwargs["permissions"]))
            
            if "is_active" in kwargs:
                updates.append("is_active = ?")
                values.append(1 if kwargs["is_active"] else 0)
            
            if "notes" in kwargs:
                updates.append("notes = ?")
                values.append(self._encrypt(kwargs["notes"]))
            
            if not updates:
                return False, "Aucune modification spécifiée"
            
            updates.append("updated_at = ?")
            values.append(datetime.now().isoformat())
            values.append(user_id)
            
            sql = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            self.cursor.execute(sql, values)
            self.connection.commit()
            
            self._log_audit("user_updated", f"Utilisateur {user_id} modifié: {list(kwargs.keys())}")
            
            return True, "Utilisateur mis à jour"
            
        except Exception as e:
            return False, f"Erreur: {str(e)}"
        finally:
            self._close()
    
    def delete_user(self, user_id: int) -> Tuple[bool, str]:
        """Supprime un utilisateur (désactivation)."""
        if not self.has_permission("manage_users") and not self.has_permission("all"):
            return False, "Permission insuffisante"
        
        # Empêcher la suppression de son propre compte
        if self.current_user and self.current_user.get("id") == user_id:
            return False, "Vous ne pouvez pas supprimer votre propre compte"
        
        self._open()
        try:
            # Vérifier que ce n'est pas le dernier admin
            self.cursor.execute('''
                SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND id != ?
            ''', (user_id,))
            
            admin_count = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            row = self.cursor.fetchone()
            if not row:
                return False, "Utilisateur non trouvé"
            
            if row[0] == "admin" and admin_count == 0:
                return False, "Impossible de supprimer le dernier administrateur"
            
            # Désactiver plutôt que supprimer (pour l'audit)
            self.cursor.execute('''
                UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?
            ''', (datetime.now().isoformat(), user_id))
            
            # Invalider les sessions
            self.cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
            
            self.connection.commit()
            
            self._log_audit("user_deleted", f"Utilisateur {user_id} désactivé")
            
            return True, "Utilisateur supprimé"
            
        except Exception as e:
            return False, f"Erreur: {str(e)}"
        finally:
            self._close()
    
    def get_user(self, user_id: int) -> Optional[Dict]:
        """Récupère les informations d'un utilisateur."""
        self._open()
        try:
            self.cursor.execute('''
                SELECT id, username, role, permissions, email, full_name, is_active,
                       created_at, last_login, notes
                FROM users WHERE id = ?
            ''', (user_id,))
            
            row = self.cursor.fetchone()
            if not row:
                return None
            
            return {
                "id": row[0],
                "username": row[1],
                "role": row[2],
                "permissions": json.loads(row[3]) if row[3] else [],
                "email": self._decrypt(row[4]),
                "full_name": self._decrypt(row[5]),
                "is_active": bool(row[6]),
                "created_at": row[7],
                "last_login": row[8],
                "notes": self._decrypt(row[9])
            }
        finally:
            self._close()
    
    def get_all_users(self) -> List[Dict]:
        """Récupère la liste de tous les utilisateurs."""
        self._open()
        try:
            self.cursor.execute('''
                SELECT id, username, role, email, full_name, is_active, 
                       created_at, last_login
                FROM users ORDER BY id
            ''')
            
            users = []
            for row in self.cursor.fetchall():
                users.append({
                    "id": row[0],
                    "username": row[1],
                    "role": row[2],
                    "email": self._decrypt(row[3]),
                    "full_name": self._decrypt(row[4]),
                    "is_active": bool(row[5]),
                    "created_at": row[6],
                    "last_login": row[7]
                })
            
            return users
        finally:
            self._close()
    
    def reset_password(self, user_id: int, new_password: str) -> Tuple[bool, str]:
        """Réinitialise le mot de passe d'un utilisateur."""
        return self.update_user(user_id, password=new_password)
    
    def unlock_user(self, user_id: int) -> Tuple[bool, str]:
        """Déverrouille un compte utilisateur."""
        if not self.has_permission("manage_users") and not self.has_permission("all"):
            return False, "Permission insuffisante"
        
        self._open()
        try:
            self.cursor.execute('''
                UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL
                WHERE id = ?
            ''', (user_id,))
            self.connection.commit()
            
            self._log_audit("user_unlocked", f"Utilisateur {user_id} déverrouillé")
            
            return True, "Compte déverrouillé"
        finally:
            self._close()
    
    # =========================================================================
    # LOGS ET STATISTIQUES
    # =========================================================================
    
    def get_audit_logs(self, limit: int = 100, user_id: int = None) -> List[Dict]:
        """Récupère les logs d'audit."""
        self._open()
        try:
            if user_id:
                self.cursor.execute('''
                    SELECT id, user_id, username, action, details, timestamp, success
                    FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?
                ''', (user_id, limit))
            else:
                self.cursor.execute('''
                    SELECT id, user_id, username, action, details, timestamp, success
                    FROM audit_logs ORDER BY id DESC LIMIT ?
                ''', (limit,))
            
            logs = []
            for row in self.cursor.fetchall():
                logs.append({
                    "id": row[0],
                    "user_id": row[1],
                    "username": row[2],
                    "action": row[3],
                    "details": row[4],
                    "timestamp": row[5],
                    "success": bool(row[6])
                })
            
            return logs
        finally:
            self._close()
    
    def get_user_stats(self) -> Dict:
        """Récupère les statistiques utilisateurs."""
        self._open()
        try:
            stats = {"total": 0, "active": 0, "locked": 0, "by_role": {}}
            
            self.cursor.execute("SELECT COUNT(*) FROM users")
            stats["total"] = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
            stats["active"] = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT COUNT(*) FROM users WHERE is_locked = 1")
            stats["locked"] = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT role, COUNT(*) FROM users GROUP BY role")
            for row in self.cursor.fetchall():
                stats["by_role"][row[0]] = row[1]
            
            return stats
        finally:
            self._close()
    
    # =========================================================================
    # GESTION DES TICKETS
    # =========================================================================
    
    def create_ticket(self, username: str, ticket_type: str, subject: str, 
                     message: str = None, user_id: int = None) -> Tuple[bool, str, int]:
        """
        Crée un nouveau ticket.
        
        Args:
            username: Nom d'utilisateur qui crée le ticket
            ticket_type: Type de ticket (password_reset, access_request, other)
            subject: Sujet du ticket
            message: Message détaillé (optionnel)
            user_id: ID utilisateur si connecté (optionnel)
        
        Returns:
            Tuple (success, message, ticket_id)
        """
        self._open()
        try:
            self.cursor.execute('''
                INSERT INTO tickets (user_id, username, ticket_type, subject, message, status, priority)
                VALUES (?, ?, ?, ?, ?, 'pending', 'normal')
            ''', (user_id, username, ticket_type, subject, message))
            
            self.connection.commit()
            ticket_id = self.cursor.lastrowid
            
            self._log_audit("ticket_created", 
                           f"Ticket #{ticket_id} créé par {username}: {ticket_type}",
                           user_id=user_id, username=username)
            
            return True, f"Ticket #{ticket_id} créé avec succès", ticket_id
            
        except Exception as e:
            return False, f"Erreur: {str(e)}", 0
        finally:
            self._close()
    
    def get_tickets(self, status: str = None, limit: int = 50) -> List[Dict]:
        """
        Récupère la liste des tickets.
        
        Args:
            status: Filtrer par statut (pending, in_progress, resolved, rejected)
            limit: Nombre max de tickets
        """
        self._open()
        try:
            if status:
                self.cursor.execute('''
                    SELECT id, user_id, username, ticket_type, subject, message, 
                           status, priority, created_at, updated_at, resolved_at,
                           resolved_by, admin_response
                    FROM tickets WHERE status = ? ORDER BY id DESC LIMIT ?
                ''', (status, limit))
            else:
                self.cursor.execute('''
                    SELECT id, user_id, username, ticket_type, subject, message, 
                           status, priority, created_at, updated_at, resolved_at,
                           resolved_by, admin_response
                    FROM tickets ORDER BY 
                        CASE status 
                            WHEN 'pending' THEN 1 
                            WHEN 'in_progress' THEN 2 
                            ELSE 3 
                        END,
                        id DESC 
                    LIMIT ?
                ''', (limit,))
            
            tickets = []
            for row in self.cursor.fetchall():
                tickets.append({
                    "id": row[0],
                    "user_id": row[1],
                    "username": row[2],
                    "ticket_type": row[3],
                    "subject": row[4],
                    "message": row[5],
                    "status": row[6],
                    "priority": row[7],
                    "created_at": row[8],
                    "updated_at": row[9],
                    "resolved_at": row[10],
                    "resolved_by": row[11],
                    "admin_response": row[12]
                })
            
            return tickets
        finally:
            self._close()
    
    def get_pending_tickets_count(self) -> int:
        """Retourne le nombre de tickets en attente."""
        self._open()
        try:
            self.cursor.execute("SELECT COUNT(*) FROM tickets WHERE status = 'pending'")
            return self.cursor.fetchone()[0]
        finally:
            self._close()
    
    def update_ticket(self, ticket_id: int, status: str = None, 
                     admin_response: str = None, priority: str = None) -> Tuple[bool, str]:
        """
        Met à jour un ticket (admin seulement).
        
        Args:
            ticket_id: ID du ticket
            status: Nouveau statut (pending, in_progress, resolved, rejected)
            admin_response: Réponse de l'admin
            priority: Priorité (low, normal, high, urgent)
        """
        if not self.has_permission("manage_users") and not self.has_permission("all"):
            return False, "Permission insuffisante"
        
        self._open()
        try:
            updates = ["updated_at = ?"]
            values = [datetime.now().isoformat()]
            
            if status:
                updates.append("status = ?")
                values.append(status)
                
                if status in ('resolved', 'rejected'):
                    updates.append("resolved_at = ?")
                    values.append(datetime.now().isoformat())
                    updates.append("resolved_by = ?")
                    values.append(self.current_user.get("id") if self.current_user else None)
            
            if admin_response:
                updates.append("admin_response = ?")
                values.append(admin_response)
            
            if priority:
                updates.append("priority = ?")
                values.append(priority)
            
            values.append(ticket_id)
            
            sql = f"UPDATE tickets SET {', '.join(updates)} WHERE id = ?"
            self.cursor.execute(sql, values)
            self.connection.commit()
            
            self._log_audit("ticket_updated", f"Ticket #{ticket_id} mis à jour: status={status}")
            
            return True, "Ticket mis à jour"
            
        except Exception as e:
            return False, f"Erreur: {str(e)}"
        finally:
            self._close()
    
    def resolve_password_reset_ticket(self, ticket_id: int, new_password: str = None, 
                                      approve: bool = True) -> Tuple[bool, str]:
        """
        Résout un ticket de demande de réinitialisation de mot de passe.
        
        Args:
            ticket_id: ID du ticket
            new_password: Nouveau mot de passe (si approve=True)
            approve: True pour approuver, False pour rejeter
        """
        if not self.has_permission("manage_users") and not self.has_permission("all"):
            return False, "Permission insuffisante"
        
        self._open()
        try:
            # Récupérer le ticket
            self.cursor.execute('''
                SELECT user_id, username, ticket_type, status 
                FROM tickets WHERE id = ?
            ''', (ticket_id,))
            
            row = self.cursor.fetchone()
            if not row:
                return False, "Ticket non trouvé"
            
            user_id, username, ticket_type, status = row
            
            if ticket_type != 'password_reset':
                return False, "Ce ticket n'est pas une demande de mot de passe"
            
            if status != 'pending':
                return False, "Ce ticket a déjà été traité"
            
            if approve:
                if not new_password:
                    return False, "Mot de passe requis pour approuver"
                
                # Trouver l'utilisateur
                self.cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                user_row = self.cursor.fetchone()
                
                if not user_row:
                    return False, f"Utilisateur '{username}' non trouvé"
                
                target_user_id = user_row[0]
                
                # Mettre à jour le mot de passe
                pwd_hash, salt = self._hash_password(new_password)
                self.cursor.execute('''
                    UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ?
                    WHERE id = ?
                ''', (pwd_hash, salt, datetime.now().isoformat(), target_user_id))
                
                # Mettre à jour le ticket
                self.cursor.execute('''
                    UPDATE tickets SET status = 'resolved', resolved_at = ?, resolved_by = ?,
                                      admin_response = ?, updated_at = ?
                    WHERE id = ?
                ''', (
                    datetime.now().isoformat(),
                    self.current_user.get("id") if self.current_user else None,
                    "Mot de passe réinitialisé avec succès",
                    datetime.now().isoformat(),
                    ticket_id
                ))
                
                self.connection.commit()
                self._log_audit("password_reset_approved", 
                               f"Ticket #{ticket_id}: MDP réinitialisé pour {username}")
                
                return True, f"Mot de passe réinitialisé pour {username}"
            else:
                # Rejeter le ticket
                self.cursor.execute('''
                    UPDATE tickets SET status = 'rejected', resolved_at = ?, resolved_by = ?,
                                      admin_response = ?, updated_at = ?
                    WHERE id = ?
                ''', (
                    datetime.now().isoformat(),
                    self.current_user.get("id") if self.current_user else None,
                    "Demande rejetée",
                    datetime.now().isoformat(),
                    ticket_id
                ))
                
                self.connection.commit()
                self._log_audit("password_reset_rejected", 
                               f"Ticket #{ticket_id}: Demande rejetée pour {username}")
                
                return True, "Demande rejetée"
                
        except Exception as e:
            return False, f"Erreur: {str(e)}"
        finally:
            self._close()


# =============================================================================
# INSTANCE GLOBALE
# =============================================================================

_auth_manager = None

def get_auth_manager() -> AuthManager:
    """Retourne l'instance globale du gestionnaire d'authentification."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


# =============================================================================
# TESTS
# =============================================================================

if __name__ == "__main__":
    import os
    
    # Nettoyer pour le test
    test_db = "test_auth.db"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    print("=" * 60)
    print("  TEST Module d'Authentification")
    print("=" * 60)
    
    auth = AuthManager(db_file=test_db)
    
    # Test login admin
    print("\n[1] Login admin/admin")
    success, msg, user = auth.login("admin", "admin")
    print(f"    Résultat: {success} - {msg}")
    if user:
        print(f"    User: {user['username']} ({user['role']})")
    
    # Test création utilisateur
    print("\n[2] Création utilisateur 'analyst1'")
    success, msg = auth.create_user("analyst1", "password123", role="analyst", 
                                    full_name="Jean Dupont")
    print(f"    Résultat: {success} - {msg}")
    
    # Test liste utilisateurs
    print("\n[3] Liste des utilisateurs")
    users = auth.get_all_users()
    for u in users:
        print(f"    - {u['username']} ({u['role']}) - Actif: {u['is_active']}")
    
    # Test permissions
    print("\n[4] Test permissions")
    print(f"    has_permission('manage_users'): {auth.has_permission('manage_users')}")
    print(f"    has_permission('view_packets'): {auth.has_permission('view_packets')}")
    
    # Test logout
    print("\n[5] Logout")
    auth.logout()
    
    # Test login avec mauvais mot de passe
    print("\n[6] Login avec mauvais mot de passe (3 tentatives)")
    for i in range(3):
        success, msg, _ = auth.login("analyst1", "wrongpassword")
        print(f"    Tentative {i+1}: {msg}")
    
    # Stats
    print("\n[7] Statistiques")
    stats = auth.get_user_stats()
    print(f"    {stats}")
    
    # Nettoyage
    os.remove(test_db)
    print("\n[OK] Tests terminés")
