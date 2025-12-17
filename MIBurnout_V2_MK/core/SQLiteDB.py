"""
SQLiteDB.py - Gestion de la base de données SQLite pour MIBurnout
Supporte le chiffrement optionnel des données sensibles via Fernet.
"""

import sqlite3
import os

# Chiffrement optionnel - ne plante pas si cryptography n'est pas installé
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None


class DataBase(object):
    """
    Outils de gestion de la base de données SQLite pour le sniffer.
    Supporte le chiffrement optionnel des données sensibles.
    
    Mode sécurisé activé si la variable d'environnement SNIFFER_KEY est définie.
    """
    
    # Colonnes contenant des données sensibles à chiffrer
    ENCRYPTED_COLUMNS = [
        "snmp_community", "snmp_oidsValues", 
        "ip_src", "ip_dst", 
        "mac_src", "mac_dst",
        "snmp_usm_user_name"
    ]
    
    def __init__(self, dbFile: str, require_encryption: bool = False):
        """
        Initialise la connexion à la base de données.
        
        Args:
            dbFile: Chemin vers le fichier SQLite
            require_encryption: Si True, lève une exception si le chiffrement n'est pas disponible
        """
        self.dbFile = dbFile
        self.connection = None
        self.cursor = None
        self.cipher = None
        self.encryption_enabled = False
        
        # Tentative d'initialisation du chiffrement
        self._init_encryption(require_encryption)
    
    def _init_encryption(self, require: bool = False):
        """Initialise le moteur de chiffrement si la clé est disponible."""
        key_str = os.getenv("SNIFFER_KEY")
        
        if not key_str:
            if require:
                raise ValueError(
                    "[ERREUR] La variable d'environnement 'SNIFFER_KEY' n'est pas définie.\n"
                    "Veuillez définir la variable: export SNIFFER_KEY='VotreClé...'\n"
                    "Pour générer une clé: python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
                )
            else:
                # Mode non chiffré (développement/test)
                self.encryption_enabled = False
                return
        
        if not CRYPTO_AVAILABLE:
            if require:
                raise ImportError(
                    "[ERREUR] Le module 'cryptography' n'est pas installé.\n"
                    "Installation: pip install cryptography"
                )
            else:
                print("[!] Avertissement: Module 'cryptography' non disponible. Mode non chiffré.")
                self.encryption_enabled = False
                return
        
        try:
            self.cipher = Fernet(key_str.encode())
            self.encryption_enabled = True
        except Exception as e:
            if require:
                raise ValueError(f"[ERREUR] Clé SNIFFER_KEY invalide: {e}")
            else:
                print(f"[!] Avertissement: Clé invalide, mode non chiffré. ({e})")
                self.encryption_enabled = False

    def open(self):
        """Ouvre la connexion à la base de données si elle n'est pas déjà ouverte."""
        if self.connection is None:
            self.connection = sqlite3.connect(self.dbFile, check_same_thread=False)
            self.cursor = self.connection.cursor()

    def close(self):
        """Ferme la connexion à la base de données si elle est ouverte."""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None

    def is_valid_identifier(self, name: str):
        """Retourne True si 'name' est un identifiant valide ou '*', sinon False."""
        if name == "*":
            return True
        return name.isidentifier()

    def table_exists(self, table: str) -> bool:
        """Vérifie si une table existe."""
        self.open()
        self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", 
            (table,)
        )
        exists = self.cursor.fetchone() is not None
        self.close()
        return exists

    # =========================================================================
    # MÉTHODES DE CHIFFREMENT
    # =========================================================================

    def _encrypt(self, data):
        """Chiffre une donnée si le chiffrement est activé."""
        if data is None:
            return None
        if not self.encryption_enabled or not self.cipher:
            return data
        
        try:
            return self.cipher.encrypt(str(data).encode()).decode()
        except Exception:
            return data

    def _decrypt(self, data):
        """Déchiffre une donnée si le chiffrement est activé."""
        if data is None:
            return None
        if not self.encryption_enabled or not self.cipher:
            return data
        
        try:
            return self.cipher.decrypt(data.encode()).decode()
        except Exception:
            # Donnée non chiffrée ou erreur -> retour tel quel
            return data

    # =========================================================================
    # INITIALISATION DES TABLES
    # =========================================================================

    def initDB(self):
        """Initialisation de la base de données avec les tables V1, V2 et V3."""
        self.open()
        
        # --- TABLE SNMP V1 ---
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS snmp_v1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            mac_src TEXT, mac_dst TEXT,
            ip_src TEXT, ip_dst TEXT,
            port_src INTEGER, port_dst INTEGER,
            snmp_community TEXT,
            snmp_pdu_type TEXT,
            
            -- Champs spécifiques Trap V1
            snmp_enterprise TEXT,
            snmp_agent_addr TEXT,
            snmp_generic_trap INTEGER,
            snmp_specific_trap INTEGER,
            
            -- Champs Standards (Get/Set/Response)
            snmp_request_id INTEGER,
            snmp_error_status INTEGER,
            snmp_error_index INTEGER,
            
            snmp_oidsValues TEXT,
            tag INTEGER)''')

        # --- TABLE SNMP V2 ---
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS snmp_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            mac_src TEXT, mac_dst TEXT,
            ip_src TEXT, ip_dst TEXT,
            port_src INTEGER, port_dst INTEGER,
            snmp_community TEXT,
            snmp_pdu_type TEXT,
            
            -- Champs Standards V2
            snmp_request_id INTEGER,
            snmp_error_status INTEGER,
            snmp_error_index INTEGER,
            
            -- Champs spécifiques Bulk V2
            snmp_non_repeaters INTEGER,
            snmp_max_repetitions INTEGER,
            
            snmp_oidsValues TEXT,
            tag INTEGER)''')
        
        # --- TABLE SNMP V3 ---
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS snmp_v3 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            mac_src TEXT, mac_dst TEXT,
            ip_src TEXT, ip_dst TEXT,
            port_src INTEGER, port_dst INTEGER,
            
            -- Champs Header SNMPv3
            snmp_msg_id INTEGER,
            snmp_msg_max_size INTEGER,
            snmp_msg_flags TEXT,
            snmp_msg_security_model INTEGER,
            
            -- Champs USM (User-based Security Model)
            snmp_usm_engine_id TEXT,
            snmp_usm_engine_boots INTEGER,
            snmp_usm_engine_time INTEGER,
            snmp_usm_user_name TEXT,
            snmp_usm_auth_protocol TEXT,
            snmp_usm_priv_protocol TEXT,
            snmp_usm_auth_params TEXT,
            snmp_usm_priv_params TEXT,
            
            -- Champs PDU (ScopedPDU)
            snmp_context_engine_id TEXT,
            snmp_context_name TEXT,
            snmp_pdu_type TEXT,
            snmp_request_id INTEGER,
            snmp_error_status INTEGER,
            snmp_error_index INTEGER,
            snmp_non_repeaters INTEGER,
            snmp_max_repetitions INTEGER,
            
            snmp_oidsValues TEXT,
            tag INTEGER,
            
            -- Champs de sécurité additionnels
            security_level TEXT,
            is_encrypted INTEGER DEFAULT 0,
            is_authenticated INTEGER DEFAULT 0,
            decryption_status TEXT)''')
            
        self.connection.commit()
        self.close()

    # =========================================================================
    # OPÉRATIONS CRUD
    # =========================================================================

    def getChamps(self, table: str):
        """Retourne la liste des noms de colonnes d'une table."""
        self.open()
        self.cursor.execute(f"PRAGMA table_info({table})")
        colonnes_info = self.cursor.fetchall()
        self.close()
        return colonnes_info

    def wrData(self, table: str, data: dict):
        """
        Écrit une ligne dans la base de données.
        Chiffre automatiquement les colonnes sensibles si le chiffrement est activé.
        """
        self.open()
        try:
            # Chiffrement des colonnes sensibles
            secure_data = data.copy()
            
            if self.encryption_enabled:
                for col, val in secure_data.items():
                    if col in self.ENCRYPTED_COLUMNS and val is not None:
                        secure_data[col] = self._encrypt(val)

            columns = ", ".join(secure_data.keys())
            placeholders = ", ".join(["?"] * len(secure_data))
            values = tuple(secure_data.values())

            sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
            self.cursor.execute(sql, values)
            self.connection.commit()

        except Exception as e:
            print(f"[ERREUR wrData {table}] {e}")
            self.connection.rollback()

        finally:
            self.close()

    def getData(self, table: str, columns: list, where: str = None, params: tuple = (), decrypt: bool = True):
        """
        Récupère des données de la base.
        Déchiffre automatiquement les colonnes sensibles si demandé.
        """
        if not self.table_exists(table):
            raise ValueError(f"La table '{table}' n'existe pas.")
        if not self.is_valid_identifier(table):
            raise ValueError("Nom de table invalide")
        for col in columns:
            if not self.is_valid_identifier(col):
                raise ValueError(f"Nom de colonne invalide: {col}")

        cols = ", ".join(columns)
        sql = f"SELECT {cols} FROM {table}"
        if where:
            sql += f" WHERE {where}"
        
        self.open()
        try:
            self.cursor.execute(sql, params)
            rows = self.cursor.fetchall()
            
            # Déchiffrement si activé
            if decrypt and self.encryption_enabled:
                decrypted_rows = []
                for row in rows:
                    new_row = list(row)
                    for i, col_name in enumerate(columns):
                        if col_name in self.ENCRYPTED_COLUMNS:
                            new_row[i] = self._decrypt(new_row[i])
                    decrypted_rows.append(tuple(new_row))
                rows = decrypted_rows

        finally:
            self.close()
        return rows

    def getCount(self, table: str, where: str = None, params: tuple = ()) -> int:
        """Retourne le nombre de lignes dans une table."""
        if not self.table_exists(table):
            return 0
        
        sql = f"SELECT COUNT(*) FROM {table}"
        if where:
            sql += f" WHERE {where}"
        
        self.open()
        try:
            self.cursor.execute(sql, params)
            count = self.cursor.fetchone()[0]
        finally:
            self.close()
        return count

    def getLatest(self, table: str, columns: list, limit: int = 100, decrypt: bool = True):
        """Récupère les dernières entrées d'une table."""
        if not self.table_exists(table):
            return []
        
        cols = ", ".join(columns)
        sql = f"SELECT {cols} FROM {table} ORDER BY id DESC LIMIT ?"
        
        self.open()
        try:
            self.cursor.execute(sql, (limit,))
            rows = self.cursor.fetchall()
            
            if decrypt and self.encryption_enabled:
                decrypted_rows = []
                for row in rows:
                    new_row = list(row)
                    for i, col_name in enumerate(columns):
                        if col_name in self.ENCRYPTED_COLUMNS:
                            new_row[i] = self._decrypt(new_row[i])
                    decrypted_rows.append(tuple(new_row))
                rows = decrypted_rows
        finally:
            self.close()
        return rows

    def deleteOld(self, table: str, days: int = 30):
        """Supprime les entrées plus anciennes que X jours."""
        self.open()
        try:
            self.cursor.execute(
                f"DELETE FROM {table} WHERE time_stamp < datetime('now', '-{days} days')"
            )
            deleted = self.cursor.rowcount
            self.connection.commit()
            return deleted
        finally:
            self.close()

    def getStatistics(self) -> dict:
        """Retourne des statistiques sur la base de données."""
        stats = {
            "v1_count": self.getCount("snmp_v1") if self.table_exists("snmp_v1") else 0,
            "v2_count": self.getCount("snmp_v2") if self.table_exists("snmp_v2") else 0,
            "v3_count": self.getCount("snmp_v3") if self.table_exists("snmp_v3") else 0,
            "encryption_enabled": self.encryption_enabled
        }
        stats["total"] = stats["v1_count"] + stats["v2_count"] + stats["v3_count"]
        return stats


# =============================================================================
# TESTS
# =============================================================================

if __name__ == "__main__":
    import os
    
    db_file = "test_snmp.db"
    if os.path.exists(db_file):
        os.remove(db_file)

    print("\n" + "="*60)
    print("  TEST SQLiteDB avec chiffrement optionnel")
    print("="*60)

    # Test sans chiffrement
    print("\n[1] Test SANS chiffrement (pas de SNIFFER_KEY)")
    db = DataBase(dbFile=db_file)
    db.initDB()
    print(f"   Chiffrement activé: {db.encryption_enabled}")

    # Test écriture
    data_v2 = {
        "time_stamp": "2025-01-01 12:00:00",
        "mac_src": "AA:BB:CC:DD:EE:FF",
        "ip_src": "192.168.1.10",
        "ip_dst": "192.168.1.50",
        "snmp_community": "public",
        "snmp_pdu_type": "SNMPget",
        "tag": 0
    }
    db.wrData("snmp_v2", data_v2)
    print("   Données écrites dans snmp_v2")

    # Test lecture
    rows = db.getData("snmp_v2", ["ip_src", "snmp_community", "snmp_pdu_type"])
    print(f"   Données lues: {rows}")

    # Stats
    stats = db.getStatistics()
    print(f"   Stats: {stats}")

    # Nettoyage
    os.remove(db_file)
    print("\n[OK] Tests terminés avec succès")
