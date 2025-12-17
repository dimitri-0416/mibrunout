import sqlite3
import os
from cryptography.fernet import Fernet

class DataBase(object):
	"""Outils de gestion de la base de données SQLite pour le sniffer avec chiffrement."""
	
	def __init__(self, dbFile:str):
		self.dbFile = dbFile
		self.connection = None
		self.cursor = None
		
		# --- SÉCURITÉ : Chargement de la clé depuis l'environnement ---
		key_str = os.getenv("SNIFFER_KEY")
		
		if not key_str:
			raise ValueError(
				"[ERREUR CRITIQUE] La variable d'environnement 'SNIFFER_KEY' est vide. "
				"Impossible de sécuriser la base de données. "
				"Veuillez définir la variable (ex: export SNIFFER_KEY='VotreClé...')."
			)
		
		try:
			# Fernet attend des bytes, on encode la string récupérée de l'env
			self.key = key_str.encode()
			self.cipher = Fernet(self.key)
		except Exception as e:
			raise ValueError(f"[ERREUR] La clé SNIFFER_KEY semble invalide ou malformée : {e}")

		# Liste des colonnes contenant des données sensibles à chiffrer
		self.encrypted_columns = ["snmp_community", "snmp_oidsValues", "ip_src", "ip_dst", "mac_src", "mac_dst"]

	def open(self):
		"""Ouvre la connexion à la base de données si elle n'est pas déjà ouverte."""
		if self.connection is None:
			self.connection = sqlite3.connect(self.dbFile)
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

	def table_exists(self, table: str):
		self.open()
		self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
		exists = self.cursor.fetchone() is not None
		self.close()
		return exists

	# --- MÉTHODES DE CHIFFREMENT INTERNES ---

	def _encrypt(self, data):
		"""Chiffre une donnée (string ou int converti en string)."""
		if data is None: return None
		# On convertit tout en string avant de chiffrer
		return self.cipher.encrypt(str(data).encode()).decode()

	def _decrypt(self, data):
		"""Déchiffre une donnée."""
		if data is None: return None
		try:
			return self.cipher.decrypt(data.encode()).decode()
		except Exception:
			# Si le déchiffrement échoue (ex: donnée non chiffrée issue d'anciens tests), on retourne tel quel
			return data

	# ----------------------------------------

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
			
			-- Champs Standards
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
			
			snmp_community TEXT, 
			snmp_pdu_type TEXT,

			snmp_context_engine_id TEXT,
			snmp_context_name TEXT,
			snmp_security_model TEXT,
			snmp_security_level TEXT,
			
			snmp_request_id INTEGER,
			snmp_error_status INTEGER,
			snmp_error_index INTEGER,
			
			snmp_non_repeaters INTEGER,
			snmp_max_repetitions INTEGER,
			
			snmp_oidsValues TEXT,
			tag INTEGER)''')
			
		self.connection.commit()
		self.close()

	def getChamps(self, table:str):
		"""Retourne la liste des noms de colonnes d'une table."""
		self.open()
		self.cursor.execute(f"PRAGMA table_info({table})")
		colonnes_info = self.cursor.fetchall()
		self.close()
		return colonnes_info

	def wrData(self, table: str, data: dict):
		"""
		Écrit une ligne dans la base de données en chiffrant les champs sensibles.
		"""
		self.open()
		try:
			# --- CHIFFREMENT A LA VOLÉE ---
			# On travaille sur une copie pour ne pas modifier le dict original
			secure_data = data.copy()
			
			for col, val in secure_data.items():
				if col in self.encrypted_columns:
					secure_data[col] = self._encrypt(val)
			# ------------------------------

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

	def getData(self, table:str, columns:list[str], where:str=None, params:tuple=()):
		"""
		Récupère des données et les déchiffre automatiquement.
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
			
			# --- DÉCHIFFREMENT A LA VOLÉE ---
			decrypted_rows = []
			for row in rows:
				# Convertit le tuple en list pour pouvoir le modifier
				new_row = list(row)
				for i, col_name in enumerate(columns):
					if col_name in self.encrypted_columns:
						new_row[i] = self._decrypt(new_row[i])
				decrypted_rows.append(tuple(new_row))
			
			rows = decrypted_rows
			# --------------------------------

		finally:
			self.close()
		return rows