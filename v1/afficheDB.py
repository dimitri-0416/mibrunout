import sqlite3
import os
import argparse
from cryptography.fernet import Fernet

# Liste des colonnes susceptibles d'être chiffrées dans votre projet
COLONNES_CHIFFREES = [
	"mac_src", "mac_dst", 
	"ip_src", "ip_dst", 
	"snmp_community", "snmp_oidsValues"
]

def get_cipher():
	"""Récupère la clé et initialise le moteur de déchiffrement."""
	key_str = os.getenv("SNIFFER_KEY")
	if not key_str:
		print("[!] Attention : L'option de déchiffrement est activée mais la variable 'SNIFFER_KEY' est vide.")
		print("    Les données seront affichées brutes (chiffrées).")
		return None
	try:
		return Fernet(key_str.encode())
	except Exception as e:
		print(f"[!] Erreur : Clé SNIFFER_KEY invalide ({e}).")
		return None

def decrypt_val(cipher, value):
	"""Tente de déchiffrer une valeur unitaire."""
	if value is None: return None
	try:
		# On suppose que la donnée chiffrée est une string dans la DB
		return cipher.decrypt(str(value).encode()).decode()
	except Exception:
		# Si ça échoue (ex: donnée pas chiffrée ou mauvaise clé), on renvoie l'original
		return value

def afficher_contenu_db(nom_db, mode_decrypt=False):
	cipher = None
	if mode_decrypt:
		print("[*] Mode déchiffrement activé.")
		cipher = get_cipher()

	try:
		if not os.path.exists(nom_db):
			print(f"[!] Le fichier {nom_db} n'existe pas.")
			return

		conn = sqlite3.connect(nom_db)
		cursor = conn.cursor()
		
		# Récupérer la liste des tables
		cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';")
		tables = cursor.fetchall()
		
		if not tables:
			print("Aucune table trouvée dans la base de données.")
			return

		for table_nom in tables:
			table = table_nom[0]
			print(f"\n{'='*20} TABLE : {table} {'='*20}")
			
			# Récupérer les données
			cursor.execute(f"SELECT * FROM {table}")
			lignes = cursor.fetchall()
			
			# Récupérer les noms des colonnes
			if cursor.description:
				noms_colonnes = [desc[0] for desc in cursor.description]
				print(f"Colonnes: {noms_colonnes}")
				
				# Identifier les index des colonnes à déchiffrer
				indices_a_traiter = []
				if cipher:
					for i, col in enumerate(noms_colonnes):
						if col in COLONNES_CHIFFREES:
							indices_a_traiter.append(i)
			else:
				print("(Pas de colonnes définies)")
				continue
			
			print("-" * 60)
			for ligne in lignes:
				# Si pas de déchiffrement, on affiche direct
				if not cipher or not indices_a_traiter:
					print(ligne)
				else:
					# Conversion tuple -> list pour modification
					ligne_modifiable = list(ligne)
					
					for index in indices_a_traiter:
						ligne_modifiable[index] = decrypt_val(cipher, ligne_modifiable[index])
					
					# Affichage sous forme de tuple pour rester cohérent avec l'affichage standard
					print(tuple(ligne_modifiable))
				
	except sqlite3.Error as e:
		print(f"Erreur SQLite : {e}")
	except Exception as e:
		print(f"Erreur inattendue : {e}")
	finally:
		if 'conn' in locals() and conn:
			conn.close()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Affiche le contenu d'une base SQLite de sniffer.")
	parser.add_argument("db_file", nargs='?', default="test.db", help="Chemin vers le fichier .db (défaut: test.db)")
	parser.add_argument("-d", "--decrypt", action="store_true", help="Active le déchiffrement (nécessite la variable d'env SNIFFER_KEY)")
	
	args = parser.parse_args()
	
	afficher_contenu_db(args.db_file, args.decrypt)