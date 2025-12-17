from threading import Thread
from queue import Queue
import os
import time
import sys

import SQLiteDB
import confAPP

import sniffer
import analyser


def main(queueSize:int, dataBase:str, interface:str, sniffFilter:str, pcapDir:str, fichier_regles:str):

	q = Queue(maxsize=queueSize)
	
	# -----------------------------------------------------------
	# 1. Initialisation de la Base de Données (Sécurisée)
	# -----------------------------------------------------------
	try:
		# SQLiteDB va chercher SNIFFER_KEY dans l'environnement
		db = SQLiteDB.DataBase(dbFile=dataBase)
		db.initDB()
		print(f"[*] Base de données '{dataBase}' initialisée et chiffrée.")
	except Exception as e:
		print(f"\n[!] ERREUR CRITIQUE BASE DE DONNÉES : {e}")
		return

	# -----------------------------------------------------------
	# 2. Chargement de la Configuration (Règles de filtrage)
	# -----------------------------------------------------------
	configuration = confAPP.ConfAPP(confFile=fichier_regles)
	
	# Si le fichier n'existait pas, on force la création d'une conf par défaut
	if configuration.config is None:
		configuration.creatConf()
		print(f"[*] Configuration par défaut créée : {fichier_regles}")
	else:
		print(f"[*] Configuration chargée : {fichier_regles}")

	# -----------------------------------------------------------
	# 3. Initialisation du Sniffer
	# -----------------------------------------------------------
	sniff_obj = sniffer.Sniffer(iface=interface, sfilter=sniffFilter, queue=q)
	
	# -----------------------------------------------------------
	# 4. Initialisation de l'Analyseur
	# -----------------------------------------------------------
	# On passe la configuration chargée et la DB sécurisée
	analyse = analyser.Analyser(queue=q, baseDB=db, config=configuration.config, pcap_dir=pcapDir, lenPcap=100)

	# -----------------------------------------------------------
	# 5. Démarrage des Threads
	# -----------------------------------------------------------
	thread_sniff = Thread(target=sniff_obj.start_sniffer, daemon=True)
	thread_sniff.start()

	thread_analyse = Thread(target=analyse.start_analyse, daemon=True)
	thread_analyse.start()
	
	print("-" * 60)
	print(f"[*] Sniffer démarré sur l'interface : {interface}")
	print(f"[*] Filtre actif : {sniffFilter}")
	print("[*] Tables actives : snmp_v1, snmp_v2, snmp_v3")
	print(f"[*] Mode Sécurisé : OUI (Chiffrement actif)")
	print("-" * 60)
	
	# Boucle pour garder le programme principal en vie
	while True:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			print("\n[!] Arrêt demandé par l'utilisateur.")
			break

if __name__ == "__main__":
	# =========================================================================
	# VÉRIFICATION DE SÉCURITÉ AVANT DÉMARRAGE
	# =========================================================================
	if not os.getenv("SNIFFER_KEY"):
		print("\n" + "!"*60)
		print("[ERREUR CRITIQUE] CLÉ DE CHIFFREMENT MANQUANTE")
		print("!"*60)
		print("Le programme ne peut pas démarrer car la variable d'environnement")
		print("'SNIFFER_KEY' n'est pas définie.")
		print("\nPOUR CORRIGER :")
		print("  1. Générez une clé (si ce n'est pas fait) :")
		print("     python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'")
		print("  2. Exportez la variable :")
		print("     export SNIFFER_KEY='VotreClé...'")
		print("\n")
		sys.exit(1)

	# =========================================================================
	# PARAMÈTRES
	# =========================================================================
	DB_FILE = "test.db"
	INTERFACE = "enp4s0" # Remplacez par votre interface réelle si besoin
	PCAP_DIR = "captures"
	CONF_FILE = "conf.json"

	# =========================================================================
	# DIAGNOSTIC DB AU DÉMARRAGE
	# =========================================================================
	if os.path.exists(DB_FILE):
		try:
			# On tente d'ouvrir la DB avec la clé présente dans l'ENV
			db_check = SQLiteDB.DataBase(dbFile=DB_FILE)
			print("\n--- État de la base de données ---")
			
			# Vérification Table V1
			if db_check.table_exists("snmp_v1"):
				rows_v1 = db_check.getData(table="snmp_v1", columns=["id"])
				print(f"   [V1] Entrées existantes : {len(rows_v1)}")
			else:
				print("   [V1] Table non existante.")

			# Vérification Table V2
			if db_check.table_exists("snmp_v2"):
				rows_v2 = db_check.getData(table="snmp_v2", columns=["id"])
				print(f"   [V2] Entrées existantes : {len(rows_v2)}")
			else:
				print("   [V2] Table non existante.")

			# Vérification Table V3
			if db_check.table_exists("snmp_v3"):
				rows_v3 = db_check.getData(table="snmp_v3", columns=["id"])
				print(f"   [V3] Entrées existantes : {len(rows_v3)}")
			else:
				print("   [V3] Table non existante.")
			print("----------------------------------\n")
				
		except ValueError as e:
			print(f"[ERREUR SÉCURITÉ] Impossible de lire la DB : {e}")
			print("Vérifiez que SNIFFER_KEY correspond bien à la clé utilisée pour créer cette DB.\n")
			sys.exit(1)
		except Exception as e:
			print(f"[ERREUR LECTURE DB] {e}\n")

	# =========================================================================
	# LANCEMENT DU PROGRAMME
	# =========================================================================
	try:
		main(
			queueSize=10000, 
			dataBase=DB_FILE, 
			interface=INTERFACE, 
			sniffFilter="udp port 161 or udp port 162", 
			pcapDir=PCAP_DIR,
			fichier_regles=CONF_FILE
		)
	except KeyboardInterrupt:
		print("\n[!] Arrêt du programme.")