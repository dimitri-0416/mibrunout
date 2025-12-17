from queue import Queue
from scapy.all import *
from datetime import datetime
import os
import json

import SQLiteDB
import paquetInfo

class Analyser(object):
	"""
	Analyse les trames stockées dans la FILE puis envoie les résultats sur une base de donnée
	Applique les filtres définis dans la configuration fournie.
	Utilise paquetInfo.py pour le parsing.
	"""
	def __init__(self, queue:Queue, baseDB, config:dict=None, pcap_dir="captures", lenPcap:int=100):
		# Instanciation de la classe d'extraction externe
		self.GetPaquetInfo = paquetInfo.GetPaquetInfo()
		
		self.queue = queue
		self.baseDB = baseDB
		self.config = config if config else {}
		self.pcap_dir = pcap_dir
		self.lenPcap = lenPcap
		self.nb_pkt = 0
		self.file_index = 0
		self.pcap_writer = None

		# Initialisation des tables en base de données (V1, V2 et V3)
		self.baseDB.initDB()

		os.makedirs(pcap_dir, exist_ok=True)
		self.open_new_pcap()

	def open_new_pcap(self):
		if self.pcap_writer:
			self.pcap_writer.close()
		filename = os.path.join(self.pcap_dir, f"capture_{self.file_index:04d}.pcap")
		self.pcap_writer = PcapWriter(filename, append=False, sync=False)
		self.file_index += 1
		self.nb_pkt = 0

	# --- Logique de filtrage ---

	def in_whitelist(self, key, value):
		whitelist = self.config.get("whiteList", {})
		values = whitelist.get(key, [])
		return value in values

	def in_filtre(self, pkt_data:dict):
		filtres = self.config.get("filtres", {})
		# On ajoute snmp_community à la liste des champs à vérifier strictement
		rule_elts = ["mac_src","mac_dst","ip_src","ip_dst","port_src","port_dst", "snmp_community"]
        
		for rule_name, rule in filtres.items():
			match = True
			if not isinstance(rule, dict): continue
            
			for key, val in rule.items():
				if not val: continue
				if key in rule_elts:
					# Comparaison stricte (IP, Port, MAC, User/Community)
					if str(val) != str(pkt_data.get(key)):
						match = False
						break
            
			# Vérification spéciale OIDs (inchangée)
			if match and "snmp_oidsValues" in rule and rule["snmp_oidsValues"]:
				target = rule["snmp_oidsValues"]
				found = False
				for oid_entry in pkt_data.get("snmp_oidsValues", []):
					if target in oid_entry["oid"]:
						found = True
						break
				if not found: match = False

			if match:
				return True, rule_name

		return False, None

	def compare(self, data:dict):
		"""
		Retourne True si le paquet est autorisé.
		Logique STRICTE (AND) pour la Whitelist.
		"""
		if not self.config: return False

		# 1. Whitelist (Logique AND : Src ET Dst doivent être autorisés)
		if data.get("mac_src") and data.get("mac_dst"):
			if self.in_whitelist("MACs", data.get("mac_src")) and self.in_whitelist("MACs", data.get("mac_dst")):
				return True
		
		if data.get("ip_src") and data.get("ip_dst"):
			if self.in_whitelist("IPs", data.get("ip_src")) and self.in_whitelist("IPs", data.get("ip_dst")):
				return True
		
		if data.get("port_src") and data.get("port_dst"):
			if self.in_whitelist("PORTs", str(data.get("port_src"))) and self.in_whitelist("PORTs", str(data.get("port_dst"))):
				return True
		
		# OIDs
		for oid_entry in data.get("snmp_oidsValues", []):
			if self.in_whitelist("OIDs", oid_entry["oid"]):
				return True

		# 2. Filtres
		is_match, rule_name = self.in_filtre(data)
		if is_match:
			print(f"[OK] Règle correspondante : {rule_name}")
			return True

		return False

	# ---------------------------

	def analyser_paquet(self, pkt):
		# 1. Extraction complète via la classe externe
		full_data = self.GetPaquetInfo.packet_info(pkt)
		
		# 2. Comparaison et définition du TAG
		full_data["tag"] = None 

		if self.compare(full_data):
			print(f"[+] Paquet autorisé ({full_data['time_stamp']})")
			full_data["tag"] = 0
		else:
			print(f"[!] Paquet suspect/interdit ({full_data['time_stamp']})")
			full_data["tag"] = 1
				
		# 3. Préparation DB
		# Construction du dictionnaire de base commun à toutes les versions
		db_data = {
			"time_stamp": full_data["time_stamp"],
			"mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
			"ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
			"port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
			"snmp_community": full_data["snmp_community"],
			"snmp_pdu_type": full_data["snmp_pdu_type"],
			"snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
			"tag": full_data["tag"]
		}

		# 4. Aiguillage selon la version (0=v1, 1=v2c, 3=v3)
		version = str(full_data.get("snmp_version"))
		table_cible = None

		if version == "0":
			table_cible = "snmp_v1"
			db_data["snmp_enterprise"] = full_data["snmp_enterprise"]
			db_data["snmp_agent_addr"] = full_data["snmp_agent_addr"]
			db_data["snmp_generic_trap"] = full_data["snmp_generic_trap"]
			db_data["snmp_specific_trap"] = full_data["snmp_specific_trap"]
			db_data["snmp_request_id"] = full_data["snmp_request_id"]
			db_data["snmp_error_status"] = full_data["snmp_error_status"]
			db_data["snmp_error_index"] = full_data["snmp_error_index"]

		elif version == "1":
			table_cible = "snmp_v2"
			db_data["snmp_request_id"] = full_data["snmp_request_id"]
			db_data["snmp_error_status"] = full_data["snmp_error_status"]
			db_data["snmp_error_index"] = full_data["snmp_error_index"]
			db_data["snmp_non_repeaters"] = full_data["snmp_non_repeaters"]
			db_data["snmp_max_repetitions"] = full_data["snmp_max_repetitions"]
		
		# --- GESTION V3 ---
		elif version == "3":
			table_cible = "snmp_v3"
			# Champs Standards PDU
			db_data["snmp_request_id"] = full_data["snmp_request_id"]
			db_data["snmp_error_status"] = full_data["snmp_error_status"]
			db_data["snmp_error_index"] = full_data["snmp_error_index"]
			db_data["snmp_non_repeaters"] = full_data["snmp_non_repeaters"]
			db_data["snmp_max_repetitions"] = full_data["snmp_max_repetitions"]
			
			# Champs de Sécurité V3
			db_data["snmp_context_engine_id"] = full_data["snmp_context_engine_id"]
			db_data["snmp_context_name"] = full_data["snmp_context_name"]
			db_data["snmp_security_model"] = full_data["snmp_security_model"]
			db_data["snmp_security_level"] = full_data["snmp_security_level"]

		# Ecriture en Base de Données seulement si la version est supportée
		if table_cible:
			# Nettoyage des valeurs None
			db_data = {k: v for k, v in db_data.items() if v is not None}
			self.baseDB.wrData(table_cible, db_data)
			
		# 5. Enregistrement PCAP
		self.pcap_writer.write(pkt)
		self.nb_pkt += 1
			
		if self.nb_pkt >= self.lenPcap:
			self.open_new_pcap()

	def start_analyse(self):
		print(list(self.queue.queue))
		try:
			while True:
				pkt = self.queue.get()
				self.analyser_paquet(pkt)
				self.queue.task_done()
		except KeyboardInterrupt:
			print("\n[!] Interruption.")
		finally:
			print("[!] Fermeture ressources...")
			if self.pcap_writer: self.pcap_writer.close()
			if hasattr(self.baseDB, 'close'): self.baseDB.close()

if __name__ == "__main__":
	# ... (Le bloc de test reste inchangé, utile pour débogage local)
	pass