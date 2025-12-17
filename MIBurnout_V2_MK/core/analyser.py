from queue import Queue
from scapy.all import *
from datetime import datetime
import os
import json
import hashlib
import binascii

# Import relatif pour utilisation en module
try:
    from . import SQLiteDB
except ImportError:
    import SQLiteDB


# =============================================================================
# CONSTANTES SNMPv3
# =============================================================================

# Protocoles d'authentification
AUTH_PROTOCOLS = {
    "1.3.6.1.6.3.10.1.1.1": "noAuth",
    "1.3.6.1.6.3.10.1.1.2": "HMAC-MD5-96",
    "1.3.6.1.6.3.10.1.1.3": "HMAC-SHA-96",
    "1.3.6.1.6.3.10.1.1.4": "HMAC-SHA-224",
    "1.3.6.1.6.3.10.1.1.5": "HMAC-SHA-256",
    "1.3.6.1.6.3.10.1.1.6": "HMAC-SHA-384",
    "1.3.6.1.6.3.10.1.1.7": "HMAC-SHA-512",
}

# Protocoles de chiffrement (Privacy)
PRIV_PROTOCOLS = {
    "1.3.6.1.6.3.10.1.2.1": "noPriv",
    "1.3.6.1.6.3.10.1.2.2": "DES",
    "1.3.6.1.6.3.10.1.2.3": "3DES-EDE",
    "1.3.6.1.6.3.10.1.2.4": "AES-128-CFB",
    "1.3.6.1.6.3.10.1.2.5": "AES-192-CFB",
    "1.3.6.1.6.3.10.1.2.6": "AES-256-CFB",
}

# Security Levels
SECURITY_LEVELS = {
    0: "noAuthNoPriv",
    1: "authNoPriv", 
    3: "authPriv"
}


class Analyser(object):
	"""
	Analyse les trames stockées dans la FILE puis envoie les résultats sur une base de donnée
	Applique les filtres définis dans la configuration fournie.
	Supporte SNMPv1, SNMPv2c et SNMPv3.
	"""
	def __init__(self, queue:Queue, baseDB, config:dict=None, pcap_dir="captures", lenPcap:int=100):
		self.queue = queue
		self.baseDB = baseDB
		self.config = config if config else {}
		self.pcap_dir = pcap_dir
		self.lenPcap = lenPcap
		self.nb_pkt = 0
		self.file_index = 0
		self.pcap_writer = None

		# Initialisation des tables en base de données (V1, V2, V3)
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

	def convert_asn1(self, obj):
		if hasattr(obj, "pretty"): return obj.pretty()
		elif hasattr(obj, "val"): return str(obj.val)
		else: return str(obj)
	
	def bytes_to_hex(self, data):
		"""Convertit des bytes en string hexadécimal"""
		if isinstance(data, bytes):
			return binascii.hexlify(data).decode('utf-8')
		return str(data)
	
	def parse_snmpv3_flags(self, flags_byte):
		"""Parse les flags SNMPv3 msgFlags"""
		if isinstance(flags_byte, bytes):
			flags = flags_byte[0] if len(flags_byte) > 0 else 0
		else:
			flags = int(flags_byte) if flags_byte else 0
		
		auth = bool(flags & 0x01)
		priv = bool(flags & 0x02)
		reportable = bool(flags & 0x04)
		
		if auth and priv:
			level = "authPriv"
		elif auth:
			level = "authNoPriv"
		else:
			level = "noAuthNoPriv"
		
		return {
			"auth": auth,
			"priv": priv,
			"reportable": reportable,
			"security_level": level,
			"raw": flags
		}

	def packet_info(self, pkt):
		# --- 1. Timestamp & Couches Réseau ---
		time_stamp = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")

		mac_src = pkt[Ether].src if Ether in pkt else None
		mac_dst = pkt[Ether].dst if Ether in pkt else None
		ip_src = pkt[IP].src if IP in pkt else None
		ip_dst = pkt[IP].dst if IP in pkt else None
		port_src = pkt[UDP].sport if UDP in pkt else None
		port_dst = pkt[UDP].dport if UDP in pkt else None

		# --- 2. Initialisation des champs SNMP (Tous à None par défaut) ---
		res = {
			"time_stamp": time_stamp,
			"mac_src": mac_src, "mac_dst": mac_dst,
			"ip_src": ip_src, "ip_dst": ip_dst,
			"port_src": port_src, "port_dst": port_dst,
			"snmp_oidsValues": [],
			"snmp_version": None, "snmp_community": None, "snmp_pdu_type": None,
			# Champs communs / V2
			"snmp_request_id": None, "snmp_error_status": None, "snmp_error_index": None,
			# Champs V1 Trap
			"snmp_enterprise": None, "snmp_agent_addr": None, 
			"snmp_generic_trap": None, "snmp_specific_trap": None,
			# Champs V2 Bulk
			"snmp_non_repeaters": None, "snmp_max_repetitions": None,
			# === Champs SNMPv3 ===
			"snmp_msg_id": None,
			"snmp_msg_max_size": None,
			"snmp_msg_flags": None,
			"snmp_msg_security_model": None,
			# USM
			"snmp_usm_engine_id": None,
			"snmp_usm_engine_boots": None,
			"snmp_usm_engine_time": None,
			"snmp_usm_user_name": None,
			"snmp_usm_auth_protocol": None,
			"snmp_usm_priv_protocol": None,
			"snmp_usm_auth_params": None,
			"snmp_usm_priv_params": None,
			# ScopedPDU
			"snmp_context_engine_id": None,
			"snmp_context_name": None,
			# Sécurité
			"security_level": None,
			"is_encrypted": 0,
			"is_authenticated": 0,
			"decryption_status": None
		}

		if SNMP in pkt:
			snmp = pkt[SNMP]
			version_raw = self.convert_asn1(snmp.version)
			res["snmp_version"] = version_raw  # 0=v1, 1=v2c, 3=v3
			
			# ==============================================================================
			# SNMPv3
			# ==============================================================================
			if str(version_raw) == "3":
				res = self._parse_snmpv3(pkt, res)
			
			# ==============================================================================
			# SNMPv1 / SNMPv2c
			# ==============================================================================
			else:
				res["snmp_community"] = self.convert_asn1(snmp.community)

				if hasattr(snmp, "PDU") and snmp.PDU:
					pdu = snmp.PDU
					res["snmp_pdu_type"] = pdu.__class__.__name__

					# CAS A : SNMP v1 TRAP
					if res["snmp_pdu_type"] == "SNMPtrap":
						res["snmp_enterprise"] = self.convert_asn1(pdu.enterprise)
						res["snmp_agent_addr"] = self.convert_asn1(pdu.agent_addr)
						res["snmp_generic_trap"] = int(pdu.generic_trap)
						res["snmp_specific_trap"] = int(pdu.specific_trap)

					# CAS B : SNMP v2 GET-BULK
					elif res["snmp_pdu_type"] == "SNMPbulk":
						res["snmp_request_id"] = self.convert_asn1(pdu.id)
						res["snmp_non_repeaters"] = self.convert_asn1(pdu.non_repeaters)
						res["snmp_max_repetitions"] = self.convert_asn1(pdu.max_repetitions)

					# CAS C : STANDARD (Get, Set, Response, Inform, TrapV2)
					else:
						if hasattr(pdu, "id"):
							res["snmp_request_id"] = self.convert_asn1(pdu.id)
						if hasattr(pdu, "error_status"):
							res["snmp_error_status"] = self.convert_asn1(pdu.error_status)
						if hasattr(pdu, "error_index"):
							res["snmp_error_index"] = self.convert_asn1(pdu.error_index)

					# EXTRACTION DES VARBINDS
					res["snmp_oidsValues"] = self._extract_varbinds(pdu)
					
		return res
	
	def _parse_snmpv3(self, pkt, res):
		"""Parse un paquet SNMPv3"""
		try:
			raw_data = bytes(pkt[UDP].payload)
			
			# Le paquet SNMPv3 est une séquence ASN.1
			# Structure: SEQUENCE { msgVersion, msgGlobalData, msgSecurityParameters, msgData }
			
			# Essayer de parser avec Scapy si disponible
			if hasattr(pkt[SNMP], 'PDU') and pkt[SNMP].PDU:
				pdu = pkt[SNMP].PDU
				res["snmp_pdu_type"] = pdu.__class__.__name__
				
				# Extraire les varbinds si possible
				res["snmp_oidsValues"] = self._extract_varbinds(pdu)
			
			# Parser les champs SNMPv3 depuis les données brutes
			res = self._parse_snmpv3_raw(raw_data, res)
			
		except Exception as e:
			res["decryption_status"] = f"Parse error: {str(e)}"
		
		return res
	
	def _parse_snmpv3_raw(self, raw_data, res):
		"""Parse les données brutes SNMPv3"""
		try:
			# Analyse simplifiée du header SNMPv3
			# Les vrais parsers utilisent pyasn1 ou pysnmp
			
			idx = 0
			
			# Skip SEQUENCE tag et length
			if raw_data[idx] == 0x30:
				idx += 1
				if raw_data[idx] & 0x80:
					len_bytes = raw_data[idx] & 0x7f
					idx += 1 + len_bytes
				else:
					idx += 1
			
			# Version (INTEGER)
			if idx < len(raw_data) and raw_data[idx] == 0x02:
				idx += 1
				ver_len = raw_data[idx]
				idx += 1
				idx += ver_len
			
			# msgGlobalData (SEQUENCE)
			if idx < len(raw_data) and raw_data[idx] == 0x30:
				idx += 1
				if raw_data[idx] & 0x80:
					len_bytes = raw_data[idx] & 0x7f
					global_len = int.from_bytes(raw_data[idx+1:idx+1+len_bytes], 'big')
					idx += 1 + len_bytes
				else:
					global_len = raw_data[idx]
					idx += 1
				
				global_end = idx + global_len
				
				# msgID (INTEGER)
				if idx < global_end and raw_data[idx] == 0x02:
					idx += 1
					msg_id_len = raw_data[idx]
					idx += 1
					res["snmp_msg_id"] = int.from_bytes(raw_data[idx:idx+msg_id_len], 'big')
					idx += msg_id_len
				
				# msgMaxSize (INTEGER)
				if idx < global_end and raw_data[idx] == 0x02:
					idx += 1
					max_size_len = raw_data[idx]
					idx += 1
					res["snmp_msg_max_size"] = int.from_bytes(raw_data[idx:idx+max_size_len], 'big')
					idx += max_size_len
				
				# msgFlags (OCTET STRING)
				if idx < global_end and raw_data[idx] == 0x04:
					idx += 1
					flags_len = raw_data[idx]
					idx += 1
					flags_data = raw_data[idx:idx+flags_len]
					flags_info = self.parse_snmpv3_flags(flags_data)
					res["snmp_msg_flags"] = flags_info["raw"]
					res["security_level"] = flags_info["security_level"]
					res["is_authenticated"] = 1 if flags_info["auth"] else 0
					res["is_encrypted"] = 1 if flags_info["priv"] else 0
					idx += flags_len
				
				# msgSecurityModel (INTEGER)
				if idx < global_end and raw_data[idx] == 0x02:
					idx += 1
					sec_model_len = raw_data[idx]
					idx += 1
					res["snmp_msg_security_model"] = int.from_bytes(raw_data[idx:idx+sec_model_len], 'big')
					idx += sec_model_len
			
			# msgSecurityParameters (OCTET STRING contenant USM)
			if idx < len(raw_data) and raw_data[idx] == 0x04:
				idx += 1
				if raw_data[idx] & 0x80:
					len_bytes = raw_data[idx] & 0x7f
					usm_len = int.from_bytes(raw_data[idx+1:idx+1+len_bytes], 'big')
					idx += 1 + len_bytes
				else:
					usm_len = raw_data[idx]
					idx += 1
				
				usm_data = raw_data[idx:idx+usm_len]
				res = self._parse_usm(usm_data, res)
				idx += usm_len
			
			# Déterminer les protocoles basés sur les flags
			if res["is_authenticated"]:
				res["snmp_usm_auth_protocol"] = "HMAC-MD5/SHA"  # Détection exacte nécessite plus d'analyse
			else:
				res["snmp_usm_auth_protocol"] = "noAuth"
			
			if res["is_encrypted"]:
				res["snmp_usm_priv_protocol"] = "DES/AES"
				res["decryption_status"] = "encrypted"
			else:
				res["snmp_usm_priv_protocol"] = "noPriv"
				res["decryption_status"] = "not_encrypted"
			
		except Exception as e:
			res["decryption_status"] = f"Raw parse error: {str(e)}"
		
		return res
	
	def _parse_usm(self, usm_data, res):
		"""Parse les paramètres USM (User-based Security Model)"""
		try:
			idx = 0
			
			# USM est une SEQUENCE
			if usm_data[idx] == 0x30:
				idx += 1
				if usm_data[idx] & 0x80:
					len_bytes = usm_data[idx] & 0x7f
					idx += 1 + len_bytes
				else:
					idx += 1
			
			# msgAuthoritativeEngineID (OCTET STRING)
			if idx < len(usm_data) and usm_data[idx] == 0x04:
				idx += 1
				engine_id_len = usm_data[idx]
				idx += 1
				res["snmp_usm_engine_id"] = self.bytes_to_hex(usm_data[idx:idx+engine_id_len])
				idx += engine_id_len
			
			# msgAuthoritativeEngineBoots (INTEGER)
			if idx < len(usm_data) and usm_data[idx] == 0x02:
				idx += 1
				boots_len = usm_data[idx]
				idx += 1
				res["snmp_usm_engine_boots"] = int.from_bytes(usm_data[idx:idx+boots_len], 'big')
				idx += boots_len
			
			# msgAuthoritativeEngineTime (INTEGER)
			if idx < len(usm_data) and usm_data[idx] == 0x02:
				idx += 1
				time_len = usm_data[idx]
				idx += 1
				res["snmp_usm_engine_time"] = int.from_bytes(usm_data[idx:idx+time_len], 'big')
				idx += time_len
			
			# msgUserName (OCTET STRING)
			if idx < len(usm_data) and usm_data[idx] == 0x04:
				idx += 1
				user_len = usm_data[idx]
				idx += 1
				try:
					res["snmp_usm_user_name"] = usm_data[idx:idx+user_len].decode('utf-8')
				except:
					res["snmp_usm_user_name"] = self.bytes_to_hex(usm_data[idx:idx+user_len])
				idx += user_len
			
			# msgAuthenticationParameters (OCTET STRING)
			if idx < len(usm_data) and usm_data[idx] == 0x04:
				idx += 1
				auth_len = usm_data[idx]
				idx += 1
				res["snmp_usm_auth_params"] = self.bytes_to_hex(usm_data[idx:idx+auth_len]) if auth_len > 0 else None
				idx += auth_len
			
			# msgPrivacyParameters (OCTET STRING)
			if idx < len(usm_data) and usm_data[idx] == 0x04:
				idx += 1
				priv_len = usm_data[idx]
				idx += 1
				res["snmp_usm_priv_params"] = self.bytes_to_hex(usm_data[idx:idx+priv_len]) if priv_len > 0 else None
				idx += priv_len
				
		except Exception as e:
			pass
		
		return res
	
	def _extract_varbinds(self, pdu):
		"""Extrait les varbinds d'un PDU"""
		varbinds = []
		if hasattr(pdu, "varbindlist"):
			for elt in pdu.varbindlist:
				val = elt.value
				if hasattr(val, "prettyPrint"): 
					val = val.prettyPrint()
				else: 
					val = str(val)
				varbinds.append({
					"oid": self.convert_asn1(elt.oid),
					"value": val
				})
		return varbinds

	# --- Logique de filtrage ---

	def in_whitelist(self, key, value):
		whitelist = self.config.get("whiteList", {})
		values = whitelist.get(key, [])
		return value in values

	def in_filtre(self, pkt_data:dict):
		filtres = self.config.get("filtres", {})
		rule_elts = ["mac_src","mac_dst","ip_src","ip_dst","port_src","port_dst"]
		
		for rule_name, rule in filtres.items():
			match = True
			if not isinstance(rule, dict): continue
			
			for key, val in rule.items():
				if not val: continue
				if key in rule_elts:
					if str(val) != str(pkt_data.get(key)):
						match = False
						break
			
			# Vérification spéciale pour OIDs (contient partiel)
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
		# MACs
		if data.get("mac_src") and data.get("mac_dst"):
			if self.in_whitelist("MACs", data.get("mac_src")) and self.in_whitelist("MACs", data.get("mac_dst")):
				return True
		
		# IPs
		if data.get("ip_src") and data.get("ip_dst"):
			if self.in_whitelist("IPs", data.get("ip_src")) and self.in_whitelist("IPs", data.get("ip_dst")):
				return True
		
		# Ports
		if data.get("port_src") and data.get("port_dst"):
			if self.in_whitelist("PORTs", str(data.get("port_src"))) and self.in_whitelist("PORTs", str(data.get("port_dst"))):
				return True
		
		# OIDs (Si l'un des OIDs du paquet est dans la liste, on accepte)
		for oid_entry in data.get("snmp_oidsValues", []):
			if self.in_whitelist("OIDs", oid_entry["oid"]):
				return True
		
		# SNMPv3 Users
		if data.get("snmp_usm_user_name"):
			if self.in_whitelist("USM_Users", data.get("snmp_usm_user_name")):
				return True

		# 2. Filtres
		is_match, rule_name = self.in_filtre(data)
		if is_match:
			print(f"[OK] Règle correspondante : {rule_name}")
			return True

		return False

	# ---------------------------

	def analyser_paquet(self, pkt):
		# 1. Extraction complète
		full_data = self.packet_info(pkt)
		
		# 2. Comparaison et définition du TAG
		full_data["tag"] = None 

		if self.compare(full_data):
			print(f"[+] Paquet autorisé ({full_data['time_stamp']})")
			full_data["tag"] = 0
		else:
			print(f"[!] Paquet suspect/interdit ({full_data['time_stamp']})")
			full_data["tag"] = 1
				
		# 3. Préparation DB - Aiguillage selon version
		version = str(full_data.get("snmp_version"))
		
		if version == "3":
			table_cible = "snmp_v3"
			db_data = {
				"time_stamp": full_data["time_stamp"],
				"mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
				"ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
				"port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
				# SNMPv3 Header
				"snmp_msg_id": full_data["snmp_msg_id"],
				"snmp_msg_max_size": full_data["snmp_msg_max_size"],
				"snmp_msg_flags": full_data["snmp_msg_flags"],
				"snmp_msg_security_model": full_data["snmp_msg_security_model"],
				# USM
				"snmp_usm_engine_id": full_data["snmp_usm_engine_id"],
				"snmp_usm_engine_boots": full_data["snmp_usm_engine_boots"],
				"snmp_usm_engine_time": full_data["snmp_usm_engine_time"],
				"snmp_usm_user_name": full_data["snmp_usm_user_name"],
				"snmp_usm_auth_protocol": full_data["snmp_usm_auth_protocol"],
				"snmp_usm_priv_protocol": full_data["snmp_usm_priv_protocol"],
				"snmp_usm_auth_params": full_data["snmp_usm_auth_params"],
				"snmp_usm_priv_params": full_data["snmp_usm_priv_params"],
				# PDU
				"snmp_context_engine_id": full_data["snmp_context_engine_id"],
				"snmp_context_name": full_data["snmp_context_name"],
				"snmp_pdu_type": full_data["snmp_pdu_type"],
				"snmp_request_id": full_data["snmp_request_id"],
				"snmp_error_status": full_data["snmp_error_status"],
				"snmp_error_index": full_data["snmp_error_index"],
				"snmp_non_repeaters": full_data["snmp_non_repeaters"],
				"snmp_max_repetitions": full_data["snmp_max_repetitions"],
				"snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
				# Sécurité
				"security_level": full_data["security_level"],
				"is_encrypted": full_data["is_encrypted"],
				"is_authenticated": full_data["is_authenticated"],
				"decryption_status": full_data["decryption_status"],
				"tag": full_data["tag"]
			}
		elif version == "0":
			table_cible = "snmp_v1"
			db_data = {
				"time_stamp": full_data["time_stamp"],
				"mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
				"ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
				"port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
				"snmp_community": full_data["snmp_community"],
				"snmp_pdu_type": full_data["snmp_pdu_type"],
				"snmp_enterprise": full_data["snmp_enterprise"],
				"snmp_agent_addr": full_data["snmp_agent_addr"],
				"snmp_generic_trap": full_data["snmp_generic_trap"],
				"snmp_specific_trap": full_data["snmp_specific_trap"],
				"snmp_request_id": full_data["snmp_request_id"],
				"snmp_error_status": full_data["snmp_error_status"],
				"snmp_error_index": full_data["snmp_error_index"],
				"snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
				"tag": full_data["tag"]
			}
		else:
			table_cible = "snmp_v2"
			db_data = {
				"time_stamp": full_data["time_stamp"],
				"mac_src": full_data["mac_src"], "mac_dst": full_data["mac_dst"],
				"ip_src": full_data["ip_src"], "ip_dst": full_data["ip_dst"],
				"port_src": full_data["port_src"], "port_dst": full_data["port_dst"],
				"snmp_community": full_data["snmp_community"],
				"snmp_pdu_type": full_data["snmp_pdu_type"],
				"snmp_request_id": full_data["snmp_request_id"],
				"snmp_error_status": full_data["snmp_error_status"],
				"snmp_error_index": full_data["snmp_error_index"],
				"snmp_non_repeaters": full_data["snmp_non_repeaters"],
				"snmp_max_repetitions": full_data["snmp_max_repetitions"],
				"snmp_oidsValues": json.dumps({"oidsValues": full_data["snmp_oidsValues"]}),
				"tag": full_data["tag"]
			}

		# Nettoyage des valeurs None pour laisser SQLite gérer les NULL
		db_data = {k: v for k, v in db_data.items() if v is not None}

		# Ecriture en Base de Données
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
	from scapy.layers.l2 import Ether
	from scapy.layers.inet import IP, UDP
	
	# Mock DB pour test
	class MockDB:
		def wrData(self, table, data):
			print(f"   [DB -> {table}] INSERT: {data.get('ip_src')} -> {data.get('ip_dst')}")
		def initDB(self): 
			print("   [DB] Init v1, v2 & v3 tables")
		def close(self): pass

	print("\n--- [TEST] Analyser avec support SNMPv3 ---")

	fake_config = {
		"filtres": {},
		"whiteList": {
			"IPs": ["10.0.0.1", "8.8.8.8"],
			"MACs": [], "PORTs": [], "OIDs": [],
			"USM_Users": ["admin", "monitoring"]
		}
	}

	analyser = Analyser(Queue(), MockDB(), config=fake_config, pcap_dir="test_cap")
	print("[+] Analyser initialisé avec support SNMPv1/v2c/v3")