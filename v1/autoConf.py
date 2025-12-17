import os
import sys
from scapy.all import sniff, SNMP
import paquetInfo
import confAPP

class AutoConfigGenerator:
	def __init__(self, conf_file="conf.json"):
		self.conf_manager = confAPP.ConfAPP(conf_file)
		self.parser = paquetInfo.GetPaquetInfo()
		self.unique_flows = set()
		self.captured_count = 0

	def clean_port(self, port):
		"""
		Nettoie les ports éphémères (>1024) pour créer des wildcards.
		"""
		if not port: return ""
		try:
			p = int(port)
			# On garde les ports standards SNMP et les ports systèmes (<1024)
			if p in [161, 162] or p <= 1024:
				return str(p)
			return ""
		except:
			return ""

	def clean_str(self, val):
		"""
		Convertit en string, mais retourne "" si la valeur est None ou 'None'.
		Indispensable pour que mac_src="None" devienne mac_src="" (wildcard).
		"""
		if val is None: return ""
		s = str(val)
		if s == "None": return ""
		return s

	def process_packet(self, pkt):
		data = self.parser.packet_info(pkt)

		if data.get("snmp_version") is None:
			return

		self.captured_count += 1
		print(f"\r[+] Paquets SNMP analysés: {self.captured_count}", end="", flush=True)

		# Nettoyage
		c_port_src = self.clean_port(data.get("port_src"))
		c_port_dst = self.clean_port(data.get("port_dst"))
		c_mac_src = self.clean_str(data.get("mac_src"))
		c_mac_dst = self.clean_str(data.get("mac_dst"))
		c_ip_src  = self.clean_str(data.get("ip_src"))
		c_ip_dst  = self.clean_str(data.get("ip_dst"))

		# AJOUT : On récupère la communauté (V1/V2) ou le User (V3)
		c_community = self.clean_str(data.get("snmp_community"))

		# On l'ajoute à la signature de base
		base_signature = (
			c_mac_src, c_mac_dst,
			c_ip_src, c_ip_dst,
			c_port_src, c_port_dst,
			c_community)

		oids_list = data.get("snmp_oidsValues", [])

		if not oids_list:
			full_signature = base_signature + ("",)
			self.unique_flows.add(full_signature)
		else:
			for oid_entry in oids_list:
				oid_val = oid_entry.get("oid", "")
				full_signature = base_signature + (oid_val,)
				self.unique_flows.add(full_signature)

	def start_live_capture(self, duration):
		print(f"\n[i] Démarrage de l'apprentissage LIVE pour {duration} secondes...")
		try:
			sniff(
				filter="udp port 161 or udp port 162",
				timeout=duration,
				prn=self.process_packet,
				store=0
			)
		except KeyboardInterrupt:
			print("\n[!] Arrêt manuel.")
		self.finish()

	def start_pcap_analysis(self, pcap_path):
		if not os.path.exists(pcap_path):
			print(f"[!] Erreur : Le fichier '{pcap_path}' n'existe pas.")
			return

		print(f"\n[i] Analyse du fichier '{pcap_path}' en cours...")
		try:
			sniff(
				offline=pcap_path,
				filter="udp port 161 or udp port 162",
				prn=self.process_packet,
				store=0
			)
		except Exception as e:
			print(f"\n[!] Erreur lors de la lecture du PCAP : {e}")
		self.finish()

	def finish(self):
		print(f"\n\n[i] Analyse terminée. {len(self.unique_flows)} règles uniques générées.")
		self.save_rules()

	def save_rules(self):
		print("[i] Mise à jour de la configuration...")
		self.conf_manager.creatConf()
        
		new_filters = {}
		sorted_flows = sorted(list(self.unique_flows))

		for index, flow in enumerate(sorted_flows):
			rule_name = f"auto_rule_{index:03d}"
            
			# Mise à jour du dictionnaire avec snmp_community
			rule_content = {
				"mac_src": flow[0],
				"mac_dst": flow[1],
				"ip_src": flow[2],
				"ip_dst": flow[3],
				"port_src": flow[4],
				"port_dst": flow[5],
				"snmp_community": flow[6],
				"snmp_oidsValues": flow[7]}
            
			rule_content = {k: v for k, v in rule_content.items() if v != ""}
			new_filters[rule_name] = rule_content

		if self.conf_manager.config is None:
			self.conf_manager.load_config()
            
		self.conf_manager.config["filtres"] = new_filters
		self.conf_manager._save()
		print(f"[OK] Configuration sauvegardée dans '{self.conf_manager.confFile}'")

if __name__ == "__main__":
	print("=== GÉNÉRATEUR AUTOMATIQUE DE RÈGLES SNMP ===")
	print("1. Apprentissage Live (Écoute réseau)")
	print("2. Apprentissage depuis un fichier PCAP")
	
	choice = input("Votre choix (1 ou 2) : ").strip()
	
	generator = AutoConfigGenerator()

	if choice == "1":
		try:
			dur = int(input("Durée d'écoute (secondes) : "))
			generator.start_live_capture(dur)
		except ValueError:
			print("Erreur : Entrez un nombre entier.")
			
	elif choice == "2":
		path = input("Chemin du fichier PCAP (ex: captures/test.pcap) : ").strip()
		generator.start_pcap_analysis(path)
		
	else:
		print("Choix invalide.")