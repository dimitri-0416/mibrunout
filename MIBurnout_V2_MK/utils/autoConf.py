#!/usr/bin/env python3
"""
autoConf.py - Générateur automatique de règles SNMP
Analyse le trafic réseau (live ou PCAP) et génère des règles de filtrage.

Usage:
    python autoConf.py
    
Puis choisir:
    1. Apprentissage Live (écoute réseau)
    2. Apprentissage depuis un fichier PCAP
"""

import os
import sys

# Ajout du chemin parent pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff, SNMP, Raw, UDP, IP, Ether
from core.confAPP import ConfAPP


class AutoConfigGenerator:
    """Génère automatiquement des règles de filtrage SNMP."""
    
    def __init__(self, conf_file="config/conf.json"):
        self.conf_manager = ConfAPP(conf_file)
        self.unique_flows = set()
        self.captured_count = 0

    def clean_port(self, port):
        """Nettoie les ports éphémères pour créer des wildcards."""
        if not port:
            return ""
        try:
            p = int(port)
            # Garder les ports SNMP standards et système
            if p in [161, 162] or p <= 1024:
                return str(p)
            return ""
        except:
            return ""

    def clean_str(self, val):
        """Convertit en string, retourne '' si None."""
        if val is None:
            return ""
        s = str(val)
        if s == "None":
            return ""
        return s

    def extract_snmp_info(self, pkt):
        """Extrait les informations SNMP d'un paquet."""
        result = {
            "mac_src": None, "mac_dst": None,
            "ip_src": None, "ip_dst": None,
            "port_src": None, "port_dst": None,
            "snmp_version": None,
            "snmp_community": None,
            "snmp_oidsValues": []
        }
        
        # Couche Ethernet
        if Ether in pkt:
            result["mac_src"] = pkt[Ether].src
            result["mac_dst"] = pkt[Ether].dst
        
        # Couche IP
        if IP in pkt:
            result["ip_src"] = pkt[IP].src
            result["ip_dst"] = pkt[IP].dst
        
        # Couche UDP
        if UDP in pkt:
            result["port_src"] = pkt[UDP].sport
            result["port_dst"] = pkt[UDP].dport
        
        # Couche SNMP
        if SNMP in pkt:
            snmp = pkt[SNMP]
            
            # Version
            if hasattr(snmp, 'version'):
                ver = snmp.version
                if hasattr(ver, 'val'):
                    result["snmp_version"] = ver.val
                else:
                    result["snmp_version"] = int(ver)
            
            # Community (V1/V2c)
            if hasattr(snmp, 'community'):
                comm = snmp.community
                if hasattr(comm, 'val'):
                    result["snmp_community"] = comm.val.decode() if isinstance(comm.val, bytes) else str(comm.val)
                else:
                    result["snmp_community"] = str(comm)
            
            # OIDs
            if hasattr(snmp, 'PDU') and snmp.PDU:
                pdu = snmp.PDU
                if hasattr(pdu, 'varbindlist'):
                    for vb in pdu.varbindlist:
                        if hasattr(vb, 'oid'):
                            oid = vb.oid
                            if hasattr(oid, 'val'):
                                result["snmp_oidsValues"].append(str(oid.val))
                            else:
                                result["snmp_oidsValues"].append(str(oid))
        
        # Tentative SNMPv3 (Raw)
        elif UDP in pkt and Raw in pkt:
            port_src = pkt[UDP].sport
            port_dst = pkt[UDP].dport
            if port_src in [161, 162] or port_dst in [161, 162]:
                raw_data = pkt[Raw].load
                # Signature V3: version = 3
                if b'\x02\x01\x03' in raw_data[:20]:
                    result["snmp_version"] = 3
                    # Tentative d'extraction du username
                    try:
                        for i, b in enumerate(raw_data):
                            if 32 <= b <= 126:
                                pass  # ASCII
                    except:
                        pass
        
        return result

    def process_packet(self, pkt):
        """Traite un paquet capturé."""
        data = self.extract_snmp_info(pkt)

        if data.get("snmp_version") is None:
            return

        self.captured_count += 1
        print(f"\r[+] Paquets SNMP analysés: {self.captured_count}", end="", flush=True)

        # Nettoyage des valeurs
        signature_base = (
            self.clean_str(data.get("mac_src")),
            self.clean_str(data.get("mac_dst")),
            self.clean_str(data.get("ip_src")),
            self.clean_str(data.get("ip_dst")),
            self.clean_port(data.get("port_src")),
            self.clean_port(data.get("port_dst")),
            self.clean_str(data.get("snmp_community"))
        )

        oids_list = data.get("snmp_oidsValues", [])

        if not oids_list:
            full_signature = signature_base + ("",)
            self.unique_flows.add(full_signature)
        else:
            for oid in oids_list:
                full_signature = signature_base + (oid,)
                self.unique_flows.add(full_signature)

    def start_live_capture(self, duration, interface=None):
        """Démarre la capture live."""
        print(f"\n[i] Apprentissage LIVE pour {duration} secondes...")
        if interface:
            print(f"[i] Interface: {interface}")
        
        try:
            sniff(
                iface=interface,
                filter="udp port 161 or udp port 162",
                timeout=duration,
                prn=self.process_packet,
                store=0
            )
        except KeyboardInterrupt:
            print("\n[!] Arrêt manuel.")
        except Exception as e:
            print(f"\n[!] Erreur: {e}")
        
        self.finish()

    def start_pcap_analysis(self, pcap_path):
        """Analyse un fichier PCAP."""
        if not os.path.exists(pcap_path):
            print(f"[!] Le fichier '{pcap_path}' n'existe pas.")
            return

        print(f"\n[i] Analyse du fichier '{pcap_path}'...")
        try:
            sniff(
                offline=pcap_path,
                filter="udp port 161 or udp port 162",
                prn=self.process_packet,
                store=0
            )
        except Exception as e:
            print(f"\n[!] Erreur: {e}")
        
        self.finish()

    def finish(self):
        """Finalise l'apprentissage."""
        print(f"\n\n[i] Terminé. {len(self.unique_flows)} règles uniques générées.")
        self.save_rules()

    def save_rules(self):
        """Sauvegarde les règles dans la configuration."""
        print("[i] Mise à jour de la configuration...")
        
        # Créer la config si elle n'existe pas
        if self.conf_manager.config is None:
            self.conf_manager.creatConf()
        
        new_filters = {}
        sorted_flows = sorted(list(self.unique_flows))

        for index, flow in enumerate(sorted_flows):
            rule_name = f"auto_rule_{index:03d}"
            
            rule_content = {
                "mac_src": flow[0],
                "mac_dst": flow[1],
                "ip_src": flow[2],
                "ip_dst": flow[3],
                "port_src": flow[4],
                "port_dst": flow[5],
                "snmp_community": flow[6],
                "snmp_oidsValues": flow[7]
            }
            
            # Retirer les champs vides
            rule_content = {k: v for k, v in rule_content.items() if v != ""}
            new_filters[rule_name] = rule_content

        self.conf_manager.config["filtres"] = new_filters
        self.conf_manager._save()
        print(f"[OK] Configuration sauvegardée dans '{self.conf_manager.confFile}'")


def main():
    """Point d'entrée principal."""
    print("=" * 50)
    print("  GÉNÉRATEUR AUTOMATIQUE DE RÈGLES SNMP")
    print("=" * 50)
    print("\n1. Apprentissage Live (Écoute réseau)")
    print("2. Apprentissage depuis un fichier PCAP")
    print("0. Quitter")
    
    choice = input("\nVotre choix: ").strip()
    
    generator = AutoConfigGenerator()

    if choice == "1":
        try:
            iface = input("Interface (laisser vide pour défaut): ").strip() or None
            dur = int(input("Durée d'écoute (secondes): "))
            generator.start_live_capture(dur, iface)
        except ValueError:
            print("Erreur: Entrez un nombre entier.")
            
    elif choice == "2":
        path = input("Chemin du fichier PCAP: ").strip()
        generator.start_pcap_analysis(path)
        
    elif choice == "0":
        print("Au revoir.")
    else:
        print("Choix invalide.")


if __name__ == "__main__":
    main()
