from scapy.all import *
from scapy.layers.l2 import Ether, CookedLinux
from scapy.layers.snmp import SNMP
from scapy.layers.inet import IP, UDP
from datetime import datetime
import string  # Nécessaire pour nettoyer le username

class GetPaquetInfo(object):

    def convert_asn1(self, field):
        if field is None: return None
        if hasattr(field, 'val'): 
            val = field.val
        else:
            val = field
        
        # Si c'est des bytes, on décode en utf-8 proprement
        if isinstance(val, bytes):
            try: return val.decode('utf-8')
            except: return str(val) # Fallback si binaire pur
            
        return str(val)

    def packet_info(self, pkt):
        # --- 1. Timestamp ---
        try:
            time_stamp = datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S.%f")
        except:
            time_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        # --- 2. MAC / IP / Ports ---
        mac_src, mac_dst = None, None
        ip_src, ip_dst = None, None
        port_src, port_dst = None, None

        # MAC
        if Ether in pkt:
            mac_src = pkt[Ether].src
            mac_dst = pkt[Ether].dst
        elif CookedLinux in pkt:
            try: mac_src = str(pkt[CookedLinux].src)
            except: pass

        # IP
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

        # PORT (Conversion int sécurisée)
        if UDP in pkt:
            try: port_src = int(pkt[UDP].sport)
            except: port_src = 0
            try: port_dst = int(pkt[UDP].dport)
            except: port_dst = 0

        # --- 3. Init Dictionnaire Résultat ---
        res = {
            "time_stamp": time_stamp,
            "mac_src": mac_src, "mac_dst": mac_dst,
            "ip_src": ip_src, "ip_dst": ip_dst,
            "port_src": port_src, "port_dst": port_dst,
            "snmp_oidsValues": [],
            "snmp_version": None, 
            "snmp_community": None, 
            "snmp_pdu_type": None,
            "snmp_request_id": None, "snmp_error_status": None, "snmp_error_index": None,
            "snmp_enterprise": None, "snmp_agent_addr": None, 
            "snmp_generic_trap": None, "snmp_specific_trap": None,
            "snmp_non_repeaters": None, "snmp_max_repetitions": None,
            "snmp_context_engine_id": None, "snmp_context_name": None,
            "snmp_security_model": None, "snmp_security_level": None
        }

        # ==============================================================================
        # LOGIQUE DE DÉCODAGE HYBRIDE (SCAPY + MANUEL)
        # ==============================================================================
        snmp_layer = None
        is_manual_v3 = False 

        # Cas 1 : Scapy a déjà reconnu le SNMP (rare pour le V3 non configuré)
        if SNMP in pkt:
            snmp_layer = pkt[SNMP]
        
        # Cas 2 : UDP + Raw -> On force l'analyse
        elif UDP in pkt and Raw in pkt:
            if port_src in [161, 162] or port_dst in [161, 162]:
                raw_data = pkt[Raw].load
                
                # A. Tentative avec Scapy Standard
                try:
                    snmp_layer = SNMP(raw_data)
                    # Si Scapy plante sur la structure V3, il lèvera une exception ici
                    # et on passera dans le bloc 'except'
                except Exception:
                    # B. ECHEC SCAPY -> ANALYSE MANUELLE V3
                    # Signature V3 ASN.1 : Version(0x02) Len(0x01) Val(0x03)
                    if b'\x02\x01\x03' in raw_data[:20]:
                        is_manual_v3 = True
                        res["snmp_version"] = 3
                        res["snmp_pdu_type"] = "SNMPv3_Frame"
                        res["snmp_community"] = "<Encrypted>"
                        
                        # Extraction améliorée du Username
                        # Le username se trouve souvent après une séquence [0x04 + Len] (Octet String)
                        # On cherche les chaînes lisibles d'au moins 4 caractères
                        try:
                            clean_chars = []
                            for byte in raw_data:
                                if 32 <= byte <= 126: # ASCII imprimable
                                    clean_chars.append(chr(byte))
                                else:
                                    clean_chars.append('.') 
                            
                            txt_dump = "".join(clean_chars)
                            parts = [p for p in txt_dump.split('.') if len(p) >= 4]

                            # Filtrage plus intelligent
                            candidates = []
                            for p in parts:
                                # On rejette les chaines qui ressemblent à du bruit cryptographique
                                # (ex: trop courtes, caractères trop répétitifs, ou mots clés crypto)
                                if len(p) < 4: continue
                                if "HMAC" in p or "AES" in p or "DES" in p or "CBC" in p: continue
                                
                                # Le username est souvent au début du paquet, avant le gros bloc chiffré
                                candidates.append(p)

                            # On prend le candidat le plus probable (souvent le premier valide après les en-têtes)
                            if candidates:
                                # Le premier candidat est souvent le bon dans l'en-tête non chiffré
                                res["snmp_community"] = candidates[0]
                        except:
                            pass

        # ==============================================================================
        # EXTRACTION SI SCAPY A RÉUSSI (V1 / V2 / V3 non chiffré)
        # ==============================================================================
        if snmp_layer and not is_manual_v3:
            try:
                raw_version = self.convert_asn1(snmp_layer.version)
                res["snmp_version"] = raw_version
            except:
                res["snmp_version"] = None

            # V1 & V2
            if str(raw_version) in ["0", "1"]: 
                if hasattr(snmp_layer, "community"):
                    res["snmp_community"] = self.convert_asn1(snmp_layer.community)
            
            # V3 (Si Scapy a réussi nativement)
            elif str(raw_version) == "3":
                res["snmp_pdu_type"] = "SNMPv3_Frame"
                res["snmp_community"] = "<Encrypted>"

            # PDU extraction
            if hasattr(snmp_layer, "PDU") and snmp_layer.PDU:
                pdu = snmp_layer.PDU
                res["snmp_pdu_type"] = pdu.__class__.__name__

                if res["snmp_pdu_type"] == "SNMPtrap":
                    res["snmp_enterprise"] = self.convert_asn1(pdu.enterprise)
                    res["snmp_agent_addr"] = self.convert_asn1(pdu.agent_addr)
                    res["snmp_generic_trap"] = int(self.convert_asn1(pdu.generic_trap))
                    res["snmp_specific_trap"] = int(self.convert_asn1(pdu.specific_trap))
                elif res["snmp_pdu_type"] == "SNMPbulk":
                    res["snmp_request_id"] = self.convert_asn1(pdu.id)
                    res["snmp_non_repeaters"] = self.convert_asn1(pdu.non_repeaters)
                    res["snmp_max_repetitions"] = self.convert_asn1(pdu.max_repetitions)
                else:
                    if hasattr(pdu, "id"): res["snmp_request_id"] = self.convert_asn1(pdu.id)
                    if hasattr(pdu, "error_status"): 
                        val = self.convert_asn1(pdu.error_status)
                        res["snmp_error_status"] = int(val) if val is not None else 0
                    if hasattr(pdu, "error_index"): 
                        val = self.convert_asn1(pdu.error_index)
                        res["snmp_error_index"] = int(val) if val is not None else 0

                if hasattr(pdu, "varbindlist"):
                    for elt in pdu.varbindlist:
                        oid_str = ""
                        val_str = ""
                        if hasattr(elt, "oid"): oid_str = self.convert_asn1(elt.oid)
                        if hasattr(elt, "value"):
                            val = elt.value
                            if hasattr(val, "prettyPrint"): val_str = val.prettyPrint()
                            else: val_str = str(val)
                        res["snmp_oidsValues"].append({"oid": oid_str, "value": val_str})
            
        return res