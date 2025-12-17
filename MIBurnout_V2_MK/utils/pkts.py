#!/usr/bin/env python3
"""
pkts.py - Générateur de paquets SNMP de test
Permet de créer des paquets SNMP v1, v2c et v3 pour les tests.

Usage:
    from utils.pkts import create_snmp_get, create_snmp_response
    
    pkt = create_snmp_get("192.168.1.1", "192.168.1.2", "public", "1.3.6.1.2.1.1.1.0")
    sendp(pkt, iface="eth0")
"""

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind


# =============================================================================
# CONSTANTES PAR DÉFAUT
# =============================================================================

DEFAULT_TTL = 64
SNMP_PORT = 161
TRAP_PORT = 162


# =============================================================================
# GÉNÉRATEURS DE PAQUETS SNMP V2C
# =============================================================================

def create_snmp_get(
    src_ip: str,
    dst_ip: str,
    community: str = "public",
    oid: str = "1.3.6.1.2.1.1.1.0",
    src_mac: str = None,
    dst_mac: str = None,
    src_port: int = None,
    request_id: int = None
) -> Ether:
    """
    Crée un paquet SNMP GET Request.
    
    Args:
        src_ip: IP source
        dst_ip: IP destination
        community: Community string (défaut: "public")
        oid: OID à interroger
        src_mac: MAC source (auto-générée si None)
        dst_mac: MAC destination (broadcast si None)
        src_port: Port source (aléatoire si None)
        request_id: ID de requête (aléatoire si None)
    
    Returns:
        Paquet Scapy prêt à être envoyé
    """
    import random
    
    src_mac = src_mac or RandMAC()
    dst_mac = dst_mac or "ff:ff:ff:ff:ff:ff"
    src_port = src_port or random.randint(49152, 65535)
    request_id = request_id or random.randint(1, 2**31)
    
    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip, ttl=DEFAULT_TTL) /
        UDP(sport=src_port, dport=SNMP_PORT) /
        SNMP(
            version='v2c',
            community=ASN1_STRING(community.encode()),
            PDU=SNMPget(
                id=request_id,
                varbindlist=[
                    SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL(0))
                ]
            )
        )
    )
    return pkt


def create_snmp_response(
    src_ip: str,
    dst_ip: str,
    community: str = "public",
    oid: str = "1.3.6.1.2.1.1.1.0",
    value: str = "Test Response",
    src_mac: str = None,
    dst_mac: str = None,
    request_id: int = None
) -> Ether:
    """
    Crée un paquet SNMP Response.
    
    Args:
        src_ip: IP source (agent SNMP)
        dst_ip: IP destination (manager)
        community: Community string
        oid: OID de la réponse
        value: Valeur de la réponse
        src_mac: MAC source
        dst_mac: MAC destination
        request_id: ID de requête
    
    Returns:
        Paquet Scapy prêt à être envoyé
    """
    import random
    
    src_mac = src_mac or RandMAC()
    dst_mac = dst_mac or RandMAC()
    request_id = request_id or random.randint(1, 2**31)
    
    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip, ttl=DEFAULT_TTL) /
        UDP(sport=SNMP_PORT, dport=random.randint(49152, 65535)) /
        SNMP(
            version='v2c',
            community=ASN1_STRING(community.encode()),
            PDU=SNMPresponse(
                id=request_id,
                varbindlist=[
                    SNMPvarbind(
                        oid=ASN1_OID(oid), 
                        value=ASN1_STRING(value.encode() if isinstance(value, str) else value)
                    )
                ]
            )
        )
    )
    return pkt


def create_snmp_bulk(
    src_ip: str,
    dst_ip: str,
    community: str = "public",
    oid: str = "1.3.6.1.2.1.1",
    src_mac: str = None,
    dst_mac: str = None,
    non_repeaters: int = 0,
    max_repetitions: int = 10
) -> Ether:
    """
    Crée un paquet SNMP GET-BULK (v2c).
    """
    from scapy.layers.snmp import SNMPbulk
    import random
    
    src_mac = src_mac or RandMAC()
    dst_mac = dst_mac or "ff:ff:ff:ff:ff:ff"
    
    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip, ttl=DEFAULT_TTL) /
        UDP(sport=random.randint(49152, 65535), dport=SNMP_PORT) /
        SNMP(
            version='v2c',
            community=ASN1_STRING(community.encode()),
            PDU=SNMPbulk(
                id=random.randint(1, 2**31),
                non_repeaters=non_repeaters,
                max_repetitions=max_repetitions,
                varbindlist=[
                    SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL(0))
                ]
            )
        )
    )
    return pkt


# =============================================================================
# GÉNÉRATEUR DE FLUX DE TEST
# =============================================================================

def generate_test_traffic(
    count: int = 10,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.1"
) -> list:
    """
    Génère une liste de paquets SNMP de test.
    
    Args:
        count: Nombre de paquets à générer
        src_ip: IP source
        dst_ip: IP destination
    
    Returns:
        Liste de paquets Scapy
    """
    packets = []
    oids = [
        "1.3.6.1.2.1.1.1.0",  # sysDescr
        "1.3.6.1.2.1.1.3.0",  # sysUpTime
        "1.3.6.1.2.1.1.5.0",  # sysName
        "1.3.6.1.2.1.1.6.0",  # sysLocation
        "1.3.6.1.2.1.2.1.0",  # ifNumber
    ]
    
    for i in range(count):
        oid = oids[i % len(oids)]
        
        # Alterner GET et Response
        if i % 2 == 0:
            pkt = create_snmp_get(src_ip, dst_ip, oid=oid)
        else:
            pkt = create_snmp_response(dst_ip, src_ip, oid=oid, value=f"Value_{i}")
        
        packets.append(pkt)
    
    return packets


def save_test_pcap(filename: str = "test_traffic.pcap", count: int = 100):
    """
    Génère et sauvegarde un fichier PCAP de test.
    """
    packets = generate_test_traffic(count)
    wrpcap(filename, packets)
    print(f"[+] Fichier PCAP créé: {filename} ({count} paquets)")


# =============================================================================
# EXEMPLES PRÉDÉFINIS
# =============================================================================

# Exemple 1: GET sysDescr
EXAMPLE_GET = create_snmp_get(
    src_ip="10.204.0.196",
    dst_ip="10.204.0.153",
    community="public",
    oid="1.3.6.1.2.1.1.1.0"
)

# Exemple 2: Response sysDescr
EXAMPLE_RESPONSE = create_snmp_response(
    src_ip="10.204.0.153",
    dst_ip="10.204.0.196",
    community="public",
    oid="1.3.6.1.2.1.1.1.0",
    value="Linux debianSNMP-server 6.12.48"
)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  Générateur de paquets SNMP de test")
    print("=" * 50)
    
    print("\n[1] Afficher un paquet GET")
    EXAMPLE_GET.show()
    
    print("\n[2] Afficher un paquet Response")
    EXAMPLE_RESPONSE.show()
    
    print("\n[3] Générer un fichier PCAP de test")
    save_test_pcap("test_snmp_traffic.pcap", 50)
