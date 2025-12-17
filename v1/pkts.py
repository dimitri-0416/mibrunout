from scapy.all import *


# ----------------------------------------------------
# SNMP GET
# ----------------------------------------------------

TARGET_MAC = "08:00:27:9f:b6:c7"
SOURCE_MAC = "d4:93:90:43:0b:ff"
SOURCE_IP = "10.204.0.196"
TARGET_IP = "10.204.0.153"
SOURCE_PORT = 50096
OID_TO_QUERY = '.1.3.6.1.2.1.1.1.0'
ID_TRANSACTION = 361124149
TTL = 64

# ----------------------------------------------------
# 1. Construction du Paquet de Requête (SNMPget)
# ----------------------------------------------------
pkt1 = (
    Ether(dst=TARGET_MAC, src=SOURCE_MAC) /
    IP(src=SOURCE_IP, dst=TARGET_IP, flags="DF", id=24174, ttl=TTL) /
    UDP(sport=SOURCE_PORT, dport=161) / # SNMP standard port 161
    SNMP(
        version='v2c',
        community=ASN1_STRING(b'public'),
        PDU=SNMPget(
            id=ID_TRANSACTION,
            varbindlist=[
                SNMPvarbind(oid=ASN1_OID(OID_TO_QUERY), value=ASN1_NULL(0))
            ]
        )
    )
)

# ----------------------------------------------------
# 2. Construction du Paquet de Réponse (SNMPresponse)
# ----------------------------------------------------
RESPONSE_ID = 43454
RESPONSE_VALUE = b'Linux debianSNMP-server 6.12.48+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (2025-09-20) x86_64'

pkt1_rep = (
    Ether(dst=SOURCE_MAC, src=TARGET_MAC) / # MAC inversées
    IP(src=TARGET_IP, dst=SOURCE_IP, flags="DF", id=RESPONSE_ID, ttl=TTL) / # IP inversées
    UDP(sport=161, dport=SOURCE_PORT) / # Ports inversés
    SNMP(
        version='v2c',
        community=ASN1_STRING(b'public'),
        PDU=SNMPresponse(
            id=ID_TRANSACTION,
            varbindlist=[
                # Utilisation de ASN1_STRING pour contourner l'erreur ASN1_OCTET_STRING
                SNMPvarbind(oid=ASN1_OID(OID_TO_QUERY), value=ASN1_STRING(RESPONSE_VALUE))
            ]
        )
    )
)