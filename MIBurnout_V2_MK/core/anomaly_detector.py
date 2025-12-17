#!/usr/bin/env python3
"""
MIBurnout Suite V1 - Module de Detection d'Anomalies Avance
============================================================
Detection en temps reel des comportements anormaux dans le trafic SNMP.

Anomalies detectees:
- FLOOD: Trop de paquets par seconde depuis une source
- SCAN: Detection de balayage reseau (GetNext consecutifs)
- TRAP_STORM: Tempete de traps SNMP
- AUTH_FAILURE: Echecs d'authentification repetes
- COMMUNITY_ENUM: Tentative d'enumeration de communautes
- BRUTE_FORCE: Tentatives de connexion en masse
- SUSPICIOUS_OID: Acces a des OIDs sensibles
- ERROR_RATE: Taux d'erreur anormalement eleve
"""

import time
import threading
import logging
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json


class Severity(Enum):
    """Niveaux de severite des alertes"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AnomalyType(Enum):
    """Types d'anomalies detectees"""
    FLOOD = "FLOOD"
    NETWORK_SCAN = "NETWORK_SCAN"
    TRAP_STORM = "TRAP_STORM"
    AUTH_FAILURE = "AUTH_FAILURE"
    COMMUNITY_ENUM = "COMMUNITY_ENUM"
    BRUTE_FORCE = "BRUTE_FORCE"
    SUSPICIOUS_OID = "SUSPICIOUS_OID"
    ERROR_RATE = "ERROR_RATE"
    UNUSUAL_PORT = "UNUSUAL_PORT"
    LARGE_RESPONSE = "LARGE_RESPONSE"


@dataclass
class AnomalyAlert:
    """Structure d'une alerte d'anomalie"""
    id: str
    timestamp: str
    anomaly_type: str
    severity: str
    source_ip: str
    destination_ip: str
    message: str
    details: Dict = field(default_factory=dict)
    acknowledged: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "type": self.anomaly_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "message": self.message,
            "details": self.details,
            "acknowledged": self.acknowledged
        }
    
    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.anomaly_type}: {self.message}"


@dataclass
class IPProfile:
    """Profil comportemental d'une adresse IP"""
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    error_count: int = 0
    trap_count: int = 0
    getnext_count: int = 0
    getbulk_count: int = 0
    set_count: int = 0
    community_strings: Set[str] = field(default_factory=set)
    accessed_oids: Set[str] = field(default_factory=set)
    ports_used: Set[int] = field(default_factory=set)
    packet_timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))
    consecutive_errors: int = 0
    alert_count: int = 0
    is_blacklisted: bool = False
    reputation_score: float = 100.0  # 0-100, plus bas = plus suspect
    
    def update_reputation(self, delta: float):
        """Met a jour le score de reputation"""
        self.reputation_score = max(0, min(100, self.reputation_score + delta))
    
    def get_packets_per_second(self, window: float = 60.0) -> float:
        """Calcule le taux de paquets par seconde"""
        now = time.time()
        recent = [t for t in self.packet_timestamps if now - t < window]
        if len(recent) < 2:
            return 0.0
        return len(recent) / window
    
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "packet_count": self.packet_count,
            "error_count": self.error_count,
            "trap_count": self.trap_count,
            "community_strings_count": len(self.community_strings),
            "reputation_score": round(self.reputation_score, 2),
            "packets_per_second": round(self.get_packets_per_second(), 2),
            "is_blacklisted": self.is_blacklisted,
            "alert_count": self.alert_count
        }


class AnomalyDetector:
    """
    Detecteur d'anomalies avance pour le trafic SNMP.
    Utilise l'analyse comportementale et des seuils adaptatifs.
    """
    
    # OIDs sensibles a surveiller
    SENSITIVE_OIDS = {
        "1.3.6.1.2.1.1.1": "sysDescr",
        "1.3.6.1.2.1.1.5": "sysName",
        "1.3.6.1.4.1": "enterprises",
        "1.3.6.1.2.1.4.20": "ipAddrTable",
        "1.3.6.1.2.1.4.21": "ipRouteTable",
        "1.3.6.1.2.1.6.13": "tcpConnTable",
        "1.3.6.1.2.1.25.4": "hrSWRunTable",
    }
    
    def __init__(self, config: Dict = None):
        """
        Initialise le detecteur d'anomalies.
        
        Args:
            config: Configuration personnalisee des seuils
        """
        self.config = config or {}
        self._setup_logging()
        
        # Seuils de detection (configurables)
        self.thresholds = {
            # Flood detection
            "packets_per_second_warning": 50,
            "packets_per_second_critical": 100,
            "packets_per_minute_max": 3000,
            
            # Scan detection
            "getnext_threshold": 30,
            "getbulk_threshold": 20,
            "oid_access_threshold": 50,
            
            # Trap detection
            "trap_per_minute_warning": 30,
            "trap_per_minute_critical": 100,
            
            # Auth detection
            "auth_failure_threshold": 5,
            "community_enum_threshold": 3,
            
            # Error detection
            "error_rate_warning": 10,  # %
            "error_rate_critical": 25,  # %
            "consecutive_errors_threshold": 10,
            
            # Reputation
            "reputation_blacklist_threshold": 20,
            
            # Time windows
            "analysis_window_seconds": 60,
            "cleanup_interval_seconds": 300,
        }
        self.thresholds.update(self.config.get("thresholds", {}))
        
        # Stockage des donnees
        self.ip_profiles: Dict[str, IPProfile] = {}
        self.alerts: List[AnomalyAlert] = []
        self.alert_history: deque = deque(maxlen=10000)
        
        # Statistiques globales
        self.stats = {
            "total_packets_analyzed": 0,
            "total_alerts_generated": 0,
            "alerts_by_type": defaultdict(int),
            "alerts_by_severity": defaultdict(int),
            "blocked_ips": set(),
            "start_time": time.time(),
        }
        
        # Thread safety
        self._lock = threading.RLock()
        self._alert_counter = 0
        
        # Demarrer le nettoyage periodique
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        
        self.logger.info("Detecteur d'anomalies initialise")
    
    def _setup_logging(self):
        """Configure le logging"""
        self.logger = logging.getLogger("AnomalyDetector")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '[%(asctime)s] %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _generate_alert_id(self) -> str:
        """Genere un ID unique pour une alerte"""
        self._alert_counter += 1
        return f"ALERT-{int(time.time())}-{self._alert_counter:06d}"
    
    def _get_or_create_profile(self, ip: str) -> IPProfile:
        """Recupere ou cree un profil IP"""
        if ip not in self.ip_profiles:
            self.ip_profiles[ip] = IPProfile(ip=ip)
        return self.ip_profiles[ip]
    
    def _create_alert(self, anomaly_type: AnomalyType, severity: Severity,
                      source_ip: str, dest_ip: str, message: str,
                      details: Dict = None) -> AnomalyAlert:
        """Cree une nouvelle alerte"""
        alert = AnomalyAlert(
            id=self._generate_alert_id(),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            anomaly_type=anomaly_type.value,
            severity=severity.value,
            source_ip=source_ip,
            destination_ip=dest_ip,
            message=message,
            details=details or {}
        )
        
        with self._lock:
            self.alerts.append(alert)
            self.alert_history.append(alert)
            self.stats["total_alerts_generated"] += 1
            self.stats["alerts_by_type"][anomaly_type.value] += 1
            self.stats["alerts_by_severity"][severity.value] += 1
            
            # Mettre a jour le profil
            profile = self._get_or_create_profile(source_ip)
            profile.alert_count += 1
        
        self.logger.warning(str(alert))
        return alert
    
    def analyze_packet(self, packet_data: Dict) -> List[AnomalyAlert]:
        """
        Analyse un paquet et detecte les anomalies.
        
        Args:
            packet_data: Dictionnaire contenant les donnees du paquet
            
        Returns:
            Liste des alertes generees
        """
        alerts = []
        
        with self._lock:
            self.stats["total_packets_analyzed"] += 1
        
        # Extraction des donnees
        ip_src = packet_data.get("ip_src", "unknown")
        ip_dst = packet_data.get("ip_dst", "unknown")
        pdu_type = str(packet_data.get("snmp_pdu_type", "")).lower()
        community = packet_data.get("snmp_community", "")
        error_status = packet_data.get("snmp_error_status")
        port_src = packet_data.get("port_src", 0)
        port_dst = packet_data.get("port_dst", 0)
        oids = packet_data.get("snmp_oidsValues", [])
        
        # Mettre a jour le profil IP
        profile = self._get_or_create_profile(ip_src)
        profile.last_seen = time.time()
        profile.packet_count += 1
        profile.packet_timestamps.append(time.time())
        
        if community:
            profile.community_strings.add(community)
        
        if port_src:
            profile.ports_used.add(port_src)
        
        # Extraire les OIDs accedes
        if isinstance(oids, list):
            for oid_entry in oids:
                if isinstance(oid_entry, dict):
                    oid = oid_entry.get("oid", "")
                    if oid:
                        profile.accessed_oids.add(oid)
        
        # Verifier si IP blacklistee
        if profile.is_blacklisted:
            return alerts  # Ignorer les paquets des IPs blacklistees
        
        # === DETECTION DES ANOMALIES ===
        
        # 1. Detection de flood
        flood_alerts = self._detect_flood(profile, ip_src, ip_dst)
        alerts.extend(flood_alerts)
        
        # 2. Detection de scan reseau
        if "getnext" in pdu_type:
            profile.getnext_count += 1
            scan_alerts = self._detect_scan(profile, ip_src, ip_dst)
            alerts.extend(scan_alerts)
        
        if "bulk" in pdu_type:
            profile.getbulk_count += 1
        
        # 3. Detection de tempete de traps
        if "trap" in pdu_type:
            profile.trap_count += 1
            trap_alerts = self._detect_trap_storm(profile, ip_src, ip_dst)
            alerts.extend(trap_alerts)
        
        # 4. Detection d'erreurs
        if error_status and str(error_status) != "0":
            profile.error_count += 1
            profile.consecutive_errors += 1
            error_alerts = self._detect_errors(profile, ip_src, ip_dst, error_status)
            alerts.extend(error_alerts)
        else:
            profile.consecutive_errors = 0
        
        # 5. Detection d'enumeration de communautes
        if len(profile.community_strings) > 1:
            enum_alerts = self._detect_community_enum(profile, ip_src, ip_dst)
            alerts.extend(enum_alerts)
        
        # 6. Detection d'acces aux OIDs sensibles
        oid_alerts = self._detect_suspicious_oids(profile, ip_src, ip_dst, oids)
        alerts.extend(oid_alerts)
        
        # 7. Detection de SET (modifications)
        if "set" in pdu_type:
            profile.set_count += 1
            if profile.set_count > 10:
                alert = self._create_alert(
                    AnomalyType.SUSPICIOUS_OID,
                    Severity.WARNING,
                    ip_src, ip_dst,
                    f"Nombreuses requetes SET depuis {ip_src} ({profile.set_count})",
                    {"set_count": profile.set_count}
                )
                alerts.append(alert)
                profile.update_reputation(-5)
        
        # 8. Verifier le score de reputation
        if profile.reputation_score < self.thresholds["reputation_blacklist_threshold"]:
            if not profile.is_blacklisted:
                profile.is_blacklisted = True
                self.stats["blocked_ips"].add(ip_src)
                alert = self._create_alert(
                    AnomalyType.BRUTE_FORCE,
                    Severity.EMERGENCY,
                    ip_src, ip_dst,
                    f"IP {ip_src} blacklistee (reputation: {profile.reputation_score:.1f})",
                    {"reputation": profile.reputation_score}
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_flood(self, profile: IPProfile, ip_src: str, ip_dst: str) -> List[AnomalyAlert]:
        """Detecte les attaques par flood"""
        alerts = []
        pps = profile.get_packets_per_second()
        
        if pps > self.thresholds["packets_per_second_critical"]:
            alert = self._create_alert(
                AnomalyType.FLOOD,
                Severity.CRITICAL,
                ip_src, ip_dst,
                f"FLOOD CRITIQUE: {pps:.1f} paquets/sec depuis {ip_src}",
                {"packets_per_second": pps, "threshold": self.thresholds["packets_per_second_critical"]}
            )
            alerts.append(alert)
            profile.update_reputation(-20)
            
        elif pps > self.thresholds["packets_per_second_warning"]:
            alert = self._create_alert(
                AnomalyType.FLOOD,
                Severity.WARNING,
                ip_src, ip_dst,
                f"Flood detecte: {pps:.1f} paquets/sec depuis {ip_src}",
                {"packets_per_second": pps}
            )
            alerts.append(alert)
            profile.update_reputation(-5)
        
        return alerts
    
    def _detect_scan(self, profile: IPProfile, ip_src: str, ip_dst: str) -> List[AnomalyAlert]:
        """Detecte les scans reseau"""
        alerts = []
        
        if profile.getnext_count > self.thresholds["getnext_threshold"]:
            # Eviter les alertes repetees
            if profile.getnext_count % 50 == 0:
                alert = self._create_alert(
                    AnomalyType.NETWORK_SCAN,
                    Severity.WARNING,
                    ip_src, ip_dst,
                    f"Scan reseau detecte: {profile.getnext_count} GetNext depuis {ip_src}",
                    {"getnext_count": profile.getnext_count, "oids_accessed": len(profile.accessed_oids)}
                )
                alerts.append(alert)
                profile.update_reputation(-10)
        
        return alerts
    
    def _detect_trap_storm(self, profile: IPProfile, ip_src: str, ip_dst: str) -> List[AnomalyAlert]:
        """Detecte les tempetes de traps"""
        alerts = []
        
        if profile.trap_count > self.thresholds["trap_per_minute_critical"]:
            if profile.trap_count % 100 == 0:
                alert = self._create_alert(
                    AnomalyType.TRAP_STORM,
                    Severity.CRITICAL,
                    ip_src, ip_dst,
                    f"Tempete de traps: {profile.trap_count} traps depuis {ip_src}",
                    {"trap_count": profile.trap_count}
                )
                alerts.append(alert)
                profile.update_reputation(-15)
                
        elif profile.trap_count > self.thresholds["trap_per_minute_warning"]:
            if profile.trap_count % 50 == 0:
                alert = self._create_alert(
                    AnomalyType.TRAP_STORM,
                    Severity.WARNING,
                    ip_src, ip_dst,
                    f"Nombre eleve de traps: {profile.trap_count} depuis {ip_src}",
                    {"trap_count": profile.trap_count}
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_errors(self, profile: IPProfile, ip_src: str, ip_dst: str, 
                       error_status) -> List[AnomalyAlert]:
        """Detecte les anomalies liees aux erreurs"""
        alerts = []
        
        # Erreur d'authentification (error_status = 16)
        if str(error_status) == "16":
            alert = self._create_alert(
                AnomalyType.AUTH_FAILURE,
                Severity.WARNING,
                ip_src, ip_dst,
                f"Echec d'authentification SNMP depuis {ip_src}",
                {"error_status": error_status, "total_errors": profile.error_count}
            )
            alerts.append(alert)
            profile.update_reputation(-10)
        
        # Erreurs consecutives
        if profile.consecutive_errors >= self.thresholds["consecutive_errors_threshold"]:
            alert = self._create_alert(
                AnomalyType.ERROR_RATE,
                Severity.WARNING,
                ip_src, ip_dst,
                f"{profile.consecutive_errors} erreurs consecutives depuis {ip_src}",
                {"consecutive_errors": profile.consecutive_errors}
            )
            alerts.append(alert)
        
        # Taux d'erreur global
        if profile.packet_count > 10:
            error_rate = (profile.error_count / profile.packet_count) * 100
            if error_rate > self.thresholds["error_rate_critical"]:
                alert = self._create_alert(
                    AnomalyType.ERROR_RATE,
                    Severity.CRITICAL,
                    ip_src, ip_dst,
                    f"Taux d'erreur critique: {error_rate:.1f}% depuis {ip_src}",
                    {"error_rate": error_rate, "errors": profile.error_count}
                )
                alerts.append(alert)
                profile.update_reputation(-10)
        
        return alerts
    
    def _detect_community_enum(self, profile: IPProfile, ip_src: str, 
                               ip_dst: str) -> List[AnomalyAlert]:
        """Detecte les tentatives d'enumeration de communautes"""
        alerts = []
        
        num_communities = len(profile.community_strings)
        if num_communities >= self.thresholds["community_enum_threshold"]:
            if num_communities % 3 == 0:  # Eviter spam d'alertes
                alert = self._create_alert(
                    AnomalyType.COMMUNITY_ENUM,
                    Severity.WARNING,
                    ip_src, ip_dst,
                    f"Enumeration de communautes: {num_communities} testees par {ip_src}",
                    {"communities_count": num_communities, 
                     "communities": list(profile.community_strings)[:10]}
                )
                alerts.append(alert)
                profile.update_reputation(-15)
        
        return alerts
    
    def _detect_suspicious_oids(self, profile: IPProfile, ip_src: str,
                                ip_dst: str, oids: list) -> List[AnomalyAlert]:
        """Detecte l'acces aux OIDs sensibles"""
        alerts = []
        
        if not isinstance(oids, list):
            return alerts
        
        for oid_entry in oids:
            if isinstance(oid_entry, dict):
                oid = oid_entry.get("oid", "")
                for sensitive_oid, name in self.SENSITIVE_OIDS.items():
                    if oid.startswith(sensitive_oid):
                        # Une alerte par type d'OID sensible
                        alert_key = f"{ip_src}:{sensitive_oid}"
                        if not hasattr(profile, '_oid_alerts'):
                            profile._oid_alerts = set()
                        
                        if alert_key not in profile._oid_alerts:
                            profile._oid_alerts.add(alert_key)
                            alert = self._create_alert(
                                AnomalyType.SUSPICIOUS_OID,
                                Severity.INFO,
                                ip_src, ip_dst,
                                f"Acces a OID sensible: {name} ({sensitive_oid}) par {ip_src}",
                                {"oid": oid, "oid_name": name}
                            )
                            alerts.append(alert)
        
        return alerts
    
    def _cleanup_loop(self):
        """Boucle de nettoyage periodique"""
        while True:
            time.sleep(self.thresholds["cleanup_interval_seconds"])
            self._cleanup()
    
    def _cleanup(self):
        """Nettoie les anciennes donnees"""
        now = time.time()
        window = self.thresholds["analysis_window_seconds"] * 10
        
        with self._lock:
            # Nettoyer les profils inactifs
            inactive_ips = []
            for ip, profile in self.ip_profiles.items():
                if now - profile.last_seen > window:
                    inactive_ips.append(ip)
            
            for ip in inactive_ips:
                del self.ip_profiles[ip]
            
            # Limiter le nombre d'alertes en memoire
            if len(self.alerts) > 5000:
                self.alerts = self.alerts[-2500:]
    
    # === API PUBLIQUE ===
    
    def get_alerts(self, severity: str = None, anomaly_type: str = None,
                   limit: int = 100, source_ip: str = None) -> List[Dict]:
        """Recupere les alertes avec filtrage"""
        with self._lock:
            filtered = self.alerts.copy()
        
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        if anomaly_type:
            filtered = [a for a in filtered if a.anomaly_type == anomaly_type]
        if source_ip:
            filtered = [a for a in filtered if a.source_ip == source_ip]
        
        return [a.to_dict() for a in filtered[-limit:]]
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques du detecteur"""
        with self._lock:
            duration = time.time() - self.stats["start_time"]
            return {
                "total_packets_analyzed": self.stats["total_packets_analyzed"],
                "total_alerts_generated": self.stats["total_alerts_generated"],
                "alerts_by_type": dict(self.stats["alerts_by_type"]),
                "alerts_by_severity": dict(self.stats["alerts_by_severity"]),
                "blocked_ips_count": len(self.stats["blocked_ips"]),
                "blocked_ips": list(self.stats["blocked_ips"]),
                "active_ip_profiles": len(self.ip_profiles),
                "uptime_seconds": round(duration, 2),
                "alerts_per_minute": round(self.stats["total_alerts_generated"] / (duration / 60), 2) if duration > 0 else 0,
            }
    
    def get_ip_profile(self, ip: str) -> Optional[Dict]:
        """Retourne le profil d'une IP"""
        with self._lock:
            profile = self.ip_profiles.get(ip)
            return profile.to_dict() if profile else None
    
    def get_all_profiles(self) -> List[Dict]:
        """Retourne tous les profils IP"""
        with self._lock:
            return [p.to_dict() for p in self.ip_profiles.values()]
    
    def clear_alerts(self):
        """Efface toutes les alertes"""
        with self._lock:
            self.alerts.clear()
    
    def reset_statistics(self):
        """Reinitialise les statistiques"""
        with self._lock:
            self.stats = {
                "total_packets_analyzed": 0,
                "total_alerts_generated": 0,
                "alerts_by_type": defaultdict(int),
                "alerts_by_severity": defaultdict(int),
                "blocked_ips": set(),
                "start_time": time.time(),
            }
    
    def unblock_ip(self, ip: str) -> bool:
        """Debloque une IP"""
        with self._lock:
            if ip in self.ip_profiles:
                self.ip_profiles[ip].is_blacklisted = False
                self.ip_profiles[ip].reputation_score = 50
                self.stats["blocked_ips"].discard(ip)
                return True
            return False
    
    def update_thresholds(self, new_thresholds: Dict):
        """Met a jour les seuils de detection"""
        with self._lock:
            self.thresholds.update(new_thresholds)


# Instance globale singleton
_detector_instance: Optional[AnomalyDetector] = None
_detector_lock = threading.Lock()


def get_detector(config: Dict = None) -> AnomalyDetector:
    """Retourne l'instance singleton du detecteur"""
    global _detector_instance
    with _detector_lock:
        if _detector_instance is None:
            _detector_instance = AnomalyDetector(config)
        return _detector_instance


def reset_detector():
    """Reinitialise le detecteur"""
    global _detector_instance
    with _detector_lock:
        _detector_instance = None
