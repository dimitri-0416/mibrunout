#!/usr/bin/env python3
"""MIBurnout Suite V1 - API REST"""

import os, sys, json, time, argparse
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
from typing import Dict, List, Optional

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT_DIR)

FLASK_AVAILABLE = False
try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    print("[!] Flask requis: pip install flask flask-cors")

CORE_AVAILABLE = False
try:
    from core.sniffer import Sniffer
    from core.analyser import Analyser
    from core.SQLiteDB import DataBase
    from core.confAPP import ConfAPP
    from core.anomaly_detector import get_detector
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"[!] Core: {e}")

API_VERSION = "1.0.0"
DEFAULT_CONFIG = {"interface": "eth0", "filter": "udp port 161 or udp port 162",
                  "database": "miburnout.db", "config_file": "config/conf.json", "pcap_dir": "captures"}


class CaptureManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init = False
        return cls._instance
    
    def __init__(self):
        if self._init: return
        self._init = True
        self.config = DEFAULT_CONFIG.copy()
        self.db, self.cfg_mgr, self.sniffer, self.analyser, self.detector = None, None, None, None, None
        self.queue = None
        self.is_capturing, self.is_initialized = False, False
        self.start_time = None
        self.packets, self.lock = [], Lock()
        self.stats = {"total": 0, "authorized": 0, "suspect": 0}
    
    def initialize(self):
        if not CORE_AVAILABLE:
            return {"success": False, "error": "Core not available"}
        try:
            os.makedirs(self.config["pcap_dir"], exist_ok=True)
            os.makedirs(os.path.dirname(self.config["config_file"]) or "config", exist_ok=True)
            self.db = DataBase(dbFile=self.config["database"])
            self.db.initDB()
            self.cfg_mgr = ConfAPP(confFile=self.config["config_file"])
            if self.cfg_mgr.config is None: self.cfg_mgr.creatConf()
            self.detector = get_detector()
            self.queue = Queue(maxsize=10000)
            self.is_initialized = True
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def start(self, iface=None, filt=None):
        if not self.is_initialized:
            r = self.initialize()
            if not r["success"]: return r
        if self.is_capturing:
            return {"success": False, "error": "Already running"}
        if iface: self.config["interface"] = iface
        if filt: self.config["filter"] = filt
        try:
            self.sniffer = Sniffer(iface=self.config["interface"], sfilter=self.config["filter"], queue=self.queue)
            cfg = self.cfg_mgr.config if self.cfg_mgr else {}
            self.analyser = Analyser(queue=self.queue, baseDB=self.db, config=cfg, pcap_dir=self.config["pcap_dir"], lenPcap=100)
            Thread(target=self.sniffer.start_sniffer, daemon=True).start()
            Thread(target=self._loop, daemon=True).start()
            self.is_capturing, self.start_time = True, time.time()
            return {"success": True, "interface": self.config["interface"]}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _loop(self):
        while self.is_capturing:
            try:
                if self.queue.empty():
                    time.sleep(0.01)
                    continue
                pkt = self.queue.get(timeout=0.5)
                data = self.analyser.packet_info(pkt)
                if self.analyser.compare(data):
                    data["tag"] = 0
                    self.stats["authorized"] += 1
                else:
                    data["tag"] = 1
                    self.stats["suspect"] += 1
                if self.detector:
                    self.detector.analyze_packet(data)
                db_data = self._prep(data)
                ver = str(data.get("snmp_version", "1"))
                self.db.wrData("snmp_v1" if ver == "0" else "snmp_v2", db_data)
                try:
                    self.analyser.pcap_writer.write(pkt)
                    self.analyser.nb_pkt += 1
                    if self.analyser.nb_pkt >= self.analyser.lenPcap:
                        self.analyser.open_new_pcap()
                except: pass
                with self.lock:
                    self.packets.append(data)
                    if len(self.packets) > 10000:
                        self.packets = self.packets[-5000:]
                self.stats["total"] += 1
                self.queue.task_done()
            except: pass
    
    def _prep(self, d):
        r = {"time_stamp": d.get("time_stamp"), "mac_src": d.get("mac_src"), "mac_dst": d.get("mac_dst"),
             "ip_src": d.get("ip_src"), "ip_dst": d.get("ip_dst"), "port_src": d.get("port_src"), "port_dst": d.get("port_dst"),
             "snmp_community": d.get("snmp_community"), "snmp_pdu_type": d.get("snmp_pdu_type"),
             "snmp_oidsValues": json.dumps({"oidsValues": d.get("snmp_oidsValues", [])}), "tag": d.get("tag", 0)}
        ver = str(d.get("snmp_version", "1"))
        if ver == "0":
            r.update({"snmp_enterprise": d.get("snmp_enterprise"), "snmp_agent_addr": d.get("snmp_agent_addr"),
                      "snmp_generic_trap": d.get("snmp_generic_trap"), "snmp_specific_trap": d.get("snmp_specific_trap"),
                      "snmp_request_id": d.get("snmp_request_id"), "snmp_error_status": d.get("snmp_error_status"), "snmp_error_index": d.get("snmp_error_index")})
        else:
            r.update({"snmp_request_id": d.get("snmp_request_id"), "snmp_error_status": d.get("snmp_error_status"),
                      "snmp_error_index": d.get("snmp_error_index"), "snmp_non_repeaters": d.get("snmp_non_repeaters"), "snmp_max_repetitions": d.get("snmp_max_repetitions")})
        return {k: v for k, v in r.items() if v is not None}
    
    def stop(self):
        if not self.is_capturing:
            return {"success": False, "error": "Not running"}
        self.is_capturing = False
        if self.analyser and hasattr(self.analyser, 'pcap_writer'):
            try: self.analyser.pcap_writer.close()
            except: pass
        dur = time.time() - self.start_time if self.start_time else 0
        return {"success": True, "duration": round(dur, 2), "packets": self.stats["total"]}
    
    def get_status(self):
        return {"version": API_VERSION, "core": CORE_AVAILABLE, "capturing": self.is_capturing,
                "interface": self.config.get("interface"), "timestamp": datetime.now().isoformat()}
    
    def get_stats(self):
        dur = time.time() - self.start_time if self.start_time and self.is_capturing else 0
        r = {**self.stats, "duration": round(dur, 2), "in_memory": len(self.packets)}
        if self.detector:
            r["anomalies"] = self.detector.get_statistics()
        return r
    
    def get_packets(self, limit=100, offset=0, tag=None):
        with self.lock:
            f = self.packets.copy()
        if tag is not None:
            f = [p for p in f if p.get("tag") == tag]
        return {"total": len(f), "packets": f[offset:offset+limit]}
    
    def get_alerts(self, limit=100):
        if not self.detector:
            return {"alerts": []}
        return {"alerts": self.detector.get_alerts(limit=limit), "stats": self.detector.get_statistics()}


def create_app():
    if not FLASK_AVAILABLE:
        print("Flask requis!")
        sys.exit(1)
    app = Flask(__name__)
    CORS(app)
    mgr = CaptureManager()
    
    @app.route("/")
    def index():
        return jsonify({"name": "MIBurnout API", "version": API_VERSION})
    
    @app.route("/api/status")
    def status():
        return jsonify(mgr.get_status())
    
    @app.route("/api/capture/start", methods=["POST"])
    def start():
        d = request.get_json() or {}
        return jsonify(mgr.start(iface=d.get("interface"), filt=d.get("filter")))
    
    @app.route("/api/capture/stop", methods=["POST"])
    def stop():
        return jsonify(mgr.stop())
    
    @app.route("/api/packets")
    def packets():
        return jsonify(mgr.get_packets(
            limit=request.args.get("limit", 100, type=int),
            offset=request.args.get("offset", 0, type=int),
            tag=request.args.get("tag", type=int)))
    
    @app.route("/api/stats")
    def stats():
        return jsonify(mgr.get_stats())
    
    @app.route("/api/alerts")
    def alerts():
        return jsonify(mgr.get_alerts(limit=request.args.get("limit", 100, type=int)))
    
    @app.route("/api/docs")
    def docs():
        return jsonify({"endpoints": [
            {"GET": "/api/status"}, {"POST": "/api/capture/start"}, {"POST": "/api/capture/stop"},
            {"GET": "/api/packets"}, {"GET": "/api/stats"}, {"GET": "/api/alerts"}
        ]})
    
    return app


def main():
    if not FLASK_AVAILABLE:
        print("pip install flask flask-cors")
        sys.exit(1)
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    print(f"API: http://{args.host}:{args.port}")
    create_app().run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
