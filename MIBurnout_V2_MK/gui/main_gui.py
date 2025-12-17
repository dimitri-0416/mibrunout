#!/usr/bin/env python3
"""
MIBurnout Suite Pro - Interface Graphique Style Grafana
========================================================
- Dashboard avec graphiques temps réel (Matplotlib)
- Analyse comportementale SNMP avancée
- Visualisation des profils IP et scores de réputation
- Détection d'anomalies en temps réel
"""

import customtkinter as ctk
from tkinter import filedialog, ttk
import tkinter as tk
from threading import Thread, Event, Lock
from queue import Queue, Empty
import json, os, sys, time, traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import deque

# Matplotlib pour les graphiques
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

# Import des modules core
CORE_AVAILABLE = False
Sniffer = None
Analyser = None
DataBase = None
ConfAPP = None
get_detector = None
AuthManager = None
get_auth_manager = None

try:
    from core.sniffer import Sniffer as _Sniffer
    from core.analyser import Analyser as _Analyser
    from core.SQLiteDB import DataBase as _DataBase
    from core.confAPP import ConfAPP as _ConfAPP
    from core.anomaly_detector import get_detector as _get_detector
    from core.auth import AuthManager as _AuthManager, get_auth_manager as _get_auth_manager
    
    Sniffer = _Sniffer
    Analyser = _Analyser
    DataBase = _DataBase
    ConfAPP = _ConfAPP
    get_detector = _get_detector
    AuthManager = _AuthManager
    get_auth_manager = _get_auth_manager
    CORE_AVAILABLE = True
    print("[+] Core modules loaded successfully")
except ImportError as e:
    print(f"[!] Core import error: {e}")

# Import des widgets d'authentification
try:
    from gui.auth_widgets import LoginWindow, ProfilePanel, UserManagementPanel
    AUTH_WIDGETS_AVAILABLE = True
except ImportError:
    try:
        from auth_widgets import LoginWindow, ProfilePanel, UserManagementPanel
        AUTH_WIDGETS_AVAILABLE = True
    except ImportError:
        AUTH_WIDGETS_AVAILABLE = False
        print("[!] Auth widgets not available")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# =============================================================================
# THEME GRAFANA DARK
# =============================================================================

THEME = {
    # Backgrounds
    "bg_main": "#0b0c0e",
    "bg_panel": "#141619",
    "bg_card": "#1e2228",
    "bg_input": "#2a2f38",
    "bg_hover": "#353b47",
    
    # Borders
    "border": "#2a2f38",
    "border_light": "#3d4452",
    
    # Text
    "text_primary": "#e6e9ef",
    "text_secondary": "#8b949e",
    "text_muted": "#5c6370",
    
    # Accent - Orange Grafana
    "accent": "#ff6b35",
    "accent_light": "#ff8c5a",
    "accent_dark": "#cc5529",
    
    # Status
    "success": "#3fb950",
    "warning": "#d29922",
    "error": "#f85149",
    "info": "#58a6ff",
    
    # Charts
    "chart_green": "#3fb950",
    "chart_blue": "#58a6ff",
    "chart_orange": "#ff6b35",
    "chart_purple": "#a371f7",
    "chart_cyan": "#39d5ff",
    "chart_yellow": "#d29922",
    "chart_red": "#f85149",
    "chart_pink": "#db61a2",
    
    # Grid
    "grid": "#21262d",
}

# Configuration matplotlib pour style Grafana
plt.rcParams.update({
    'figure.facecolor': THEME["bg_card"],
    'axes.facecolor': THEME["bg_card"],
    'axes.edgecolor': THEME["border"],
    'axes.labelcolor': THEME["text_secondary"],
    'axes.grid': True,
    'grid.color': THEME["grid"],
    'grid.alpha': 0.5,
    'text.color': THEME["text_primary"],
    'xtick.color': THEME["text_muted"],
    'ytick.color': THEME["text_muted"],
    'legend.facecolor': THEME["bg_panel"],
    'legend.edgecolor': THEME["border"],
    'font.size': 11,
})

# =============================================================================
# TAILLES DE POLICE GLOBALES
# =============================================================================

FONTS = {
    "title_xl": ("", 24, "bold"),
    "title_lg": ("", 18, "bold"),
    "title_md": ("", 15, "bold"),
    "title_sm": ("", 13, "bold"),
    "body_lg": ("", 14, "normal"),
    "body_md": ("", 13, "normal"),
    "body_sm": ("", 12, "normal"),
    "mono_lg": ("Courier", 13, "normal"),
    "mono_md": ("Courier", 12, "normal"),
    "mono_sm": ("Courier", 11, "normal"),
    "stat_value": ("", 36, "bold"),
    "gauge_value": ("", 28, "bold"),
}

ctk.set_appearance_mode("dark")


# =============================================================================
# WIDGETS GRAPHIQUES TEMPS REEL
# =============================================================================

class TimeSeriesChart(tk.Frame):
    """Graphique de série temporelle style Grafana Pro"""
    
    def __init__(self, parent, title="", ylabel="", max_points=60, **kwargs):
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._ylabel = ylabel
        self._max_points = max_points
        self._series = {}
        self._lock = Lock()
        
        self._build()
    
    def _build(self):
        # Header avec style
        header = tk.Frame(self, bg=THEME["bg_card"], height=40)
        header.pack(fill="x", padx=15, pady=(12, 0))
        
        # Titre avec icône
        title_frame = tk.Frame(header, bg=THEME["bg_card"])
        title_frame.pack(side="left")
        
        tk.Label(title_frame, text=self._title,
                font=("Segoe UI", 14, "bold"),
                fg=THEME["text_primary"],
                bg=THEME["bg_card"]).pack(side="left")
        
        # Valeur actuelle (grand)
        self._value_label = tk.Label(header, text="0",
                                    font=("Segoe UI", 20, "bold"),
                                    fg=THEME["accent"],
                                    bg=THEME["bg_card"])
        self._value_label.pack(side="right", padx=10)
        
        # Figure Matplotlib améliorée
        self._fig = Figure(figsize=(5, 2.5), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111)
        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
        
        self._setup_axes()
    
    def _setup_axes(self):
        self._ax.clear()
        self._ax.set_facecolor(THEME["bg_card"])
        
        # Style Grafana - axes minimalistes
        self._ax.spines['top'].set_visible(False)
        self._ax.spines['right'].set_visible(False)
        self._ax.spines['bottom'].set_color(THEME["grid"])
        self._ax.spines['left'].set_color(THEME["grid"])
        self._ax.spines['bottom'].set_linewidth(0.5)
        self._ax.spines['left'].set_linewidth(0.5)
        
        # Grille subtile
        self._ax.grid(True, alpha=0.15, color=THEME["text_muted"], linestyle='-', linewidth=0.5)
        self._ax.set_axisbelow(True)
        
        # Labels
        self._ax.tick_params(axis='both', labelsize=9, colors=THEME["text_muted"], length=0)
        self._ax.set_ylabel(self._ylabel, fontsize=10, color=THEME["text_secondary"], labelpad=10)
        
        self._fig.tight_layout(pad=2)
    
    def add_series(self, name: str, color: str):
        with self._lock:
            self._series[name] = {
                "data": deque(maxlen=self._max_points),
                "color": color
            }
    
    def add_point(self, series_name: str, value: float, timestamp: datetime = None):
        if timestamp is None:
            timestamp = datetime.now()
        with self._lock:
            if series_name in self._series:
                self._series[series_name]["data"].append((timestamp, value))
    
    def update_chart(self):
        with self._lock:
            self._ax.clear()
            self._setup_axes()
            
            last_value = None
            for name, series in self._series.items():
                if series["data"] and len(series["data"]) > 1:
                    times = [d[0] for d in series["data"]]
                    values = [d[1] for d in series["data"]]
                    
                    color = series["color"]
                    
                    # Ligne principale avec effet glow
                    self._ax.plot(times, values, color=color, linewidth=2, 
                                 solid_capstyle='round', zorder=3)
                    
                    # Remplissage gradient
                    self._ax.fill_between(times, values, alpha=0.3, color=color, zorder=2)
                    self._ax.fill_between(times, values, alpha=0.1, color=color, zorder=1)
                    
                    # Points sur les dernières valeurs
                    if len(values) > 0:
                        self._ax.scatter([times[-1]], [values[-1]], color=color, s=40, zorder=4, edgecolors='white', linewidth=1.5)
                    
                    last_value = values[-1] if values else None
            
            # Format axe X
            self._ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            self._ax.xaxis.set_major_locator(plt.MaxNLocator(5))
            self._fig.autofmt_xdate()
            
            # Limites Y avec marge
            if last_value is not None:
                self._value_label.configure(text=f"{last_value:.1f}")
            
            try:
                self._canvas.draw_idle()
            except:
                pass


class BarChart(tk.Frame):
    """Graphique en barres style Grafana Pro"""
    
    def __init__(self, parent, title="", **kwargs):
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._data = {}
        
        self._build()
    
    def _build(self):
        # Header
        header = tk.Frame(self, bg=THEME["bg_card"], height=40)
        header.pack(fill="x", padx=15, pady=(12, 0))
        
        tk.Label(header, text=self._title,
                font=("Segoe UI", 14, "bold"),
                fg=THEME["text_primary"],
                bg=THEME["bg_card"]).pack(side="left")
        
        # Figure
        self._fig = Figure(figsize=(4, 2.8), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111)
        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
    
    def set_data(self, data: Dict[str, float], colors: List[str] = None):
        self._data = data
        self._ax.clear()
        self._ax.set_facecolor(THEME["bg_card"])
        
        if not data:
            try:
                self._canvas.draw_idle()
            except:
                pass
            return
        
        # Trier et limiter
        sorted_data = dict(sorted(data.items(), key=lambda x: x[1], reverse=True)[:6])
        labels = list(sorted_data.keys())
        values = list(sorted_data.values())
        
        # Palette de couleurs Grafana
        grafana_colors = [
            "#7eb26d", "#eab839", "#6ed0e0", "#ef843c", 
            "#e24d42", "#1f78c1", "#ba43a9", "#705da0"
        ]
        
        if colors is None:
            colors = grafana_colors
        
        # Barres horizontales avec style
        y_pos = range(len(labels))
        bars = self._ax.barh(y_pos, values, color=colors[:len(labels)], 
                            height=0.6, edgecolor='none', alpha=0.9)
        
        # Style
        self._ax.set_yticks(y_pos)
        self._ax.set_yticklabels(labels, fontsize=10, color=THEME["text_primary"])
        self._ax.invert_yaxis()
        
        # Valeurs à droite des barres
        for i, (bar, val) in enumerate(zip(bars, values)):
            self._ax.text(bar.get_width() + max(values)*0.02, bar.get_y() + bar.get_height()/2,
                         f'{int(val)}', va='center', fontsize=10, 
                         color=THEME["text_secondary"], fontweight='bold')
        
        # Style minimaliste
        self._ax.spines['top'].set_visible(False)
        self._ax.spines['right'].set_visible(False)
        self._ax.spines['bottom'].set_visible(False)
        self._ax.spines['left'].set_visible(False)
        self._ax.tick_params(axis='x', which='both', bottom=False, labelbottom=False)
        self._ax.tick_params(axis='y', which='both', left=False)
        
        # Grille horizontale subtile
        self._ax.set_axisbelow(True)
        self._ax.xaxis.grid(True, alpha=0.1, color=THEME["text_muted"])
        
        self._fig.tight_layout(pad=2)
        try:
            self._canvas.draw_idle()
        except:
            pass


class GaugeChart(tk.Frame):
    """Jauge circulaire style Grafana moderne"""
    
    def __init__(self, parent, title="", max_val=100, unit="", 
                 thresholds=None, **kwargs):
        tk_kwargs = {k: v for k, v in kwargs.items() if k in ['width', 'height']}
        super().__init__(parent, bg=THEME["bg_card"], **tk_kwargs)
        self._title = title
        self._max_val = max_val
        self._unit = unit
        self._value = 0
        self._thresholds = thresholds or {"warning": 60, "critical": 80}
        
        self._build()
    
    def _build(self):
        # Titre
        tk.Label(self, text=self._title,
                font=("Segoe UI", 12),
                fg=THEME["text_secondary"],
                bg=THEME["bg_card"]).pack(pady=(15, 8))
        
        # Figure
        self._fig = Figure(figsize=(2.2, 1.4), dpi=100, facecolor=THEME["bg_card"])
        self._ax = self._fig.add_subplot(111, projection='polar')
        
        self._canvas = FigureCanvasTkAgg(self._fig, self)
        self._canvas.get_tk_widget().configure(bg=THEME["bg_card"], highlightthickness=0)
        self._canvas.get_tk_widget().pack()
        
        # Valeur
        self._value_label = tk.Label(self, text="0",
                                    font=("Segoe UI", 36, "bold"),
                                    fg=THEME["success"],
                                    bg=THEME["bg_card"])
        self._value_label.pack(pady=(0, 2))
        
        tk.Label(self, text=self._unit,
                font=("Segoe UI", 11),
                fg=THEME["text_muted"],
                bg=THEME["bg_card"]).pack(pady=(0, 15))
        
        self._draw_gauge()
    
    def _draw_gauge(self):
        import numpy as np
        
        self._ax.clear()
        self._ax.set_facecolor(THEME["bg_card"])
        
        # Configuration
        self._ax.set_theta_offset(np.pi)
        self._ax.set_theta_direction(-1)
        self._ax.set_thetamin(0)
        self._ax.set_thetamax(180)
        
        # Arc de fond (gris foncé)
        theta_bg = np.linspace(0, np.pi, 100)
        self._ax.plot(theta_bg, [1]*100, color=THEME["border"], linewidth=20, 
                     solid_capstyle='round', alpha=0.5)
        
        # Calcul de la valeur
        pct = min(self._value / self._max_val, 1.0) if self._max_val > 0 else 0
        theta_val = np.linspace(0, np.pi * pct, 100)
        
        # Couleur selon seuils
        pct_100 = pct * 100
        if pct_100 >= self._thresholds["critical"]:
            color = THEME["error"]
        elif pct_100 >= self._thresholds["warning"]:
            color = THEME["warning"]
        else:
            color = THEME["success"]
        
        # Arc de valeur avec effet glow
        if pct > 0.01:
            # Glow effect
            self._ax.plot(theta_val, [1]*len(theta_val), color=color, linewidth=24, 
                         solid_capstyle='round', alpha=0.3)
            # Arc principal
            self._ax.plot(theta_val, [1]*len(theta_val), color=color, linewidth=18, 
                         solid_capstyle='round')
        
        # Masquer les axes
        self._ax.set_yticks([])
        self._ax.set_xticks([])
        self._ax.spines['polar'].set_visible(False)
        
        self._fig.tight_layout(pad=0)
        
        try:
            self._canvas.draw_idle()
        except:
            pass
        
        # Mettre à jour le label
        self._value_label.configure(text=f"{int(self._value)}", fg=color)
    
    def set_value(self, val):
        self._value = val
        self._draw_gauge()


# =============================================================================
# WIDGETS STATISTIQUES
# =============================================================================

class StatCard(ctk.CTkFrame):
    """Carte de statistique compacte style Grafana"""
    
    def __init__(self, parent, title="", icon="", color=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._color = color or THEME["text_primary"]
        
        # Icône
        ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(size=24)).pack(anchor="w", padx=18, pady=(15, 0))
        
        # Valeur - GRANDE
        self._value_label = ctk.CTkLabel(self, text="0",
                                        font=ctk.CTkFont(size=42, weight="bold"),
                                        text_color=self._color)
        self._value_label.pack(anchor="w", padx=18, pady=(8, 0))
        
        # Titre
        ctk.CTkLabel(self, text=title,
                    font=ctk.CTkFont(size=13),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=18, pady=(2, 15))
    
    def set_value(self, val, color=None):
        self._value_label.configure(text=str(val))
        if color:
            self._value_label.configure(text_color=color)


class AlertPanel(ctk.CTkFrame):
    """Panneau d'alertes avec détails comportementaux - Polices agrandies"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._alerts = []
        self._build()
    
    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=14)
        
        ctk.CTkLabel(header, text="🚨 Alertes Comportementales",
                    font=ctk.CTkFont(size=15, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        self._count_label = ctk.CTkLabel(header, text="0",
                                        font=ctk.CTkFont(size=13, weight="bold"),
                                        text_color=THEME["error"],
                                        fg_color=THEME["bg_input"],
                                        corner_radius=10, width=35)
        self._count_label.pack(side="right")
        
        # Liste des alertes
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=THEME["bg_panel"],
                                                 corner_radius=6, height=200)
        self._list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    
    def add_alert(self, alert):
        """Ajoute une alerte au panneau"""
        self._alerts.append(alert)
        self._count_label.configure(text=str(len(self._alerts)))
        
        # Couleur selon sévérité
        colors = {
            "critical": THEME["error"],
            "warning": THEME["warning"],
            "info": THEME["info"],
            "emergency": THEME["chart_pink"]
        }
        color = colors.get(alert.severity, THEME["warning"])
        
        # Créer la carte d'alerte
        card = ctk.CTkFrame(self._list_frame, fg_color=THEME["bg_card"], corner_radius=6)
        card.pack(fill="x", pady=4)
        
        # Indicateur de sévérité
        indicator = ctk.CTkFrame(card, fg_color=color, width=5, corner_radius=2)
        indicator.pack(side="left", fill="y", padx=(0, 12))
        
        # Contenu
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", expand=True, pady=10, padx=(0, 12))
        
        # Header de l'alerte
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text=alert.anomaly_type,
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=color).pack(side="left")
        
        ctk.CTkLabel(header, text=alert.timestamp[-8:] if len(alert.timestamp) > 8 else alert.timestamp,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(side="right")
        
        # Source IP
        ctk.CTkLabel(content, text=f"Source: {alert.source_ip}",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"]).pack(anchor="w", pady=(3, 0))
        
        # Message (tronqué)
        msg = alert.message[:70] + "..." if len(alert.message) > 70 else alert.message
        ctk.CTkLabel(content, text=msg,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(anchor="w")
    
    def clear(self):
        self._alerts.clear()
        self._count_label.configure(text="0")
        for widget in self._list_frame.winfo_children():
            widget.destroy()


class IPProfileTable(ctk.CTkFrame):
    """Tableau des profils IP avec scores de réputation - Optimisé anti-clignotement"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._profiles = []
        self._profile_rows = {}  # IP -> widgets de la ligne
        self._build()
    
    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=15)
        
        ctk.CTkLabel(header, text="👤 Profils IP - Analyse Comportementale",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        # En-têtes de colonnes
        cols_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=0)
        cols_frame.pack(fill="x", padx=12)
        
        columns = [
            ("IP", 140), ("Réputation", 90), ("Paquets", 80), 
            ("Erreurs", 70), ("PPS", 60), ("Status", 100)
        ]
        
        for col_name, width in columns:
            ctk.CTkLabel(cols_frame, text=col_name, width=width,
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=THEME["text_secondary"]).pack(side="left", padx=6, pady=10)
        
        # Liste des profils
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=THEME["bg_panel"],
                                                 corner_radius=0, height=200)
        self._list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    
    def update_profiles(self, profiles: List[Dict]):
        """Met à jour la liste des profils (optimisé)"""
        sorted_profiles = sorted(profiles, key=lambda x: x.get("reputation_score", 100))[:15]
        
        # Vérifier si la liste d'IPs a changé
        new_ips = [p.get("ip") for p in sorted_profiles]
        old_ips = [p.get("ip") for p in self._profiles]
        
        if new_ips != old_ips:
            # Liste a changé, reconstruire
            for widget in self._list_frame.winfo_children():
                widget.destroy()
            self._profile_rows.clear()
            
            for profile in sorted_profiles:
                self._add_profile_row(profile)
        else:
            # Même liste, mettre à jour les valeurs seulement
            for profile in sorted_profiles:
                ip = profile.get("ip")
                if ip in self._profile_rows:
                    self._update_profile_row(ip, profile)
        
        self._profiles = sorted_profiles
    
    def _add_profile_row(self, profile: Dict):
        ip = profile.get("ip", "?")
        
        row = ctk.CTkFrame(self._list_frame, fg_color="transparent", height=38)
        row.pack(fill="x", pady=2)
        row.pack_propagate(False)
        
        # IP
        ip_label = ctk.CTkLabel(row, text=ip[:18], width=140,
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_primary"], anchor="w")
        ip_label.pack(side="left", padx=6)
        
        # Réputation avec couleur
        rep = profile.get("reputation_score", 100)
        rep_color = self._get_rep_color(rep)
        
        rep_label = ctk.CTkLabel(row, text=f"{rep:.0f}%", width=90,
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=rep_color)
        rep_label.pack(side="left", padx=6)
        
        # Paquets
        pkt_label = ctk.CTkLabel(row, text=str(profile.get("packet_count", 0)), width=80,
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"])
        pkt_label.pack(side="left", padx=6)
        
        # Erreurs
        errors = profile.get("error_count", 0)
        err_color = THEME["error"] if errors > 5 else THEME["text_secondary"]
        err_label = ctk.CTkLabel(row, text=str(errors), width=70,
                    font=ctk.CTkFont(size=12),
                    text_color=err_color)
        err_label.pack(side="left", padx=6)
        
        # PPS
        pps = profile.get("packets_per_second", 0)
        pps_label = ctk.CTkLabel(row, text=f"{pps:.1f}", width=60,
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"])
        pps_label.pack(side="left", padx=6)
        
        # Status
        status_text, status_color = self._get_status(profile)
        status_label = ctk.CTkLabel(row, text=status_text, width=100,
                    font=ctk.CTkFont(size=12),
                    text_color=status_color)
        status_label.pack(side="left", padx=6)
        
        # Stocker les références pour mise à jour
        self._profile_rows[ip] = {
            "row": row,
            "rep_label": rep_label,
            "pkt_label": pkt_label,
            "err_label": err_label,
            "pps_label": pps_label,
            "status_label": status_label
        }
    
    def _update_profile_row(self, ip: str, profile: Dict):
        """Met à jour une ligne existante sans la recréer"""
        widgets = self._profile_rows.get(ip)
        if not widgets:
            return
        
        rep = profile.get("reputation_score", 100)
        rep_color = self._get_rep_color(rep)
        widgets["rep_label"].configure(text=f"{rep:.0f}%", text_color=rep_color)
        
        widgets["pkt_label"].configure(text=str(profile.get("packet_count", 0)))
        
        errors = profile.get("error_count", 0)
        err_color = THEME["error"] if errors > 5 else THEME["text_secondary"]
        widgets["err_label"].configure(text=str(errors), text_color=err_color)
        
        pps = profile.get("packets_per_second", 0)
        widgets["pps_label"].configure(text=f"{pps:.1f}")
        
        status_text, status_color = self._get_status(profile)
        widgets["status_label"].configure(text=status_text, text_color=status_color)
    
    def _get_rep_color(self, rep: float) -> str:
        if rep < 30:
            return THEME["error"]
        elif rep < 60:
            return THEME["warning"]
        return THEME["success"]
    
    def _get_status(self, profile: Dict) -> tuple:
        rep = profile.get("reputation_score", 100)
        if profile.get("is_blacklisted"):
            return "🚫 Bloqué", THEME["error"]
        elif rep < 30:
            return "⚠️ Suspect", THEME["warning"]
        return "✓ Normal", THEME["success"]


# =============================================================================
# ANALYSEUR DE BASELINE DYNAMIQUE
# =============================================================================

class BaselineAnalyzer:
    """
    Analyseur de baseline pour détection d'anomalies par dépassement de seuil.
    
    Calcule une moyenne mobile du trafic et génère des alertes quand le trafic
    dépasse un certain pourcentage au-dessus de cette baseline.
    """
    
    def __init__(self, window_size: int = 60, threshold_pct: float = 50.0,
                 min_samples: int = 10):
        """
        Args:
            window_size: Taille de la fenêtre pour le calcul de la moyenne (en secondes)
            threshold_pct: Pourcentage de dépassement pour déclencher une alerte
            min_samples: Nombre minimum d'échantillons avant de commencer l'analyse
        """
        self.window_size = window_size
        self.threshold_pct = threshold_pct
        self.min_samples = min_samples
        
        # Historique des mesures (timestamp, valeur)
        self._pps_history = deque(maxlen=window_size * 2)  # PPS par seconde
        self._error_history = deque(maxlen=window_size * 2)  # Erreurs par seconde
        
        # Baselines calculées
        self._baseline_pps = 0.0
        self._baseline_errors = 0.0
        self._std_pps = 0.0
        self._std_errors = 0.0
        
        # Seuils dynamiques
        self._threshold_pps = 0.0
        self._threshold_errors = 0.0
        
        # Stats
        self._total_samples = 0
        self._alerts_generated = 0
        self._last_alert_time = 0
        self._alert_cooldown = 5  # Secondes entre alertes du même type
        
        # Alertes actives
        self.alerts = []
        
        # État de l'apprentissage
        self._is_learning = True
        self._learning_complete = False
        
        self._lock = Lock()
    
    def add_sample(self, pps: float, errors: int, timestamp: float = None):
        """Ajoute un échantillon et recalcule les baselines"""
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            self._pps_history.append((timestamp, pps))
            self._error_history.append((timestamp, errors))
            self._total_samples += 1
            
            # Recalculer les baselines
            self._compute_baselines()
    
    def _compute_baselines(self):
        """Calcule les baselines (moyenne et écart-type)"""
        now = time.time()
        
        # Filtrer les échantillons dans la fenêtre
        recent_pps = [v for t, v in self._pps_history if now - t <= self.window_size]
        recent_errors = [v for t, v in self._error_history if now - t <= self.window_size]
        
        if len(recent_pps) >= self.min_samples:
            self._is_learning = False
            self._learning_complete = True
            
            # Moyenne
            self._baseline_pps = sum(recent_pps) / len(recent_pps)
            self._baseline_errors = sum(recent_errors) / len(recent_errors) if recent_errors else 0
            
            # Écart-type
            if len(recent_pps) > 1:
                variance_pps = sum((x - self._baseline_pps) ** 2 for x in recent_pps) / len(recent_pps)
                self._std_pps = variance_pps ** 0.5
            
            if len(recent_errors) > 1 and self._baseline_errors > 0:
                variance_errors = sum((x - self._baseline_errors) ** 2 for x in recent_errors) / len(recent_errors)
                self._std_errors = variance_errors ** 0.5
            
            # Seuils dynamiques = baseline + (threshold_pct% de la baseline)
            # Ou baseline + 2*std si plus restrictif
            self._threshold_pps = max(
                self._baseline_pps * (1 + self.threshold_pct / 100),
                self._baseline_pps + 2 * self._std_pps
            )
            self._threshold_errors = max(
                self._baseline_errors * (1 + self.threshold_pct / 100) if self._baseline_errors > 0 else 5,
                self._baseline_errors + 2 * self._std_errors if self._baseline_errors > 0 else 5
            )
    
    def check_anomaly(self, pps: float, errors: int) -> List[Dict]:
        """
        Vérifie si les valeurs actuelles dépassent les seuils.
        Retourne une liste d'alertes.
        """
        alerts = []
        now = time.time()
        
        with self._lock:
            if self._is_learning:
                return alerts
            
            # Vérifier dépassement PPS
            if pps > self._threshold_pps and self._threshold_pps > 0:
                if now - self._last_alert_time >= self._alert_cooldown:
                    deviation_pct = ((pps - self._baseline_pps) / self._baseline_pps * 100) if self._baseline_pps > 0 else 0
                    
                    alert = {
                        "type": "PPS_THRESHOLD_EXCEEDED",
                        "severity": "warning" if deviation_pct < 100 else "critical",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Débit anormal: {pps:.1f} PPS (baseline: {self._baseline_pps:.1f}, seuil: {self._threshold_pps:.1f})",
                        "details": {
                            "current_pps": pps,
                            "baseline_pps": round(self._baseline_pps, 2),
                            "threshold_pps": round(self._threshold_pps, 2),
                            "deviation_pct": round(deviation_pct, 1),
                            "std_pps": round(self._std_pps, 2)
                        }
                    }
                    alerts.append(alert)
                    self.alerts.append(alert)
                    self._alerts_generated += 1
                    self._last_alert_time = now
            
            # Vérifier dépassement Erreurs
            if errors > self._threshold_errors and self._threshold_errors > 0:
                if now - self._last_alert_time >= self._alert_cooldown:
                    deviation_pct = ((errors - self._baseline_errors) / self._baseline_errors * 100) if self._baseline_errors > 0 else 100
                    
                    alert = {
                        "type": "ERROR_RATE_EXCEEDED",
                        "severity": "warning" if deviation_pct < 100 else "critical",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Taux d'erreur anormal: {errors} (baseline: {self._baseline_errors:.1f}, seuil: {self._threshold_errors:.1f})",
                        "details": {
                            "current_errors": errors,
                            "baseline_errors": round(self._baseline_errors, 2),
                            "threshold_errors": round(self._threshold_errors, 2),
                            "deviation_pct": round(deviation_pct, 1)
                        }
                    }
                    alerts.append(alert)
                    self.alerts.append(alert)
                    self._alerts_generated += 1
                    self._last_alert_time = now
        
        return alerts
    
    def get_status(self) -> Dict:
        """Retourne l'état actuel de l'analyseur"""
        with self._lock:
            return {
                "is_learning": self._is_learning,
                "learning_progress": min(100, (self._total_samples / self.min_samples) * 100),
                "total_samples": self._total_samples,
                "baseline_pps": round(self._baseline_pps, 2),
                "baseline_errors": round(self._baseline_errors, 2),
                "std_pps": round(self._std_pps, 2),
                "threshold_pps": round(self._threshold_pps, 2),
                "threshold_errors": round(self._threshold_errors, 2),
                "threshold_pct": self.threshold_pct,
                "alerts_generated": self._alerts_generated,
                "window_size": self.window_size
            }
    
    def update_threshold(self, new_threshold_pct: float):
        """Met à jour le pourcentage de seuil"""
        with self._lock:
            self.threshold_pct = new_threshold_pct
            self._compute_baselines()
    
    def reset(self):
        """Réinitialise l'analyseur"""
        with self._lock:
            self._pps_history.clear()
            self._error_history.clear()
            self._baseline_pps = 0.0
            self._baseline_errors = 0.0
            self._std_pps = 0.0
            self._std_errors = 0.0
            self._threshold_pps = 0.0
            self._threshold_errors = 0.0
            self._total_samples = 0
            self._alerts_generated = 0
            self._is_learning = True
            self._learning_complete = False
            self.alerts.clear()


# =============================================================================
# PANNEAU D'ANALYSE BASELINE
# =============================================================================

class BaselinePanel(ctk.CTkFrame):
    """Panneau d'affichage et contrôle de l'analyse baseline"""
    
    def __init__(self, parent, analyzer: BaselineAnalyzer, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._analyzer = analyzer
        self._build()
    
    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=18, pady=15)
        
        ctk.CTkLabel(header, text="📊 Analyse de Baseline Dynamique",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left")
        
        # Status apprentissage
        self._learning_label = ctk.CTkLabel(header, text="🔄 Apprentissage...",
                                           font=ctk.CTkFont(size=12),
                                           text_color=THEME["warning"])
        self._learning_label.pack(side="right")
        
        # Contenu principal
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        content.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Colonne 1: Baseline PPS
        col1 = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        col1.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(col1, text="📈 Baseline PPS",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text_primary"]).pack(pady=(12, 5))
        
        self._baseline_pps_label = ctk.CTkLabel(col1, text="--",
                                               font=ctk.CTkFont(size=28, weight="bold"),
                                               text_color=THEME["chart_green"])
        self._baseline_pps_label.pack()
        
        ctk.CTkLabel(col1, text="paquets/sec",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack()
        
        self._threshold_pps_label = ctk.CTkLabel(col1, text="Seuil: --",
                                                font=ctk.CTkFont(size=12),
                                                text_color=THEME["text_secondary"])
        self._threshold_pps_label.pack(pady=(8, 12))
        
        # Colonne 2: Baseline Erreurs
        col2 = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        col2.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(col2, text="⚠️ Baseline Erreurs",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text_primary"]).pack(pady=(12, 5))
        
        self._baseline_errors_label = ctk.CTkLabel(col2, text="--",
                                                  font=ctk.CTkFont(size=28, weight="bold"),
                                                  text_color=THEME["chart_orange"])
        self._baseline_errors_label.pack()
        
        ctk.CTkLabel(col2, text="erreurs/sec",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack()
        
        self._threshold_errors_label = ctk.CTkLabel(col2, text="Seuil: --",
                                                   font=ctk.CTkFont(size=12),
                                                   text_color=THEME["text_secondary"])
        self._threshold_errors_label.pack(pady=(8, 12))
        
        # Colonne 3: Contrôles
        col3 = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        col3.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(col3, text="⚙️ Configuration",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["text_primary"]).pack(pady=(12, 10))
        
        # Slider pour le seuil
        ctk.CTkLabel(col3, text="Seuil de dépassement:",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack()
        
        slider_frame = ctk.CTkFrame(col3, fg_color="transparent")
        slider_frame.pack(fill="x", padx=15, pady=5)
        
        self._threshold_slider = ctk.CTkSlider(slider_frame, from_=10, to=200,
                                              number_of_steps=19,
                                              command=self._on_threshold_change,
                                              fg_color=THEME["bg_input"],
                                              progress_color=THEME["accent"])
        self._threshold_slider.set(self._analyzer.threshold_pct)
        self._threshold_slider.pack(side="left", fill="x", expand=True)
        
        self._threshold_value_label = ctk.CTkLabel(slider_frame, 
                                                  text=f"{int(self._analyzer.threshold_pct)}%",
                                                  font=ctk.CTkFont(size=13, weight="bold"),
                                                  text_color=THEME["accent"], width=50)
        self._threshold_value_label.pack(side="right", padx=(10, 0))
        
        # Bouton reset
        ctk.CTkButton(col3, text="🔄 Réinitialiser", 
                     command=self._reset_baseline,
                     fg_color=THEME["bg_input"],
                     hover_color=THEME["error"],
                     font=ctk.CTkFont(size=11),
                     height=30).pack(pady=(10, 12))
        
        # Stats
        stats_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=6)
        stats_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self._stats_label = ctk.CTkLabel(stats_frame, 
                                        text="Échantillons: 0 | Alertes: 0 | Fenêtre: 60s",
                                        font=ctk.CTkFont(size=11),
                                        text_color=THEME["text_muted"])
        self._stats_label.pack(pady=8)
    
    def _on_threshold_change(self, value):
        self._analyzer.update_threshold(value)
        self._threshold_value_label.configure(text=f"{int(value)}%")
    
    def _reset_baseline(self):
        self._analyzer.reset()
        self.update_display()
    
    def update_display(self):
        """Met à jour l'affichage avec les données actuelles"""
        status = self._analyzer.get_status()
        
        # Status apprentissage
        if status["is_learning"]:
            progress = status["learning_progress"]
            self._learning_label.configure(
                text=f"🔄 Apprentissage: {progress:.0f}%",
                text_color=THEME["warning"]
            )
        else:
            self._learning_label.configure(
                text="✓ Baseline établie",
                text_color=THEME["success"]
            )
        
        # Baselines
        self._baseline_pps_label.configure(text=f"{status['baseline_pps']:.1f}")
        self._baseline_errors_label.configure(text=f"{status['baseline_errors']:.1f}")
        
        # Seuils
        self._threshold_pps_label.configure(
            text=f"Seuil: {status['threshold_pps']:.1f} (±{status['std_pps']:.1f})"
        )
        self._threshold_errors_label.configure(
            text=f"Seuil: {status['threshold_errors']:.1f}"
        )
        
        # Stats
        self._stats_label.configure(
            text=f"Échantillons: {status['total_samples']} | "
                 f"Alertes: {status['alerts_generated']} | "
                 f"Fenêtre: {status['window_size']}s"
        )


# =============================================================================
# GESTIONNAIRE D'APPAREILS SNMP
# =============================================================================

class SNMPDevice:
    """Représente un appareil SNMP découvert sur le réseau"""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.mac = None
        self.hostname = None
        self.sys_descr = None
        self.sys_name = None
        self.sys_location = None
        self.sys_contact = None
        self.sys_object_id = None
        self.snmp_versions = set()  # {"v1", "v2c", "v3"}
        self.communities = set()
        self.usm_users = set()  # Pour SNMPv3
        self.ports = set()  # Ports utilisés
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.packet_count = 0
        self.request_count = 0  # GET, SET, etc.
        self.response_count = 0
        self.trap_count = 0
        self.error_count = 0
        self.oids_accessed = set()  # OIDs interrogés
        self.vendor = None  # Déduit du MAC ou sysObjectID
        self.device_type = "unknown"  # router, switch, server, printer, etc.
        self.is_manager = False  # Envoie des requêtes
        self.is_agent = False    # Répond aux requêtes
        self.status = "active"   # active, inactive, suspicious
        # Nouveaux champs pour la gestion
        self.is_trusted = False   # Appareil de confiance (vert)
        self.is_ignored = False   # Appareil ignoré (masqué)
        self.custom_name = None   # Nom personnalisé
        self.notes = None         # Notes utilisateur
        
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.custom_name or self.hostname or self.sys_name or "Inconnu",
            "sys_descr": self.sys_descr,
            "sys_name": self.sys_name,
            "sys_location": self.sys_location,
            "vendor": self.vendor or "Inconnu",
            "device_type": self.device_type,
            "snmp_versions": list(self.snmp_versions),
            "communities": list(self.communities)[:5],  # Limiter
            "usm_users": list(self.usm_users)[:5],
            "ports": list(self.ports),
            "first_seen": self.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "packet_count": self.packet_count,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "trap_count": self.trap_count,
            "error_count": self.error_count,
            "is_manager": self.is_manager,
            "is_agent": self.is_agent,
            "status": self.status,
            "oids_count": len(self.oids_accessed),
            # Nouveaux champs
            "is_trusted": self.is_trusted,
            "is_ignored": self.is_ignored,
            "custom_name": self.custom_name,
            "notes": self.notes
        }


class DeviceManager:
    """Gestionnaire de découverte et suivi des appareils SNMP"""
    
    # OIDs système standard
    OID_SYS_DESCR = "1.3.6.1.2.1.1.1"
    OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2"
    OID_SYS_NAME = "1.3.6.1.2.1.1.5"
    OID_SYS_LOCATION = "1.3.6.1.2.1.1.6"
    OID_SYS_CONTACT = "1.3.6.1.2.1.1.4"
    
    # Préfixes OID constructeurs connus
    VENDOR_OIDS = {
        "1.3.6.1.4.1.9": "Cisco",
        "1.3.6.1.4.1.2636": "Juniper",
        "1.3.6.1.4.1.11": "HP",
        "1.3.6.1.4.1.2011": "Huawei",
        "1.3.6.1.4.1.6527": "Nokia",
        "1.3.6.1.4.1.3076": "Alteon/Nortel",
        "1.3.6.1.4.1.1991": "Foundry/Brocade",
        "1.3.6.1.4.1.1916": "Extreme Networks",
        "1.3.6.1.4.1.25506": "H3C",
        "1.3.6.1.4.1.8072": "Net-SNMP",
        "1.3.6.1.4.1.311": "Microsoft",
        "1.3.6.1.4.1.2021": "Linux UCD-SNMP",
    }
    
    # Préfixes MAC constructeurs (OUI)
    MAC_VENDORS = {
        "00:00:0c": "Cisco",
        "00:1a:a1": "Cisco",
        "00:1b:54": "Cisco",
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "00:15:5d": "Microsoft Hyper-V",
        "08:00:27": "VirtualBox",
        "00:1c:42": "Parallels",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "00:1e:67": "Intel",
        "3c:fd:fe": "Intel",
        "00:25:90": "SuperMicro",
        "00:30:48": "SuperMicro",
        "00:e0:4c": "Realtek",
        "00:1a:2b": "Ayecom",
        "70:b3:d5": "IEEE Registration",
    }
    
    # Types de PDU qui indiquent un vrai appareil SNMP (agent)
    AGENT_PDU_TYPES = {"response", "snmpresponse", "trap", "snmptrap", "trapv2", 
                       "inform", "snmpinform", "report"}
    
    # Types de PDU qui indiquent un manager SNMP
    MANAGER_PDU_TYPES = {"get", "getnext", "getrequest", "getnextrequest", 
                         "set", "setrequest", "bulk", "getbulk", "snmpbulk"}
    
    def __init__(self):
        self._devices: Dict[str, SNMPDevice] = {}  # IP -> Device
        self._pending_devices: Dict[str, SNMPDevice] = {}  # Appareils en attente de confirmation
        self._lock = Lock()
        self._inactive_timeout = 300  # 5 minutes sans activité = inactif
        
    def process_packet(self, pkt_data: Dict):
        """
        Traite un paquet SNMP et met à jour les appareils.
        
        Logique de découverte :
        - Un appareil est confirmé comme "vrai" s'il ENVOIE une Response, Trap ou Inform
        - Les managers (qui envoient des requêtes) sont aussi des vrais appareils
        - Les IPs qui ne font que recevoir des requêtes ne sont PAS des appareils confirmés
        """
        with self._lock:
            ip_src = pkt_data.get("ip_src")
            pdu_type = str(pkt_data.get("snmp_pdu_type", "")).lower()
            
            if not ip_src:
                return
            
            # Déterminer si c'est un vrai appareil SNMP
            is_agent_response = any(t in pdu_type for t in self.AGENT_PDU_TYPES)
            is_manager_request = any(t in pdu_type for t in self.MANAGER_PDU_TYPES)
            
            # Si l'appareil envoie une réponse/trap OU une requête, c'est un vrai appareil
            if is_agent_response or is_manager_request:
                # Promouvoir de pending vers confirmed si nécessaire
                if ip_src in self._pending_devices and ip_src not in self._devices:
                    self._devices[ip_src] = self._pending_devices.pop(ip_src)
                
                # Créer ou mettre à jour l'appareil confirmé
                if ip_src not in self._devices:
                    self._devices[ip_src] = SNMPDevice(ip_src)
                
                self._update_device(ip_src, pkt_data, is_agent=is_agent_response, 
                                   is_manager=is_manager_request)
            else:
                # Paquet inconnu - mettre en pending pour collecter des infos
                if ip_src not in self._devices:
                    if ip_src not in self._pending_devices:
                        self._pending_devices[ip_src] = SNMPDevice(ip_src)
                    self._update_device_basic(self._pending_devices[ip_src], pkt_data)
    
    def _update_device(self, ip: str, pkt_data: Dict, is_agent: bool = False, 
                       is_manager: bool = False):
        """Met à jour un appareil confirmé"""
        device = self._devices[ip]
        device.last_seen = datetime.now()
        device.packet_count += 1
        
        if is_agent:
            device.is_agent = True
            pdu_type = str(pkt_data.get("snmp_pdu_type", "")).lower()
            if "response" in pdu_type:
                device.response_count += 1
            elif "trap" in pdu_type or "inform" in pdu_type:
                device.trap_count += 1
        
        if is_manager:
            device.is_manager = True
            device.request_count += 1
        
        # Infos de base
        self._update_device_basic(device, pkt_data)
    
    def _update_device_basic(self, device: SNMPDevice, pkt_data: Dict):
        """Met à jour les infos de base d'un appareil"""
        # MAC source
        if pkt_data.get("mac_src"):
            device.mac = pkt_data["mac_src"]
            self._detect_vendor_from_mac(device)
        
        # Ports
        if pkt_data.get("port_src"):
            device.ports.add(pkt_data["port_src"])
        
        # Version SNMP
        version = str(pkt_data.get("snmp_version", ""))
        if version == "0":
            device.snmp_versions.add("v1")
        elif version == "1":
            device.snmp_versions.add("v2c")
        elif version == "3":
            device.snmp_versions.add("v3")
        
        # Community (v1/v2c)
        community = pkt_data.get("snmp_community")
        if community and community not in ["", "None", None]:
            device.communities.add(str(community))
        
        # USM User (v3)
        usm_user = pkt_data.get("snmp_usm_user_name")
        if usm_user and usm_user not in ["", "None", None]:
            device.usm_users.add(str(usm_user))
        
        # Erreurs
        error_status = pkt_data.get("snmp_error_status")
        if error_status and str(error_status) not in ["0", "None", ""]:
            device.error_count += 1
        
        # OIDs et infos système
        oids = pkt_data.get("snmp_oidsValues", [])
        if isinstance(oids, str):
            try:
                oids = json.loads(oids).get("oidsValues", [])
            except:
                oids = []
        
        for oid_entry in oids:
            oid = oid_entry.get("oid", "")
            value = oid_entry.get("value", "")
            device.oids_accessed.add(oid)
            
            # Extraire infos système depuis les réponses
            if value and value not in ["None", "", "b''"]:
                if self.OID_SYS_DESCR in oid:
                    device.sys_descr = str(value)[:200]
                    self._detect_device_type(device)
                elif self.OID_SYS_NAME in oid:
                    device.sys_name = str(value)[:100]
                elif self.OID_SYS_LOCATION in oid:
                    device.sys_location = str(value)[:100]
                elif self.OID_SYS_CONTACT in oid:
                    device.sys_contact = str(value)[:100]
                elif self.OID_SYS_OBJECT_ID in oid:
                    device.sys_object_id = str(value)
                    self._detect_vendor_from_oid(device)
        
        # Mettre à jour le status
        self._determine_device_status(device)
    
    def _detect_vendor_from_mac(self, device: SNMPDevice):
        """Détecte le constructeur à partir du préfixe MAC"""
        if not device.mac:
            return
        mac_prefix = device.mac.lower()[:8]
        for prefix, vendor in self.MAC_VENDORS.items():
            if mac_prefix.startswith(prefix.lower()):
                device.vendor = vendor
                return
    
    def _detect_vendor_from_oid(self, device: SNMPDevice):
        """Détecte le constructeur à partir du sysObjectID"""
        if not device.sys_object_id:
            return
        for oid_prefix, vendor in self.VENDOR_OIDS.items():
            if device.sys_object_id.startswith(oid_prefix):
                device.vendor = vendor
                return
    
    def _detect_device_type(self, device: SNMPDevice):
        """Détecte le type d'appareil à partir de sysDescr"""
        if not device.sys_descr:
            return
        
        descr_lower = device.sys_descr.lower()
        
        if any(x in descr_lower for x in ["router", "routeur", "ios", "junos"]):
            device.device_type = "router"
        elif any(x in descr_lower for x in ["switch", "catalyst", "nexus"]):
            device.device_type = "switch"
        elif any(x in descr_lower for x in ["firewall", "asa", "fortigate", "palo"]):
            device.device_type = "firewall"
        elif any(x in descr_lower for x in ["access point", "wireless", "wifi", "ap"]):
            device.device_type = "access_point"
        elif any(x in descr_lower for x in ["printer", "imprimante", "laserjet", "print"]):
            device.device_type = "printer"
        elif any(x in descr_lower for x in ["linux", "ubuntu", "debian", "centos", "rhel"]):
            device.device_type = "server_linux"
        elif any(x in descr_lower for x in ["windows", "microsoft"]):
            device.device_type = "server_windows"
        elif any(x in descr_lower for x in ["ups", "apc", "eaton"]):
            device.device_type = "ups"
        elif any(x in descr_lower for x in ["storage", "nas", "san", "netapp", "synology"]):
            device.device_type = "storage"
        elif any(x in descr_lower for x in ["camera", "ipcam", "video"]):
            device.device_type = "camera"
        else:
            device.device_type = "unknown"
    
    def _determine_device_status(self, device: SNMPDevice):
        """Détermine le status de l'appareil"""
        # Status basé sur l'activité
        elapsed = (datetime.now() - device.last_seen).total_seconds()
        if elapsed > self._inactive_timeout:
            device.status = "inactive"
        elif device.error_count > device.packet_count * 0.5:
            device.status = "suspicious"
        else:
            device.status = "active"
    
    def get_all_devices(self) -> List[Dict]:
        """Retourne la liste de tous les appareils confirmés"""
        with self._lock:
            # Mettre à jour les status
            for device in self._devices.values():
                self._determine_device_status(device)
            
            return [d.to_dict() for d in sorted(
                self._devices.values(), 
                key=lambda x: x.last_seen, 
                reverse=True
            )]
    
    def get_device(self, ip: str) -> Optional[Dict]:
        """Retourne un appareil spécifique"""
        with self._lock:
            if ip in self._devices:
                return self._devices[ip].to_dict()
            return None
    
    def get_statistics(self) -> Dict:
        """Retourne des statistiques globales"""
        with self._lock:
            total = len(self._devices)
            active = sum(1 for d in self._devices.values() if d.status == "active")
            managers = sum(1 for d in self._devices.values() if d.is_manager)
            agents = sum(1 for d in self._devices.values() if d.is_agent)
            
            # Compter par type
            by_type = {}
            for d in self._devices.values():
                by_type[d.device_type] = by_type.get(d.device_type, 0) + 1
            
            # Compter par version SNMP
            by_version = {"v1": 0, "v2c": 0, "v3": 0}
            for d in self._devices.values():
                for v in d.snmp_versions:
                    by_version[v] = by_version.get(v, 0) + 1
            
            return {
                "total_devices": total,
                "active_devices": active,
                "inactive_devices": total - active,
                "managers": managers,
                "agents": agents,
                "by_type": by_type,
                "by_snmp_version": by_version,
                "trusted": sum(1 for d in self._devices.values() if d.is_trusted),
                "ignored": sum(1 for d in self._devices.values() if d.is_ignored)
            }
    
    def set_trusted(self, ip: str, trusted: bool = True):
        """Marque un appareil comme de confiance"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].is_trusted = trusted
                if trusted:
                    self._devices[ip].is_ignored = False  # Un appareil trusted n'est pas ignoré
                return True
        return False
    
    def set_ignored(self, ip: str, ignored: bool = True):
        """Marque un appareil comme ignoré"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].is_ignored = ignored
                if ignored:
                    self._devices[ip].is_trusted = False  # Un appareil ignoré n'est pas trusted
                return True
        return False
    
    def set_custom_name(self, ip: str, name: str):
        """Définit un nom personnalisé pour un appareil"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].custom_name = name if name else None
                return True
        return False
    
    def set_notes(self, ip: str, notes: str):
        """Définit des notes pour un appareil"""
        with self._lock:
            if ip in self._devices:
                self._devices[ip].notes = notes if notes else None
                return True
        return False
    
    def get_trusted_devices(self) -> List[Dict]:
        """Retourne la liste des appareils de confiance"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values() if d.is_trusted]
    
    def get_ignored_devices(self) -> List[Dict]:
        """Retourne la liste des appareils ignorés"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values() if d.is_ignored]
    
    def get_filtered_devices(self, show_ignored: bool = False, show_inactive: bool = True,
                            device_type: str = None) -> List[Dict]:
        """Retourne la liste filtrée des appareils"""
        with self._lock:
            # Mettre à jour les status
            for device in self._devices.values():
                self._determine_device_status(device)
            
            result = []
            for d in self._devices.values():
                # Filtre ignorés
                if d.is_ignored and not show_ignored:
                    continue
                # Filtre inactifs
                if d.status == "inactive" and not show_inactive:
                    continue
                # Filtre type
                if device_type and d.device_type != device_type:
                    continue
                result.append(d.to_dict())
            
            return sorted(result, key=lambda x: x['last_seen'], reverse=True)
    
    def export_devices(self) -> List[Dict]:
        """Exporte tous les appareils pour sauvegarde"""
        with self._lock:
            return [d.to_dict() for d in self._devices.values()]
    
    def delete_device(self, ip: str) -> bool:
        """Supprime un appareil de la liste"""
        with self._lock:
            if ip in self._devices:
                del self._devices[ip]
                return True
        return False
    
    def clear(self):
        """Efface tous les appareils"""
        with self._lock:
            self._devices.clear()
            self._pending_devices.clear()


# =============================================================================
# WIDGET LISTE DES APPAREILS (avec filtres et menu contextuel)
# =============================================================================

class DeviceListWidget(ctk.CTkFrame):
    """Widget affichant la liste des appareils SNMP avec filtres et actions"""
    
    # Icônes par type d'appareil
    DEVICE_ICONS = {
        "router": "🌐",
        "switch": "🔀",
        "firewall": "🛡️",
        "access_point": "📶",
        "printer": "🖨️",
        "server_linux": "🐧",
        "server_windows": "🪟",
        "ups": "🔋",
        "storage": "💾",
        "camera": "📷",
        "unknown": "❓"
    }
    
    def __init__(self, parent, device_manager=None, on_select=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._device_manager = device_manager
        self._on_select = on_select
        self._devices = []
        self._selected_device = None
        
        # Filtres
        self._show_ignored = False
        self._show_inactive = True
        self._filter_type = None
        
        self._build()
        self._create_context_menu()
    
    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=12)
        
        ctk.CTkLabel(header, text="🖥️ Appareils SNMP Découverts",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        self._count_label = ctk.CTkLabel(header, text="0 appareils",
                                        font=ctk.CTkFont(size=12),
                                        text_color=THEME["text_secondary"])
        self._count_label.pack(side="right")
        
        # === BARRE DE FILTRES ===
        filter_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=6)
        filter_frame.pack(fill="x", padx=12, pady=(0, 8))
        
        # Checkbox Afficher ignorés
        self._show_ignored_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(filter_frame, text="Afficher ignorés",
                       variable=self._show_ignored_var,
                       command=self._on_filter_change,
                       font=ctk.CTkFont(size=11),
                       fg_color=THEME["accent"],
                       hover_color=THEME["chart_blue"],
                       height=24).pack(side="left", padx=10, pady=8)
        
        # Checkbox Afficher inactifs
        self._show_inactive_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(filter_frame, text="Afficher inactifs",
                       variable=self._show_inactive_var,
                       command=self._on_filter_change,
                       font=ctk.CTkFont(size=11),
                       fg_color=THEME["accent"],
                       hover_color=THEME["chart_blue"],
                       height=24).pack(side="left", padx=10, pady=8)
        
        # Filtre par type
        ctk.CTkLabel(filter_frame, text="Type:",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(side="left", padx=(20, 5))
        
        type_options = ["Tous", "Router", "Switch", "Firewall", "Server Linux", 
                       "Server Windows", "Printer", "Unknown"]
        self._type_filter = ctk.CTkComboBox(filter_frame, values=type_options,
                                           width=120, height=28,
                                           font=ctk.CTkFont(size=11),
                                           command=self._on_type_filter_change,
                                           fg_color=THEME["bg_input"],
                                           button_color=THEME["accent"])
        self._type_filter.set("Tous")
        self._type_filter.pack(side="left", padx=5, pady=8)
        
        # Bouton Export
        ctk.CTkButton(filter_frame, text="📥 Export",
                     width=80, height=28,
                     font=ctk.CTkFont(size=11),
                     fg_color=THEME["bg_card"],
                     hover_color=THEME["accent"],
                     command=self._export_devices).pack(side="right", padx=10, pady=8)
        
        # En-têtes colonnes
        cols = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=0, height=38)
        cols.pack(fill="x", padx=12)
        cols.pack_propagate(False)
        
        columns = [
            ("", 35), ("IP", 125), ("Hostname", 130), ("Type", 85),
            ("Vendor", 90), ("SNMP", 65), ("Paquets", 60), ("Status", 75)
        ]
        
        for name, width in columns:
            ctk.CTkLabel(cols, text=name, width=width,
                        font=ctk.CTkFont(size=11, weight="bold"),
                        text_color=THEME["text_secondary"], anchor="w").pack(side="left", padx=3, pady=8)
        
        # Liste scrollable
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=THEME["bg_panel"],
                                                 corner_radius=0)
        self._list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    
    def _create_context_menu(self):
        """Crée le menu contextuel (clic droit)"""
        self._context_menu = tk.Menu(self, tearoff=0,
                                    bg=THEME["bg_card"],
                                    fg=THEME["text_primary"],
                                    activebackground=THEME["accent"],
                                    activeforeground="white",
                                    font=("Segoe UI", 10))
        
        self._context_menu.add_command(label="⭐ Marquer comme connu",
                                       command=self._mark_trusted)
        self._context_menu.add_command(label="🚫 Ignorer cet appareil",
                                       command=self._mark_ignored)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="✏️ Renommer...",
                                       command=self._rename_device)
        self._context_menu.add_command(label="📋 Copier IP",
                                       command=self._copy_ip)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="🔄 Réinitialiser status",
                                       command=self._reset_device_status)
        self._context_menu.add_command(label="🗑️ Supprimer",
                                       command=self._delete_device)
    
    def _on_filter_change(self):
        """Appelé quand un filtre change"""
        self._show_ignored = self._show_ignored_var.get()
        self._show_inactive = self._show_inactive_var.get()
        self._refresh_list()
    
    def _on_type_filter_change(self, value):
        """Appelé quand le filtre type change"""
        if value == "Tous":
            self._filter_type = None
        else:
            self._filter_type = value.lower().replace(" ", "_")
        self._refresh_list()
    
    def _refresh_list(self):
        """Rafraîchit la liste avec les filtres actuels"""
        if self._device_manager:
            devices = self._device_manager.get_filtered_devices(
                show_ignored=self._show_ignored,
                show_inactive=self._show_inactive,
                device_type=self._filter_type
            )
            self.update_devices(devices)
    
    def update_devices(self, devices: List[Dict]):
        """Met à jour la liste des appareils (optimisé pour éviter le clignotement)"""
        # Vérifier si la liste a vraiment changé
        new_ips = set(d.get("ip") for d in devices)
        old_ips = set(d.get("ip") for d in self._devices)
        
        # Si même liste d'IPs, juste mettre à jour les compteurs de paquets
        if new_ips == old_ips and len(devices) == len(self._devices):
            # Vérifier si les données importantes ont changé
            data_changed = False
            for new_dev in devices:
                old_dev = next((d for d in self._devices if d.get("ip") == new_dev.get("ip")), None)
                if old_dev:
                    # Comparer les champs qui changent souvent
                    if (new_dev.get("packet_count") != old_dev.get("packet_count") or
                        new_dev.get("status") != old_dev.get("status") or
                        new_dev.get("is_trusted") != old_dev.get("is_trusted") or
                        new_dev.get("is_ignored") != old_dev.get("is_ignored")):
                        data_changed = True
                        break
            
            if not data_changed:
                return  # Rien n'a changé, pas besoin de rafraîchir
        
        self._devices = devices
        self._count_label.configure(text=f"{len(devices)} appareils")
        
        # Effacer les anciennes lignes
        for widget in self._list_frame.winfo_children():
            widget.destroy()
        
        # Créer les nouvelles lignes
        for i, device in enumerate(devices):
            self._create_row(device, i)
    
    def _create_row(self, device: Dict, idx: int):
        # Couleur de fond selon status et trusted/ignored
        is_trusted = device.get("is_trusted", False)
        is_ignored = device.get("is_ignored", False)
        status = device.get("status", "active")
        
        if is_trusted:
            bg = "#1a2f1a"  # Vert foncé
        elif is_ignored:
            bg = "#2a2a2a"  # Gris foncé
        elif status == "inactive":
            bg = THEME["bg_card"]
        elif status == "suspicious":
            bg = "#2d2d1f"  # Jaune foncé
        else:
            bg = THEME["bg_panel"] if idx % 2 == 0 else THEME["bg_card"]
        
        row = ctk.CTkFrame(self._list_frame, fg_color=bg, corner_radius=4, height=36)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)
        
        # Icône (type + trusted/ignored)
        device_type = device.get("device_type", "unknown")
        if is_trusted:
            icon = "⭐"
        elif is_ignored:
            icon = "🚫"
        else:
            icon = self.DEVICE_ICONS.get(device_type, "❓")
        
        ctk.CTkLabel(row, text=icon, width=35,
                    font=ctk.CTkFont(size=14)).pack(side="left", padx=3)
        
        # IP
        ip_color = THEME["success"] if is_trusted else (THEME["text_muted"] if is_ignored else THEME["text_primary"])
        ctk.CTkLabel(row, text=device.get("ip", "?"), width=125,
                    font=ctk.CTkFont(size=11),
                    text_color=ip_color, anchor="w").pack(side="left", padx=3)
        
        # Hostname
        hostname = device.get("hostname", "Inconnu")[:16]
        ctk.CTkLabel(row, text=hostname, width=130,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"], anchor="w").pack(side="left", padx=3)
        
        # Type
        type_text = device_type.replace("_", " ").title()[:11]
        ctk.CTkLabel(row, text=type_text, width=85,
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"], anchor="w").pack(side="left", padx=3)
        
        # Vendor
        vendor = device.get("vendor", "Inconnu")[:11]
        ctk.CTkLabel(row, text=vendor, width=90,
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"], anchor="w").pack(side="left", padx=3)
        
        # Versions SNMP
        versions = device.get("snmp_versions", [])
        versions_str = ", ".join(versions) if versions else "-"
        ctk.CTkLabel(row, text=versions_str, width=65,
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["chart_blue"], anchor="w").pack(side="left", padx=3)
        
        # Paquets
        pkt_count = device.get("packet_count", 0)
        ctk.CTkLabel(row, text=str(pkt_count), width=60,
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_secondary"], anchor="w").pack(side="left", padx=3)
        
        # Status
        if is_trusted:
            status_text = "⭐ Connu"
            status_color = THEME["success"]
        elif is_ignored:
            status_text = "🚫 Ignoré"
            status_color = THEME["text_muted"]
        else:
            status_colors = {
                "active": THEME["success"],
                "inactive": THEME["text_muted"],
                "suspicious": THEME["warning"]
            }
            status_texts = {"active": "● Actif", "inactive": "○ Inactif", "suspicious": "⚠ Suspect"}
            status_text = status_texts.get(status, status)
            status_color = status_colors.get(status, THEME["text_muted"])
        
        ctk.CTkLabel(row, text=status_text, width=75,
                    font=ctk.CTkFont(size=10),
                    text_color=status_color).pack(side="left", padx=3)
        
        # Bind click gauche et droit
        row.bind("<Button-1>", lambda e, d=device: self._on_click(d))
        row.bind("<Button-3>", lambda e, d=device: self._show_context_menu(e, d))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, d=device: self._on_click(d))
            child.bind("<Button-3>", lambda e, d=device: self._show_context_menu(e, d))
    
    def _on_click(self, device: Dict):
        """Clic gauche - sélection"""
        self._selected_device = device
        if self._on_select:
            self._on_select(device)
    
    def _show_context_menu(self, event, device: Dict):
        """Affiche le menu contextuel"""
        self._selected_device = device
        
        # Mettre à jour les labels du menu selon l'état
        if device.get("is_trusted"):
            self._context_menu.entryconfig(0, label="⭐ Retirer de confiance")
        else:
            self._context_menu.entryconfig(0, label="⭐ Marquer comme connu")
        
        if device.get("is_ignored"):
            self._context_menu.entryconfig(1, label="👁️ Ne plus ignorer")
        else:
            self._context_menu.entryconfig(1, label="🚫 Ignorer cet appareil")
        
        try:
            self._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._context_menu.grab_release()
    
    def _mark_trusted(self):
        """Marque/démarque l'appareil comme de confiance"""
        if self._selected_device and self._device_manager:
            ip = self._selected_device.get("ip")
            current = self._selected_device.get("is_trusted", False)
            self._device_manager.set_trusted(ip, not current)
            self._refresh_list()
    
    def _mark_ignored(self):
        """Marque/démarque l'appareil comme ignoré"""
        if self._selected_device and self._device_manager:
            ip = self._selected_device.get("ip")
            current = self._selected_device.get("is_ignored", False)
            self._device_manager.set_ignored(ip, not current)
            self._refresh_list()
    
    def _rename_device(self):
        """Ouvre une popup pour renommer l'appareil"""
        if not self._selected_device:
            return
        
        dialog = ctk.CTkInputDialog(
            text=f"Nouveau nom pour {self._selected_device.get('ip')}:",
            title="Renommer l'appareil"
        )
        new_name = dialog.get_input()
        
        if new_name and self._device_manager:
            self._device_manager.set_custom_name(self._selected_device.get("ip"), new_name)
            self._refresh_list()
    
    def _copy_ip(self):
        """Copie l'IP dans le presse-papiers"""
        if self._selected_device:
            ip = self._selected_device.get("ip", "")
            self.clipboard_clear()
            self.clipboard_append(ip)
    
    def _reset_device_status(self):
        """Réinitialise le status de l'appareil"""
        if self._selected_device and self._device_manager:
            ip = self._selected_device.get("ip")
            self._device_manager.set_trusted(ip, False)
            self._device_manager.set_ignored(ip, False)
            self._refresh_list()
    
    def _delete_device(self):
        """Supprime l'appareil de la liste"""
        if self._selected_device and self._device_manager:
            ip = self._selected_device.get("ip")
            self._device_manager.delete_device(ip)
            self._selected_device = None
            self._refresh_list()
    
    def _export_devices(self):
        """Exporte la liste des appareils en JSON"""
        if not self._device_manager:
            return
        
        devices = self._device_manager.export_devices()
        
        # Créer le fichier
        export_file = os.path.join(os.path.dirname(__file__), "..", "exports", 
                                   f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        os.makedirs(os.path.dirname(export_file), exist_ok=True)
        
        with open(export_file, 'w', encoding='utf-8') as f:
            json.dump(devices, f, indent=2, ensure_ascii=False)
        
        # Notification
        print(f"[+] Appareils exportés: {export_file}")


class DeviceDetailPanel(ctk.CTkFrame):
    """Panneau de détails d'un appareil SNMP avec boutons d'action"""
    
    def __init__(self, parent, device_manager=None, on_action=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._device_manager = device_manager
        self._on_action = on_action  # Callback pour rafraîchir après action
        self._current_device = None
        self._build()
    
    def _build(self):
        # Header avec boutons
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(12, 8))
        
        ctk.CTkLabel(header, text="📋 Détails de l'appareil",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        # Boutons d'action
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        
        self._btn_trust = ctk.CTkButton(btn_frame, text="⭐ Confiance",
                                       width=90, height=28,
                                       font=ctk.CTkFont(size=11),
                                       fg_color=THEME["success"],
                                       hover_color="#2ea043",
                                       command=self._toggle_trusted)
        self._btn_trust.pack(side="left", padx=3)
        
        self._btn_ignore = ctk.CTkButton(btn_frame, text="🚫 Ignorer",
                                        width=80, height=28,
                                        font=ctk.CTkFont(size=11),
                                        fg_color=THEME["bg_panel"],
                                        hover_color=THEME["error"],
                                        command=self._toggle_ignored)
        self._btn_ignore.pack(side="left", padx=3)
        
        ctk.CTkButton(btn_frame, text="📋",
                     width=32, height=28,
                     font=ctk.CTkFont(size=12),
                     fg_color=THEME["bg_panel"],
                     hover_color=THEME["accent"],
                     command=self._copy_ip).pack(side="left", padx=3)
        
        # Zone de texte
        self._text = ctk.CTkTextbox(self, fg_color=THEME["bg_panel"],
                                   font=ctk.CTkFont(family="Courier", size=12),
                                   text_color=THEME["text_primary"])
        self._text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._text.insert("1.0", "Sélectionnez un appareil pour voir les détails...")
        self._text.configure(state="disabled")
    
    def show_device(self, device: Dict):
        """Affiche les détails d'un appareil"""
        self._current_device = device
        
        # Mettre à jour les boutons
        self._update_buttons()
        
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        
        # Déterminer rôle
        roles = []
        if device.get("is_manager"):
            roles.append("Manager (envoie des requêtes)")
        if device.get("is_agent"):
            roles.append("Agent (répond aux requêtes)")
        role_str = " & ".join(roles) if roles else "Non déterminé"
        
        # Versions SNMP
        versions = device.get("snmp_versions", [])
        versions_str = ", ".join(versions) if versions else "Non détecté"
        
        # Communities
        communities = device.get("communities", [])
        communities_str = ", ".join(communities) if communities else "N/A"
        
        # USM Users (v3)
        usm_users = device.get("usm_users", [])
        usm_str = ", ".join(usm_users) if usm_users else "N/A"
        
        # Ports
        ports = device.get("ports", [])
        ports_str = ", ".join(str(p) for p in sorted(ports)) if ports else "N/A"
        
        # Status spécial
        is_trusted = device.get("is_trusted", False)
        is_ignored = device.get("is_ignored", False)
        if is_trusted:
            status_display = "⭐ CONFIANCE"
        elif is_ignored:
            status_display = "🚫 IGNORÉ"
        else:
            status_display = device.get('status', 'N/A').upper()
        
        # Nom personnalisé
        custom_name = device.get("custom_name")
        name_display = f"{custom_name} (personnalisé)" if custom_name else device.get('hostname', 'Inconnu')
        
        text = f"""
═══════════════════════════════════════════════════════════════
  APPAREIL SNMP  {status_display}
═══════════════════════════════════════════════════════════════

  ▸ IDENTIFICATION
  ─────────────────────────────────────────────────────────────
    Adresse IP:      {device.get('ip', 'N/A')}
    Adresse MAC:     {device.get('mac', 'N/A')}
    Hostname:        {name_display}
    Vendor:          {device.get('vendor', 'Inconnu')}
    Type:            {device.get('device_type', 'unknown').replace('_', ' ').title()}

  ▸ INFORMATIONS SYSTÈME (MIB-2)
  ─────────────────────────────────────────────────────────────
    sysName:         {device.get('sys_name', 'N/A')}
    sysDescr:        {(device.get('sys_descr') or 'N/A')[:60]}
    sysLocation:     {device.get('sys_location', 'N/A')}

  ▸ SNMP
  ─────────────────────────────────────────────────────────────
    Versions:        {versions_str}
    Communities:     {communities_str}
    USM Users (v3):  {usm_str}
    Ports utilisés:  {ports_str}
    Rôle:            {role_str}

  ▸ STATISTIQUES
  ─────────────────────────────────────────────────────────────
    Total paquets:   {device.get('packet_count', 0)}
    Requêtes:        {device.get('request_count', 0)}
    Réponses:        {device.get('response_count', 0)}
    Traps:           {device.get('trap_count', 0)}
    Erreurs:         {device.get('error_count', 0)}
    OIDs accédés:    {device.get('oids_count', 0)}

  ▸ ACTIVITÉ
  ─────────────────────────────────────────────────────────────
    Première vue:    {device.get('first_seen', 'N/A')}
    Dernière vue:    {device.get('last_seen', 'N/A')}

═══════════════════════════════════════════════════════════════

  💡 Clic droit sur un appareil pour plus d'options
"""
        
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")
    
    def _update_buttons(self):
        """Met à jour l'apparence des boutons selon l'état"""
        if not self._current_device:
            return
        
        is_trusted = self._current_device.get("is_trusted", False)
        is_ignored = self._current_device.get("is_ignored", False)
        
        if is_trusted:
            self._btn_trust.configure(text="⭐ Retiré", fg_color=THEME["warning"])
        else:
            self._btn_trust.configure(text="⭐ Confiance", fg_color=THEME["success"])
        
        if is_ignored:
            self._btn_ignore.configure(text="👁️ Afficher", fg_color=THEME["accent"])
        else:
            self._btn_ignore.configure(text="🚫 Ignorer", fg_color=THEME["bg_panel"])
    
    def _toggle_trusted(self):
        """Toggle l'état trusted"""
        if self._current_device and self._device_manager:
            ip = self._current_device.get("ip")
            current = self._current_device.get("is_trusted", False)
            self._device_manager.set_trusted(ip, not current)
            self._current_device["is_trusted"] = not current
            self._current_device["is_ignored"] = False
            self._update_buttons()
            self.show_device(self._current_device)
            if self._on_action:
                self._on_action()
    
    def _toggle_ignored(self):
        """Toggle l'état ignored"""
        if self._current_device and self._device_manager:
            ip = self._current_device.get("ip")
            current = self._current_device.get("is_ignored", False)
            self._device_manager.set_ignored(ip, not current)
            self._current_device["is_ignored"] = not current
            self._current_device["is_trusted"] = False
            self._update_buttons()
            self.show_device(self._current_device)
            if self._on_action:
                self._on_action()
    
    def _copy_ip(self):
        """Copie l'IP dans le presse-papiers"""
        if self._current_device:
            ip = self._current_device.get("ip", "")
            self.clipboard_clear()
            self.clipboard_append(ip)


# =============================================================================
# LISTE DES PAQUETS AMÉLIORÉE
# =============================================================================

class PacketListWidget(ctk.CTkFrame):
    """Liste des paquets avec coloration selon l'analyse - Polices agrandies"""
    
    def __init__(self, parent, on_select=None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._on_select = on_select
        self.packets = []
        self._rows = []
        self._lock = Lock()
        self._build()
    
    def _build(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=12)
        
        ctk.CTkLabel(header, text="📦 Paquets SNMP",
                    font=ctk.CTkFont(size=15, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        self._count_label = ctk.CTkLabel(header, text="0 paquets",
                                        font=ctk.CTkFont(size=12),
                                        text_color=THEME["text_secondary"])
        self._count_label.pack(side="right")
        
        # En-têtes colonnes
        cols = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=0, height=36)
        cols.pack(fill="x", padx=12)
        cols.pack_propagate(False)
        
        columns = [("#", 45), ("Heure", 85), ("Source", 130), ("Dest", 130), 
                   ("PDU", 100), ("Community", 90), ("Tag", 55)]
        
        for name, width in columns:
            ctk.CTkLabel(cols, text=name, width=width,
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=THEME["text_secondary"], anchor="w").pack(side="left", padx=4, pady=8)
        
        # Liste scrollable
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color=THEME["bg_panel"],
                                                 corner_radius=0)
        self._list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
    
    def add_packet(self, pkt: Dict):
        """Ajoute un paquet à la liste"""
        with self._lock:
            self.packets.append(pkt)
            idx = len(self.packets) - 1
            
            if len(self._rows) >= 200:
                old = self._rows.pop(0)
                try:
                    old.destroy()
                except:
                    pass
            
            self._create_row(pkt, idx)
            self._count_label.configure(text=f"{len(self.packets)} paquets")
        
        try:
            self._list_frame._parent_canvas.yview_moveto(1.0)
        except:
            pass
    
    def _create_row(self, pkt: Dict, idx: int):
        tag = pkt.get('tag', 0)
        error_status = pkt.get('snmp_error_status', 0)
        pdu_type = str(pkt.get('snmp_pdu_type', 'N/A'))
        
        # Couleur de fond selon l'état
        if error_status and error_status != 0:
            bg = "#2d1f1f"  # Rouge foncé - erreur
        elif tag == 1:
            bg = "#2d2d1f"  # Jaune foncé - suspect
        elif 'trap' in pdu_type.lower():
            bg = "#1f2d2d"  # Cyan foncé - trap
        else:
            bg = THEME["bg_card"] if idx % 2 == 0 else THEME["bg_panel"]
        
        row = ctk.CTkFrame(self._list_frame, fg_color=bg, corner_radius=4, height=34)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)
        
        # Numéro
        ctk.CTkLabel(row, text=str(idx + 1), width=45,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"], anchor="w").pack(side="left", padx=4)
        
        # Timestamp
        ts = str(pkt.get('time_stamp', ''))[-8:]
        ctk.CTkLabel(row, text=ts, width=85,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_primary"], anchor="w").pack(side="left", padx=4)
        
        # Source IP
        ctk.CTkLabel(row, text=str(pkt.get('ip_src', ''))[:16], width=130,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_primary"], anchor="w").pack(side="left", padx=4)
        
        # Dest IP
        ctk.CTkLabel(row, text=str(pkt.get('ip_dst', ''))[:16], width=130,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"], anchor="w").pack(side="left", padx=4)
        
        # PDU Type avec couleur
        pdu_colors = {
            "SNMPget": THEME["chart_blue"],
            "SNMPgetnext": THEME["chart_purple"],
            "SNMPbulk": THEME["chart_cyan"],
            "SNMPset": THEME["chart_orange"],
            "SNMPresponse": THEME["chart_green"],
            "SNMPtrap": THEME["chart_red"],
            "SNMPv2trap": THEME["chart_pink"],
        }
        pdu_color = pdu_colors.get(pdu_type, THEME["text_secondary"])
        
        ctk.CTkLabel(row, text=pdu_type[:12], width=100,
                    font=ctk.CTkFont(size=11),
                    text_color=pdu_color, anchor="w").pack(side="left", padx=4)
        
        # Community
        ctk.CTkLabel(row, text=str(pkt.get('snmp_community', ''))[:10], width=90,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"], anchor="w").pack(side="left", padx=4)
        
        # Tag
        tag_text = "⚠️" if tag == 1 else "✓"
        tag_color = THEME["warning"] if tag == 1 else THEME["success"]
        ctk.CTkLabel(row, text=tag_text, width=55,
                    font=ctk.CTkFont(size=11),
                    text_color=tag_color).pack(side="left", padx=4)
        
        # Bind click
        row.bind("<Button-1>", lambda e, p=pkt: self._on_click(p))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, p=pkt: self._on_click(p))
        
        self._rows.append(row)
    
    def _on_click(self, pkt):
        if self._on_select:
            self._on_select(pkt)
    
    def clear(self):
        with self._lock:
            self.packets.clear()
            for row in self._rows:
                try:
                    row.destroy()
                except:
                    pass
            self._rows.clear()
            self._count_label.configure(text="0 paquets")
    
    def get_stats(self):
        with self._lock:
            total = len(self.packets)
            suspects = sum(1 for p in self.packets if p.get('tag') == 1)
            errors = sum(1 for p in self.packets if p.get('snmp_error_status', 0) != 0)
        return {"total": total, "suspects": suspects, "errors": errors}


# =============================================================================
# PANNEAU DE DÉTAILS PAQUET
# =============================================================================

class PacketDetailPanel(ctk.CTkFrame):
    """Panneau de détails d'un paquet - Support SNMPv1/v2c/v3"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        self._build()
    
    def _build(self):
        # Header
        ctk.CTkLabel(self, text="📋 Détails du paquet",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=18, pady=(15, 10))
        
        # Zone de texte - POLICE PLUS GRANDE
        self._text = ctk.CTkTextbox(self, fg_color=THEME["bg_panel"],
                                   font=ctk.CTkFont(family="Courier", size=13),
                                   text_color=THEME["text_primary"])
        self._text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._text.insert("1.0", "Sélectionnez un paquet pour voir les détails...")
        self._text.configure(state="disabled")
    
    def show_packet(self, pkt: Dict):
        """Affiche les détails d'un paquet (v1/v2c/v3)"""
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        
        # Parser les OIDs
        oids = pkt.get('snmp_oidsValues', [])
        if isinstance(oids, str):
            try:
                oids = json.loads(oids).get('oidsValues', [])
            except:
                oids = []
        
        # Déterminer la version
        version_raw = str(pkt.get('snmp_version', '1'))
        if version_raw == '0':
            version = "SNMPv1"
        elif version_raw == '3':
            version = "SNMPv3"
        else:
            version = "SNMPv2c"
        
        tag_str = "⚠️ SUSPECT" if pkt.get('tag') == 1 else "✓ OK"
        
        text = f"""
═══════════════════════════════════════════════════════════
  TIMESTAMP:  {pkt.get('time_stamp', 'N/A')}
  VERSION:    {version}
═══════════════════════════════════════════════════════════

  ▸ RÉSEAU
  ─────────────────────────────────────────────────────────
    MAC Source:      {str(pkt.get('mac_src', 'N/A'))}
    MAC Destination: {str(pkt.get('mac_dst', 'N/A'))}
    IP Source:       {str(pkt.get('ip_src', 'N/A'))}
    IP Destination:  {str(pkt.get('ip_dst', 'N/A'))}
    Ports:           {pkt.get('port_src', '?')} → {pkt.get('port_dst', '?')}
"""
        
        # Section spécifique SNMPv3
        if version_raw == '3':
            is_auth = "✓" if pkt.get('is_authenticated') else "✗"
            is_priv = "✓" if pkt.get('is_encrypted') else "✗"
            text += f"""
  ▸ SNMPv3 SECURITY
  ─────────────────────────────────────────────────────────
    Security Level:  {pkt.get('security_level', 'N/A')}
    User Name:       {pkt.get('snmp_usm_user_name', 'N/A')}
    Engine ID:       {pkt.get('snmp_usm_engine_id', 'N/A')[:32] if pkt.get('snmp_usm_engine_id') else 'N/A'}...
    Auth Protocol:   {pkt.get('snmp_usm_auth_protocol', 'N/A')} [{is_auth}]
    Priv Protocol:   {pkt.get('snmp_usm_priv_protocol', 'N/A')} [{is_priv}]
    Engine Boots:    {pkt.get('snmp_usm_engine_boots', 'N/A')}
    Engine Time:     {pkt.get('snmp_usm_engine_time', 'N/A')}

  ▸ SNMPv3 PDU
  ─────────────────────────────────────────────────────────
    Message ID:      {pkt.get('snmp_msg_id', 'N/A')}
    PDU Type:        {pkt.get('snmp_pdu_type', 'N/A')}
    Request ID:      {pkt.get('snmp_request_id', 'N/A')}
    Error Status:    {pkt.get('snmp_error_status', 0)}
    Decrypt Status:  {pkt.get('decryption_status', 'N/A')}
"""
        else:
            # SNMPv1/v2c
            text += f"""
  ▸ SNMP
  ─────────────────────────────────────────────────────────
    Community:       {str(pkt.get('snmp_community', 'N/A'))}
    Type PDU:        {str(pkt.get('snmp_pdu_type', 'N/A'))}
    Request ID:      {str(pkt.get('snmp_request_id', 'N/A'))}
    Error Status:    {str(pkt.get('snmp_error_status', 0))}
    Error Index:     {str(pkt.get('snmp_error_index', 0))}
"""
        
        text += f"""
  ▸ STATUS:          {tag_str}

  ▸ OIDs ({len(oids)} variable{'s' if len(oids) > 1 else ''})
  ─────────────────────────────────────────────────────────
"""
        for i, oid in enumerate(oids[:10], 1):
            oid_str = str(oid.get('oid', 'N/A'))
            val_str = str(oid.get('value', 'N/A'))[:60]
            text += f"    [{i}] {oid_str}\n"
            text += f"        Valeur: {val_str}\n\n"
        
        if len(oids) > 10:
            text += f"    ... et {len(oids) - 10} autres OIDs\n"
        
        text += "\n═══════════════════════════════════════════════════════════"
        
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")


# =============================================================================
# CLIENT API REST
# =============================================================================

class APIClientWidget(ctk.CTkFrame):
    """Client API REST simplifié"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_main"], **kwargs)
        self._base_url = "http://127.0.0.1:5000"
        self._build()
    
    def _build(self):
        if not REQUESTS_AVAILABLE:
            ctk.CTkLabel(self, text="Module 'requests' requis\npip install requests",
                        font=ctk.CTkFont(size=14),
                        text_color=THEME["error"]).pack(pady=50)
            return
        
        # Header
        header = ctk.CTkFrame(self, fg_color=THEME["bg_card"], corner_radius=8)
        header.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkLabel(header, text="🔌 API REST",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left", padx=15, pady=12)
        
        # URL
        url_frame = ctk.CTkFrame(header, fg_color="transparent")
        url_frame.pack(side="right", padx=15, pady=12)
        
        ctk.CTkLabel(url_frame, text="URL:", 
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(side="left", padx=5)
        
        self._url_entry = ctk.CTkEntry(url_frame, width=180, height=30,
                                      fg_color=THEME["bg_input"])
        self._url_entry.insert(0, self._base_url)
        self._url_entry.pack(side="left", padx=5)
        
        # Requête
        req_frame = ctk.CTkFrame(self, fg_color=THEME["bg_card"], corner_radius=8)
        req_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        row = ctk.CTkFrame(req_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=12)
        
        self._method_var = ctk.StringVar(value="GET")
        ctk.CTkOptionMenu(row, values=["GET", "POST", "PUT", "DELETE"],
                         variable=self._method_var, width=90, height=32,
                         fg_color=THEME["bg_input"]).pack(side="left", padx=5)
        
        self._endpoint_entry = ctk.CTkEntry(row, width=280, height=32,
                                           placeholder_text="/api/status",
                                           fg_color=THEME["bg_input"])
        self._endpoint_entry.insert(0, "/api/status")
        self._endpoint_entry.pack(side="left", padx=10)
        
        ctk.CTkButton(row, text="Envoyer", command=self._send_request,
                     fg_color=THEME["accent"], hover_color=THEME["accent_dark"],
                     width=100, height=32).pack(side="left", padx=5)
        
        # Raccourcis
        shortcuts = ctk.CTkFrame(req_frame, fg_color="transparent")
        shortcuts.pack(fill="x", padx=15, pady=(0, 12))
        
        endpoints = [("/api/status", "Status"), ("/api/stats", "Stats"),
                    ("/api/packets", "Packets"), ("/api/alerts", "Alerts"),
                    ("/api/profiles", "Profiles")]
        
        for ep, label in endpoints:
            ctk.CTkButton(shortcuts, text=label, width=65, height=26,
                         fg_color=THEME["bg_input"],
                         hover_color=THEME["bg_hover"],
                         font=ctk.CTkFont(size=10),
                         command=lambda e=ep: self._set_endpoint(e)).pack(side="left", padx=2)
        
        # Réponse
        resp_frame = ctk.CTkFrame(self, fg_color=THEME["bg_card"], corner_radius=8)
        resp_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        resp_header = ctk.CTkFrame(resp_frame, fg_color="transparent")
        resp_header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(resp_header, text="Réponse",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        self._status_label = ctk.CTkLabel(resp_header, text="",
                                         font=ctk.CTkFont(size=11),
                                         text_color=THEME["text_muted"])
        self._status_label.pack(side="right")
        
        self._response_text = ctk.CTkTextbox(resp_frame, fg_color=THEME["bg_panel"],
                                            font=ctk.CTkFont(family="Courier", size=11))
        self._response_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _set_endpoint(self, ep):
        self._endpoint_entry.delete(0, "end")
        self._endpoint_entry.insert(0, ep)
    
    def _send_request(self):
        base = self._url_entry.get().strip().rstrip("/")
        endpoint = self._endpoint_entry.get().strip()
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = base + endpoint
        method = self._method_var.get()
        
        self._response_text.delete("1.0", "end")
        self._status_label.configure(text="Envoi...", text_color=THEME["warning"])
        
        def do_request():
            try:
                start = time.time()
                if method == "GET":
                    r = requests.get(url, timeout=10)
                elif method == "POST":
                    r = requests.post(url, json={}, timeout=10)
                elif method == "PUT":
                    r = requests.put(url, json={}, timeout=10)
                else:
                    r = requests.delete(url, timeout=10)
                elapsed = (time.time() - start) * 1000
                
                self.after(0, lambda: self._show_response(r, elapsed))
            except Exception as e:
                self.after(0, lambda: self._show_error(str(e)))
        
        Thread(target=do_request, daemon=True).start()
    
    def _show_response(self, r, elapsed):
        color = THEME["success"] if r.status_code < 400 else THEME["error"]
        self._status_label.configure(text=f"{r.status_code} - {elapsed:.0f}ms", text_color=color)
        try:
            formatted = json.dumps(r.json(), indent=2, ensure_ascii=False)
        except:
            formatted = r.text
        self._response_text.delete("1.0", "end")
        self._response_text.insert("1.0", formatted)
    
    def _show_error(self, msg):
        self._status_label.configure(text="Erreur", text_color=THEME["error"])
        self._response_text.delete("1.0", "end")
        self._response_text.insert("1.0", f"Erreur: {msg}")


# =============================================================================
# APPLICATION PRINCIPALE
# =============================================================================

class MIBurnoutApp(ctk.CTk):
    """Application principale MIBurnout Suite - Style Grafana"""
    
    def __init__(self):
        super().__init__()
        self.title("MIBurnout Suite - SNMP Monitoring & Behavioral Analysis")
        self.geometry("1500x900")
        self.configure(fg_color=THEME["bg_main"])
        
        # Variables
        self._queue = Queue(maxsize=10000)
        self._db = None
        self._config_mgr = None
        self._sniffer = None
        self._analyser = None
        self._detector = None
        
        self._is_capturing = False
        self._stop_event = Event()
        
        self._interface = "eth0"
        self._snmp_filter = "udp port 161 or udp port 162"
        self._db_file = "miburnout.db"
        self._config_file = os.path.join(ROOT_DIR, "config", "conf.json")
        self._pcap_dir = os.path.join(ROOT_DIR, "captures")
        
        self._last_pkt_count = 0
        self._pps = 0.0
        self._errors_per_sec = 0
        self._last_error_count = 0
        
        # Données pour les graphiques
        self._pps_history = deque(maxlen=60)
        self._threat_history = deque(maxlen=60)
        
        # Analyseur de Baseline
        self._baseline_analyzer = BaselineAnalyzer(
            window_size=60,      # Fenêtre de 60 secondes
            threshold_pct=50.0,  # Alerte si dépassement de 50%
            min_samples=10       # Minimum 10 échantillons avant analyse
        )
        
        # Gestionnaire d'appareils
        self._device_manager = DeviceManager()
        
        # === AUTHENTIFICATION ===
        self._is_authenticated = False
        self._current_user = None
        self._auth_manager = None
        
        if get_auth_manager:
            self._auth_manager = get_auth_manager()
        
        self._setup_ui()
        self._init_core()
        self.after(1000, self._update_loop)
    
    def _init_core(self):
        if not CORE_AVAILABLE:
            self._status_label.configure(text="⚠ Modules core non disponibles", 
                                        text_color=THEME["error"])
            return
        
        try:
            os.makedirs(self._pcap_dir, exist_ok=True)
            os.makedirs(os.path.dirname(self._config_file), exist_ok=True)
            
            self._db = DataBase(dbFile=self._db_file)
            self._db.initDB()
            
            self._config_mgr = ConfAPP(confFile=self._config_file)
            if self._config_mgr.config is None:
                self._config_mgr.creatConf()
            
            self._detector = get_detector()
            
            self._status_label.configure(text="✓ Système prêt", text_color=THEME["success"])
        except Exception as e:
            print(f"[!] Init error: {e}")
            traceback.print_exc()
            self._status_label.configure(text=f"⚠ Erreur: {e}", text_color=THEME["error"])
    
    def _setup_ui(self):
        self.grid_columnconfigure(1, weight=1)  # Colonne contenu principal
        self.grid_rowconfigure(0, weight=1)
        
        # ===== SIDEBAR GAUCHE =====
        self._sidebar = ctk.CTkFrame(self, width=200, fg_color=THEME["bg_panel"], corner_radius=0)
        self._sidebar.grid(row=0, column=0, rowspan=2, sticky="ns")
        self._sidebar.grid_propagate(False)
        
        # Logo dans la sidebar
        logo_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=15, pady=(20, 30))
        
        ctk.CTkLabel(logo_frame, text="MIBurnout",
                    font=ctk.CTkFont(size=20, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w")
        ctk.CTkLabel(logo_frame, text="Suite Pro",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w")
        
        # Menu de navigation
        self._nav_buttons = {}
        self._current_tab = "dashboard"
        
        nav_items = [
            ("dashboard", "Dashboard"),
            ("capture", "Capture"),
            ("devices", "Appareils"),
            ("behavior", "Analyse"),
            ("api", "API"),
            ("profile", "Profil"),
        ]
        
        for tab_id, tab_name in nav_items:
            btn = ctk.CTkButton(
                self._sidebar,
                text=tab_name,
                font=ctk.CTkFont(size=13),
                fg_color="transparent",
                text_color=THEME["text_secondary"],
                hover_color=THEME["bg_hover"],
                anchor="w",
                height=40,
                corner_radius=6,
                command=lambda t=tab_id: self._switch_tab(t)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self._nav_buttons[tab_id] = btn
        
        # Sélectionner le premier onglet
        self._nav_buttons["dashboard"].configure(
            fg_color=THEME["accent"],
            text_color=THEME["text_primary"]
        )
        
        # Séparateur
        ctk.CTkFrame(self._sidebar, height=1, fg_color=THEME["border"]).pack(fill="x", padx=15, pady=20)
        
        # Contrôles de capture dans la sidebar
        capture_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        capture_frame.pack(fill="x", padx=15)
        
        ctk.CTkLabel(capture_frame, text="CAPTURE",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=THEME["text_muted"]).pack(anchor="w", pady=(0, 8))
        
        ctk.CTkLabel(capture_frame, text="Interface:",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w")
        
        self._if_entry = ctk.CTkEntry(capture_frame, height=32,
                                     fg_color=THEME["bg_input"],
                                     border_color=THEME["border"])
        self._if_entry.insert(0, self._interface)
        self._if_entry.pack(fill="x", pady=(3, 10))
        
        btn_frame = ctk.CTkFrame(capture_frame, fg_color="transparent")
        btn_frame.pack(fill="x")
        
        self._start_btn = ctk.CTkButton(btn_frame, text="Demarrer",
                                       command=self.start_capture,
                                       fg_color=THEME["success"],
                                       hover_color="#2ea043",
                                       height=32,
                                       font=ctk.CTkFont(size=11, weight="bold"))
        self._start_btn.pack(side="left", fill="x", expand=True, padx=(0, 3))
        
        self._stop_btn = ctk.CTkButton(btn_frame, text="Stop",
                                      command=self.stop_capture,
                                      fg_color=THEME["error"],
                                      hover_color="#da3633",
                                      height=32,
                                      font=ctk.CTkFont(size=11, weight="bold"),
                                      state="disabled")
        self._stop_btn.pack(side="right", fill="x", expand=True, padx=(3, 0))
        
        # Indicateur de capture
        self._capture_indicator = ctk.CTkLabel(capture_frame, text="ARRETE",
                                              font=ctk.CTkFont(size=10, weight="bold"),
                                              text_color=THEME["text_muted"])
        self._capture_indicator.pack(pady=(10, 0))
        
        # Spacer
        ctk.CTkFrame(self._sidebar, fg_color="transparent").pack(fill="both", expand=True)
        
        # Info utilisateur en bas de la sidebar
        user_frame = ctk.CTkFrame(self._sidebar, fg_color=THEME["bg_card"], corner_radius=6)
        user_frame.pack(fill="x", padx=10, pady=15)
        
        self._user_indicator = ctk.CTkLabel(user_frame, text="",
                                           font=ctk.CTkFont(size=11, weight="bold"),
                                           text_color=THEME["text_primary"])
        self._user_indicator.pack(anchor="w", padx=10, pady=(8, 2))
        
        self._user_role_label = ctk.CTkLabel(user_frame, text="",
                                            font=ctk.CTkFont(size=10),
                                            text_color=THEME["text_muted"])
        self._user_role_label.pack(anchor="w", padx=10, pady=(0, 8))
        
        # ===== CONTENU PRINCIPAL =====
        main_container = ctk.CTkFrame(self, fg_color=THEME["bg_main"], corner_radius=0)
        main_container.grid(row=0, column=1, sticky="nsew")
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(0, weight=1)
        
        # Header du contenu principal
        header = ctk.CTkFrame(main_container, height=50, fg_color=THEME["bg_panel"], corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        self._page_title = ctk.CTkLabel(header, text="Dashboard",
                                       font=ctk.CTkFont(size=18, weight="bold"),
                                       text_color=THEME["text_primary"])
        self._page_title.pack(side="left", padx=20, pady=10)
        
        self._time_label = ctk.CTkLabel(header, text="",
                                       font=ctk.CTkFont(size=11),
                                       text_color=THEME["text_muted"])
        self._time_label.pack(side="right", padx=20)
        
        ctk.CTkButton(header, text="Effacer", width=80, height=30,
                     fg_color=THEME["bg_input"],
                     hover_color=THEME["error"],
                     font=ctk.CTkFont(size=11),
                     command=self.clear_all).pack(side="right", padx=5)
        
        # Container pour les pages
        self._pages_container = ctk.CTkFrame(main_container, fg_color=THEME["bg_main"])
        self._pages_container.pack(fill="both", expand=True, padx=10, pady=10)
        self._pages_container.grid_columnconfigure(0, weight=1)
        self._pages_container.grid_rowconfigure(0, weight=1)
        
        # Créer toutes les pages
        self._pages = {}
        
        self._pages["dashboard"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["capture"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["devices"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["behavior"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["api"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        self._pages["profile"] = ctk.CTkFrame(self._pages_container, fg_color="transparent")
        
        for page in self._pages.values():
            page.grid(row=0, column=0, sticky="nsew")
        
        # Construire le contenu de chaque page
        self._build_dashboard_tab(self._pages["dashboard"])
        self._build_capture_tab(self._pages["capture"])
        self._build_devices_tab(self._pages["devices"])
        self._build_behavior_tab(self._pages["behavior"])
        self._build_api_tab(self._pages["api"])
        self._build_profile_tab(self._pages["profile"])
        
        # Afficher la page dashboard par défaut
        self._pages["dashboard"].tkraise()
        
        # ===== STATUS BAR =====
        statusbar = ctk.CTkFrame(main_container, height=28, fg_color=THEME["bg_panel"], corner_radius=0)
        statusbar.pack(fill="x", side="bottom")
        
        self._status_label = ctk.CTkLabel(statusbar, text="Initialisation...",
                                         font=ctk.CTkFont(size=10),
                                         text_color=THEME["text_muted"])
        self._status_label.pack(side="left", padx=15, pady=5)
        
        self._user_status = ctk.CTkLabel(statusbar, text="",
                                        font=ctk.CTkFont(size=10),
                                        text_color=THEME["info"])
        self._user_status.pack(side="right", padx=10)
        
        core_txt = "Core OK" if CORE_AVAILABLE else "Core ERR"
        core_col = THEME["success"] if CORE_AVAILABLE else THEME["error"]
        ctk.CTkLabel(statusbar, text=core_txt, font=ctk.CTkFont(size=10),
                    text_color=core_col).pack(side="right", padx=15)
    
    def _switch_tab(self, tab_id: str):
        """Change l'onglet actif."""
        # Reset tous les boutons
        for btn_id, btn in self._nav_buttons.items():
            btn.configure(
                fg_color="transparent",
                text_color=THEME["text_secondary"]
            )
        
        # Activer le bouton sélectionné
        self._nav_buttons[tab_id].configure(
            fg_color=THEME["accent"],
            text_color=THEME["text_primary"]
        )
        
        # Changer le titre
        titles = {
            "dashboard": "Dashboard",
            "capture": "Capture",
            "devices": "Appareils",
            "behavior": "Analyse Comportementale",
            "api": "API REST",
            "profile": "Profil"
        }
        self._page_title.configure(text=titles.get(tab_id, tab_id))
        
        # Afficher la page correspondante
        self._pages[tab_id].tkraise()
        self._current_tab = tab_id
        
        # Rafraîchir le profil si nécessaire
        if tab_id == "profile":
            self._update_profile_visibility()
    
    def _build_dashboard_tab(self, tab):
        """Construit l'onglet Dashboard style Grafana"""
        tab.grid_columnconfigure((0, 1, 2, 3), weight=1)
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_rowconfigure(2, weight=1)
        
        # ROW 0: Stats cards
        self._stat_packets = StatCard(tab, title="Total Paquets", icon="📦", color=THEME["chart_blue"])
        self._stat_packets.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        self._stat_pps = StatCard(tab, title="Paquets/sec", icon="📈", color=THEME["chart_green"])
        self._stat_pps.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        self._stat_suspects = StatCard(tab, title="Suspects", icon="⚠️", color=THEME["warning"])
        self._stat_suspects.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        
        self._stat_alerts = StatCard(tab, title="Alertes", icon="🚨", color=THEME["error"])
        self._stat_alerts.grid(row=0, column=3, sticky="nsew", padx=5, pady=5)
        
        # ROW 1: Graphiques temps réel
        # Graphique PPS
        self._chart_pps = TimeSeriesChart(tab, title="📈 Débit (Paquets/sec)", ylabel="PPS")
        self._chart_pps.add_series("PPS", THEME["chart_green"])
        self._chart_pps.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # Graphique menaces
        self._chart_threat = TimeSeriesChart(tab, title="🔴 Niveau de Menace (%)", ylabel="%")
        self._chart_threat.add_series("Threat", THEME["chart_red"])
        self._chart_threat.grid(row=1, column=2, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # ROW 2: Jauges et Distribution
        gauges_frame = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=8)
        gauges_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        gauges_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        self._gauge_threat = GaugeChart(gauges_frame, title="Menace", max_val=100, unit="%")
        self._gauge_threat.grid(row=0, column=0, padx=10, pady=10)
        
        self._gauge_errors = GaugeChart(gauges_frame, title="Erreurs", max_val=100, unit="%",
                                       thresholds={"warning": 10, "critical": 25})
        self._gauge_errors.grid(row=0, column=1, padx=10, pady=10)
        
        self._gauge_reputation = GaugeChart(gauges_frame, title="Réputation Min", max_val=100, unit="%",
                                           thresholds={"warning": 40, "critical": 20})
        self._gauge_reputation.grid(row=0, column=2, padx=10, pady=10)
        
        # Distribution PDU
        self._chart_pdu = BarChart(tab, title="📊 Distribution PDU")
        self._chart_pdu.grid(row=2, column=2, columnspan=2, sticky="nsew", padx=5, pady=5)
    
    def _build_capture_tab(self, tab):
        """Construit l'onglet Capture"""
        tab.grid_columnconfigure(0, weight=3)
        tab.grid_columnconfigure(1, weight=2)
        tab.grid_rowconfigure(0, weight=1)
        
        # Liste des paquets (gauche)
        self._packet_list = PacketListWidget(tab, on_select=self._on_packet_select)
        self._packet_list.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)
        
        # Détails (droite)
        right_frame = ctk.CTkFrame(tab, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)
        right_frame.grid_rowconfigure(0, weight=1)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)
        
        self._packet_detail = PacketDetailPanel(right_frame)
        self._packet_detail.grid(row=0, column=0, sticky="nsew", pady=(0, 3))
        
        self._alert_panel = AlertPanel(right_frame)
        self._alert_panel.grid(row=1, column=0, sticky="nsew", pady=(3, 0))
    
    def _build_devices_tab(self, tab):
        """Construit l'onglet Appareils"""
        tab.grid_columnconfigure(0, weight=3)
        tab.grid_columnconfigure(1, weight=2)
        tab.grid_rowconfigure(1, weight=1)
        
        # Header avec stats
        header = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=8)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        ctk.CTkLabel(header, text="🖥️ Découverte d'Appareils SNMP",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left", padx=20, pady=15)
        
        self._device_stats_label = ctk.CTkLabel(header, text="0 appareils découverts",
                                               font=ctk.CTkFont(size=12),
                                               text_color=THEME["text_secondary"])
        self._device_stats_label.pack(side="right", padx=20)
        
        # Stats cards
        stats_frame = ctk.CTkFrame(tab, fg_color="transparent")
        stats_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=(60, 5))
        
        # Mini cards pour les stats
        self._device_stats_cards = {}
        stats_items = [
            ("total", "📊 Total", THEME["chart_blue"]),
            ("active", "✓ Actifs", THEME["success"]),
            ("managers", "📤 Managers", THEME["chart_orange"]),
            ("agents", "📥 Agents", THEME["chart_purple"]),
            ("trusted", "⭐ Connus", THEME["success"]),
            ("ignored", "🚫 Ignorés", THEME["text_muted"]),
        ]
        
        for i, (key, label, color) in enumerate(stats_items):
            card = ctk.CTkFrame(stats_frame, fg_color=THEME["bg_card"], corner_radius=6)
            card.pack(side="left", padx=5, pady=5, fill="x", expand=True)
            
            ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=24, weight="bold"),
                        text_color=color).pack(pady=(10, 0))
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10),
                        text_color=THEME["text_muted"]).pack(pady=(0, 10))
            
            self._device_stats_cards[key] = card.winfo_children()[0]
        
        # Liste des appareils (gauche) - avec device_manager
        self._device_list = DeviceListWidget(tab, 
                                            device_manager=self._device_manager,
                                            on_select=self._on_device_select)
        self._device_list.grid(row=1, column=0, sticky="nsew", padx=(5, 3), pady=5)
        
        # Détails appareil (droite) - avec device_manager et callback
        self._device_detail = DeviceDetailPanel(tab, 
                                               device_manager=self._device_manager,
                                               on_action=self._refresh_device_list)
        self._device_detail.grid(row=1, column=1, sticky="nsew", padx=(3, 5), pady=5)
    
    def _on_device_select(self, device: Dict):
        """Callback sélection d'un appareil"""
        self._device_detail.show_device(device)
    
    def _refresh_device_list(self):
        """Rafraîchit la liste des appareils après une action"""
        if hasattr(self, '_device_list'):
            self._device_list._refresh_list()
    
    def _build_behavior_tab(self, tab):
        """Construit l'onglet Analyse Comportementale"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=0)
        tab.grid_rowconfigure(2, weight=1)
        
        # Header avec stats du détecteur
        header = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=8)
        header.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(header, text="🧠 Analyse Comportementale SNMP",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left", padx=20, pady=15)
        
        self._detector_stats_label = ctk.CTkLabel(header, text="",
                                                 font=ctk.CTkFont(size=12),
                                                 text_color=THEME["text_secondary"])
        self._detector_stats_label.pack(side="right", padx=20)
        
        # Panneau Baseline
        self._baseline_panel = BaselinePanel(tab, self._baseline_analyzer)
        self._baseline_panel.pack(fill="x", padx=5, pady=5)
        
        # Profils IP
        self._ip_table = IPProfileTable(tab)
        self._ip_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Liste des alertes baseline
        alerts_frame = ctk.CTkFrame(tab, fg_color=THEME["bg_card"], corner_radius=8)
        alerts_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(alerts_frame, text="🚨 Alertes de Dépassement de Seuil",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["text_primary"]).pack(anchor="w", padx=18, pady=(12, 8))
        
        self._baseline_alerts_frame = ctk.CTkScrollableFrame(alerts_frame, 
                                                            fg_color=THEME["bg_panel"],
                                                            corner_radius=6, height=120)
        self._baseline_alerts_frame.pack(fill="x", padx=12, pady=(0, 12))
    
    def _build_api_tab(self, tab):
        """Construit l'onglet API"""
        self._api_client = APIClientWidget(tab)
        self._api_client.pack(fill="both", expand=True)
    
    def _build_profile_tab(self, tab):
        """Construit l'onglet Profil utilisateur"""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        
        if not AUTH_WIDGETS_AVAILABLE:
            ctk.CTkLabel(tab, text="Module d'authentification non disponible",
                        font=ctk.CTkFont(size=14),
                        text_color=THEME["error"]).pack(pady=50)
            return
        
        # Panneau de profil (gauche)
        self._profile_panel = ProfilePanel(tab, 
                                          auth_manager=self._auth_manager,
                                          on_logout=self._on_logout)
        self._profile_panel.grid(row=0, column=0, sticky="nsew", padx=(5, 3), pady=5)
        
        # Panneau de gestion utilisateurs (droite) - visible seulement pour admin
        self._user_mgmt_panel = UserManagementPanel(tab, auth_manager=self._auth_manager)
        self._user_mgmt_panel.grid(row=0, column=1, sticky="nsew", padx=(3, 5), pady=5)
        
        # Masquer le panneau de gestion si pas admin
        self._update_profile_visibility()
    
    def _update_profile_visibility(self):
        """Met à jour la visibilité des panneaux selon le rôle."""
        if not hasattr(self, '_profile_panel'):
            return
        
        if self._auth_manager and self._auth_manager.current_user:
            user = self._auth_manager.current_user
            self._profile_panel.update_profile()
            
            # Afficher la gestion des users seulement pour admin
            if user.get("role") == "admin" or "all" in user.get("permissions", []):
                self._user_mgmt_panel.grid()
                self._user_mgmt_panel.refresh()
            else:
                self._user_mgmt_panel.grid_remove()
    
    def _on_logout(self):
        """Callback de déconnexion."""
        self._is_authenticated = False
        self._current_user = None
        
        # Arrêter la capture si en cours
        if self._is_capturing:
            self.stop_capture()
        
        # Fermer l'application et afficher le login
        self.destroy()
    
    def _on_packet_select(self, pkt):
        """Callback sélection d'un paquet"""
        self._packet_detail.show_packet(pkt)
    
    # =========================================================================
    # CAPTURE
    # =========================================================================
    
    def start_capture(self):
        if not CORE_AVAILABLE:
            self._status_label.configure(text="⚠ Modules core non disponibles!", 
                                        text_color=THEME["error"])
            return
        
        if self._is_capturing:
            return
        
        self._interface = self._if_entry.get().strip() or "eth0"
        
        try:
            self._queue = Queue(maxsize=10000)
            self._stop_event.clear()
            
            self._sniffer = Sniffer(iface=self._interface, sfilter=self._snmp_filter, 
                                   queue=self._queue)
            
            cfg = self._config_mgr.config if self._config_mgr else {}
            self._analyser = Analyser(queue=self._queue, baseDB=self._db, config=cfg,
                                     pcap_dir=self._pcap_dir, lenPcap=100)
            
            self._is_capturing = True
            
            Thread(target=self._sniffer.start_sniffer, daemon=True).start()
            Thread(target=self._capture_loop, daemon=True).start()
            
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
            self._capture_indicator.configure(text="● CAPTURE", text_color=THEME["success"])
            self._status_label.configure(text=f"Capture sur {self._interface}...", 
                                        text_color=THEME["success"])
            
        except Exception as e:
            print(f"[!] Start error: {e}")
            traceback.print_exc()
            self._status_label.configure(text=f"⚠ Erreur: {e}", text_color=THEME["error"])
    
    def _capture_loop(self):
        while self._is_capturing and not self._stop_event.is_set():
            try:
                pkt = self._queue.get(timeout=0.5)
            except Empty:
                continue
            except:
                continue
            
            # Analyse du paquet
            try:
                data = self._analyser.packet_info(pkt)
            except:
                data = {"time_stamp": str(datetime.now()), "ip_src": "?", "ip_dst": "?",
                        "snmp_pdu_type": "Unknown", "tag": 0}
            
            # Tag whitelist
            try:
                data["tag"] = 0 if self._analyser.compare(data) else 1
            except:
                data["tag"] = 0
            
            # === DÉCOUVERTE D'APPAREILS ===
            try:
                self._device_manager.process_packet(data)
            except:
                pass
            
            # Analyse comportementale
            try:
                if self._detector:
                    alerts = self._detector.analyze_packet(data)
                    if alerts:
                        for alert in alerts:
                            self.after(0, lambda a=alert: self._alert_panel.add_alert(a))
            except:
                pass
            
            # Sauvegarde DB
            try:
                db_data = self._prepare_db_data(data)
                version = str(data.get("snmp_version", "1"))
                table = "snmp_v1" if version == "0" else "snmp_v2"
                self._db.wrData(table, db_data)
            except:
                pass
            
            # PCAP
            try:
                if self._analyser and hasattr(self._analyser, 'pcap_writer') and self._analyser.pcap_writer:
                    self._analyser.pcap_writer.write(pkt)
                    self._analyser.nb_pkt += 1
                    if self._analyser.nb_pkt >= self._analyser.lenPcap:
                        self._analyser.open_new_pcap()
            except:
                pass
            
            # UI
            try:
                pkt_copy = data.copy()
                self.after(0, lambda d=pkt_copy: self._packet_list.add_packet(d))
            except:
                pass
            
            try:
                self._queue.task_done()
            except:
                pass
    
    def _prepare_db_data(self, data):
        result = {
            "time_stamp": data.get("time_stamp"),
            "mac_src": data.get("mac_src"),
            "mac_dst": data.get("mac_dst"),
            "ip_src": data.get("ip_src"),
            "ip_dst": data.get("ip_dst"),
            "port_src": data.get("port_src"),
            "port_dst": data.get("port_dst"),
            "snmp_community": data.get("snmp_community"),
            "snmp_pdu_type": data.get("snmp_pdu_type"),
            "snmp_oidsValues": json.dumps({"oidsValues": data.get("snmp_oidsValues", [])}),
            "tag": data.get("tag", 0)
        }
        
        version = str(data.get("snmp_version", "1"))
        if version == "0":
            result.update({
                "snmp_enterprise": data.get("snmp_enterprise"),
                "snmp_agent_addr": data.get("snmp_agent_addr"),
                "snmp_generic_trap": data.get("snmp_generic_trap"),
                "snmp_specific_trap": data.get("snmp_specific_trap"),
                "snmp_request_id": data.get("snmp_request_id"),
                "snmp_error_status": data.get("snmp_error_status"),
                "snmp_error_index": data.get("snmp_error_index")
            })
        else:
            result.update({
                "snmp_request_id": data.get("snmp_request_id"),
                "snmp_error_status": data.get("snmp_error_status"),
                "snmp_error_index": data.get("snmp_error_index"),
                "snmp_non_repeaters": data.get("snmp_non_repeaters"),
                "snmp_max_repetitions": data.get("snmp_max_repetitions")
            })
        
        return {k: v for k, v in result.items() if v is not None}
    
    def stop_capture(self):
        self._is_capturing = False
        self._stop_event.set()
        
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._capture_indicator.configure(text="● ARRÊTÉ", text_color=THEME["warning"])
        self._status_label.configure(text="Capture arrêtée", text_color=THEME["text_muted"])
        
        if self._analyser and hasattr(self._analyser, 'pcap_writer') and self._analyser.pcap_writer:
            try:
                self._analyser.pcap_writer.close()
            except:
                pass
    
    def clear_all(self):
        self._packet_list.clear()
        self._alert_panel.clear()
        if self._detector:
            self._detector.clear_alerts()
    
    def _update_loop(self):
        """Boucle de mise à jour UI"""
        now = datetime.now()
        self._time_label.configure(text=now.strftime("%H:%M:%S"))
        
        # Calcul PPS
        current_count = len(self._packet_list.packets)
        self._pps = current_count - self._last_pkt_count
        self._last_pkt_count = current_count
        
        # Stats
        stats = self._packet_list.get_stats()
        total = stats["total"]
        suspects = stats["suspects"]
        errors = stats["errors"]
        
        # Calcul erreurs/sec
        errors_this_sec = errors - self._last_error_count
        self._last_error_count = errors
        
        # === ANALYSE BASELINE ===
        # Ajouter l'échantillon à l'analyseur
        self._baseline_analyzer.add_sample(self._pps, errors_this_sec)
        
        # Vérifier les anomalies de dépassement de seuil
        baseline_alerts = self._baseline_analyzer.check_anomaly(self._pps, errors_this_sec)
        
        # Afficher les alertes baseline
        for alert in baseline_alerts:
            self._add_baseline_alert(alert)
        
        # Mettre à jour le panneau baseline
        if hasattr(self, '_baseline_panel'):
            self._baseline_panel.update_display()
        
        # === FIN ANALYSE BASELINE ===
        
        self._stat_packets.set_value(total)
        self._stat_pps.set_value(int(self._pps))
        self._stat_suspects.set_value(suspects, THEME["error"] if suspects > 0 else THEME["warning"])
        
        # Alertes
        alert_count = 0
        if self._detector:
            alert_count = len(self._detector.alerts) if hasattr(self._detector, 'alerts') else 0
        alert_count += self._baseline_analyzer._alerts_generated
        self._stat_alerts.set_value(alert_count, THEME["error"] if alert_count > 0 else THEME["text_muted"])
        
        # Graphiques temps réel
        self._chart_pps.add_point("PPS", self._pps, now)
        
        threat = (suspects / total * 100) if total > 0 else 0
        self._chart_threat.add_point("Threat", threat, now)
        
        # Mettre à jour les graphiques toutes les 2 secondes
        if now.second % 2 == 0:
            self._chart_pps.update_chart()
            self._chart_threat.update_chart()
        
        # Jauges
        self._gauge_threat.set_value(threat)
        error_rate = (errors / total * 100) if total > 0 else 0
        self._gauge_errors.set_value(error_rate)
        
        # Distribution PDU - mise à jour toutes les 2 secondes
        if now.second % 2 == 0:
            pdu_cnt = {}
            for p in self._packet_list.packets[-500:]:
                pdu = p.get('snmp_pdu_type', 'Unknown')
                pdu_cnt[pdu] = pdu_cnt.get(pdu, 0) + 1
            self._chart_pdu.set_data(pdu_cnt)
        
        # Profils IP et réputation - mise à jour toutes les 3 secondes
        if now.second % 3 == 0 and self._detector:
            profiles = self._detector.get_all_profiles()
            self._ip_table.update_profiles(profiles)
            
            # Réputation minimale
            if profiles:
                min_rep = min(p.get("reputation_score", 100) for p in profiles)
                self._gauge_reputation.set_value(min_rep)
            
            # Stats détecteur
            det_stats = self._detector.get_statistics()
            self._detector_stats_label.configure(
                text=f"Paquets analysés: {det_stats['total_packets_analyzed']} | "
                     f"Alertes comportement: {det_stats['total_alerts_generated']} | "
                     f"IPs bloquées: {det_stats['blocked_ips_count']}"
            )
        
        # === MISE À JOUR DES APPAREILS (toutes les 3 secondes) ===
        if now.second % 3 == 0:
            try:
                # Utiliser get_filtered_devices avec les filtres actuels
                if hasattr(self, '_device_list') and self._device_list._device_manager:
                    self._device_list._refresh_list()
                
                # Stats appareils
                dev_stats = self._device_manager.get_statistics()
                self._device_stats_label.configure(
                    text=f"{dev_stats['total_devices']} appareils découverts | "
                         f"{dev_stats['active_devices']} actifs | "
                         f"{dev_stats.get('trusted', 0)} connus"
                )
                
                # Mettre à jour les mini cards
                if hasattr(self, '_device_stats_cards'):
                    if 'total' in self._device_stats_cards:
                        self._device_stats_cards['total'].configure(text=str(dev_stats['total_devices']))
                    if 'active' in self._device_stats_cards:
                        self._device_stats_cards['active'].configure(text=str(dev_stats['active_devices']))
                    if 'managers' in self._device_stats_cards:
                        self._device_stats_cards['managers'].configure(text=str(dev_stats['managers']))
                    if 'agents' in self._device_stats_cards:
                        self._device_stats_cards['agents'].configure(text=str(dev_stats['agents']))
                    if 'trusted' in self._device_stats_cards:
                        self._device_stats_cards['trusted'].configure(text=str(dev_stats.get('trusted', 0)))
                    if 'ignored' in self._device_stats_cards:
                        self._device_stats_cards['ignored'].configure(text=str(dev_stats.get('ignored', 0)))
            except Exception as e:
                pass
        
        self.after(1000, self._update_loop)
    
    def _add_baseline_alert(self, alert: Dict):
        """Ajoute une alerte baseline à l'interface"""
        if not hasattr(self, '_baseline_alerts_frame'):
            return
        
        # Couleur selon sévérité
        color = THEME["error"] if alert["severity"] == "critical" else THEME["warning"]
        
        # Créer la carte d'alerte
        card = ctk.CTkFrame(self._baseline_alerts_frame, fg_color=THEME["bg_card"], corner_radius=6)
        card.pack(fill="x", pady=3, padx=5)
        
        # Indicateur
        indicator = ctk.CTkFrame(card, fg_color=color, width=4, corner_radius=2)
        indicator.pack(side="left", fill="y")
        
        # Contenu
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="x", expand=True, pady=8, padx=10)
        
        # Header
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")
        
        ctk.CTkLabel(header, text=alert["type"],
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=color).pack(side="left")
        
        ctk.CTkLabel(header, text=alert["timestamp"][-8:],
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(side="right")
        
        # Message
        ctk.CTkLabel(content, text=alert["message"],
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", pady=(3, 0))
        
        # Détails
        details = alert.get("details", {})
        if "deviation_pct" in details:
            ctk.CTkLabel(content, 
                        text=f"Déviation: +{details['deviation_pct']:.1f}% par rapport à la baseline",
                        font=ctk.CTkFont(size=10),
                        text_color=THEME["text_muted"]).pack(anchor="w")
        
        # Limiter le nombre d'alertes affichées
        children = self._baseline_alerts_frame.winfo_children()
        if len(children) > 20:
            children[0].destroy()
    
    def set_authenticated_user(self, user_data: Dict):
        """Configure l'utilisateur authentifié."""
        self._is_authenticated = True
        self._current_user = user_data
        
        # Mettre à jour les indicateurs
        username = user_data.get("username", "?")
        role = user_data.get("role", "?").upper()
        
        self._user_indicator.configure(text=username)
        self._user_role_label.configure(text=role)
        self._user_status.configure(text=f"Connecte: {username} ({role})")
        
        # Mettre à jour le panneau profil
        self._update_profile_visibility()


def run_with_auth():
    """Lance l'application avec authentification obligatoire."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
    
    # Variable pour stocker les données utilisateur
    user_data_result = [None]
    app_closed_by_logout = [False]
    
    def show_login():
        """Affiche la fenêtre de login et retourne True si succès."""
        login_root = ctk.CTk()
        login_root.title("MIBurnout - Connexion")
        login_root.geometry("400x520")
        login_root.resizable(False, False)
        login_root.configure(fg_color=THEME["bg_main"])
        
        # Centrer la fenêtre
        login_root.update_idletasks()
        x = (login_root.winfo_screenwidth() - 400) // 2
        y = (login_root.winfo_screenheight() - 520) // 2
        login_root.geometry(f"400x520+{x}+{y}")
        
        auth = get_auth_manager()
        login_success = [False]
        
        # Interface de login
        # Logo
        ctk.CTkLabel(login_root, text="MIBurnout",
                    font=ctk.CTkFont(size=28, weight="bold"),
                    text_color=THEME["accent"]).pack(pady=(40, 5))
        
        ctk.CTkLabel(login_root, text="Suite Pro",
                    font=ctk.CTkFont(size=14),
                    text_color=THEME["text_secondary"]).pack()
        
        ctk.CTkLabel(login_root, text="Connexion requise",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(pady=(10, 25))
        
        # Formulaire
        form_frame = ctk.CTkFrame(login_root, fg_color=THEME["bg_card"], corner_radius=12)
        form_frame.pack(padx=40, fill="x")
        
        ctk.CTkLabel(form_frame, text="Identifiant",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        
        username_entry = ctk.CTkEntry(form_frame, height=38, fg_color=THEME["bg_input"])
        username_entry.pack(fill="x", padx=20)
        
        ctk.CTkLabel(form_frame, text="Mot de passe",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        
        password_entry = ctk.CTkEntry(form_frame, height=38, show="*", fg_color=THEME["bg_input"])
        password_entry.pack(fill="x", padx=20)
        
        error_label = ctk.CTkLabel(form_frame, text="",
                                  font=ctk.CTkFont(size=11),
                                  text_color=THEME["error"])
        error_label.pack(pady=8)
        
        def do_login():
            username = username_entry.get().strip()
            password = password_entry.get()
            
            if not username or not password:
                error_label.configure(text="Remplissez tous les champs")
                return
            
            success, msg, user = auth.login(username, password)
            
            if success:
                login_success[0] = True
                user_data_result[0] = user
                login_root.quit()
                login_root.destroy()
            else:
                error_label.configure(text=msg)
                password_entry.delete(0, "end")
        
        login_btn = ctk.CTkButton(form_frame, text="Se connecter",
                                 command=do_login,
                                 height=40,
                                 fg_color=THEME["accent"],
                                 font=ctk.CTkFont(size=13, weight="bold"))
        login_btn.pack(fill="x", padx=20, pady=(5, 20))
        
        # Bind Enter
        login_root.bind("<Return>", lambda e: do_login())
        
        # Lien mot de passe oublié
        def show_password_request():
            """Affiche le formulaire de demande de réinitialisation."""
            # Créer une nouvelle fenêtre
            request_window = ctk.CTkToplevel(login_root)
            request_window.title("Demande de reinitialisation")
            request_window.geometry("380x350")
            request_window.resizable(False, False)
            request_window.configure(fg_color=THEME["bg_main"])
            
            # Centrer
            request_window.update_idletasks()
            rx = (request_window.winfo_screenwidth() - 380) // 2
            ry = (request_window.winfo_screenheight() - 350) // 2
            request_window.geometry(f"380x350+{rx}+{ry}")
            
            request_window.transient(login_root)
            request_window.grab_set()
            
            ctk.CTkLabel(request_window, text="Mot de passe oublie",
                        font=ctk.CTkFont(size=18, weight="bold"),
                        text_color=THEME["text_primary"]).pack(pady=(25, 5))
            
            ctk.CTkLabel(request_window, text="Envoyez une demande a l'administrateur",
                        font=ctk.CTkFont(size=11),
                        text_color=THEME["text_muted"]).pack(pady=(0, 20))
            
            req_frame = ctk.CTkFrame(request_window, fg_color=THEME["bg_card"], corner_radius=10)
            req_frame.pack(fill="x", padx=25)
            
            ctk.CTkLabel(req_frame, text="Votre identifiant",
                        font=ctk.CTkFont(size=11),
                        text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(15, 5))
            
            req_username = ctk.CTkEntry(req_frame, height=35, fg_color=THEME["bg_input"])
            req_username.pack(fill="x", padx=15)
            
            # Pré-remplir si un nom est déjà saisi
            current_username = username_entry.get().strip()
            if current_username:
                req_username.insert(0, current_username)
            
            ctk.CTkLabel(req_frame, text="Raison (optionnel)",
                        font=ctk.CTkFont(size=11),
                        text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(10, 5))
            
            req_reason = ctk.CTkTextbox(req_frame, height=60, fg_color=THEME["bg_input"])
            req_reason.pack(fill="x", padx=15, pady=(0, 10))
            
            status_label = ctk.CTkLabel(req_frame, text="",
                                       font=ctk.CTkFont(size=11))
            status_label.pack(pady=5)
            
            def submit_request():
                uname = req_username.get().strip()
                reason = req_reason.get("1.0", "end").strip()
                
                if not uname:
                    status_label.configure(text="Identifiant requis", text_color=THEME["error"])
                    return
                
                # Créer le ticket
                success, msg, ticket_id = auth.create_ticket(
                    username=uname,
                    ticket_type="password_reset",
                    subject=f"Demande de reinitialisation de mot de passe",
                    message=reason if reason else "Aucune raison specifiee"
                )
                
                if success:
                    status_label.configure(
                        text=f"Demande envoyee (Ticket #{ticket_id})",
                        text_color=THEME["success"]
                    )
                    # Fermer après 2 secondes
                    request_window.after(2000, request_window.destroy)
                else:
                    status_label.configure(text=msg, text_color=THEME["error"])
            
            btn_frame = ctk.CTkFrame(req_frame, fg_color="transparent")
            btn_frame.pack(fill="x", padx=15, pady=(5, 15))
            
            ctk.CTkButton(btn_frame, text="Annuler", width=100, height=35,
                         fg_color=THEME["bg_input"],
                         command=request_window.destroy).pack(side="left")
            
            ctk.CTkButton(btn_frame, text="Envoyer", width=100, height=35,
                         fg_color=THEME["success"],
                         command=submit_request).pack(side="right")
        
        # Bouton mot de passe oublié
        forgot_btn = ctk.CTkButton(login_root, text="Mot de passe oublie ?",
                                  command=show_password_request,
                                  fg_color="transparent",
                                  hover_color=THEME["bg_hover"],
                                  text_color=THEME["info"],
                                  font=ctk.CTkFont(size=11),
                                  height=30)
        forgot_btn.pack(pady=(10, 5))
        
        # Info
        ctk.CTkLabel(login_root, text="Identifiants par defaut: admin / admin",
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(pady=10)
        
        # Focus
        username_entry.focus()
        
        # Fermeture = quitter
        def on_close():
            login_root.quit()
            login_root.destroy()
        
        login_root.protocol("WM_DELETE_WINDOW", on_close)
        
        login_root.mainloop()
        
        return login_success[0]
    
    # Boucle principale
    while True:
        # Afficher le login
        if not show_login():
            # Login annulé, quitter
            break
        
        if user_data_result[0] is None:
            break
        
        # Login réussi, lancer l'application
        try:
            app = MIBurnoutApp()
            app.set_authenticated_user(user_data_result[0])
            app.mainloop()
            
            # Vérifier si déconnexion
            if hasattr(app, '_is_authenticated') and not app._is_authenticated:
                # Déconnexion, relancer le login
                user_data_result[0] = None
                continue
            else:
                # Fermeture normale
                break
        except Exception as e:
            print(f"Erreur application: {e}")
            import traceback
            traceback.print_exc()
            break


def main():
    """Point d'entrée principal - authentification obligatoire."""
    print("[*] Demarrage MIBurnout Suite...")
    
    if not AUTH_WIDGETS_AVAILABLE:
        print("[!] Module auth_widgets non disponible")
    
    if not get_auth_manager:
        print("[!] Module auth non disponible")
    
    if get_auth_manager:
        try:
            run_with_auth()
        except Exception as e:
            print(f"[!] Erreur: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("=" * 50)
        print("  ERREUR: Module d'authentification requis")
        print("=" * 50)
        print("\nVerifiez que les fichiers existent:")
        print("  - core/auth.py")
        print("  - gui/auth_widgets.py")


if __name__ == "__main__":
    main()
