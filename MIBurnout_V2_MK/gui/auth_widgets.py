"""
auth_widgets.py - Widgets d'authentification pour MIBurnout GUI
Contient:
- LoginWindow: Fenêtre de connexion
- ProfilePanel: Panneau de profil utilisateur
- UserManagementPanel: Panneau de gestion des utilisateurs (admin)
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from typing import Dict, List, Optional, Callable
import os
import sys

# Ajout du chemin
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, ROOT_DIR)

from core.auth import AuthManager, get_auth_manager, ROLES, PERMISSIONS


# =============================================================================
# THEME (copié de main_gui pour cohérence)
# =============================================================================

THEME = {
    "bg_main": "#0b0c0e",
    "bg_panel": "#141619",
    "bg_card": "#1e2228",
    "bg_input": "#2a2f38",
    "bg_hover": "#353b47",
    "border": "#2a2f38",
    "text_primary": "#e6e9ef",
    "text_secondary": "#8b949e",
    "text_muted": "#5c6370",
    "accent": "#ff6b35",
    "success": "#3fb950",
    "warning": "#d29922",
    "error": "#f85149",
    "info": "#58a6ff",
}


# =============================================================================
# FENÊTRE DE LOGIN
# =============================================================================

class LoginWindow(ctk.CTkToplevel):
    """Fenêtre de connexion modale."""
    
    def __init__(self, parent, on_login_success: Callable = None):
        super().__init__(parent)
        
        self.on_login_success = on_login_success
        self.auth = get_auth_manager()
        self.logged_in = False
        
        # Configuration fenêtre
        self.title("MIBurnout - Connexion")
        self.geometry("400x480")
        self.resizable(False, False)
        self.configure(fg_color=THEME["bg_main"])
        
        # Centrer la fenêtre
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 400) // 2
        y = (self.winfo_screenheight() - 500) // 2
        self.geometry(f"400x500+{x}+{y}")
        
        # Modal
        self.transient(parent)
        self.grab_set()
        
        self._build_ui()
        
        # Focus sur le champ username
        self.after(100, lambda: self.username_entry.focus())
        
        # Bind Enter
        self.bind("<Return>", lambda e: self._login())
    
    def _build_ui(self):
        """Construit l'interface de login."""
        # Logo et titre
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.pack(pady=(40, 20))
        
        ctk.CTkLabel(logo_frame, text="MIBurnout",
                    font=ctk.CTkFont(size=28, weight="bold"),
                    text_color=THEME["accent"]).pack()
        
        ctk.CTkLabel(logo_frame, text="Suite Pro",
                    font=ctk.CTkFont(size=14),
                    text_color=THEME["text_secondary"]).pack(pady=(5, 0))
        
        ctk.CTkLabel(logo_frame, text="Connexion requise",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack(pady=(10, 0))
        
        # Formulaire
        form_frame = ctk.CTkFrame(self, fg_color=THEME["bg_card"], corner_radius=12)
        form_frame.pack(padx=40, pady=20, fill="x")
        
        # Username
        ctk.CTkLabel(form_frame, text="Nom d'utilisateur",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(20, 5))
        
        self.username_entry = ctk.CTkEntry(form_frame, 
                                          placeholder_text="Entrez votre identifiant",
                                          height=40,
                                          fg_color=THEME["bg_input"],
                                          border_color=THEME["border"])
        self.username_entry.pack(padx=20, fill="x")
        
        # Password
        ctk.CTkLabel(form_frame, text="Mot de passe",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=20, pady=(15, 5))
        
        self.password_entry = ctk.CTkEntry(form_frame,
                                          placeholder_text="Entrez votre mot de passe",
                                          show="•",
                                          height=40,
                                          fg_color=THEME["bg_input"],
                                          border_color=THEME["border"])
        self.password_entry.pack(padx=20, fill="x")
        
        # Message d'erreur
        self.error_label = ctk.CTkLabel(form_frame, text="",
                                       font=ctk.CTkFont(size=11),
                                       text_color=THEME["error"])
        self.error_label.pack(pady=(10, 0))
        
        # Bouton login
        self.login_btn = ctk.CTkButton(form_frame, text="Se connecter",
                                       command=self._login,
                                       height=42,
                                       fg_color=THEME["accent"],
                                       hover_color=THEME["accent_light"] if "accent_light" in THEME else THEME["accent"],
                                       font=ctk.CTkFont(size=14, weight="bold"))
        self.login_btn.pack(padx=20, pady=(20, 25), fill="x")
        
        # Info
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.pack(pady=10)
        
        ctk.CTkLabel(info_frame, text="Première connexion ?",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_muted"]).pack()
        
        ctk.CTkLabel(info_frame, text="Utilisateur: admin | Mot de passe: admin",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack()
    
    def _login(self):
        """Tente la connexion."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.error_label.configure(text="Veuillez remplir tous les champs")
            return
        
        self.login_btn.configure(state="disabled", text="Connexion...")
        self.update()
        
        success, message, user_data = self.auth.login(username, password)
        
        if success:
            self.logged_in = True
            self.error_label.configure(text="")
            
            if self.on_login_success:
                self.on_login_success(user_data)
            
            self.destroy()
        else:
            self.error_label.configure(text=message)
            self.login_btn.configure(state="normal", text="Se connecter")
            self.password_entry.delete(0, "end")
            self.password_entry.focus()


# =============================================================================
# PANNEAU DE PROFIL UTILISATEUR
# =============================================================================

class ProfilePanel(ctk.CTkFrame):
    """Panneau de profil utilisateur avec options."""
    
    def __init__(self, parent, auth_manager: AuthManager = None, 
                 on_logout: Callable = None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        
        self.auth = auth_manager or get_auth_manager()
        self.on_logout = on_logout
        
        self._build_ui()
    
    def _build_ui(self):
        """Construit le panneau de profil."""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        
        ctk.CTkLabel(header, text="Mon Profil",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        # Bouton logout
        ctk.CTkButton(header, text="Deconnexion",
                     width=120, height=32,
                     fg_color=THEME["error"],
                     hover_color="#da3633",
                     command=self._logout).pack(side="right")
        
        # Contenu scrollable
        content = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Section Info Utilisateur
        self._info_frame = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        self._info_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(self._info_frame, text="Informations",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(12, 8))
        
        self._info_labels = {}
        for key, label in [("username", "Identifiant"), ("full_name", "Nom complet"),
                           ("email", "Email"), ("role", "Rôle"), ("last_login", "Dernière connexion")]:
            row = ctk.CTkFrame(self._info_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)
            
            ctk.CTkLabel(row, text=f"{label}:",
                        font=ctk.CTkFont(size=12),
                        text_color=THEME["text_secondary"],
                        width=130, anchor="w").pack(side="left")
            
            value_label = ctk.CTkLabel(row, text="-",
                                       font=ctk.CTkFont(size=12),
                                       text_color=THEME["text_primary"])
            value_label.pack(side="left", fill="x", expand=True)
            self._info_labels[key] = value_label
        
        # Padding en bas de la section info
        ctk.CTkFrame(self._info_frame, fg_color="transparent", height=10).pack()
        
        # Section Modifier le mot de passe
        pwd_frame = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        pwd_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(pwd_frame, text="Changer le mot de passe",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(12, 10))
        
        # Ancien mot de passe
        ctk.CTkLabel(pwd_frame, text="Ancien mot de passe",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15)
        self.old_pwd_entry = ctk.CTkEntry(pwd_frame, show="•", height=35,
                                         fg_color=THEME["bg_input"])
        self.old_pwd_entry.pack(fill="x", padx=15, pady=(3, 8))
        
        # Nouveau mot de passe
        ctk.CTkLabel(pwd_frame, text="Nouveau mot de passe",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15)
        self.new_pwd_entry = ctk.CTkEntry(pwd_frame, show="•", height=35,
                                         fg_color=THEME["bg_input"])
        self.new_pwd_entry.pack(fill="x", padx=15, pady=(3, 8))
        
        # Confirmer
        ctk.CTkLabel(pwd_frame, text="Confirmer le nouveau mot de passe",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15)
        self.confirm_pwd_entry = ctk.CTkEntry(pwd_frame, show="•", height=35,
                                             fg_color=THEME["bg_input"])
        self.confirm_pwd_entry.pack(fill="x", padx=15, pady=(3, 8))
        
        self.pwd_status_label = ctk.CTkLabel(pwd_frame, text="",
                                            font=ctk.CTkFont(size=11))
        self.pwd_status_label.pack(pady=3)
        
        ctk.CTkButton(pwd_frame, text="Modifier le mot de passe",
                     command=self._change_password,
                     height=35,
                     fg_color=THEME["accent"]).pack(padx=15, pady=(5, 15))
        
        # Section Permissions
        perms_frame = ctk.CTkFrame(content, fg_color=THEME["bg_panel"], corner_radius=8)
        perms_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(perms_frame, text="Mes permissions",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=15, pady=(12, 8))
        
        self._perms_list = ctk.CTkTextbox(perms_frame, height=100,
                                         fg_color=THEME["bg_input"],
                                         font=ctk.CTkFont(size=11))
        self._perms_list.pack(fill="x", padx=15, pady=(0, 15))
        self._perms_list.configure(state="disabled")
    
    def update_profile(self):
        """Met à jour l'affichage du profil."""
        user = self.auth.current_user
        if not user:
            return
        
        self._info_labels["username"].configure(text=user.get("username", "-"))
        self._info_labels["full_name"].configure(text=user.get("full_name") or "-")
        self._info_labels["email"].configure(text=user.get("email") or "-")
        
        role = user.get("role", "viewer")
        role_info = ROLES.get(role, {})
        role_text = f"{role.upper()} - {role_info.get('description', '')}"
        self._info_labels["role"].configure(text=role_text)
        
        # Dernière connexion
        last = user.get("last_login")
        if last:
            self._info_labels["last_login"].configure(text=last)
        
        # Permissions
        perms = user.get("permissions", [])
        self._perms_list.configure(state="normal")
        self._perms_list.delete("1.0", "end")
        
        if "all" in perms:
            self._perms_list.insert("1.0", "✓ Accès complet (administrateur)")
        else:
            for perm in perms:
                desc = PERMISSIONS.get(perm, perm)
                self._perms_list.insert("end", f"✓ {desc}\n")
        
        self._perms_list.configure(state="disabled")
    
    def _change_password(self):
        """Change le mot de passe de l'utilisateur."""
        old_pwd = self.old_pwd_entry.get()
        new_pwd = self.new_pwd_entry.get()
        confirm_pwd = self.confirm_pwd_entry.get()
        
        if not all([old_pwd, new_pwd, confirm_pwd]):
            self.pwd_status_label.configure(text="Remplissez tous les champs",
                                           text_color=THEME["error"])
            return
        
        if new_pwd != confirm_pwd:
            self.pwd_status_label.configure(text="Les mots de passe ne correspondent pas",
                                           text_color=THEME["error"])
            return
        
        if len(new_pwd) < 6:
            self.pwd_status_label.configure(text="Mot de passe trop court (min 6 car.)",
                                           text_color=THEME["error"])
            return
        
        # Vérifier l'ancien mot de passe
        user = self.auth.current_user
        success, msg, _ = self.auth.login(user["username"], old_pwd)
        
        if not success:
            self.pwd_status_label.configure(text="Ancien mot de passe incorrect",
                                           text_color=THEME["error"])
            return
        
        # Changer le mot de passe
        success, msg = self.auth.update_user(user["id"], password=new_pwd)
        
        if success:
            self.pwd_status_label.configure(text="Mot de passe modifié ✓",
                                           text_color=THEME["success"])
            self.old_pwd_entry.delete(0, "end")
            self.new_pwd_entry.delete(0, "end")
            self.confirm_pwd_entry.delete(0, "end")
        else:
            self.pwd_status_label.configure(text=msg, text_color=THEME["error"])
    
    def _logout(self):
        """Déconnexion."""
        if messagebox.askyesno("Déconnexion", "Voulez-vous vous déconnecter ?"):
            self.auth.logout()
            if self.on_logout:
                self.on_logout()


# =============================================================================
# PANNEAU DE GESTION DES UTILISATEURS (ADMIN)
# =============================================================================

class UserManagementPanel(ctk.CTkFrame):
    """Panneau de gestion des utilisateurs pour les admins."""
    
    def __init__(self, parent, auth_manager: AuthManager = None, **kwargs):
        super().__init__(parent, fg_color=THEME["bg_card"], corner_radius=8, **kwargs)
        
        self.auth = auth_manager or get_auth_manager()
        self._selected_user = None
        
        self._build_ui()
    
    def _build_ui(self):
        """Construit l'interface de gestion."""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 10))
        
        ctk.CTkLabel(header, text="Gestion des Utilisateurs",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        # Bouton nouveau
        ctk.CTkButton(header, text="+ Nouvel utilisateur",
                     width=150, height=32,
                     fg_color=THEME["success"],
                     hover_color="#2ea043",
                     command=self._show_create_dialog).pack(side="right")
        
        # Stats rapides
        self._stats_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=6)
        self._stats_frame.pack(fill="x", padx=15, pady=5)
        
        self._stats_labels = {}
        stats_row = ctk.CTkFrame(self._stats_frame, fg_color="transparent")
        stats_row.pack(fill="x", padx=10, pady=8)
        
        for key, label, color in [("total", "Total", THEME["info"]),
                                   ("active", "Actifs", THEME["success"]),
                                   ("locked", "Verrouilles", THEME["warning"]),
                                   ("tickets", "Tickets", THEME["error"])]:
            item = ctk.CTkFrame(stats_row, fg_color="transparent")
            item.pack(side="left", padx=20)
            
            val_label = ctk.CTkLabel(item, text="0",
                                     font=ctk.CTkFont(size=20, weight="bold"),
                                     text_color=color)
            val_label.pack()
            
            ctk.CTkLabel(item, text=label,
                        font=ctk.CTkFont(size=10),
                        text_color=THEME["text_muted"]).pack()
            
            self._stats_labels[key] = val_label
        
        # Onglets (Utilisateurs / Tickets)
        self._tab_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._tab_frame.pack(fill="x", padx=15, pady=(5, 0))
        
        self._tab_users_btn = ctk.CTkButton(self._tab_frame, text="Utilisateurs",
                                           width=120, height=30,
                                           fg_color=THEME["accent"],
                                           command=lambda: self._switch_tab("users"))
        self._tab_users_btn.pack(side="left", padx=(0, 5))
        
        self._tab_tickets_btn = ctk.CTkButton(self._tab_frame, text="Tickets",
                                             width=120, height=30,
                                             fg_color=THEME["bg_input"],
                                             command=lambda: self._switch_tab("tickets"))
        self._tab_tickets_btn.pack(side="left")
        
        self._current_tab = "users"
        
        # Layout principal (liste + détails)
        self._main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._main_frame.pack(fill="both", expand=True, padx=15, pady=10)
        self._main_frame.grid_columnconfigure(0, weight=1)
        self._main_frame.grid_columnconfigure(1, weight=1)
        self._main_frame.grid_rowconfigure(0, weight=1)
        
        # Liste des utilisateurs
        list_frame = ctk.CTkFrame(self._main_frame, fg_color=THEME["bg_panel"], corner_radius=8)
        list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        
        ctk.CTkLabel(list_frame, text="Utilisateurs",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=12, pady=(10, 5))
        
        self._user_list = ctk.CTkScrollableFrame(list_frame, fg_color="transparent")
        self._user_list.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Panneau de détails
        self._detail_frame = ctk.CTkFrame(self._main_frame, fg_color=THEME["bg_panel"], corner_radius=8)
        self._detail_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        
        ctk.CTkLabel(self._detail_frame, text="Details",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=12, pady=(10, 5))
        
        self._detail_content = ctk.CTkScrollableFrame(self._detail_frame, fg_color="transparent")
        self._detail_content.pack(fill="both", expand=True, padx=5, pady=5)
        
        self._build_detail_empty()
        
        # === PANNEAU TICKETS ===
        self._tickets_frame = ctk.CTkFrame(self, fg_color="transparent")
        # Ne pas pack maintenant, sera affiché via switch_tab
        
        self._build_tickets_panel()
        
        # Logs d'audit
        logs_frame = ctk.CTkFrame(self, fg_color=THEME["bg_panel"], corner_radius=8)
        logs_frame.pack(fill="x", padx=15, pady=(5, 15))
        
        ctk.CTkLabel(logs_frame, text="Dernieres actions",
                    font=ctk.CTkFont(size=13, weight="bold"),
                    text_color=THEME["accent"]).pack(anchor="w", padx=12, pady=(10, 5))
        
        self._logs_text = ctk.CTkTextbox(logs_frame, height=80,
                                        fg_color=THEME["bg_input"],
                                        font=ctk.CTkFont(family="Courier", size=10))
        self._logs_text.pack(fill="x", padx=10, pady=(0, 10))
        self._logs_text.configure(state="disabled")
    
    def _build_detail_empty(self):
        """Affiche un message quand aucun utilisateur n'est sélectionné."""
        for w in self._detail_content.winfo_children():
            w.destroy()
        
        ctk.CTkLabel(self._detail_content, 
                    text="Sélectionnez un utilisateur\ndans la liste",
                    font=ctk.CTkFont(size=12),
                    text_color=THEME["text_muted"]).pack(pady=30)
    
    def _build_detail_for_user(self, user: Dict):
        """Affiche les détails d'un utilisateur."""
        for w in self._detail_content.winfo_children():
            w.destroy()
        
        self._selected_user = user
        
        # Infos de base
        info = [
            ("ID", str(user.get("id", "-"))),
            ("Identifiant", user.get("username", "-")),
            ("Nom complet", user.get("full_name") or "-"),
            ("Email", user.get("email") or "-"),
            ("Rôle", user.get("role", "viewer").upper()),
            ("Actif", "✓ Oui" if user.get("is_active") else "✗ Non"),
            ("Créé le", user.get("created_at", "-")),
            ("Dernière connexion", user.get("last_login") or "Jamais"),
        ]
        
        for label, value in info:
            row = ctk.CTkFrame(self._detail_content, fg_color="transparent")
            row.pack(fill="x", pady=2)
            
            ctk.CTkLabel(row, text=f"{label}:",
                        font=ctk.CTkFont(size=11),
                        text_color=THEME["text_secondary"],
                        width=110, anchor="w").pack(side="left", padx=5)
            
            ctk.CTkLabel(row, text=value,
                        font=ctk.CTkFont(size=11),
                        text_color=THEME["text_primary"]).pack(side="left")
        
        # Séparateur
        ctk.CTkFrame(self._detail_content, fg_color=THEME["border"], height=1).pack(fill="x", pady=10)
        
        # Actions
        actions = ctk.CTkFrame(self._detail_content, fg_color="transparent")
        actions.pack(fill="x", pady=5)
        
        ctk.CTkButton(actions, text="Modifier",
                     width=90, height=30,
                     fg_color=THEME["info"],
                     command=lambda: self._show_edit_dialog(user)).pack(side="left", padx=3)
        
        ctk.CTkButton(actions, text="Reinit. MDP",
                     width=100, height=30,
                     fg_color=THEME["warning"],
                     command=lambda: self._reset_password(user)).pack(side="left", padx=3)
        
        if user.get("username") != "admin":
            btn_text = "Debloquer" if not user.get("is_active") else "Supprimer"
            btn_color = THEME["success"] if not user.get("is_active") else THEME["error"]
            btn_cmd = lambda: self._toggle_user(user)
            
            ctk.CTkButton(actions, text=btn_text,
                         width=100, height=30,
                         fg_color=btn_color,
                         command=btn_cmd).pack(side="left", padx=3)
    
    def refresh(self):
        """Rafraîchit la liste des utilisateurs."""
        # Stats
        stats = self.auth.get_user_stats()
        self._stats_labels["total"].configure(text=str(stats.get("total", 0)))
        self._stats_labels["active"].configure(text=str(stats.get("active", 0)))
        self._stats_labels["locked"].configure(text=str(stats.get("locked", 0)))
        
        # Tickets en attente
        pending_tickets = self.auth.get_pending_tickets_count()
        self._stats_labels["tickets"].configure(text=str(pending_tickets))
        
        # Liste des utilisateurs
        for w in self._user_list.winfo_children():
            w.destroy()
        
        users = self.auth.get_all_users()
        
        for user in users:
            self._create_user_row(user)
        
        # Logs
        self._refresh_logs()
        
        # Rafraîchir les tickets si on est sur cet onglet
        if self._current_tab == "tickets":
            self._refresh_tickets()
    
    def _create_user_row(self, user: Dict):
        """Crée une ligne pour un utilisateur."""
        is_active = user.get("is_active", False)
        
        row = ctk.CTkFrame(self._user_list, 
                          fg_color=THEME["bg_card"] if is_active else THEME["bg_input"],
                          corner_radius=6)
        row.pack(fill="x", pady=2)
        
        # Icône rôle
        role = user.get("role", "viewer")
        role_icons = {"admin": "[A]", "analyst": "[N]", "operator": "[O]", "viewer": "[V]"}
        icon = role_icons.get(role, "[?]")
        
        ctk.CTkLabel(row, text=icon, font=ctk.CTkFont(size=16)).pack(side="left", padx=(10, 5))
        
        # Info
        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, pady=8)
        
        name_color = THEME["text_primary"] if is_active else THEME["text_muted"]
        ctk.CTkLabel(info, text=user.get("username", "?"),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=name_color).pack(anchor="w")
        
        subtitle = f"{role.upper()}"
        if user.get("full_name"):
            subtitle = f"{user['full_name']} • {subtitle}"
        
        ctk.CTkLabel(info, text=subtitle,
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(anchor="w")
        
        # Status
        if not is_active:
            ctk.CTkLabel(row, text="Inactif",
                        font=ctk.CTkFont(size=10),
                        text_color=THEME["error"]).pack(side="right", padx=10)
        
        # Clic pour sélectionner
        row.bind("<Button-1>", lambda e, u=user: self._build_detail_for_user(u))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda e, u=user: self._build_detail_for_user(u))
    
    def _refresh_logs(self):
        """Rafraîchit les logs d'audit."""
        logs = self.auth.get_audit_logs(limit=10)
        
        self._logs_text.configure(state="normal")
        self._logs_text.delete("1.0", "end")
        
        for log in logs:
            status = "✓" if log.get("success") else "✗"
            time_str = log.get("timestamp", "")[:19]
            user = log.get("username") or "?"
            action = log.get("action", "?")
            
            line = f"{status} [{time_str}] {user}: {action}\n"
            self._logs_text.insert("end", line)
        
        self._logs_text.configure(state="disabled")
    
    def _show_create_dialog(self):
        """Affiche la popup de création d'utilisateur."""
        dialog = UserDialog(self, self.auth, mode="create")
        dialog.wait_window()
        self.refresh()
    
    def _show_edit_dialog(self, user: Dict):
        """Affiche la popup d'édition d'utilisateur."""
        dialog = UserDialog(self, self.auth, mode="edit", user=user)
        dialog.wait_window()
        self.refresh()
    
    def _reset_password(self, user: Dict):
        """Réinitialise le mot de passe d'un utilisateur."""
        dialog = ctk.CTkInputDialog(
            text=f"Nouveau mot de passe pour {user['username']}:",
            title="Réinitialiser le mot de passe"
        )
        new_pwd = dialog.get_input()
        
        if new_pwd:
            if len(new_pwd) < 6:
                messagebox.showerror("Erreur", "Mot de passe trop court (min 6 car.)")
                return
            
            success, msg = self.auth.reset_password(user["id"], new_pwd)
            if success:
                messagebox.showinfo("Succès", f"Mot de passe réinitialisé pour {user['username']}")
            else:
                messagebox.showerror("Erreur", msg)
            
            self.refresh()
    
    def _toggle_user(self, user: Dict):
        """Active/désactive un utilisateur."""
        if user.get("is_active"):
            if messagebox.askyesno("Confirmer", 
                                  f"Voulez-vous désactiver l'utilisateur {user['username']} ?"):
                success, msg = self.auth.delete_user(user["id"])
                if success:
                    messagebox.showinfo("Succès", "Utilisateur désactivé")
                else:
                    messagebox.showerror("Erreur", msg)
        else:
            success, msg = self.auth.update_user(user["id"], is_active=True)
            if success:
                messagebox.showinfo("Succès", "Utilisateur réactivé")
            else:
                messagebox.showerror("Erreur", msg)
        
        self.refresh()
    
    def _switch_tab(self, tab: str):
        """Change l'onglet actif (users/tickets)."""
        self._current_tab = tab
        
        if tab == "users":
            self._tab_users_btn.configure(fg_color=THEME["accent"])
            self._tab_tickets_btn.configure(fg_color=THEME["bg_input"])
            self._tickets_frame.pack_forget()
            self._main_frame.pack(fill="both", expand=True, padx=15, pady=10)
        else:
            self._tab_users_btn.configure(fg_color=THEME["bg_input"])
            self._tab_tickets_btn.configure(fg_color=THEME["accent"])
            self._main_frame.pack_forget()
            self._tickets_frame.pack(fill="both", expand=True, padx=15, pady=10)
            self._refresh_tickets()
    
    def _build_tickets_panel(self):
        """Construit le panneau de gestion des tickets."""
        # Liste des tickets
        list_frame = ctk.CTkFrame(self._tickets_frame, fg_color=THEME["bg_panel"], corner_radius=8)
        list_frame.pack(fill="both", expand=True)
        
        header = ctk.CTkFrame(list_frame, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=10)
        
        ctk.CTkLabel(header, text="Demandes en attente",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=THEME["accent"]).pack(side="left")
        
        ctk.CTkButton(header, text="Actualiser", width=80, height=28,
                     fg_color=THEME["bg_input"],
                     command=self._refresh_tickets).pack(side="right")
        
        self._tickets_list = ctk.CTkScrollableFrame(list_frame, fg_color="transparent")
        self._tickets_list.pack(fill="both", expand=True, padx=5, pady=5)
    
    def _refresh_tickets(self):
        """Rafraîchit la liste des tickets."""
        for w in self._tickets_list.winfo_children():
            w.destroy()
        
        tickets = self.auth.get_tickets(limit=50)
        
        if not tickets:
            ctk.CTkLabel(self._tickets_list, text="Aucun ticket",
                        font=ctk.CTkFont(size=12),
                        text_color=THEME["text_muted"]).pack(pady=30)
            return
        
        for ticket in tickets:
            self._create_ticket_row(ticket)
    
    def _create_ticket_row(self, ticket: Dict):
        """Crée une ligne pour un ticket."""
        status = ticket.get("status", "pending")
        
        # Couleurs selon statut
        status_colors = {
            "pending": THEME["warning"],
            "in_progress": THEME["info"],
            "resolved": THEME["success"],
            "rejected": THEME["error"]
        }
        status_texts = {
            "pending": "En attente",
            "in_progress": "En cours",
            "resolved": "Resolu",
            "rejected": "Rejete"
        }
        
        row = ctk.CTkFrame(self._tickets_list, fg_color=THEME["bg_card"], corner_radius=6)
        row.pack(fill="x", pady=3)
        
        # Header du ticket
        header = ctk.CTkFrame(row, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(8, 5))
        
        # ID et type
        ctk.CTkLabel(header, text=f"#{ticket['id']}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=THEME["text_primary"]).pack(side="left")
        
        type_text = "MDP" if ticket.get("ticket_type") == "password_reset" else ticket.get("ticket_type", "?")
        ctk.CTkLabel(header, text=f"[{type_text}]",
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["info"]).pack(side="left", padx=(8, 0))
        
        # Statut
        ctk.CTkLabel(header, text=status_texts.get(status, status),
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=status_colors.get(status, THEME["text_muted"])).pack(side="right")
        
        # Infos
        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(fill="x", padx=10, pady=(0, 5))
        
        ctk.CTkLabel(info, text=f"De: {ticket.get('username', '?')}",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w")
        
        ctk.CTkLabel(info, text=ticket.get("subject", ""),
                    font=ctk.CTkFont(size=10),
                    text_color=THEME["text_muted"]).pack(anchor="w")
        
        # Date
        created = ticket.get("created_at", "")[:16] if ticket.get("created_at") else ""
        ctk.CTkLabel(info, text=created,
                    font=ctk.CTkFont(size=9),
                    text_color=THEME["text_muted"]).pack(anchor="w")
        
        # Boutons d'action (seulement si pending)
        if status == "pending":
            actions = ctk.CTkFrame(row, fg_color="transparent")
            actions.pack(fill="x", padx=10, pady=(0, 8))
            
            if ticket.get("ticket_type") == "password_reset":
                ctk.CTkButton(actions, text="Approuver", width=80, height=26,
                             fg_color=THEME["success"],
                             font=ctk.CTkFont(size=10),
                             command=lambda t=ticket: self._approve_password_reset(t)).pack(side="left", padx=(0, 5))
            
            ctk.CTkButton(actions, text="Rejeter", width=70, height=26,
                         fg_color=THEME["error"],
                         font=ctk.CTkFont(size=10),
                         command=lambda t=ticket: self._reject_ticket(t)).pack(side="left")
    
    def _approve_password_reset(self, ticket: Dict):
        """Approuve une demande de réinitialisation de mot de passe."""
        dialog = ctk.CTkInputDialog(
            text=f"Nouveau mot de passe pour {ticket['username']}:",
            title="Reinitialiser le mot de passe"
        )
        new_pwd = dialog.get_input()
        
        if new_pwd:
            if len(new_pwd) < 6:
                messagebox.showerror("Erreur", "Mot de passe trop court (min 6 caracteres)")
                return
            
            success, msg = self.auth.resolve_password_reset_ticket(
                ticket["id"], new_password=new_pwd, approve=True
            )
            
            if success:
                messagebox.showinfo("Succes", f"Mot de passe reinitialise pour {ticket['username']}")
            else:
                messagebox.showerror("Erreur", msg)
            
            self.refresh()
    
    def _reject_ticket(self, ticket: Dict):
        """Rejette un ticket."""
        if messagebox.askyesno("Confirmer", f"Rejeter le ticket #{ticket['id']} ?"):
            success, msg = self.auth.update_ticket(ticket["id"], status="rejected")
            
            if success:
                messagebox.showinfo("Succes", "Ticket rejete")
            else:
                messagebox.showerror("Erreur", msg)
            
            self.refresh()


# =============================================================================
# DIALOGUE CRÉATION/ÉDITION UTILISATEUR
# =============================================================================

class UserDialog(ctk.CTkToplevel):
    """Dialogue pour créer ou modifier un utilisateur."""
    
    def __init__(self, parent, auth: AuthManager, mode: str = "create", user: Dict = None):
        super().__init__(parent)
        
        self.auth = auth
        self.mode = mode
        self.user = user
        
        title = "Nouvel utilisateur" if mode == "create" else f"Modifier {user['username']}"
        self.title(title)
        self.geometry("400x500")
        self.resizable(False, False)
        self.configure(fg_color=THEME["bg_main"])
        
        # Centrer
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 400) // 2
        y = (self.winfo_screenheight() - 500) // 2
        self.geometry(f"400x500+{x}+{y}")
        
        self.transient(parent)
        self.grab_set()
        
        self._build_ui()
    
    def _build_ui(self):
        """Construit le formulaire."""
        # Titre
        ctk.CTkLabel(self, text="Nouvel utilisateur" if self.mode == "create" else "Modifier utilisateur",
                    font=ctk.CTkFont(size=18, weight="bold"),
                    text_color=THEME["accent"]).pack(pady=(20, 15))
        
        form = ctk.CTkFrame(self, fg_color=THEME["bg_card"], corner_radius=10)
        form.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Username
        ctk.CTkLabel(form, text="Identifiant *",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(15, 3))
        
        self.username_entry = ctk.CTkEntry(form, height=35, fg_color=THEME["bg_input"])
        self.username_entry.pack(fill="x", padx=15)
        
        if self.mode == "edit":
            self.username_entry.insert(0, self.user.get("username", ""))
            self.username_entry.configure(state="disabled")
        
        # Mot de passe
        pwd_label = "Mot de passe *" if self.mode == "create" else "Nouveau mot de passe (laisser vide pour ne pas changer)"
        ctk.CTkLabel(form, text=pwd_label,
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(10, 3))
        
        self.password_entry = ctk.CTkEntry(form, height=35, show="•", fg_color=THEME["bg_input"])
        self.password_entry.pack(fill="x", padx=15)
        
        # Nom complet
        ctk.CTkLabel(form, text="Nom complet",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(10, 3))
        
        self.fullname_entry = ctk.CTkEntry(form, height=35, fg_color=THEME["bg_input"])
        self.fullname_entry.pack(fill="x", padx=15)
        
        if self.mode == "edit" and self.user.get("full_name"):
            self.fullname_entry.insert(0, self.user["full_name"])
        
        # Email
        ctk.CTkLabel(form, text="Email",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(10, 3))
        
        self.email_entry = ctk.CTkEntry(form, height=35, fg_color=THEME["bg_input"])
        self.email_entry.pack(fill="x", padx=15)
        
        if self.mode == "edit" and self.user.get("email"):
            self.email_entry.insert(0, self.user["email"])
        
        # Rôle
        ctk.CTkLabel(form, text="Rôle *",
                    font=ctk.CTkFont(size=11),
                    text_color=THEME["text_secondary"]).pack(anchor="w", padx=15, pady=(10, 3))
        
        self.role_var = ctk.StringVar(value=self.user.get("role", "viewer") if self.user else "viewer")
        self.role_menu = ctk.CTkComboBox(form, 
                                        values=list(ROLES.keys()),
                                        variable=self.role_var,
                                        height=35,
                                        fg_color=THEME["bg_input"])
        self.role_menu.pack(fill="x", padx=15)
        
        # Message d'erreur
        self.error_label = ctk.CTkLabel(form, text="",
                                       font=ctk.CTkFont(size=11),
                                       text_color=THEME["error"])
        self.error_label.pack(pady=10)
        
        # Boutons
        btn_frame = ctk.CTkFrame(form, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=15)
        
        ctk.CTkButton(btn_frame, text="Annuler",
                     width=100, height=35,
                     fg_color=THEME["bg_input"],
                     command=self.destroy).pack(side="left")
        
        ctk.CTkButton(btn_frame, text="Enregistrer",
                     width=100, height=35,
                     fg_color=THEME["success"],
                     command=self._save).pack(side="right")
    
    def _save(self):
        """Enregistre l'utilisateur."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        full_name = self.fullname_entry.get().strip()
        email = self.email_entry.get().strip()
        role = self.role_var.get()
        
        if self.mode == "create":
            if not username:
                self.error_label.configure(text="L'identifiant est requis")
                return
            
            if not password or len(password) < 6:
                self.error_label.configure(text="Mot de passe requis (min 6 car.)")
                return
            
            success, msg = self.auth.create_user(
                username=username,
                password=password,
                role=role,
                email=email if email else None,
                full_name=full_name if full_name else None
            )
        else:
            kwargs = {"role": role}
            
            if password:
                if len(password) < 6:
                    self.error_label.configure(text="Mot de passe trop court (min 6 car.)")
                    return
                kwargs["password"] = password
            
            if full_name:
                kwargs["full_name"] = full_name
            if email:
                kwargs["email"] = email
            
            success, msg = self.auth.update_user(self.user["id"], **kwargs)
        
        if success:
            self.destroy()
        else:
            self.error_label.configure(text=msg)


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    # Test standalone
    ctk.set_appearance_mode("dark")
    
    root = ctk.CTk()
    root.title("Test Auth Widgets")
    root.geometry("1200x800")
    
    def on_login(user):
        print(f"Connecté: {user}")
        # Afficher le panneau profil
        profile = ProfilePanel(root)
        profile.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        profile.update_profile()
        
        # Afficher la gestion users si admin
        if user.get("role") == "admin":
            users = UserManagementPanel(root)
            users.pack(side="right", fill="both", expand=True, padx=5, pady=5)
            users.refresh()
    
    # Login
    login = LoginWindow(root, on_login_success=on_login)
    
    root.mainloop()
