#!/usr/bin/env python3
"""
afficheDB.py - Affichage du contenu de la base de données SQLite
Supporte le déchiffrement automatique des données sensibles.

Usage:
    python afficheDB.py [chemin_db] [-d/--decrypt]
"""

import sqlite3
import os
import argparse
import json

COLONNES_CHIFFREES = [
    "mac_src", "mac_dst", "ip_src", "ip_dst", 
    "snmp_community", "snmp_oidsValues", "snmp_usm_user_name"
]

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def get_cipher():
    """Récupère la clé et initialise le moteur de déchiffrement."""
    if not CRYPTO_AVAILABLE:
        print("[!] Module 'cryptography' non installé.")
        return None
    
    key_str = os.getenv("SNIFFER_KEY")
    if not key_str:
        print("[!] Variable 'SNIFFER_KEY' non définie.")
        return None
    
    try:
        return Fernet(key_str.encode())
    except Exception as e:
        print(f"[!] Clé invalide: {e}")
        return None


def decrypt_val(cipher, value):
    """Déchiffre une valeur."""
    if value is None:
        return None
    try:
        return cipher.decrypt(str(value).encode()).decode()
    except:
        return value


def afficher_contenu_db(nom_db, mode_decrypt=False, table_filter=None, limit=50):
    """Affiche le contenu d'une base de données SQLite."""
    cipher = get_cipher() if mode_decrypt else None

    if not os.path.exists(nom_db):
        print(f"[!] Le fichier '{nom_db}' n'existe pas.")
        return

    try:
        conn = sqlite3.connect(nom_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';")
        tables = [t[0] for t in cursor.fetchall()]
        
        if table_filter:
            tables = [t for t in tables if table_filter.lower() in t.lower()]

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            total = cursor.fetchone()[0]
            
            print(f"\n{'='*60}")
            print(f"  TABLE: {table}  ({total} lignes)")
            print(f"{'='*60}")
            
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]
            
            cursor.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))
            
            for row in cursor.fetchall():
                print(f"\n  --- #{row[0]} ---")
                for i, (col, val) in enumerate(zip(columns, row)):
                    if cipher and col in COLONNES_CHIFFREES:
                        val = decrypt_val(cipher, val)
                    val_str = str(val)[:80] + "..." if val and len(str(val)) > 80 else str(val)
                    print(f"    {col:25}: {val_str}")
                    
    except Exception as e:
        print(f"Erreur: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Affiche une base SQLite MIBurnout.")
    parser.add_argument("db_file", nargs='?', default="test.db")
    parser.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("-t", "--table", type=str, default=None)
    parser.add_argument("-n", "--limit", type=int, default=50)
    
    args = parser.parse_args()
    afficher_contenu_db(args.db_file, args.decrypt, args.table, args.limit)
