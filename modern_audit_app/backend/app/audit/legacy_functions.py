# GUI imports removed - not needed for API usage
from collections import defaultdict
import os, sys, threading
from pathlib import Path
# Optional GUI imports (commented out)
# from tkinter import Scrollbar, Checkbutton, IntVar, filedialog, messagebox, ttk
# import tkinter as tk
# from PIL import Image, ImageTk
import openpyxl
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Side, Font, PatternFill
from openpyxl.formatting.rule import CellIsRule
from datetime import datetime
import pandas as pd
from openpyxl.drawing.image import Image as OpenpyxlImage
from openpyxl.chart import PieChart, ProjectedPieChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.series import DataPoint  # type: ignore
from openpyxl.chart.shapes import GraphicalProperties
import requests
from bs4 import BeautifulSoup
import re
from typing import List, Tuple, Dict
from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_COLOR_INDEX
from docx.section import Section
from docx.oxml.ns import qn, nsdecls
from docx.oxml import OxmlElement, parse_xml
import shutil
from docx.enum.table import WD_TABLE_ALIGNMENT
import msal
import pickle
import re
from typing import Iterable, Optional, Tuple, Dict, Any
import time
import ipaddress



# Path resolution helper for reference files
def _get_references_path(filename: str) -> str:
    """
    Resolve path to files in the Références directory.
    Returns absolute path to the file, creating directory if needed.
    Raises FileNotFoundError if file doesn't exist with helpful message.
    """
    # Get the backend directory (parent of app directory)
    backend_dir = Path(__file__).parent.parent.parent
    references_dir = backend_dir / "Références"
    references_dir.mkdir(exist_ok=True)
    file_path = references_dir / filename
    
    # Check if file exists, provide helpful error if not
    if not file_path.exists():
        raise FileNotFoundError(
            f"Reference file not found: {file_path}\n"
            f"Please ensure '{filename}' is placed in the Références directory:\n"
            f"{references_dir}\n"
            f"See Références/README.md for a list of required files."
        )
    
    # Return absolute path as string
    return str(file_path.resolve())



# Code d'audit configuration FortiGate réalisée par Thierry HOKMAYAN pour SNS Security

imported_filepath = ""
imported_filename = ""
wan_interfaces = {}
wan_check_vars = []

# Fonction pour lire le fichier de conf du Fortigate
def lire_config_fortigate(filepath):
    return list(_iter_config_lines(filepath))


# Fonction qui va extraire le nom du Fortigate
def extraire_hostname(config_lines):
    for line in config_lines:
        if 'set hostname' in line:
            hostname = line.split('"')[1]
            return hostname
    return "UnknownHost"

def _fmt_date_fr(date_str: str) -> str:
    if not date_str:
        return ""
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return date_str

def detecter_objets_non_utilises(config_lines):
    """
    Détecte les types d'objets de configuration ayant au moins un objet non référencé.
    Distingue VIP et Virtual Server dans le bloc config firewall vip.
    Retourne: (result_message, conformity, unused_details)
    """

    # Dictionnaires pour stocker les objets extraits
    objets_definis = {
        'addresses': set(),
        'addrgrps': set(),
        'vips': set(),
        'virtual_servers': set(),
        'vipgrps': set(),
        'zones': set(),
        'users': set(),
        'usergroups': set(),
        'radius': set(),
        'ldap': set(),
        'webfilter': set(),
        'antivirus': set(),
        'ips': set(),
        'appcontrol': set(),
        'sslssh': set(),
        'dnsfilter': set()
    }

    # Mapping des types pour l'affichage
    type_display_names = {
        'addresses': 'adresse',
        'addrgrps': 'groupe d\'adresse',
        'vips': 'VIP',
        'virtual_servers': 'Virtual Server',
        'vipgrps': 'groupe de VIP',
        'zones': 'zone',
        'users': 'utilisateur',
        'usergroups': 'groupe d\'utilisateur',
        'radius': 'connecteur RADIUS',
        'ldap': 'connecteur LDAP',
        'webfilter': 'profil Web Filter',
        'antivirus': 'profil Antivirus',
        'ips': 'profil IPS',
        'appcontrol': 'profil App Control',
        'sslssh': 'profil SSL/SSH',
        'dnsfilter': 'profil DNS Filter'
    }

    valid_config_lines = [line for line in config_lines if isinstance(line, str)]

    # Fonction helper pour extraire les objets d'un bloc de configuration avec gestion des sous-blocs
    def extraire_objets_du_bloc(nom_bloc):
        objets = set()
        in_bloc = False
        niveau_imbrication = 0
        config_stack = []

        for line in valid_config_lines:
            line_strip = line.strip()

            if line_strip == f"config {nom_bloc}":
                in_bloc = True
                niveau_imbrication = 1
                config_stack.append(nom_bloc)
                continue

            if not in_bloc:
                continue

            if line_strip.startswith("config "):
                niveau_imbrication += 1
                config_stack.append(line_strip)
                continue

            if line_strip == "end":
                if config_stack:
                    config_stack.pop()
                    niveau_imbrication -= 1
                    if niveau_imbrication == 0:
                        in_bloc = False
                continue

            if niveau_imbrication == 1 and line_strip.startswith("edit "):
                match = re.search(r'edit\s+"([^"]+)"', line_strip)
                if match:
                    objets.add(match.group(1))
                else:
                    parts = line_strip.split()
                    if len(parts) >= 2:
                        nom_objet = parts[1].strip('"')
                        objets.add(nom_objet)

        return objets

    def extraire_vips_et_vs():
        vips = set()
        virtual_servers = set()
        in_bloc = False
        niveau_imbrication = 0
        edit_name = None
        is_vs = False

        for line in valid_config_lines:
            line_strip = line.strip()

            if line_strip == "config firewall vip":
                in_bloc = True
                niveau_imbrication = 1
                continue

            if not in_bloc:
                continue

            if line_strip.startswith("config "):
                niveau_imbrication += 1
                continue

            if line_strip == "end":
                niveau_imbrication -= 1
                if niveau_imbrication == 0:
                    in_bloc = False
                continue

            if niveau_imbrication == 1 and line_strip.startswith("edit "):
                match = re.search(r'edit\s+"([^"]+)"', line_strip)
                edit_name = match.group(1) if match else line_strip.split()[1].strip('"')
                is_vs = False
                continue

            # Si on rencontre "next" au niveau principal, terminer l'objet courant
            if niveau_imbrication == 1 and line_strip == "next":
                if edit_name:
                    if is_vs:
                        virtual_servers.add(edit_name)
                    else:
                        vips.add(edit_name)
                edit_name = None
                is_vs = False
                continue

            if edit_name and "set type server-load-balance" in line_strip:
                is_vs = True

        return vips, virtual_servers

    # Extraction des objets définis pour tous les types
    objets_definis['addresses'] = extraire_objets_du_bloc("firewall address")
    objets_definis['addrgrps'] = extraire_objets_du_bloc("firewall addrgrp")
    objets_definis['vips'], objets_definis['virtual_servers'] = extraire_vips_et_vs()
    objets_definis['vipgrps'] = extraire_objets_du_bloc("firewall vipgrp")
    objets_definis['zones'] = extraire_objets_du_bloc("system zone")
    objets_definis['users'] = extraire_objets_du_bloc("user local")
    objets_definis['usergroups'] = extraire_objets_du_bloc("user group")
    objets_definis['radius'] = extraire_objets_du_bloc("user radius")
    objets_definis['ldap'] = extraire_objets_du_bloc("user ldap")
    objets_definis['webfilter'] = extraire_objets_du_bloc("webfilter profile")
    objets_definis['antivirus'] = extraire_objets_du_bloc("antivirus profile")
    objets_definis['ips'] = extraire_objets_du_bloc("ips sensor")
    objets_definis['appcontrol'] = extraire_objets_du_bloc("application list")
    objets_definis['sslssh'] = extraire_objets_du_bloc("firewall ssl-ssh-profile")
    objets_definis['dnsfilter'] = extraire_objets_du_bloc("dnsfilter profile")

    config_text = '\n'.join(valid_config_lines)

    def est_objet_reference(nom_objet, type_objet):
        if not nom_objet:
            return False

        # Ignorer les définitions de l'objet
        if f'edit "{nom_objet}"' in config_text:
            config_search = config_text.replace(f'edit "{nom_objet}"', '')
        else:
            config_search = config_text.replace(f'edit {nom_objet}', '')

        # Recherche simple et efficace
        return f'"{nom_objet}"' in config_search or f' {nom_objet} ' in f' {config_search} '

    types_avec_objets_non_utilises = []
    total_types = len(objets_definis)
    types_traites = 0

    for type_objet, objets in objets_definis.items():
        if objets:
            for objet in objets:
                if not est_objet_reference(objet, type_objet):
                    types_avec_objets_non_utilises.append(type_display_names[type_objet])
                    break
        types_traites += 1

    if not types_avec_objets_non_utilises:
        result_message = "Tous les objets (adresses, groupes d'adresses, VIPs, Virtual Servers, VIP groupes, zones, utilisateurs, groupes d'utilisateurs, connecteurs RADIUS/LDAP et profils de sécurité) sont utilisés"
        conformity = True
    else:
        if len(types_avec_objets_non_utilises) == 1:
            result_message = f"Détection d'objet sans référence pour le type suivant : {types_avec_objets_non_utilises[0]}"
        else:
            result_message = f"Détection d'objet sans référence pour les types suivants : {', '.join(types_avec_objets_non_utilises)}"
        conformity = False

    unused_details = {}

    return result_message, conformity, unused_details


def verifier_auto_install_usb(config_lines):
    """
    Vérifie que l'auto-installation par USB (config et image) est désactivée
    Renvoie (message, conforme)
    """
    in_auto_install_block = False
    found_auto_install_block = False
    auto_install_config_disable = False
    auto_install_image_disable = False

    for line in config_lines:
        line = line.strip()
        if line == "config system auto-install":
            in_auto_install_block = True
            found_auto_install_block = True
            continue
        if in_auto_install_block and line == "end":
            in_auto_install_block = False
            continue
        if in_auto_install_block:
            if line == "set auto-install-config disable":
                auto_install_config_disable = True
            if line == "set auto-install-image disable":
                auto_install_image_disable = True


    if auto_install_config_disable and auto_install_image_disable:
        return ("L'auto-installation automatique par USB (config & image) est BIEN désactivée", True)
    else:
        msg = "Non conforme : "
        if not auto_install_config_disable and not auto_install_image_disable:
            msg += "les deux options auto-install (config & image) sont actives."
        elif not auto_install_config_disable:
            msg += "auto-install-config n'est pas désactivé."
        elif not auto_install_image_disable:
            msg += "auto-install-image n'est pas désactivé."
        return (msg, False)



def verifier_vips_extintf_any(config_lines):
    """
    Vérifie que les VIP classiques n'ont pas 'any' pour 'set extintf'
    Retourne : (result, conform)
    """
    in_bloc = False
    niveau_imbrication = 0
    edit_name = None
    is_vs = False
    vip_extintf_any = []

    for line in config_lines:
        line_strip = line.strip()

        if line_strip == "config firewall vip":
            in_bloc = True
            niveau_imbrication = 1
            continue

        if not in_bloc:
            continue

        if line_strip.startswith("config "):
            niveau_imbrication += 1
            continue

        if line_strip == "end":
            niveau_imbrication -= 1
            if niveau_imbrication == 0:
                in_bloc = False
            continue

        if niveau_imbrication == 1 and line_strip.startswith("edit "):
            match = re.search(r'edit\s+"([^"]+)"', line_strip)
            edit_name = match.group(1) if match else line_strip.split()[1].strip('"')
            is_vs = False
            extintf_any = False
            continue

        if niveau_imbrication == 1 and line_strip == "next":
            if edit_name and not is_vs and extintf_any:
                vip_extintf_any.append(edit_name)
            edit_name = None
            is_vs = False
            extintf_any = False
            continue

        # Marqueur Virtual Server
        if edit_name and "set type server-load-balance" in line_strip:
            is_vs = True
        # Marqueur "any" interface
        if edit_name and re.match(r'set extintf\s+"?any"?', line_strip):
            extintf_any = True

    if not vip_extintf_any:
        result = "Aucune VIP a 'ANY' comme interface externe"
        conform = True
    else:
        result = f"VIP(s) avec 'ANY' sur l'interface externe : {', '.join(vip_extintf_any)}"
        conform = False

    return result, conform

import re
import ipaddress


def verifier_vs_extintf_any(config_lines):
    """
    Vérifie les Virtual Servers avec extintf 'any'.

    Conforme si :
    - absence de Virtual Server => N/A
    - aucun Virtual Server n'utilise extintf any
    - ou extintf any est utilisé MAIS :
        - l'extip est dans le même subnet que les real servers
        - ou le VS est utilisé dans une policy avec srcintf multi-interface
        - ou le VS est utilisé dans une policy avec srcintf "any"
        - ou le VS est utilisé dans une policy dont srcintf est une zone contenant plusieurs interfaces

    Retourne : (result, conform)
    """

    def extraire_valeurs_ligne(line):
        quoted_values = re.findall(r'"([^"]+)"', line)
        if quoted_values:
            return quoted_values

        tokens = line.split()
        if len(tokens) >= 3:
            return tokens[2:]

        return []

    def get_private_prefix(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj in ipaddress.ip_network("10.0.0.0/8"):
                return 8
            if ip_obj in ipaddress.ip_network("172.16.0.0/12"):
                return 16
            if ip_obj in ipaddress.ip_network("192.168.0.0/16"):
                return 24

            return 24
        except ValueError:
            return 24

    def meme_subnet(ip1, ip2):
        try:
            prefix = get_private_prefix(ip1)
            net1 = ipaddress.ip_interface(f"{ip1}/{prefix}").network
            net2 = ipaddress.ip_interface(f"{ip2}/{prefix}").network
            return net1 == net2
        except ValueError:
            return False

    def extraire_zones(config_lines):
        """
        Retourne un dictionnaire :
        {
            "NomZone": ["interface1", "interface2"],
            "NomZoneSDWAN": ["wan1", "wan2"]
        }
        """

        zones = {}

        # Zones classiques
        in_zone_block = False
        current_zone = None

        # SD-WAN
        in_sdwan_block = False
        sdwan_stack = []
        current_sdwan_zone = None

        inside_member_edit = False
        current_member_interface = None
        current_member_zone = None
        sdwan_zone_members = {}

        for raw_line in config_lines:
            line = raw_line.strip()

            # -------------------------
            # Zones classiques
            # -------------------------
            if line == "config system zone":
                in_zone_block = True
                current_zone = None
                continue

            if in_zone_block:
                if line == "end":
                    in_zone_block = False
                    current_zone = None
                    continue

                if line.startswith("edit "):
                    values = extraire_valeurs_ligne(line)
                    current_zone = values[0] if values else None
                    if current_zone:
                        zones.setdefault(current_zone, [])
                    continue

                if current_zone and line.startswith("set interface "):
                    interfaces = extraire_valeurs_ligne(line)
                    zones[current_zone].extend(interfaces)
                    continue

                if line == "next":
                    current_zone = None
                    continue

            # -------------------------
            # Zones SD-WAN
            # -------------------------
            if line == "config system sdwan":
                in_sdwan_block = True
                sdwan_stack = []
                continue

            if not in_sdwan_block:
                continue

            if line.startswith("config "):
                sdwan_stack.append(line)
                continue

            if line == "end":
                if sdwan_stack:
                    last_block = sdwan_stack.pop()

                    if last_block == "config zone":
                        current_sdwan_zone = None

                    if last_block == "config members":
                        inside_member_edit = False
                        current_member_interface = None
                        current_member_zone = None
                else:
                    in_sdwan_block = False

                continue

            current_sdwan_context = sdwan_stack[-1] if sdwan_stack else None

            if current_sdwan_context == "config zone":
                if line.startswith("edit "):
                    values = extraire_valeurs_ligne(line)
                    current_sdwan_zone = values[0] if values else None
                    if current_sdwan_zone:
                        zones.setdefault(current_sdwan_zone, [])
                        sdwan_zone_members.setdefault(current_sdwan_zone, [])
                    continue

                if line == "next":
                    current_sdwan_zone = None
                    continue

            if current_sdwan_context == "config members":
                if line.startswith("edit "):
                    inside_member_edit = True
                    current_member_interface = None
                    current_member_zone = None
                    continue

                if line == "next" and inside_member_edit:
                    if current_member_interface:
                        zone_name = current_member_zone or "virtual-wan-link"
                        sdwan_zone_members.setdefault(zone_name, [])
                        sdwan_zone_members[zone_name].append(current_member_interface)
                        zones.setdefault(zone_name, [])
                        zones[zone_name].append(current_member_interface)

                    inside_member_edit = False
                    current_member_interface = None
                    current_member_zone = None
                    continue

                if inside_member_edit and line.startswith("set interface "):
                    values = extraire_valeurs_ligne(line)
                    current_member_interface = values[0] if values else None
                    continue

                if inside_member_edit and line.startswith("set zone "):
                    values = extraire_valeurs_ligne(line)
                    current_member_zone = values[0] if values else None
                    continue

        return zones

    def srcintf_est_multi_interface(srcintf_list, zones):
        if len(srcintf_list) > 1:
            return True

        if any(i.lower() == "any" for i in srcintf_list):
            return True

        if len(srcintf_list) == 1:
            src = srcintf_list[0]

            if src in zones and len(zones[src]) > 1:
                return True

        return False

    def get_vs_acceptables_par_policy(config_lines, zones):
        """
        Retourne l'ensemble des objets dstaddr utilisés dans une policy
        dont la source est équivalente à du multi-interface.
        """

        in_firewall_policy = False
        in_policy_edit = False

        current_srcintf = []
        current_dstaddr = []

        vs_acceptables_par_policy = set()

        for raw_line in config_lines:
            line = raw_line.strip()

            if line == "config firewall policy":
                in_firewall_policy = True
                continue

            if not in_firewall_policy:
                continue

            if line.startswith("edit "):
                in_policy_edit = True
                current_srcintf = []
                current_dstaddr = []
                continue

            if line == "next" and in_policy_edit:
                if srcintf_est_multi_interface(current_srcintf, zones):
                    for obj in current_dstaddr:
                        vs_acceptables_par_policy.add(obj)

                in_policy_edit = False
                current_srcintf = []
                current_dstaddr = []
                continue

            if line == "end":
                in_firewall_policy = False
                in_policy_edit = False
                continue

            if not in_policy_edit:
                continue

            if line.startswith("set srcintf "):
                current_srcintf = extraire_valeurs_ligne(line)

            elif line.startswith("set dstaddr "):
                current_dstaddr = extraire_valeurs_ligne(line)

        return vs_acceptables_par_policy

    zones = extraire_zones(config_lines)
    vs_acceptables_par_policy = get_vs_acceptables_par_policy(config_lines, zones)

    in_bloc = False
    niveau_imbrication = 0

    edit_name = None
    is_vs = False
    extintf_any = False
    extip = None
    realservers = []
    in_realservers = False

    vs_found = False
    vs_non_conformes = []
    vs_conformes_avec_reserve_subnet = []
    vs_conformes_avec_reserve_policy = []

    for line in config_lines:
        line_strip = line.strip()

        if line_strip == "config firewall vip":
            in_bloc = True
            niveau_imbrication = 1
            continue

        if not in_bloc:
            continue

        if line_strip.startswith("config "):
            niveau_imbrication += 1

            if line_strip == "config realservers":
                in_realservers = True

            continue

        if line_strip == "end":
            if in_realservers:
                in_realservers = False

            niveau_imbrication -= 1

            if niveau_imbrication == 0:
                in_bloc = False

            continue

        if niveau_imbrication == 1 and line_strip.startswith("edit "):
            match = re.search(r'edit\s+"([^"]+)"', line_strip)
            edit_name = match.group(1) if match else line_strip.split()[1].strip('"')

            is_vs = False
            extintf_any = False
            extip = None
            realservers = []
            in_realservers = False
            continue

        if niveau_imbrication == 1 and line_strip == "next":
            if edit_name and is_vs:
                vs_found = True

                if extintf_any:
                    if edit_name in vs_acceptables_par_policy:
                        vs_conformes_avec_reserve_policy.append(edit_name)

                    elif extip and realservers:
                        realservers_hors_subnet = [
                            real_ip for real_ip in realservers
                            if not meme_subnet(extip, real_ip)
                        ]

                        if realservers_hors_subnet:
                            vs_non_conformes.append(edit_name)
                        else:
                            vs_conformes_avec_reserve_subnet.append(edit_name)

                    else:
                        vs_non_conformes.append(edit_name)

            edit_name = None
            is_vs = False
            extintf_any = False
            extip = None
            realservers = []
            in_realservers = False
            continue

        if edit_name and line_strip == "set type server-load-balance":
            is_vs = True

        if edit_name and re.match(r'set extintf\s+"?any"?$', line_strip):
            extintf_any = True

        if edit_name and line_strip.startswith("set extip "):
            extip = line_strip.replace("set extip", "").strip().strip('"')

        if edit_name and in_realservers and line_strip.startswith("set ip "):
            real_ip = line_strip.replace("set ip", "").strip().strip('"')
            realservers.append(real_ip)

    if not vs_found:
        return "Absence de Virtual Server", "N/A"

    messages = []

    if vs_non_conformes:
        messages.append(
            "Virtual Server(s) avec 'ANY' sur l'interface externe non conforme(s) : "
            + ", ".join(vs_non_conformes)
        )

    if vs_conformes_avec_reserve_subnet:
        messages.append(
            "Présence de Virtual Server(s) avec 'ANY' sur l'interface externe, "
            "mais l'IP externe est dans le même subnet que les real servers, "
            "cette configuration est donc considérée comme acceptable dans ce contexte : "
            + ", ".join(vs_conformes_avec_reserve_subnet)
        )

    if vs_conformes_avec_reserve_policy:
        messages.append(
            "Présence de Virtual Server(s) avec 'ANY' sur l'interface externe, "
            "mais le Virtual Server est utilisé dans au moins une firewall policy dont l'interface source "
            "est équivalente à du multi-interfaces (plusieurs interfaces, srcintf 'any' ou zone contenant plusieurs interfaces), "
            "cette configuration est donc considérée comme acceptable dans ce contexte : "
            + ", ".join(vs_conformes_avec_reserve_policy)
        )

    if messages:
        return ".\n".join(messages), False if vs_non_conformes else True

    return "Les Virtuals Servers sont conformes (aucun avec ANY en interface externe)", True


# Fonction qui verifie la presence du compte par défaut "guest"
def verifier_compte_guest(config_lines):
    in_user_local_block = False
    guest_found = False
    for line in config_lines:
        line = line.strip()
        if line == 'config user local':
            in_user_local_block = True
        elif line == 'end' and in_user_local_block:
            in_user_local_block = False
            return ("Compte Guest par défaut présent", False) if guest_found else ("Compte Guest par défaut non trouvé", True)
        elif in_user_local_block and line.startswith('edit "guest"'):
            guest_found = True
    return "Compte Guest par défaut non trouvé", True

# Fonction qui verifie la presence du compte par défaut "admin"
def verifier_compte_admin(config_lines):
    in_admin_block = False
    admin_found = False
    nested_level = 0
    for line in config_lines:
        line = line.strip()
        if line.startswith('config'):
            if line == 'config system admin':
                in_admin_block = True
                nested_level = 1
            elif in_admin_block:
                nested_level += 1
        elif line == 'end' and in_admin_block:
            nested_level -= 1
            if nested_level == 0:
                in_admin_block = False
        elif in_admin_block and line.startswith('edit "admin"'):
            admin_found = True
    return ("Le compte Admin par défaut est présent", False) if admin_found else ("Compte Admin par défaut non trouvé", True)


# Fonction pour vérifier la synchronisation du FGT avec un FortiManager
def verifier_sync_fortimanager(config_lines):
    in_central_management = False
    central_management_type = None
    fmg_server = None

    for line in config_lines:
        line = line.strip()
        if line == 'config system central-management':
            in_central_management = True
            central_management_type = None  # reset à l'entrée du bloc
            fmg_server = None
        elif line == 'end' and in_central_management:
            in_central_management = False
        elif in_central_management:
            if line.startswith('set type'):
                parts = line.split()
                if len(parts) >= 3:
                    central_management_type = parts[2].lower()
            elif line.startswith('set fmg'):
                parts = line.split('"')
                if len(parts) > 1:
                    fmg_server = parts[1]  # Extraire uniquement la chaîne entre guillemets

    if central_management_type == "fortimanager":
        if fmg_server:
            return f"Le FortiGate est synchronisé avec le FortiManager {fmg_server}. Etat de la synchronisation à vérifier.", True
        else:
            return "Le FortiGate est configuré pour synchroniser avec un FortiManager mais le serveur n’est pas précisé.", False

    elif central_management_type == "fortiguard":
        return "Le FortiGate est synchronisé avec FortiCloud. Etat de la synchronisation à vérifier.", True

    else:
        return "Le FortiGate n'est pas synchronisé avec un FortiManager ni avec FortiCloud.", False


def verifier_sync_fortianalyzer(config_lines):
    in_faz_setting = False
    in_faz_cloud_setting = False
    faz_status = "disable"
    faz_server = None
    faz_cloud_status = "disable"

    for line in config_lines:
        line = line.strip()

        # Bloc FortiAnalyzer classique
        if line == 'config log fortianalyzer setting':
            in_faz_setting = True
            faz_status = "disable"
            faz_server = None

        elif line == 'end' and in_faz_setting:
            in_faz_setting = False

        elif in_faz_setting:
            if line.startswith('set status'):
                parts = line.split()
                if len(parts) >= 3:
                    faz_status = parts[2].lower()

            elif line.startswith('set server'):
                if '"' in line:
                    parts = line.split('"')
                    if len(parts) > 1:
                        faz_server = parts[1]
                else:
                    parts = line.split()
                    if len(parts) >= 3:
                        faz_server = parts[2]

        # Bloc FortiAnalyzer Cloud
        elif line == 'config log fortianalyzer-cloud setting':
            in_faz_cloud_setting = True
            faz_cloud_status = "disable"

        elif line == 'end' and in_faz_cloud_setting:
            in_faz_cloud_setting = False

        elif in_faz_cloud_setting:
            if line.startswith('set status'):
                parts = line.split()
                if len(parts) >= 3:
                    faz_cloud_status = parts[2].lower()

    # Résultats
    if faz_status == "enable" and faz_server:
        return (
            f"Le FortiGate est synchronisé avec le FortiAnalyzer {faz_server}. "
            "Etat de la synchronisation à vérifier.",
            True
        )
    elif faz_cloud_status == "enable":
        return (
            "Le FortiGate est synchronisé avec FortiAnalyzer Cloud. "
            "Etat de la synchronisation à vérifier",
            True
        )
    else:
        return (
            "Le FortiGate n'est pas synchronisé avec un FortiAnalyzer "
            "ni avec FortiAnalyzer Cloud",
            False
        )



def extraire_modele_version_fortigate(config_lines):
    """
    Extrait le modèle et la version du FortiGate depuis les lignes de configuration
    Retourne: (message, version, modele_normalise)
    """

    def normaliser_modele(config_model):
        """
        Convertit le nom du modèle du fichier de config vers le nom standardisé
        Exemple: FG100F -> 100F, FGVM64 -> VM64, F2K60F -> 2600F
        """
        # Cas spéciaux VM
        if config_model.startswith('FGVM'):
            return config_model.replace('FG', '')

        # Cas spéciaux avec patterns complexes
        special_patterns = {
            r'F2K60F': '2600F',
            r'FG(\d)H(\d)([EFG])': lambda m: f"{m.group(1)}0{m.group(2)}{m.group(3)}",  # FG3H0E -> 300E
            r'FG(\d)H(\d)([EFG])': lambda m: f"{m.group(1)}0{m.group(2)}{m.group(3)}",  # FG4H1F -> 401F
            r'FG9H(\d)G': lambda m: f"90{m.group(1)}G",  # FG9H0G -> 900G
            r'FG1K(\d)D': lambda m: f"1{m.group(1)}00D",  # FG1K2D -> 1200D
            r'FG1K(\d)F': lambda m: f"100{m.group(1)}F",  # FG1K0F -> 1000F
            r'FG18(\d)F': lambda m: f"180{m.group(1)}F",  # FG180F -> 1800F
            r'FG10E(\d)': lambda m: f"110{m.group(1)}E",  # FG10E0 -> 1100E
            r'FGT1KD': '1000D'
        }

        # Vérifier les patterns spéciaux
        for pattern, replacement in special_patterns.items():
            if callable(replacement):
                match = re.match(pattern, config_model)
                if match:
                    return replacement(match)
            else:
                if re.match(pattern, config_model):
                    return replacement

        # Pattern générique pour les modèles standards
        # FGT30E -> 30E, FG100F -> 100F, etc.
        standard_patterns = [
            (r'FGT(\d+[EFG])', r'\1'),  # FGT30E -> 30E
            (r'FG(\d+[EFG])', r'\1'),  # FG100F -> 100F
            (r'FG(\d+D)', r'\1'),  # FG800D -> 800D
        ]

        for pattern, replacement in standard_patterns:
            match = re.match(pattern, config_model)
            if match:
                return match.group(1)

        # Si aucun pattern ne correspond, retourner tel quel
        return config_model

    for line in config_lines:
        if line.startswith('#config-version'):
            try:
                parts = line.split('=')
                config_version = parts[1].split(':')[0]
                model_version_split = config_version.split('-')

                if len(model_version_split) >= 2:
                    config_model = model_version_split[0]  # "FGVM64", "FG100F", "F2K60F"
                    version = model_version_split[1]

                    # Normaliser le modèle
                    normalized_model = normaliser_modele(config_model)

                    return (f"Modèle FGT : {config_model} ({normalized_model}), Version firmware : {version}",
                            version,
                            normalized_model)
            except (IndexError, ValueError):
                continue

    return "Version du FortiGate non trouvée", None, None


def parse_version(version_str):
    """
    Convertit un string de version (ex: '7.4.1') en tuple d'entiers (ex: (7,4,1)).
    Si le format n'est pas respecté, renvoie (0,0,0) par défaut.
    """
    try:
        parts = version_str.split('.')
        # On limite à 3 parties max pour éviter les formats exotiques
        major, minor, patch = (int(x) for x in parts[:3])
        return (major, minor, patch)
    except ValueError:
        return (0, 0, 0)




# Chemin fixe vers ton fichier local
FORTIGATE_EOL_XLSX = _get_references_path("fortigate-model-eol.xlsx")

def verifier_modele_fortigate_eol(modele) -> Tuple[str, bool]:
    """
    Vérifie le statut de support Fortinet à partir du fichier Excel local.

    Logique :
      - Si le modèle est présent dans le fichier et EOE = Y => non conforme
      - Si le modèle est présent dans le fichier et EOE != Y => conforme
      - Si le modèle est absent du fichier :
          - génération F ou supérieure => conforme
          - génération inférieure à F => non conforme / obsolète
    """

    def norm_key(s: str) -> str:
        return re.sub(r"[^A-Z0-9]", "", (s or "").upper())

    def extract_model_keys(product_details: str) -> set[str]:
        """
        Extrait des clés modèles depuis la colonne "Product Details".

        Exemples :
          - FortiGate-60E -> {"60E"}
          - FortiWiFi-60E -> {"60E"}
          - FortiGate-50G/51G and variants -> {"50G", "51G"}
          - FortiGate-40F-3G4G -> {"40F3G4G"}
        """
        txt = (product_details or "").strip()
        if not txt:
            return set()

        up = txt.upper()

        up = re.sub(r"\bAND VARIANTS\b", "", up)
        up = re.sub(r"\bVARIANTS\b", "", up)
        up = re.sub(r"\bFORTIGATE\b", "", up)
        up = re.sub(r"\bFORTIWIFI\b", "", up)
        up = re.sub(r"\bRUGGED\b", "", up)

        parts = re.split(r"[\/,;]|(?:\s+)", up)

        keys: set[str] = set()

        for p in parts:
            p = p.strip("-_ \t")
            if not p:
                continue

            k = norm_key(p)

            if re.match(r"^\d", k) and re.search(r"[A-Z]", k):
                keys.add(k)

        # Extraction globale au cas où le découpage précédent ne suffit pas
        for m in re.findall(r"\d+[A-Z]\w*", norm_key(up)):
            if re.match(r"^\d", m) and re.search(r"[A-Z]", m):
                keys.add(m)

        return keys

    def get_generation_letter(model_key: str) -> str | None:
        """
        Extrait la lettre de génération du modèle.

        Exemples :
          - 60E -> E
          - 100F -> F
          - 40F3G4G -> F
          - 90G -> G
        """
        match = re.search(r"\d+([A-Z])", model_key)
        return match.group(1) if match else None

    # --- validations ---
    if not modele or not str(modele).strip():
        return "Le modèle FortiGate n’a pas été renseigné.", False

    if not os.path.exists(FORTIGATE_EOL_XLSX):
        return f"Le fichier de référence EOE est introuvable : {FORTIGATE_EOL_XLSX}", False

    target = norm_key(str(modele))

    if not target:
        return f"Le modèle FortiGate renseigné est invalide : {modele}", False

    # --- lecture Excel ---
    try:
        wb = openpyxl.load_workbook(FORTIGATE_EOL_XLSX, data_only=True)
        ws = wb.active
    except Exception as e:
        return f"Impossible d’ouvrir le fichier de référence EOE : {e}", False

    # --- construire un index modèle -> (product_details, recommended, eoe) ---
    index: dict[str, tuple[str, str, str]] = {}

    for row in ws.iter_rows(min_row=2, values_only=True):
        product_details = row[0] if len(row) > 0 else None
        recommended = row[1] if len(row) > 1 else None
        eoe = row[2] if len(row) > 2 else None

        if not product_details:
            continue

        product_details_str = str(product_details).strip()
        recommended_str = str(recommended).strip() if recommended is not None else ""
        eoe_str = str(eoe).strip().upper() if eoe is not None else ""

        keys = extract_model_keys(product_details_str)

        for k in keys:
            if k not in index:
                index[k] = (product_details_str, recommended_str, eoe_str)

    # --- modèle trouvé dans le fichier de référence ---
    if target in index:
        product_details, recommended, eoe_str = index[target]

        if eoe_str == "Y":
            return (
                f"Le modèle {product_details} est obsolète et n’est plus supporté par Fortinet "
                f"(End of Engineering Support dépassé). "
                f"(source : fichier local).",
                False,
            )

        return (
            f"Le modèle {product_details} est actuellement supporté par Fortinet. "
            f"(source : fichier local).",
            True,
        )

    # --- modèle non trouvé : cas FortiGate VM ---
    if target.startswith("VM"):
        return (
            f"Le modèle {modele} est un FortiGate virtuel. "
            f"Son statut de support dépend de la version de FortiOS et de la licence, "
            f"et non d’une génération matérielle E/F/G.",
            True,
        )

    # --- modèle non trouvé : décision selon génération ---
    generation = get_generation_letter(target)

    if generation and generation >= "F":
        return (
            f"Le modèle {modele} est actuellement supporté par Fortinet.",
            True,
        )

    if generation and generation < "F":
        return (
            f"Le modèle {modele} est obsolète et n’est plus supporté par Fortinet.",
            False,
        )

    return (
        f"Impossible de déterminer le statut de support Fortinet pour le modèle {modele}.",
        False,
    )


def est_version_concernee_par_cve(version):
    base_url = "https://www.fortiguard.com/psirt"
    params = {
        "filter": "1",
        "product": "FortiOS-6K7K,FortiOS",
        "version": version,
        "severity": ["5", "4"],
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    }

    try:
        # timeout=(connexion, lecture) pour bien distinguer
        response = requests.get(
            base_url,
            headers=headers,
            params=params,
            timeout=(5, 30),  # 5s pour se connecter, 30s pour lire la réponse
        )
        # Ne raise pas tout de suite, on veut voir ce qu'il y a éventuellement dans le body
        if response.status_code != 200:
            print("Début du body:", response.text[:500])
            response.raise_for_status()
    # Le second membre du tuple signifie "version concernee par au moins une CVE",
    # et pilote le marquage non-conforme dans les rapports. En cas d'echec reseau
    # on renvoie True : une verification impossible n'est pas une verification
    # reussie, et un audit ne doit jamais declarer un firmware sain par defaut.
    # Ce cas devient frequent en conteneur si l'acces a fortiguard.com est filtre.
    except requests.exceptions.Timeout as e:
        print("Timeout rencontré :", e)
        return (
            f"VERIFICATION CVE IMPOSSIBLE pour la version {version} : délai dépassé "
            f"en contactant fortiguard.com (site lent ou filtrage réseau). "
            f"Le statut CVE de cette version n'a PAS pu être établi et doit être "
            f"vérifié manuellement : https://www.fortiguard.com/psirt",
            True,
        )
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des données : {e}")
        return (
            f"VERIFICATION CVE IMPOSSIBLE pour la version {version} : erreur réseau "
            f"en contactant fortiguard.com. Le statut CVE de cette version n'a PAS "
            f"pu être établi et doit être vérifié manuellement : "
            f"https://www.fortiguard.com/psirt",
            True,
        )

    soup = BeautifulSoup(response.text, 'html.parser')
    cve_elements = soup.find_all("b", class_="cve")
    cve_list = [cve.get_text(strip=True) for cve in cve_elements]

    # Le selecteur <b class="cve"> casse des que fortiguard.com change son
    # markup. Repli : on cherche les identifiants CVE directement dans la page.
    if not cve_list:
        cve_list = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", response.text)))

    # Point critique : une page peut repondre HTTP 200 sans etre la page PSIRT.
    # fortiguard.com est derriere une protection anti-bot qui renvoie 200 avec
    # un corps "Just a moment - verifying connection security". Sans ce controle,
    # aucun CVE n'est trouve, aucune exception n'est levee, et la fonction conclut
    # "version saine" -- un faux negatif silencieux sur un controle de securite.
    # Zero CVE n'est une conclusion valable que si la page analysee est bien la
    # page PSIRT.
    page = response.text.lower()
    challenge_markers = (
        "just a moment",
        "verifying connection security",
        "checking your browser",
        "cf-browser-verification",
        "enable javascript and cookies",
        "attention required",
    )
    page_is_unusable = any(m in page for m in challenge_markers) or "psirt" not in page

    if not cve_list and page_is_unusable:
        return (
            f"VERIFICATION CVE IMPOSSIBLE pour la version {version} : fortiguard.com "
            f"a répondu sans fournir la liste des vulnérabilités (protection anti-bot "
            f"ou changement de format de la page). Le statut CVE de cette version n'a "
            f"PAS pu être établi et doit être vérifié manuellement : "
            f"https://www.fortiguard.com/psirt",
            True,
        )

    if len(cve_list) > 3:
        message = (
            f"Version {version} concernée par plus de 3 CVE 'high' et/ou 'critiques' connues.\n "
            "Pour voir la liste : https://www.fortiguard.com/psirt"
        )
    elif len(cve_list) > 0:
        cve_details = ', '.join(cve_list)
        message = (
            f"Version {version} concernée par des CVE 'high' et/ou 'critiques' connues : "
            f"{cve_details}. \n Source : https://www.fortiguard.com/psirt"
        )
    else:
        message = (
            f"Version {version} non concernée par des CVE 'high' et/ou 'critiques' connues\n "
            "Source : https://www.fortiguard.com/psirt"
        )

    return message, len(cve_list) > 0


def verifier_vpn_ssl_utilisation(config_lines):
    vpn_ssl_utilise = False
    vpn_ssl_desactive = False
    in_vpn_ssl_settings = False

    # Analyse du bloc 'config vpn ssl settings' pour vérifier l'utilisation et le statut du VPN SSL
    for line in config_lines:
        stripped_line = line.strip()

        if stripped_line == 'config vpn ssl settings':
            in_vpn_ssl_settings = True
        elif stripped_line == 'end' and in_vpn_ssl_settings:
            in_vpn_ssl_settings = False
        elif in_vpn_ssl_settings:
            if 'set status disable' in stripped_line:
                vpn_ssl_desactive = True
            if 'set source-interface' in stripped_line:
                vpn_ssl_utilise = True

    if vpn_ssl_desactive:
        result = "Le VPN SSL est désactivé"
        return result, True
    elif not vpn_ssl_utilise:
        result = "Le VPN SSL n'est pas utilisé"
        return result, True
    else:
        result = "Le VPN SSL est configuré."
        return result, False


def extraire_vips_avec_portforward(config_lines):
    vips = {}
    in_vip_block = False
    current_vip = None

    for line in config_lines:
        line = line.strip()
        if line == 'config firewall vip':
            in_vip_block = True
        elif line == 'end' and in_vip_block:
            in_vip_block = False
        elif in_vip_block:
            if line.startswith('edit '):
                # Extract the name after 'edit '
                name_part = line[len('edit '):].strip()
                # Remove quotes if present
                if name_part.startswith('"') and name_part.endswith('"'):
                    name = name_part[1:-1]
                else:
                    name = name_part
                current_vip = {'name': name, 'portforward': False}
            elif current_vip and 'set portforward enable' in line:
                current_vip['portforward'] = True
            elif line == 'next' and current_vip:
                vips[current_vip['name']] = current_vip['portforward']
                current_vip = None

    return vips


def verifier_presence_all_port_dans_regles(config_lines, selected_wan_interfaces):
    vips = extraire_vips_avec_portforward(config_lines)
    in_firewall_policy = False
    current_rule = None
    all_services_rules = []

    for line in config_lines:
        line = line.strip()
        if line == 'config firewall policy':
            in_firewall_policy = True
        elif line == 'end' and in_firewall_policy:
            in_firewall_policy = False
            if current_rule and current_rule.get('action') == 'accept':
                # Modification : prise en compte uniquement si dstintf est WAN
                if ('ALL' in current_rule.get('services', []) and not current_rule.get('is_safe', False) and
                    current_rule.get('dstintf') in selected_wan_interfaces):
                    if 'IPV4_W_SNS' not in current_rule.get('dstaddr', []):
                        all_services_rules.append(current_rule['id'])
            current_rule = None
        elif in_firewall_policy:
            if line.startswith('edit '):
                if current_rule and current_rule.get('action') == 'accept':
                    # Modification : prise en compte uniquement si dstintf est WAN
                    if ('ALL' in current_rule.get('services', []) and not current_rule.get('is_safe', False) and
                        current_rule.get('dstintf') in selected_wan_interfaces):
                        if 'IPV4_W_SNS' not in current_rule.get('dstaddr', []):
                            all_services_rules.append(current_rule['id'])
                current_rule = {
                    'id': line.split(' ')[1].strip('"'),
                    'services': [],
                    'is_safe': False,
                    'action': 'deny',
                    'srcintf': None,
                    'dstintf': None,
                    'dstaddr': []
                }
            elif line.startswith('set service '):
                services = line.split('"')[1::2]
                current_rule['services'].extend(services)
            elif line.startswith('set dstaddr '):
                dstaddr = line.split('"')[1::2]
                current_rule['dstaddr'].extend(dstaddr)
                if 'IPV4_W_SNS' in dstaddr:
                    current_rule['is_safe'] = True
                elif any(addr in vips and vips[addr] for addr in dstaddr):
                    current_rule['is_safe'] = True
            elif line.startswith('set action '):
                current_rule['action'] = line.split(' ')[2]
            elif line.startswith('set srcintf '):
                current_rule['srcintf'] = line.split('"')[1]
            elif line.startswith('set dstintf '):
                current_rule['dstintf'] = line.split('"')[1]
            elif line.startswith('set internet-service enable') or line.startswith('set internet-service-src enable'):
                current_rule['is_safe'] = True
            elif line.startswith('set internet-service-name') or line.startswith('set internet-service-src-name'):
                current_rule['is_safe'] = True

    if all_services_rules:
        if len(all_services_rules) == 1:
            return f"Tous les ports sont ouverts dans la règle ID : {all_services_rules[0]}. Ce résultat exclut les règles en DENY", False, all_services_rules
        else:
            return f"Tous les ports sont ouverts dans les règles ID : {', '.join(all_services_rules)}. Ce résultat exclut les règles en DENY", False, all_services_rules
    return "Absence de 'ALL' dans les ports des règles à destination d'Internet. Ce résultat exclut les règles en DENY", True, []


def verifier_logs_par_regle(config_lines):
    def scan_initial(config_lines):
        in_firewall_policy = False
        current_rule_id = None

        rule_logs = {}
        implicit_deny_logging = 'disable'

        # Recherche du log implicit deny
        for line in config_lines:
            if 'set fwpolicy-implicit-log enable' in line.strip().lower():
                implicit_deny_logging = 'all'
                break

        for line in config_lines:
            line = line.strip()
            line_lower = line.lower()

            if line_lower == 'config firewall policy':
                in_firewall_policy = True
                continue

            elif line_lower == 'end' and in_firewall_policy:
                in_firewall_policy = False
                continue

            if in_firewall_policy:
                if line_lower.startswith('edit '):
                    current_rule_id = line.split(' ', 1)[1].strip('"')
                    rule_logs[current_rule_id] = None

                elif line_lower.startswith('set logtraffic') and current_rule_id:
                    if ' all' in f' {line_lower} ':
                        rule_logs[current_rule_id] = 'all'
                    elif ' disable' in f' {line_lower} ':
                        rule_logs[current_rule_id] = 'disable'
                    elif ' utm' in f' {line_lower} ':
                        rule_logs[current_rule_id] = 'utm'

                elif line_lower == 'next' and current_rule_id:
                    if rule_logs[current_rule_id] is None:
                        rule_logs[current_rule_id] = 'utm'

                    current_rule_id = None

        rules_with_logs_all = [
            rule_id for rule_id, status in rule_logs.items()
            if status == 'all'
        ]

        rules_with_logs_disabled = [
            rule_id for rule_id, status in rule_logs.items()
            if status == 'disable'
        ]

        rules_with_logs_utm = [
            rule_id for rule_id, status in rule_logs.items()
            if status == 'utm'
        ]

        nb_all = len(rules_with_logs_all)
        nb_disable = len(rules_with_logs_disabled)
        nb_utm = len(rules_with_logs_utm)

        # Gestion de la règle implicit deny
        if implicit_deny_logging == 'all':
            nb_all += 1
        else:
            nb_disable += 1

        return {
            'rules_with_logs_all': rules_with_logs_all,
            'rules_with_logs_disabled': rules_with_logs_disabled,
            'rules_with_logs_utm': rules_with_logs_utm,
            'counts': {
                'all': nb_all,
                'disable': nb_disable,
                'utm': nb_utm
            },
            'security_fabric': {
                'enabled': False,
                'log_unification_disabled': None,
                'configuration_sync_local': None,
                'mode': 'scan_initial'
            }
        }

    def analyser_security_fabric(config_lines):
        in_csf = False
        csf_enabled = False
        log_unification_disabled = False
        configuration_sync_local = False

        for raw_line in config_lines:
            line = raw_line.strip().lower()

            if line == 'config system csf':
                in_csf = True
                continue

            if in_csf and line == 'end':
                in_csf = False
                continue

            if in_csf:
                if line == 'set status enable':
                    csf_enabled = True

                elif line == 'set log-unification disable':
                    log_unification_disabled = True

                elif line == 'set configuration-sync local':
                    configuration_sync_local = True

        return csf_enabled, log_unification_disabled, configuration_sync_local

    def recuperer_ids_regles_firewall(config_lines):
        in_firewall_policy = False
        rule_ids = []

        for raw_line in config_lines:
            line = raw_line.strip()
            line_lower = line.lower()

            if line_lower == 'config firewall policy':
                in_firewall_policy = True
                continue

            elif line_lower == 'end' and in_firewall_policy:
                in_firewall_policy = False
                continue

            if in_firewall_policy and line_lower.startswith('edit '):
                rule_id = line.split(' ', 1)[1].strip('"')
                rule_ids.append(rule_id)

        return rule_ids

    csf_enabled, log_unification_disabled, configuration_sync_local = analyser_security_fabric(config_lines)

    # Cas 1 : Security Fabric absent ou non activé
    if not csf_enabled:
        return scan_initial(config_lines)

    # Cas 2 : Security Fabric actif, mais log-unification désactivé
    if log_unification_disabled:
        result = scan_initial(config_lines)
        result['security_fabric'] = {
            'enabled': True,
            'log_unification_disabled': True,
            'configuration_sync_local': configuration_sync_local,
            'mode': 'scan_initial'
        }
        return result

    # Cas 3 : Security Fabric actif, log-unification non désactivé,
    # mais configuration-sync local
    if configuration_sync_local:
        result = scan_initial(config_lines)
        result['security_fabric'] = {
            'enabled': True,
            'log_unification_disabled': False,
            'configuration_sync_local': True,
            'mode': 'scan_initial'
        }
        return result

    # Cas 4 : Security Fabric actif,
    # pas de log-unification disable,
    # pas de configuration-sync local
    # => toutes les règles sont considérées en logtraffic all
    rule_ids = recuperer_ids_regles_firewall(config_lines)

    nb_all = len(rule_ids)

    # On ajoute l'implicit deny pour rester cohérent avec le scan initial.
    nb_all += 1

    return {
        'rules_with_logs_all': rule_ids,
        'rules_with_logs_disabled': [],
        'rules_with_logs_utm': [],
        'counts': {
            'all': nb_all,
            'disable': 0,
            'utm': 0
        },
        'security_fabric': {
            'enabled': True,
            'log_unification_disabled': False,
            'configuration_sync_local': False,
            'mode': 'all_rules_considered_all'
        }
    }

def verifier_usage_by_sequence(config_lines):
    """
    Vérifie si le client utilise une logique 'by sequence' dans les policies du firewall.
    Critères de détection :
      1. Présence d'un 'set global-label'
      2. Présence de plusieurs interfaces dans srcintf ou dstintf
      3. Présence de "any" dans srcintf et/ou dstintf
    """

    in_firewall_policy = False
    by_sequence_detected = False

    # Capture toutes les valeurs entre guillemets: "port1" "port2" ...
    quoted_values = re.compile(r'"([^"]+)"')

    for raw_line in config_lines:
        line = raw_line.strip()

        # Entrée dans la section firewall policy
        if line == 'config firewall policy':
            in_firewall_policy = True
            continue

        # Sortie de la section firewall policy
        if line == 'end' and in_firewall_policy:
            in_firewall_policy = False
            continue

        if not in_firewall_policy:
            continue

        # Critère 1 : global-label
        if line.startswith('set global-label '):
            by_sequence_detected = True
            continue

        # Critères 2 & 3 : srcintf / dstintf
        if line.startswith('set srcintf ') or line.startswith('set dstintf '):
            interfaces = quoted_values.findall(line)  # ex: ["port1", "port2"] ou ["any"]

            # Si jamais la ligne n'a pas de guillemets (cas rare), fallback simple
            if not interfaces:
                tokens = line.split()
                # tokens: ["set", "srcintf", "any"] par ex.
                if len(tokens) >= 3:
                    interfaces = tokens[2:]

            # Critère 2 : multi-interface
            if len(interfaces) > 1:
                by_sequence_detected = True
                continue

            # Critère 3 : présence de "any"
            if any(i.lower() == "any" for i in interfaces):
                by_sequence_detected = True
                continue

    if by_sequence_detected:
        return (
            "Détection de policy avec plusieurs interfaces, 'any' dans srcintf/dstintf, "
            "ou 'set global-label'. Cela indique que le client fait du 'By Sequence'.",
            True
        )

    return "Aucune policy avec plusieurs interfaces, ni 'any', ni 'set global-label' détectée.", False


def verifier_logs_deny_implicit(config_lines):
    for line in config_lines:
        if 'set fwpolicy-implicit-log enable' in line:
            return "Les logs sont activés sur la règle deny implicit", True
    return "Les logs ne sont pas activés sur la règle deny implicit", False





def verifier_utilisation_geo_ip(config_lines, selected_wan_interfaces):
    in_firewall_address = False
    in_addrgrp = False
    geo_ip_objects = set()
    addrgrp_mapping = {}
    current_object_name = ""
    current_group_name = ""

    # Identification des objets GEO-IP dans les configurations d'adresses et groupes d'adresses
    for line in config_lines:
        line = line.strip()

        # Analyse des objets individuels
        if line.startswith('config firewall address'):
            in_firewall_address = True
        elif line.startswith('end') and in_firewall_address:
            in_firewall_address = False
        elif in_firewall_address:
            if line.startswith('edit '):
                if '"' in line:
                    current_object_name = line.split('"')[1]
                else:
                    parts = line.split()
                    current_object_name = parts[1] if len(parts) > 1 else ""
            elif 'set type geography' in line and current_object_name:
                geo_ip_objects.add(current_object_name)
            elif line == 'next':
                current_object_name = ""

        # Analyse des groupes d'adresses
        if line.startswith('config firewall addrgrp'):
            in_addrgrp = True
        elif line.startswith('end') and in_addrgrp:
            in_addrgrp = False
        elif in_addrgrp:
            if line.startswith('edit '):
                if '"' in line:
                    current_group_name = line.split('"')[1]
                else:
                    parts = line.split()
                    current_group_name = parts[1] if len(parts) > 1 else ""
                addrgrp_mapping[current_group_name] = []
            elif line.startswith('set member') and current_group_name:
                # Extraction sécurisée des membres
                members = line.split('"')[1:-1:2]
                addrgrp_mapping[current_group_name].extend(members)
            elif line == 'next':
                current_group_name = ""

    # Ajouter les objets GEO-IP contenus dans les groupes
    for group, members in addrgrp_mapping.items():
        for member in members:
            if member in geo_ip_objects:
                geo_ip_objects.add(group)
                break

    in_firewall_policy = False
    rules_using_geo_ip = []
    current_rule_id = None
    current_srcintf = None
    current_dstintf = None
    current_srcaddr = []
    current_dstaddr = []

    # Vérification des règles de pare-feu pour l'utilisation de GEO-IP
    for line in config_lines:
        line = line.strip()

        if line.startswith('config firewall policy'):
            in_firewall_policy = True

        elif in_firewall_policy and line.startswith('edit '):
            # Extraction sécurisée de l'ID de règle
            parts = line.split()
            if len(parts) > 1:
                current_rule_id = parts[1].strip('"')
            else:
                current_rule_id = ""

        elif in_firewall_policy and line.startswith('set srcintf '):
            if '"' in line:
                current_srcintf = line.split('"')[1]
            else:
                parts = line.split()
                current_srcintf = parts[1] if len(parts) > 1 else ""

        elif in_firewall_policy and line.startswith('set dstintf '):
            if '"' in line:
                current_dstintf = line.split('"')[1]
            else:
                parts = line.split()
                current_dstintf = parts[1] if len(parts) > 1 else ""

        elif in_firewall_policy and line.startswith('set srcaddr '):
            current_srcaddr = re.findall(r'"([^"]*)"', line)

        elif in_firewall_policy and line.startswith('set dstaddr '):
            current_dstaddr = re.findall(r'"([^"]*)"', line)

        elif in_firewall_policy and line == 'next':
            srcaddr_geoip_match = any(addr in geo_ip_objects for addr in current_srcaddr)
            dstaddr_geoip_match = any(addr in geo_ip_objects for addr in current_dstaddr)

            geoip_in_src_traffic = srcaddr_geoip_match and (
                current_srcintf in selected_wan_interfaces or current_srcintf == "any"
            )
            geoip_in_dst_traffic = dstaddr_geoip_match and (
                current_dstintf in selected_wan_interfaces or current_dstintf == "any"
            )

            if geoip_in_src_traffic or geoip_in_dst_traffic:
                rules_using_geo_ip.append(current_rule_id)

            # Réinitialisation pour la règle suivante
            current_rule_id = None
            current_srcintf = None
            current_dstintf = None
            current_srcaddr = []
            current_dstaddr = []

        elif line == 'end' and in_firewall_policy:
            in_firewall_policy = False

    # Génération du message en fonction des règles détectées
    if rules_using_geo_ip:
        if len(rules_using_geo_ip) == 1:
            result_message = (
                f"GEO-IP est utilisé dans la règle suivante : ID {rules_using_geo_ip[0]}. Il peut être pertinent d'actualiser le filtrage GEO-IP."
            )
        else:
            result_message = (
                "GEO-IP est utilisé dans les règles suivantes : "
                f"{', '.join(rules_using_geo_ip)}. Il peut être pertinent d'actualiser le filtrage GEO-IP."
            )
        return result_message, True
    else:
        # Retour par défaut si aucune règle n'utilise GEO-IP
        return "Aucune utilisation de GEO-IP détectée dans les règles de pare-feu", False



def verifier_http_https_desactive_sur_interfaces_wan(config_lines, wan_interfaces):
    in_system_interface_block = False
    in_secondary_ip_block = False

    current_interface = None
    # Ce dictionnaire stocke pour chaque interface un set des services détectés (ssh, http, https).
    interfaces_access_sets = {}

    for line in config_lines:
        line = line.strip()

        # Début du bloc "config system interface"
        if line == 'config system interface':
            in_system_interface_block = True
            continue

        # Fin du bloc "config system interface" (si on n’est pas dans un sous-bloc secondaryip)
        if line == 'end':
            if in_secondary_ip_block:
                # On sort seulement du bloc secondaryip
                in_secondary_ip_block = False
            elif in_system_interface_block:
                # On sort complètement du bloc system interface
                in_system_interface_block = False
            continue

        # Si on n'est pas dans le bloc "config system interface", on ignore le reste
        if not in_system_interface_block:
            continue

        # Début du bloc "config secondaryip"
        if line.startswith('config secondaryip'):
            in_secondary_ip_block = True
            continue

        # On détecte la commande "edit <nom>" qui définit une interface
        # (uniquement si on n’est pas dans un sous-bloc secondaryip)
        if not in_secondary_ip_block and line.startswith('edit '):
            parts = line.split('"')
            if len(parts) > 1:
                current_interface = parts[1]
            else:
                current_interface = None
            # On initialise le set des accès pour cette interface
            if current_interface and current_interface not in interfaces_access_sets:
                interfaces_access_sets[current_interface] = set()
            continue

        # Début d’un bloc "edit x" à l’intérieur de secondaryip (on pourrait le noter, mais
        # l’important est de continuer à gérer les "set allowaccess" si on en trouve).
        if in_secondary_ip_block and line.startswith('edit '):
            # Ici, si besoin, on pourrait gérer l’identifiant du secondary IP (ex: "edit 1", "edit 2", etc.)
            # Mais l’essentiel est simplement de capter les `set allowaccess`.
            continue

        # Gestion des "set allowaccess ..." (interface principale OU secondary ip)
        if line.startswith('set allowaccess'):
            allowed_accesses = line.split()[2:]
            active_services = [access for access in allowed_accesses if access in ['ssh', 'http', 'https']]

            # On met à jour le set de l’interface en cours si c’est une WAN
            # (ou, si on préfère : on stocke tout, et on filtrera après coup)
            if current_interface and current_interface in wan_interfaces:
                interfaces_access_sets[current_interface].update(active_services)
            continue

        # Quand on rencontre un "next", il peut s’agir :
        # - de la fin de l’édition du secondary IP
        # - ou de la fin de l’édition de l’interface
        # On ne remet `current_interface` à None QUE si on est en dehors du bloc secondaryip
        if line == 'next':
            if in_secondary_ip_block:
                # "next" dans le bloc secondaryip => on finit un secondary ip,
                # mais on reste toujours sur la même interface.
                continue
            else:
                # "next" hors bloc secondaryip => on a fini l’interface.
                current_interface = None
            continue

    # À ce stade, interfaces_access_sets contient pour chaque interface un set de tous les services trouvés.
    # On va filtrer ou construire le résultat final.
    # On ne s’intéresse qu’aux interfaces WAN et seulement si elles ont au moins un des services SSH/HTTP/HTTPS.
    interfaces_access_details = {}
    for interface, services_set in interfaces_access_sets.items():
        # Ne conserver que les services SSH/HTTP/HTTPS
        relevant_services = services_set.intersection({'ssh', 'http', 'https'})
        if relevant_services:
            interfaces_access_details[interface] = sorted(relevant_services)  # Tri pour l’affichage

    if interfaces_access_details:
        result_lines = []
        for interface, services in interfaces_access_details.items():
            result_lines.append(f"Services activés sur {interface} (ou IP secondaire rattachée à ce port) : {', '.join(services)}.")
        # False => le contrôle échoue puisqu’on a trouvé des interfaces WAN avec SSH/HTTP/HTTPS activés
        return " ".join(result_lines), False, list(interfaces_access_details.keys()), interfaces_access_details

    # Si aucune interface WAN n’a SSH/HTTP/HTTPS activé
    return "SSH/HTTP/HTTPS désactivé sur toutes les interfaces WAN", True, [], {}


def verifier_compte_admin_sns(config_lines):
    sns_admins = ["admin-sns", "sns-admin", "admin_sns", "adm_sns", "sns_admin", "snsadmin", "adminsns", "admin.sns", "sns.admin", "adm.sns", "sns.adm", "sns", "admin-SNS"]
    admin_sns_found = False
    found_admin_name = None
    in_system_admin_block = False
    in_edit_block = False
    depth = 0
    pki_account = False
    mfa_enabled = False
    mfa_email_correct = False
    found_mfa_email = None

    for line in config_lines:
        line = line.strip()
        if line == 'config system admin':
            in_system_admin_block = True
        elif line == 'end' and in_system_admin_block and depth == 0:
            in_system_admin_block = False
        elif in_system_admin_block:
            if line == 'config' or line.startswith('config '):
                depth += 1
            elif line == 'end':
                if depth > 0:
                    depth -= 1
                else:
                    in_system_admin_block = False
            elif line.startswith('edit ') and '"' in line and depth == 0:
                admin_name = line.split('"')[1]
                if admin_name in sns_admins:
                    in_edit_block = True
                    found_admin_name = admin_name
                    pki_account = False
                    mfa_enabled = False
                    mfa_email_correct = False
                    found_mfa_email = None
            elif in_edit_block:
                if 'set peer-group "sns-pki-admin-group"' in line:
                    pki_account = True
                elif 'set password' in line and not pki_account:
                    admin_sns_found = True
                elif 'set two-factor email' in line:
                    mfa_enabled = True
                elif 'set email-to ' in line:
                    found_mfa_email = line.split('"')[1]
                    if found_mfa_email == "support@sns-security.fr":
                        mfa_email_correct = True
                elif line == 'next' and depth == 0:
                    in_edit_block = False
                    if admin_sns_found and not pki_account:
                        break

    if admin_sns_found and not pki_account:
        if mfa_enabled and mfa_email_correct:
            return (f"Compte administrateur local SNS trouvé : '{found_admin_name}',\n avec MFA activée avec l'email 'support@sns-security.fr'", True)
        elif not mfa_enabled:
            return (f"Compte administrateur local SNS trouvé : '{found_admin_name}',\n mais la MFA n'est pas activée", False)
        elif not mfa_email_correct and found_mfa_email:
            return (f"Compte administrateur local SNS trouvé : '{found_admin_name}',\n MFA activée mais avec l'email : {found_mfa_email}", False)
        else:
            return (f"Compte administrateur local SNS trouvé : '{found_admin_name}',\n mais la MFA n'est pas conforme à notre politique", False)
    else:
        return ("Compte administrateur local SNS non trouvé", False)


def verifier_suppression_compte_pki_sns(config_lines):
    pki_sns_found = False
    in_system_admin_block = False
    in_edit_block = False
    depth = 0

    for line in config_lines:
        line = line.strip()
        if line == 'config system admin':
            in_system_admin_block = True
        elif line == 'end' and in_system_admin_block and depth == 0:
            in_system_admin_block = False
        elif in_system_admin_block:
            if line == 'config' or line.startswith('config '):
                depth += 1
            elif line == 'end':
                if depth > 0:
                    depth -= 1
                else:
                    in_system_admin_block = False
            elif line.startswith('edit "sns"') and depth == 0:
                in_edit_block = True
            elif in_edit_block and 'set peer-group' in line:
                pki_sns_found = True
            elif in_edit_block and 'set peer-auth enable' in line:
                pki_sns_found = True
            elif line == 'next' and in_edit_block and depth == 0:
                in_edit_block = False

    return ("Compte administrateur PKI 'sns' trouvé", False) if pki_sns_found else ("Absence de compte administrateur PKI 'sns'", True)


def verifier_presence_compte_pki_pkisns(config_lines):
    pki_sns_found = False
    in_system_admin_block = False
    in_edit_block = False
    depth = 0

    for line in config_lines:
        line = line.strip()
        if line == 'config system admin':
            in_system_admin_block = True
        elif line == 'end' and in_system_admin_block and depth == 0:
            in_system_admin_block = False
        elif in_system_admin_block:
            if line == 'config' or line.startswith('config '):
                depth += 1
            elif line == 'end':
                if depth > 0:
                    depth -= 1
                else:
                    in_system_admin_block = False
            elif line.startswith('edit "pki-sns"') and depth == 0:
                in_edit_block = True
            elif in_edit_block and 'set peer-group' in line:
                pki_sns_found = True
            elif in_edit_block and 'set peer-auth enable' in line:
                pki_sns_found = True
            elif line == 'next' and in_edit_block and depth == 0:
                in_edit_block = False

    return ("Compte administrateur PKI 'pki-sns' trouvé", True) if pki_sns_found else ("Absence de compte administrateur PKI 'pki-sns'", False)


# Listes/ensembles de valeurs acceptées
ACCEPTED_ENCRYPTIONS = {'aes256', 'aes256gcm', 'chacha20poly1305'}
ACCEPTED_AUTHENTICATIONS = {'sha256', 'sha384', 'sha512', 'prfsha256', 'prfsha384', 'prfsha512'}


def is_proposal_compliant(proposal):
    """
    Vérifie qu'une proposition (ex. 'aes256-sha512' ou 'aes256gcm')
    est conforme à la politique de chiffrement et d'authentification.
    """
    proposal = proposal.lower()
    # Cas 1 : algorithmes AEAD (GCM/CHACHA) => pas de '-'
    if '-' not in proposal:
        # On considère que proposal = aes256gcm ou chacha20poly1305, etc.
        return proposal in ACCEPTED_ENCRYPTIONS

    # Cas 2 : algorithme de chiffrement + algorithme d'authentification
    enc, auth = proposal.split('-', 1)
    return (enc in ACCEPTED_ENCRYPTIONS) and (auth in ACCEPTED_AUTHENTICATIONS)


def verifier_ike_version(config_lines):
    """
    Vérifie que tous les tunnels Phase 1 utilisent IKEv2.
    Supporte les formes:
      - edit "Nom Du Tunnel"
      - edit TUNNEL_X
      - edit 1
    et capture 'set ike-version 1|2'. Si non précisé, on considère 1 par défaut (non conforme).
    """
    in_phase1_block = False
    current_tunnel = None
    ike_issues = []

    # helpers
    def _flush_current():
        nonlocal current_tunnel, ike_issues
        if current_tunnel:
            if current_tunnel.get('ike_version', 1) != 2:
                ike_issues.append(current_tunnel['name'])
            current_tunnel = None

    # patterns
    p_edit_quoted = re.compile(r'^edit\s+"([^"]+)"$')
    p_edit_unquoted = re.compile(r'^edit\s+(\S+)$')
    p_set_ike = re.compile(r'^set\s+ike-version\s+(\d+)\b', re.IGNORECASE)

    for raw in config_lines:
        line = raw.strip()
        if not line:
            continue

        if line == 'config vpn ipsec phase1-interface':
            in_phase1_block = True
            current_tunnel = None
            continue

        if in_phase1_block:
            if line == 'end':
                # fin du bloc phase1 -> valider le dernier tunnel
                _flush_current()
                in_phase1_block = False
                continue

            if line == 'next':
                # fin d'un tunnel -> valider
                _flush_current()
                continue

            m_q = p_edit_quoted.match(line)
            m_u = p_edit_unquoted.match(line)

            if m_q or (m_u and not line.lower().startswith('edit delete')):  # ignore "edit delete" éventuels
                # on démarre un nouveau tunnel -> flusher l'actuel avant
                _flush_current()
                name = (m_q.group(1) if m_q else m_u.group(1)).strip()
                current_tunnel = {'name': name, 'ike_version': 1}  # défaut: 1 (non conforme)
                continue

            if current_tunnel:
                m_ike = p_set_ike.match(line)
                if m_ike:
                    try:
                        current_tunnel['ike_version'] = int(m_ike.group(1))
                    except ValueError:
                        # Valeur inattendue (ex: "auto") -> considérer non conforme
                        current_tunnel['ike_version'] = 1

    # sécurité si le fichier ne se termine pas proprement
    if in_phase1_block and current_tunnel:
        _flush_current()

    if ike_issues:
        list_message = ', '.join(ike_issues)
        return (f"Version IKE non conforme sur les tunnels (<V2): {list_message}",
                False, list_message)

    return "Version IKE conforme (IKEv2) sur tous les tunnels", True, ""


def verifier_diffie_hellman(config_lines):
    """
    Vérifie les groupes Diffie-Hellman Phase 1 et Phase 2 (minimum DH14).
    Gère: edit "Nom", edit TUNNEL_X, edit 1 ; flush sur next/end.
    Si dhgrp absent ou invalide -> non conforme (défaut [14,5] => min=5).
    """
    # --- helpers & patterns ---
    p_edit_quoted   = re.compile(r'^edit\s+"([^"]+)"$')
    p_edit_unquoted = re.compile(r'^edit\s+(\S+)$')
    p_set_dh        = re.compile(r'^set\s+dhgrp\s+(.+)$', re.IGNORECASE)

    def parse_dh_values(s: str):
        # tokens séparés par espaces; on garde les entiers valides
        vals = []
        for tok in s.split():
            try:
                vals.append(int(tok))
            except ValueError:
                # ignore tokens non numériques (rare, mais safe)
                pass
        return vals

    # --- Phase 1 ---
    in_phase1 = False
    cur_p1 = None
    p1_issues = []

    def flush_p1():
        nonlocal cur_p1, p1_issues
        if cur_p1:
            dh = cur_p1.get('dhgrp', [])
            min_dh = min(dh) if dh else None
            if min_dh is None or min_dh < 14:
                p1_issues.append(cur_p1['name'])
            cur_p1 = None

    for raw in config_lines:
        line = raw.strip()
        if not line:
            continue

        if line == 'config vpn ipsec phase1-interface':
            in_phase1 = True
            cur_p1 = None
            continue

        if in_phase1:
            if line == 'end':
                flush_p1()
                in_phase1 = False
                continue
            if line == 'next':
                flush_p1()
                continue

            m_q = p_edit_quoted.match(line)
            m_u = p_edit_unquoted.match(line)
            if m_q or (m_u and not line.lower().startswith('edit delete')):
                flush_p1()
                name = (m_q.group(1) if m_q else m_u.group(1)).strip()
                # défaut [14,5] => non conforme (min=5) si non spécifié
                cur_p1 = {'name': name, 'dhgrp': [14, 5]}
                continue

            if cur_p1:
                m_dh = p_set_dh.match(line)
                if m_dh:
                    vals = parse_dh_values(m_dh.group(1))
                    cur_p1['dhgrp'] = vals if vals else [14, 5]

    # sécurité si bloc non refermé
    if in_phase1 and cur_p1:
        flush_p1()

    # --- Phase 2 ---
    in_phase2 = False
    cur_p2 = None
    p2_issues = []

    def flush_p2():
        nonlocal cur_p2, p2_issues
        if cur_p2:
            dh = cur_p2.get('dhgrp', [])
            min_dh = min(dh) if dh else None
            if min_dh is None or min_dh < 14:
                p2_issues.append(cur_p2['name'])
            cur_p2 = None

    for raw in config_lines:
        line = raw.strip()
        if not line:
            continue

        if line == 'config vpn ipsec phase2-interface':
            in_phase2 = True
            cur_p2 = None
            continue

        if in_phase2:
            if line == 'end':
                flush_p2()
                in_phase2 = False
                continue
            if line == 'next':
                flush_p2()
                continue

            m_q = p_edit_quoted.match(line)
            m_u = p_edit_unquoted.match(line)
            if m_q or (m_u and not line.lower().startswith('edit delete')):
                flush_p2()
                name = (m_q.group(1) if m_q else m_u.group(1)).strip()
                cur_p2 = {'name': name, 'dhgrp': [14, 5]}
                continue

            if cur_p2:
                m_dh = p_set_dh.match(line)
                if m_dh:
                    vals = parse_dh_values(m_dh.group(1))
                    cur_p2['dhgrp'] = vals if vals else [14, 5]

    if in_phase2 and cur_p2:
        flush_p2()

    # Assemblage du message
    if p1_issues or p2_issues:
        all_tunnels = set(p1_issues + p2_issues)
        tunnel_phases = {}
        for t in all_tunnels:
            phases = []
            if t in p1_issues: phases.append("phase 1")
            if t in p2_issues: phases.append("phase 2")
            tunnel_phases[t] = " et ".join(phases)

        display_list = [f"{t} ({ph})" for t, ph in tunnel_phases.items()]
        result_message = "Groupes Diffie-Hellman insuffisants (< DH14) : " + ", ".join(display_list)
        list_message = ", ".join(display_list)
        return (result_message, False, list_message)

    return "Groupes Diffie-Hellman conformes (≥ DH14) sur toutes les phases", True, ""


def verifier_algorithmes_chiffrement_auth(config_lines):
    """
    Vérifie les algorithmes de chiffrement et d'authentification Phase 1 et Phase 2.
    Gère edit quoted/unquoted + flush sur next/end.
    Si aucune proposal -> non conforme.
    """
    p_edit_quoted   = re.compile(r'^edit\s+"([^"]+)"$')
    p_edit_unquoted = re.compile(r'^edit\s+(\S+)$')
    p_set_prop      = re.compile(r'^set\s+proposal\s+(.+)$', re.IGNORECASE)

    # Phase 1
    in_phase1 = False
    cur_p1 = None
    p1_issues = []

    def flush_p1():
        nonlocal cur_p1, p1_issues
        if cur_p1:
            props = cur_p1.get('proposal', [])
            ok = (len(props) > 0) and all(is_proposal_compliant(p) for p in props)
            if not ok:
                p1_issues.append(cur_p1['name'])
            cur_p1 = None

    for raw in config_lines:
        line = raw.strip()
        if not line:
            continue

        if line == 'config vpn ipsec phase1-interface':
            in_phase1 = True
            cur_p1 = None
            continue

        if in_phase1:
            if line == 'end':
                flush_p1()
                in_phase1 = False
                continue
            if line == 'next':
                flush_p1()
                continue

            m_q = p_edit_quoted.match(line)
            m_u = p_edit_unquoted.match(line)
            if m_q or (m_u and not line.lower().startswith('edit delete')):
                flush_p1()
                name = (m_q.group(1) if m_q else m_u.group(1)).strip()
                cur_p1 = {'name': name, 'proposal': []}
                continue

            if cur_p1:
                m_prop = p_set_prop.match(line)
                if m_prop:
                    # proposals séparées par espaces, p.ex. "aes256-sha256 aes256gcm-prfsha256"
                    cur_p1['proposal'] = m_prop.group(1).split()

    if in_phase1 and cur_p1:
        flush_p1()

    # Phase 2
    in_phase2 = False
    cur_p2 = None
    p2_issues = []

    def flush_p2():
        nonlocal cur_p2, p2_issues
        if cur_p2:
            props = cur_p2.get('proposal', [])
            ok = (len(props) > 0) and all(is_proposal_compliant(p) for p in props)
            if not ok:
                p2_issues.append(cur_p2['name'])
            cur_p2 = None

    for raw in config_lines:
        line = raw.strip()
        if not line:
            continue

        if line == 'config vpn ipsec phase2-interface':
            in_phase2 = True
            cur_p2 = None
            continue

        if in_phase2:
            if line == 'end':
                flush_p2()
                in_phase2 = False
                continue
            if line == 'next':
                flush_p2()
                continue

            m_q = p_edit_quoted.match(line)
            m_u = p_edit_unquoted.match(line)
            if m_q or (m_u and not line.lower().startswith('edit delete')):
                flush_p2()
                name = (m_q.group(1) if m_q else m_u.group(1)).strip()
                cur_p2 = {'name': name, 'proposal': []}
                continue

            if cur_p2:
                m_prop = p_set_prop.match(line)
                if m_prop:
                    cur_p2['proposal'] = m_prop.group(1).split()

    if in_phase2 and cur_p2:
        flush_p2()

    if p1_issues or p2_issues:
        all_tunnels = set(p1_issues + p2_issues)
        tunnel_phases = {}
        for t in all_tunnels:
            phases = []
            if t in p1_issues: phases.append("phase 1")
            if t in p2_issues: phases.append("phase 2")
            tunnel_phases[t] = " et ".join(phases)

        display_list = [f"{t} ({ph})" for t, ph in tunnel_phases.items()]
        result_message = "Algorithmes de chiffrement/authentification non conformes : " + ", ".join(display_list)
        list_message = ", ".join(display_list)
        return (result_message, False, list_message)

    return "Algorithmes de chiffrement et d'authentification robustes sur toutes les phases", True, ""


def verifier_durcissement_vpn_ipsec_split(config_lines):
    """
    Fonction principale qui effectue les 3 vérifications séparées
    Retourne 9 variables : (ike_result, ike_conform, ike_list, dh_result, dh_conform, dh_list, algo_result, algo_conform, algo_list)
    """
    # Vérifie si un tunnel IPSEC est présent
    ipsec_tunnel_present = any('config vpn ipsec' in line for line in config_lines)

    if not ipsec_tunnel_present:
        return ("Absence de tunnel IPSEC configuré", False, "",
                "Absence de tunnel IPSEC configuré", False, "",
                "Absence de tunnel IPSEC configuré", False, "")

    # Vérifications séparées
    ike_result, ike_conform, ike_list = verifier_ike_version(config_lines)
    dh_result, dh_conform, dh_list = verifier_diffie_hellman(config_lines)
    algo_result, algo_conform, algo_list = verifier_algorithmes_chiffrement_auth(config_lines)

    return (ike_result, ike_conform, ike_list,
            dh_result, dh_conform, dh_list,
            algo_result, algo_conform, algo_list)



def verifier_mfa_utilisateurs_admins(config_lines):
    in_user_local_block = False
    in_system_admin_block = False

    current_user = None
    current_admin = None

    mfa_absent_users = []
    mfa_absent_admins = []

    depth = 0

    # Vérification des comptes utilisateurs locaux
    for raw_line in config_lines:
        line = raw_line.strip()

        if line == "config user local":
            in_user_local_block = True

        elif line == "end" and in_user_local_block:
            in_user_local_block = False

        elif in_user_local_block:
            if line.startswith("edit "):
                current_user = {
                    "Nom du compte": extraire_nom_compte(line),
                    "MFA": "No",
                }

            elif current_user and line.startswith("set two-factor "):
                current_user["MFA"] = line.split(maxsplit=2)[2]

            elif line == "next" and current_user:
                if current_user["MFA"].lower() in {"no", "disable"}:
                    mfa_absent_users.append(current_user["Nom du compte"])

                current_user = None

    # Vérification des comptes administrateurs
    for raw_line in config_lines:
        line = raw_line.strip()

        if line == "config system admin":
            in_system_admin_block = True
            depth = 0
            current_admin = None
            continue

        if not in_system_admin_block:
            continue

        if line.startswith("config "):
            depth += 1
            continue

        if line == "end":
            if depth > 0:
                depth -= 1
            else:
                in_system_admin_block = False
            continue

        if line.startswith("edit ") and depth == 0:
            current_admin = {
                "Nom du compte": extraire_nom_compte(line),
                "MFA": "No",
                "Peer Auth": False,
            }

        elif current_admin and depth == 0:
            if line.startswith("set two-factor "):
                current_admin["MFA"] = line.split(maxsplit=2)[2]

            elif line == "set peer-auth enable":
                current_admin["Peer Auth"] = True

            elif line == "next":
                mfa_absente = current_admin["MFA"].lower() in {
                    "no",
                    "disable",
                }

                # Un administrateur PKI avec peer-auth activé
                # n'a pas besoin d'avoir un MFA configuré.
                if mfa_absente and not current_admin["Peer Auth"]:
                    mfa_absent_admins.append(
                        current_admin["Nom du compte"]
                    )

                current_admin = None

    if mfa_absent_users or mfa_absent_admins:
        mfa_absent_accounts = mfa_absent_users + mfa_absent_admins

        if len(mfa_absent_accounts) > 3:
            return (
                "Plusieurs comptes sont configurés sans MFA. "
                "Voir la liste complète 'Accounts' pour plus de détails.",
                False,
            )

        if len(mfa_absent_accounts) == 1:
            return (
                "MFA absente pour le compte suivant : "
                f"{mfa_absent_accounts[0]}",
                False,
            )

        messages = []

        if mfa_absent_users:
            messages.append(
                "Comptes utilisateurs sans MFA : "
                + ", ".join(mfa_absent_users)
            )

        if mfa_absent_admins:
            messages.append(
                "Admins sans MFA : "
                + ", ".join(mfa_absent_admins)
            )

        return "\n".join(messages), False

    return (
        "MFA présente pour tous les comptes utilisateurs et administrateurs",
        True,
    )


def extraire_nom_compte(edit_line):
    """
    Extrait le nom d'un compte depuis une ligne FortiGate de type :
    edit "nom-du-compte"
    ou :
    edit nom-du-compte
    """
    value = edit_line.removeprefix("edit ").strip()

    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]

    return value



def get_expected_cti_objects(model):
    """
    Retourne la liste des objets CTI (IPv4 et autres) attendus en fonction du modèle.
    Accepte des formes : "40F", "FGT40F", "FG-40F", "FortiGate-40F", etc.
    """

    def canonize(m):
        if not m:
            return ""
        s = str(m).upper().strip()
        # Enlever espaces/traits d'union/points, etc.
        s = re.sub(r'[^A-Z0-9]', '', s)
        # Retirer les préfixes éventuels (FORTIGATE / FGT / FG)
        s = re.sub(r'^(FORTIGATE|FGT|FG)', '', s)
        # À ce stade on s'attend à "40F", "60E", etc.
        return s

    c = canonize(model)

    if c in {"30E", "50E"}:
        return ["IPV4_SNS", "HASH_SNS_SHA1", "HASH_SNS_SHA256", "FQDN_SNS", "URL_SNS"]

    elif c in {"60E", "80E", "40F"}:
        return [
            "IPV4_CTI_SNS", "IPV4_SNS", "HASH_CTI_SNS_SHA1", "HASH_CTI_SNS_SHA256",
            "HASH_SNS_SHA1", "HASH_SNS_SHA256", "FQDN_SNS", "URL_SNS",
            "FQDN_CTI_SNS", "URL_CTI_SNS"
        ]

    else:
        return [
            "IPV4_CTI_SNS", "IPV4_CTI_SNS2", "IPV4_CTI_SNS3", "IPV4_SNS",
            "HASH_CTI_SNS_SHA1", "HASH_CTI_SNS_SHA256", "HASH_SNS_SHA1", "HASH_SNS_SHA256",
            "FQDN_SNS", "URL_SNS", "FQDN_CTI_SNS", "URL_CTI_SNS"
        ]


def get_external_resources(config_lines):
    """
    Parcourt 'config system external-resource' et renvoie la liste des ressources définies.
    """
    in_external_resource = False
    external_resources = []
    for line in config_lines:
        line = line.strip()
        if line.lower() == "config system external-resource":
            in_external_resource = True
            continue
        elif in_external_resource:
            if line.lower().startswith("edit "):
                parts = line.split('"')
                if len(parts) > 1:
                    name = parts[1].upper()
                    external_resources.append(name)
            elif line.lower() == "end":
                in_external_resource = False
    return external_resources


def ajouter_regle_cti(current_rule, rules, valid_cti_objects, expected_ipv4_cti_objects):
    """
    Ajoute / met à jour la règle CTI dans 'rules' en cumulant les CTI SRC/DST.
    La complétude est évaluée sur les listes fusionnées (cumulées) du couple (src,dst).
    """
    if not current_rule:
        return

    key = (current_rule['src_interface'], current_rule['dst_interface'])
    if key not in rules:
        rules[key] = {
            'cti_src_list': [],
            'cti_dst_list': [],
            'cti': False,
            'accept': False,
            'deny': False,
            'invalid_cti': [],
            'missing_cti': [],           # laissé pour compat, non utilisé pour le rendu final
            'incoming_cti_complete': False,
            'outgoing_cti_complete': False
        }

    # --- Source (inbound) ---
    if current_rule['src_cti_list']:
        valid_src_entries = [c for c in current_rule['src_cti_list'] if c in valid_cti_objects]
        invalid_src_entries = [c for c in current_rule['src_cti_list'] if c.startswith("IPV4") and c not in valid_cti_objects]
        if valid_src_entries:
            rules[key]['cti'] = True
            # Fusion sans doublon
            for c in valid_src_entries:
                if c not in rules[key]['cti_src_list']:
                    rules[key]['cti_src_list'].append(c)
        if invalid_src_entries:
            for c in invalid_src_entries:
                if c not in rules[key]['invalid_cti']:
                    rules[key]['invalid_cti'].append(c)

    # --- Destination (outbound) ---
    if current_rule['dst_cti_list']:
        valid_dst_entries = [c for c in current_rule['dst_cti_list'] if c in valid_cti_objects]
        invalid_dst_entries = [c for c in current_rule['dst_cti_list'] if c.startswith("IPV4") and c not in valid_cti_objects]
        if valid_dst_entries:
            rules[key]['cti'] = True
            for c in valid_dst_entries:
                if c not in rules[key]['cti_dst_list']:
                    rules[key]['cti_dst_list'].append(c)
        if invalid_dst_entries:
            for c in invalid_dst_entries:
                if c not in rules[key]['invalid_cti']:
                    rules[key]['invalid_cti'].append(c)

    # --- Complétude sur les listes FUSIONNÉES ---
    if all(o in rules[key]['cti_src_list'] for o in expected_ipv4_cti_objects):
        rules[key]['incoming_cti_complete'] = True
    else:
        missing_inbound = [o for o in expected_ipv4_cti_objects if o not in rules[key]['cti_src_list']]
        rules[key]['missing_cti'] = list(set(rules[key]['missing_cti'] + missing_inbound))

    if all(o in rules[key]['cti_dst_list'] for o in expected_ipv4_cti_objects):
        rules[key]['outgoing_cti_complete'] = True
    else:
        missing_outbound = [o for o in expected_ipv4_cti_objects if o not in rules[key]['cti_dst_list']]
        rules[key]['missing_cti'] = list(set(rules[key]['missing_cti'] + missing_outbound))

    # Actions
    if current_rule['accept']:
        rules[key]['accept'] = True
    if current_rule['deny']:
        rules[key]['deny'] = True


def is_wan_or_any_interface(iface, selected_wan_interfaces):
    """
    True si 'ANY' ou l'une des interfaces WAN choisies.
    """
    iface = iface.upper()
    if iface == "ANY":
        return True
    return iface in [wan.upper() for wan in selected_wan_interfaces]


def is_explicit_wan(iface, selected_wan_interfaces):
    """
    True si l'interface correspond exactement à un WAN sélectionné.
    """
    return iface.upper() in [wan.upper() for wan in selected_wan_interfaces]


def verifier_presence_cti(config_lines, selected_wan_interfaces, model):
    """
    Vérifie la présence des CTI IPv4 dans les policies. Donne le DÉTAIL des CTI manquants par flux.
    """
    external_resources = get_external_resources(config_lines)
    expected_cti_objects = [c.upper() for c in get_expected_cti_objects(model)]
    expected_ipv4_cti_objects = [c for c in expected_cti_objects if c.startswith("IPV4")]
    valid_cti_objects = expected_ipv4_cti_objects.copy()

    # Vérif que les connecteurs sont déclarés
    missing_resources = [obj for obj in expected_cti_objects if obj not in external_resources]
    if missing_resources:
        msg = ("Les connecteurs suivants sont manquants dans 'config system external-resource' : " +
               ", ".join(missing_resources))
        return msg, False

    # Parse firewall policy
    in_firewall_policy = False
    current_rule = None
    rules = {}
    for line in config_lines:
        line = line.strip()
        low = line.lower()
        if low == 'config firewall policy':
            in_firewall_policy = True
        elif low == 'end' and in_firewall_policy:
            in_firewall_policy = False
            if current_rule:
                ajouter_regle_cti(current_rule, rules, valid_cti_objects, expected_ipv4_cti_objects)
                current_rule = None
        elif in_firewall_policy:
            if low.startswith('edit '):
                if current_rule:
                    ajouter_regle_cti(current_rule, rules, valid_cti_objects, expected_ipv4_cti_objects)
                current_rule = {
                    'src_interface': None,
                    'dst_interface': None,
                    'src_cti_list': [],
                    'dst_cti_list': [],
                    'accept': False,
                    'deny': False,
                }
            elif low.startswith('set srcintf '):
                parts = line.split('"')
                if len(parts) > 1:
                    current_rule['src_interface'] = parts[1].upper()
                else:
                    toks = line.split()
                    if len(toks) > 2:
                        current_rule['src_interface'] = toks[2].upper()
            elif low.startswith('set dstintf '):
                parts = line.split('"')
                if len(parts) > 1:
                    current_rule['dst_interface'] = parts[1].upper()
                else:
                    toks = line.split()
                    if len(toks) > 2:
                        current_rule['dst_interface'] = toks[2].upper()
            elif 'set srcaddr' in low:
                parts = line.split('"')
                cti_names = [cti.upper() for cti in parts[1::2] if cti.upper().startswith("IPV4")]
                if cti_names:
                    current_rule['src_cti_list'].extend(cti_names)
            elif 'set dstaddr' in low:
                parts = line.split('"')
                cti_names = [cti.upper() for cti in parts[1::2] if cti.upper().startswith("IPV4")]
                if cti_names:
                    current_rule['dst_cti_list'].extend(cti_names)
            elif 'set action accept' in low:
                current_rule['accept'] = True
            elif 'set action deny' in low:
                current_rule['deny'] = True

    if current_rule:
        ajouter_regle_cti(current_rule, rules, valid_cti_objects, expected_ipv4_cti_objects)

    # --- Couverture ANY ---
    global_inbound_coverage = False
    global_outbound_coverage = False
    any_any_key = ("ANY", "ANY")
    if any_any_key in rules:
        details_any = rules[any_any_key]
        if details_any.get('incoming_cti_complete'):
            global_inbound_coverage = True
        if details_any.get('outgoing_cti_complete'):
            global_outbound_coverage = True

    # Collecte des flux suspects
    missing_inbound_flows = set()   # WAN -> LAN (doit avoir CTI en source)
    missing_outbound_flows = set()  # LAN -> WAN (doit avoir CTI en destination)

    for (src, dst), details in rules.items():
        if not src or not dst:
            continue
        if src.upper() == "ANY" and dst.upper() == "ANY":
            continue
        if "ADMIN-FGT" in src.upper() or "ADMIN-FGT" in dst.upper():
            continue

        if is_explicit_wan(src, selected_wan_interfaces) and (not is_explicit_wan(dst, selected_wan_interfaces)) and dst.upper() != "ANY":
            if not details.get('incoming_cti_complete'):
                missing_inbound_flows.add(f"{src} vers {dst}")
        if is_explicit_wan(dst, selected_wan_interfaces) and (not is_explicit_wan(src, selected_wan_interfaces)) and src.upper() != "ANY":
            if not details.get('outgoing_cti_complete'):
                missing_outbound_flows.add(f"{src} vers {dst}")

    # Filtrage ANY pour évit. doublons
    missing_inbound_flows  = {f for f in missing_inbound_flows  if "ANY" not in f}
    missing_outbound_flows = {f for f in missing_outbound_flows if "ANY" not in f}

    # Couverture WAN->ANY / ANY->WAN quand complètes
    for (src, dst), details in rules.items():
        if is_explicit_wan(src, selected_wan_interfaces) and dst.upper() == "ANY" and details.get('incoming_cti_complete'):
            wan = src.upper()
            to_remove = {f for f in missing_inbound_flows if f.split(" vers ")[0].upper() == wan}
            missing_inbound_flows -= to_remove
        if src.upper() == "ANY" and is_explicit_wan(dst, selected_wan_interfaces) and details.get('outgoing_cti_complete'):
            wan = dst.upper()
            to_remove = {f for f in missing_outbound_flows if f.split(" vers ")[1].upper() == wan}
            missing_outbound_flows -= to_remove

    if global_inbound_coverage:
        missing_inbound_flows.clear()
    if global_outbound_coverage:
        missing_outbound_flows.clear()

    # --- Détail des CTI manquants par flux (union effective) ---
    def effective_src_cti(src_u, dst_u):
        """CTI effectifs en SOURCE (inbound) = exact + (src,ANY) + (ANY,ANY)."""
        eff = set()
        r = rules.get((src_u, dst_u));
        eff |= set(r.get('cti_src_list', [])) if r else set()
        r = rules.get((src_u, "ANY"));
        eff |= set(r.get('cti_src_list', [])) if r else set()
        r = rules.get(("ANY", "ANY"));
        eff |= set(r.get('cti_src_list', [])) if r else set()
        return eff

    def effective_dst_cti(src_u, dst_u):
        """CTI effectifs en DEST (outbound) = exact + (ANY,dst) + (ANY,ANY)."""
        eff = set()
        r = rules.get((src_u, dst_u));
        eff |= set(r.get('cti_dst_list', [])) if r else set()
        r = rules.get(("ANY", dst_u));
        eff |= set(r.get('cti_dst_list', [])) if r else set()
        r = rules.get(("ANY", "ANY"));
        eff |= set(r.get('cti_dst_list', [])) if r else set()
        return eff

        # 1) Calcule les manquants par flux

    inbound_groups = {}  # key: tuple(sorted missing), val: [flows...]
    outbound_groups = {}

    # Inbound (source)
    for flow in sorted(missing_inbound_flows):
        src, dst = flow.split(" vers ")
        src_u, dst_u = src.upper(), dst.upper()
        eff_src = effective_src_cti(src_u, dst_u)
        missing = tuple(sorted([o for o in expected_ipv4_cti_objects if o not in eff_src]))
        if missing:
            inbound_groups.setdefault(missing, []).append(f"{src} → {dst}")

    # Outbound (destination)
    for flow in sorted(missing_outbound_flows):
        src, dst = flow.split(" vers ")
        src_u, dst_u = src.upper(), dst.upper()
        eff_dst = effective_dst_cti(src_u, dst_u)
        missing = tuple(sorted([o for o in expected_ipv4_cti_objects if o not in eff_dst]))
        if missing:
            outbound_groups.setdefault(missing, []).append(f"{src} → {dst}")

    # 2) Construit le message regroupé
    error_lines = []
    for missing_tuple, flows in inbound_groups.items():
        flows_str = ", ".join(flows)
        miss_str = ", ".join(missing_tuple)
        error_lines.append(
            f"Flux CTI entrants manquants (CTI en source) : {flows_str} => CTI manquants en source : {miss_str}"
        )
    for missing_tuple, flows in outbound_groups.items():
        flows_str = ", ".join(flows)
        miss_str = ", ".join(missing_tuple)
        error_lines.append(
            f"Flux CTI sortants manquants (CTI en destination) : {flows_str} => CTI manquants en destination : {miss_str}"
        )

    if error_lines:
        return "Règles CTI incomplètes :\n" + "\n".join(error_lines), False

    return "CTI correctement configuré", True



# ISDB Lists
outgoing_isdbs = [
    "VPN-Anonymous.VPN", "Tor-Relay.Node",
    "Spam-Spamming.Server", "Proxy-Proxy.Server", "Phishing-Phishing.Server",
    "Malicious-Malicious.Server", "Botnet-C&C.Server", "Blockchain-Crypto.Mining.Pool"
]

incoming_isdbs = [
    "VPN-Anonymous.VPN", "Tor-Relay.Node", "Tor-Exit.Node",
    "Spam-Spamming.Server", "Proxy-Proxy.Server", "Phishing-Phishing.Server",
    "Malicious-Malicious.Server", "Botnet-C&C.Server"
]


def ajouter_regle_isdb(current_rule, rules, incoming_isdbs, outgoing_isdbs):
    """
    Ajoute ou met à jour les détails de la règle ISDB dans le dictionnaire rules.

    Hypothèses :
      - current_rule['rule_id'] : ID de la règle
      - current_rule['inbound_isdb_list'] : ISDB liés au 'internet-service-src' (inbound)
      - current_rule['outbound_isdb_list'] : ISDB liés au 'internet-service' (outbound)
      - incoming_isdbs : liste de référence inbound
      - outgoing_isdbs : liste de référence outbound

    On ignore les ISDB non listés, sans bloquer la complétude.
    """
    if not current_rule:
        return

    rule_id = current_rule.get('rule_id', 'Unknown')
    # Action par défaut => DENY
    if not current_rule.get('accept') and not current_rule.get('deny'):
        current_rule['deny'] = True

    key = (current_rule.get('src_interface'), current_rule.get('dst_interface'))
    if key not in rules:
        rules[key] = {
            'rule_id': rule_id,
            'isdb': False,
            'accept': False,
            'deny': False,
            'isdb_inbound_list': [],
            'isdb_outbound_list': [],
            'invalid_isdb': [],
            'incoming_isdb_complete': False,
            'outgoing_isdb_complete': False
        }

    inbound_list = current_rule.get('inbound_isdb_list', [])
    outbound_list = current_rule.get('outbound_isdb_list', [])

    # Marque la règle 'isdb' si inbound_list ou outbound_list non vides
    if inbound_list or outbound_list:
        rules[key]['isdb'] = True

    # Ajout inbound/outbound sans doublons
    for isdb_in in inbound_list:
        if isdb_in not in rules[key]['isdb_inbound_list']:
            rules[key]['isdb_inbound_list'].append(isdb_in)
    for isdb_out in outbound_list:
        if isdb_out not in rules[key]['isdb_outbound_list']:
            rules[key]['isdb_outbound_list'].append(isdb_out)

    # Complétude inbound => si tous les ISDB "officiels" inbound sont présents
    if all(i in inbound_list for i in incoming_isdbs):
        rules[key]['incoming_isdb_complete'] = True

    # Complétude outbound => si tous les ISDB "officiels" outbound sont présents
    if all(o in outbound_list for o in outgoing_isdbs):
        rules[key]['outgoing_isdb_complete'] = True

    # Action
    if current_rule.get('accept'):
        rules[key]['accept'] = True
    if current_rule.get('deny'):
        rules[key]['deny'] = True


def parse_internet_service_groups(config_lines):
    """
    Parse la section 'config firewall internet-service-group'
    et renvoie un dictionnaire { group_name: [liste_des_ISDB], ... }.
    """
    in_section = False
    current_group = None
    internet_service_groups = {}

    for line in config_lines:
        raw = line.strip().lower()
        if raw == 'config firewall internet-service-group':
            in_section = True
            continue
        elif raw == 'end' and in_section:
            in_section = False
            current_group = None
            continue

        if in_section:
            if raw.startswith('edit '):
                tokens = line.strip().split('"')
                if len(tokens) >= 2:
                    group_name = tokens[1]
                else:
                    group_name = line.strip().split()[1] if len(line.strip().split()) > 1 else "UnknownGroup"
                internet_service_groups[group_name] = []
                current_group = group_name
            elif raw == 'next':
                current_group = None
            else:
                if 'set member ' in raw:
                    parts = line.strip().split('"')
                    members = parts[1::2]
                    if current_group:
                        internet_service_groups[current_group].extend(members)
    return internet_service_groups


def is_explicit_wan(iface, selected_wan_interfaces):
    """
    Retourne True si l'interface correspond exactement à l'une des interfaces WAN sélectionnées.
    """
    if not iface:
        return False
    return iface.upper() in [wan.upper() for wan in selected_wan_interfaces]


def verifier_presence_isdb(config_lines, selected_wan_interfaces, incoming_isdbs, outgoing_isdbs):
    """
    Vérifie la présence et la configuration des ISDB dans les règles de pare-feu,
    en se basant sur les groupes internet-service et sur la configuration firewall policy.

    Pour un flux "WAN vers LAN" (entrant), la règle doit fournir la liste complète ISDB en source.
    Pour un flux "LAN vers WAN" (sortant), la règle doit fournir la liste complète ISDB en destination.
    Des règles globales utilisant "ANY" (ex. "ANY → ANY", "WAN → ANY" ou "ANY → WAN")
    peuvent couvrir tous les flux pour une interface WAN.

    Returns:
        tuple: (message, statut)
               - message (str): Détail des flux pour lesquels la configuration ISDB est incomplète.
               - statut (bool): True si la configuration ISDB est correcte, False sinon.
    """
    # 1) Parse des groupes ISDB
    internet_service_groups = parse_internet_service_groups(config_lines)

    # 2) Lecture de la section firewall policy et construction des règles ISDB
    rules = {}
    in_firewall_policy = False
    current_rule = None

    for line in config_lines:
        raw_line = line.strip()
        lower_line = raw_line.lower()

        if lower_line == 'config firewall policy':
            in_firewall_policy = True
            continue
        elif lower_line == 'end' and in_firewall_policy:
            in_firewall_policy = False
            if current_rule:
                ajouter_regle_isdb(current_rule, rules, incoming_isdbs, outgoing_isdbs)
                current_rule = None
            continue

        if in_firewall_policy:
            if lower_line.startswith('edit '):
                if current_rule:
                    ajouter_regle_isdb(current_rule, rules, incoming_isdbs, outgoing_isdbs)
                tokens = raw_line.split()
                rule_id = tokens[1] if len(tokens) > 1 else "Unknown"
                current_rule = {
                    'rule_id': rule_id,
                    'src_interface': None,
                    'dst_interface': None,
                    'inbound_isdb_list': [],
                    'outbound_isdb_list': [],
                    'accept': False,
                    'deny': False
                }
            elif lower_line == 'next':
                if current_rule:
                    ajouter_regle_isdb(current_rule, rules, incoming_isdbs, outgoing_isdbs)
                    current_rule = None
            else:
                if lower_line.startswith('set srcintf '):
                    parts = raw_line.split('"')
                    if len(parts) > 1:
                        current_rule['src_interface'] = parts[1].upper()
                    else:
                        tokens = raw_line.split()
                        if len(tokens) > 2:
                            current_rule['src_interface'] = tokens[2].upper()

                elif lower_line.startswith('set dstintf '):
                    parts = raw_line.split('"')
                    if len(parts) > 1:
                        current_rule['dst_interface'] = parts[1].upper()
                    else:
                        tokens = raw_line.split()
                        if len(tokens) > 2:
                            current_rule['dst_interface'] = tokens[2].upper()

                elif 'set action accept' in lower_line:
                    current_rule['accept'] = True
                elif 'set action deny' in lower_line:
                    current_rule['deny'] = True

                elif 'set internet-service-src-group' in lower_line:
                    parts = raw_line.split('"')
                    if len(parts) > 1:
                        group_name = parts[1]
                        if group_name in internet_service_groups:
                            current_rule['inbound_isdb_list'].extend(internet_service_groups[group_name])

                elif 'set internet-service-group' in lower_line:
                    parts = raw_line.split('"')
                    if len(parts) > 1:
                        group_name = parts[1]
                        if group_name in internet_service_groups:
                            current_rule['outbound_isdb_list'].extend(internet_service_groups[group_name])

                elif 'set internet-service-src-name' in lower_line:
                    parts = raw_line.split('"')
                    isdb_names = parts[1::2]
                    current_rule['inbound_isdb_list'].extend(isdb_names)

                elif 'set internet-service-name' in lower_line:
                    parts = raw_line.split('"')
                    isdb_names = parts[1::2]
                    current_rule['outbound_isdb_list'].extend(isdb_names)

    if current_rule:
        ajouter_regle_isdb(current_rule, rules, incoming_isdbs, outgoing_isdbs)

    # --- Gestion des règles globales ANY ---
    global_inbound_coverage = False
    global_outbound_coverage = False
    any_any_key = ("ANY", "ANY")
    if any_any_key in rules:
        details_any = rules[any_any_key]
        if details_any.get('incoming_isdb_complete'):
            global_inbound_coverage = True
        if details_any.get('outgoing_isdb_complete'):
            global_outbound_coverage = True

    missing_inbound_flows = set()
    missing_outbound_flows = set()

    for (src, dst), info in rules.items():
        if src.upper() == "ANY" and dst.upper() == "ANY":
            continue

        # >>> Nouveau filtre pour exclure ADMIN-FGT <<<
        if src and "ADMIN-FGT" in src.upper():
            continue
        if dst and "ADMIN-FGT" in dst.upper():
            continue
        # >>> Fin du filtre <<<

        if is_explicit_wan(src, selected_wan_interfaces) and (not is_explicit_wan(dst, selected_wan_interfaces)):
            if not info.get('incoming_isdb_complete'):
                missing_inbound_flows.add(f"{src} --> {dst}")
        if is_explicit_wan(dst, selected_wan_interfaces) and (not is_explicit_wan(src, selected_wan_interfaces)):
            if not info.get('outgoing_isdb_complete'):
                missing_outbound_flows.add(f"{src} --> {dst}")

    missing_inbound_flows = {flow for flow in missing_inbound_flows if "ANY" not in flow}
    missing_outbound_flows = {flow for flow in missing_outbound_flows if "ANY" not in flow}

    for (src, dst), info in rules.items():
        if is_explicit_wan(src, selected_wan_interfaces) and dst.upper() == "ANY" and info.get('incoming_isdb_complete'):
            wan_interface = src.upper()
            flows_to_remove = {flow for flow in missing_inbound_flows if flow.split(" --> ")[0].upper() == wan_interface}
            missing_inbound_flows -= flows_to_remove
        if src.upper() == "ANY" and is_explicit_wan(dst, selected_wan_interfaces) and info.get('outgoing_isdb_complete'):
            wan_interface = dst.upper()
            flows_to_remove = {flow for flow in missing_outbound_flows if flow.split(" --> ")[1].upper() == wan_interface}
            missing_outbound_flows -= flows_to_remove

    if global_inbound_coverage:
        missing_inbound_flows.clear()
    if global_outbound_coverage:
        missing_outbound_flows.clear()

    # --- On va maintenant détailler les ISDB manquants ---
    error_messages = []

    def regrouper_par_isdb(missing_flows, flow_type):
        """
        Calcule les ISDB manquants en comparant non pas seulement la règle (src,dst),
        mais l'UNION des listes applicables :
          - règle exacte (src,dst)
          - ANY→ANY
          - (ANY,dst) pour l'OUTBOUND  (couverture ANY->WAN)
          - (src,ANY) pour l'INBOUND   (couverture WAN->ANY)
        """

        def _outbound_effective(src_u, dst_u):
            eff = set()
            r = rules.get((src_u, dst_u));
            eff |= set(r.get('isdb_outbound_list', [])) if r else set()
            r = rules.get(("ANY", "ANY"));
            eff |= set(r.get('isdb_outbound_list', [])) if r else set()
            r = rules.get(("ANY", dst_u));
            eff |= set(r.get('isdb_outbound_list', [])) if r else set()
            return eff

        def _inbound_effective(src_u, dst_u):
            eff = set()
            r = rules.get((src_u, dst_u));
            eff |= set(r.get('isdb_inbound_list', [])) if r else set()
            r = rules.get(("ANY", "ANY"));
            eff |= set(r.get('isdb_inbound_list', [])) if r else set()
            r = rules.get((src_u, "ANY"));
            eff |= set(r.get('isdb_inbound_list', [])) if r else set()
            return eff

        regroupement = {}

        for flow in missing_flows:
            src, dst = flow.split(" --> ")
            src_u, dst_u = src.upper(), dst.upper()

            if flow_type == "outbound":
                eff = _outbound_effective(src_u, dst_u)
                missing = sorted(set(outgoing_isdbs) - eff)
            else:
                eff = _inbound_effective(src_u, dst_u)
                missing = sorted(set(incoming_isdbs) - eff)

            if missing:
                regroupement.setdefault(tuple(missing), []).append(flow)

        return regroupement

    inbound_groups = regrouper_par_isdb(missing_inbound_flows, "inbound")
    outbound_groups = regrouper_par_isdb(missing_outbound_flows, "outbound")

    for missing_isdbs, flows in inbound_groups.items():
        error_messages.append(
            f"Flux ISDB entrants manquants : {', '.join(sorted(flows))} "
            f"=> ISDB manquants en source : {', '.join(sorted(missing_isdbs))}."
        )

    for missing_isdbs, flows in outbound_groups.items():
        error_messages.append(
            f"Flux ISDB sortants manquants : {', '.join(sorted(flows))} "
            f"=> ISDB manquants en destination : {', '.join(sorted(missing_isdbs))}"
        )

    if error_messages:
        return "Configuration ISDB incomplète :\n" + "\n\n".join(error_messages), False

    return "Configuration ISDB correctement configurée", True


def _iter_config_lines(file_path: str):
    """
    Lit le fichier en binaire, essaie plusieurs encodages connus puis
    retombe sur utf-8 avec replacement pour éviter tout crash.
    Retourne un itérable de lignes (sans \n).
    """
    with open(file_path, 'rb') as fb:
        raw = fb.read()

    for enc in ('utf-8', 'utf-8-sig', 'cp1252', 'latin-1'):
        try:
            text = raw.decode(enc)
            return text.splitlines()
        except UnicodeDecodeError:
            continue

    # Dernier recours : on ne plante pas, on remplace les octets invalides
    text = raw.decode('utf-8', errors='replace')
    return text.splitlines()

def read_active_interfaces(file_path):
    interfaces = {}
    current_interface = None
    inside_interface_block = False
    block_depth = 0
    explicit_wan = False

    wan_patterns = [
        r"\bwan\b",
        r"\bfibre\b",
        r"\bftto\b",
        r"\bftth\b",
        r"\binternet\b",
        r"\badsl\b",
        r"\b4g\b"
    ]

    for line in _iter_config_lines(file_path):
        line_strip = line.strip()

        # Entrée dans le bloc interfaces
        if line_strip == "config system interface":
            inside_interface_block = True
            block_depth = 0
            continue

        if inside_interface_block:
            # Gestion des blocs imbriqués
            if line_strip.startswith("config "):
                block_depth += 1
            elif line_strip == "end":
                if block_depth > 0:
                    block_depth -= 1
                else:
                    inside_interface_block = False
                    current_interface = None
                    explicit_wan = False
                    continue

            # Début d'une interface
            if block_depth == 0 and line_strip.startswith("edit "):
                match = re.search(r'"(.+)"', line_strip)
                if match:
                    current_interface = match.group(1)
                    interfaces[current_interface] = {
                        'active': True,
                        'alias': '',
                        'role': None
                    }
                    explicit_wan = False

            # Alias
            if current_interface and line_strip.startswith("set alias "):
                match = re.search(r'"(.+)"', line_strip)
                if match:
                    interfaces[current_interface]['alias'] = match.group(1)

            # Interface désactivée
            elif current_interface and line_strip == "set status down":
                interfaces[current_interface]['active'] = False

            # Indication explicite WAN
            elif current_interface and line_strip in ("set role wan", "set mode pppoe"):
                explicit_wan = True

            # Fin de l'interface
            elif line_strip == "next" and current_interface:
                alias_lower = interfaces[current_interface]['alias'].lower()
                iface_lower = current_interface.lower()

                # EXCLUSION : ssl.root n'est JAMAIS WAN
                if iface_lower == "ssl.root":
                    interfaces[current_interface]['role'] = None

                # EXCLUSION MPLS
                elif "mpls" in alias_lower:
                    interfaces[current_interface]['role'] = None

                # Détection WAN
                elif explicit_wan or any(re.search(p, alias_lower) for p in wan_patterns):
                    interfaces[current_interface]['role'] = "wan"

                current_interface = None
                explicit_wan = False

    # On ne retourne que les interfaces actives
    return {
        iface: details
        for iface, details in interfaces.items()
        if details['active']
    }


def read_zones(file_path, all_interfaces):
    zones = {}
    sdwan_zones = {}
    current_zone = None

    inside_zone_block = False
    inside_sdwan_block = False
    inside_sdwan_zone_block = False
    inside_sdwan_members_block = False

    zone_members = {}

    inside_member_edit = False
    current_member_interface = None
    current_member_zone = None

    for line in _iter_config_lines(file_path):
        line_strip = line.strip()

        # Zones "classiques"
        if line_strip == "config system zone":
            inside_zone_block = True

        elif inside_zone_block and line_strip == "end":
            inside_zone_block = False

        elif inside_zone_block and line_strip.startswith("edit "):
            current_zone = line_strip.split('"')[1]
            zones[current_zone] = {
                'interfaces': [],
                'is_wan_zone': ('internet' in current_zone.lower())
            }

        elif inside_zone_block and current_zone and line_strip.startswith("set interface"):
            interfaces_list = line_strip.split()[2:]
            zones[current_zone]['interfaces'].extend([iface.strip('"') for iface in interfaces_list])

        elif line_strip == "next" and inside_zone_block:
            current_zone = None

        # SD-WAN blocks
        elif line_strip == "config system sdwan":
            inside_sdwan_block = True

        elif inside_sdwan_block and line_strip.startswith("config zone"):
            inside_sdwan_zone_block = True

        elif inside_sdwan_block and line_strip == "end" and inside_sdwan_zone_block:
            inside_sdwan_zone_block = False

        elif inside_sdwan_zone_block and line_strip.startswith("edit "):
            current_zone = line_strip.split('"')[1]
            sdwan_zones[current_zone] = {
                'interfaces': [],
                'is_wan_zone': ('internet' in current_zone.lower())
            }
            zone_members[current_zone] = []

        elif inside_sdwan_zone_block and line_strip == "next":
            current_zone = None

        elif inside_sdwan_block and line_strip.startswith("config members"):
            inside_sdwan_members_block = True

        elif inside_sdwan_members_block and line_strip == "end":
            inside_sdwan_members_block = False

        elif inside_sdwan_members_block and line_strip.startswith("edit "):
            inside_member_edit = True
            current_member_interface = None
            current_member_zone = None

        elif inside_sdwan_members_block and line_strip == "next" and inside_member_edit:
            if current_member_zone:
                zone_members[current_member_zone].append(current_member_interface)
            else:
                zone_members.setdefault('virtual-wan-link', []).append(current_member_interface)

            inside_member_edit = False
            current_member_interface = None
            current_member_zone = None

        elif inside_sdwan_members_block and inside_member_edit and line_strip.startswith("set interface"):
            current_member_interface = line_strip.split('"')[1]

        elif inside_sdwan_members_block and inside_member_edit and line_strip.startswith("set zone"):
            current_member_zone = line_strip.split('"')[1]

    # Associer les membres SD-WAN aux zones
    for zone_name, members in zone_members.items():
        sdwan_zones.setdefault(zone_name, {'interfaces': [], 'is_wan_zone': ('internet' in zone_name.lower())})
        sdwan_zones[zone_name]['interfaces'].extend(members)

    # Marquer les zones WAN si elles contiennent au moins une interface WAN
    for zone_name, zone_data in zones.items():
        for iface in zone_data['interfaces']:
            if iface in all_interfaces and all_interfaces[iface].get('role') == 'wan':
                zone_data['is_wan_zone'] = True
                break

    for zone_name, zone_data in sdwan_zones.items():
        for iface in zone_data['interfaces']:
            if iface in all_interfaces and all_interfaces[iface].get('role') == 'wan':
                zone_data['is_wan_zone'] = True
                break

    return zones, sdwan_zones




def importer_fichier():
    global imported_filepath, imported_filename
    global wan_interfaces  # ou toute autre variable globale à ré-initialiser

    # 1) Vider le dictionnaire (ou réaffecter) pour repartir de zéro
    wan_interfaces = {}

    # 2) Effacer les widgets existants dans le frame, s’il est déjà rempli
    for widget in wan_frame.winfo_children():
        widget.destroy()

    # 3) Ouvrir la boîte de dialogue
    filepath = filedialog.askopenfilename(
        title="Sélectionnez le fichier de configuration",
        filetypes=(("Configuration Files", "*.conf"), ("All Files", "*.*"))
    )
    if filepath:
        # 4) Mettre à jour les variables globales et le label
        imported_filepath = filepath
        imported_filename = os.path.basename(filepath)
        fichier_label.config(text=f"Fichier importé :\n {imported_filename}")
    else:
        messagebox.showerror("Erreur", "Aucun fichier sélectionné !")


def load_wan_interfaces():
    if imported_filepath:
        active_interfaces = read_active_interfaces(imported_filepath)
        zones, sdwan_zones = read_zones(imported_filepath,active_interfaces)
        global wan_interfaces
        wan_interfaces = {iface: details for iface, details in active_interfaces.items()}
        update_wan_interface_list(wan_interfaces, zones, sdwan_zones)
    else:
        messagebox.showerror("Erreur", "Aucun fichier importé !")


def update_wan_interface_list(interfaces, zones, sdwan_zones):
    ...
    global wan_check_vars
    wan_check_vars = []

    # 1) Interfaces actives
    wan_index = 0
    for i, (iface, details) in enumerate(interfaces.items()):
        var = IntVar()
        alias = f' ({details["alias"]})' if details["alias"] else ""

        # Si role == 'wan', on coche par défaut (var.set(1))
        if details.get('role') == 'wan':
            var.set(1)  # <--- cocher par défaut

        cb = Checkbutton(wan_frame, text=f"{iface}{alias}", variable=var, bg="white")
        cb.grid(row=wan_index, column=0, sticky="w")
        wan_check_vars.append(var)
        wan_index += 1

    # 2) Zones classiques
    for zone_i, (zone_name, zone_info) in enumerate(zones.items()):
        # zone_info contient {'interfaces': [...], 'is_wan_zone': True/False}
        var = IntVar()
        # Cocher par défaut si is_wan_zone == True
        if zone_info.get('is_wan_zone'):
            var.set(1)

        iface_list = [i for i in zone_info.get('interfaces', []) if i]
        iface_list_str = ", ".join(iface_list)
        cb = Checkbutton(
            wan_frame,
            text=f"Zone: {zone_name} ({iface_list_str})",
            variable=var,
            bg="white"
        )
        cb.grid(row=wan_index + zone_i, column=0, sticky="w")
        wan_check_vars.append(var)

    # 3) Zones SD-WAN
    sdwan_index = wan_index + len(zones)
    for sdwan_i, (zone_name, zone_info) in enumerate(sdwan_zones.items()):
        var = IntVar()
        if zone_info.get('is_wan_zone'):
            var.set(1)

        iface_list = [i for i in zone_info.get('interfaces', []) if i]
        iface_list_str = ", ".join(iface_list)
        cb = Checkbutton(
            wan_frame,
            text=f"Zone SD-WAN: {zone_name} ({iface_list_str})",
            variable=var,
            bg="white"
        )
        cb.grid(row=sdwan_index + sdwan_i, column=0, sticky="w")
        wan_check_vars.append(var)

    # Ajuster la zone de défilement
    wan_canvas.config(scrollregion=wan_canvas.bbox("all"))


# Fonction pour vérifier et ajouter les interfaces des zones sélectionnées dans les interfaces WAN présumées
def get_selected_wan_interfaces(zones, sdwan_zones):
    selected_interfaces = []

    # Ajout des interfaces présumées WAN
    for iface, var in zip(wan_interfaces.keys(), wan_check_vars):
        if var.get() == 1:
            selected_interfaces.append(iface)

    # Ajout des zones et des zones sd-wan
    offset = len(wan_interfaces)
    for zone, var in zip(zones.keys(), wan_check_vars[offset:offset + len(zones)]):
        if var.get() == 1:
            selected_interfaces.append(zone)

    offset += len(zones)
    for zone, var in zip(sdwan_zones.keys(), wan_check_vars[offset:offset + len(sdwan_zones)]):
        if var.get() == 1:
            selected_interfaces.append(zone)

    return selected_interfaces



def verifier_ldaps(config_lines):
    ldap_connections_non_secure = []
    ldap_connections_without_cert = []

    current_ldap = None
    in_ldap_block = False
    ldap_found = False

    secure_ldaps_found = False
    ca_cert_found = False

    for line in config_lines:
        line = line.strip()

        if line.startswith('config user ldap'):
            in_ldap_block = True

        elif in_ldap_block and line.startswith('edit '):
            ldap_found = True

            if '"' in line:
                current_ldap = line.split('"')[1]
            else:
                current_ldap = line.replace("edit", "").strip()

            secure_ldaps_found = False
            ca_cert_found = False

        elif in_ldap_block and line.startswith('set secure ldaps'):
            secure_ldaps_found = True

        elif in_ldap_block and line.startswith('set ca-cert '):
            ca_cert = line.replace('set ca-cert', '').strip().strip('"')
            if ca_cert:
                ca_cert_found = True

        elif in_ldap_block and line == 'next':
            if current_ldap:
                if not secure_ldaps_found:
                    ldap_connections_non_secure.append(current_ldap)
                elif not ca_cert_found:
                    ldap_connections_without_cert.append(current_ldap)

            current_ldap = None
            secure_ldaps_found = False
            ca_cert_found = False

        elif in_ldap_block and line == 'end':
            in_ldap_block = False

    if not ldap_found:
        return "Aucune synchronisation LDAP(S) identifiée", "N/A"

    if ldap_connections_non_secure or ldap_connections_without_cert:
        messages = []

        if ldap_connections_non_secure:
            messages.append(
                "Présence LDAP mais pas LDAPS pour les connexions suivantes : "
                f"'{', '.join(ldap_connections_non_secure)}'"
            )

        if ldap_connections_without_cert:
            messages.append(
                "Présence LDAPS sans certificat CA pour les connexions suivantes : "
                f"'{', '.join(ldap_connections_without_cert)}'"
            )

        return " / ".join(messages), "Non"

    return "Présence LDAPS avec certificat CA pour toutes les connexions LDAP", "Oui"



def verifier_sauvegardes_automatiques(config_lines):
    backup_on_logout = False
    image_auto_backup = False

    for line in config_lines:
        line = line.strip()
        if 'set revision-backup-on-logout enable' in line:
            backup_on_logout = True
        if 'set revision-image-auto-backup enable' in line:
            image_auto_backup = True

    if backup_on_logout and image_auto_backup:
        return "Sauvegardes automatiques configurées", True
    else:
        missing = []
        if not backup_on_logout:
            missing.append("auto backup logout")
        if not image_auto_backup:
            missing.append("auto backup upgrade")
        return f"Sauvegardes automatiques non configurées correctement. Manquantes: {', '.join(missing)}", False



def verifier_acces_admin_sns_via_loopback(config_lines):
    import re

    # 1) Détection des interfaces loopback avec gestion de l'imbrication du bloc "config system interface"
    loopback_interfaces = set()
    current_interface = None
    in_system_interface = False
    block_depth = 0

    for line in config_lines:
        line_stripped = line.strip()
        if line_stripped.startswith("config system interface"):
            in_system_interface = True
            block_depth = 1
            continue

        if in_system_interface:
            if line_stripped.startswith("config "):
                block_depth += 1
            elif line_stripped == "end":
                block_depth -= 1
                if block_depth == 0:
                    in_system_interface = False
                    continue

            # On ne traite que le niveau 1 (hors sous-blocs)
            if block_depth == 1:
                if line_stripped.startswith("edit "):
                    match = re.search(r'^edit\s+"([^"]+)"', line_stripped)
                    if match:
                        current_interface = match.group(1)
                    else:
                        parts = line_stripped.split()
                        current_interface = parts[1] if len(parts) > 1 else None
                elif current_interface and 'set type loopback' in line_stripped:
                    loopback_interfaces.add(current_interface)

    # 2) Analyse des objets d'adresse pour trouver ceux qui pointent vers 'ip.sns-security.fr'
    in_firewall_address = False
    current_address = None
    current_address_is_fqdn = False
    fqdn_objects_with_ip_sns = set()

    for line in config_lines:
        line = line.strip()

        if line == 'config firewall address':
            in_firewall_address = True
        elif line == 'end' and in_firewall_address:
            in_firewall_address = False
        elif in_firewall_address:
            if line.startswith('edit '):
                match = re.search(r'^edit\s+"([^"]+)"', line)
                if match:
                    current_address = match.group(1)
                else:
                    current_address = line.split()[1]
                current_address_is_fqdn = False
            elif line.startswith('set type '):
                addr_type = line.split()[2]
                if addr_type == 'fqdn':
                    current_address_is_fqdn = True
            elif current_address_is_fqdn and line.startswith('set fqdn '):
                match = re.search(r'^set fqdn\s+"([^"]+)"', line)
                if match:
                    fqdn = match.group(1)
                else:
                    fqdn = line.split()[2]
                if "ip.sns-security.fr" in fqdn:
                    fqdn_objects_with_ip_sns.add(current_address)
            elif line == 'next':
                current_address = None
                current_address_is_fqdn = False

    equivalent_objects = set(fqdn_objects_with_ip_sns)

    # 3) Analyse des groupes d'adresses (config firewall addrgrp)
    addrgrp_members = {}
    in_addrgrp_block = False
    current_addrgrp = None
    addrgrp_contains_ip_sns = set()

    for line in config_lines:
        line = line.strip()

        if line == 'config firewall addrgrp':
            in_addrgrp_block = True
        elif line == 'end' and in_addrgrp_block:
            in_addrgrp_block = False
        elif in_addrgrp_block:
            if line.startswith('edit '):
                match = re.search(r'^edit\s+"([^"]+)"', line)
                if match:
                    current_addrgrp = match.group(1)
                else:
                    current_addrgrp = line.split()[1]
                addrgrp_members[current_addrgrp] = set()
            elif line.startswith('set member ') and current_addrgrp:
                content = line[len('set member '):].strip()
                members = re.findall(r'"([^"]+)"', content)
                if not members:
                    members = content.split()
                addrgrp_members[current_addrgrp].update(members)
                if any(member in equivalent_objects for member in members):
                    addrgrp_contains_ip_sns.add(current_addrgrp)
            elif line == 'next':
                current_addrgrp = None

    # 4) Analyse des VIP (config firewall vip) avec gestion de la profondeur (pour config realservers)
    in_vip_block = False
    vip_block_depth = 0
    vip_addresses = set()
    current_vip = None

    for line in config_lines:
        line = line.strip()

        if line == 'config firewall vip':
            in_vip_block = True
            vip_block_depth = 1
            continue

        if in_vip_block:
            if line.startswith('config '):
                vip_block_depth += 1
                continue
            elif line == 'end':
                vip_block_depth -= 1
                if vip_block_depth == 0:
                    in_vip_block = False
                continue
            else:
                if line.startswith('edit '):
                    if vip_block_depth == 1:
                        match = re.search(r'^edit\s+"([^"]+)"', line)
                        if match:
                            current_vip = match.group(1)
                        else:
                            current_vip = line.split()[1]
                        vip_addresses.add(current_vip)

    # 5) Analyse des groupes de VIP (config firewall vipgrp)
    in_vipgrp_block = False
    vipgrp_members = {}
    current_vipgrp = None

    for line in config_lines:
        line = line.strip()

        if line == 'config firewall vipgrp':
            in_vipgrp_block = True
        elif line == 'end' and in_vipgrp_block:
            in_vipgrp_block = False
        elif in_vipgrp_block:
            if line.startswith('edit '):
                match = re.search(r'^edit\s+"([^"]+)"', line)
                if match:
                    current_vipgrp = match.group(1)
                else:
                    current_vipgrp = line.split()[1]
                vipgrp_members[current_vipgrp] = set()
            elif line.startswith('set member ') and current_vipgrp:
                content = line[len('set member '):].strip()
                members = re.findall(r'"([^"]+)"', content)
                if not members:
                    members = content.split()
                vipgrp_members[current_vipgrp].update(members)
            elif line == 'next':
                current_vipgrp = None

    # Ajout des VIP membres de vipgrp dans vip_addresses
    for vipgrp, members in vipgrp_members.items():
        for member in members:
            vip_addresses.add(member)

    # 6) Vérification des politiques d'accès (config firewall policy)
    in_firewall_policy = False
    access_policies = []
    current_policy = None

    for line in config_lines:
        line = line.strip()

        if line == 'config firewall policy':
            in_firewall_policy = True
        elif line == 'end' and in_firewall_policy:
            in_firewall_policy = False
        elif in_firewall_policy:
            if line.startswith('edit '):
                policy_id = line.split()[1]
                current_policy = {
                    'id': policy_id,
                    'srcaddr': [],
                    'dstintf': None,
                    'dstaddr': []
                }
            elif current_policy and line.startswith('set srcaddr '):
                content = line[len('set srcaddr '):].strip()
                src_objects = re.findall(r'"([^"]+)"', content)
                if not src_objects:
                    src_objects = content.split()
                current_policy['srcaddr'] = src_objects
            elif current_policy and line.startswith('set dstintf '):
                match = re.search(r'^set dstintf\s+"([^"]+)"', line)
                if match:
                    current_policy['dstintf'] = match.group(1)
                else:
                    splitted = line.split()
                    if len(splitted) >= 3:
                        current_policy['dstintf'] = splitted[2]
            elif current_policy and line.startswith('set dstaddr '):
                content = line[len('set dstaddr '):].strip()
                dst_objects = re.findall(r'"([^"]+)"', content)
                if not dst_objects:
                    dst_objects = content.split()
                current_policy['dstaddr'] = dst_objects
            elif line == 'next' and current_policy:
                access_policies.append(current_policy)
                current_policy = None

    # 7) Vérification finale des politiques
    for policy in access_policies:
        # Condition 1 : au moins un srcaddr est dans la liste d'objets "ip.sns-security.fr"
        # ou dans un groupe contenant ces objets
        is_source_in_equiv = any(addr in equivalent_objects for addr in policy['srcaddr'])
        is_source_in_grp = any(addr in addrgrp_contains_ip_sns for addr in policy['srcaddr'])
        is_source_valid = is_source_in_equiv or is_source_in_grp

        # Condition 2 : l'interface de destination doit être une loopback
        is_loopback_valid = (policy['dstintf'] in loopback_interfaces)

        # Condition 3 : la destination doit être un VIP (ou un VIP dans un groupe de VIP)
        is_vip_valid = any(
            (dst in vip_addresses) or (dst in vipgrp_members)
            for dst in policy['dstaddr']
        )

        if is_source_valid and is_loopback_valid and is_vip_valid:
            return (
                "Accès administration SNS configuré correctement\n"
                "(IP SNS en source + loopback + VIP)"
            ), True

    return "Accès administration SNS via une loopback\n non configuré ou incomplet", False


def verifier_dns_database(config_lines):
    in_dns_database = False
    dns_database_found = False

    for line in config_lines:
        line = line.strip()
        if line == 'config system dns-database':
            in_dns_database = True
        elif line == 'end' and in_dns_database:
            in_dns_database = False
        elif in_dns_database and 'edit "ip.sns-security.fr"' in line:
            dns_database_found = True
            break

    if dns_database_found:
        return "Entrée DNS Database 'ip.sns-security.fr' présente", True
    else:
        return "Entrée DNS Database 'ip.sns-security.fr' absente", False


def verifier_sip_alg(config_lines):
    in_session_helper_block = False
    sip_found = False
    voip_alg_mode_correct = False
    voip_alg_mode_line_present = False

    for line in config_lines:
        line = line.strip()
        if line == 'config system session-helper':
            in_session_helper_block = True
        elif line == 'end' and in_session_helper_block:
            in_session_helper_block = False
        elif in_session_helper_block and 'set name sip' in line:
            sip_found = True
        elif 'set default-voip-alg-mode' in line:
            voip_alg_mode_line_present = True
            if 'kernel-helper-based' in line:
                voip_alg_mode_correct = True

    # Évaluer les résultats
    non_conformities = []
    if sip_found:
        non_conformities.append("SIP est présent dans le bloc 'session-helper'.")
    if not voip_alg_mode_line_present:
        non_conformities.append("La ligne 'set default-voip-alg-mode kernel-helper-based ' est absente.")
    elif not voip_alg_mode_correct:
        non_conformities.append("La valeur de 'set default-voip-alg-mode' n'est pas 'kernel-helper-based'.")

    if non_conformities:
        return f"Problèmes détectés avec la configuration SIP ALG : {'; '.join(non_conformities)}", False
    else:
        return "SIP ALG est correctement désactivé", True


def verifier_fortisandbox_cloud(config_lines, licence_utm):
    sandbox_region = None

    # Si la licence UTM n'est pas valide
    if not licence_utm:
        return f"La licence UTM n'est pas valide", False

    for line in config_lines:
        line = line.strip()
        if line.startswith('set sandbox-region '):
            sandbox_region = line.split('"')[1]
            break

    if sandbox_region:
        if sandbox_region == "Europe":
            return "FortiSandbox Cloud configurée avec la région 'Europe'", True
        else:
            return f"FortiSandbox Cloud configurée avec une autre région : '{sandbox_region}'", False
    else:
        return "FortiSandbox Cloud non configurée", False


def verifier_anycast_fortiguard(config_lines, licence_utm):
    # Si la licence UTM n'est pas valide
    if not licence_utm:
        return f"La licence UTM n'est pas valide", False

    for line in config_lines:
        if 'set fortiguard-anycast disable' in line:
            return "Requêtes anycast vers FortiGuard désactivées", True
    return "Requêtes anycast vers FortiGuard actives", False


def verifier_mises_a_jour_fortiguard(config_lines, licence_utm):
    # Si la licence UTM n'est pas valide
    if not licence_utm:
        return f"La licence UTM n'est pas valide", False

    in_autoupdate_block = False
    autoupdate_status = None
    autoupdate_frequency = None
    autoupdate_block_found = False  # Indicateur pour vérifier la présence du bloc

    for line in config_lines:
        line = line.strip()
        if line == 'config system autoupdate schedule':
            in_autoupdate_block = True
            autoupdate_block_found = True
        elif line == 'end' and in_autoupdate_block:
            in_autoupdate_block = False
        elif in_autoupdate_block:
            if line.startswith('set status'):
                autoupdate_status = line.split()[-1].lower()
            elif line.startswith('set frequency'):
                autoupdate_frequency = line.split()[-1].lower()

    frequency_required = 'automatic'

    if not autoupdate_block_found:
        # Si le bloc autoupdate n'est pas présent, considérer comme configuration par défaut et conforme
        fortiguard_autoupdate_result = (
            "La configuration des mises à jour Fortiguard est paramétré sur 'automatique'")
        fortiguard_autoupdate_conform = True
    else:
        # Logique existante pour vérifier la conformité
        if autoupdate_frequency == frequency_required:
            fortiguard_autoupdate_result = (
                "La configuration des mises à jour Fortiguard est paramétré sur 'automatic'")
            fortiguard_autoupdate_conform = True
        else:
            # Si la fréquence n'est pas 'automatic', vérifier le statut
            if autoupdate_status == 'enable':
                if autoupdate_frequency:
                    fortiguard_autoupdate_result = (
                        f"Les mises à jour Fortiguard des bases AV + IPS sont activées "
                        f"mais configurées sur une fréquence non conforme: '{autoupdate_frequency}'. "
                        f"Elle doit être définie sur 'automatic'.")
                else:
                    fortiguard_autoupdate_result = (
                        "Les mises à jour Fortiguard des bases AV + IPS sont activées "
                        "mais aucune fréquence n'est définie. Elle doit être définie sur 'automatic'.")
                fortiguard_autoupdate_conform = False
            elif autoupdate_status == 'disable':
                fortiguard_autoupdate_result = "Les mises à jour Fortiguard des bases AV + IPS sont désactivées"
                fortiguard_autoupdate_conform = False
            else:
                fortiguard_autoupdate_result = "Les mises à jour Fortiguard des bases AV + IPS ne sont pas configurées sur 'automatic'"
                fortiguard_autoupdate_conform = False

    return fortiguard_autoupdate_result, fortiguard_autoupdate_conform


def verifier_route_blackhole(config_lines, lien_mpls_L2L):
    in_router_static_block = False
    in_edit_block = False
    blackhole_enable = False
    distance_254 = False
    dstaddr_rfc_6890 = False

    for line in config_lines:
        line = line.strip()
        if line == 'config router static':
            in_router_static_block = True
        elif line == 'end' and in_router_static_block:
            in_router_static_block = False
        elif in_router_static_block:
            if line.startswith('edit '):
                in_edit_block = True
                blackhole_enable = False
                distance_254 = False
                dstaddr_rfc_6890 = False
            elif line == 'next' and in_edit_block:
                if blackhole_enable and distance_254 and dstaddr_rfc_6890:
                    if lien_mpls_L2L:
                        return (
                            "Route blackhole pour les réseaux privés présente alors qu'il y a un lien MPLS ou L2L, attention !",
                            False
                        )
                    else:
                        return "Route blackhole pour les réseaux privés présente", True
                in_edit_block = False
            elif in_edit_block:
                if 'set blackhole enable' in line:
                    blackhole_enable = True
                elif 'set distance 254' in line:
                    distance_254 = True
                elif 'set dstaddr "RFC-6890_Unreachable-Subnets"' in line:
                    dstaddr_rfc_6890 = True

    if lien_mpls_L2L:
        return "La blackhole RFC 6890 n'est pas présente ou incomplète mais le résultat est conforme car présence de lien MPLS ou L2L", True
    else:
        return "La blackhole RFC 6890 n'est pas présente ou incomplète", False


def extraire_ha_details(config_lines):
    in_ha_block = False
    in_ha_mgmt_block = False

    ha_details = {
        "group_name": None,
        "session_pickup": None,
        "session_pickup_connectionless": None,
        "session_pickup_expectation": None,
        "hbdev": None,
        "ha_mgmt_interfaces": False,
        "override": None,
        "override_wait_time": None,
        "ha_present": False
    }

    for line in config_lines:
        line = line.strip()

        # Détecter l'entrée dans le bloc principal
        if line.startswith('config system ha'):
            in_ha_block = True
            continue

        # Détecter l'entrée dans le sous-bloc
        if in_ha_block and line.startswith('config ha-mgmt-interfaces'):
            in_ha_mgmt_block = True
            ha_details["ha_mgmt_interfaces"] = True
            continue

        # Détecter la fermeture d'un bloc (principal ou sous-bloc)
        if line == 'end':
            if in_ha_mgmt_block:
                in_ha_mgmt_block = False
            elif in_ha_block:
                in_ha_block = False
            continue

        # Traitement des lignes si on est dans le bloc principal (hors sous-bloc)
        if in_ha_block and not in_ha_mgmt_block:
            if line.startswith('set group-name '):
                ha_details["group_name"] = line.split('"')[1]
                ha_details["ha_present"] = True
            elif line.startswith('set session-pickup '):
                ha_details["session_pickup"] = line.split()[2]
            elif line.startswith('set session-pickup-connectionless '):
                ha_details["session_pickup_connectionless"] = line.split()[2]
            elif line.startswith('set session-pickup-expectation '):
                ha_details["session_pickup_expectation"] = line.split()[2]
            elif line.startswith('set hbdev '):
                # Récupère toutes les interfaces entre guillemets
                ha_details["hbdev"] = line.split('"')[1::2]
            elif line.startswith('set override '):
                parts = line.split()
                if len(parts) >= 3:
                    ha_details["override"] = parts[2]
            elif line.startswith('set override-wait-time '):
                parts = line.split()
                if len(parts) >= 3:
                    ha_details["override_wait_time"] = int(parts[2])

    return ha_details



# Fonction pour vérifier l'activation du session pickup
def verifier_ha_session_pickup(config_lines):
    ha_details = extraire_ha_details(config_lines)
    if not ha_details["ha_present"]:
        return "Absence de Cluster", "N/A"

    missing_settings = []

    def format_option(option_name, value):
        if value is None or value == "disable":
            return f"{option_name} (option non activée)."
        else:
            return f"{option_name}: {value}"

    if ha_details["session_pickup"] != "enable":
        missing_settings.append(format_option("session-pickup", ha_details["session_pickup"]))
    if ha_details["session_pickup_connectionless"] != "enable":
        missing_settings.append(format_option("session-pickup-connectionless", ha_details["session_pickup_connectionless"]))
    if ha_details["session_pickup_expectation"] != "enable":
        missing_settings.append(format_option("session-pickup-expectation", ha_details["session_pickup_expectation"]))

    if not missing_settings:
        return "Session pickup correctement configuré", True
    else:
        return "Session pickup non correctement configuré : " + " ".join(missing_settings), False



# Fonction pour vérifier la redondance des interfaces HA
def verifier_ha_redundance_interfaces(config_lines):
    ha_details = extraire_ha_details(config_lines)
    if not ha_details["ha_present"]:
        return "Absence de Cluster", "N/A"

    if ha_details["hbdev"]:
        if len(ha_details['hbdev']) < 2:
            return f"Nombre de Heartbeat insuffisant : {len(ha_details['hbdev'])} (moins de 2)", False
        return f"Nombre de Heartbeat : {len(ha_details['hbdev'])}", True
    else:
        return "Redondance des interfaces HA non configurée", False


def verifier_ha_override(config_lines):
    ha_details = extraire_ha_details(config_lines)

    # Pas de HA configuré
    if not ha_details["ha_present"]:
        return "Absence de Cluster", "N/A"

    override = ha_details["override"]
    override_wait_time = ha_details["override_wait_time"]

    if override == "enable":
        # Si override est activé, vérifions la valeur du wait_time
        if override_wait_time is None:
            return (
                "Override activé mais le délai n'est pas configuré (override-wait-time manquant).",
                False
            )
        else:
            # Si le délai est configuré, on vérifie la valeur
            if override_wait_time == 30:
                return "Override configuré avec attente de 30 secondes", True
            else:
                return (
                    f"Override activé avec une attente de {override_wait_time} seconde(s)",
                    False
                )

    elif override == "disable":
        # Override désactivé => conforme
        return "Override désactivé", True

    # Valeur inattendue ou non configurée
    return "N/A", "N/A"


def ajouter_regle_ports_deny(rule, rules):
    """
    Ajoute (ou met à jour) la règle dans le dictionnaire 'rules'.
    On stocke un booléen 'ports_deny' qui indique la présence
    ou l'absence du service "Ports-Deny".
    """
    # Conversion des interfaces en majuscules pour assurer l'uniformité
    src = rule['src_interface'].upper() if rule['src_interface'] else None
    dst = rule['dst_interface'].upper() if rule['dst_interface'] else None
    services = rule['services']

    # Le service "Ports-Deny" est recherché exactement dans la liste des services
    ports_deny = "Ports-Deny" in services

    # Crée ou met à jour l'entrée (src, dst)
    if (src, dst) not in rules:
        rules[(src, dst)] = {'ports_deny': ports_deny}
    else:
        # Si une entrée existe déjà, on passe à True si l'une des règles l'active
        rules[(src, dst)]['ports_deny'] = rules[(src, dst)]['ports_deny'] or ports_deny


def verifier_ports_deny(config_lines, selected_wan_interfaces):
    """
    Vérifie la configuration du service "Ports-Deny" dans les règles de firewall pour le flux LAN → WAN.

    La logique appliquée est la suivante :
      - Si une règle globale ANY → ANY avec "Ports-Deny" est présente, la configuration est considérée correcte.
      - Sinon, si une règle ANY → <WAN> (par exemple ANY → Z-INTERNET) est présente, elle couvre l'ensemble des flux LAN vers ce WAN.
      - Pour chaque règle dont la destination est une interface WAN non globalement couverte, il faut que le service "Ports-Deny" soit activé.
      - Enfin, les flux dont la source est "ANY" ne sont pas affichés dans la liste des flux manquants.

    Returns:
        tuple: (message, statut)
            - message (str): Message décrivant le résultat de la vérification.
            - statut (bool): True si la configuration est correcte, False sinon.
    """
    in_firewall_policy = False
    current_rule = None
    rules = {}

    # Parsing du bloc de configuration "config firewall policy"
    for line in config_lines:
        line = line.strip()
        if line.lower() == 'config firewall policy':
            in_firewall_policy = True
        elif line.lower() == 'end' and in_firewall_policy:
            in_firewall_policy = False
            if current_rule:
                ajouter_regle_ports_deny(current_rule, rules)
                current_rule = None
        elif in_firewall_policy:
            if line.lower().startswith('edit '):
                if current_rule:
                    ajouter_regle_ports_deny(current_rule, rules)
                current_rule = {
                    'src_interface': None,
                    'dst_interface': None,
                    'services': [],
                    'actions': []
                }
            elif line.lower().startswith('set srcintf '):
                # Exemple: set srcintf "any"
                current_rule['src_interface'] = line.split('"')[1].upper()
            elif line.lower().startswith('set dstintf '):
                # Exemple: set dstintf "Z-INTERNET"
                current_rule['dst_interface'] = line.split('"')[1].upper()
            elif line.lower().startswith('set service '):
                # Exemple: set service "Ports-Deny" "HTTP" "HTTPS"
                current_rule['services'] = line.split('"')[1::2]
            elif line.lower().startswith('set action '):
                # On récupère l'action (même si elle n'est pas utilisée ici)
                current_rule['actions'] = line.split(' ')[2:]

    # Si un bloc "edit" était ouvert mais non refermé
    if current_rule:
        ajouter_regle_ports_deny(current_rule, rules)

    # --- Vérification de la présence d'une règle globale ANY → ANY ---
    any_any_key = ("ANY", "ANY")
    if any_any_key in rules and rules[any_any_key].get('ports_deny'):
        return "Le 'Ports-Deny' est correctement configuré", True

    # --- Détection des règles globales de type ANY → WAN ---
    selected_wan = [iface.upper() for iface in selected_wan_interfaces]
    any_covered_dst = set()
    for (src, dst), details in rules.items():
        if src == "ANY" and dst in selected_wan and details.get('ports_deny'):
            any_covered_dst.add(dst)

    # --- Vérification sur chaque flux LAN → WAN non couvert globalement ---
    missing_ports_deny_rules = []
    for (src, dst), details in rules.items():
        if dst in selected_wan:
            if dst in any_covered_dst:
                continue
            if not details.get('ports_deny'):
                # On n'ajoute pas les règles dont la source est ANY pour éviter les doublons
                if src == "ANY":
                    continue
                missing_ports_deny_rules.append(f"{src} vers {dst}")

    if missing_ports_deny_rules:
        if len(missing_ports_deny_rules) == 1:
            return (
                f"Règle 'Ports-Deny' manquante ou mal configurée pour le flux {missing_ports_deny_rules[0]}",
                False
            )
        else:
            return (
                "Règle 'Ports-Deny' manquante ou mal configurée pour les flux suivants : " +
                ", ".join(missing_ports_deny_rules),
                False
            )

    return "Le 'Ports-Deny' est correctement configuré", True


def verifier_utilisation_sdwan(config_lines, selected_wan_interfaces):
    in_sdwan_block = False
    in_zone_block = False
    in_members_block = False
    in_interface_block = False

    sdwan_members = set()
    sdwan_zones_names = set()
    physical_interfaces = set()

    current_interface = None
    current_sdwan_zone = None

    missing_interfaces = []

    for line in config_lines:
        line = line.strip()

        # ----- Bloc SD-WAN -----
        if line == 'config system sdwan':
            in_sdwan_block = True

        elif line == 'end' and in_sdwan_block:
            if in_zone_block:
                in_zone_block = False
                current_sdwan_zone = None
            elif in_members_block:
                in_members_block = False
            else:
                in_sdwan_block = False

        if in_sdwan_block:
            if line == 'config zone':
                in_zone_block = True

            elif line == 'config members':
                in_members_block = True

            elif in_zone_block and line.startswith('edit '):
                parts = line.split('"')
                if len(parts) > 1:
                    current_sdwan_zone = parts[1]
                    sdwan_zones_names.add(current_sdwan_zone)

            elif in_members_block and 'set interface' in line:
                parts = line.split('"')
                if len(parts) > 1:
                    sdwan_members.add(parts[1])

        # ----- Interfaces physiques -----
        if line == 'config system interface':
            in_interface_block = True

        elif line == 'end' and in_interface_block:
            in_interface_block = False

        if in_interface_block:
            if line.startswith('edit '):
                parts = line.split('"')
                if len(parts) > 1:
                    current_interface = parts[1]
                    physical_interfaces.add(current_interface)

            elif current_interface and line == 'next':
                current_interface = None

    # ----- Vérifications -----
    sdwan_configured = len(sdwan_members) > 0
    if not sdwan_configured:
        return "Le SD-WAN n'est pas configuré", False, "Configurer le SD-WAN", []

    # Exclure les zones SD-WAN des éléments sélectionnés
    selected_real_ifaces = [
        x for x in selected_wan_interfaces
        if x not in sdwan_zones_names
    ]

    for iface in selected_real_ifaces:
        if iface not in sdwan_members:
            missing_interfaces.append(iface)

    if missing_interfaces:
        return (
            f"Le SD-WAN est configuré, mais les interfaces suivantes ne sont pas présentes dans les membres SD-WAN : {', '.join(missing_interfaces)}",
            False,
            f"Configurer le SD-WAN pour les interfaces suivantes : {', '.join(missing_interfaces)}",
            missing_interfaces
        )

    return "Le SD-WAN est configuré", True, "", []


def verifier_profils_securite_sur_regles(config_lines):
    """
    Vérifie que toutes les règles avec logs UTM ont un profil de sécurité activé.

    Prend en compte le cas Security Fabric :
    - Si Security Fabric non activé : scan initial.
    - Si Security Fabric activé + log-unification disable : scan initial.
    - Si Security Fabric activé + configuration-sync local : scan initial.
    - Sinon : toutes les règles sont considérées comme ayant les logs en "all",
      donc aucune règle n'est considérée comme ayant des logs UTM.
    """

    def analyser_security_fabric(config_lines):
        in_csf = False
        csf_enabled = False
        log_unification_disabled = False
        configuration_sync_local = False

        for raw_line in config_lines:
            line = raw_line.strip().lower()

            if line == 'config system csf':
                in_csf = True
                continue

            if in_csf and line == 'end':
                in_csf = False
                continue

            if in_csf:
                if line == 'set status enable':
                    csf_enabled = True

                elif line == 'set log-unification disable':
                    log_unification_disabled = True

                elif line == 'set configuration-sync local':
                    configuration_sync_local = True

        return csf_enabled, log_unification_disabled, configuration_sync_local

    def recuperer_ids_regles_firewall(config_lines):
        in_firewall_policy = False
        rule_ids = []

        for raw_line in config_lines:
            line = raw_line.strip()
            line_lower = line.lower()

            if line_lower == 'config firewall policy':
                in_firewall_policy = True
                continue

            if line_lower == 'end' and in_firewall_policy:
                in_firewall_policy = False
                continue

            if in_firewall_policy and line_lower.startswith('edit '):
                rule_id = line.split(' ', 1)[1].strip('"')
                rule_ids.append(rule_id)

        return rule_ids

    def scan_initial(config_lines):
        in_firewall_policy = False
        current_rule_id = None
        logs_are_utm = False
        security_profile_enabled = False
        rules_with_utm_logs_no_security_profile = []

        has_firewall_policy = any(
            line.strip().lower() == 'config firewall policy'
            for line in config_lines
        )

        if not has_firewall_policy:
            return (
                "Aucune section 'config firewall policy' trouvée dans la configuration.",
                True,
                []
            )

        for raw_line in config_lines:
            line = raw_line.strip()
            line_lower = line.lower()

            if line_lower == 'config firewall policy':
                in_firewall_policy = True
                continue

            if line_lower == 'end' and in_firewall_policy:
                in_firewall_policy = False
                continue

            if in_firewall_policy:
                if line_lower.startswith('edit '):
                    current_rule_id = line.split(' ', 1)[1].strip('"')

                    # Par défaut FortiGate : si logtraffic absent,
                    # on considère ici que c'est UTM, comme dans ton scan initial.
                    logs_are_utm = True
                    security_profile_enabled = False

                elif line_lower.startswith('set logtraffic ') and current_rule_id:
                    if ' disable' in f' {line_lower} ':
                        logs_are_utm = False
                    elif ' all' in f' {line_lower} ':
                        logs_are_utm = False
                    else:
                        logs_are_utm = True

                elif line_lower == 'set utm-status enable' and current_rule_id:
                    security_profile_enabled = True

                elif line_lower == 'next' and current_rule_id:
                    if logs_are_utm and not security_profile_enabled:
                        rules_with_utm_logs_no_security_profile.append(current_rule_id)

                    current_rule_id = None
                    logs_are_utm = False
                    security_profile_enabled = False

        if rules_with_utm_logs_no_security_profile:
            return (
                "Règles avec logs UTM sans profils de sécurité activés : "
                f"{', '.join(rules_with_utm_logs_no_security_profile)}",
                False,
                rules_with_utm_logs_no_security_profile
            )

        return (
            "Toutes les règles avec logs UTM ont des profils de sécurité activés.",
            True,
            []
        )

    csf_enabled, log_unification_disabled, configuration_sync_local = analyser_security_fabric(config_lines)

    # Cas 1 : Security Fabric absent ou non activé
    if not csf_enabled:
        return scan_initial(config_lines)

    # Cas 2 : Security Fabric actif + log-unification désactivé
    if log_unification_disabled:
        return scan_initial(config_lines)

    # Cas 3 : Security Fabric actif + configuration-sync local
    if configuration_sync_local:
        return scan_initial(config_lines)

    # Cas 4 : Security Fabric actif,
    # sans log-unification disable,
    # sans configuration-sync local.
    # Dans ce cas, toutes les règles sont considérées comme logtraffic all.
    # Donc aucune règle n'est considérée comme UTM.
    rule_ids = recuperer_ids_regles_firewall(config_lines)

    if not rule_ids:
        return (
            "Aucune section 'config firewall policy' trouvée dans la configuration.",
            True,
            []
        )

    return (
        "Security Fabric actif sans 'set log-unification disable' "
        "ni 'set configuration-sync local' : toutes les règles sont considérées "
        "comme ayant les logs en 'all'. Aucune règle avec logs UTM à contrôler.",
        True,
        []
    )



def verifier_mail_filter(config_lines):
    in_firewall_policy = False
    rule_id = None
    rules_with_mail_filter = []

    for line in config_lines:
        line = line.strip()
        if 'config firewall policy' in line:
            in_firewall_policy = True
        elif 'end' in line and in_firewall_policy:
            in_firewall_policy = False
        elif in_firewall_policy:
            if line.startswith('edit '):
                rule_id = line.split(' ')[1].strip('"')
            elif 'set emailfilter-profile' in line and rule_id:
                rules_with_mail_filter.append(rule_id)
                rule_id = None

    if rules_with_mail_filter:
        return f"Règles utilisant un 'Mail Filter' : {', '.join(rules_with_mail_filter)}", False, rules_with_mail_filter
    else:
        return "Le profil de sécurité 'Mail Filter' n'est pas utilisé", True, []


def verifier_webfilter_profiles(config_lines, licence_utm):
    profiles = {}
    profile_groups = {}  # Mapping des groupes de profils WebFilter vers leurs profils
    current_profile = None
    current_profile_info = None
    categories_to_check = {209, 210}

    # Flags pour suivre le contexte
    in_profile = False
    in_web = False
    in_ftgd_wf = False
    in_filters = False
    in_filter_edit = False
    in_profile_group = False
    in_profile_group_edit = False
    current_edit_group = None
    current_edit_category = None
    current_edit_action = None

    # Pile pour suivre la hiérarchie de configuration
    config_stack = []

    # Phase 1: Extraction des profils WebFilter et des groupes
    for line_number, line in enumerate(config_lines, 1):
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            config_stack.append(stripped_line)
            if stripped_line == 'config webfilter profile':
                in_profile = True
            elif stripped_line == 'config web' and in_profile:
                in_web = True
            elif stripped_line == 'config ftgd-wf' and in_profile:
                in_ftgd_wf = True
            elif stripped_line == 'config filters' and in_ftgd_wf:
                in_filters = True
            elif stripped_line == 'config firewall profile-group':
                in_profile_group = True

        elif stripped_line == 'end':
            popped = None
            if config_stack:
                popped = config_stack.pop()

                if popped == 'config webfilter profile':
                    if current_profile and current_profile_info:
                        profiles[current_profile] = current_profile_info
                    current_profile = None
                    current_profile_info = None
                    in_profile = False
                    in_web = False
                    in_ftgd_wf = False
                    in_filters = False

                elif popped == 'config web':
                    in_web = False

                elif popped == 'config ftgd-wf':
                    in_ftgd_wf = False

                elif popped == 'config filters':
                    in_filters = False

                elif popped == 'config firewall profile-group':
                    in_profile_group = False
                    in_profile_group_edit = False
                    current_edit_group = None

            in_filter_edit = False
            current_edit_category = None
            current_edit_action = None

            if in_profile_group_edit and popped and popped.startswith('edit '):
                in_profile_group_edit = False
                current_edit_group = None

        elif stripped_line.startswith('edit '):
            if in_profile and config_stack and config_stack[-1] == 'config webfilter profile':
                if current_profile and current_profile_info:
                    profiles[current_profile] = current_profile_info

                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_profile = parts[1]
                    current_profile_info = {
                        'options_error_allow': False,
                        'blocklist_enable': False,
                        'categories_blocked': {209: False, 210: False},
                        'category_207_has_action': False
                    }
                else:
                    current_profile = None
                    current_profile_info = None

            elif in_profile_group and config_stack and config_stack[-1] == 'config firewall profile-group':
                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_edit_group = parts[1]
                    profile_groups[current_edit_group] = set()
                    in_profile_group_edit = True
                else:
                    current_edit_group = None
                    in_profile_group_edit = False

            elif in_filters and in_ftgd_wf and in_profile:
                in_filter_edit = True
                current_edit_category = None
                current_edit_action = None

        else:
            if in_profile and in_web:
                if stripped_line.startswith('set blocklist enable'):
                    if current_profile_info is not None:
                        current_profile_info['blocklist_enable'] = True

            if in_profile and in_ftgd_wf and not in_filters:
                if stripped_line.startswith('set options error-allow'):
                    if current_profile_info is not None:
                        current_profile_info['options_error_allow'] = True

            if in_filters and in_filter_edit and in_ftgd_wf and in_profile:
                if stripped_line.startswith('set category '):
                    parts = stripped_line.split()
                    if len(parts) == 3:
                        try:
                            current_edit_category = int(parts[2])
                        except ValueError:
                            current_edit_category = None
                    else:
                        current_edit_category = None

                elif stripped_line.startswith('set action '):
                    parts = stripped_line.split()
                    if len(parts) >= 3:
                        current_edit_action = parts[2]
                    else:
                        current_edit_action = None

            if in_profile_group_edit and current_edit_group:
                if stripped_line.startswith('set webfilter-profile '):
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        webfilter_profile = parts[1]
                        profile_groups[current_edit_group].add(webfilter_profile)

            if stripped_line == 'next':
                if in_filter_edit and in_filters and in_ftgd_wf and in_profile:
                    if current_profile_info is not None:
                        if current_edit_category in categories_to_check:
                            if current_edit_action == 'block':
                                current_profile_info['categories_blocked'][current_edit_category] = True

                        # Nouvelle règle : pour la catégorie 207,
                        # il doit y avoir absence de "set action xxx"
                        if current_edit_category == 207 and current_edit_action is not None:
                            current_profile_info['category_207_has_action'] = True

                    in_filter_edit = False
                    current_edit_category = None
                    current_edit_action = None

    # Phase 2: Extraction des profils utilisés dans les politiques
    in_firewall_policy = False
    in_proxy_policy = False
    used_profiles = set()
    config_stack = []

    for line_number, line in enumerate(config_lines, 1):
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            config_stack.append(stripped_line)
            if stripped_line == 'config firewall policy':
                in_firewall_policy = True
            elif stripped_line == 'config firewall proxy-policy':
                in_proxy_policy = True

        elif stripped_line == 'end':
            if config_stack:
                popped = config_stack.pop()
                if popped == 'config firewall policy':
                    in_firewall_policy = False
                elif popped == 'config firewall proxy-policy':
                    in_proxy_policy = False

        else:
            if in_firewall_policy or in_proxy_policy:
                if 'set webfilter-profile ' in stripped_line:
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        profile_name = parts[1]
                        if profile_name in profiles:
                            used_profiles.add(profile_name)

                elif 'set profile-group ' in stripped_line:
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        group_name = parts[1]
                        if group_name in profile_groups:
                            used_profiles.update(profile_groups[group_name])

    # Phase 3: Vérification de la conformité des profils utilisés
    non_conforming_web_filter = {}

    for profile in used_profiles:
        issues = []
        profile_data = profiles.get(profile, {})

        if not profile_data.get('categories_blocked', {}).get(209, False):
            issues.append("URL_CTI_SNS non bloquées")

        if not profile_data.get('categories_blocked', {}).get(210, False):
            issues.append("URL_SNS SOC non bloquées")

        if profile_data.get('category_207_has_action', False):
            issues.append("la catégorie 207 n'est pas en monitor")

        if not profile_data.get('options_error_allow', False):
            issues.append("option manquante : autoriser les sites lorsqu'une erreur de notation se produit")

        if not profile_data.get('blocklist_enable', False):
            issues.append("scan URL FortiSandbox manquant")

        if issues:
            non_conforming_web_filter[profile] = issues

    conformity_web_filter = len(non_conforming_web_filter) == 0

    # Phase 4: Génération du résultat final
    result_web_filter = []

    if not licence_utm:
        result_web_filter.append("La licence UTM n'est pas valide")
        conformity_web_filter = False

        if non_conforming_web_filter:
            details = []
            for profile, issues in non_conforming_web_filter.items():
                issues_str = "; ".join(issues)
                details.append(f"{profile} ({issues_str})")

            if len(non_conforming_web_filter) == 1:
                result_web_filter.append(
                    "De plus, le profil de WebFilter suivant n'est pas conforme : " + " , ".join(details)
                )
            else:
                result_web_filter.append(
                    "De plus, les profils de WebFilter suivants ne sont pas conformes : " + ", ".join(details)
                )
    else:
        if len(used_profiles) == 0:
            result_web_filter.append("Aucun profil WebFilter n'est utilisé dans les règles")
            conformity_web_filter = False

        if non_conforming_web_filter:
            details = []
            for profile, issues in non_conforming_web_filter.items():
                issues_str = "; ".join(issues)
                details.append(f"{profile} ({issues_str})")

            if len(non_conforming_web_filter) == 1:
                result_web_filter.append(
                    "Le profil de WebFilter suivant n'est pas conforme : " + " , ".join(details)
                )
            else:
                result_web_filter.append(
                    "Les profils de WebFilter suivants ne sont pas conformes : " + " , ".join(details)
                )

    if conformity_web_filter:
        result_web_filter = "Tous les profils de filtrage web utilisés sont conformes."
    else:
        result_web_filter = " ".join(result_web_filter)

    return result_web_filter, conformity_web_filter, non_conforming_web_filter


def verifier_antivirus_profiles(config_lines, licence_utm):
    profiles = {}
    profile_groups_av = {}  # Dictionnaire pour mapper les groupes de profils Antivirus à leurs profils
    current_profile = None
    current_profile_info = None
    current_edit_group = None

    # Flags pour suivre le contexte
    in_av_profile = False
    in_profile_group = False
    in_profile_group_edit = False

    # Pile pour suivre la hiérarchie de configuration
    config_stack = []

    # Ensemble des 4 hachages obligatoires (si on n'a pas external-blocklist-enable-all enable)
    REQUIRED_HASHES = {
        "HASH_CTI_SNS_SHA1",
        "HASH_CTI_SNS_SHA256",
        "HASH_SNS_SHA1",
        "HASH_SNS_SHA256",
    }

    # === Étape 1 : Extraction des profils antivirus et des groupes de profils ===
    for line_number, line in enumerate(config_lines, 1):
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            config_stack.append(stripped_line)
            if stripped_line == 'config antivirus profile':
                in_av_profile = True
            elif stripped_line == 'config firewall profile-group':
                in_profile_group = True

        elif stripped_line == 'end':
            if config_stack:
                popped = config_stack.pop()
                if popped == 'config antivirus profile':
                    # Sauvegarder le dernier profil en cours si nécessaire
                    if current_profile and current_profile_info:
                        profiles[current_profile] = current_profile_info
                    current_profile = None
                    current_profile_info = None
                    in_av_profile = False

                elif popped == 'config firewall profile-group':
                    in_profile_group = False
                    in_profile_group_edit = False
                    current_edit_group = None

            # Réinitialiser les variables d'édition
            if in_profile_group_edit and popped.startswith('edit '):
                in_profile_group_edit = False
                current_edit_group = None

        elif stripped_line.startswith('edit '):
            if in_av_profile and config_stack and config_stack[-1] == 'config antivirus profile':
                # Sauvegarder le profil précédent s'il existe
                if current_profile and current_profile_info:
                    profiles[current_profile] = current_profile_info

                # Extraire le nom du profil
                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_profile = parts[1]

                    # Initialiser les informations du profil
                    current_profile_info = {
                        'external_blocklist_enable_all': False,
                        'external_blocklist_hashes': set(),  # <--- Pour stocker les hachages
                        'analytics_db_enable': False
                    }
                else:
                    current_profile = None
                    current_profile_info = None

            elif in_profile_group and config_stack and config_stack[-1] == 'config firewall profile-group':
                # Éditer un groupe de profils Antivirus
                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_edit_group = parts[1]
                    profile_groups_av[current_edit_group] = set()  # Init avec un ensemble vide
                    in_profile_group_edit = True
                else:
                    current_edit_group = None
                    in_profile_group_edit = False

        else:
            # === Gestion des commandes 'set' dans les profils antivirus ===
            if in_av_profile and config_stack and config_stack[-1] == 'config antivirus profile' and current_profile_info is not None:

                if stripped_line.startswith('set external-blocklist-enable-all '):
                    # Vérifie si 'enable' est dans la ligne
                    if 'enable' in stripped_line:
                        current_profile_info['external_blocklist_enable_all'] = True

                elif stripped_line.startswith('set external-blocklist '):
                    # On récupère tous les items dans les guillemets
                    # Exemple : set external-blocklist "HASH_CTI_SNS_SHA1" "IOC-MALWARE"
                    # On ne se soucie pas des hachages "en plus"
                    # => On veut juste s'assurer que les 4 requis sont présents
                    hash_items = re.findall(r'"([^"]+)"', stripped_line)
                    # Ajout dans le set
                    current_profile_info['external_blocklist_hashes'].update(hash_items)

                elif stripped_line.startswith('set analytics-db '):
                    if 'enable' in stripped_line:
                        current_profile_info['analytics_db_enable'] = True

            # === Gestion des commandes 'set' dans les groupes de profils Antivirus ===
            if in_profile_group_edit and current_edit_group:
                if stripped_line.startswith('set av-profile '):
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        av_profile = parts[1]
                        profile_groups_av[current_edit_group].add(av_profile)
                    else:
                        # Gérer les cas sans guillemets
                        av_profile = stripped_line.split()[-1]
                        profile_groups_av[current_edit_group].add(av_profile)

    # === Étape 2 : Extraction des profils utilisés dans les politiques ===
    in_firewall_policy = False
    in_proxy_policy = False
    used_profiles = set()
    used_profile_groups = set()

    for line_number, line in enumerate(config_lines, 1):
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            if stripped_line == 'config firewall policy':
                in_firewall_policy = True
            elif stripped_line == 'config firewall proxy-policy':
                in_proxy_policy = True

        elif stripped_line == 'end':
            if in_firewall_policy:
                in_firewall_policy = False
            if in_proxy_policy:
                in_proxy_policy = False

        else:
            if in_firewall_policy or in_proxy_policy:
                if 'set av-profile ' in stripped_line:
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        profile_name = parts[1]
                        if profile_name in profiles:
                            used_profiles.add(profile_name)
                elif 'set profile-group ' in stripped_line:
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        group_name = parts[1]
                        if group_name in profile_groups_av:
                            used_profile_groups.add(group_name)

    # Ajouter les profils Antivirus issus des groupes utilisés
    for group in used_profile_groups:
        used_profiles.update(profile_groups_av.get(group, set()))

    # === Étape 3 : Vérification de la conformité des profils utilisés ===
    non_conforming_av_profiles = {}
    for profile in used_profiles:
        issues = []
        profile_info = profiles.get(profile, {})

        # --- Contrôle external-blocklist ---
        external_blocklist_enable_all = profile_info.get('external_blocklist_enable_all', False)
        external_blocklist_hashes = profile_info.get('external_blocklist_hashes', set())

        # On est conforme s'il y a "external-blocklist-enable-all enable"
        # OU si les 4 hachages requis sont présents (peu importe les hachages supplémentaires)
        required_ok = REQUIRED_HASHES.issubset(external_blocklist_hashes)
        if not external_blocklist_enable_all and not required_ok:
            issues.append("External Blocklist (CTI) non bloquée")

        # --- Contrôle analytics-db (FortiSandbox) ---
        if not profile_info.get('analytics_db_enable', False):
            issues.append("FortiSandbox Database non activée")

        if issues:
            non_conforming_av_profiles[profile] = issues

    conformity_av_profiles = len(non_conforming_av_profiles) == 0
    result_av_profiles = []

    # === Étape 4 : Vérification de la licence UTM et génération du message ===
    if not licence_utm:
        result_av_profiles.append("La licence UTM n'est pas valide")
        conformity_av_profiles = False
        if non_conforming_av_profiles:
            details = []
            for profile, issues in non_conforming_av_profiles.items():
                issues_str = "; ".join(issues)
                details.append(f"{profile} ({issues_str})")

            if len(non_conforming_av_profiles) == 1:
                result_av_profiles.append(
                    "De plus, le profil Antivirus suivant n'est pas conforme : " + " ".join(details)
                )
            else:
                result_av_profiles.append(
                    "De plus, les profils Antivirus suivants ne sont pas conformes : " + " ".join(details)
                )
    else:
        if len(used_profiles) == 0:
            # Si la licence est valide mais aucun profil n'est utilisé
            result_av_profiles.append("Aucun profil Antivirus n'est utilisé dans les règles")
            conformity_av_profiles = False

        if non_conforming_av_profiles:
            details = []
            for profile, issues in non_conforming_av_profiles.items():
                issues_str = "; ".join(issues)
                details.append(f"{profile} ({issues_str})")
            if len(non_conforming_av_profiles) == 1:
                result_av_profiles.append(
                    "Le profil Antivirus suivant n'est pas conforme : " + " ".join(details)
                )
            else:
                result_av_profiles.append(
                    "Les profils Antivirus suivants ne sont pas conformes : " + " ".join(details)
                )

    # === Résultat final ===
    if conformity_av_profiles:
        result_av_profiles = "Tous les profils Antivirus utilisés sont conformes"
    else:
        result_av_profiles = "\n".join(result_av_profiles)

    return result_av_profiles, conformity_av_profiles, non_conforming_av_profiles



def verifier_ssl_ssh_profiles(config_lines):

    # Contrôle de version
    version_info, version_str, model = extraire_modele_version_fortigate(config_lines)
    version_tuple = parse_version(version_str) if version_str else (0, 0, 0)
    if not ((version_tuple[0] == 7 and version_tuple[1] == 2 and version_tuple[2] >= 11) or
            (version_tuple[0] == 7 and version_tuple[1] == 4 and version_tuple[2] >= 5)):
        return ("Contrôle des profils SSL/SSH non applicable pour la version du FortiOS", "N/A", {}, [])

    # Extraction des définitions des profils SSL/SSH
    ssl_profiles = {}
    in_ssl_block = False
    in_https_block = False
    current_profile = None
    current_profile_compliant = False
    config_stack = []

    # Parcours global de la config pour extraire / analyser les blocs ssl-ssh-profile
    for idx, line in enumerate(config_lines, 1):
        stripped = line.strip()

        # Début du bloc "config firewall ssl-ssh-profile"
        if stripped.startswith("config ") and stripped == "config firewall ssl-ssh-profile":
            config_stack.append(stripped)
            in_ssl_block = True
            continue

        # Gestion de la sortie de bloc via "end"
        if stripped == "end":
            if config_stack:
                popped = config_stack.pop()
                if popped == "config firewall ssl-ssh-profile":
                    # On quitte le bloc principal SSL/SSH
                    in_ssl_block = False
                    # Si un profil était en cours, on l'enregistre
                    if current_profile is not None:
                        ssl_profiles[current_profile] = {
                            "compliant": current_profile_compliant,
                            "reason": (
                                "" if current_profile_compliant
                                else "Ligne 'set cert-probe-failure allow' ou 'set sni-server-cert-check disable' absente dans le bloc https"
                            )
                        }
                    current_profile = None
                    current_profile_compliant = False

            # Si on était dans un bloc https, on en sort également
            if in_https_block:
                in_https_block = False
            continue

        # On ne traite que l'intérieur de "config firewall ssl-ssh-profile"
        if not in_ssl_block:
            continue

        # Sous-blocs
        if stripped.startswith("config "):
            config_stack.append(stripped)
            if stripped == "config https":
                in_https_block = True
            continue

        # Détection "edit <profil>"
        if stripped.startswith("edit "):
            # Clôturer le profil précédent le cas échéant
            if current_profile is not None:
                ssl_profiles[current_profile] = {
                    "compliant": current_profile_compliant,
                    "reason": (
                        "" if current_profile_compliant
                        else "Ligne 'set cert-probe-failure allow' ou 'set sni-server-cert-check disable' absente dans le bloc https"
                    )
                }

            parts = stripped.split('"')
            if len(parts) >= 2:
                current_profile = parts[1]
                current_profile_compliant = False
            else:
                current_profile = None
            continue

        # Analyse des lignes dans le bloc https
        if in_https_block and current_profile:
            tokens = stripped.split()
            cert_probe_found = ("set" in tokens and "cert-probe-failure" in tokens and "allow" in tokens)
            sni_check_found = ("set" in tokens and "sni-server-cert-check" in tokens and "disable" in tokens)
            if cert_probe_found or sni_check_found:
                current_profile_compliant = True
            continue

        # Fermeture du profil via "next"
        if stripped == "next":
            if current_profile is not None:
                ssl_profiles[current_profile] = {
                    "compliant": current_profile_compliant,
                    "reason": (
                        "" if current_profile_compliant
                        else "Ligne 'set cert-probe-failure allow' ou 'set sni-server-cert-check disable' absente dans le bloc https"
                    )
                }
            current_profile = None
            current_profile_compliant = False
            continue


    # Extraction des profils SSL/SSH utilisés dans les règles
    used_profiles = {}
    in_policy = False
    current_rule_id = None

    for idx, line in enumerate(config_lines, 1):
        stripped = line.strip()
        if stripped.startswith("config firewall policy"):
            in_policy = True
            continue
        elif in_policy and stripped == "end":
            in_policy = False
            continue

        if in_policy:
            if stripped.startswith("edit "):
                parts = stripped.split()
                if len(parts) >= 2:
                    current_rule_id = parts[1].strip('"')
            elif current_rule_id and "set ssl-ssh-profile" in stripped:
                parts = stripped.split('"')
                if len(parts) >= 2:
                    profile = parts[1]
                    used_profiles.setdefault(profile, []).append(current_rule_id)
            elif stripped == "next":
                current_rule_id = None


    # Vérification de conformité des profils utilisés
    non_conforming_profiles = {}
    rules_with_non_conforming = []

    for profile, rule_ids in used_profiles.items():
        if profile not in ssl_profiles:
            non_conforming_profiles[profile] = ["Profil non défini dans la configuration."]
            rules_with_non_conforming.extend(rule_ids)
        else:
            if not ssl_profiles[profile]["compliant"]:
                non_conforming_profiles[profile] = [ssl_profiles[profile]["reason"]]
                rules_with_non_conforming.extend(rule_ids)

    # Tri numérique des règles
    if non_conforming_profiles:
        details = [f"{p}: {', '.join(r)}" for p, r in non_conforming_profiles.items()]
        sorted_rules = sorted(set(rules_with_non_conforming), key=lambda x: int(x))
        result_message = (
            "Les profils SSL/SSH suivants ne sont pas conformes :\n"
            + "\n".join(details)
            + "\nUtilisés dans les règles : "
            + ", ".join(sorted_rules)
        )
        conformity = False
    else:
        result_message = "Tous les profils SSL/SSH utilisés sont conformes."
        conformity = True

    return result_message, conformity, non_conforming_profiles, sorted(set(rules_with_non_conforming), key=lambda x: int(x))




def verifier_dnsfilter_profiles(config_lines, licence_utm, model):
    def canonize(m):
        if not m:
            return ""
        s = str(m).upper().strip()
        s = re.sub(r'[^A-Z0-9]', '', s)  # retire espaces/traits/etc.
        s = re.sub(r'^(FORTIGATE|FGT|FG)', '', s)  # retire préfixes
        return s  # ex: "40F", "60E", ...

    cm = canonize(model)

    # Définition des blocklists en fonction du modèle
    if model in ["30E", "50E"]:
        external_ip_blocklist_criteria = {"IPV4_SNS"}
    elif model in ["60E", "80E", "40F"]:
        external_ip_blocklist_criteria = {"IPV4_CTI_SNS", "IPV4_SNS"}
    else:
        external_ip_blocklist_criteria = {"IPV4_CTI_SNS", "IPV4_CTI_SNS2", "IPV4_CTI_SNS3", "IPV4_SNS"}

    profiles = {}
    profile_groups_dns = {}  # Mapping des groupes de profils DNS Filter vers leurs profils
    current_profile = None
    current_profile_info = None
    current_edit_group = None

    # Flags pour suivre le contexte
    in_dnsfilter_profile = False
    in_ftgd_dns = False
    in_filters = False
    in_profile_group = False
    in_profile_group_edit = False

    # Pile pour suivre la hiérarchie de configuration
    config_stack = []

    # Variable pour suivre la catégorie en cours (pour le bloc 'filters')
    current_category = None
    categories_to_check = {211, 212}

    # Pré-compilation des expressions régulières
    re_error_allow = re.compile(r'^set\s+options\s+error-allow\b', re.IGNORECASE)
    re_category    = re.compile(r'^set\s+category\s+(\d+)\b', re.IGNORECASE)
    re_ext_ip      = re.compile(r'^set\s+external-ip-blocklist\s+(.*)', re.IGNORECASE)

    # Phase 1 : Extraction des profils DNS Filter et des groupes
    for line in config_lines:
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            config_stack.append(stripped_line)
            if stripped_line == 'config dnsfilter profile':
                in_dnsfilter_profile = True
            elif stripped_line == 'config firewall profile-group':
                in_profile_group = True
            elif stripped_line == 'config ftgd-dns' and in_dnsfilter_profile and current_profile:
                in_ftgd_dns = True
            elif stripped_line == 'config filters' and in_ftgd_dns:
                in_filters = True

        elif stripped_line == 'end':
            if config_stack:
                popped = config_stack.pop()
                if popped == 'config dnsfilter profile':
                    if current_profile and current_profile_info:
                        profiles[current_profile] = current_profile_info
                    current_profile = None
                    current_profile_info = None
                    in_dnsfilter_profile = False
                    in_ftgd_dns = False
                    in_filters = False
                elif popped == 'config firewall profile-group':
                    in_profile_group = False
                    in_profile_group_edit = False
                    current_edit_group = None
                elif popped == 'config ftgd-dns':
                    in_ftgd_dns = False
                elif popped == 'config filters':
                    in_filters = False

        elif stripped_line.startswith('edit '):
            if config_stack and config_stack[-1] == 'config dnsfilter profile':
                if current_profile and current_profile_info:
                    profiles[current_profile] = current_profile_info
                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_profile = parts[1]
                    current_profile_info = {
                        'external-ip-blocklist_found': set(),
                        'options_error_allow': False,
                        'categories_blocked': {211: False, 212: False}
                    }
                else:
                    current_profile = None
                    current_profile_info = None
            else:
                # Ignorer la commande 'edit' dans les sous-blocs (exemple : config filters)
                pass

        else:
            if in_dnsfilter_profile and current_profile_info is not None:
                match_ext = re_ext_ip.search(stripped_line)
                if match_ext:
                    tokens = match_ext.group(1).split()
                    blocklists = {t.strip('"') for t in tokens}
                    current_profile_info['external-ip-blocklist_found'] = current_profile_info.get('external-ip-blocklist_found', set())
                    current_profile_info['external-ip-blocklist_found'].update(blocklists)

                if in_ftgd_dns:
                    if re_error_allow.search(stripped_line):
                        current_profile_info['options_error_allow'] = True
                    if in_filters:
                        match_cat = re_category.search(stripped_line)
                        if match_cat:
                            current_category = int(match_cat.group(1))
                        elif stripped_line.startswith('set action block'):
                            if current_category in categories_to_check:
                                current_profile_info['categories_blocked'][current_category] = True

            if in_profile_group_edit and current_edit_group:
                if stripped_line.startswith('set dnsfilter-profile '):
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        dns_profile = parts[1]
                        profile_groups_dns[current_edit_group].add(dns_profile)
                    else:
                        dns_profile = stripped_line.split()[-1]
                        profile_groups_dns[current_edit_group].add(dns_profile)

    # Phase 2 : Extraction des profils utilisés dans les politiques
    in_firewall_policy = False
    in_proxy_policy = False
    used_profiles = set()
    used_profile_groups = set()

    for line in config_lines:
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            if stripped_line == 'config firewall policy':
                in_firewall_policy = True
            elif stripped_line == 'config firewall proxy-policy':
                in_proxy_policy = True
        elif stripped_line == 'end':
            if in_firewall_policy:
                in_firewall_policy = False
            if in_proxy_policy:
                in_proxy_policy = False
        else:
            if in_firewall_policy or in_proxy_policy:
                if 'set dnsfilter-profile ' in stripped_line:
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        profile_name = parts[1]
                        if profile_name in profiles:
                            used_profiles.add(profile_name)
                elif 'set profile-group ' in stripped_line:
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        group_name = parts[1]
                        if group_name in profile_groups_dns:
                            used_profile_groups.add(group_name)

    for group in used_profile_groups:
        used_profiles.update(profile_groups_dns.get(group, set()))

    # Phase 3 : Vérification de la conformité des profils utilisés
    non_conforming_dns_filter = {}
    for profile in used_profiles:
        issues = []
        found_blocklists = profiles.get(profile, {}).get('external-ip-blocklist_found', set())
        missing_blocklists = external_ip_blocklist_criteria - found_blocklists

        if not profiles.get(profile, {}).get('categories_blocked', {}).get(212, False):
            issues.append("FQDN CTI non bloqués")
        if not profiles.get(profile, {}).get('categories_blocked', {}).get(211, False):
            issues.append("FQDN SNS SOC non bloqués")
        if missing_blocklists:
            issues.append(f"blocklists externes manquantes : {', '.join(sorted(missing_blocklists))}")
        if not profiles.get(profile, {}).get('options_error_allow', False):
            issues.append("option manquante : autoriser les requêtes DNS lorsqu'une erreur de notation se produit")

        if issues:
            non_conforming_dns_filter[profile] = issues

    conformity_dns_filter = len(non_conforming_dns_filter) == 0
    result_dns_filter = []

    # Phase 4 : Vérification de la licence UTM et génération du message
    if not licence_utm:
        result_dns_filter.append("La licence UTM n'est pas valide")
        conformity_dns_filter = False
        if non_conforming_dns_filter:
            details = [f"{p} ({'; '.join(i)})" for p, i in non_conforming_dns_filter.items()]
            if len(non_conforming_dns_filter) == 1:
                result_dns_filter.append("De plus, le profil de DNS Filter suivant n'est pas conforme : " + "".join(details))
            else:
                result_dns_filter.append("De plus, les profils de DNS Filter suivants ne sont pas conformes : " + "".join(details))
    else:
        if len(used_profiles) == 0:
            result_dns_filter.append("Aucun profil DNS Filter n'est utilisé dans les règles")
            conformity_dns_filter = False

        if non_conforming_dns_filter:
            details = [f"{p} ({'; '.join(i)})" for p, i in non_conforming_dns_filter.items()]
            if len(non_conforming_dns_filter) == 1:
                result_dns_filter.append("Le profil DNS Filter suivant n'est pas conforme : " + " ".join(details))
            else:
                result_dns_filter.append("Les profils DNS Filter suivants ne sont pas conformes : " + "".join(details))

    if conformity_dns_filter:
        result_dns_filter = "Tous les profils DNS Filter utilisés sont conformes"
    else:
        result_dns_filter = "\n".join(result_dns_filter)

    return result_dns_filter, conformity_dns_filter, non_conforming_dns_filter



def verifier_ips_profiles(config_lines, licence_utm):
    profiles = {}
    profile_groups_ips = {}  # Dictionnaire pour mapper les groupes de profils IPS à leurs profils
    current_profile = None
    current_profile_info = {}
    current_edit_group = None

    # Flags pour suivre le contexte
    in_ips_profile = False
    in_entries = False
    in_profile_group = False
    in_profile_group_edit = False

    # Pile pour suivre la hiérarchie de configuration
    config_stack = []

    # Phase 1: Extraction des profils IPS et des groupes de profils
    for line in config_lines:
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            config_stack.append(stripped_line)
            if stripped_line == 'config ips sensor':
                in_ips_profile = True
            elif stripped_line == 'config firewall profile-group':
                in_profile_group = True
        elif stripped_line == 'end':
            if config_stack:
                popped = config_stack.pop()
                if popped == 'config ips sensor':
                    if current_profile and current_profile_info:
                        profiles[current_profile] = current_profile_info
                    current_profile = None
                    current_profile_info = {}
                    in_ips_profile = False
                elif popped == 'config firewall profile-group':
                    in_profile_group = False
                    in_profile_group_edit = False
                    current_edit_group = None
                elif popped == 'config entries' and in_entries:
                    in_entries = False
            # Réinitialiser les variables d'édition
            if in_profile_group_edit and popped.startswith('edit '):
                in_profile_group_edit = False
                current_edit_group = None
        elif stripped_line.startswith('edit '):
            if in_ips_profile and config_stack and config_stack[-1] == 'config ips sensor':
                # Sauvegarder le profil précédent s'il existe
                if current_profile and current_profile_info:
                    profiles[current_profile] = current_profile_info
                # Extraire le nom du profil
                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_profile = parts[1]
                    # Initialiser les informations du profil
                    current_profile_info = {
                        'block_malicious_url_enable': False,
                        'scan_botnet_connections_block': False
                    }
                else:
                    current_profile = None
                    current_profile_info = {}
            elif in_profile_group and config_stack and config_stack[-1] == 'config firewall profile-group':
                # Éditer un groupe de profils IPS
                parts = stripped_line.split('"')
                if len(parts) > 1:
                    current_edit_group = parts[1]
                else:
                    current_edit_group = stripped_line.split()[-1]
                profile_groups_ips[current_edit_group] = set()
                in_profile_group_edit = True
        else:
            # Gestion des commandes 'set' dans les profils IPS
            if in_ips_profile and config_stack and config_stack[-1] == 'config ips sensor' and current_profile_info is not None:
                if stripped_line.startswith('config entries'):
                    in_entries = True
                elif in_entries:
                    # Vous pouvez gérer les entrées ici si nécessaire
                    pass
                else:
                    # Gestion des commandes 'set' en dehors de 'config entries'
                    if stripped_line.startswith('set block-malicious-url'):
                        if 'enable' in stripped_line:
                            current_profile_info['block_malicious_url_enable'] = True
                    elif stripped_line.startswith('set scan-botnet-connections'):
                        if 'block' in stripped_line:
                            current_profile_info['scan_botnet_connections_block'] = True

            # Gestion des commandes 'set' dans les groupes de profils IPS
            if in_profile_group_edit and current_edit_group:
                if stripped_line.startswith('set ips-sensor '):
                    parts = stripped_line.split('"')
                    if len(parts) > 1:
                        ips_profile = parts[1]
                    else:
                        ips_profile = stripped_line.split()[-1]
                    profile_groups_ips[current_edit_group].add(ips_profile)

    # Phase 2: Extraction des profils utilisés dans les politiques
    in_firewall_policy = False
    in_proxy_policy = False
    used_profiles = set()
    used_profile_groups = set()

    for line in config_lines:
        stripped_line = line.strip()

        if stripped_line.startswith('config '):
            if stripped_line == 'config firewall policy':
                in_firewall_policy = True
            elif stripped_line == 'config firewall proxy-policy':
                in_proxy_policy = True
        elif stripped_line == 'end':
            if in_firewall_policy:
                in_firewall_policy = False
            if in_proxy_policy:
                in_proxy_policy = False
        else:
            if in_firewall_policy or in_proxy_policy:
                if 'set ips-sensor ' in stripped_line:
                    if '"' in stripped_line:
                        profile_name = stripped_line.split('"')[1]
                    else:
                        profile_name = stripped_line.split()[-1]
                    if profile_name in profiles:
                        used_profiles.add(profile_name)
                elif 'set profile-group ' in stripped_line:
                    if '"' in stripped_line:
                        group_name = stripped_line.split('"')[1]
                    else:
                        group_name = stripped_line.split()[-1]
                    if group_name in profile_groups_ips:
                        used_profile_groups.add(group_name)

    # Ajouter les profils IPS issus des groupes utilisés
    for group in used_profile_groups:
        used_profiles.update(profile_groups_ips.get(group, set()))

    # Phase 3: Vérification de la conformité des profils utilisés
    non_conforming_ips_profiles = {}
    for profile in used_profiles:
        issues = []
        profile_info = profiles.get(profile, {})
        if not profile_info.get('block_malicious_url_enable', False):
            issues.append("option manquante : block-malicious-url enable")
        if not profile_info.get('scan_botnet_connections_block', False):
            issues.append("option manquante : scan-botnet-connections block")
        if issues:
            non_conforming_ips_profiles[profile] = issues

    conformity_ips_profiles = len(non_conforming_ips_profiles) == 0
    result_ips_profiles = []

    # Phase 4: Vérification de la licence UTM et génération du message
    if not licence_utm:
        result_ips_profiles.append("La licence UTM n'est pas valide")
        conformity_ips_profiles = False
        if non_conforming_ips_profiles:
            details = [f"{p} ({'; '.join(i)})" for p, i in non_conforming_ips_profiles.items()]
            if len(non_conforming_ips_profiles) == 1:
                result_ips_profiles.append(
                    "De plus, le profil IPS suivant n'est pas conforme : " + " ".join(details))
            else:
                result_ips_profiles.append(
                    "De plus, les profils IPS suivants ne sont pas conformes : " + " ".join(details))
    else:
        if len(used_profiles) == 0:
            result_ips_profiles.append("Aucun profil IPS utilisé dans les règles")
            conformity_ips_profiles = False

        if non_conforming_ips_profiles:
            details = [f"{p} ({'; '.join(i)})" for p, i in non_conforming_ips_profiles.items()]
            if len(non_conforming_ips_profiles) == 1:
                result_ips_profiles.append(
                    "Le profil IPS suivant n'est pas conforme : " + " ".join(details))
            else:
                result_ips_profiles.append(
                    "Les profils IPS suivants ne sont pas conformes : " + " ".join(details))

    # Génération du résultat final
    if conformity_ips_profiles:
        result_ips_profiles = "Tous les profils IPS utilisés sont conformes"
    else:
        result_ips_profiles = "\n".join(result_ips_profiles)

    return result_ips_profiles, conformity_ips_profiles, non_conforming_ips_profiles


def verifier_app_control_profiles(config_lines, licence_utm):
    """
    Vérifie la présence des catégories 2 (P2P), 6 (Proxy) et 7 (Remote Access)
    dans les profils d'App Control (application list) réellement utilisés
    dans les règles (ou via des profile-group).

    Retourne:
       result_app_control (str): Message global sur la conformité.
       conformity_app_control (bool): True si tous les profils utilisés sont conformes.
       non_conforming_app_control (dict): Détail des profils non conformes { profil_name: [liste_raisons] }
    """

    # Pour l'affichage lisible des noms de catégories
    category2label = {
        2: "P2P",
        6: "Proxy",
        7: "Remote Access"
    }

    # Les catégories obligatoires pour la conformité
    required_categories = {2, 6, 7}  # P2P, Proxy, Remote Access

    # --- Phase 1: Extraction des App Control profiles ---
    app_profiles = {}
    in_app_list = False
    current_app_profile = None
    in_edit_app_profile = False

    in_config_entries = False
    in_entry_edit = False
    temp_categories = set()
    temp_action = None

    config_stack = []

    for line in config_lines:
        stripped = line.strip()

        if stripped.startswith("config "):
            config_stack.append(stripped)
            if stripped == "config application list":
                in_app_list = True

            elif stripped == "config entries" and in_app_list and in_edit_app_profile:
                in_config_entries = True

        elif stripped == "end":
            if config_stack:
                popped = config_stack.pop()
                if popped == "config application list":
                    in_app_list = False
                    current_app_profile = None
                    in_edit_app_profile = False

                elif popped == "config entries":
                    in_config_entries = False
                    in_entry_edit = False

        elif stripped.startswith("edit "):
            # On est dans config application list
            if in_app_list and config_stack and config_stack[-1] == "config application list":
                parts = stripped.split('"')
                if len(parts) > 1:
                    profile_name = parts[1]
                    current_app_profile = profile_name
                    in_edit_app_profile = True
                    if current_app_profile not in app_profiles:
                        app_profiles[current_app_profile] = {
                            "blocked_categories": set(),
                            "has_any_category_line": False
                        }

            elif in_config_entries and in_edit_app_profile:
                in_entry_edit = True
                temp_categories = set()
                temp_action = None

        else:
            # Traitement des "set" à l'intérieur d'une entry
            if in_app_list and in_edit_app_profile and in_config_entries and in_entry_edit:
                if stripped.startswith("set category "):
                    parts = stripped.split()
                    for cat_str in parts[2:]:
                        try:
                            cat_val = int(cat_str)
                            temp_categories.add(cat_val)
                        except ValueError:
                            pass
                    app_profiles[current_app_profile]["has_any_category_line"] = True

                elif stripped.startswith("set action "):
                    parts = stripped.split()
                    if len(parts) >= 3:
                        temp_action = parts[2]

                elif stripped == "next":
                    # Fin d'un edit <x>
                    if temp_categories:
                        if temp_action == "pass":
                            # On ne bloque pas ces catégories
                            pass
                        else:
                            # Par défaut ou set action block => bloquées
                            app_profiles[current_app_profile]["blocked_categories"].update(temp_categories)

                    in_entry_edit = False
                    temp_categories = set()
                    temp_action = None

    # --- Phase 2: Extraction des profile-groups et association "application-list" ---
    profile_groups_app = {}
    in_profile_group = False
    in_profile_group_edit = False
    current_profile_group = None

    config_stack = []
    for line in config_lines:
        stripped = line.strip()

        if stripped.startswith("config "):
            config_stack.append(stripped)
            if stripped == "config firewall profile-group":
                in_profile_group = True

        elif stripped == "end":
            if config_stack:
                popped = config_stack.pop()
                if popped == "config firewall profile-group":
                    in_profile_group = False
                    in_profile_group_edit = False
                    current_profile_group = None

        elif stripped.startswith("edit "):
            if in_profile_group and config_stack and config_stack[-1] == "config firewall profile-group":
                parts = stripped.split('"')
                if len(parts) > 1:
                    group_name = parts[1]
                    current_profile_group = group_name
                    in_profile_group_edit = True
                    profile_groups_app[current_profile_group] = set()

        else:
            if in_profile_group_edit and current_profile_group:
                if stripped.startswith("set application-list "):
                    parts = stripped.split('"')
                    if len(parts) > 1:
                        app_control_profile = parts[1]
                        profile_groups_app[current_profile_group].add(app_control_profile)

    # --- Phase 3: Recherche des profils d'app control utilisés dans les règles ---
    used_app_profiles = set()
    in_firewall_policy = False
    config_stack = []

    for line in config_lines:
        stripped = line.strip()

        if stripped.startswith("config "):
            config_stack.append(stripped)
            if stripped == "config firewall policy":
                in_firewall_policy = True

        elif stripped == "end":
            if config_stack:
                popped = config_stack.pop()
                if popped == "config firewall policy":
                    in_firewall_policy = False

        else:
            if in_firewall_policy:
                if "set application-list " in stripped:
                    parts = stripped.split('"')
                    if len(parts) > 1:
                        app_control_profile = parts[1]
                        used_app_profiles.add(app_control_profile)

                elif "set profile-group " in stripped:
                    parts = stripped.split('"')
                    if len(parts) > 1:
                        group_name = parts[1]
                        if group_name in profile_groups_app:
                            used_app_profiles.update(profile_groups_app[group_name])

    # --- Phase 4: Vérification de la conformité des profils utilisés ---
    non_conforming_app_control = {}
    for profile_name in used_app_profiles:
        reasons = []
        profile_data = app_profiles.get(profile_name)

        if not profile_data:
            reasons.append("Le profil n'existe pas ou n'a pas été défini.")
        else:
            if not profile_data["has_any_category_line"]:
                reasons.append("(aucune catégorie n'est bloquée.)")
            else:
                blocked_cats = profile_data["blocked_categories"]
                missing = required_categories - blocked_cats
                if missing:
                    # Remplace les numéros par leurs noms
                    missing_names = [category2label[m] for m in sorted(missing)]
                    reasons.append("(catégories non bloquées : " + ", ".join(missing_names)+")")

        if reasons:
            non_conforming_app_control[profile_name] = reasons

        # --- Phase 5: Construction du message final ---
    conformity_app_control = len(non_conforming_app_control) == 0
    result_app_control_lines = []

    # pour un ordre stable (optionnel)
    def format_entries(d):
        # d: dict {profil: [reasons]}
        entries = []
        for prof, reasons in sorted(d.items(), key=lambda x: x[0].lower()):
            entries.append(f"{prof} {', '.join(reasons)}")
        return entries

    if not licence_utm:
        result_app_control_lines.append("La licence UTM n'est pas valide pour App Control.")
        conformity_app_control = False
        if non_conforming_app_control:
            entries = format_entries(non_conforming_app_control)
            result_app_control_lines.append(
                "De plus, les profils suivants ne sont pas conformes : " + ", ".join(entries)
            )
    else:
        if not used_app_profiles:
            result_app_control_lines.append("Aucun profil App Control n'est utilisé dans les règles.")
            conformity_app_control = False
        else:
            if non_conforming_app_control:
                entries = format_entries(non_conforming_app_control)
                if len(entries) == 1:
                    result_app_control_lines.append(
                        "Le profil App Control suivant n'est pas conforme : " + entries[0]
                    )
                else:
                    result_app_control_lines.append(
                        "Les profils App Control suivants ne sont pas conformes : " + ", ".join(entries)
                    )
            else:
                result_app_control_lines.append("Tous les profils App Control utilisés sont conformes.")

    result_app_control = " ".join(result_app_control_lines)
    return result_app_control, conformity_app_control, non_conforming_app_control



# Fonction pour vérifier si le port HTTPS pour accéder à la console admin a été changé
def verifier_port_https_admin(config_lines):
    https_port = 443  # Port par défaut
    for line in config_lines:
        line = line.strip()
        if line.startswith("set admin-sport"):
            https_port = int(line.split()[2])
            break

    # Vérification du port
    if https_port == 443:
        return "Le port HTTPS pour accéder à l'interface admin du FortiGate est le 443, c'est le port par défaut", False
    else:
        return f"Le port HTTPS pour accéder à l'interface admin du FortiGate a été personnalisé avec le port suivant : {https_port}", True


def check_obsolete_fortiap_devices(config_lines):
    """
    Vérifie s'il y a des bornes FortiAP bientôt obsolètes (modèles B et C).
    Seules les vraies bornes dans le bloc 'config wireless-controller wtp' sont analysées.
    """

    def extract_fortiap_model(device_id):
        """
        Extrait correctement le modèle FortiAP à partir de l'ID.
        Gère les cas particuliers pour la gamme B :
          - FAP22B... => 220B
          - FAP2223X... => 222B
          - FAP14C => 14C (classique)
        """
        if not device_id.startswith("FAP"):
            return None

        rest = device_id[3:]

        # Cas particulier : FAP22B... => modèle 220B
        m = re.match(r"^(\d{2})B", rest)
        if m:
            return f"{m.group(1)}0B"   # Exemple : 22 -> 220B

        # Cas FAP2223X... => modèle 222B
        m = re.match(r"^(\d{3})B", rest)
        if m:
            return f"{m.group(1)}B"    # Exemple : 222 -> 222B

        # Cas classiques : FAP14C, FAP224E...
        m = re.match(r"(\d{2,3}[A-Z])", rest)
        if m:
            return m.group(1)

        return None

    profiles = []
    obsolete_devices = []
    obsolete_models = []
    in_wtp_block = False
    current_device_id = None
    block_depth = 0

    for line in config_lines:
        stripped_line = line.strip()

        # Début du bloc WTP
        if stripped_line == "config wireless-controller wtp":
            in_wtp_block = True
            block_depth = 1
            continue

        if not in_wtp_block:
            continue

        # Gestion profondeur sous-blocs
        if stripped_line.startswith("config "):
            block_depth += 1
            continue

        if stripped_line == "end":
            block_depth -= 1
            if block_depth == 0:
                in_wtp_block = False
                current_device_id = None
            continue

        if stripped_line == "next":
            current_device_id = None
            continue

        # Identification appareil
        if stripped_line.startswith('edit') and block_depth == 1 and '"' in stripped_line:
            try:
                current_device_id = stripped_line.split('"')[1]

                # Récupération du modèle
                if current_device_id.startswith("FAP"):
                    model_match = extract_fortiap_model(current_device_id)
                elif current_device_id.startswith("FP"):
                    model_match = current_device_id[2:6]
                else:
                    model_match = None

                # Vérifier modèles obsolètes: B ou C
                if model_match and model_match.endswith(('B', 'C')):
                    obsolete_devices.append({
                        'device_id': current_device_id,
                        'model': model_match,
                        'name': None
                    })
                    if model_match not in obsolete_models:
                        obsolete_models.append(model_match)
            except IndexError:
                continue

        # Nom de l'appareil
        elif stripped_line.startswith('set name "') and current_device_id and block_depth == 1:
            try:
                device_name = stripped_line.split('"')[1]
                for device in obsolete_devices:
                    if device['device_id'] == current_device_id:
                        device['name'] = device_name
                        break
            except IndexError:
                continue

        # Récupération du wtp-profile
        elif stripped_line.startswith("set wtp-profile") and block_depth == 1:
            try:
                profile_name = stripped_line.split('"')[1]
                if profile_name not in profiles:
                    profiles.append(profile_name)
            except IndexError:
                continue

    # Génération du résultat
    if not profiles:
        result = "N/A car absence de borne WIFI FortiAP configurée"
        conform = True
        obsolete_models = []
    elif obsolete_devices:
        device_details = []
        for device in obsolete_devices:
            name_info = f" ({device['name']})" if device['name'] else ""
            device_details.append(f"- {device['device_id']}{name_info} - Modèle {device['model']}")
        result = "Bornes FortiAP obsolètes détectées : " + " ".join(device_details)
        conform = False
    else:
        result = "Aucun modèle de borne FortiAP bientôt obsolète détecté"
        conform = True
        obsolete_models = []

    return result, conform, obsolete_models


def verifier_nombre_ssid_par_profil_wifi(config_lines):
    profiles_utilises = []
    ssid_counts = {}
    in_wtp_block = False
    in_wtp_profile_block = False
    in_radio_block = False
    current_profile = None
    current_radio = None
    block_level = 0  # Pour suivre le niveau d'imbrication des blocs

    # Étape 1 : Identifier les profils WiFi AP dans config wireless-controller wtp
    for line in config_lines:
        stripped_line = line.strip()
        if "config wireless-controller wtp" in stripped_line:
            in_wtp_block = True
        elif in_wtp_block and "end" == stripped_line:
            in_wtp_block = False
        elif in_wtp_block and "set wtp-profile" in stripped_line:
            profile_name = stripped_line.split('"')[1]
            profiles_utilises.append(profile_name)
        elif "config router rip" in stripped_line:
            break

    if not profiles_utilises:
        return "N/A car absence de borne WIFI FortiAP configurée", True, [], profiles_utilises

    # Étape 2 : Récupérer les SSID pour chaque profil dans config wireless-controller wtp-profile
    for line in config_lines:
        stripped_line = line.strip()
        if "config wireless-controller wtp-profile" in stripped_line:
            in_wtp_profile_block = True
            block_level = 0  # Réinitialiser le niveau d'imbrication pour ce bloc
            continue
        elif in_wtp_profile_block:
            if "config " in stripped_line:
                block_level += 1
            elif "end" == stripped_line:
                block_level -= 1
                if block_level < 0:
                    in_wtp_profile_block = False
                    current_profile = None
                    current_radio = None
                    continue
            if "edit " in stripped_line:
                profile_name = stripped_line.split('"')[1]
                if profile_name in profiles_utilises:
                    current_profile = profile_name
                    ssid_counts[current_profile] = {}
                else:
                    current_profile = None
            elif "next" in stripped_line:
                current_profile = None
                current_radio = None
            elif "config radio-" in stripped_line and current_profile:
                in_radio_block = True
                current_radio = stripped_line.split(" ")[1]
                ssid_counts[current_profile][current_radio] = 0  # Initialiser le compteur de SSID pour cette radio
            elif in_radio_block and "end" == stripped_line:
                in_radio_block = False
                current_radio = None
            elif in_radio_block and "set vaps" in stripped_line and current_profile:
                ssids = stripped_line.split('"')[1::2]
                ssid_counts[current_profile][current_radio] = len(ssids)

    # Étape 3 : Évaluer le nombre de SSID par radio pour la conformité
    non_conforming_profiles = []
    for profile, radios in ssid_counts.items():
        for radio, ssid_count in radios.items():
            if ssid_count >= 5:
                non_conforming_profiles.append((profile, radio, ssid_count))

    # Étape 4 : Générer le résultat et le drapeau de conformité
    if non_conforming_profiles:
        # Convertir les tuples en chaînes de caractères pour l'affichage
        non_conforming_profiles_str = ', '.join([f"{p} ({r}: {c} SSID)" for p, r, c in non_conforming_profiles])
        return f"Profils WIFI non conformes : {non_conforming_profiles_str}", False, non_conforming_profiles, profiles_utilises
    else:
        return "Tous les profils WIFI sont conformes", True, [], profiles_utilises



def verifier_utilisation_bande_5ghz(config_lines):
    profiles = []
    non_compliant_profiles = []
    in_wtp_block = False
    in_wtp_profile_block = False
    in_radio2_block = False
    current_profile = None
    block_level = 0  # Pour suivre le niveau d'imbrication des blocs

    # Étape 1 : Identifier les profils WiFi AP dans config wireless-controller wtp
    for line in config_lines:
        stripped_line = line.strip()
        if "config wireless-controller wtp" in stripped_line:
            in_wtp_block = True
        elif in_wtp_block and "end" == stripped_line:
            in_wtp_block = False
        elif in_wtp_block and "set wtp-profile" in stripped_line:
            profile_name = stripped_line.split('"')[1]
            profiles.append(profile_name)
        elif "config router rip" in stripped_line:
            break

    if not profiles:
        return "N/A car absence de borne WIFI FortiAP configurée", True, []

    # Étape 2 : Vérifier l'utilisation de la bande 5 GHz pour chaque profil
    for line in config_lines:
        stripped_line = line.strip()
        if "config wireless-controller wtp-profile" in stripped_line:
            in_wtp_profile_block = True
            block_level = 0
            continue
        elif in_wtp_profile_block:
            if "config " in stripped_line:
                block_level += 1
            elif "end" == stripped_line:
                block_level -= 1
                if block_level < 0:
                    in_wtp_profile_block = False
                    current_profile = None
                    in_radio2_block = False
                    continue
            if "edit " in stripped_line:
                profile_name = stripped_line.split('"')[1]
                if profile_name in profiles:
                    current_profile = profile_name
                    radio2_mode_disabled = False
                    channel_bonding_40mhz = False
                    in_radio2_block = False
                    reasons = []  # Liste des raisons de non-conformité pour ce profil
                else:
                    current_profile = None
            elif "next" in stripped_line:
                if current_profile:
                    if radio2_mode_disabled:
                        # Si la radio 2 est désactivée, on ajoute le profil aux non-conformes
                        non_compliant_profiles.append({
                            'profile': current_profile,
                            'reasons': reasons
                        })
                    else:
                        if not channel_bonding_40mhz:
                            # Si la radio 2 est activée mais que le channel bonding n'est pas configuré
                            reasons.append("Channel bonding n'est pas configuré sur 40MHz")
                            non_compliant_profiles.append({
                                'profile': current_profile,
                                'reasons': reasons
                            })
                    # Réinitialiser les variables pour le prochain profil
                    current_profile = None
                    in_radio2_block = False
            elif "config radio-2" in stripped_line and current_profile:
                in_radio2_block = True
                radio2_mode_disabled = False
                channel_bonding_40mhz = False
            elif in_radio2_block and "end" == stripped_line:
                in_radio2_block = False
            elif in_radio2_block and current_profile:
                if "set mode disabled" in stripped_line:
                    radio2_mode_disabled = True
                    if "Radio 2 est désactivée" not in reasons:
                        reasons.append("Radio 2 est désactivée")
                if "set channel-bonding 40MHz" in stripped_line:
                    channel_bonding_40mhz = True

    # Vérifier le dernier profil s'il n'y a pas de "next" à la fin
    if current_profile:
        if radio2_mode_disabled:
            non_compliant_profiles.append({
                'profile': current_profile,
                'reasons': reasons
            })
        else:
            if not channel_bonding_40mhz:
                reasons.append("Channel bonding n'est pas configuré sur 40MHz")
                non_compliant_profiles.append({
                    'profile': current_profile,
                    'reasons': reasons
                })

    # Générer le résultat détaillé
    if non_compliant_profiles:
        messages = []
        for item in non_compliant_profiles:
            profile_name = item['profile']
            reasons = item['reasons']
            # Éliminer les doublons dans reasons au cas où
            reasons = list(set(reasons))
            reason_str = ', '.join(reasons)
            messages.append(f"{profile_name} : {reason_str}")
        result_message = "Profils WIFI non conformes : " + ' '.join(messages)
        return (
            result_message,
            False,
            non_compliant_profiles
        )
    else:
        return "Tous les profils sont conformes", True, []


def verifier_darrp_enable(config_lines):
    """
    Vérifie si l'option 'darrp' est activée pour chaque radio (radio-1 et radio-2) dans chaque profil WiFi AP.

    Parameters:
        config_lines (list of str): Liste des lignes de configuration.

    Returns:
        tuple:
            - str: Message indiquant les profils non conformes ou la conformité générale.
            - bool: Statut de conformité (True si conforme, False sinon).
            - dict: Dictionnaire des profils non conformes avec les radios problématiques.
    """
    # Initialisation des variables
    profiles_utilises = set()  # Ensemble pour stocker les profils utilisés
    non_conforming_profiles = {}  # Dictionnaire pour collecter les radios non conformes par profil
    darrp_enabled = {}  # Dictionnaire pour stocker l'état de darrp pour chaque profil et radio
    radio_disabled = {}  # Dictionnaire pour stocker l'état de désactivation des radios

    # Expressions régulières pour une meilleure robustesse
    config_wtp_regex = re.compile(r'^config\s+wireless-controller\s+wtp\s*$', re.IGNORECASE)
    set_wtp_profile_regex = re.compile(r'^set\s+wtp-profile\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_wtp_profile_regex = re.compile(r'^config\s+wireless-controller\s+wtp-profile\s*$', re.IGNORECASE)
    edit_regex = re.compile(r'^edit\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_radio_regex = re.compile(r'^config\s+radio-(\d+)\s*$', re.IGNORECASE)
    set_darrp_enable_regex = re.compile(r'^set\s+darrp\s+enable\s*$', re.IGNORECASE)
    set_mode_disabled_regex = re.compile(r'^set\s+mode\s+disabled\s*$', re.IGNORECASE)
    end_regex = re.compile(r'^end\s*$', re.IGNORECASE)
    next_regex = re.compile(r'^next\s*$', re.IGNORECASE)

    # Étape 1 : Identifier les profils utilisés dans 'config wireless-controller wtp' via 'set wtp-profile'
    in_wtp_block = False
    block_level_wtp = 0
    for line in config_lines:
        stripped_line = line.strip()

        # Détection du début du bloc 'config wireless-controller wtp'
        if config_wtp_regex.match(stripped_line):
            in_wtp_block = True
            block_level_wtp = 1
            continue

        if in_wtp_block:
            # Détection du début d'un sous-bloc 'config'
            if stripped_line.lower().startswith("config "):
                block_level_wtp += 1
                continue

            # Détection de la fin d'un bloc
            if end_regex.match(stripped_line):
                block_level_wtp -= 1
                if block_level_wtp == 0:
                    in_wtp_block = False
                continue

            # Détection des lignes 'set wtp-profile "NomDuProfil"'
            match = set_wtp_profile_regex.match(stripped_line)
            if match:
                profile_name = match.group(1)
                profiles_utilises.add(profile_name)
                continue

    if not profiles_utilises:
        return "N/A car absence de borne WIFI FortiAP configurée", True, {}

    # Étape 2 : Analyser les paramètres des profils utilisés dans 'config wireless-controller wtp-profile'
    in_wtp_profile_block = False
    block_level_profile = 0
    current_profile = None
    current_radio = None
    in_radio_block = False
    for line in config_lines:
        stripped_line = line.strip()

        # Détection du début du bloc 'config wireless-controller wtp-profile'
        if config_wtp_profile_regex.match(stripped_line):
            in_wtp_profile_block = True
            block_level_profile = 1
            continue

        if in_wtp_profile_block:
            # Détection du début d'un sous-bloc 'config'
            if stripped_line.lower().startswith("config "):
                block_level_profile += 1
                # Vérifier si c'est une radio
                radio_match = config_radio_regex.match(stripped_line)
                if radio_match and current_profile:
                    radio_number = radio_match.group(1)
                    current_radio = f"radio-{radio_number}"
                    if radio_number not in ['1', '2']:
                        current_radio = None
                        in_radio_block = False
                    else:
                        in_radio_block = True
                        darrp_enabled[current_profile][current_radio] = False  # Par défaut, darrp non activé
                        radio_disabled[current_profile][current_radio] = False  # Par défaut, radio activée
                continue

            # Détection de la fin d'un bloc
            if end_regex.match(stripped_line):
                block_level_profile -= 1
                if in_radio_block and current_radio:
                    # Fin de la configuration de la radio
                    in_radio_block = False
                    current_radio = None
                if block_level_profile == 0:
                    in_wtp_profile_block = False
                    current_profile = None
                    current_radio = None
                elif block_level_profile < 0:
                    # Correction si block_level_profile devient négatif
                    block_level_profile = 0
                    in_wtp_profile_block = False
                    current_profile = None
                    current_radio = None
                    in_radio_block = False
                continue

            # Détection des lignes 'edit "NomDuProfil"'
            match = edit_regex.match(stripped_line)
            if match:
                profile_name = match.group(1)
                if profile_name in profiles_utilises:
                    current_profile = profile_name
                    darrp_enabled[current_profile] = {}
                    radio_disabled[current_profile] = {}
                else:
                    current_profile = None
                continue

            # Détection de 'next' indiquant la fin de la définition du profil
            if next_regex.match(stripped_line):
                current_profile = None
                current_radio = None
                in_radio_block = False
                continue

            # Gestion des radios au sein d'un profil
            if current_profile and in_radio_block and current_radio:
                if set_darrp_enable_regex.match(stripped_line):
                    darrp_enabled[current_profile][current_radio] = True
                if set_mode_disabled_regex.match(stripped_line):
                    radio_disabled[current_profile][current_radio] = True

    # Étape 3 : Vérifier les profils non conformes
    for profile in profiles_utilises:
        non_conform_radios = []
        for radio in ['radio-1', 'radio-2']:  # Ignorer radio-3
            # Vérifier si la radio est désactivée
            if radio_disabled.get(profile, {}).get(radio, False):
                continue  # Ignorer les radios désactivées

            # Vérifier si la radio est configurée avec 'set darrp enable'
            if radio in darrp_enabled.get(profile, {}):
                if not darrp_enabled[profile][radio]:
                    non_conform_radios.append(radio)
            else:
                # Si la radio n'est pas configurée, on la considère comme non conforme
                non_conform_radios.append(radio)

        if non_conform_radios:
            non_conforming_profiles[profile] = non_conform_radios

    # Générer le résultat
    if non_conforming_profiles:
        messages = []
        for profile, radios in non_conforming_profiles.items():
            if len(radios) == 1:
                radios_str = radios[0]
            elif len(radios) == 2:
                radios_str = ' et '.join(radios)
            else:
                radios_str = ', '.join(radios[:-1]) + f", et {radios[-1]}"
            messages.append(f"{profile} ({radios_str}) : Option 'darrp' non activée")
        result_message = "Profils non conformes :\n" + '\n'.join(messages)
        return result_message, False, non_conforming_profiles
    else:
        return "Tous les profils WIFI sont conformes", True, {}

def verifier_tim_enable(config_lines):
    """
    Vérifie si l'option 'powersave-optimize tim' est activée pour chaque radio (radio-1 et radio-2) dans chaque profil WiFi AP.

    Parameters:
        config_lines (list of str): Liste des lignes de configuration.

    Returns:
        tuple:
            - str: Message indiquant les profils non conformes ou la conformité générale.
            - bool: Statut de conformité (True si conforme, False sinon).
            - dict: Dictionnaire des profils non conformes avec les radios problématiques.
    """
    # Initialisation des variables
    profiles_utilises = set()  # Ensemble pour stocker les profils utilisés
    non_conforming_profiles = {}  # Dictionnaire pour collecter les radios non conformes par profil
    tim_enabled = {}  # Dictionnaire pour stocker l'état de TIM pour chaque profil et radio
    radio_disabled = {}  # Dictionnaire pour stocker l'état de désactivation des radios

    # Expressions régulières pour une meilleure robustesse
    config_wtp_regex = re.compile(r'^config\s+wireless-controller\s+wtp\s*$', re.IGNORECASE)
    set_wtp_profile_regex = re.compile(r'^set\s+wtp-profile\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_wtp_profile_regex = re.compile(r'^config\s+wireless-controller\s+wtp-profile\s*$', re.IGNORECASE)
    edit_regex = re.compile(r'^edit\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_radio_regex = re.compile(r'^config\s+radio-(\d+)\s*$', re.IGNORECASE)
    set_tim_enable_regex = re.compile(r'^set\s+powersave-optimize\s+tim\s*$', re.IGNORECASE)
    set_mode_disabled_regex = re.compile(r'^set\s+mode\s+disabled\s*$', re.IGNORECASE)
    end_regex = re.compile(r'^end\s*$', re.IGNORECASE)
    next_regex = re.compile(r'^next\s*$', re.IGNORECASE)

    # Étape 1 : Identifier les profils utilisés dans 'config wireless-controller wtp' via 'set wtp-profile'
    in_wtp_block = False
    block_level_wtp = 0
    for line in config_lines:
        stripped_line = line.strip()

        # Détection du début du bloc 'config wireless-controller wtp'
        if config_wtp_regex.match(stripped_line):
            in_wtp_block = True
            block_level_wtp = 1
            continue

        if in_wtp_block:
            # Détection du début d'un sous-bloc 'config'
            if stripped_line.lower().startswith("config "):
                block_level_wtp += 1
                continue

            # Détection de la fin d'un bloc
            if end_regex.match(stripped_line):
                block_level_wtp -= 1
                if block_level_wtp == 0:
                    in_wtp_block = False
                continue

            # Détection des lignes 'set wtp-profile "NomDuProfil"'
            match = set_wtp_profile_regex.match(stripped_line)
            if match:
                profile_name = match.group(1)
                profiles_utilises.add(profile_name)
                continue

    if not profiles_utilises:
        return "N/A car absence de borne WIFI FortiAP configurée", True, {}

    # Étape 2 : Analyser les paramètres des profils utilisés dans 'config wireless-controller wtp-profile'
    in_wtp_profile_block = False
    block_level_profile = 0
    current_profile = None
    current_radio = None
    in_radio_block = False
    for line in config_lines:
        stripped_line = line.strip()

        # Détection du début du bloc 'config wireless-controller wtp-profile'
        if config_wtp_profile_regex.match(stripped_line):
            in_wtp_profile_block = True
            block_level_profile = 1
            continue

        if in_wtp_profile_block:
            # Détection du début d'un sous-bloc 'config'
            if stripped_line.lower().startswith("config "):
                block_level_profile += 1
                # Vérifier si c'est une radio
                radio_match = config_radio_regex.match(stripped_line)
                if radio_match and current_profile:
                    radio_number = radio_match.group(1)
                    current_radio = f"radio-{radio_number}"
                    if radio_number not in ['1', '2']:
                        current_radio = None
                        in_radio_block = False
                    else:
                        in_radio_block = True
                        tim_enabled[current_profile][current_radio] = False  # Par défaut, TIM non activé
                        radio_disabled[current_profile][current_radio] = False  # Par défaut, radio activée
                continue

            # Détection de la fin d'un bloc
            if end_regex.match(stripped_line):
                block_level_profile -= 1
                if in_radio_block and current_radio:
                    # Fin de la configuration de la radio
                    in_radio_block = False
                    current_radio = None
                if block_level_profile == 0:
                    in_wtp_profile_block = False
                    current_profile = None
                    current_radio = None
                elif block_level_profile < 0:
                    # Correction si block_level_profile devient négatif
                    block_level_profile = 0
                    in_wtp_profile_block = False
                    current_profile = None
                    current_radio = None
                    in_radio_block = False
                continue

            # Détection des lignes 'edit "NomDuProfil"'
            match = edit_regex.match(stripped_line)
            if match:
                profile_name = match.group(1)
                if profile_name in profiles_utilises:
                    current_profile = profile_name
                    tim_enabled[current_profile] = {}
                    radio_disabled[current_profile] = {}
                else:
                    current_profile = None
                continue

            # Détection de 'next' indiquant la fin de la définition du profil
            if next_regex.match(stripped_line):
                current_profile = None
                current_radio = None
                in_radio_block = False
                continue

            # Gestion des radios au sein d'un profil
            if current_profile and in_radio_block and current_radio:
                if set_tim_enable_regex.match(stripped_line):
                    tim_enabled[current_profile][current_radio] = True
                if set_mode_disabled_regex.match(stripped_line):
                    radio_disabled[current_profile][current_radio] = True

    # Étape 3 : Vérifier les profils non conformes
    for profile in profiles_utilises:
        non_conform_radios = []
        for radio in ['radio-1', 'radio-2']:  # Ignorer radio-3
            # Vérifier si la radio est désactivée
            if radio_disabled.get(profile, {}).get(radio, False):
                continue  # Ignorer les radios désactivées

            # Vérifier si la radio est configurée avec 'set powersave-optimize tim'
            if radio in tim_enabled.get(profile, {}):
                if not tim_enabled[profile][radio]:
                    non_conform_radios.append(radio)
            else:
                # Si la radio n'est pas configurée, on la considère comme non conforme
                non_conform_radios.append(radio)

        if non_conform_radios:
            non_conforming_profiles[profile] = non_conform_radios

    # Générer le résultat
    if non_conforming_profiles:
        messages = []
        for profile, radios in non_conforming_profiles.items():
            if len(radios) == 1:
                radios_str = radios[0]
            elif len(radios) == 2:
                radios_str = ' et '.join(radios)
            else:
                radios_str = ', '.join(radios[:-1]) + f", et {radios[-1]}"
            messages.append(f"{profile} ({radios_str}) : Option 'TIM' non activée")
        result_message = "Profils non conformes : " + ''.join(messages)
        return result_message, False, non_conforming_profiles
    else:
        return "Tous les profils WIFI sont conformes.", True, {}

def verifier_frequency_handoff(config_lines):
    used_profiles = set()  # Ensemble pour stocker les profils utilisés
    profiles_settings = {}  # Dictionnaire pour stocker les paramètres des profils utilisés
    in_wtp_block = False
    block_level_wtp = 0  # Niveau d'imbrication pour 'config wireless-controller wtp'
    in_wtp_profile_block = False
    current_profile = None
    in_radio_block = False
    current_radio = None
    block_level_profile = 0  # Niveau d'imbrication pour 'config wireless-controller wtp-profile'

    # Expressions régulières pour détecter les blocs et les paramètres
    config_wtp_regex = re.compile(r'^config\s+wireless-controller\s+wtp$')
    config_wtp_profile_regex = re.compile(r'^config\s+wireless-controller\s+wtp-profile$')
    edit_regex = re.compile(r'^edit\s+"([^"]+)"$')
    set_wtp_profile_regex = re.compile(r'^set\s+wtp-profile\s+"([^"]+)"$')
    set_freq_handoff_regex = re.compile(r'^set\s+frequency-handoff\s+enable$')
    set_radio_mode_disabled_regex = re.compile(r'^set\s+mode\s+disabled$')
    set_radio_mode_enable_regex = re.compile(r'^set\s+mode\s+enable$')
    config_radio_regex = re.compile(r'^config\s+radio-(\d+)$')
    next_regex = re.compile(r'^next$')
    end_regex = re.compile(r'^end$')

    # Étape 1 : Identifier les profils utilisés dans 'config wireless-controller wtp'
    for line_num, line in enumerate(config_lines, 1):
        stripped_line = line.strip()

        # Détection du début du bloc 'config wireless-controller wtp'
        if config_wtp_regex.match(stripped_line):
            in_wtp_block = True
            block_level_wtp = 1
            continue

        if in_wtp_block:
            # Détection du début d'un sous-bloc 'edit' ou 'config radio-X'
            if stripped_line.startswith("edit ") or stripped_line.startswith("config "):
                block_level_wtp += 1
                edit_match = edit_regex.match(stripped_line)
                config_radio_match = config_radio_regex.match(stripped_line)
                if edit_match:
                    profile_name = edit_match.group(1)
                    # 'set wtp-profile' sera détecté plus tard
                elif config_radio_match:
                    # Sous-blocs radio, pas de traitement particulier ici
                    pass
                continue

            # Détection de la fin d'un bloc
            if end_regex.match(stripped_line):
                block_level_wtp -= 1
                if block_level_wtp == 0:
                    in_wtp_block = False
                continue

            # Détection des lignes 'set wtp-profile "NomDuProfil"'
            match = set_wtp_profile_regex.match(stripped_line)
            if match:
                profile_name = match.group(1)
                used_profiles.add(profile_name)
                continue

    if not used_profiles:
        return "N/A car absence de borne WIFI FortiAP configurée", True, []

    # Étape 2 : Analyser les paramètres des profils utilisés dans 'config wireless-controller wtp-profile'
    for line_num, line in enumerate(config_lines, 1):
        stripped_line = line.strip()

        # Détection du début du bloc 'config wireless-controller wtp-profile'
        if config_wtp_profile_regex.match(stripped_line):
            in_wtp_profile_block = True
            block_level_profile = 1
            continue

        if in_wtp_profile_block:
            # Détection du début d'un sous-bloc 'edit' ou 'config radio-X'
            if stripped_line.startswith("edit ") or stripped_line.startswith("config "):
                block_level_profile += 1
                edit_match = edit_regex.match(stripped_line)
                config_radio_match = config_radio_regex.match(stripped_line)
                if edit_match:
                    profile_name = edit_match.group(1)
                    if profile_name in used_profiles:
                        current_profile = profile_name
                        profiles_settings[current_profile] = {
                            'frequency-handoff': False,
                            'radio-1': 'enabled'  # Par défaut, radio-1 est activée
                        }
                    else:
                        current_profile = None
                elif config_radio_match:
                    radio_number = config_radio_match.group(1)
                    if current_profile:
                        current_radio = f"radio-{radio_number}"
                        in_radio_block = True
                continue

            # Détection de la fin d'un bloc
            if end_regex.match(stripped_line):
                if in_radio_block:
                    in_radio_block = False
                    current_radio = None
                block_level_profile -= 1
                if block_level_profile == 0:
                    in_wtp_profile_block = False
                    current_profile = None
                continue

            # Détection de 'next' indiquant la fin de la définition du profil
            if next_regex.match(stripped_line):
                current_profile = None
                continue

            # Traitement des paramètres du profil courant
            if current_profile:
                if in_radio_block and current_radio == "radio-1":
                    if set_radio_mode_disabled_regex.match(stripped_line):
                        profiles_settings[current_profile]['radio-1'] = 'disabled'
                    elif set_radio_mode_enable_regex.match(stripped_line):
                        profiles_settings[current_profile]['radio-1'] = 'enabled'
                else:
                    if set_freq_handoff_regex.match(stripped_line):
                        profiles_settings[current_profile]['frequency-handoff'] = True
                    # Vous pouvez ajouter ici d'autres paramètres à surveiller si nécessaire

    # Étape 3 : Vérifier les profils non conformes
    non_conforming_profiles = {}
    for profile, settings in profiles_settings.items():
        frequency_handoff = settings['frequency-handoff']
        radio1_state = settings['radio-1']
        if radio1_state == 'enabled' and not frequency_handoff:
            non_conforming_profiles[profile] = "Option 'Frequency Handoff' non activée"

    # Générer le résultat
    if non_conforming_profiles:
        messages = [f"{profile} : {message}" for profile, message in non_conforming_profiles.items()]
        result_message = "Profils WIFI non conformes : " + ' '.join(messages)
        return result_message, False, non_conforming_profiles
    else:
        return "Tous les profils WIFI sont conformes", True, []


def verifier_band_conformite(config_lines):
    """
    Vérifie si les 'bands' configurés pour chaque radio-1 et radio-2 sont conformes :
    - ✅ Autorisés : 802.11n-only, 802.11ac-only, 802.11ac,n-only, 802.11ax-only, 802.11ax,n-only
    - ❌ Interdits : toute présence de b,g,a ou un band trop permissif (ex: '802.11ax' sans '-only')

    Parameters:
        config_lines (list of str): Liste des lignes de configuration FortiGate.

    Returns:
        tuple:
            - str: Message indiquant les profils non conformes ou la conformité générale.
            - bool: Statut global de conformité.
            - dict: Dictionnaire des profils non conformes avec les radios problématiques et leur band.
    """

    # Étape 0 : Regex utilisés
    config_wtp_regex = re.compile(r'^config\s+wireless-controller\s+wtp\s*$', re.IGNORECASE)
    set_wtp_profile_regex = re.compile(r'^set\s+wtp-profile\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_wtp_profile_regex = re.compile(r'^config\s+wireless-controller\s+wtp-profile\s*$', re.IGNORECASE)
    edit_regex = re.compile(r'^edit\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_radio_regex = re.compile(r'^config\s+radio-(\d+)\s*$', re.IGNORECASE)
    set_band_regex = re.compile(r'^set\s+band\s+(.+?)\s*$', re.IGNORECASE)
    set_mode_disabled_regex = re.compile(r'^set\s+mode\s+disabled\s*$', re.IGNORECASE)
    end_regex = re.compile(r'^end\s*$', re.IGNORECASE)
    next_regex = re.compile(r'^next\s*$', re.IGNORECASE)

    # Autorisation
    allowed_bands = {
        "802.11n-only",
        "802.11ac-only",
        "802.11ac,n-only",
        "802.11ax-only",
        "802.11ax,n-only"
    }

    # Étape 1 : Identifier les profils utilisés
    profiles_utilises = set()
    in_wtp_block = False
    block_level_wtp = 0
    for line in config_lines:
        stripped = line.strip()

        if config_wtp_regex.match(stripped):
            in_wtp_block = True
            block_level_wtp = 1
            continue

        if in_wtp_block:
            if stripped.lower().startswith("config "):
                block_level_wtp += 1
                continue

            if end_regex.match(stripped):
                block_level_wtp -= 1
                if block_level_wtp == 0:
                    in_wtp_block = False
                continue

            match = set_wtp_profile_regex.match(stripped)
            if match:
                profiles_utilises.add(match.group(1))

    if not profiles_utilises:
        return "N/A car absence de borne WIFI FortiAP configurée", True, {}

    # Étape 2 : Scanner la config des profils utilisés
    bands_config = {}
    radio_disabled = {}
    in_wtp_profile_block = False
    block_level_profile = 0
    current_profile = None
    current_radio = None
    in_radio_block = False

    for line in config_lines:
        stripped = line.strip()

        if config_wtp_profile_regex.match(stripped):
            in_wtp_profile_block = True
            block_level_profile = 1
            continue

        if in_wtp_profile_block:
            # Début sous-bloc
            if stripped.lower().startswith("config "):
                block_level_profile += 1
                radio_match = config_radio_regex.match(stripped)
                if radio_match and current_profile:
                    radio_number = radio_match.group(1)
                    if radio_number in ["1", "2"]:
                        current_radio = f"radio-{radio_number}"
                        in_radio_block = True
                        bands_config[current_profile][current_radio] = None
                        radio_disabled[current_profile][current_radio] = False
                continue

            # Fin d'un bloc
            if end_regex.match(stripped):
                block_level_profile -= 1
                if in_radio_block and current_radio:
                    in_radio_block = False
                    current_radio = None
                if block_level_profile == 0:
                    in_wtp_profile_block = False
                    current_profile = None
                continue

            # edit "profil"
            match = edit_regex.match(stripped)
            if match:
                prof = match.group(1)
                if prof in profiles_utilises:
                    current_profile = prof
                    bands_config[current_profile] = {}
                    radio_disabled[current_profile] = {}
                else:
                    current_profile = None
                continue

            # next
            if next_regex.match(stripped):
                current_profile = None
                current_radio = None
                in_radio_block = False
                continue

            # Gestion des radios
            if current_profile and in_radio_block and current_radio:
                # set band
                m_band = set_band_regex.match(stripped)
                if m_band:
                    bands_config[current_profile][current_radio] = m_band.group(1).strip()

                # radio désactivée
                if set_mode_disabled_regex.match(stripped):
                    radio_disabled[current_profile][current_radio] = True

    # Étape 3 : Vérification conformité
    non_conforming_profiles = {}
    for profile in profiles_utilises:
        non_conform_radios = {}
        for radio in ["radio-1", "radio-2"]:
            if radio_disabled.get(profile, {}).get(radio, False):
                continue
            band = bands_config.get(profile, {}).get(radio)
            if band is None:
                # Non défini => non conforme
                non_conform_radios[radio] = "non défini"
            elif band not in allowed_bands:
                non_conform_radios[radio] = band
        if non_conform_radios:
            non_conforming_profiles[profile] = non_conform_radios

    # Génération résultat
    if non_conforming_profiles:
        messages = []
        for profile, radios in non_conforming_profiles.items():
            radios_str = ', '.join([f"{r} ({b})" for r,b in radios.items()])
            messages.append(f"{profile} : {radios_str} ")
        return "Profils non conformes : " + " ".join(messages), False, non_conforming_profiles
    else:
        return "Tous les profils WIFI sont conformes.", True, {}


def verifier_channels_conformite(config_lines):
    """
    Vérifie la conformité des channels configurés dans les radios des profils WTP.

    - ✅ conforme si 'set channel "1" "6" "11"' uniquement (radio-1 seulement)
    - ❌ non conforme si canaux différents, plus nombreux, ou absence
    - radio-2 : ignorée (on ne force pas les channels dessus)

    Parameters:
        config_lines (list[str]): Lignes de configuration

    Returns:
        tuple:
            - str: message lisible
            - bool: statut global conformité
            - dict: profils non conformes avec radios et channels trouvés
    """

    # Définition des regex
    config_wtp_regex = re.compile(r'^config\s+wireless-controller\s+wtp\s*$', re.IGNORECASE)
    set_wtp_profile_regex = re.compile(r'^set\s+wtp-profile\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_wtp_profile_regex = re.compile(r'^config\s+wireless-controller\s+wtp-profile\s*$', re.IGNORECASE)
    edit_regex = re.compile(r'^edit\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_radio_regex = re.compile(r'^config\s+radio-(\d+)\s*$', re.IGNORECASE)
    set_channel_regex = re.compile(r'^set\s+channel\s+(.+)$', re.IGNORECASE)
    set_mode_disabled_regex = re.compile(r'^set\s+mode\s+disabled\s*$', re.IGNORECASE)
    end_regex = re.compile(r'^end\s*$', re.IGNORECASE)
    next_regex = re.compile(r'^next\s*$', re.IGNORECASE)

    allowed_channels = {"1", "6", "11"}

    # Étape 1 : récupérer profils utilisés dans config wireless-controller wtp
    profiles_utilises = set()
    in_wtp_block = False
    block_level_wtp = 0

    for line in config_lines:
        stripped = line.strip()
        if config_wtp_regex.match(stripped):
            in_wtp_block = True
            block_level_wtp = 1
            continue

        if in_wtp_block:
            if stripped.lower().startswith("config "):
                block_level_wtp += 1
                continue

            if end_regex.match(stripped):
                block_level_wtp -= 1
                if block_level_wtp == 0:
                    in_wtp_block = False
                continue

            m = set_wtp_profile_regex.match(stripped)
            if m:
                profiles_utilises.add(m.group(1))

    if not profiles_utilises:
        return "N/A car absence de borne WIFI FortiAP configurée", True, {}

    # Étape 2 : analyser les profils utilisés dans config wireless-controller wtp-profile
    channels_config = {}
    radio_disabled = {}
    in_wtp_profile_block = False
    block_level_profile = 0
    current_profile = None
    current_radio = None
    in_radio_block = False

    for line in config_lines:
        stripped = line.strip()

        if config_wtp_profile_regex.match(stripped):
            in_wtp_profile_block = True
            block_level_profile = 1
            continue

        if in_wtp_profile_block:
            if stripped.lower().startswith("config "):
                block_level_profile += 1
                radio_match = config_radio_regex.match(stripped)
                if radio_match and current_profile:
                    radio_num = radio_match.group(1)
                    # Contrôle uniquement pour radio-1
                    if radio_num == "1":
                        current_radio = "radio-1"
                        in_radio_block = True
                        channels_config.setdefault(current_profile, {})[current_radio] = None
                        radio_disabled.setdefault(current_profile, {})[current_radio] = False
                continue

            if end_regex.match(stripped):
                block_level_profile -= 1
                if in_radio_block and current_radio:
                    in_radio_block = False
                    current_radio = None
                if block_level_profile == 0:
                    in_wtp_profile_block = False
                    current_profile = None
                continue

            m = edit_regex.match(stripped)
            if m:
                prof = m.group(1)
                if prof in profiles_utilises:
                    current_profile = prof
                    channels_config.setdefault(current_profile, {})
                    radio_disabled.setdefault(current_profile, {})
                else:
                    current_profile = None
                continue

            if next_regex.match(stripped):
                current_profile = None
                current_radio = None
                in_radio_block = False
                continue

            if current_profile and in_radio_block and current_radio:
                m_channel = set_channel_regex.match(stripped)
                if m_channel:
                    raw_channels = m_channel.group(1).replace('"', '').split()
                    channels_config[current_profile][current_radio] = raw_channels

                if set_mode_disabled_regex.match(stripped):
                    radio_disabled[current_profile][current_radio] = True

    # Étape 3 : vérifier conformité uniquement sur radio-1
    non_conforming_profiles = {}
    for profile in profiles_utilises:
        non_conform_radios = {}
        if not radio_disabled.get(profile, {}).get("radio-1", False):
            chans = channels_config.get(profile, {}).get("radio-1")
            if chans is None:
                non_conform_radios["radio-1"] = "non défini"
            else:
                chans_set = set(chans)
                if not (chans_set == allowed_channels and len(chans) == 3):
                    non_conform_radios["radio-1"] = chans

        if non_conform_radios:
            non_conforming_profiles[profile] = non_conform_radios

    # Générer le résultat
    if non_conforming_profiles:
        messages = []
        for profile, radios in non_conforming_profiles.items():
            radios_str = ', '.join([f"{r} ({c})" for r, c in radios.items()])
            messages.append(f"{profile} : {radios_str} non conformes")
        return "Profils non conformes :\n" + "\n".join(messages), False, non_conforming_profiles
    else:
        return "Tous les profils WIFI sont conformes pour les channels (1,6,11)", True, {}

def verifier_short_guard_interval(config_lines):
    """
    Vérifie si l'option 'short-guard-interval' est activée pour radio-1 et radio-2 dans chaque profil WTP.

    Parameters:
        config_lines (list of str): lignes de config FortiGate.

    Returns:
        tuple:
            - str: message descriptif
            - bool: True si tous conformes, False sinon
            - dict: profils non conformes avec radios sans option activée
    """

    # Regex
    config_wtp_regex = re.compile(r'^config\s+wireless-controller\s+wtp\s*$', re.IGNORECASE)
    set_wtp_profile_regex = re.compile(r'^set\s+wtp-profile\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_wtp_profile_regex = re.compile(r'^config\s+wireless-controller\s+wtp-profile\s*$', re.IGNORECASE)
    edit_regex = re.compile(r'^edit\s+"([^"]+)"\s*$', re.IGNORECASE)
    config_radio_regex = re.compile(r'^config\s+radio-(\d+)\s*$', re.IGNORECASE)
    set_sgi_enable_regex = re.compile(r'^set\s+short-guard-interval\s+enable\s*$', re.IGNORECASE)
    set_mode_disabled_regex = re.compile(r'^set\s+mode\s+disabled\s*$', re.IGNORECASE)
    end_regex = re.compile(r'^end\s*$', re.IGNORECASE)
    next_regex = re.compile(r'^next\s*$', re.IGNORECASE)

    # Étape 1 : profils utilisés
    profiles_utilises = set()
    in_wtp_block = False
    block_level_wtp = 0
    for line in config_lines:
        stripped = line.strip()
        if config_wtp_regex.match(stripped):
            in_wtp_block = True
            block_level_wtp = 1
            continue
        if in_wtp_block:
            if stripped.lower().startswith("config "):
                block_level_wtp += 1
                continue
            if end_regex.match(stripped):
                block_level_wtp -= 1
                if block_level_wtp == 0:
                    in_wtp_block = False
                continue
            m = set_wtp_profile_regex.match(stripped)
            if m:
                profiles_utilises.add(m.group(1))

    if not profiles_utilises:
        return "N/A car absence de borne WIFI FortiAP configurée", True, {}

    # Étape 2 : analyse profils
    sgi_enabled = {}
    radio_disabled = {}
    in_wtp_profile_block = False
    block_level_profile = 0
    current_profile = None
    current_radio = None
    in_radio_block = False

    for line in config_lines:
        stripped = line.strip()

        if config_wtp_profile_regex.match(stripped):
            in_wtp_profile_block = True
            block_level_profile = 1
            continue

        if in_wtp_profile_block:
            if stripped.lower().startswith("config "):
                block_level_profile += 1
                radio_match = config_radio_regex.match(stripped)
                if radio_match and current_profile:
                    radio_num = radio_match.group(1)
                    if radio_num in ["1", "2"]:
                        current_radio = f"radio-{radio_num}"
                        in_radio_block = True
                        sgi_enabled.setdefault(current_profile, {})[current_radio] = False
                        radio_disabled.setdefault(current_profile, {})[current_radio] = False
                continue

            if end_regex.match(stripped):
                block_level_profile -= 1
                if in_radio_block and current_radio:
                    in_radio_block = False
                    current_radio = None
                if block_level_profile == 0:
                    in_wtp_profile_block = False
                    current_profile = None
                continue

            m = edit_regex.match(stripped)
            if m:
                prof = m.group(1)
                if prof in profiles_utilises:
                    current_profile = prof
                else:
                    current_profile = None
                continue

            if next_regex.match(stripped):
                current_profile = None
                current_radio = None
                in_radio_block = False
                continue

            if current_profile and in_radio_block and current_radio:
                if set_sgi_enable_regex.match(stripped):
                    sgi_enabled[current_profile][current_radio] = True
                if set_mode_disabled_regex.match(stripped):
                    radio_disabled[current_profile][current_radio] = True

    # Étape 3 : vérification conformité
    non_conforming_profiles = {}
    for profile in profiles_utilises:
        non_conform_radios = []
        for radio in ["radio-1", "radio-2"]:
            if radio_disabled.get(profile, {}).get(radio, False):
                continue
            if not sgi_enabled.get(profile, {}).get(radio, False):
                non_conform_radios.append(radio)
        if non_conform_radios:
            non_conforming_profiles[profile] = non_conform_radios

    if non_conforming_profiles:
        messages = []
        for profile, radios in non_conforming_profiles.items():
            radios_str = ' et '.join(radios) if len(radios) == 2 else radios[0]
            messages.append(f"{profile} ({radios_str}) : Option 'short-guard-interval' non activée")
        return "Profils non conformes : " + " ".join(messages), False, non_conforming_profiles
    else:
        return "Tous les profils WIFI sont conformes.", True, {}


def compter_regles_activ_ou_desactiv(config_lines):
    """
    Analyse la config FortiGate pour compter les règles activées ou désactivées
    dans la section 'config firewall policy'.
     """

    in_firewall_policy = False
    in_current_rule = False
    rules = []  # Cette liste contiendra chaque règle comme un bloc de lignes
    current_rule_lines = []

    for line in config_lines:
        # Début de la section config firewall policy
        if line.strip().startswith("config firewall policy"):
            in_firewall_policy = True
            continue

        # Fin de la section config firewall policy
        if in_firewall_policy and line.strip().startswith("end"):
            # On ferme la dernière règle en cours (si elle existe)
            if current_rule_lines:
                rules.append(current_rule_lines)
            in_firewall_policy = False
            break

        # Si on est dans la bonne section, on collecte les lignes
        if in_firewall_policy:
            if line.strip().startswith("edit "):
                # Si on avait déjà une règle en cours, on la stocke
                if current_rule_lines:
                    rules.append(current_rule_lines)
                # On commence une nouvelle règle
                current_rule_lines = []
                in_current_rule = True
            elif line.strip().startswith("next"):
                # Fin de la règle en cours
                if in_current_rule:
                    rules.append(current_rule_lines)
                    current_rule_lines = []
                    in_current_rule = False
            else:
                # On est dans une règle
                if in_current_rule:
                    current_rule_lines.append(line.strip())

    # Maintenant qu'on a la liste de toutes les règles,
    # on compte le nombre de règles activées et désactivées.
    nb_disabled = 0
    nb_enabled = 1

    for rule in rules:
        # 'rule' est une liste de lignes de configuration
        # Si on trouve 'set status disable', la règle est désactivée
        if any("set status disable" in line for line in rule):
            nb_disabled += 1
        else:
            nb_enabled += 1

    return nb_enabled, nb_disabled


def collect_schedule_data(config_lines: List[str], current_date: datetime) -> Tuple[int, int, int]:
    """
    Analyse les configurations de pare-feu pour catégoriser les règles basées sur leurs schedules.

    Args:
        config_lines (List[str]): Liste des lignes de configuration du pare-feu.
        current_date (datetime): Date actuelle pour vérifier l'expiration des schedules ponctuels.

    Returns:
        Tuple[int, int, int]: (Always, Scheduled_Actif, Scheduled_Expiré)
    """

    onetime_schedules = {}          # {nom_schedule: date_fin}
    recurring_schedules = set()     # Set des schedules récurrents
    group_schedules = {}            # {nom_groupe: [membres]}
    policy_schedules = []           # Liste des schedules appliqués dans les policies

    in_onetime = False
    in_recurring = False
    in_policy = False
    in_group = False
    current_edit = None

    # ---------------------- PARSING DE LA CONFIG ----------------------
    for line in config_lines:
        line = line.strip()

        if line.startswith("config firewall schedule onetime"):
            in_onetime = True; in_recurring = in_policy = in_group = False
            continue

        elif line.startswith("config firewall schedule recurring"):
            in_recurring = True; in_onetime = in_policy = in_group = False
            continue

        elif line.startswith("config firewall schedule group"):
            in_group = True; in_onetime = in_recurring = in_policy = False
            continue

        elif line.startswith("config firewall policy"):
            in_policy = True; in_onetime = in_recurring = in_group = False
            continue

        elif line == "end":
            in_onetime = in_recurring = in_policy = in_group = False
            current_edit = None
            continue

        # ------ ONETIME ------
        if in_onetime:
            if line.startswith("edit "):
                current_edit = line.split(' ')[1].strip('"')

            elif line.startswith("set end"):
                parts = line.split(' ')
                if len(parts) >= 4:
                    end_time_str = parts[2]
                    end_date_str = parts[3]
                    end_datetime_str = f"{end_time_str} {end_date_str}"
                    try:
                        end_date = datetime.strptime(end_datetime_str, "%H:%M %Y/%m/%d")
                        onetime_schedules[current_edit] = end_date
                    except ValueError:
                        pass
            continue

        # ------ RECURRING ------
        if in_recurring:
            if line.startswith("edit "):
                current_edit = line.split(' ')[1].strip('"')
                if current_edit.lower() != "always":
                    recurring_schedules.add(current_edit)
            continue

        # ------ GROUPS ------
        if in_group:
            if line.startswith("edit "):
                current_edit = line.split(' ')[1].strip('"')
                group_schedules[current_edit] = []

            elif line.startswith("set member"):
                parts = line.split('"')
                members = [p for i, p in enumerate(parts) if i % 2 == 1]
                group_schedules[current_edit].extend(members)
            continue

        # ------ POLICY ------
        if in_policy:
            if line.startswith("set schedule"):
                parts = line.split(' ')
                if len(parts) >= 3:
                    policy_schedules.append(parts[2].strip('"'))
            continue

    # ---------------------- CATEGORISATION ----------------------

    always_count = 1  # Règle implicite deny
    scheduled_actif_count = 0
    scheduled_expire_count = 0

    for schedule in policy_schedules:

        # ALWAYS
        if schedule.lower() == "always":
            always_count += 1
            continue

        # GROUPS
        if schedule in group_schedules:
            members = group_schedules[schedule]

            member_expired = False
            member_active = False

            for m in members:
                # Récurrent
                if m in recurring_schedules:
                    member_active = True

                # Onetime
                elif m in onetime_schedules:
                    if onetime_schedules[m] < current_date:
                        member_expired = True
                    else:
                        member_active = True

                # Inconnu → ignoré

            if member_expired:
                scheduled_expire_count += 1
            elif member_active:
                scheduled_actif_count += 1

            continue

        # RÉCURRENT SIMPLE
        if schedule in recurring_schedules:
            scheduled_actif_count += 1
            continue

        # ONETIME SIMPLE
        if schedule in onetime_schedules:
            if onetime_schedules[schedule] < current_date:
                scheduled_expire_count += 1
            else:
                scheduled_actif_count += 1
            continue

        # Inconnu → ignoré

    return always_count, scheduled_actif_count, scheduled_expire_count

def verifier_ha_redundance_cablage(config_lines, redondance_HA):
    ha_details = extraire_ha_details(config_lines)
    if not ha_details["ha_present"]:
        return "Absence de Cluster", "N/A"

    if redondance_HA:
        return (
            "Le câblage est entièrement redondé entre les FortiGate",
            True
        )
    else:
        return (
            "Le câblage n'est pas entièrement redondé entre les FortiGate",
            False
        )



def auditer():
    if not wan_interfaces:
        messagebox.showerror("Erreur", "Vous devez charger les interfaces avant de lancer l'audit !")
        return

    if imported_filepath:
        config_lines = lire_config_fortigate(imported_filepath)
        hostname = extraire_hostname(config_lines)

        active_interfaces = read_active_interfaces(imported_filepath)
        zones, sdwan_zones = read_zones(imported_filepath, active_interfaces)

        selected_wan_interfaces = get_selected_wan_interfaces(zones, sdwan_zones)
        licence_utm = licence_utm_var.get()
        lien_mpls_L2L = lien_mpls_L2L_var.get()
        redondance_HA = redondance_HA_var.get()
        vip_any_result, vip_any_conform = verifier_vips_extintf_any(config_lines)
        vs_any_result, vs_any_conform = verifier_vs_extintf_any(config_lines)
        sequence_result, sequence_conform = verifier_usage_by_sequence(config_lines)
        objets_result, objets_conform, objets_non_utilises = detecter_objets_non_utilises(config_lines)
        guest_result, guest_conform = verifier_compte_guest(config_lines)
        admin_result, admin_conform = verifier_compte_admin(config_lines)
        utilisation_ssl_result, utilisation_ssl_conform = verifier_vpn_ssl_utilisation(config_lines)
        all_in_rules_result, all_in_rules_conform, all_in_rules_ids = verifier_presence_all_port_dans_regles(
            config_lines, selected_wan_interfaces)
        geo_ip_result, geo_ip_conform = verifier_utilisation_geo_ip(config_lines, selected_wan_interfaces)
        deny_implicit_result, deny_implicit_conform = verifier_logs_deny_implicit(config_lines)
        version_fortigate_result, version, model = extraire_modele_version_fortigate(config_lines)
        version_cve_message, version_conform = est_version_concernee_par_cve(version)
        eol_result, eol_conform = verifier_modele_fortigate_eol(model)
        usb_result, usb_conform = verifier_auto_install_usb(config_lines)
        isdb_result, isdb_conform = verifier_presence_isdb(config_lines, selected_wan_interfaces, incoming_isdbs,
                                                           outgoing_isdbs)
        http_https_result, http_https_conform, http_https_enabled_interfaces, interfaces_access_details = verifier_http_https_desactive_sur_interfaces_wan(
            config_lines, selected_wan_interfaces)
        admin_sns_result, admin_sns_conform = verifier_compte_admin_sns(config_lines)
        pki_sns_result, pki_sns_conform = verifier_suppression_compte_pki_sns(config_lines)
        pki_pkisns_result, pki_pkisns_conform = verifier_presence_compte_pki_pkisns(config_lines)
        sync_fortianalyzer_result, sync_fortianalyzer_conform = verifier_sync_fortianalyzer(config_lines)
        sync_fortimanager_result, sync_fortimanager_conform = verifier_sync_fortimanager(config_lines)
        mfa_result, mfa_conform = verifier_mfa_utilisateurs_admins(config_lines)
        ike_result, ike_conform, ike_list, dh_result, dh_conform, dh_list, algo_result, algo_conform, algo_list = verifier_durcissement_vpn_ipsec_split(
            config_lines)
        cti_result, cti_conform = verifier_presence_cti(config_lines, selected_wan_interfaces, model)
        ldaps_result, ldaps_conform = verifier_ldaps(config_lines)
        sauvegardes_result, sauvegardes_conform = verifier_sauvegardes_automatiques(config_lines)
        acces_admin_sns_result, acces_admin_sns_conform = verifier_acces_admin_sns_via_loopback(config_lines)
        dns_database_result, dns_database_conform = verifier_dns_database(config_lines)
        sip_alg_result, sip_alg_conform = verifier_sip_alg(config_lines)
        fortisandbox_result, fortisandbox_conform = verifier_fortisandbox_cloud(config_lines, licence_utm)
        anycast_fortiguard_result, anycast_fortiguard_conform = verifier_anycast_fortiguard(config_lines, licence_utm)
        fortiguard_result, fortiguard_conform = verifier_mises_a_jour_fortiguard(config_lines, licence_utm)
        blackhole_result, blackhole_conform = verifier_route_blackhole(config_lines, lien_mpls_L2L)
        ha_cablage_result, ha_cablage_conform = verifier_ha_redundance_cablage(config_lines, redondance_HA)
        ha_session_pickup_result, ha_session_pickup_conform = verifier_ha_session_pickup(config_lines)
        ha_redundance_result, ha_redundance_conform = verifier_ha_redundance_interfaces(config_lines)
        ha_override_result, ha_override_conform = verifier_ha_override(config_lines)
        ports_deny_result, ports_deny_conform = verifier_ports_deny(config_lines, selected_wan_interfaces)
        sdwan_result, sdwan_conform, sdwan_action_message, missing_sdwan_interfaces = verifier_utilisation_sdwan(
            config_lines, selected_wan_interfaces)
        result_profils, conformity_profils, rule_ids_profils = verifier_profils_securite_sur_regles(config_lines)
        result_mail_filter, conformity_mail_filter, rule_ids_mail_filter = verifier_mail_filter(config_lines)
        result_web_filter, conformity_web_filter, non_conforming_web_filter = verifier_webfilter_profiles(config_lines,
                                                                                                          licence_utm)
        av_result, av_conformity, av_non_conforming = verifier_antivirus_profiles(config_lines, licence_utm)
        dnsfilter_result, dnsfilter_conformity, dnsfilter_non_conforming = verifier_dnsfilter_profiles(config_lines,
                                                                                                       licence_utm,
                                                                                                       model)
        ips_result, ips_conformity, ips_non_conforming = verifier_ips_profiles(config_lines, licence_utm)
        result_app_control, conformity_app_control, non_conforming_app_control = verifier_app_control_profiles(
            config_lines, licence_utm)
        result_port_https_admin, is_compliant_https = verifier_port_https_admin(config_lines)
        modele_FAP_result, modele_FAP_conform, modele_FAP_list = check_obsolete_fortiap_devices(config_lines)
        ssid_result, ssid_conform, ssid_non_conforming_profiles, profiles_utilises = verifier_nombre_ssid_par_profil_wifi(config_lines)
        bande_5ghz_result, bande_5ghz_conform, bande_5ghz_non_conform = verifier_utilisation_bande_5ghz(config_lines)
        darrp_result, darrp_conform, darrp_non_conform = verifier_darrp_enable(config_lines)
        frequency_handoff_result, frequency_handoff_conform, frequency_handoff_non_conform = verifier_frequency_handoff(
            config_lines)
        tim_result, tim_conform, tim_non_conform = verifier_tim_enable(config_lines)
        results_logs = verifier_logs_par_regle(config_lines)
        nb_all = results_logs['counts']['all']
        nb_disabled = results_logs['counts']['disable']
        nb_utm = results_logs['counts']['utm']
        users_data = exporter_utilisateurs_admins()
        nb_policy_enable, nb_policy_disabled = compter_regles_activ_ou_desactiv(config_lines)
        nb_policy_always, nb_policy_schedule_actif, nb_policy_schedule_expire = collect_schedule_data(config_lines,
                                                                                                      datetime.today())
        ssl_ssh_result, ssl_ssh_conform, ssl_ssh_non_conforming, rule_ids_ssl_ssh = verifier_ssl_ssh_profiles(
            config_lines)
        band_result, band_conform, band_non_conform = verifier_band_conformite(config_lines)
        channel_result, channel_conform, channel_non_conform = verifier_channels_conformite(config_lines)
        sgi_result, sgi_conform, sgi_non_conform = verifier_short_guard_interval(config_lines)


        # Création du rapport Excel
        filename = creer_rapport_excel(
            guest_result, guest_conform, admin_result, admin_conform, usb_result, usb_conform,
            vs_any_result, vs_any_conform, vip_any_result, vip_any_conform,utilisation_ssl_result, utilisation_ssl_conform,
            all_in_rules_result, all_in_rules_conform, all_in_rules_ids, geo_ip_result, geo_ip_conform,
            hostname, version_fortigate_result, version_conform, isdb_result, isdb_conform,
            version_cve_message, http_https_result, eol_result, eol_conform,  http_https_conform, http_https_enabled_interfaces, interfaces_access_details, admin_sns_result,
            admin_sns_conform, pki_sns_result, pki_sns_conform, pki_pkisns_result, pki_pkisns_conform, deny_implicit_result,  deny_implicit_conform, sync_fortianalyzer_result,
            sync_fortianalyzer_conform, sync_fortimanager_result,
            sync_fortimanager_conform, mfa_result, mfa_conform,
            ike_result, ike_conform, ike_list, dh_result, dh_conform, dh_list, algo_result, algo_conform, algo_list,
            cti_result, cti_conform,
            ldaps_result, ldaps_conform,
            sauvegardes_result, sauvegardes_conform,
            objets_result, objets_conform, objets_non_utilises,
            acces_admin_sns_result, acces_admin_sns_conform,
            dns_database_result, dns_database_conform,
            sip_alg_result, sip_alg_conform,
            fortisandbox_result, fortisandbox_conform,
            anycast_fortiguard_result, anycast_fortiguard_conform,
            fortiguard_result, fortiguard_conform,
            blackhole_result, blackhole_conform,
            ha_session_pickup_result, ha_session_pickup_conform, ha_cablage_result, ha_cablage_conform,ha_redundance_result, ha_redundance_conform, ha_override_result, ha_override_conform,
            ports_deny_result, ports_deny_conform,
            sdwan_result, sdwan_conform, sdwan_action_message,
            licence_utm, result_profils, conformity_profils, rule_ids_profils,
            result_mail_filter, conformity_mail_filter, rule_ids_mail_filter,
            result_web_filter, conformity_web_filter, non_conforming_web_filter,
            av_result, av_conformity, av_non_conforming,
            dnsfilter_result, dnsfilter_conformity, dnsfilter_non_conforming,
            ips_result, ips_conformity, ips_non_conforming,
            result_app_control, conformity_app_control, non_conforming_app_control,
            result_port_https_admin, is_compliant_https,
            modele_FAP_result, modele_FAP_conform, modele_FAP_list,
            ssid_result, ssid_conform, ssid_non_conforming_profiles,
            bande_5ghz_result, bande_5ghz_conform, bande_5ghz_non_conform,
            darrp_result, darrp_conform, darrp_non_conform,
            frequency_handoff_result, frequency_handoff_conform, frequency_handoff_non_conform,
            tim_result, tim_conform, tim_non_conform,
            nb_all, nb_disabled, nb_utm, users_data, nb_policy_enable, nb_policy_disabled,
            nb_policy_always, nb_policy_schedule_actif, nb_policy_schedule_expire,
            ssl_ssh_result, ssl_ssh_conform, ssl_ssh_non_conforming, rule_ids_ssl_ssh,
            version, model, band_result, band_conform, band_non_conform,
            channel_result, channel_conform, channel_non_conform, sgi_result, sgi_conform, sgi_non_conform,
            sequence_result, sequence_conform
        )

        filename_word = creer_rapport_word(hostname, version, model, config_lines, version_conform, eol_conform, sauvegardes_conform, usb_conform, result_port_https_admin, is_compliant_https,
                                           sync_fortimanager_result, sync_fortimanager_conform, sync_fortianalyzer_result, sync_fortianalyzer_conform, http_https_result, http_https_conform, admin_result, admin_conform, mfa_result, mfa_conform, deny_implicit_result,
                                           deny_implicit_conform,sdwan_result, sdwan_conform, isdb_result, isdb_conform, cti_result, cti_conform, all_in_rules_result, all_in_rules_conform,
                                           vip_any_result, vip_any_conform, vs_any_result, vs_any_conform, geo_ip_result, geo_ip_conform, ldaps_result, ldaps_conform,
                                           ha_session_pickup_result, ha_session_pickup_conform, ha_cablage_result, ha_cablage_conform, ha_redundance_result, ha_redundance_conform, ha_override_result, ha_override_conform,
                                           utilisation_ssl_result, utilisation_ssl_conform, ike_result, ike_conform, dh_result, dh_conform, algo_result, algo_conform, licence_utm,
                                           dnsfilter_result, dnsfilter_conformity, result_web_filter, conformity_web_filter, av_result, av_conformity, ips_result, ips_conformity,
                                           result_app_control, conformity_app_control, modele_FAP_result, modele_FAP_conform, modele_FAP_list, ssid_result, ssid_conform, ssid_non_conforming_profiles, profiles_utilises,
                                           bande_5ghz_result, bande_5ghz_conform, bande_5ghz_non_conform, darrp_result, darrp_conform, darrp_non_conform, frequency_handoff_result, frequency_handoff_conform,
                                           frequency_handoff_non_conform, tim_result, tim_conform, tim_non_conform, band_result, band_conform, band_non_conform, channel_result, channel_conform, channel_non_conform, sgi_result, sgi_conform, sgi_non_conform,
                                           objets_result, objets_conform, objets_non_utilises, result_profils, conformity_profils, rule_ids_profils, blackhole_result, blackhole_conform, ports_deny_result, ports_deny_conform, fortiguard_result, fortiguard_conform, fortisandbox_result, fortisandbox_conform,
                                           sequence_result, sequence_conform)


def creer_rapport_excel(guest_result, guest_conform, admin_result, admin_conform, usb_result, usb_conform, vs_any_result, vs_any_conform, vip_any_result, vip_any_conform, utilisation_ssl_result, utilisation_ssl_conform, all_in_rules_result, all_in_rules_conform, all_in_rules_ids, geo_ip_result, geo_ip_conform, hostname,
                            version_fortigate_result, version_conform, isdb_result, isdb_conform, version_cve_message, http_https_result, eol_result, eol_conform,
                            http_https_conform, http_https_enabled_interfaces, interfaces_access_details, admin_sns_result, admin_sns_conform,
                            pki_sns_result, pki_sns_conform, pki_pkisns_result, pki_pkisns_conform, deny_implicit_result, deny_implicit_conform, sync_fortianalyzer_result,
                            sync_fortianalyzer_conform, sync_fortimanager_result, sync_fortimanager_conform,
                            mfa_result, mfa_conform, ike_result, ike_conform, ike_list, dh_result, dh_conform, dh_list, algo_result, algo_conform, algo_list,
                            cti_result, cti_conform, ldaps_result, ldaps_conform, sauvegardes_result, sauvegardes_conform, objets_result, objets_conform, objets_non_utilises,
                            acces_admin_sns_result, acces_admin_sns_conform, dns_database_result, dns_database_conform,
                            sip_alg_result, sip_alg_conform, fortisandbox_result, fortisandbox_conform, anycast_fortiguard_result,
                            anycast_fortiguard_conform, fortiguard_result, fortiguard_conform, blackhole_result, blackhole_conform,
                            ha_session_pickup_result, ha_session_pickup_conform, ha_cablage_result, ha_cablage_conform, ha_redundance_result, ha_redundance_conform, ha_override_result,
                            ha_override_conform, ports_deny_result, ports_deny_conform, sdwan_result, sdwan_conform, sdwan_action_message,
                            licence_utm,result_profils, conformity_profils, rule_ids_profils, result_mail_filter, conformity_mail_filter,
                            rule_ids_mail_filter, result_web_filter, conformity_web_filter, non_conforming_web_filter,
                            av_result, av_conformity, av_non_conforming, dnsfilter_result, dnsfilter_conformity, dnsfilter_non_conforming,
                            ips_result, ips_conformity, ips_non_conforming, result_app_control, conformity_app_control, non_conforming_app_control, result_port_https_admin, is_compliant_https,
                            modele_FAP_result, modele_FAP_conform, modele_FAP_list, ssid_result, ssid_conform, ssid_non_conforming_profiles, bande_5ghz_result, bande_5ghz_conform, bande_5ghz_non_conform,darrp_result, darrp_conform, darrp_non_conform,
                            frequency_handoff_result, frequency_handoff_conform, frequency_handoff_non_conform, tim_result, tim_conform, tim_non_conform, nb_all, nb_disabled, nb_utm, users_data, nb_policy_enable, nb_policy_disabled, nb_policy_always, nb_policy_schedule_actif, nb_policy_schedule_expire,
                        ssl_ssh_result, ssl_ssh_conform, ssl_ssh_non_conforming, rule_ids_ssl_ssh, version, model, band_result, band_conform, band_non_conform,
                        channel_result, channel_conform, channel_non_conform, sgi_result, sgi_conform, sgi_non_conform,
                        sequence_result, sequence_conform, regle_no_match: int = 0, client_name: str = "",site_name: str = "",serial_number: str = "",license_end_date: str = "",system_uptime: str = "",):
        current_time = datetime.now().strftime("%Y-%m-%d-%Hh%Mm%Ss")
        date_today = datetime.now().strftime("%d/%m/%Y")
        filename = f"{hostname} - Fichier audit Excel - {current_time}.xlsx"

        # Centralisation des informations dans des listes de dictionnaires
        audit_data = [
            {"point": "Catégorie : Système" },

            {
                "point": "Contrôle de la version du FortiGate pour les vulnérabilités",
                "benefice": "Le maintien à jour du firmware garantit une protection contre les vulnérabilités connues et patchées",
                "result": version_cve_message,
                "conform": 'Non' if version_conform else 'Oui',
                "accord": 'OUI',
                "action_sns": '',
                "action": "Mettre à jour votre Fortigate" if version_conform else ''
            },

            {
                "point": "Contrôle du modèle du FortiGate pour l'obsolescence",
                "benefice": "Permet d'éviter les interruptions de service et les failles de sécurité liées à l'arrêt du support technique et des mises à jour de sécurité",
                "result": eol_result,
                "conform": 'Oui' if eol_conform else 'Non',
                "accord": 'OUI',
                "action_sns": '',
                "action": '' if eol_conform else "Faire un trade-up de Fortigate"
            },

            {"point": "Sauvegardes automatiques de la configuration",
             "benefice": "Création automatique de backup lors d'un upgrade ou à chaque logout d'un compte admin",
             "result": sauvegardes_result, "conform": 'Oui' if sauvegardes_conform else 'Non', "accord": 'NON',
             "action": ''},

            {"point": "Absence d'objet sans référence",
             "benefice": "Réduction de la surface d'exposition et des risques d'erreurs",
             "result": objets_result,
             "conform": 'Oui' if objets_conform else 'Non',
             "accord": 'OUI',
             "action": '' if objets_conform else f"Faire une revue des objets sans référence détectés : {objets_result.split('pour les types suivants : ')[1] if 'pour les types suivants :' in objets_result else objets_result.split('pour le type suivant : ')[1] if 'pour le type suivant :' in objets_result else 'objets détectés'}"},

            {
                "point": "Contrôle désactivation USB",
                "benefice": "Protection physique contre un attaquant local",
                "result": usb_result,
                "conform": 'Oui' if usb_conform else 'Non',
                "accord": 'OUI',
                "action_sns": '',
                "action": '' if usb_conform else 'Désactiver les options USB'
            },

            {"point": "Catégorie : Administration et comptes"},

            {
                "point": "Personnalisation du port HTTPS pour l'accès admin",
                "benefice": "La modification de ce port permet d'éviter des conflits et d'améliorer la sécurité de votre pare-feu ",
                "result": result_port_https_admin,
                "conform": 'Oui' if is_compliant_https else 'Non',
                "accord": 'OUI',
                "action_sns": '',
                "action": "Changer le port HTTPS par défaut (443)" if not is_compliant_https else ''
            },

            {"point": "Synchronisation avec un FortiManager",
             "benefice": "Backups automatiques et fréquents de la configuration",
             "result": sync_fortimanager_result, "conform": 'Oui' if sync_fortimanager_conform else 'Non',
             "accord": 'NON', "action_sns": '',
             "action": ''},

            {"point": "Synchronisation des logs avec un FortiAnalyzer",
             "benefice": "Rétention des logs sur une durée étendue",
             "result": sync_fortianalyzer_result, "conform": 'Oui' if sync_fortianalyzer_conform else 'Non',
             "accord": 'OUI', "action_sns": '',
             "action": "Synchroniser votre FGT avec un FAZ" if not sync_fortianalyzer_conform else ''},

            {"point": "Durcissement accès administration à votre FGT", "benefice": "Permet de filtrer les IP sources entrantes pour l'administration de votre parefeu",
             "result": acces_admin_sns_result, "conform": 'Oui' if acces_admin_sns_conform else 'Non', "accord": 'NON',
             "action": ''},

            {   "point": "Désactivation du SSH, HTTP et HTTPS sur les interfaces WAN",
                "benefice": "Durcissement de l'accès au pare-feu depuis Internet",
                "result": http_https_result,
                "conform": 'Oui' if http_https_conform else 'Non',
                "accord": 'OUI',
                "action_sns": '',
                "action": (
                    "Désactiver les accès suivants sur les interfaces :\n" +
                    "\n".join([f"{interface} : {', '.join(services)}" for interface, services in
                               interfaces_access_details.items()])
                    if len(interfaces_access_details) > 1 else
                    f"Désactiver les accès suivants sur l'interface {list(interfaces_access_details.keys())[0]} : " +
                    f"{', '.join(interfaces_access_details[list(interfaces_access_details.keys())[0]])}"
                ) if not http_https_conform else ''
            },

            {"point": "Contrôle de la présence d'un compte administrateur local pour SNS",
             "benefice": "Compte admin SNS de backup en cas de défaillance du compte PKI",
             "result": admin_sns_result, "conform": 'Oui' if admin_sns_conform else 'Non', "accord": 'NON',
             "action_sns": '',
             "action": ''},

            {"point": "Contrôle de la suppression du compte PKI 'sns'", "benefice": "Couche de sécurité supplémentaire",
             "result": pki_sns_result, "conform": 'Oui' if pki_sns_conform else 'Non', "accord": 'NON',
             "action": ''},

            {"point": "Contrôle de la présence du compte PKI 'pki-sns'", "benefice": "Amélioration de la traçabilité des actions SNS. Ce compte permet une identification nominative du technicien",
             "result": pki_pkisns_result, "conform": 'Oui' if pki_pkisns_conform else 'Non', "accord": 'NON',
             "action": ''},

            {"point": "Contrôle de la suppression du compte 'Admin'", "benefice": "Réduction de la surface d'exposition en supprimant ce compte par défaut",
             "result": admin_result, "conform": 'Oui' if admin_conform else 'Non', "accord": 'OUI', "action_sns": '',
             "action": "Supprimer le compte admin par défaut" if not admin_conform else ''},

            {"point": "Contrôle de la suppression du compte local 'Guest'",
             "benefice": "Réduction de la surface d'exposition en supprimant ce compte par défaut",
             "result": guest_result, "conform": 'Oui' if guest_conform else 'Non', "accord": 'OUI', "action_sns": '',
             "action": "Supprimer le compte 'guest' par défaut" if not guest_conform else ''},

            {"point": "Vérification de la présence de MFA sur les comptes locaux administrateurs et utilisateurs",
             "benefice": "Renforcement de la sécurité des comptes administratifs et des utilisateurs",
             "result": mfa_result, "conform": 'Oui' if mfa_conform else 'Non', "accord": 'OUI',
             "action": "Mettre en place de la MFA pour les comptes locaux administrateurs  et utilisateurs" if not mfa_conform else ''},

            {"point": "DNS Database SNS",
             "benefice": "Garantit la résolution des FQDN SNS Security",
             "result": dns_database_result, "conform": 'Oui' if dns_database_conform else 'Non', "accord": 'NON',
             "action": ''},

            # ------------------------------------------------------------------------------------------------------------
            {"point": "Catégorie : Réseau et flux"},

            {"point": "Utilisation des règles en 'By Sequence'",
             "benefice": "Contrôle précis de l'ordre des règles",
             "result": sequence_result, "conform": 'Oui' if sequence_conform else 'Non', "accord": 'OUI',
             "action_sns": '',
             "action": 'Utiliser du By Sequence pour les règles' if not sequence_conform else ''},

            {"point": "Activation des logs sur la règle 'deny implicit'",
             "benefice": "Traçabilité des flux bloqués qui ne correspondent à aucune règle",
             "result": deny_implicit_result, "conform": 'Oui' if deny_implicit_conform else 'Non', "accord": 'NON',
             "action_sns": '',
             "action": ''},

            {"point": "Utilisation du SD-WAN",
             "benefice": "Optimisation de la bande passante, redondance et amélioration des performances. En cas d'un seul lien WAN, une configuration SD-WAN anticipée permet une flexibilité en cas d'ajout postérieur de nouveaux liens WAN",
             "result": sdwan_result, "conform": 'Oui' if sdwan_conform else 'Non', "accord": 'OUI',
             "action": sdwan_action_message if not sdwan_conform else ''},

            {"point": "Utilisation des listes d'ISDB malveillantes",
             "benefice": "Blocage des services indésirables pour les flux entrants et sortants. Base tenue par Fortinet.",
             "result": isdb_result, "conform": 'Oui' if isdb_conform else 'Non', "accord": 'NON', "action_sns": '',
             "action": ''},

            {"point": "Filtrage des ports au strict minimum pour les flux vers Internet",
             "benefice": "Réduction de la surface d'exposition basée sur le principe du moindre privilège",
             "result": all_in_rules_result, "conform": 'Oui' if all_in_rules_conform else 'Non', "accord": 'OUI', "action_sns":'',
             "action": f"Filtrer les ports au strict minimum dans les règles ID {', '.join(all_in_rules_ids)}" if not all_in_rules_conform else ''},

            {"point": "Contrôle absence de VIP avec any en interface",
             "benefice": "L'absence de VIP avec any permet d'éviter des problèmes de NAT",
             "result": vip_any_result, "conform": 'Oui' if vip_any_conform else 'Non', "accord": 'OUI', "action_sns": '',
             "action": 'Eviter de mettre "any" en interface externe des VIP' if not vip_any_conform else ''},

            {"point": "Contrôle absence de Virtual Server avec any en interface",
             "benefice": "L'absence de Virtual Server avec any permet d'éviter des problèmes de NAT",
             "result": vs_any_result, "conform": 'Oui' if vs_any_conform else 'Non', "accord": 'OUI', "action_sns": '',
             "action": 'Eviter de mettre "any" en interface externe des Virtual Servers' if not vs_any_conform else ''},

            {"point": "Filtrage des IP en fonction de leur pays d'origine",
            "benefice": "Réduction de la surface d'exposition basée sur le filtrage géographique",
            "result": geo_ip_result, "conform": 'Oui' if geo_ip_conform else 'Non', "accord": "OUI","action_sns": "",
            "action": "Faire une revue du filtrage GEO-IP pour vérifier sa pertinence" if geo_ip_conform == False and "GEO-IP est utilisé" in geo_ip_result else "Configurer l'utilisation de GEO-IP pour les flux entrants et sortants"},

            {"point": "Utilisation de nos CTI",
             "benefice": "Blocage des services indésirables\n pour les flux entrants et sortants.\nBase SNS + acteurs majeurs cybersécurité",
             "result": cti_result, "conform": 'Oui' if cti_conform else 'Non', "accord": 'NON',"action_sns":'',
             "action": ''},

            {"point": "Absence de règles avec logs en UTM sans profils de sécurité activés",
             "benefice": "Traçabilité des actions et transparence opérationnelle",
             "result": result_profils, "conform": 'Oui' if conformity_profils else 'Non', "accord": 'OUI', "action_sns": '',
             "action": f"Faire une passe sur les règles  qui ont des logs en UTM sans profil de sécurité activé" if not conformity_profils else ''},

            {"point": "Route Blackhole pour les réseaux privés",
             "benefice": "Alignement sur la RFC 6890 et empêchement des fuites de paquets privés",
             "result": blackhole_result, "conform": 'Oui' if blackhole_conform else 'Non', "accord": 'NON',
             "action": ''},

            {"point": "Blocage de certains ports pour les flux vers Internet : KERBEROS, LDAP, LDAPS, RADIUS, SAMBA, SMB",
             "benefice": "Minimise le risque d'accès non autorisé et de compromission",
             "result": ports_deny_result, "conform": 'Oui' if ports_deny_conform else 'Non', "accord": 'OUI',
             "action": "Bloquer certains ports pour les flux vers Internet : KERBEROS, LDAP, LDAPS, etc" if not ports_deny_conform else ''},

            {"point": "Connecteur LDAPS",
             "benefice": "Chiffrement des données permettant une protection contre les interceptions malveillantes",
             "result": ldaps_result, "conform": ldaps_conform, "accord": 'OUI',
             "action": "Mettre en place du LDAPS avec certificat" if ldaps_conform == "Non" else ''},

            {"point": "Désactivation du SIP ALG",
             "benefice": "Désactiver le SIP ALG empêche la corruption des paquets SIP",
             "result": sip_alg_result, "conform": 'Oui' if sip_alg_conform else 'Non', "accord": 'OUI',
             "action": "Désactiver le SIP ALG" if not sip_alg_conform else ''},

            #------------------------------------------------------------------------------------------------------------
            {"point": "Catégorie : HA - Cluster"},

            {"point": "Activer le session pickup",
             "benefice": "Permet de minimiser les interruptions de communication, évitant de devoir redémarrer les sessions actives",
             "result": ha_session_pickup_result,
             "conform": 'Oui' if ha_session_pickup_conform == True else 'Non' if ha_session_pickup_conform == False else 'N/A',
             "accord": 'OUI',
             "action": "Activer le session pickup et les 2 options associées" if ha_session_pickup_conform == False else ''},

            {"point": "Redondance du câblage entre les FortiGate (HA)",
             "benefice": "Permet d'assurer une continuité des flux en cas de bascule",
             "result": ha_cablage_result,
             "conform": 'Oui' if ha_cablage_conform == True else 'Non' if ha_cablage_conform == False else 'N/A',
             "accord": 'OUI',
             "action": "Redonder complètement le câblage entre les FortiGate" if ha_cablage_conform == False else ''},

            {"point": "Redondance des interfaces de HA (Heartbeat)",
             "benefice": "Assurer la redondance pour la synchronisation du cluster",
             "result": ha_redundance_result,
             "conform": 'Oui' if ha_redundance_conform == True else 'Non' if ha_redundance_conform == False else 'N/A',
             "accord": 'OUI',
             "action": "Configurer la redondance des interfaces HA" if ha_redundance_conform == False else ''},

            {   "point": "Override à 30 secondes ou désactivé",
                "benefice": (
                    "Si l'override est activée, mettre la durée d'attente à 30 secondes "
                    "est un compromis entre stabilité et réactivité. "
                    "Sinon, l'override peut être désactivé."
                ),
                "result": ha_override_result,
                "conform": (
                    "Oui" if ha_override_conform is True
                    else "Non" if ha_override_conform is False
                    else "N/A"
                ),
                "accord": "OUI",
                "action": (
                    "Configurer override avec une attente de 30 secondes"
                    if ha_override_conform is False else ""
                ),
            },

            # ------------------------------------------------------------------------------------------------------------
            {"point": "Catégorie : VPN"},

            {"point": "Contrôle de la non-utilisation du VPN-SSL",
                "benefice": "Fortinet a déprécié le VPN-SSL car jugé trop vulnérable. Il faut à la place utiliser le VPN IPSEC Nomade, plus sécurisé",
                "result": utilisation_ssl_result,
                "conform": 'Oui' if utilisation_ssl_conform else 'Non',
                "accord": 'OUI',
                "action": "Utiliser de l'IPSEC Nomade à la place du VPN-SSL" if not utilisation_ssl_conform else ''},


            {  "point": "Durcissement des VPN IPSEC : contrôle IKE",
                "benefice": "Protection accrue des échanges et diminution des risques d'interception des messages",
                "result": ike_result,
                "conform": 'N/A' if ike_result == "Absence de tunnel IPSEC configuré" else (
                    'Oui' if ike_conform else 'Non'),
                "accord": 'OUI',
                "action": f"Durcir la configuration du critère IKE pour le(s) tunnel(s) IPSEC suivant(s) : {ike_list}" if not ike_conform and ike_list else ''
            },

            {"point": "Durcissement des VPN IPSEC : contrôle DH Group",
             "benefice": "Protection accrue des échanges et diminution des risques d'interception des messages",
             "result": dh_result,
             "conform": 'N/A' if dh_result == "Absence de tunnel IPSEC configuré" else (
                 'Oui' if dh_conform else 'Non'),
             "accord": 'OUI',
             "action": f"Durcir la configuration du DH Group pour le(s) tunnel(s) IPSEC suivant(s) :{dh_list}" if not dh_conform else ''
             },

            {"point": "Durcissement des VPN IPSEC : contrôle des algorithmes",
             "benefice": "Protection accrue des échanges et diminution des risques d'interception des messages",
             "result": algo_result,
             "conform": 'N/A' if algo_result == "Absence de tunnel IPSEC configuré" else (
                 'Oui' if algo_conform else 'Non'),
             "accord": 'OUI',
             "action": f"Durcir la configuration des algorithmes pour le(s) tunnel(s) suivant(s) : {algo_list}" if not algo_conform else ''
             },

            # ------------------------------------------------------------------------------------------------------------
            {"point": "Catégorie : Profils de sécurité UTM - Gestion unifiée des menaces"},

            {"point": "Vérification de la licence UTM", "benefice": "Utilisation des profils de sécurité",
             "result": 'La licence UTM est valide' if licence_utm else "Le Fortigate ne dispose pas d'une licence UTM valide",
             "conform": 'Oui' if licence_utm else 'Non', "accord": 'OUI', "action_sns": '',
             "action": "Obtenir une licence UTM valide" if not licence_utm else ''},

            {"point": "Désactivation des requêtes anycast vers FortiGuard",
             "benefice": "Améliorer la liaison avec les serveurs FortiGuard",
             "result": anycast_fortiguard_result, "conform": 'Oui' if anycast_fortiguard_conform else 'Non', "accord": 'OUI',
             "action_sns": '',
             "action": "Obtenir une licence UTM valide" if not licence_utm else 'Désactiver les requêtes anycast'},

            {"point": "FortiGuard - Mises à jour automatiques des bases AV + IPS",
             "benefice": "Permet de recevoir plus rapidement les mises à jour critiques des bases AV + IPS FortiGuard",
             "result": fortiguard_result, "conform": 'Oui' if fortiguard_conform else 'Non', "accord": 'OUI',
             "action": "Obtenir une licence UTM valide" if not licence_utm else 'Configurer les MAJ FortiGuard sur automatic'},

            {"point": "Configuration FortiSandbox Cloud",
             "benefice": "Sandbox qui permet de bloquer des fichiers suspects sans impacter la performance du FortiGate",
             "result": fortisandbox_result, "conform": 'Oui' if fortisandbox_conform else 'Non', "accord": 'OUI',
             "action": "Obtenir une licence UTM valide" if not licence_utm else 'Configurer la FortiSandbox Cloud'},

            {"point": "Eviter le Mail Filter",
             "benefice": "Le Fortigate n'est pas un relais de mail. Si vous souhaitez une passerelle de messagerie sécurisée, nous vous recommandons l'utilisation de FortiMail",
             "result": result_mail_filter, "conform": 'Oui' if conformity_mail_filter else 'Non',"accord": 'OUI',
            "action": f"Désactiver le mail filter sur les règles ID {', '.join(rule_ids_mail_filter)}" if not conformity_mail_filter else ''},

            {
                "point": "Utilisation du DNS-Filter",
                "benefice": "Le DNS-filter évalue les requêtes DNS basées sur les notations de domaine de FortiGuard, le filtrage CTI et le blocage de botnets connus",
                "result": (
                    "La licence UTM n'est pas valide et aucun profil DNS Filter n'est utilisé"
                    if not licence_utm and dnsfilter_result == "Aucun profil DNS Filter n'est utilisé dans les règles"
                    else "La licence UTM n'est pas valide"
                    if not licence_utm
                    else dnsfilter_result
                ),
                "conform": 'Non' if not licence_utm or not dnsfilter_conformity else 'Oui',
                "accord": 'OUI',
                "action": (
                    "Commander une licence UTM valide et utiliser un profil DNS Filter"
                    if not licence_utm and dnsfilter_result == "Aucun profil DNS Filter n'est utilisé dans les règles"
                    else "Commander une licence UTM valide"
                    if not licence_utm
                    else "Utiliser un profil DNS Filter dans les règles vers Internet"
                    if licence_utm and dnsfilter_result == "Aucun profil DNS Filter n'est utilisé dans les règles"
                    else f"Vérifier et corriger les configurations des profils DNS filter suivants : {', '.join(dnsfilter_non_conforming)}"
                    if not dnsfilter_conformity
                    else ''
                )
            },
            {
                "point": "Utilisation du Web-Filter",
                "benefice": "Restreint les accès des utilisateurs aux ressources web (ex : « contenu adulte », « site de phishing »)",
                "result": (
                    "La licence UTM n'est pas valide et aucun profil Web-Filter n'est utilisé"
                    if not licence_utm and result_web_filter == "Aucun profil Web-Filter n'est utilisé dans les règles"
                    else "La licence UTM n'est pas valide"
                    if not licence_utm
                    else result_web_filter
                ),
                "conform": 'Non' if not licence_utm or not conformity_web_filter else 'Oui',
                "accord": 'OUI',
                "action": (
                    "Commander une licence UTM valide et utiliser un profil Web-Filter"
                    if not licence_utm and result_web_filter == "Aucun profil WebFilter n'est utilisé dans les règles"
                    else "Commander une licence UTM valide"
                    if not licence_utm
                    else "Utiliser un profil Web-Filter dans les règles vers Internet"
                    if licence_utm and result_web_filter == "Aucun profil WebFilter n'est utilisé dans les règles"
                    else f"Vérifier et corriger les configurations des profils web filter suivants : {', '.join(non_conforming_web_filter)}"
                    if not conformity_web_filter
                    else ''
                )
            },

            {
                "point": "Utilisation de l'Antivirus",
                "benefice": "Défense du SI contre les menaces les plus récentes",
                "result": (
                    "La licence UTM n'est pas valide et aucun profil Antivirus n'est utilisé"
                    if not licence_utm and av_result == "Aucun profil Antivirus n'est utilisé dans les règles"
                    else "La licence UTM n'est pas valide"
                    if not licence_utm
                    else av_result
                ),
                "conform": 'Non' if not licence_utm or not av_conformity else 'Oui',
                "accord": 'OUI',
                "action": (
                    "Commander une licence UTM valide et utiliser un profil Antivirus"
                    if not licence_utm and av_result == "Aucun profil Antivirus n'est utilisé dans les règles"
                    else "Commander une licence UTM valide"
                    if not licence_utm
                    else "Utiliser un profil Antivirus dans les règles vers/depuis Internet"
                    if licence_utm and av_result == "Aucun profil Antivirus n'est utilisé dans les règles"
                    else f"Vérifier et corriger les configurations des profils antivirus suivants : {', '.join(av_non_conforming)}"
                    if not av_conformity
                    else ''
                )
            },

            {
                "point": "Utilisation de l'IPS",
                "benefice": "Détection et blocage des attaques réseaux. Ce système se base sur des signatures, l'analyse comportementale et d'autres techniques avancées",
                "result": (
                    "La licence UTM n'est pas valide et aucun profil IPS n'est utilisé"
                    if not licence_utm and ips_result == "Aucun profil IPS utilisé dans les règles"
                    else "La licence UTM n'est pas valide"
                    if not licence_utm
                    else ips_result
                ),
                "conform": 'Non' if not licence_utm or not ips_conformity else 'Oui',
                "accord": 'OUI',
                "action": (
                    "Commander une licence UTM valide et utiliser un profil IPS"
                    if not licence_utm and ips_result == "Aucun profil IPS utilisé dans les règles"
                    else "Commander une licence UTM valide"
                    if not licence_utm
                    else "Utiliser un profil IPS dans les règles vers/depuis Internet"
                    if licence_utm and ips_result == "Aucun profil IPS utilisé dans les règles"
                    else f"Vérifier et corriger les configurations des profils IPS suivants : {', '.join(ips_non_conforming)}"
                    if not ips_conformity
                    else ''
                )
            },

            {
                "point": "Blocage Proxy, P2P et Remote access via l'Application Control",
                "benefice": "Réduction des risques de piratage et augmentation du controle de la surface d'attaque",
                "result": (
                    "La licence UTM n'est pas valide et aucun profil App Control n'est utilisé"
                    if not licence_utm and result_app_control == "Aucun profil App Control n'est utilisé dans les règles"
                    else "La licence UTM n'est pas valide"
                    if not licence_utm
                    else result_app_control
                ),
                "conform": 'Non' if not licence_utm or not conformity_app_control else 'Oui',
                "accord": 'OUI',
                "action": (
                    "Commander une licence UTM valide et utiliser un profil App Control"
                    if not licence_utm and result_app_control == "Aucun profil App Control n'est utilisé dans les règles."
                    else "Commander une licence UTM valide"
                    if not licence_utm
                    else "Utiliser un profil App Control dans les règles vers Internet"
                    if licence_utm and result_app_control == "Aucun profil App Control n'est utilisé dans les règles."
                    else f"Vérifier et corriger les configurations des profils App Control suivants : {', '.join(non_conforming_app_control)}"
                    if not conformity_app_control
                    else ''
                )
            },

            {
                "point": "Inspection SSL/SSH - Probe Failure",
                "benefice": "Evite d'avoir des flux bloqués en raison d'un problème de validation de certificat",
                "result": (
                    "Ce contrôle n'est pas applicable pour cette version du FortiOS"
                    if ssl_ssh_result == "N/A"
                    else ssl_ssh_result
                ),
                "conform": 'Non' if ssl_ssh_conform is False else ('Oui' if ssl_ssh_conform is True else 'N/A'),
                "accord": "OUI",
                "action": (
                    f"Vérifier et corriger les configurations des profils SSL/SSH suivants : {', '.join(ssl_ssh_non_conforming)}. "
                    f"Les règles concernées sont : {', '.join(rule_ids_ssl_ssh)}"
                    if ssl_ssh_conform is False else ""
                )
            },

            # ------------------------------------------------------------------------------------------------------------
            {"point": "Catégorie : WIFI"},

            {"point": "Modèle de FortiAP - Prévention de l'obsolescence",
             "benefice": "Anticiper le renouvellement des FortiAP permet d'éviter les interruptions de service liées aux incompatibilités suite aux mises à jour majeures du FortiGate",
             "result": modele_FAP_result,
             "conform": "N/A" if modele_FAP_result == "N/A car absence de borne WIFI FortiAP configurée" else ('Oui' if modele_FAP_conform else 'Non'),
             "accord":'OUI',
             "action": ("Renouveller les FortiAP proches de l'obsolescence : " + ", ".join(modele_FAP_list)) if not modele_FAP_conform else ''},

            {"point": "Nombre de SSID par profil WIFI",
             "benefice": "Avoir plus de 4 SSIDs sur un profil WIFI entraine une dégradation des performances et une saturation du spectre radio",
             "result": ssid_result, "conform": "N/A" if ssid_result == "N/A car absence de borne WIFI FortiAP configurée" else ('Oui' if ssid_conform else 'Non'), "accord": 'OUI',
             "action": (f"Utiliser moins de 5 SSID pour les profils suivants : " f"{', '.join([f'{p} ({r}: {c} SSID)' for p, r, c in ssid_non_conforming_profiles])}") if not ssid_conform else ''},

            {"point": "Utilisation de la bande 5GHz sur le canal 40MHz",
             "benefice": "Le 5GHz est moins sensible aux interférences, offre des débits plus élevés et moins de latence. Le canal 40MHz offre le meilleur compromis entre débit et stabilité",
             "result": bande_5ghz_result,
             "conform": "N/A" if bande_5ghz_result == "N/A car absence de borne WIFI FortiAP configurée" else ("Oui" if bande_5ghz_conform else "Non"),
             "accord": "OUI",
             "action": (f"""Corriger les profils suivants : {'\n'.join([f"{item['profile']}  ({', '.join(item['reasons'])})" for item in bande_5ghz_non_conform])}""") if not bande_5ghz_conform else ''
             },

            {   "point": "Activation de l'option 'Radio Resource Provision'",
                "benefice": "Cette option permet une gestion dynamique des ressources radio, améliorant la qualité du signal et réduisant les interférences",
                "result": darrp_result,
                "conform": "N/A" if darrp_result == "N/A car absence de borne WIFI FortiAP configurée" else ("Oui" if darrp_conform else "Non"),
                "accord": "OUI",
                "action": (
                    f"""Corriger les profils suivants : {'\n'.join([f"{profile} ({' et '.join(radios)}) : Option 'Radio Resource Provision' non activée" for profile, radios in darrp_non_conform.items()])}"""
                ) if not darrp_conform else ''
            },

            {
                "point": "Activation de l'option 'Frequency Handoff'",
                "benefice": "Amélioration du load balancing entre les bandes 2,4GHz et 5GHz",
                "result": (
                            frequency_handoff_result + "\nAttention cette option peut entrainer des déconnexions en cas de réseaux mal conçus (ex : excès de couverture)"),
                "conform": "N/A" if frequency_handoff_result.startswith("N/A car absence de borne WIFI FortiAP configurée") else (
                    "Oui" if frequency_handoff_conform else "Non"),
                "accord": "OUI",
                "action": (
                    f"""Corriger les profils suivants : {'\n'.join([f"{profile} : Option 'Frequency Handoff' non activée" for profile in frequency_handoff_non_conform])}"""
                ) if not frequency_handoff_conform else ''
            },

            {
                "point": "Activation de l'option 'TIM'",
                "benefice": "L'activation de 'TIM' permet une meilleure gestion des économies d'énergie pour les clients connectés, tout en garantissant une connectivité efficace",
                "result": tim_result,
                "conform": "N/A" if tim_result == "N/A car absence de borne WIFI FortiAP configurée" else (
                    "Oui" if tim_conform else "Non"),
                "accord": "OUI",
                "action": (
                    f"""Corriger les profils suivants : {'\n'.join([f"{profile} ({' et '.join(radios)}) : Option 'TIM' non activée" for profile, radios in tim_non_conform.items()])}"""
                ) if not tim_conform else ''
            },

            {
                "point": "Conformité des canaux radio utilisés",
                "benefice": "Utiliser uniquement les trois canaux 1, 6 et 11 permet d’éviter les interférences entre réseaux voisins et d'assurer une transmission stable ",
                "result": channel_result,
                "conform": "N/A" if channel_result == "N/A car absence de borne WIFI FortiAP configurée" else (
                    "Oui" if channel_conform else "Non"),
                "accord": "OUI",
                "action": (f"""Corriger les profils suivants : {'\n'.join([f"{profile} ({', '.join([f'{radio} : {channels}' for radio, channels in radios.items()])}) : Channels non conformes" for profile, radios in channel_non_conform.items()])}"""
                           ) if not channel_conform else ''
            },

            {
                "point": "Conformité des bandes radio utilisées (802.11)",
                "benefice": "Les standards récents (n/ac/ax) offrent de meilleures performances. Il faut éviter les standards obsolètes (a/b/g) sources d’interférences et de faible débit",
                "result": band_result,
                "conform": "N/A" if band_result == "N/A car absence de borne WIFI FortiAP configurée" else (
                    "Oui" if band_conform else "Non"),
                "accord": "OUI",
                "action": (
                    f"""Corriger les profils suivants : {'\n'.join([f"{profile} ({', '.join([f'{radio} : {band}' for radio, band in radios.items()])}) : Bande non conforme" for profile, radios in band_non_conform.items()])}"""
                ) if not band_conform else ''
            },

            {
                "point": "Activation de l'option Short Guard Interval",
                "benefice": "Dans les environnements où il y a peu d'interférences et d'obstacles, l'option Short Guard Interval permet d’augmenter le débit jusqu’à +11 %",
                "result": sgi_result,
                "conform": "N/A" if sgi_result == "N/A car absence de borne WIFI FortiAP configurée" else (
                    "Oui" if sgi_conform else "Non"),
                "accord": "OUI",
                "action": (
                    f"""Corriger les profils suivants : {'\n'.join([f"{profile} ({' et '.join(radios)}) : Option 'Short Guard Interval' non activée" for profile, radios in sgi_non_conform.items()])}"""
                ) if not sgi_conform else ''
            },
        ]

        # Génération du DataFrame à partir des données
        df = pd.DataFrame(audit_data)
        df = df[
            ["point", "benefice", "result", "conform", "accord", "action_sns", "action"]]
        df['action_sns'] = df.apply(
            lambda row: "/" if row['conform'] == 'Oui' or (row['conform'] == 'Non' and row['accord'] == 'OUI') or row['conform'] =="N/A" else '',
            axis=1)
        df['action'] = df.apply(lambda row: "/" if row['conform'] == 'Oui' or (row['conform'] == 'Non' and row['accord'] == 'NON') or row['conform'] =="N/A" else row['action'], axis=1)

        df.rename(columns={'conform': 'Conformité audit'}, inplace=True)

        # Vérification préalable de l'existence de la colonne "Conformité audit"
        if 'Conformité audit' not in df.columns:
            raise ValueError("La colonne 'Conformité audit' est manquante dans le DataFrame.")

        # Création du fichier Excel
        wb = Workbook()
        ws = wb.active
        ws.title = "Audit de Configuration"

        # Création des en-têtes
        headers = ['Point d\'Audit', 'Bénéfice client', 'Résultat de l\'Audit', 'Conformité audit',
                   'Accord client nécessaire', 'Actions effectuées par SNS', 'Actions en attente accord client']
        ws.append(headers)

        thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'),
                             bottom=Side(style='thin'))
        header_fill = PatternFill(start_color="232323", end_color="232323", fill_type="solid")
        top_fill = PatternFill(start_color="232323", end_color="232323", fill_type="solid")

        for col in 'ABCDEFG':
            ws[f'{col}1'].fill = top_fill

        for col_idx, header in enumerate(headers, start=1):
            cell = ws.cell(row=6, column=col_idx, value=header)
            cell.font = Font(bold=True, size=12, color="FED2F2")
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            cell.border = thin_border
            cell.fill = header_fill

        ws.row_dimensions[6].height = 35

        # Remplir le tableau avec les données
        for r_idx, row in df.iterrows():
            ws.append(row.values.tolist())

        # Ajouter des bordures, centrer le texte, aligner verticalement et permettre le retour à la ligne pour chaque cellule à partir de la ligne 7
        for row in ws.iter_rows(min_row=7, max_row=ws.max_row, min_col=1, max_col=7):
            for cell in row:
                cell.border = thin_border  # Appliquer les bordures fines à chaque cellule
                cell.alignment = Alignment(horizontal='center', vertical='center',
                                           wrap_text=True)  # Centrer le texte, aligner verticalement et permettre le retour à la ligne

        # Ajustement des colonnes
        ws.column_dimensions['A'].width = 49
        ws.column_dimensions['B'].width = 53.5
        ws.column_dimensions['C'].width = 61
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 15
        ws.column_dimensions['F'].width = 35
        ws.column_dimensions['G'].width = 43

        fixed_row_height = 50
        for row in ws.iter_rows(min_row=7, max_row=ws.max_row):
            ws.row_dimensions[row[0].row].height = fixed_row_height

        ws.row_dimensions[1].height = 18
        for row in range(2, 6):
            ws.row_dimensions[row].height = 25
        for row in [27, 28, 29, 30, 31, 32, 33, 34,35, 36, 37, 52, 53, 54, 55, 56, 57, 58, 59,60,61,62, 63, 64, 65, 66,67]:
            ws.row_dimensions[row].height = 70
        ws.row_dimensions[11].height = 82


        # Application du formatage conditionnel
        green_fill = PatternFill(start_color="2A83E8", end_color="2A83E8", fill_type="solid")
        red_fill = PatternFill(start_color="FED2F2", end_color="FED2F2", fill_type="solid")
        green_font = Font(color="FFFFFF", bold=True)
        red_font = Font(color="FFFFFF", bold=True)

        for col in ['D']:
            ws.conditional_formatting.add(f'{col}2:{col}{ws.max_row}',
                                          CellIsRule(operator='equal', formula=['"Oui"'], stopIfTrue=True,
                                                     fill=green_fill, font=green_font))
            ws.conditional_formatting.add(f'{col}2:{col}{ws.max_row}',
                                          CellIsRule(operator='equal', formula=['"Non"'], stopIfTrue=True,
                                                     fill=red_fill, font=red_font))

        # Configuration de l'en-tête du document
        ws.merge_cells('B2:F5')
        ws['B2'] = "Audit de Configuration Fortigate\n -\n Feuille de travail SNS"
        ws['B2'].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws['B2'].font = Font(size=20, bold=True)

        ws.merge_cells('G2:G3')
        img = OpenpyxlImage(_get_references_path("sns-security-logo1.png"))
        img.anchor = 'G2'
        ws.add_image(img)

        ws['A2'] = f"Client : {client_name}"
        ws['A3'] = f"Site : {site_name}"
        ws['A4'] = f"S/N : {serial_number}"
        ws['A2'].alignment = ws['A3'].alignment = ws['A4'].alignment = Alignment(horizontal='left', vertical='center',
                                                                                 indent=2)
        ws['A2'].font = ws['A3'].font = ws['A4'].font = Font(bold=True, size=12)

        try:
            firmware_version = version_fortigate_result.split(', Version firmware : ')[1]
        except IndexError:
            firmware_version = "Inconnue"

        ws['A5'] = f"Modèle : {model} / Version firmware : {firmware_version}"
        ws['A5'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws['A5'].font = Font(bold=True, size=12)

        ws['G4'] = "Date audit : " + date_today
        ws['G4'].alignment = Alignment(horizontal='center', vertical='center')
        ws['G4'].font = Font(bold=True, size=12)

        ws['G5'] = f"Date de fin de licence : {_fmt_date_fr(license_end_date)}"
        ws['G5'].alignment = Alignment(horizontal='center', vertical='center')
        ws['G5'].font = Font(bold=True, size=12)

        for row in ws.iter_rows(min_row=2, max_row=5, min_col=1, max_col=7):
            for cell in row:
                cell.border = thin_border

        # Figer les volets au dessus de la ligne 7
        ws.freeze_panes = ws['A7']

        # Application d'un filtre sur la ligne 6
        ws.auto_filter.ref = f"A6:G{ws.max_row}"

        # Formatage lignes catégories
        def format_merged_row(ws, start_cell, end_cell,
                              text_alignment=('left', 'center', 2),
                              fill_color='D9D9D9',
                              font_size=12,
                              row_height=40):
            ws.merge_cells(f'{start_cell}:{end_cell}')
            ws[start_cell].alignment = Alignment(horizontal=text_alignment[0], vertical=text_alignment[1],
                                                 indent=text_alignment[2])
            ws[start_cell].fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type='solid')
            ws[start_cell].font = Font(bold=True, size=font_size)
            ws.row_dimensions[int(start_cell[1:])].height = row_height

        format_merged_row(ws, 'A7', 'G7')
        format_merged_row(ws, 'A13', 'G13')
        format_merged_row(ws, 'A26', 'G26')
        format_merged_row(ws, 'A41', 'G41')
        format_merged_row(ws, 'A46', 'G46')
        format_merged_row(ws, 'A51', 'G51')
        format_merged_row(ws, 'A63', 'G63')

        categories_map = {
            "Catégorie : Système": range(8, 13),
            "Catégorie : Administration & comptes": range(14, 26),
            "Catégorie : Réseau et flux": range(27, 41),
            "Catégorie : HA - Cluster": range(42, 46),
            "Catégorie : VPN": range(47, 51),
            "Catégorie : Profils de sécurité": range(52, 63),
            "Catégorie : WIFI": range(64, ws.max_row + 1)
        }

        # Onglet "Sans accord"
        ws_sans_accord = wb.create_sheet(title="Sans accord")

        ws_sans_accord.merge_cells('A1:C1')
        cell = ws_sans_accord['A1']
        cell.value = ""
        cell.fill = top_fill

        ws_sans_accord.merge_cells('B2:B5')
        cell = ws_sans_accord['B2']
        cell.value = "Audit de Configuration Fortigate\n -\n Actions effectuées"
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.font = Font(bold=True, size=16)

        ws_sans_accord.merge_cells('C2:C3')
        img_sans_accord = OpenpyxlImage(_get_references_path("sns-security-logo-actions.png"))
        img_sans_accord.anchor = 'C2'
        ws_sans_accord.add_image(img_sans_accord)

        ws_sans_accord.merge_cells('A6:C6')
        cell = ws_sans_accord['A6']
        cell.value = (
            "Dans le but d'améliorer l'efficacité et la sécurité des configurations de nos clients, "
            "nous avons entrepris des ajustements et\n des paramétrages sur les équipements dont nous avons la gestion.\n "
            "Vous trouverez ci-dessous une description des actions entreprises par nos équipes ainsi que les bénéfices apportés."
        )
        cell.font = Font(size=12)
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        header_fill_sans_accord = PatternFill(start_color="232323", end_color="232323", fill_type="solid")
        headers_sans_accord = [
            "Point d'Audit",
            "Actions effectuées par SNS",
            "Bénéfices client"
        ]

        for col_idx, header in enumerate(headers_sans_accord, start=1):
            cell = ws_sans_accord.cell(row=7, column=col_idx, value=header)
            cell.font = Font(bold=True, size=12, color="FED2F2")
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            cell.fill = header_fill_sans_accord
            cell.border = thin_border

        ws_sans_accord.column_dimensions['A'].width = 49
        ws_sans_accord.column_dimensions['B'].width = 50
        ws_sans_accord.column_dimensions['C'].width = 41
        ws_sans_accord.row_dimensions[1].height = 18
        ws_sans_accord.row_dimensions[2].height = 25
        ws_sans_accord.row_dimensions[3].height = 25
        ws_sans_accord.row_dimensions[4].height = 25
        ws_sans_accord.row_dimensions[5].height = 25
        ws_sans_accord.row_dimensions[6].height = 65
        ws_sans_accord.row_dimensions[7].height = 35

        # Bordures pour A2 à C6
        for row in range(2, 7):
            for col in range(1, 4):
                cell = ws_sans_accord.cell(row=row, column=col)
                cell.border = thin_border

        # Ajout des formules pour copier les valeurs
        ws_sans_accord['A2'] = "=\'Audit de Configuration\'!A2"
        ws_sans_accord['A3'] = "=\'Audit de Configuration\'!A3"
        ws_sans_accord['A4'] = "=\'Audit de Configuration\'!A4"
        ws_sans_accord['A5'] = "=\'Audit de Configuration\'!A5"
        ws_sans_accord['C4'] = "=\'Audit de Configuration\'!G4"
        ws_sans_accord['C5'] = "=\'Audit de Configuration\'!G5"

        ws_sans_accord['A2'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_sans_accord['A2'].font = Font(bold=True, size=12)

        ws_sans_accord['A3'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_sans_accord['A3'].font = Font(bold=True, size=12)

        ws_sans_accord['A4'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_sans_accord['A4'].font = Font(bold=True, size=12)

        ws_sans_accord['A5'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_sans_accord['A5'].font = Font(bold=True, size=12)

        ws_sans_accord['C4'].alignment = Alignment(horizontal='center', vertical='center')
        ws_sans_accord['C4'].font = Font(bold=True, size=12)

        ws_sans_accord['C5'].alignment = Alignment(horizontal='center', vertical='center')
        ws_sans_accord['C5'].font = Font(bold=True, size=12)

        # Ajout des données dynamiques et des bordures
        audit_ws = wb["Audit de Configuration"]
        current_row = 8
        last_category = None
        for r_idx in range(8, audit_ws.max_row + 1):
            if audit_ws[f'D{r_idx}'].value == 'Non' and audit_ws[f'E{r_idx}'].value == 'NON':
                for category, rows in categories_map.items():
                    if r_idx in rows and category != last_category:
                        ws_sans_accord.merge_cells(f'A{current_row}:C{current_row}')
                        ws_sans_accord[f'A{current_row}'].value = category
                        ws_sans_accord[f'A{current_row}'].alignment = Alignment(horizontal='left', vertical='center',
                                                                                indent=2)
                        ws_sans_accord[f'A{current_row}'].font = Font(bold=True, size=12)
                        ws_sans_accord[f'A{current_row}'].fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9",
                                                                             fill_type='solid')
                        ws_sans_accord.row_dimensions[current_row].height = 40

                        for col in 'ABC':
                            ws_sans_accord[f'{col}{current_row}'].border = thin_border

                        current_row += 1
                        last_category = category

                ws_sans_accord[f'A{current_row}'] = f"=\'Audit de Configuration\'!A{r_idx}"
                ws_sans_accord[f'C{current_row}'] = f"=\'Audit de Configuration\'!B{r_idx}"
                ws_sans_accord[f'B{current_row}'] = f"=\'Audit de Configuration\'!F{r_idx}"
                for col in 'ABC':
                    cell = ws_sans_accord[f'{col}{current_row}']
                    cell.border = thin_border
                    cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
                ws_sans_accord.row_dimensions[current_row].height = 75
                current_row += 1

        # Paramètres pour l'impression
        ws_sans_accord.sheet_properties.pageSetUpPr.fitToPage = True
        ws_sans_accord.page_setup.fitToWidth = 1
        ws_sans_accord.page_setup.fitToHeight = 0
        ws_sans_accord.page_setup.paperSize = ws_sans_accord.PAPERSIZE_A4
        ws_sans_accord.print_title_rows = "7:7"

        # Ajout de l'onglet "Avec accord"
        ws_avec_accord = wb.create_sheet(title="Avec accord")

        ws_avec_accord.merge_cells('A1:C1')
        cell = ws_avec_accord['A1']
        cell.value = ""
        cell.fill = top_fill

        ws_avec_accord.merge_cells('B2:B5')
        cell = ws_avec_accord['B2']
        cell.value = "Audit de Configuration Fortigate\n -\n Actions en attente de votre accord"
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.font = Font(bold=True, size=16)

        ws_avec_accord.merge_cells('C2:C3')
        img_avec_accord = OpenpyxlImage(_get_references_path("sns-security-logo-actions.png"))
        img_avec_accord.anchor = 'C2'
        ws_avec_accord.add_image(img_avec_accord)

        ws_avec_accord.merge_cells('A6:C6')
        cell = ws_avec_accord['A6']
        cell.value = (
            "Dans le but d'améliorer l'efficacité et la sécurité des configurations de nos clients, nous avons audité la configuration\n des équipements dont nous avons la gestion. Vous trouverez ci-dessous une description des actions que nous\n souhaiterions effectuer et pour lesquelles nous avons besoin de votre accord ou de vos actions.\n Nous vous invitons à en prendre connaissance et à prendre contact avec notre équipe."
        )
        cell.font = Font(size=12)
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        header_fill_avec_accord = PatternFill(start_color="232323", end_color="232323", fill_type="solid")
        headers_avec_accord = [
            "Point d'Audit",
            "Actions en attente accord client",
            "Bénéfices client"
        ]

        for col_idx, header in enumerate(headers_avec_accord, start=1):
            cell = ws_avec_accord.cell(row=7, column=col_idx, value=header)
            cell.font = Font(bold=True, size=12, color="FED2F2")
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            cell.fill = header_fill_avec_accord
            cell.border = thin_border

        ws_avec_accord.column_dimensions['A'].width = 49
        ws_avec_accord.column_dimensions['B'].width = 50
        ws_avec_accord.column_dimensions['C'].width = 41
        ws_avec_accord.row_dimensions[1].height = 18
        ws_avec_accord.row_dimensions[2].height = 25
        ws_avec_accord.row_dimensions[3].height = 25
        ws_avec_accord.row_dimensions[4].height = 25
        ws_avec_accord.row_dimensions[5].height = 25
        ws_avec_accord.row_dimensions[6].height = 75
        ws_avec_accord.row_dimensions[7].height = 35

        # Bordures pour A2 à C6
        for row in range(2, 7):
            for col in range(1, 4):
                cell = ws_avec_accord.cell(row=row, column=col)
                cell.border = thin_border

        # Ajout des formules pour copier les valeurs
        ws_avec_accord['A2'] = "=\'Audit de Configuration\'!A2"
        ws_avec_accord['A3'] = "=\'Audit de Configuration\'!A3"
        ws_avec_accord['A4'] = "=\'Audit de Configuration\'!A4"
        ws_avec_accord['A5'] = "=\'Audit de Configuration\'!A5"
        ws_avec_accord['C4'] = "=\'Audit de Configuration\'!G4"
        ws_avec_accord['C5'] = "=\'Audit de Configuration\'!G5"

        ws_avec_accord['A2'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_avec_accord['A2'].font = Font(bold=True, size=12)

        ws_avec_accord['A3'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_avec_accord['A3'].font = Font(bold=True, size=12)

        ws_avec_accord['A4'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_avec_accord['A4'].font = Font(bold=True, size=12)

        ws_avec_accord['A5'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_avec_accord['A5'].font = Font(bold=True, size=12)

        ws_avec_accord['C4'].alignment = Alignment(horizontal='center', vertical='center')
        ws_avec_accord['C4'].font = Font(bold=True, size=12)

        ws_avec_accord['C5'].alignment = Alignment(horizontal='center', vertical='center')
        ws_avec_accord['C5'].font = Font(bold=True, size=12)

        # Ajout des données dynamiques et bordures
        current_row = 8
        last_category = None
        category_added = set()  # ← Ajoutez cette ligne

        for r_idx in range(8, audit_ws.max_row + 1):
            if audit_ws[f'D{r_idx}'].value == 'Non' and audit_ws[f'E{r_idx}'].value == 'OUI':
                # Identifiez d'abord la catégorie de cette ligne
                current_category = None
                for category, rows in categories_map.items():
                    if r_idx in rows:
                        current_category = category
                        break

                # Ajoutez le titre de catégorie seulement si pas encore ajouté
                if current_category and current_category not in category_added:  # ← Modifiez ici
                    ws_avec_accord.merge_cells(f'A{current_row}:C{current_row}')
                    ws_avec_accord[f'A{current_row}'].value = current_category
                    ws_avec_accord[f'A{current_row}'].alignment = Alignment(horizontal='left', vertical='center',
                                                                            indent=2)
                    ws_avec_accord[f'A{current_row}'].font = Font(bold=True, size=12)
                    ws_avec_accord[f'A{current_row}'].fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9",
                                                                         fill_type='solid')
                    ws_avec_accord.row_dimensions[current_row].height = 40

                    for col in 'ABC':
                        ws_avec_accord[f'{col}{current_row}'].border = thin_border

                    current_row += 1
                    category_added.add(current_category)  # ← Marquez comme ajoutée

                # Ajoutez ensuite la ligne de données
                ws_avec_accord[f'A{current_row}'] = f"=\'Audit de Configuration\'!A{r_idx}"
                ws_avec_accord[f'B{current_row}'] = f"=\'Audit de Configuration\'!G{r_idx}"
                ws_avec_accord[f'C{current_row}'] = f"=\'Audit de Configuration\'!B{r_idx}"
                for col in 'ABC':
                    cell = ws_avec_accord[f'{col}{current_row}']
                    cell.border = thin_border
                    cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
                ws_avec_accord.row_dimensions[current_row].height = 75
                current_row += 1

        # Ajuster toutes les colonnes sur une page pour l'impression
        ws_avec_accord.sheet_properties.pageSetUpPr.fitToPage = True
        ws_avec_accord.page_setup.fitToWidth = 1
        ws_avec_accord.page_setup.fitToHeight = 0
        ws_avec_accord.page_setup.paperSize = ws_sans_accord.PAPERSIZE_A4
        ws_avec_accord.print_title_rows = "7:7"

        #------------------------------Onglet "Stats"--------------------------------------------#

        ws_stats = wb.create_sheet(title="Stats")

        # Apply the white fill to all cells in the ws_stats worksheet
        for row in ws_stats.iter_rows(min_row=1, max_row=140, min_col=1, max_col=4):
            for cell in row:
                cell.fill = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")

        ws_stats.merge_cells('A1:D1')
        cell = ws_stats['A1']
        cell.value = ""
        cell.fill = top_fill

        ws_stats.merge_cells('A2:B2')
        ws_stats.merge_cells('A3:B3')
        ws_stats.merge_cells('A4:B4')
        ws_stats.merge_cells('A5:B5')

        ws_stats.merge_cells('C2:C5')
        cell = ws_stats['C2']
        cell.value = "Audit de Configuration Fortigate\n -\n Caractéristiques des règles"
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.font = Font(bold=True, size=16)

        ws_stats.merge_cells('D2:D3')
        img_stats = OpenpyxlImage(_get_references_path("sns-security-logo1.png"))
        img_stats.anchor = 'D2'
        ws_stats.add_image(img_stats)

        ws_stats.merge_cells('A6:D6')
        cell = ws_stats['A6']
        cell.value = (
            "Notre audit a permis d'analyser plusieurs caractéristiques des règles de votre pare-feu : log, schedule, statut et activité."
            "\nNous vous recommandons de réaliser une revue de vos règles afin de vérifier leur pertinence.\n "
            "Nous pouvons vous accompagner dans cette démarche."
        )
        cell.font = Font(size=12)
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        ws_stats.column_dimensions['A'].width = 39
        ws_stats.column_dimensions['B'].width = 10
        ws_stats.column_dimensions['C'].width = 60
        ws_stats.column_dimensions['D'].width = 40
        ws_stats.row_dimensions[1].height = 18
        ws_stats.row_dimensions[2].height = 25
        ws_stats.row_dimensions[3].height = 25
        ws_stats.row_dimensions[4].height = 25
        ws_stats.row_dimensions[5].height = 25
        ws_stats.row_dimensions[6].height = 85
        ws_stats.row_dimensions[7].height = 45
        ws_stats.row_dimensions[8].height = 30
        ws_stats.row_dimensions[32].height = 50
        ws_stats.row_dimensions[58].height = 50
        ws_stats.row_dimensions[62].height = 91

        ws_stats.merge_cells('A27:D31')
        ws_stats.merge_cells('A53:D57')
        ws_stats.merge_cells('A85:D88')

        # Police et fond pour la ligne 7
        top_fill = PatternFill(start_color='232323', end_color='232323', fill_type='solid')
        header_font = Font(bold=True, color='FED2F2', size=12)
        for cell in ws_stats[7]:
            cell.fill = top_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        ws_stats["A7"] = "Graphiques commentés"
        ws_stats.merge_cells('A7:D7')

        # Exemple : bordures pour A2 à C6 (simple border, si souhaité)
        for row in range(1, 7):
            for col in range(1, 5):  # A..D
                cell = ws_stats.cell(row=row, column=col)
                cell.border = thin_border

        thin_side = Side(style='thin')

        # --- Bordure du bas : ligne 32 (colonnes A..D) ---
        for col in range(1, 5):
            cell = ws_stats.cell(row=32, column=col)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=original_border.right,
                top=original_border.top,
                bottom=thin_side  # on ajoute/renforce le bas
            )
            cell.border = new_border

        # --- Bordure de droite : colonne D (lignes 1..61) ---
        for row in range(1, 61):
            cell = ws_stats.cell(row=row, column=4)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=thin_side,
                top=original_border.top,
                bottom=original_border.bottom
            )
            cell.border = new_border

        # --- Bordure du bas :
        for col in range(1, 5):
            cell = ws_stats.cell(row=60, column=col)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=original_border.right,
                top=original_border.top,
                bottom=thin_side
            )
            cell.border = new_border

        # --- Bordure de gauche : colonne A (lignes 7..61) ---
        for row in range(7, 61):
            cell = ws_stats.cell(row=row, column=1)
            original_border = cell.border
            new_border = Border(
                left=thin_side,  # on ajoute/renforce la gauche
                right=original_border.right,
                top=original_border.top,
                bottom=original_border.bottom
            )
            cell.border = new_border

        # --- Bordure de droite :
        for row in range(64, 127):
            cell = ws_stats.cell(row=row, column=4)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=thin_side,
                top=original_border.top,
                bottom=original_border.bottom
            )
            cell.border = new_border

        # --- Bordure de gauche : colonne A
        for row in range(64, 127):
            cell = ws_stats.cell(row=row, column=1)
            original_border = cell.border
            new_border = Border(
                left=thin_side,  # on ajoute/renforce la gauche
                right=original_border.right,
                top=original_border.top,
                bottom=original_border.bottom
            )
            cell.border = new_border

        # --- Bordure du bas :
        for col in range(1, 5):
            cell = ws_stats.cell(row=63, column=col)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=original_border.right,
                top=original_border.top,
                bottom=thin_side
            )
            cell.border = new_border

        # --- Bordure du bas : ligne 85 (colonnes A..D) ---
        for col in range(1, 5):
            cell = ws_stats.cell(row=85, column=col)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=original_border.right,
                top=original_border.top,
                bottom=thin_side
            )
            cell.border = new_border

        # --- Bordure du bas :
        for col in range(1, 5):
            cell = ws_stats.cell(row=94, column=col)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=original_border.right,
                top=original_border.top,
                bottom=thin_side
            )
            cell.border = new_border

        # --- Bordure du bas :
        for col in range(1, 5):
            cell = ws_stats.cell(row=126, column=col)
            original_border = cell.border
            new_border = Border(
                left=original_border.left,
                right=original_border.right,
                top=original_border.top,
                bottom=thin_side
            )
            cell.border = new_border

        # Ajout des formules pour copier les valeurs
        ws_stats['A2'] = "=\'Audit de Configuration\'!A2"
        ws_stats['A3'] = "=\'Audit de Configuration\'!A3"
        ws_stats['A4'] = "=\'Audit de Configuration\'!A4"
        ws_stats['A5'] = "=\'Audit de Configuration\'!A5"
        ws_stats['D4'] = "=\'Audit de Configuration\'!G4"
        ws_stats['D5'] = "=\'Audit de Configuration\'!G5"

        ws_stats['A2'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_stats['A2'].font = Font(bold=True, size=12)
        ws_stats['A3'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_stats['A3'].font = Font(bold=True, size=12)
        ws_stats['A4'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_stats['A4'].font = Font(bold=True, size=12)
        ws_stats['A5'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_stats['A5'].font = Font(bold=True, size=12)
        ws_stats['D4'].alignment = Alignment(horizontal='center', vertical='center')
        ws_stats['D4'].font = Font(bold=True, size=12)
        ws_stats['D5'].alignment = Alignment(horizontal='center', vertical='center')
        ws_stats['D5'].font = Font(bold=True, size=12)
        ws_stats['A7'].alignment = Alignment(horizontal='center', vertical='center')



        # GRAPHE pour la répartition des règles par type de logs
        # Étiquettes et valeurs à partir de la ligne 20
        ws_stats["B9"] = "Ce graphique montre la répartition des règles par type de logs :"
        ws_stats["B9"].font = Font(size=12)

        ws_stats["B11"] = "Type de logs"
        ws_stats["C11"] = "Nombre"
        ws_stats["B12"] = "Règles avec logs en all"
        ws_stats["C12"] = nb_all
        ws_stats["B13"] = "Règles avec logs désactivés"
        ws_stats["C13"] = nb_disabled
        ws_stats["B14"] = "Règles avec logs en UTM"
        ws_stats["C14"] = nb_utm

        pie_logs = PieChart()
        labels2 = Reference(ws_stats, min_col=2, min_row=12, max_row=14)
        data2 = Reference(ws_stats, min_col=3, min_row=11, max_row=14)

        pie_logs.add_data(data2, titles_from_data=True)
        pie_logs.set_categories(labels2)
        pie_logs.series[0].data_points = [
            DataPoint(idx=0, spPr=GraphicalProperties(solidFill="FED2F2")),
            DataPoint(idx=1, spPr=GraphicalProperties(solidFill="DDDDDD")),
            DataPoint(idx=2, spPr=GraphicalProperties(solidFill="2A83E8")),
        ]
        pie_logs.title = "Répartition des règles par type de logs"
        pie_logs.dataLabels = DataLabelList()
        pie_logs.dataLabels.showPercent = False
        pie_logs.dataLabels.showVal = True
        pie_logs.dataLabels.showCatName = False
        pie_logs.dataLabels.showSeriesName = False
        pie_logs.dataLabels.showLegendKey = False

        for label in pie_logs.dataLabels:
            label.font = Font(bold=True)

        # Positionner le diagramme dans la feuille
        ws_stats.add_chart(pie_logs, "B11")

        messages = []
        if nb_all > 0:
            messages.append(f"Vous avez {nb_all} règles avec les logs configurés en 'all'.")
        if nb_disabled > 0:
            messages.append(f"Vous avez {nb_disabled} règles avec les logs désactivés.")
        if nb_utm > 0:
            messages.append(
                f"Vous avez {nb_utm} règles avec les logs en UTM. \nAttention, les logs en UTM "
                "n'enregistrent que les flux qui matchent les profils de sécurité."
            )

        # On joint les phrases avec des retours à la ligne
        texte_final = "\n".join(messages)

        # Écrire le résultat dans A47
        ws_stats["A27"] = texte_final

        # Ajuster l’alignement, la police, etc.
        ws_stats["A27"].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws_stats["A27"].font = Font(size=12)


        # GRAPHE  pour classer les règles en fonction de leur schedule
        ws_stats["B35"] = "Ce graphique montre la répartition des règles par type de schedule :"
        ws_stats["B35"].font = Font(size=12)

        ws_stats["B37"] = "Type de Schedule"
        ws_stats["C37"] = "Nombre"
        ws_stats["B38"] = "Always"
        ws_stats["C38"] = nb_policy_always
        ws_stats["B39"] = "Scheduled - Actif"
        ws_stats["C39"] = nb_policy_schedule_actif
        ws_stats["B40"] = "Scheduled - Expiré"
        ws_stats["C40"] = nb_policy_schedule_expire

        # Création du PieChart pie_schedule
        if nb_policy_schedule_actif > 0 and nb_policy_schedule_expire > 0 :
            pie_schedule = ProjectedPieChart()  # On crée un pie chart projeté
            pie_schedule.type = "pie"
            pie_schedule.splitType = "percent"
        else:
            pie_schedule = PieChart()  # On crée un pie chart normal


        # Définir les labels et les données
        labels = Reference(ws_stats, min_col=2, min_row=38, max_row=40)
        data = Reference(ws_stats, min_col=3, min_row=37, max_row=40)

        pie_schedule.add_data(data, titles_from_data=True)
        pie_schedule.set_categories(labels)

        # Appliquer des couleurs aux parts du graphique
        colors = ["2A83E8", "FED2F2", "DDDDDD"]  # Bleu, Vert, Rouge
        data_points = [
            DataPoint(idx=0, spPr=GraphicalProperties(solidFill=colors[0])),  # Always
            DataPoint(idx=1, spPr=GraphicalProperties(solidFill=colors[1])),  # Scheduled - Actif
            DataPoint(idx=2, spPr=GraphicalProperties(solidFill=colors[2]))  # Scheduled - Expiré
        ]

        pie_schedule.series[0].data_points = data_points

        pie_schedule.title = "Répartition des règles par schedule"
        pie_schedule.dataLabels = DataLabelList()
        pie_schedule.dataLabels.showPercent = False
        pie_schedule.dataLabels.showVal = True
        pie_schedule.dataLabels.showCatName = False
        pie_schedule.dataLabels.showSeriesName = False
        pie_schedule.dataLabels.showLegendKey = False

        # Ajouter le graphe à la feuille de calcul
        ws_stats.add_chart(pie_schedule, "B37")

        # Calcul du total
        total_rules_schedule = nb_policy_always + nb_policy_schedule_actif + nb_policy_schedule_expire
        total_rules_scheduled_perso = nb_policy_schedule_actif + nb_policy_schedule_expire

        # Préparation du message
        message_schedule = ""

        # 1) Cas : 100% en always
        if nb_policy_always == total_rules_schedule and total_rules_schedule > 0:
            message_schedule = (
                f"Toutes vos règles ({nb_policy_always}) ont un schedule always, "
                "c'est-à-dire qu'elles sont actives 24/7.\n"
                "Est-ce vraiment nécessaire ou est-ce que vous pouvez en restreindre certaines ?"
            )

        # 2) Cas : présence de always, schedule actif ET schedule expiré
        elif (nb_policy_always > 0
              and nb_policy_schedule_actif > 0
              and nb_policy_schedule_expire > 0):
            message_schedule = (
                f"Vous avez {nb_policy_always} règle(s) avec un schedule en always (24/7).\n"
                f"Vous avez {total_rules_scheduled_perso} règle(s) avec un schedule personnalisé, dont {nb_policy_schedule_actif} règle(s) avec un schedule encore actif,\n"
                f"et {nb_policy_schedule_expire} règle(s) avec un schedule qui a expiré"
                " (cela équivaut à une désactivation de la règle)."
            )

        # 3) Cas : présence de always + schedule actif ou expiré (mais pas les 2)
        elif nb_policy_always > 0 and (nb_policy_schedule_actif > 0 or nb_policy_schedule_expire > 0):
            # On vérifie lequel des deux est > 0
            if nb_policy_schedule_actif > 0 and nb_policy_schedule_expire == 0:
                # always + actif seulement
                message_schedule = (
                    f"Vous avez {nb_policy_always} règle(s) avec un schedule en always (24/7).\n"
                    f"Vous avez également {nb_policy_schedule_actif} règle(s) avec un schedule personnalisé actif."
                )
            elif nb_policy_schedule_expire > 0 and nb_policy_schedule_actif == 0:
                # always + expiré seulement
                message_schedule = (
                    f"Vous avez {nb_policy_always} règle(s) avec un schedule en always (24/7).\n"
                    f"Vous avez également {nb_policy_schedule_expire} règle(s) avec un schedule personnalisé expiré "
                    "(cela équivaut à une désactivation de la règle)."
                )

        ws_stats["A53"] = message_schedule
        ws_stats["A53"].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        # GRAPHE pour comparer le nombre de règles activées/désactivées
        ws_stats["B67"] = "Ce graphique montre la répartition des règles de votre pare-feu en fonction de leur statut :"
        ws_stats["B67"].font = Font(size=12)

        ws_stats["B69"] = "État des règles"
        ws_stats["C69"] = "Nombre"
        ws_stats["B70"] = "Règles activées"
        ws_stats["C70"] = nb_policy_enable
        ws_stats["B71"] = "Règles désactivées"
        ws_stats["C71"] = nb_policy_disabled
        nb_regles_total = nb_policy_enable + nb_policy_disabled

        # Création du PieChart
        pie_statut = PieChart()
        labels3 = Reference(ws_stats, min_col=2, min_row=70,
                            max_row=71)  # Colonne A : "Règles activées"/"Règles désactivées"
        data3 = Reference(ws_stats, min_col=3, min_row=69, max_row=71)  # Colonne B : contient le titre + les 2 valeurs

        pie_statut.add_data(data3, titles_from_data=True)
        pie_statut.set_categories(labels3)
        pie_statut.series[0].data_points = [
            DataPoint(idx=0, spPr=GraphicalProperties(solidFill="2A83E8")),
            DataPoint(idx=1, spPr=GraphicalProperties(solidFill="DDDDDD")),
        ]
        pie_statut.title = "Règles activées / désactivées"
        pie_statut.dataLabels = DataLabelList()
        pie_statut.dataLabels.showPercent = False
        pie_statut.dataLabels.showVal = True
        pie_statut.dataLabels.showCatName = False
        pie_statut.dataLabels.showSeriesName = False
        pie_statut.dataLabels.showLegendKey = False

        # Positionner le graphique dans la feuille
        ws_stats.add_chart(pie_statut, "B69")

        if nb_policy_disabled > 0:
            resultat_pie3 = (
                f"Vous avez {nb_policy_enable} règles activées contre {nb_policy_disabled} règle(s) désactivée(s).\n Est-ce que les règles désactivées sont légitimes ?"
            )
        else:
            resultat_pie3 = (
                f"Toutes vos règles ({nb_policy_enable}) sont actives. Vous n'avez pas de règle désactivée."
            )

        ws_stats["A85"] = resultat_pie3
        # Alignement (wrap_text pour gérer les sauts de ligne)
        ws_stats["A85"].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws_stats["A85"].font = Font(size=12)

        # GRAPHE pour comparer le nombre de règles utilisées / inutilisées
        ws_stats["B98"] = "Ce graphique montre la répartition des règles qui matchent :"
        ws_stats["B98"].font = Font(size=12)

        regle_no_match = max(0, int(regle_no_match))
        regle_no_match = min(regle_no_match, nb_regles_total) #sécurité
        regle_with_match = nb_regles_total - regle_no_match
        ws_stats["B100"] = "Utilisation des règles"
        ws_stats["C100"] = "Nombre"
        ws_stats["B101"] = "Règles utilisées"
        ws_stats["C101"] = regle_with_match
        ws_stats["B102"] = "Règles inutilisées"
        ws_stats["C102"] = regle_no_match

        # Création du PieChart
        pie_statut = PieChart()
        labels3 = Reference(ws_stats, min_col=2, min_row=101,
                            max_row=102)
        data3 = Reference(ws_stats, min_col=3, min_row=100, max_row=102)

        pie_statut.add_data(data3, titles_from_data=True)
        pie_statut.set_categories(labels3)
        pie_statut.series[0].data_points = [
            DataPoint(idx=0, spPr=GraphicalProperties(solidFill="2A83E8")),
            DataPoint(idx=1, spPr=GraphicalProperties(solidFill="DDDDDD")),
        ]
        pie_statut.title = "Utilisation des règles"
        pie_statut.dataLabels = DataLabelList()
        pie_statut.dataLabels.showPercent = False
        pie_statut.dataLabels.showVal = True
        pie_statut.dataLabels.showCatName = False
        pie_statut.dataLabels.showSeriesName = False
        pie_statut.dataLabels.showLegendKey = False

        # Positionner le graphique dans la feuille
        ws_stats.add_chart(pie_statut, "B100")

        ws_stats.merge_cells('A116:D120')

        if regle_no_match > 0:
            resultat_pie4 = (
                f"Vous avez {regle_with_match} règles qui ont matchées depuis le {_fmt_date_fr(system_uptime)} (Uptime).\n Vous avez {regle_no_match} règle(s) sans match(s). Est-ce que ces règles sont légitimes ?"
                f"\nAttention, nous vous conseillons de garder les règles en DENY (sauf si un regroupement est possible)\n et de vous concentrer sur la pertinence des règles en ACCEPT."
            )
        else:
            resultat_pie4 = (
                f"Toutes vos règles sont utilisées, c'est à dire qu'il y a au moins un flux qui a matché chacune de vos règles depuis depuis le {_fmt_date_fr(system_uptime)} (Uptime)."
            )

        ws_stats["A116"] = resultat_pie4
        # Alignement (wrap_text pour gérer les sauts de ligne)
        ws_stats["A116"].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws_stats["A116"].font = Font(size=12)

        # Paramètres impression
        ws_stats.sheet_properties.pageSetUpPr.fitToPage = True
        ws_stats.page_setup.fitToWidth = 1
        ws_stats.page_setup.fitToHeight = 0
        ws_stats.page_setup.paperSize = ws_stats.PAPERSIZE_A4


        # ------------------------------Onglet "Accounts"--------------------------------------------#
        ws_accounts = wb.create_sheet(title="Accounts")

        ws_accounts.merge_cells('A1:F1')
        cell = ws_accounts['A1']
        cell.value = ""
        top_fill = PatternFill(start_color='232323', end_color='232323', fill_type='solid')
        cell.fill = top_fill

        ws_accounts.merge_cells('B2:E5')
        ws_accounts['B2'] = "Audit de Configuration Fortigate\n-\nListe des comptes administrateurs et utilisateurs"
        # Active le wrap_text
        ws_accounts['B2'].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws_accounts['B2'].font = Font(bold=True, size=18)

        ws_accounts.merge_cells('F2:F3')
        img_accounts = OpenpyxlImage(_get_references_path("sns-security-logo-account.png"))
        img_accounts.anchor = 'F2'
        ws_accounts.add_image(img_accounts)

        # Ajout des formules pour copier les valeurs
        ws_accounts['A2'] = "=\'Audit de Configuration\'!A2"
        ws_accounts['A3'] = "=\'Audit de Configuration\'!A3"
        ws_accounts['A4'] = "=\'Audit de Configuration\'!A4"
        ws_accounts['A5'] = "=\'Audit de Configuration\'!A5"
        ws_accounts['F4'] = "=\'Audit de Configuration\'!G4"
        ws_accounts['F5'] = "=\'Audit de Configuration\'!G5"

        # Alignements + styles
        ws_accounts['A2'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_accounts['A2'].font = Font(bold=True, size=12)
        ws_accounts['A3'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_accounts['A3'].font = Font(bold=True, size=12)
        ws_accounts['A4'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_accounts['A4'].font = Font(bold=True, size=12)
        ws_accounts['A5'].alignment = Alignment(horizontal='left', vertical='center', indent=2)
        ws_accounts['A5'].font = Font(bold=True, size=12)
        ws_accounts['F4'].alignment = Alignment(horizontal='center', vertical='center')
        ws_accounts['F4'].font = Font(bold=True, size=12)
        ws_accounts['F5'].alignment = Alignment(horizontal='center', vertical='center')
        ws_accounts['F5'].font = Font(bold=True, size=12)

        ws_accounts.merge_cells('A6:F6')
        ws_accounts['A6'] = (
            "Vous trouverez ci dessous une liste des comptes administrateurs et utilisateurs "
            "présents localement dans votre FortiGate. Nous vous recommandons d'effectuer une revue de ces comptes afin d’identifier "
            "les comptes qui doivent être désactivés ou supprimés, puis de réaligner les droits accordés sur chaque compte légitime.\n"
            "Si vous avez des comptes sans MFA (double authentification), nous vous recommandons l'utilisation de cette fonctionnalité afin de renforcer la sécurité de vos comptes."
        )
        ws_accounts['A6'].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws_accounts['A6'].font = Font(size=12)

        # --- Ajout des en-têtes (ils iront en ligne 7) ---
        ws_accounts.append([
            "Type de compte", "Nom du compte", "Statut", "Groupe",
            "MFA configurée dans Fortigate", "Données MFA"
        ])

        # Police et fond pour la ligne 7
        header_font = Font(bold=True, color='FED2F2')  # gras + texte blanc
        for cell in ws_accounts[7]:
            cell.fill = top_fill
            cell.font = header_font
            # wrap_text si vous le souhaitez, sinon:
            cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)

        # Ajout des données des utilisateurs
        for user in users_data:
            ws_accounts.append([
                user.get("Type de compte", ""),
                user.get("Nom du compte", ""),
                user.get("Statut", ""),
                user.get("Groupe", ""),
                user.get("Type MFA", ""),
                user.get("Données MFA", "")
            ])

        # --- Ajustement des largeurs de colonnes et lignes ---
        ws_accounts.column_dimensions["A"].width = 49
        ws_accounts.column_dimensions["B"].width = 42
        ws_accounts.column_dimensions["C"].width = 12
        ws_accounts.column_dimensions["D"].width = 40
        ws_accounts.column_dimensions["E"].width = 17
        ws_accounts.column_dimensions["F"].width = 45

        ws_accounts.row_dimensions[1].height = 18
        ws_accounts.row_dimensions[2].height = 25
        ws_accounts.row_dimensions[3].height = 25
        ws_accounts.row_dimensions[4].height = 25
        ws_accounts.row_dimensions[5].height = 25
        ws_accounts.row_dimensions[6].height = 65
        ws_accounts.row_dimensions[7].height = 30


        # --- Création d'une bordure fine ---
        thin_border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )

        # Applique bordure sur certaines lignes spécifiques
        # (exemple : si vous voulez border la ligne 2, etc.)
        for cell in ws_accounts[2]:
            cell.border = thin_border

        # Bords + condition Admin sur les lignes 3 à fin
        admin_font = Font(color="0070C0")
        for row in ws_accounts.iter_rows(min_row=3, max_row=ws_accounts.max_row, min_col=1, max_col=6):
            type_compte = row[0].value
            # Couleur bleue si compte Admin
            if type_compte and type_compte.startswith("Admin"):
                for cell in row:
                    cell.font = admin_font
            for cell in row:
                cell.border = thin_border

        # Filtre sur la ligne 7 (en-têtes) et les données qui suivent
        ws_accounts.auto_filter.ref = f"A7:F{ws_accounts.max_row}"

        # Paramètres impression
        ws_accounts.sheet_properties.pageSetUpPr.fitToPage = True
        ws_accounts.page_setup.fitToWidth = 1
        ws_accounts.page_setup.fitToHeight = 0
        ws_accounts.page_setup.paperSize = ws_accounts.PAPERSIZE_A4
        ws_accounts.page_setup.orientation = ws_accounts.ORIENTATION_LANDSCAPE
        ws_accounts.print_title_rows = "7:7"


        # Sauvegarde du fichier
        wb.save(filename)
        return filename




def color_cell_background(cell, hex_color):
    """
    Applique une couleur de fond à une cellule (hex_color sans #, ex: "FF0000")
    """
    shading_elm = parse_xml(r'<w:shd {} w:fill="{}"/>'.format(nsdecls('w'), hex_color))
    cell._tc.get_or_add_tcPr().append(shading_elm)


IMPACT_LEVELS = ["CRITIQUE", "GRAVE", "SIGNIFICATIF", "NEGLIGEABLE"]
VRAISEMBLANCE_LEVELS = ["PEU VRAISEMBLABLE", "VRAISEMBLABLE", "TRÈS VRAISEMBLABLE", "QUASI CERTAIN"]
RISK_MATRIX = [
    ["MOYEN", "ÉLEVÉ", "TRÈS ÉLEVÉ", "TRÈS ÉLEVÉ"],
    ["FAIBLE", "ÉLEVÉ", "ÉLEVÉ", "TRÈS ÉLEVÉ"],
    ["FAIBLE", "MOYEN", "MOYEN", "ÉLEVÉ"],
    ["FAIBLE", "FAIBLE", "FAIBLE", "FAIBLE"],
]
RISK_COLORS = {
    "TRÈS ÉLEVÉ": "FF0000",   # Rouge
    "ÉLEVÉ": "FFC000",        # Orange
    "MOYEN": "FFFF00",        # Jaune
    "FAIBLE": "C4E59F",       # Vert clair
}

# Couleurs des niveaux de correction
CORRECTION_COLORS = {
    "COMPLEXE": "FF0000",     # Rouge
    "RAISONNABLE": "FFC000",  # Orange
    "SIMPLE": "FFFF00",       # Jaune
}

# Couleurs des niveaux d'impact
IMPACT_COLORS = {
    "CRITIQUE": "FF0000",     # Rouge
    "GRAVE": "FFC000",        # Orange
    "SIGNIFICATIF": "FFFF00", # Jaune
    "NEGLIGEABLE": "C4E59F",  # Vert
}

# Couleurs des niveaux de vraisemblance
VRAISEMBLANCE_COLORS = {
    "QUASI CERTAIN": "FF0000",        # Rouge
    "TRÈS VRAISEMBLABLE": "FFC000",   # Orange
    "VRAISEMBLABLE": "FFFF00",        # Jaune
    "PEU VRAISEMBLABLE": "C4E59F",    # Vert clair
}
def get_risk_level(impact, vraisemblance):
    try:
        i = IMPACT_LEVELS.index(impact.upper())
        j = VRAISEMBLANCE_LEVELS.index(vraisemblance.upper())
        return RISK_MATRIX[i][j]
    except ValueError:
        return "INDETERMINÉ"

def color_cell(cell, hex_color):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)

def set_font_white(cell):
    for paragraph in cell.paragraphs:
        for run in paragraph.runs:
            run.font.color.rgb = RGBColor(255, 255, 255)

def add_risk_table(doc, risk_number, point_audite, description_risque, vraisemblance, impact, correction, remediation):
    risque = get_risk_level(impact, vraisemblance)

    risk_color = RISK_COLORS.get(risque, "FFFFFF")
    impact_color = IMPACT_COLORS.get(impact.upper(), "FFFFFF")
    vraisemblance_color = VRAISEMBLANCE_COLORS.get(vraisemblance.upper(), "FFFFFF")
    correction_color = CORRECTION_COLORS.get(correction.upper(), "FFFFFF")

    table = doc.add_table(rows=7, cols=2)
    table.style = 'Table Grid'

    labels = [
        ("R" + str(risk_number), point_audite),
        ("DESCRIPTION DU RISQUE", description_risque),
        ("VRAISEMBLANCE", vraisemblance),
        ("IMPACT", impact),
        ("RISQUE", risque),
        ("CORRECTION", correction),
        ("REMEDIATION", remediation)
    ]

    for idx, (label, value) in enumerate(labels):
        cell_label = table.cell(idx, 0)
        cell_value = table.cell(idx, 1)

        # Vider puis écrire via runs pour gérer le style
        cell_label.text = ""
        cell_value.text = ""

        # Label toujours en gras
        run_label = cell_label.paragraphs[0].add_run(str(label))
        run_label.bold = True

        # Valeur : mettre en gras uniquement le point_audite (ligne 0)
        if idx == 0:
            run_value = cell_value.paragraphs[0].add_run(str(value))
            run_value.bold = True
        else:
            cell_value.paragraphs[0].add_run(str(value))

        # Coloration selon type de ligne
        if label == "RISQUE":
            color_cell(cell_value, risk_color)
            for run in cell_value.paragraphs[0].runs:
                run.bold = True
            if risque == "TRÈS ÉLEVÉ":
                set_font_white(cell_value)
        elif label == "IMPACT":
            color_cell(cell_value, impact_color)
            if impact.upper() == "CRITIQUE":
                set_font_white(cell_value)
        elif label == "VRAISEMBLANCE":
            color_cell(cell_value, vraisemblance_color)
            if vraisemblance.upper() == "QUASI CERTAIN":
                set_font_white(cell_value)
        elif label == "CORRECTION":
            color_cell(cell_value, correction_color)
            if correction.upper() == "COMPLEXE":
                set_font_white(cell_value)

        for run in cell_label.paragraphs[0].runs:
            run.bold = True

    # Largeurs personnalisées
    from docx.shared import Cm
    col_widths = [Cm(3.8), Cm(13)]
    for row in table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = width

    # --- Ajoute le return pour le tableau récapitulatif ---
    return {
        "id": "R" + str(risk_number),
        "point_audite": point_audite,
        "description_risque": description_risque,
        "vraisemblance": vraisemblance,
        "impact": impact,
        "risque": risque,
        "correction": correction
    }




def highlight_text_in_doc(doc, text_to_highlight):
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            if text_to_highlight in run.text:
                # Découpage
                text = run.text
                parts = text.split(text_to_highlight)

                # Supprime le texte actuel du run
                run.text = parts[0]

                # Ajoute un run surligné avec le texte ciblé
                highlight_run = paragraph.add_run(text_to_highlight)
                highlight_run.font.highlight_color = WD_COLOR_INDEX.YELLOW

                # Ajoute le reste du texte après
                if len(parts) > 1:
                    paragraph.add_run(parts[1])

                # Arrête ici si tu assumes un seul surlignage par run
                break

def creer_rapport_word(hostname, version, model, config_lines, version_conform, eol_conform, sauvegardes_conform, usb_conform, result_port_https_admin, is_compliant_https,
                                           sync_fortimanager_result, sync_fortimanager_conform, sync_fortianalyzer_result, sync_fortianalyzer_conform, http_https_result, http_https_conform, admin_result, admin_conform, mfa_result, mfa_conform, deny_implicit_result,
                                           deny_implicit_conform,sdwan_result, sdwan_conform, isdb_result, isdb_conform, cti_result, cti_conform, all_in_rules_result, all_in_rules_conform,
                                           vip_any_result, vip_any_conform, vs_any_result, vs_any_conform, geo_ip_result, geo_ip_conform, ldaps_result, ldaps_conform,
                                           ha_session_pickup_result, ha_session_pickup_conform, ha_cablage_result, ha_cablage_conform, ha_redundance_result, ha_redundance_conform, ha_override_result, ha_override_conform,
                                           utilisation_ssl_result, utilisation_ssl_conform, ike_result, ike_conform, dh_result, dh_conform, algo_result, algo_conform, licence_utm,
                                           dnsfilter_result, dnsfilter_conformity, result_web_filter, conformity_web_filter, av_result, av_conformity, ips_result, ips_conformity,
                                           result_app_control, conformity_app_control, modele_FAP_result, modele_FAP_conform, modele_FAP_list, ssid_result, ssid_conform, ssid_non_conforming_profiles, profiles_utilises,
                                           bande_5ghz_result, bande_5ghz_conform, bande_5ghz_non_conform, darrp_result, darrp_conform, darrp_non_conform, frequency_handoff_result, frequency_handoff_conform,
                                           frequency_handoff_non_conform, tim_result, tim_conform, tim_non_conform, band_result, band_conform, band_non_conform, channel_result, channel_conform, channel_non_conform, sgi_result, sgi_conform, sgi_non_conform,
                                           objets_result, objets_conform, objets_non_utilises, result_profils, conformity_profils, rule_ids_profils, blackhole_result, blackhole_conform, ports_deny_result, ports_deny_conform, fortiguard_result, fortiguard_conform, fortisandbox_result, fortisandbox_conform,
                                           sequence_result, sequence_conform,client_name: str = "", serial_number: str = ""):
    modele = _get_references_path("generique.docx")
    current_time = datetime.now().strftime("%Y-%m-%d-%Hh%Mm%Ss")
    filename = f"{hostname} - Fichier audit Word - {current_time}.docx"

    # Copier le modèle
    shutil.copyfile(modele, filename)
    doc = Document(filename)

    # Remplacer "NOM CLIENT" par la variable client_name
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            if "NOM CLIENT" in run.text:
                run.text = run.text.replace("NOM CLIENT", client_name)

    # --- Ajout du titre 3 "Audit" ---
    titre_para = doc.add_heading("Audit de configuration", level=1)
    doc.add_paragraph("")
    texte1 = doc.add_paragraph().add_run("Caractéristiques :")
    texte1.bold = True
    texte1.font.size = Pt(14)
    doc.add_paragraph("")
    doc.add_paragraph("")

    # Ajout du tableau personnalisé
    table = doc.add_table(rows=7, cols=2)
    table.style = 'Table Grid'

    # En-têtes
    table.cell(0, 0).text = "\nLIBELLE\n"
    table.cell(0, 1).text = "\nVALEUR"

    # Appliquer la couleur fond bleu foncé et texte blanc en gras sur la 1ère ligne
    for cell in table.rows[0].cells:
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        shd = OxmlElement('w:shd')
        shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:color'), 'FED2F2')
        shd.set(qn('w:fill'), '232323')
        tcPr.append(shd)

        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.bold = True
                run.font.color.rgb = RGBColor(0xFE, 0xD2, 0xF2)

    # Extraction des détails HA (si possible)
    try:
        ha_details = extraire_ha_details(config_lines)
    except Exception:
        ha_details = {"ha_present": False}

    doc.add_paragraph('')

    # Remplir les valeurs
    table.cell(1, 0).text = "\nHostname\n"
    table.cell(1, 1).text = "\n" + hostname
    table.cell(2, 0).text = "\nVersion firmware\n"
    table.cell(2, 1).text = "\n" + version
    table.cell(3, 0).text = "\nModèle de FortiGate\n"
    table.cell(3, 1).text = "\n" + model
    table.cell(4, 0).text = "\nNuméro de série\n"
    table.cell(4, 1).text = "\n" + serial_number
    table.cell(5, 0).text = "\nCluster\n"
    table.cell(5, 1).text = "\nOui\n" if ha_details["ha_present"] else "\nNon\n"
    table.cell(6, 0).text = "\nLicences\n"
    table.cell(6, 1).text = "\nEcrire ici l'état des licences\n"

    # Centre le tableau dans la page
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    # Alignement des données de la 1ère colonne à gauche
    for row_idx in range(1, 7):
        cell = table.cell(row_idx, 0)
        for paragraph in cell.paragraphs:
            paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT

    # Alignement des données de la 2ème colonne à gauche
    for row_idx in range(1, 7):
        cell = table.cell(row_idx, 1)
        for paragraph in cell.paragraphs:
            paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT

    # Largeur désirée pour chaque colonne
    col_widths = [Cm(4), Cm(8)]
    for row in table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = width

    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')
    doc.add_paragraph('')


    # --- Ajout des sous parties pour l'audit (partie 3)
    doc.add_paragraph('\n')
    risques = []
    risk_number = 1  # Initialise le compteur de risque
    titre_para = doc.add_heading(" Audit - Système", level=2)
    doc.add_paragraph('')

    titre_para = doc.add_heading(" Version Fortigate", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph("Vérification de la version du firmware FortiOS installée sur le FortiGate afin de "
                      "détecter la présence de vulnérabilités hautes ou critiques connues pouvant compromettre la sécurité du système.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("NON CONFORME" if version_conform else "CONFORME")
    run_status.bold = True
    if not version_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"La version du FortiGate détectée est la version {version}. "
        f"{'Cette version de FortiOS ne comporte à ce jour pas de vulnérabilité haute ou critique connue. ' if not version_conform else 'Cette version de FortiOS comporte à ce jour au moins une vulnérabilité haute ou critique connue.'}"
    )
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Source :").bold = True
    doc.add_paragraph().add_run(
        "https://www.fortiguard.com/psirt")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if version_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Version FortiOS vulnérable",
            description_risque="La version de FortiOS actuelle présente des vulnérabilités hautes et/ou critiques connues qui "
                               "peuvent être exploitées pour compromettre la sécurité du système, entraînant des accès non autorisés ou des interruptions de service. ",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="CRITIQUE",
            correction="SIMPLE",
            remediation = "Mettre à jour la version FortiOS avec le dernier patch sécuritaire"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')


    titre_para = doc.add_heading(" Modèle Fortigate", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph("Vérification que votre modèle de FortiGate bénéficie toujours d’un support actif et des mises à jour fournies par Fortinet.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if eol_conform else "NON CONFORME")
    run_status.bold = True
    if  eol_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
            f"Votre Fortigate est un modèle {model}. "
            + ("Ce modèle bénéficie toujours d'un support actif par Fortinet." if eol_conform else
               "Ce modèle ne bénéficie plus d'un support actif par Fortinet. Nous vous recommandons un trade-up.")
    )
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Source :").bold = True
    doc.add_paragraph().add_run(
        "https://community.fortinet.com/t5/FortiGate/Technical-Tip-Recommended-Release-for-FortiOS/ta-p/227178")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not eol_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Fin du support Fortinet pour le modèle de FortiGate",
            description_risque="Exposition de vos systèmes à un risque accru de bugs et vulnérabilités non corrigés par Fortinet",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation = "Demander un trade-up auprès du service commercial SNS"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Sauvegardes automatiques", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph("Vérification que les options 'set revision-backup-on-logout' et 'set revision-image-auto-backup' sont activées. "
                      "Elles permettent la création automatique de backup de FortiGate lors d'un upgrade ou à chaque logout d'un compte admin."
                      "Ces sauvegardes sont essentielles pour permettre un rollback rapide en cas de dysfonctionnement ou de configuration erronée.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if sauvegardes_conform else "NON CONFORME")
    run_status.bold = True
    if sauvegardes_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"Les sauvegardes automatiques sont correctement configurées." if sauvegardes_conform else
           "Les sauvegardes automatiques ne sont pas correctement configurées.")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not sauvegardes_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Sauvegardes automatiques",
            description_risque="Perte de la configuration du Fortigate en cas de dysfonctionnement, pas de roll-back possible",
            vraisemblance="VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Configurer les sauvegardes automatiques"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Objets sans référence", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification d'objet sans référence. L'absence d'objet sans référence permet de réduire la surface d'exposition ou des risques d'erreur. "
        "Contrôle dans les adresses, groupes d'adresses, VIP, groupes de VIP, Virtuals Serveur, Zones, Utilisateurs, Groupes d'utilisateurs et profils de sécurité. ")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if objets_conform else "NON CONFORME")
    run_status.bold = True
    if objets_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"Absence d'objet sans référence." if objets_conform else
        f"{objets_result}.")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not objets_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Objet sans référence",
            description_risque="Erreur de configuration et augmentation de la surface d'exposition",
            vraisemblance="VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="SIMPLE",
            remediation="Supprimer les objets sans référence"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')


    titre_para = doc.add_heading(" Auto-installation d'image par USB", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification de la désactivation des options ‘set auto-install-config’ et ‘set auto-install-image’. "
        "Si ces fonctionnalités sont actives, un attaquant disposant d’un accès physique pourrait introduire une clé USB contenant un firmware ou une configuration malveillante sur votre FortiGate. "
        "Lors d’un redémarrage de l’équipement, la présence de ces options actives entraînerait l’installation automatique du contenu USB, risquant ainsi le déploiement non autorisé d’une configuration ou d’un système compromettant la sécurité de votre réseau.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if usb_conform else "NON CONFORME")
    run_status.bold = True
    if usb_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"Les options d'auto install par USB sont désactivées." if usb_conform else
        "Les options d'auto install par USB n'ont pas été désactivées.")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not usb_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Auto-installation d'image par USB",
            description_risque="L’auto-installation d'une configuration ou d'un firmware via USB peut permettre à un attaquant local de compromettre le FortiGate et, par effet de propagation, votre réseau.",
            vraisemblance="VRAISEMBLABLE",
            impact="CRITIQUE",
            correction="SIMPLE",
            remediation="Désactiver le paramètre auto install par USB"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Audit - Administration et comptes", level=2)
    doc.add_paragraph('')

    titre_para = doc.add_heading(" Port HTTPS personnalisé", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification que le port HTTPS d’accès administrateur au Fortigate n’est pas laissé sur la valeur par défaut 443.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if is_compliant_https else "NON CONFORME")
    run_status.bold = True
    if is_compliant_https:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{result_port_https_admin}. " if is_compliant_https else
        f"{result_port_https_admin}. "
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not is_compliant_https:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Port HTTPS personnalisé",
            description_risque="L’utilisation du port par défaut expose le FortiGate à des tentatives d’accès plus fréquentes, augmentant les risques de compromission par brute force ou exploitation automatisée",
            vraisemblance="VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Personnaliser le port HTTPS"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Synchronisation avec un FortiManager", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification que votre FortiGate soit configuré avec un FortiManager ou FortiCloud.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if sync_fortimanager_conform else "NON CONFORME")
    run_status.bold = True
    if sync_fortimanager_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{sync_fortimanager_result} " if sync_fortimanager_conform else
        f"{sync_fortimanager_result}. Si vous ne disposez pas d'un FortiManager, nous pouvons rattacher votre FortiGate à notre FortiManager mutualisé."
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not sync_fortimanager_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Synchronisation avec un FortiManager ou FortiCloud",
            description_risque="Capacité diminuée pour répondre rapidement aux incidents et vulnérabilités",
            vraisemblance="VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="SIMPLE",
            remediation="Synchroniser votre FortiGate avec un FortiManager ou FortiCloud"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Synchronisation avec un FortiAnalyzer", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification que votre FortiGate soit configuré avec un FortiAnalyzer.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if sync_fortianalyzer_conform else "NON CONFORME")
    run_status.bold = True
    if sync_fortianalyzer_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{sync_fortianalyzer_result} " if sync_fortianalyzer_conform else
        f"{sync_fortianalyzer_result}. Si vous ne disposez pas d'un FortiAnalyzer, nous pouvons rattacher votre FortiGate à notre FortiAnalyzer mutualisé."
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not sync_fortianalyzer_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Synchronisation avec un FortiAnalyzer",
            description_risque="Manque de visibilité centralisée sur les logs et événements, réduisant la capacité à détecter rapidement les incidents de sécurité",
            vraisemblance="VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="SIMPLE",
            remediation="Synchroniser votre FortiGate avec un FortiAnalyzer"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Durcissement accès administration à votre Fortigate", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Le point audité est la vérification que les services SSH, HTTP et HTTPS sur les interfaces WAN soient désactivés. "
        "En effet, l’accès au pare-feu depuis Internet est critique car un attaquant qui prend la main sur le pare-feu peut "
        "faire des dégâts considérables au sein des SI. Par défaut, les accès HTTP et HTTPS au pare-feu sont activés sur les liens WANs. ")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if http_https_conform else "NON CONFORME")
    run_status.bold = True
    if http_https_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    txt_https = doc.add_paragraph(
        f"{http_https_result}." if http_https_conform else
        f"{http_https_result}"
    )
    txt_https = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not http_https_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Durcissement accès admin",
            description_risque="Tentatives d’accès non autorisées à votre FortiGate depuis Internet",
            vraisemblance="VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Désactiver les services SSH/HTTP/HTTPS sur toutes vos interfaces et IP secondaires WAN. Utiliser une loopback à la place."
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Compte 'Admin' par défaut", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification si le compte 'Admin' par défaut a été supprimé. En effet, les attaquants qui tentent d'accéder à "
        "un système commencent souvent par cibler les comptes par défaut bien connus, comme 'admin'")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if admin_conform else "NON CONFORME")
    run_status.bold = True
    if admin_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{admin_result}." if admin_conform else
        f"{admin_result}"
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not admin_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Compte 'admin' par défaut",
            description_risque="Le compte 'admin' par défaut facilite les accès non autorisés, compromettant la sécurité du FortiGate et du réseau",
            vraisemblance="VRAISEMBLABLE",
            impact="CRITIQUE",
            correction="SIMPLE",
            remediation="Supprimer le compte 'admin' par défaut"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" MFA pour les comptes admins et utilisateurs", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification de la présence de double authentification (MFA) sur les comptes administrateurs et utilisateurs présents dans votre fichier de configuration. "
        "Les comptes distants non synchronisés ne sont pas contrôlés car le FortiGate ne peut pas gérer leur MFA.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if mfa_conform else "NON CONFORME")
    run_status.bold = True
    if mfa_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{mfa_result}." if mfa_conform else
        f"{mfa_result}"
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not mfa_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="MFA pour les comptes admins et users locaux",
            description_risque="Tentatives d’accès non autorisées à votre FortiGate, réseau et données",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="CRITIQUE",
            correction="SIMPLE",
            remediation="Utiliser de la MFA sur l'ensemble des comptes admins et users"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')


    titre_para = doc.add_heading(" Audit - Réseaux et flux", level=2)
    doc.add_paragraph('')

    titre_para = doc.add_heading(" Règles en 'By Sequence'", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Contrôle de l'utilisation du 'By Sequence' pour les règles du parefeu. Le principal avantage est de permettre un contrôle précis "
        "de l’ordre d’évaluation, en positionnant d’abord les règles les plus restrictives pour bloquer rapidement les menaces, "
        "puis les plus permissives pour autoriser le trafic souhaité, optimisant ainsi la sécurité et les performances du pare-feu.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if sequence_conform else "NON CONFORME")
    run_status.bold = True
    if sequence_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{sequence_result}." if sequence_conform else
        f"{sequence_result}"
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not sequence_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Règles en By Sequence",
            description_risque="Les règles peuvent être mal ordonnées et laisser passer du traffic indésirable",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Utiliser le 'By Sequence' pour les règles"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Logs sur la règle implicit deny", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Activation des logs pour la règle 'implicit deny' afin d’assurer la journalisation des flux "
        "réseau bloqués par défaut. Ces logs permettent d'avoir une visibilité essentielle sur "
        "les tentatives d’accès non autorisées. Par défaut, ils sont désactivés.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if deny_implicit_conform else "NON CONFORME")
    run_status.bold = True
    if deny_implicit_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{deny_implicit_result}." if deny_implicit_conform else
        f"{deny_implicit_result}"
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not deny_implicit_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Logs implicit deny",
            description_risque="Manque de visibilité sur les flux bloqués, réduisant la capacité à détecter rapidement les incidents de sécurité",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Activer les logs sur la règle implicit deny"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Utilisation du SD-WAN", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Contrôle de l'utilisation du SD-WAN. "
        "Le SD-WAN a plusieurs avantages tels que l'optimisation de la bande passante, le load balancing des liens et l'amélioration des performances. "
        "En cas d'un seul lien WAN, une configuration SD-WAN anticipée permet une flexibilité renforcée en cas d'ajout postérieur de nouveaux liens WAN.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if sdwan_conform else "NON CONFORME")
    run_status.bold = True
    if sdwan_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{sdwan_result}. " if sdwan_conform else
        f"{sdwan_result}. "
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not sdwan_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Utilisation du SD-WAN",
            description_risque="Mauvaise répartition de la charge, dégradation des performances réseau et une moindre résilience en cas d’ajout de nouveaux liens WAN",
            vraisemblance="VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="RAISONNABLE",
            remediation="Utiliser le SD-WAN et y configurer tous vos liens WANs"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Blocage des ISDB malveillants", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Les ISDB (Internet Service Database) sont des bases complètes d’adresses IP qui regroupe les plages d’adresses IP, les propriétaires d’IP,"
        " les numéros de ports de service ainsi que la crédibilité en matière de sécurité des adresses IP. Les données proviennent du système de services FortiGuard. "
        "Des informations y sont régulièrement ajoutées, telles que la localisation géographique, la réputation des adresses IP, leur popularité, les enregistrements DNS, et ainsi de suite. "
        "Fortinet distingue des ISDB malveillants, qui peuvent être bloqués dans les deux directions (source et destination) pour certains. "
        "Voici une liste des ISDB malveillants qui doivent être bloqués pour les flux utilisant un WAN :"
        )
    doc.add_paragraph('')
    doc.add_picture(_get_references_path('ISDB.png'), width=Inches(5.5))
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if isdb_conform else "NON CONFORME")
    run_status.bold = True
    if isdb_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    txt_isdb = doc.add_paragraph(
        f"{isdb_result}. " if isdb_conform else
        f"{isdb_result}. "
    )
    txt_isdb.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not isdb_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Blocage des ISDB malveillants",
            description_risque="En l'absence de blocage des ISDB malveillants pour tous les sens de flux utilisant un WAN, il y a un risque accru de compromission "
                               "de vos systèmes d'information par des communications avec des infrastructures malicieuses (scanners, botnets, phishing), "
                               "pouvant conduire à une exfiltration de données.",
            vraisemblance="VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Bloquer l'ensemble des ISDB malveillants pour tous les sens de flux utilisant un WAN"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Filtrage des ports vers Internet", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    txt_ports_ouvert = doc.add_paragraph(
        "Filtrage des ports au strict minimum pour les flux vers Internet. "
        "Pourquoi limiter les ports ouverts ?                       "
        "1) Surface d’attaque réduite : plus il y a de ports ouverts, plus il y a de services accessibles et donc de points d'entrée potentiels pour les attaquants. Chaque port ouvert représente un service qui pourrait être exploité s'il est vulnérable ou mal configuré.\n"
        "2) Moins de risques d’exploitation de vulnérabilités : des malwares et vers comme WannaCry attaquent des ports spécifiques (SMB/445 par exemple). Garder ces ports ouverts augmente la probabilité que ces attaques réussissent.\n"
        "3) Limiter l’exposition des données : certains protocoles non chiffrés (ex. FTP) exposent les informations sensibles transitant sur le réseau. Filtrer les ports prévient l’exfiltration de données. ")
    txt_ports_ouvert.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if all_in_rules_conform else "NON CONFORME")
    run_status.bold = True
    if all_in_rules_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    txt_ports_ouverts = doc.add_paragraph(
        f"{all_in_rules_result}. " if all_in_rules_conform else
        f"{all_in_rules_result}. "
    )
    txt_ports_ouverts = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not all_in_rules_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Filtrage des ports vers Internet",
            description_risque="Ouvrir trop de ports sur un pare-feu expose le réseau à des attaques, "
                               "exploitations de vulnérabilités, intrusions non autorisées, propagation de malwares et rend la détection des menaces plus difficile.",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="RAISONNABLE",
            remediation="Filtrer les ports au minimum pour les flux à destination d'Internet"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Absence de VIP en ANY", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Les VIP (Virtual IP) sont utilisées lorsqu’on veut faire rentrer du flux de l’extérieur vers l’interne à destination d'un serveur par exemple. "
        "Si les VIP sont en écoute sur 'ANY', le Fortigate ne sait pas sur quelle interface appliquer le NAT pour le trafic sortant. "
        "Il risque d’utiliser l’adresse IP source de la VIP pour effectuer le NAT à la place de l’adresse IP publique normale du wan. "
        "Ça peut provoquer un NAT non désiré : si une ressource interne (par exemple, 10.0.0.1) sort vers Internet, Fortigate peut alors « natter » "
        "(changer) cette adresse source avec l'adresse de la VIP au lieu de l’adresse publique attendue. Cela peut causer des problèmes d’accès, d’identification "
        "et de fonctionnement vers l’extérieur. Sauf cas particulier et mesuré, il est préférable de sélectionner une interface (et donc éviter le ANY) pour éviter ces effets de bords. ")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if vip_any_conform else "NON CONFORME")
    run_status.bold = True
    if vip_any_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{vip_any_result}. " if vip_any_conform else
        f"{vip_any_result}. "
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not vip_any_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Absence de VIP en ANY",
            description_risque="Dysfonctionnement du NAT sur le Fortigate",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="SIMPLE",
            remediation="Ne pas utiliser de ANY sur les VIP"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Absence de Virtual Server en ANY", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Les Virtuals Servers sont utilisées lorsqu’on veut faire rentrer du flux de l’extérieur vers l’interne à destination d'un serveur via un LOAD BALANCER. "
        "Si les Virtuals Servers sont en écoute sur 'ANY', le Fortigate ne sait pas sur quelle interface appliquer le NAT pour le trafic sortant. "
        "Il risque d’utiliser l’adresse IP source des Virtuals Servers pour effectuer le NAT à la place de l’adresse IP publique normale du wan. "
        "Ça peut provoquer un NAT non désiré : si une ressource interne (par exemple, 10.0.0.1) sort vers Internet, Fortigate peut alors « natter » "
        "(changer) cette adresse source avec l'adresse des Virtuals Servers au lieu de l’adresse publique attendue. Cela peut causer des problèmes d’accès, d’identification "
        "et de fonctionnement vers l’extérieur. Sauf cas particulier et mesuré, il est préférable de sélectionner une interface (et donc éviter le ANY) pour éviter ces effets de bords. "
        "Toutefois, deux situations sont acceptables avec du ANY en interface externe : 1) lorsque l’adresse IP externe du Virtual Server se trouve dans le même subnet que les real servers (ressources internes),"
        " 2) lorsqu'il y a plusieurs interfaces dans les règles de parefeu. ")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if vs_any_conform else "NON CONFORME")
    run_status.bold = True
    if vs_any_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    txt_vs = doc.add_paragraph(
        f"{vs_any_result}. " if vs_any_conform else
        f"{vs_any_result}. "
    )
    txt_vs = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not vs_any_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Absence de Virtual Server en ANY",
            description_risque="Dysfonctionnement du NAT sur le Fortigate",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="SIMPLE",
            remediation="Eviter d'utiliser ANY en interface externe des Virtuals Servers"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Utilisation de la GEO-IP", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    txt_geoip = doc.add_paragraph(
        "FortiGuard a un service « GeoIP » qui est une base de données permettant d’identifier le pays d’origine d’une adresse IP.\n "
        "Cette base de données est régulièrement mise à jour afin d’assurer sa précision et sa pertinence. Ce service permet de filtrer les flux entrants de deux façons :\n"
        "- Autoriser uniquement certains pays considérés comme sources de confiance, par exemple la France, à interagir avec les SI.\n"
        "- Bloquer d’office certains pays d’où proviennent fréquemment des attaques (ex : Corée du Nord, Russie, Chine, Iran).\n"
        "Ce filtrage doit être utilisé avec prudence pour éviter de bloquer de manière inappropriée des utilisateurs légitimes ou des partenaires commerciaux.")
    txt_geoip.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if geo_ip_conform else "NON CONFORME")
    run_status.bold = True
    if geo_ip_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    txt_geoip_r = doc.add_paragraph(
        f"{geo_ip_result} " if geo_ip_conform else
        f"{geo_ip_result} "
    )
    txt_geoip_r = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not geo_ip_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Utilisation de la fonction GEO-IP",
            description_risque="Exposition de vos réseaux à un risque accru d’attaques provenant de zones géographiques non maîtrisées ou hostiles",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="GRAVE",
            correction="RAISONNABLE",
            remediation="Utiliser de la GEO-IP"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Utilisation de nos CTI", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "L’utilisation de nos sources de Cyber Threat Intelligence (CTI) permet de renforcer significativement la protection du système d’information "
        "en élargissant le spectre de détection et de blocage. En complément des ISDB Fortinet, notre CTI consolide les flux issus de la base SNS et de "
        "plusieurs acteurs majeurs de la cybersécurité, garantissant une vision actualisée et enrichie de la menace. Elle intègre des indicateurs"
        " techniques tels que les adresses IP, les noms de domaine et les hachages de malwares, permettant d’identifier "
        "et de bloquer de manière proactive les services indésirables sur les flux entrants comme sortants. Cette approche réduit la surface "
        "d’exposition et offre une meilleure capacité à anticiper, détecter et stopper les attaques avant qu’elles ne compromettent vos infrastructures. "
        "Capture d'écran de nos connecteurs CTI :"
    )
    doc.add_paragraph('')
    doc.add_picture(_get_references_path('CTI.png'), width=Inches(6.7))
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if cti_conform else "NON CONFORME")
    run_status.bold = True
    if cti_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    txt_CTI = doc.add_paragraph(
        f"{cti_result}. " if cti_conform else
        f"{cti_result}. "
    )
    txt_CTI = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not cti_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Utilisation de nos CTI",
            description_risque="Sans nos CTI sur l'ensemble des sens de flux utilisant un WAN, certaines menaces (IP et domaines malveillants, malwares) ne sont pas détectées, augmentant le risque de compromission.",
            vraisemblance="VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Utiliser nos CTI pour tous les sens de flux utilisant un WAN"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Logs en UTM sans profil de sécurité", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Recherche de règles avec logs en UTM sans profils de sécurité activés. Les logs en UTM n'enregistrent que les flux qui matchent les profils de sécurité. Ainsi, régler les logs en UTM sans configurer des profils de sécurité revient à n'avoir aucun log de flux.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if conformity_profils else "NON CONFORME")
    run_status.bold = True
    if conformity_profils:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{result_profils}")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not conformity_profils:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Logs en UTM sans profil de sécurité",
            description_risque="Absence de traçabilité des actions et opérations",
            vraisemblance="QUASI CERTAIN",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Effectuer une revue des réglages des logs / profils de sécurité dans les règles concernées"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Route Blackhole pour les réseaux privés", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Nous recommandons la mise en place d'une route Blackhole pour les réseaux privés sauf si vous avez un lien MPLS ou L2L. Elle permet de s'aligner sur la RFC 6890 et d'empêcher des fuites de paquets privés vers Internet.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if blackhole_conform else "NON CONFORME")
    run_status.bold = True
    if blackhole_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{blackhole_result}." if blackhole_conform else
        f"{blackhole_result}.")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not blackhole_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Route Blackhole pour les réseaux privés",
            description_risque="Fuite de paquets privés vers Internet",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="SIGNIFICATIF",
            correction="SIMPLE",
            remediation="Mettre en place une blackhole pour les réseaux privés"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    titre_para = doc.add_heading(" Ports-Deny vers Internet", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Nous recommandons le blocage de certains ports pour les flux à destination d'Internet : KERBEROS, LDAP, LDAPS, RADIUS, SAMBA, SMB. ")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if ports_deny_conform else "NON CONFORME")
    run_status.bold = True
    if ports_deny_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{ports_deny_result}." if ports_deny_conform else
        f"{ports_deny_result}.")
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not ports_deny_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Ports-Deny vers Internet",
            description_risque="Risque accru d'accès non autorisé et de compromission",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="GRAVE",
            correction="SIMPLE",
            remediation="Bloquer les ports recommandés par SNS"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')

    if ldaps_conform != "N/A":
        titre_para = doc.add_heading(" Utilisation du LDAPS", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Utilisation du LDAPS avec certificat pour les connecteurs AD. Le LDAPS permet un chiffrement des données, offrant une protection accrue contre les interceptions malveillantes.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ldaps_conform == "Oui" else "NON CONFORME")
        run_status.bold = True
        if ldaps_conform == "Oui":
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{ldaps_result}. "
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if ldaps_conform == "Non":
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation du LDAPS",
                description_risque="Interception des données utilisateur car elles transitent en clair sur le réseau en cas d'utilisation de LDAP (et non LDAPS)",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Utiliser un connecteur LDAPS avec certificat"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

    if ha_details["ha_present"]:
        titre_para = doc.add_heading(" Audit - Cluster", level=2)
        doc.add_paragraph('')
        titre_para = doc.add_heading(" Session pickup", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification si les options 'session pickup' sont activées. Le session 'session pickup' permet de minimiser les interruptions de communication, évitant de devoir redémarrer les sessions actives."
            " \nPérimètre des 3 options : 'set session-pickup' = sessions TCP, 'session-pickup-connectionless' = sessions UDP, 'session-pickup-expectation' = sessions dynamiques (FTP, SIP, etc).  "
            )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ha_session_pickup_conform else "NON CONFORME")
        run_status.bold = True
        if ha_session_pickup_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_sessionpickup = doc.add_paragraph(
            f"{ha_session_pickup_result}." if ha_session_pickup_conform else
            f"{ha_session_pickup_result}"
        )
        txt_sessionpickup = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ha_session_pickup_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="HA / Cluster : Session pickup",
                description_risque="Interruptions des sessions en cas de bascule, il faut redémarrer manuellement les sessions.",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="SIMPLE",
                remediation="Activer les options session pickup"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Redondance du câblage", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification si le câblage est redondé entre les FortiGate. Permet d'assurer une continuité des flux en cas de bascule."
            " Veuillez noter qu'il faut effectuer régulièrement des tests de bascule afin de s'assurer du correct fonctionnement de votre redondance."
        )
        doc.add_paragraph('')

        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True

        run_status = txt.add_run("CONFORME" if ha_cablage_conform else "NON CONFORME")
        run_status.bold = True
        if ha_cablage_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000

        txt_redondance_HA = doc.add_paragraph(
            f"{ha_cablage_result}." if ha_cablage_conform else f"{ha_cablage_result}"
        )
        txt_redondance_HA.alignment = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ha_cablage_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="HA / Cluster : Redondance du câblage",
                description_risque="En cas de bascule HA, sans redondance complète, certains flux ne pourront plus fonctionner. "
                                   "Peut impacter la haute disponibilité et la continuité de service. ",
                vraisemblance="VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Redonder complètement le câblage entre les FortiGate"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Redondance des interfaces de HA", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification si les interfaces de HA sont redondées avec au minimum 2 heartbeats. Permet d'assurer la redondance pour la synchronisation du cluster.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ha_redundance_conform else "NON CONFORME")
        run_status.bold = True
        if ha_redundance_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_sessions_pickup = doc.add_paragraph(
            f"{ha_redundance_result}." if ha_redundance_conform else
            f"{ha_redundance_result}"
        )
        txt_sessions_pickup.alignment = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ha_redundance_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="HA / Cluster : Redondance des interfaces HA",
                description_risque="La présence d'une redondance insuffisante des interfaces HA (moins de 2 heartbeats) expose le cluster à un risque accru de "
                                   "défaillance du lien de synchronisation entre les membres. En cas de panne d’une interface unique, "
                                   "l'absence de lien alternatif peut entraîner une perte de la synchronisation, provoquant une indisponibilité"
                                   " du cluster ou un basculement intempestif, impactant la haute disponibilité et la continuité de service. ",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="SIMPLE",
                remediation="Mettre au moins 2 heartbeat"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Override à 30 secondes ou désactivé", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Si l'override est activée, mettre la durée d'attente à 30 secondes est un compromis entre stabilité et réactivité. Sinon, l'override peut être désactivé.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ha_override_conform else "NON CONFORME")
        run_status.bold = True
        if ha_override_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{ha_override_result}." if ha_override_conform else
            f"{ha_override_result}"
        )
        doc.add_paragraph('')
        doc.add_paragraph('')
        doc.add_paragraph("Voici l'ordre de négociation primaire/secondaire en fonction si l'override est actif ou non :")
        doc.add_paragraph('')
        doc.add_picture(_get_references_path('cluster.png'), width=Inches(6.5))
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ha_override_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="HA / Cluster : Override",
                description_risque="Avec un override trop faible : si le fortigate revient trop rapidement en ligne après une panne ou reboot, il peut reprendre le contrôle avant que la synchronisation complète des sessions et des tables de routage ne soit effectuée. "
                                   "Avec un override trop élevé : délai de reprise excessif et/ou perte d'efficacité opérationnelle. ",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="SIMPLE",
                remediation="Configurer l'override sur 30 secondes ou le désactiver"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')


    titre_para = doc.add_heading(" Audit - Connexions distantes : VPN", level=2)
    doc.add_paragraph('')

    titre_para = doc.add_heading(" Utilisation du VPN SSL", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Contrôle de la non-utilisation du VPN SSL.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if utilisation_ssl_conform else "NON CONFORME")
    run_status.bold = True
    if utilisation_ssl_conform:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        f"{utilisation_ssl_result}." if utilisation_ssl_conform else
        f"{utilisation_ssl_result}"
    )
    doc.add_paragraph('')
    doc.add_paragraph('')

    if not utilisation_ssl_conform:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Utilisation du VPN SSL",
            description_risque="Continuer à utiliser le VPN SSL du FortiGate après sa dépréciation vous expose à un risque critique de compromission complète,"
                               " avec régulièrement des vulnérabilités découvertes, des campagnes d'attaques zero-day actives exploitant des failles de "
                               "contournement d'authentification, et l'absence totale de support technique à partir de FortiOS 7.6.3, transformant cette technologie"
                               " en porte d'entrée privilégiée pour les cybercriminels.",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="CRITIQUE",
            correction="RAISONNABLE",
            remediation="Migrer le VPN SSL vers de l'IPSEC Nomade"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')


    if not ike_result == "Absence de tunnel IPSEC configuré":
        titre_para = doc.add_heading(" Durcissement des VPN IPSEC : contrôle IKE", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "IKE (Internet Key Exchange) est le protocole chargé d’établir les Security Associations (SA), "
            "c’est-à-dire les paramètres cryptographiques utilisés pour créer un tunnel IPSEC sécurisé. "
            "Il fonctionne en deux phases pour négocier et établir les clés de chiffrement. Deux versions coexistent : IKEv1 et IKEv2. "
            "L’ANSSI et la plupart des référentiels de sécurité recommandent l’utilisation exclusive de IKEv2, "
            "qui simplifie les échanges, corrige des vulnérabilités connues dans IKEv1 et améliore la gestion des erreurs.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ike_conform else "NON CONFORME")
        run_status.bold = True
        if ike_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{ike_result}." if ike_conform else
            f"{ike_result}"
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ike_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Durcissement des VPN IPSEC : contrôle IKE",
                description_risque="L’utilisation d’IKEv1 expose à des vulnérabilités connues, notamment des attaques de "
                                   "type Man-in-the-Middle ou de déni de service, en raison de faiblesses dans la négociation des clés. "
                                   "Cela compromet directement la confidentialité et l’intégrité des communications.",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="SIMPLE",
                remediation="Utiliser IKE V2"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Durcissement des VPN IPSEC : contrôle DH Group", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Le processus d’échange de clés est réalisé avec des groupes 'Diffie-Hellman'. "
            "C’est un algorithme de chiffrement asymétrique qui permet d’échanger de manière sécurisée une clé cryptographique entre deux parties. "
            "Les groupes numérotés plus élevés offrent une sécurité accrue, toutefois leur création nécessite davantage de temps. "
            "Ainsi, en fonction des performances du réseau, il est possible d’opter pour un groupe plus ou moins élevé. "
            "Nous recommandons d'utiliser au minimum le groupe 14 qui corresponds à une longueur de clé de 2048 bits.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if dh_conform else "NON CONFORME")
        run_status.bold = True
        if dh_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{dh_result}." if dh_conform else
            f"{dh_result}"
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not dh_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Durcissement des VPN IPSEC : contrôle DH Group",
                description_risque="L’utilisation d’un groupe Diffie-Hellman inférieur à 14 (par ex. groupes 1, 2 ou 5) "
                                   "réduit considérablement la sécurité du tunnel et peut permettre à un attaquant de casser "
                                   "la clé échangée par force brute ou par attaques sur la base de pré-calculs connus.",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="SIMPLE",
                remediation="Utiliser au minimum le groupe DH 14"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Durcissement des VPN IPSEC : ESP et algorithmes", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "L’ESP (Encapsulating Security Payload) est le protocole assurant confidentialité, intégrité et authentification des données dans IPSEC. "
            "Il repose sur des algorithmes de chiffrement symétrique (DES, 3DES, AES128/192/256) et fonctions de hachage "
            "pour l’intégrité et l’authenticité (MD5, SHA1, SHA2). Parmi ces options, DES, 3DES et MD5 sont obsolètes"
            " et ne doivent plus être utilisés. Nous recommandons AES256 pour le chiffrement et SHA256 "
            " pour l’intégrité, considérés comme le bon équilibre entre robustesse et performance.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if algo_conform else "NON CONFORME")
        run_status.bold = True
        if algo_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{algo_result}." if algo_conform else
            f"{algo_result}"
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not algo_conform :
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Durcissement des VPN IPSEC : contrôle des algorithmes",
                description_risque="L’utilisation d’algorithmes obsolètes comme DES, 3DES, MD5 ou SHA1 expose le tunnel "
                                   "à une compromission rapide des échanges (faible entropie, collisions cryptographiques "
                                   "ou attaques différentielles). Cela remet directement en cause la confidentialité des communications.",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="SIMPLE",
                remediation="Utiliser au moins AES256 et SHA256 pour les algorithmes ESP"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

    titre_para = doc.add_heading(" Audit - Profils de sécurité UTM", level=2)
    doc.add_paragraph('')

    titre_para = doc.add_heading(" Vérification de la licence UTM", level=3)
    doc.add_paragraph('')
    doc.add_paragraph().add_run("Point audité :").bold = True
    doc.add_paragraph(
        "Vérification que la licence UTM est toujours valide. La licence UTM permet d'utiliser des profils de sécurité.  Sans cette licence, le Fortigate ne "
                      "peut pas accéder aux bases de données de Fortiguard lui permettant d’analyser les flux.")
    doc.add_paragraph('')
    txt = doc.add_paragraph()
    run_result = txt.add_run("Résultat : ")
    run_result.bold = True
    run_status = txt.add_run("CONFORME" if licence_utm else "NON CONFORME")
    run_status.bold = True
    if licence_utm:
        run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
    else:
        run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
    doc.add_paragraph(
        "La licence UTM est valide." if licence_utm else "Le Fortigate ne dispose pas d'une licence UTM valide."
    )
    doc.add_paragraph('')
    doc.add_paragraph("L'exécution des principaux profils de sécurité se déroule dans cet ordre : ")
    doc.add_picture(_get_references_path('Security_profiles.png'), width=Inches(6.7))
    doc.add_paragraph('')
    doc.add_paragraph(
        "Tous les profils de sécurité ne doivent pas être configurés sur toutes les règles. Il faut distinguer le sens des flux :")

    doc.add_paragraph('')
    # Ajout du tableau personnalisé
    table = doc.add_table(rows=6, cols=3)
    table.style = 'Table Grid'

    # En-têtes
    table.cell(0, 0).text = "\nProfil de sécurité\n"
    table.cell(0, 1).text = "\nFlux entrant (vers réseau interne)\n"
    table.cell(0, 2).text = "\nFlux sortant (vers Internet)\n"

    # Appliquer la couleur #DBE5F1 sur la première ligne
    for cell in table.rows[0].cells:
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        shd = OxmlElement('w:shd')
        shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:color'), 'auto')
        shd.set(qn('w:fill'), 'DBE5F1')
        tcPr.append(shd)

    doc.add_paragraph('')
    # Remplir les valeurs
    table.cell(1, 0).text = "\nFiltre DNS\n"
    table.cell(1, 1).text = "\nNon\n"
    table.cell(1, 2).text = "\nOui\n"
    table.cell(2, 0).text = "\nFiltre Web\n"
    table.cell(2, 1).text = "\nNon\n"
    table.cell(2, 2).text = "\nOui\n"
    table.cell(3, 0).text = "\nAntivirus\n"
    table.cell(3, 1).text = "\nOui\n"
    table.cell(3, 2).text = "\nOui\n"
    table.cell(4, 0).text = "\nIPS\n"
    table.cell(4, 1).text = "\nOui\n"
    table.cell(4, 2).text = "\nOui\n"
    table.cell(5, 0).text = "\nApplication Control\n"
    table.cell(5, 1).text = "\nOui\n"
    table.cell(5, 2).text = "\nOui\n"

    table.alignment = WD_TABLE_ALIGNMENT.CENTER  # centre le tableau dans la page

    # Mettre un peu de gras sur l'entête
    for i in range(3):
        for paragraph in table.cell(0, i).paragraphs:
            for run in paragraph.runs:
                run.bold = True

    # Alignement des données de la 1ère colonne à gauche
    for row_idx in range(0, 6):
        cell = table.cell(row_idx, 0)
        for paragraph in cell.paragraphs:
            paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT

    doc.add_paragraph('')

    if not licence_utm:
        risque = add_risk_table(
            doc,
            risk_number,
            point_audite="Vérification de la licence UTM",
            description_risque="En cas de licence UTM expirée, vous perdez une couche de sécurité précieuse. Cela provoque une augmentation du risque de compromission de vos réseaux et données.",
            vraisemblance="TRÈS VRAISEMBLABLE",
            impact="GRAVE",
            correction="RAISONNABLE",
            remediation="Commander une licence UTM auprès du service commercial SNS"
        )
        risques.append(risque)
        risk_number += 1
        doc.add_paragraph('')
        doc.add_paragraph('')


    if licence_utm:
        titre_para = doc.add_heading(" Mises à jour FortiGuard", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run(" Point audité :").bold = True
        doc.add_paragraph(
            "Vérification que les mises à jour automatiques des bases AV + IPS (FortiGuard) soient configurées sur 'automatic'. Ce réglage permet de recevoir plus rapidement les mises à jour critiques. ")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if fortiguard_conform else "NON CONFORME")
        run_status.bold = True
        if fortiguard_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_dns = doc.add_paragraph(
            f"{fortiguard_result}." if fortiguard_conform else
            f"{fortiguard_result}."
        )
        txt_dns = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not fortiguard_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Mises à jour FortiGuard",
                description_risque="Retard dans la mise à jour des bases critiques, provoquant une baisse temporaire du niveau de sécurité de votre réseau",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="SIMPLE",
                remediation="Configurer les mises à jour FortiGuard sur 'Automatic'"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

    if licence_utm:
        titre_para = doc.add_heading(" FortiSandbox Cloud", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run(" Point audité :").bold = True
        doc.add_paragraph(
            "Contrôle de l'activation et du paramétrage de la FortiSandbox Cloud. Cette sandbox permet de bloquer des fichiers suspects sans impacter la performance du FortiGate.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if fortisandbox_conform else "NON CONFORME")
        run_status.bold = True
        if fortisandbox_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_dns = doc.add_paragraph(
            f"{fortisandbox_result}." if fortisandbox_conform else
            f"{fortisandbox_result}."
        )
        txt_dns = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not fortisandbox_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="FortiSandbox Cloud",
                description_risque="Sans la FortiSandbox Cloud, augmentation des vulnérabilités aux attaques zero day et menaces avancées que les signatures classiques du FortiGate ne peuvent pas détecter",
                vraisemblance="VRAISEMBLABLE",
                impact="GRAVE",
                correction="SIMPLE",
                remediation="Activer et configurer la FortiSandbox Cloud"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

    if licence_utm:
        titre_para = doc.add_heading(" Utilisation du DNS-Filter", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run(" Point audité :").bold = True
        doc.add_paragraph(
            "Vérification de l'utilisation de la fonction DNS Filter. Ce filtrage offre plusieurs fonctionnalités pour améliorer la sécurité et la gestion du réseau. "
            "Il inclut le filtrage FortiGuard, qui évalue les requêtes DNS basées sur les notations de domaine de FortiGuard, le filtrage CTI et le blocage de botnets connus. "
            "Il permet également de personnaliser le filtrage par catégories de domaines, d'appliquer des recherches sécurisées pour le contrôle parental et de créer "
            "des listes personnalisées de domaines ou d'IP à bloquer. ")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if dnsfilter_conformity else "NON CONFORME")
        run_status.bold = True
        if dnsfilter_conformity:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_dns = doc.add_paragraph(
            f"{dnsfilter_result}." if dnsfilter_conformity else
            f"{dnsfilter_result}."
        )
        txt_dns = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not dnsfilter_conformity:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation du DNS-Filter",
                description_risque="Risque de compromission",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Utiliser le DNS Filter et le durcir conformément à nos préconisations"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Utilisation du Web-Filter", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification de l'utilisation de la fonction Web-filter. Les Filtres Web restreignent ou contrôlent les accès des utilisateurs aux ressources web. "
            "Fortinet distingue plusieurs catégories telles que « contenu adulte », « consommateur de bande passante », « risques pour la sécurité » "
            "(ex : sites de phishing). Chaque catégorie contient des sites ou des pages qui ont été catégorisés par rapport à leur contenu dominant. ")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if conformity_web_filter else "NON CONFORME")
        run_status.bold = True
        if conformity_web_filter:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_web_filter = doc.add_paragraph(
            f"{result_web_filter}." if conformity_web_filter else
            f"{result_web_filter}."
        )
        txt_web_filter = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not conformity_web_filter:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation du Web-Filter",
                description_risque="Risque de compromission (ex : sites de phishing non bloqués), risque de perte de performance (ex : site de consommateur de bande passante non bloqué)",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Utiliser le web-filter et le durcir conformément à nos préconisations"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Utilisation de l'Antivirus", level=3)
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Point audité : ")
        run_result.bold = True

        doc.add_paragraph(
            "Vérification de l'utilisation de la fonction antivirus. L’antivirus de FortiGuard permet de défendre les SI contre les menaces les plus récentes, telles que les attaques polymorphes, les virus et les logiciels espions. "
            "Il inspecte le trafic qui transite au travers du Fortigate. Le moteur de cet antivirus utilise des bases de données de FortiGuard pour comparer les "
            "signatures (hash) des virus connus. Il peut également utiliser des bases externes (ex : CTI). En se basant sur le comportement des fichiers, "
            "il est également capable de bloquer des virus dont leur signature n’est pas encore répertoriée comme malveillante. C'est donc une fonction précieuse à ne pas négliger.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()

        run_label = txt.add_run("Résultat : ")
        run_label.bold = True

        run_status = txt.add_run("CONFORME" if av_conformity else "NON CONFORME")
        run_status.bold = True

        if av_conformity:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000

        txt_antivirus = doc.add_paragraph(
            f"{av_result}." if av_conformity else
            f"{av_result}."
        )
        txt_antivirus = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not av_conformity:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation de l'Antivirus",
                description_risque="Risque de compromission par des virus",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Utiliser l'antivirus de FortiGuard et le durcir conformément à nos préconisations"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Utilisation de l'IPS", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification de l'utilisation de la fonction IPS (Système de Prévention d'Intrusion). Ce système permet de détecter des attaques réseaux "
            "et de les bloquer. L'IPS utilise des signatures, des décodeurs de protocole, l'heuristique (ou la surveillance comportementale), "
            "l'intelligence des menaces (comme celle de FortiGuard Labs) et la détection avancée des menaces pour prévenir l'exploitation des menaces"
            " connues et inconnues, y compris les attaques de jour zéro (zero-day).")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ips_conformity else "NON CONFORME")
        run_status.bold = True
        if ips_conformity:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_ips = doc.add_paragraph(
            f"{ips_result}." if ips_conformity else
            f"{ips_result}."
        )
        txt_ips = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ips_conformity:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation de l'IPS",
                description_risque="Risque de compromission accru",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Utiliser l'IPS et le durcir conformément à nos préconisations"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        titre_para = doc.add_heading(" Utilisation de l'Application Control", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification de l'utilisation de la fonction Application Control. Ce profil de sécurité permet de monitorer ou de bloquer l’utilisation "
            "d’applications qui vont à l’encontre d’une politique de sécurité. Par exemple, une entreprise peut choisir de bloquer l'accès à des "
            "applications de partage de fichiers pour limiter le vol de données. Nous recommandons de bloquer à minima les catégories suivantes : Proxy, Remote.Access et P2P. "
            "Si vous avez des besoins par rapport à ces catégories, exemple utilisation de Anydesk, vous pouvez ajouter l'application désirée en exception.")
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if conformity_app_control else "NON CONFORME")
        run_status.bold = True
        if conformity_app_control:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_app_control = doc.add_paragraph(
            f"{result_app_control}." if conformity_app_control else
            f"{result_app_control}."
        )
        txt_app_control = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not conformity_app_control:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation de l'Application Control",
                description_risque="Risque de compromission accru",
                vraisemblance="TRÈS VRAISEMBLABLE",
                impact="GRAVE",
                correction="RAISONNABLE",
                remediation="Utiliser l'Application Control et bloquer au moins les catégories suivantes : Proxy, Remote.Access et P2P"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')


    if  profiles_utilises:
        titre_para = doc.add_heading(" Audit - WIFI", level=2)
        doc.add_paragraph('')
        titre_para = doc.add_heading(" Modèle de FAP", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification des modèles de FAP utilisés. Contrôle de l'obsolescence. "
            "Anticiper le renouvellement des FortiAP permet d'éviter les interruptions de service liées aux "
            "incompatibilités suite aux mises à jour majeures du FortiGate."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if modele_FAP_conform else "NON CONFORME")
        run_status.bold = True
        if modele_FAP_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_fap = doc.add_paragraph(
            f"{modele_FAP_result}." if modele_FAP_conform else f"{modele_FAP_result}"
        )
        txt_fap = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not modele_FAP_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Modèle de FortiAP - Prévention de l'obsolescence",
                description_risque="Risques d’interruption de service dus à l’obsolescence des FortiAP",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation="Renouveler les FortiAP proches de l'obsolescence : " + ", ".join(modele_FAP_list)
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Nombre de SSID par profil WIFI
        titre_para = doc.add_heading(" Nombre de SSID par profil WIFI", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Contrôle du nombre de SSID par profil WIFI. Avoir plus de 4 SSIDs sur un profil WIFI entraîne une dégradation des performances et une saturation du spectre radio."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if ssid_conform else "NON CONFORME")
        run_status.bold = True
        if ssid_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{ssid_result}." if ssid_conform else ssid_result
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not ssid_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Nombre de SSID par profil WIFI",
                description_risque="Dégradation des performances dues à trop de SSID",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Utiliser moins de 5 SSID pour les profils suivants : {', '.join([f'{p} ({r}: {c} SSID)' for p, r, c in ssid_non_conforming_profiles])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Utilisation de la bande 5GHz sur le canal 40MHz
        titre_para = doc.add_heading(" Utilisation de la bande 5GHz", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Contrôle de l'utilisation de la bande 5GHz sur le canal 40MHz. La bande 5GHz est moins sensible aux interférences,"
            " offre des débits plus élevés et moins de latence."
            " Le canal 40MHz offre le meilleur compromis entre débit et stabilité."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if bande_5ghz_conform else "NON CONFORME")
        run_status.bold = True
        if bande_5ghz_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{bande_5ghz_result}." if bande_5ghz_conform else bande_5ghz_result
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not bande_5ghz_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Utilisation de la bande 5GHz sur le canal 40MHz",
                description_risque="Performance réduite et latence accrue",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join([f'{item['profile']} ({', '.join(item['reasons'])})' for item in bande_5ghz_non_conform])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Activation de l'option 'Radio Resource Provision'
        titre_para = doc.add_heading(" Option 'Radio Resource Provision'", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification si l'option 'Radio Resource Provision' est activée. "
            "Cette option permet une gestion dynamique des ressources radio, améliorant la qualité du signal et réduisant les interférences."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if darrp_conform else "NON CONFORME")
        run_status.bold = True
        if darrp_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{darrp_result}." if darrp_conform else darrp_result
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not darrp_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Option'Radio Resource Provision'",
                description_risque="Qualité du signal et gestion des interférences altérées",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join([f'{profile} ({' et '.join(radios)})' for profile, radios in darrp_non_conform.items()])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Activation de l'option 'Frequency Handoff'
        titre_para = doc.add_heading(" Option 'Frequency Handoff'", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification si l'option 'Frequency Handoff' est activée."
            "Cette option permet d'améliorer le load balancing entre les bandes 2,4GHz et 5GHz."
            "Attention : cette option peut entraîner des déconnexions en cas de réseaux mal conçus (ex : excès de couverture)."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if frequency_handoff_conform else "NON CONFORME")
        run_status.bold = True
        if frequency_handoff_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_frequency = doc.add_paragraph(
            f"{frequency_handoff_result}." if frequency_handoff_conform else frequency_handoff_result
        )
        txt_frequency = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not frequency_handoff_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Option 'Frequency Handoff'",
                description_risque="Déséquilibre du load balancing entre les bandes 2,4GHz et 5GHz",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join(frequency_handoff_non_conform)}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Activation de l'option 'TIM'
        titre_para = doc.add_heading(" Option 'TIM'", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "L'activation de 'TIM' permet une meilleure gestion des économies d'énergie pour les clients connectés, tout en garantissant une connectivité efficace."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if tim_conform else "NON CONFORME")
        run_status.bold = True
        if tim_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_tim = doc.add_paragraph(
            f"{tim_result}." if tim_conform else tim_result
        )
        txt_tim = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not tim_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Option 'TIM'",
                description_risque="Une économie d'énergie insuffisante avec un risque de déconnexion",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join([f'{profile} ({' et '.join(radios)})' for profile, radios in tim_non_conform.items()])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Conformité des canaux radio utilisés
        titre_para = doc.add_heading(" Conformité des canaux radio utilisés", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Utiliser uniquement les trois canaux 1, 6 et 11 permet d’éviter les interférences entre réseaux voisins et d'assurer une transmission stable."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if channel_conform else "NON CONFORME")
        run_status.bold = True
        if channel_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        doc.add_paragraph(
            f"{channel_result}." if channel_conform else channel_result
        )
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not channel_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Conformité des canaux radio utilisés",
                description_risque="Interférences et instabilités radio accrues",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join([f'{profile} ({', '.join([f'{radio} : {channels}' for radio, channels in radios.items()])})' for profile, radios in channel_non_conform.items()])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Conformité des bandes radio utilisées (802.11)
        titre_para = doc.add_heading(" Conformité des bandes radio utilisées (802.11)", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Vérification de l'utilisation des standards récents (n/ac/ax) pour de meilleures performances. "
            "Les standards obsolètes (a/b/g) sont sources d’interférences et de faible débit."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if band_conform else "NON CONFORME")
        run_status.bold = True
        if band_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_bandes_radio = doc.add_paragraph(
            f"{band_result}." if band_conform else band_result
        )
        txt_bandes_radio = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not band_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Conformité des bandes radio utilisées (802.11n/ac/ax)",
                description_risque="Performances radio dégradées et risques d’interférence accrus",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join([f'{profile} ({', '.join([f'{radio} : {band}' for radio, band in radios.items()])})' for profile, radios in band_non_conform.items()])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

        # Activation de l'option Short Guard Interval
        titre_para = doc.add_heading(" Option Short Guard Interval", level=3)
        doc.add_paragraph('')
        doc.add_paragraph().add_run("Point audité :").bold = True
        doc.add_paragraph(
            "Dans les environnements où il y a peu d'interférences et d'obstacles, l'option 'Short Guard Interval' permet d’augmenter le débit jusqu’à +11 %."
        )
        doc.add_paragraph('')
        txt = doc.add_paragraph()
        run_result = txt.add_run("Résultat : ")
        run_result.bold = True
        run_status = txt.add_run("CONFORME" if sgi_conform else "NON CONFORME")
        run_status.bold = True
        if sgi_conform:
            run_status.font.color.rgb = RGBColor(0x00, 0xB0, 0x50)  # Vert #00B050
        else:
            run_status.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)  # Rouge #CC0000
        txt_sgi = doc.add_paragraph(
            f"{sgi_result}." if sgi_conform else sgi_result
        )
        txt_sgi = WD_ALIGN_PARAGRAPH.LEFT
        doc.add_paragraph('')
        doc.add_paragraph('')

        if not sgi_conform:
            risque = add_risk_table(
                doc,
                risk_number,
                point_audite="Option Short Guard Interval",
                description_risque="Débit radio potentiellement réduit",
                vraisemblance="VRAISEMBLABLE",
                impact="SIGNIFICATIF",
                correction="RAISONNABLE",
                remediation=f"Corriger les profils suivants : {'; '.join([f'{profile} ({' et '.join(radios)})' for profile, radios in sgi_non_conform.items()])}"
            )
            risques.append(risque)
            risk_number += 1
            doc.add_paragraph('')
            doc.add_paragraph('')

    if risques:
        doc.add_page_break()
        doc.add_heading(" Tableau récapitulatif des risques", level=2)
        doc.add_paragraph('')
        recap_table = doc.add_table(rows=1, cols=4)
        recap_table.style = 'Table Grid'

        headers = ["ID", "\nPOINT AUDITE ET DESCRIPTION DU RISQUE\n", "RISQUE", "CORRECTION"]
        for idx, header in enumerate(headers):
            cell = recap_table.cell(0, idx)
            cell.text = header
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.bold = True
            # Centrer entêtes colonnes RISQUE et CORRECTION (colonnes 2,3)
            if idx in [2, 3]:
                for paragraph in cell.paragraphs:
                    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Coloration fond bleu foncé et texte blanc pour la 1ère ligne (en-têtes)
        header_bg_color = "232323"
        header_text_color = RGBColor(0xFE, 0xD2, 0xF2)
        for cell in recap_table.rows[0].cells:
            color_cell_background(cell, header_bg_color)
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.font.color.rgb = header_text_color
                    run.bold = True

        # Remplir les lignes avec les risques stockés
        for i, risque in enumerate(risques):
            row_cells = recap_table.add_row().cells
            row_cells[0].text = risque["id"]
            row_cells[1].text = f"{risque['point_audite']} : {risque['description_risque']}"
            row_cells[2].text = risque.get("risque", "")
            row_cells[3].text = risque["correction"]

            # Couleurs de fond selon dictionnaires
            risque_val = risque.get("risque", "").upper()
            correction_val = risque["correction"].upper()

            risk_color = RISK_COLORS.get(risque_val, "FFFFFF")
            correction_color = CORRECTION_COLORS.get(correction_val, "FFFFFF")

            color_cell_background(row_cells[2], risk_color)
            color_cell_background(row_cells[3], correction_color)

            # Centrer contenu colonnes RISQUE et CORRECTION
            for col_idx in [2, 3]:
                cell = row_cells[col_idx]
                for paragraph in cell.paragraphs:
                    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER

            # Mettre le texte en blanc et gras selon la valeur
            # Colonne RISQUE
            if risque_val in ["TRÈS ÉLEVÉ"]:
                for paragraph in row_cells[2].paragraphs:
                    for run in paragraph.runs:
                        run.font.color.rgb = RGBColor(255, 255, 255) # Texte blanc
                        run.bold = True

            # Colonne CORRECTION
            if correction_val == "COMPLEXE":
                for paragraph in row_cells[3].paragraphs:
                    for run in paragraph.runs:
                        run.font.color.rgb = RGBColor(255, 255, 255) # Texte blanc
                        run.bold = True

            # Définir les largeurs pour chaque colonne
            col_widths = [Cm(0.7), Cm(30), Cm(1.5), Cm(1.5)]
            for idx, width in enumerate(col_widths):
                row_cells[idx].width = width

        # Coloration fond bleu foncé et texte blanc pour toute la 1ère colonne (y compris en-tête)
        for row in recap_table.rows:
            cell = row.cells[0]
            color_cell_background(cell, header_bg_color)
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.font.color.rgb = header_text_color
                    run.bold = True

    def set_vertical_align_center(cell):
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        vAlign = tcPr.find(qn('w:vAlign'))
        if vAlign is None:
            vAlign = OxmlElement('w:vAlign')
            tcPr.append(vAlign)
        vAlign.set(qn('w:val'), 'center')

    # Appliquer alignement vertical centré dans les colonnes 2 et 3
    for row in recap_table.rows:
        for col_idx in [0, 2, 3]:
            set_vertical_align_center(row.cells[col_idx])

    cell = recap_table.cell(0, 1)
    for paragraph in cell.paragraphs:
        paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT

    doc.add_paragraph("")

    highlight_text_in_doc(doc, "Etat de la synchronisation à vérifier")
    # Enregistrement
    doc.save(filename)
    return filename



def exporter_utilisateurs_admins(filepath=None):
    # Accept filepath parameter instead of using global
    if filepath is None:
        return []
    config_lines = lire_config_fortigate(filepath)

    users_data = []      # Liste des utilisateurs et administrateurs
    groups = {}          # Dictionnaire des groupes et leurs membres

    # États pour chaque bloc
    in_user_group_block = False
    ug_depth = 0
    current_group = None

    in_user_local_block = False
    current_user = None

    in_system_admin_block = False
    sa_depth = 0
    current_admin = None

    for raw_line in config_lines:
        line = raw_line.strip()

        # ================================
        # Bloc des groupes d'utilisateurs
        # ================================
        if line == 'config user group':
            in_user_group_block = True
            ug_depth = 0
            current_group = None
            continue

        if in_user_group_block:
            # Gérer la profondeur pour ne pas sortir au 'end' des sous-blocs (ex: config match)
            if line.startswith('config ') and not line.startswith('config user group'):
                ug_depth += 1
                continue
            elif line == 'end':
                if ug_depth > 0:
                    ug_depth -= 1
                else:
                    in_user_group_block = False
                    current_group = None
                continue

            # Nouveau groupe
            if line.startswith('edit '):
                parts = line.split('"')
                if len(parts) > 1:
                    current_group = parts[1]
                    groups[current_group] = []
                continue

            # Fin d'un groupe
            if line == 'next':
                current_group = None
                continue

            # Membres du groupe
            if line.startswith('set member ') and current_group:
                # Récupère toutes les occurrences entre guillemets
                members = re.findall(r'"([^"]+)"', line)
                groups[current_group].extend(members)
                continue

        # ====================
        # Bloc utilisateurs locaux
        # ====================
        if line == 'config user local':
            in_user_local_block = True
            current_user = None
            continue
        elif line == 'end' and in_user_local_block:
            in_user_local_block = False
            current_user = None
            continue

        if in_user_local_block:
            if line.startswith('edit '):
                current_user = {
                    'Type de compte': '',
                    'Nom du compte': '',
                    'Type MFA': 'None',
                    'Données MFA': '',
                    'Statut': 'Actif',
                    'Groupe': ''
                }
                if '"' in line:
                    current_user['Nom du compte'] = line.split('"')[1]
                    users_data.append(current_user)
                continue

            # IMPORTANT: traiter 'next' AVANT le bloc de parsing des attributs
            if line == 'next' and current_user:
                current_user = None
                continue

            # Attributs de l'utilisateur courant
            if current_user:
                if 'set type password' in line:
                    current_user['Type de compte'] = 'User Local'
                elif 'set type radius' in line:
                    current_user['Type de compte'] = 'User Radius'
                elif 'set type ldap' in line:
                    current_user['Type de compte'] = 'User LDAP'
                elif 'set type tacacs+' in line:
                    current_user['Type de compte'] = 'User Tacacs+'
                elif 'set status disable' in line:
                    current_user['Statut'] = 'Désactivé'
                elif 'set two-factor disable' in line:
                    current_user['Type MFA'] = 'Désactivé'
                elif 'set two-factor fortitoken' in line:
                    current_user['Type MFA'] = 'FortiToken'
                elif 'set fortitoken' in line:
                    current_user['Données MFA'] = f"FortiToken ID: {line.split(' ')[-1]}"
                elif 'set two-factor email' in line:
                    current_user['Type MFA'] = 'Email'
                elif 'set email-to' in line and '"' in line:
                    current_user['Données MFA'] = line.split('"')[1]
                elif 'set two-factor sms' in line:
                    current_user['Type MFA'] = 'SMS'
                elif 'set sms-phone' in line and '"' in line:
                    current_user['Données MFA'] = line.split('"')[1]
                continue

        # ====================
        # Bloc administrateurs système
        # ====================
        if line == 'config system admin':
            in_system_admin_block = True
            sa_depth = 0
            current_admin = None
            continue
        elif line == 'end' and in_system_admin_block and sa_depth == 0:
            in_system_admin_block = False
            current_admin = None
            continue

        if in_system_admin_block:
            # Gérer profondeur sous-blocs éventuels
            if line.startswith('config ') and not line.startswith('config system admin'):
                sa_depth += 1
                continue
            elif line == 'end':
                if sa_depth > 0:
                    sa_depth -= 1
                else:
                    in_system_admin_block = False
                continue

            if line.startswith('edit ') and '"' in line and sa_depth == 0:
                current_admin = {
                    'Type de compte': 'Administrateur',
                    'Nom du compte': line.split('"')[1],
                    'Statut': 'Actif',
                    'Groupe': '',
                    'Type MFA': 'None',
                    'Données MFA': ''
                }
                users_data.append(current_admin)
                continue

            # IMPORTANT: traiter 'next' AVANT le parsing des attributs
            if line == 'next' and current_admin and sa_depth == 0:
                current_admin = None
                continue

            if current_admin:
                if 'set accprofile' in line and '"' in line:
                    access_type = line.split('"')[1]
                    current_admin['Type de compte'] = f"Administrateur ({access_type})"
                elif 'set status disable' in line:
                    current_admin['Statut'] = 'Désactivé'
                elif 'set status enable' in line:
                    current_admin['Statut'] = 'Actif'
                elif 'set two-factor disable' in line:
                    current_admin['Type MFA'] = 'Désactivé'
                elif 'set two-factor fortitoken' in line:
                    current_admin['Type MFA'] = 'FortiToken'
                elif 'set fortitoken' in line:
                    current_admin['Données MFA'] = f"FortiToken ID: {line.split(' ')[-1]}"
                elif 'set two-factor email' in line:
                    current_admin['Type MFA'] = 'Email'
                elif 'set email-to' in line and '"' in line:
                    current_admin['Données MFA'] = line.split('"')[1]
                elif 'set two-factor sms' in line:
                    current_admin['Type MFA'] = 'SMS'
                elif 'set sms-phone' in line and '"' in line:
                    current_admin['Données MFA'] = line.split('"')[1]
                elif 'set remote-group' in line and '"' in line:
                    remote_group = line.split('"')[1]
                    if current_admin['Groupe']:
                        current_admin['Groupe'] += f", {remote_group}"
                    else:
                        current_admin['Groupe'] = remote_group
                continue

    # ===========================
    # Associer les groupes aux utilisateurs locaux
    # ===========================
    for user in users_data:
        # Ignorer les administrateurs lors de l'association aux groupes locaux
        if isinstance(user.get('Type de compte'), str) and user['Type de compte'].startswith('Administrateur'):
            continue

        # Trouver tous les groupes contenant ce compte
        noms_groupes = [g for g, membres in groups.items() if user.get('Nom du compte') in membres]
        user['Groupe'] = ', '.join(noms_groupes)

    return users_data





# GUI code removed - module used as library only
