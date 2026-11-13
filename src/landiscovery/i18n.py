"""Small built-in English/Italian catalog for the interface."""
from __future__ import annotations

import os

CATALOG = {
    "Scan": "Scansione",
    "Start": "Avvia",
    "Cancel": "Annulla",
    "History": "Storico",
    "Compare": "Confronta",
    "Inventory": "Inventario",
    "Security": "Sicurezza",
    "Inferred topology": "Topologia inferita",
    "Network targets": "Reti da esaminare",
    "Profile": "Profilo",
    "IP": "IP",
    "Hostname": "Nome host",
    "MAC": "MAC",
    "Vendor": "Produttore",
    "Latency": "Latenza",
    "Ports": "Porte",
    "Services": "Servizi",
    "OS": "Sistema operativo",
    "No hosts found": "Nessun host trovato",
    "Reduced mode: some information is unavailable":
        "Modalità ridotta: alcune informazioni non sono disponibili",
    "Confirm scan": "Conferma scansione",
    "This scan covers a public or large network. Continue?":
        "Questa scansione riguarda una rete pubblica o ampia. Continuare?",
    "SNMP community": "Community SNMP",
    "Scan cancelled": "Scansione annullata",
    "Scan failed": "Scansione non riuscita",
    "Scan complete": "Scansione completata",
    "Comparison is unreliable": "Il confronto non è affidabile",
    "New": "Nuovo",
    "Gone": "Scomparso",
    "Changed": "Modificato",
    "Name": "Nome",
    "Notes": "Note",
    "Tags": "Etichette",
    "Save": "Salva",
    "Export": "Esporta",
    "No scans saved": "Nessuna scansione salvata",
    "SSH": "SSH",
    "RDP": "RDP",
    "Browser": "Browser",
    "Ping": "Ping",
    "Traceroute": "Traceroute",
    "Wake on LAN": "Riattiva via rete",
    "Copy IP": "Copia IP",
    "Map": "Mappa",
    "Columns": "Colonne",
    "Explore your local network": "Esplora la rete locale",
    "Enter an IP address or network range": "Inserisci un indirizzo IP o un intervallo di rete",
    "Scan profile": "Profilo di scansione",
    "Ready to discover": "Pronto per la scansione",
    "Enter a network target and start a scan": "Inserisci una rete e avvia la scansione",
    "Results will appear here after a scan": "I risultati appariranno qui dopo una scansione",
    "Try another target or scan profile": "Prova un'altra rete o un altro profilo",
    "Hosts": "Host",
    "Status": "Stato",
    "State": "Stato",
    "Detail": "Dettaglio",
    "Key": "Chiave",
    "Severity": "Gravità",
    "Title": "Titolo",
    "Refresh": "Aggiorna",
    "Delete": "Elimina",
    "Delete scan {id}?": "Eliminare la scansione {id}?",
    "Delete device {key}?": "Eliminare il dispositivo {key}?",
    "Device key is required": "La chiave del dispositivo è obbligatoria",
    "{n} hosts": "{n} host",
    "done": "completata",
    "cancelled": "annullata",
    "failed": "non riuscita",
    "running": "in corso",
    "info": "info",
    "warning": "avviso",
    "critical": "critico",
    "discovery": "individuazione",
    "ports": "porte",
    "os": "sistema operativo",
    "traceroute": "traceroute",
    "security": "sicurezza",
    "mdns": "mDNS",
    "ssdp": "SSDP",
    "snmp": "SNMP",
    "target networks differ": "le reti esaminate sono diverse",
    "privilege modes differ": "le modalità di privilegio sono diverse",
    "host discovery methods differ": "i metodi di individuazione degli host sono diversi",
    "both scans must be complete": "entrambe le scansioni devono essere complete",
    "scan coverage is unavailable": "la copertura della scansione non è disponibile",
    "Invalid target": "Rete non valida",
    "Accepted targets: an IP address, a network such as 192.168.1.0/24, or several separated by spaces or commas": "Reti ammesse: un indirizzo IP, una rete come 192.168.1.0/24, oppure più elementi separati da spazi o virgole",
    "{tool} is not installed": "{tool} non è installato",
    "IPv4 networks wider than /{n} cannot be scanned": "Le reti IPv4 più ampie di /{n} non possono essere scansionate",
    "Use a file name ending in .csv, .json or .html": "Usa un nome file che termini con .csv, .json o .html",
    "Select two scans to compare": "Seleziona due scansioni da confrontare",
    "No devices saved": "Nessun dispositivo salvato",
    "No findings": "Nessun risultato di sicurezza",
    "target outside private address ranges": "rete fuori dagli intervalli privati",
    "IPv4 network wider than /16": "rete IPv4 più ampia di /16",
    "IPv6 network wider than /112 is not allowed": "le reti IPv6 più ampie di /112 non sono ammesse",
    "snmp community not provided": "community SNMP non fornita",
}

_language = "en"


def set_language(code: str) -> None:
    global _language
    if code == "auto":
        value = (os.environ.get("LANGUAGE") or os.environ.get("LC_ALL") or
                 os.environ.get("LC_MESSAGES") or os.environ.get("LANG", "en"))
        code = value.split(":")[0].split("_")[0].split(".")[0].lower()
    if code not in ("it", "en"):
        code = "en"
    _language = code


def _(key: str) -> str:
    return CATALOG.get(key, key) if _language == "it" else key
