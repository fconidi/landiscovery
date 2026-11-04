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
