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
