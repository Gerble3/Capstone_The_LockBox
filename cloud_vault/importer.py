# This file contains functions to import CSV files into the vault database (acessed in main_window.py).

# cloud_vault/importer.py
from __future__ import annotations
import csv, io, os
from typing import Iterable, Dict, Tuple, List
from .db import Vault, add_entry, list_entries
from .crypto import normalize_host

# Supported formats
FORMATS = ["auto", "chrome", "bitwarden", "lastpass", "generic"]

def _read_csv_head(path: str, limit: int = 50) -> Tuple[List[str], List[Dict[str, str]]]:
    # read with utf-8-sig to strip BOM if present
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        rdr = csv.DictReader(f)
        headers = [h.strip() for h in (rdr.fieldnames or [])]
        rows = []
        for i, row in enumerate(rdr):
            if i >= limit:
                break
            rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items()})
    return headers, rows

def _sniff_format(headers: Iterable[str]) -> str:
    H = {h.strip().lower() for h in headers}
    # Chrome/Edge: name,url,username,password,notes
    if {"name", "url", "username", "password"} <= H:
        return "chrome"
    # Bitwarden: name,username,uri,notes,login_password (exports vary)
    if ({"name", "username", "uri"} <= H) or ({"name", "login_username", "login_password"} <= H):
        return "bitwarden"
    # LastPass: url,username,password,extra,name,grouping,fav
    if {"url", "username", "password", "name"} <= H:
        return "lastpass"
    # Fallback
    return "generic"

def _map_row(fmt: str, row: Dict[str, str]) -> Dict[str, str]:
    r = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
    if fmt == "chrome":
        return {
            "title": r.get("name", "") or (r.get("url") or r.get("origin") or ""),
            "url": r.get("url", ""),
            "username": r.get("username", ""),
            "password": r.get("password", ""),
            "notes": r.get("notes", ""),
        }
    if fmt == "bitwarden":
        # BW has multiple layouts; try both
        return {
            "title": r.get("name", ""),
            "url": r.get("uri", "") or r.get("login_uri", ""),
            "username": r.get("username", "") or r.get("login_username", ""),
            "password": r.get("password", "") or r.get("login_password", ""),
            "notes": r.get("notes", "") or r.get("login_totp", ""),
        }
    if fmt == "lastpass":
        return {
            "title": r.get("name", ""),
            "url": r.get("url", ""),
            "username": r.get("username", ""),
            "password": r.get("password", ""),
            "notes": r.get("extra", "") or r.get("notes", ""),
        }
    # generic guess: try common column names
    return {
        "title": r.get("title", "") or r.get("name", "") or r.get("site", "") or r.get("url", ""),
        "url": r.get("url", "") or r.get("uri", ""),
        "username": r.get("username", "") or r.get("login", "") or r.get("user", ""),
        "password": r.get("password", "") or r.get("pass", ""),
        "notes": r.get("notes", "") or r.get("extra", ""),
    }

def import_csv(
    vault: Vault,
    csv_path: str,
    fmt: str = "auto",
    skip_empty_passwords: bool = True,
    dedupe: bool = True,
) -> Dict[str, int]:
    """
    Reads a CSV and imports rows into the vault via add_entry.
    Returns stats: {"imported": n, "skipped_empty": n, "skipped_dupe": n, "errors": n}
    """
    headers, _ = _read_csv_head(csv_path, limit=1)
    det = _sniff_format(headers) if fmt == "auto" else fmt
    if det not in FORMATS:
        det = "generic"

    # Build existing (host, username) set for de-dup
    existing = set()
    for e in list_entries(vault):
        existing.add((e.get("host") or "", (e.get("username") or "").strip()))

    stats = {"imported": 0, "skipped_empty": 0, "skipped_dupe": 0, "errors": 0}

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            try:
                mapped = _map_row(det, row)
                title = (mapped.get("title") or "").strip()
                url = (mapped.get("url") or "").strip()
                username = (mapped.get("username") or "").strip()
                password = (mapped.get("password") or "").strip()
                notes = mapped.get("notes") or ""

                if skip_empty_passwords and not password:
                    stats["skipped_empty"] += 1
                    continue

                host = normalize_host(url or "")
                if dedupe and (host, username) in existing:
                    stats["skipped_dupe"] += 1
                    continue

                add_entry(vault, title or host or "(imported)", url, username, password, notes)
                existing.add((host, username))
                stats["imported"] += 1
            except Exception:
                stats["errors"] += 1
                continue

    return stats

def preview_csv(path: str, limit: int = 12) -> Tuple[str, List[str], List[Dict[str, str]]]:
    headers, rows = _read_csv_head(path, limit=limit)
    return _sniff_format(headers), headers, rows
