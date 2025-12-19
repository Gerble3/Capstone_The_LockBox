
from __future__ import annotations
import sqlite3, time, os, json
from dataclasses import dataclass
from typing import Optional
from .crypto import KDFParams, derive_master_key, aead_encrypt, aead_decrypt, normalize_host

# This file contains database functions for the vault application and uses SQLite for storage.

#  Schema 
SCHEMA_SQL = """
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY CHECK (id=1),
    version INTEGER NOT NULL,
    kdf_params TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    wrapped_vault_key BLOB NOT NULL,
    wrapped_vault_nonce BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    url TEXT,
    lower_host TEXT,
    username_nonce BLOB NOT NULL,
    username_cipher BLOB NOT NULL,
    password_nonce BLOB NOT NULL,
    password_cipher BLOB NOT NULL,
    notes_nonce BLOB,
    notes_cipher BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(lower_host);
CREATE INDEX IF NOT EXISTS idx_entries_updated ON entries(updated_at);
"""


@dataclass
class Vault:
    path: str
    conn: sqlite3.Connection
    vault_key: bytes  # 32 bytes



def connect(db_path: str) -> sqlite3.Connection:
    # Allow using the same connection from a different thread (UI) after unlock/init
    conn = sqlite3.connect(db_path, check_same_thread=False)

    # Be nice about transient locks (cloud sync / antivirus / another process)
    conn.execute("PRAGMA busy_timeout=5000;")  # ms

    # Cloud-sync friendly: avoid -wal / -shm sidecar files
    conn.execute("PRAGMA journal_mode=DELETE;")

    # Safer durability for a file that might be synced/moved/copied
    conn.execute("PRAGMA synchronous=FULL;")

    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_vault(db_path: str, master_password: str, params: Optional[KDFParams]=None) -> Vault:
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        raise RuntimeError("Database already exists; refusing to overwrite.")
    params = params or KDFParams()
    conn = connect(db_path)
    with conn:
        conn.executescript(SCHEMA_SQL)
        # derive master key
        salt = os.urandom(params.salt_len)
        mkey = derive_master_key(master_password, salt, params)
        # generate vault key and wrap it
        vkey = os.urandom(32)
        nonce, wrapped = aead_encrypt(mkey, vkey, aad=b"vault-key")
        conn.execute("""
            INSERT INTO meta (id, version, kdf_params, kdf_salt, wrapped_vault_key, wrapped_vault_nonce, created_at)
            VALUES (1, ?, ?, ?, ?, ?, ?)
        """, (1, params.to_json(), salt, wrapped, nonce, int(time.time())))
    return Vault(db_path, conn, vkey)


def open_vault(db_path: str, master_password: str) -> Vault:
    if not os.path.exists(db_path):
        raise RuntimeError("Database not found.")
    conn = connect(db_path)
    row = conn.execute("SELECT version, kdf_params, kdf_salt, wrapped_vault_key, wrapped_vault_nonce FROM meta WHERE id=1").fetchone()
    if not row:
        raise RuntimeError("Meta not initialized.")
    version, kdf_params_s, salt, wrapped, nonce = row
    params = KDFParams.from_json(kdf_params_s)
    mkey = derive_master_key(master_password, salt, params)
    vkey = aead_decrypt(mkey, nonce, wrapped, aad=b"vault-key")
    return Vault(db_path, conn, vkey)


#  CRUD 
def add_entry(v: Vault, title: str, url: str, username: str, password: str, notes: str="") -> int:
    now = int(time.time())
    host = normalize_host(url or "")
    n_u, c_u = aead_encrypt(v.vault_key, username.encode("utf-8"))
    n_p, c_p = aead_encrypt(v.vault_key, password.encode("utf-8"))
    n_n, c_n = aead_encrypt(v.vault_key, notes.encode("utf-8"))
    with v.conn:
        cur = v.conn.execute("""
            INSERT INTO entries (title, url, lower_host, username_nonce, username_cipher,
                                 password_nonce, password_cipher, notes_nonce, notes_cipher,
                                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (title, url, host, n_u, c_u, n_p, c_p, n_n, c_n, now, now))
        return cur.lastrowid


# AFTER
def list_entries(v: Vault, reveal_password: bool = False) -> list[dict]:
    rows = v.conn.execute("""
        SELECT id, title, url, lower_host, username_nonce, username_cipher,
               password_nonce, password_cipher, notes_nonce, notes_cipher,
               created_at, updated_at
        FROM entries ORDER BY updated_at DESC
    """).fetchall()
    out = []
    for r in rows:
        (id_, title, url, host, nu, cu, np, cp, nn, cn, created, updated) = r
        username = aead_decrypt(v.vault_key, nu, cu).decode("utf-8")
        item = {
            "id": id_, "title": title, "url": url, "host": host,
            "username": username, "created_at": created, "updated_at": updated
        }
        if reveal_password:
            password = aead_decrypt(v.vault_key, np, cp).decode("utf-8")
            item["password"] = password
        out.append(item)
    return out



def get_entry(v: Vault, entry_id: int, reveal_password: bool=False) -> dict:
    r = v.conn.execute("""
        SELECT id, title, url, lower_host, username_nonce, username_cipher,
               password_nonce, password_cipher, notes_nonce, notes_cipher,
               created_at, updated_at
        FROM entries WHERE id=?
    """, (entry_id,)).fetchone()
    if not r: raise KeyError("Entry not found")
    (id_, title, url, host, nu, cu, np, cp, nn, cn, created, updated) = r
    username = aead_decrypt(v.vault_key, nu, cu).decode("utf-8")
    notes = aead_decrypt(v.vault_key, nn, cn).decode("utf-8") if nn and cn else ""
    password = aead_decrypt(v.vault_key, np, cp).decode("utf-8") if reveal_password else None
    return {"id": id_, "title": title, "url": url, "host": host, "username": username,
            "password": password, "notes": notes, "created_at": created, "updated_at": updated}


def update_entry(v: Vault, entry_id: int, **fields) -> None:
    # fields may include: title, url, username, password, notes
    r = v.conn.execute("SELECT id FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not r: raise KeyError("Entry not found")
    sets = []; params = []
    now = int(time.time())

    if "title" in fields:
        sets.append("title=?"); params.append(fields["title"])
    if "url" in fields:
        sets.append("url=?"); params.append(fields["url"])
        sets.append("lower_host=?"); params.append(normalize_host(fields["url"]))
    if "username" in fields:
        nu, cu = aead_encrypt(v.vault_key, fields["username"].encode("utf-8"))
        sets.append("username_nonce=?"); params.append(nu)
        sets.append("username_cipher=?"); params.append(cu)
    if "password" in fields:
        np, cp = aead_encrypt(v.vault_key, fields["password"].encode("utf-8"))
        sets.append("password_nonce=?"); params.append(np)
        sets.append("password_cipher=?"); params.append(cp)
    if "notes" in fields:
        nn, cn = aead_encrypt(v.vault_key, fields["notes"].encode("utf-8"))
        sets.append("notes_nonce=?"); params.append(nn)
        sets.append("notes_cipher=?"); params.append(cn)

    sets.append("updated_at=?"); params.append(now)
    params.append(entry_id)
    with v.conn:
        v.conn.execute(f"UPDATE entries SET {', '.join(sets)} WHERE id=?", params)


def delete_entry(v: Vault, entry_id: int) -> None:
    with v.conn:
        v.conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
