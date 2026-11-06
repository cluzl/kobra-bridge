"""
kobrax_moonraker_bridge.py - Moonraker-compatible HTTP/WebSocket bridge for the Anycubic Kobra X

Emulates the Moonraker/Klipper API so OrcaSlicer can control the Kobra X directly.

Verwendung:
  python kobrax_moonraker_bridge.py --printer-ip 192.168.178.94

OrcaSlicer-Konfiguration:
  Drucker-Typ: Klipper  |  Host: 127.0.0.1  |  Port: 7125

────────────────────────────────────────────────────────────────────────────
Copyright (C) 2026 viewit (KX-Bridge contributors)
Modified in 2026 by Kobra Bridge contributors (model-aware S1/S1 Max support,
farm reliability, security hardening, and safe cross-model G-code adaptation).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License v3.0 as published
by the Free Software Foundation. See the LICENSE file in the project root
or <https://www.gnu.org/licenses/gpl-3.0.html> for the full text.

This program is distributed WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Reverse-engineering of the Anycubic Kobra X MQTT protocol was carried out
for interoperability purposes (§69e UrhG / EU Software Directive Art. 6).
This project is not affiliated with Anycubic. See NOTICE.md for details.
"""

import argparse
import sqlite3
import uuid
try:
    import config_loader as env_loader
except ImportError:
    import env_loader
import asyncio
import hashlib
import copy
import json
import logging
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import threading
import html
from urllib.parse import quote, urlsplit

# For PyInstaller binaries everything sits next to sys.executable, otherwise next to __file__
_BASE = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BASE)
# Read-only web assets (themes) are embedded in the onefile binary via --add-data under
# sys._MEIPASS entpackt; im Script-/Docker-Modus liegen sie neben dieser Datei.
_WEB_BASE = getattr(sys, "_MEIPASS", _BASE)
from kobrax_client import KobraXClient
from gcode_preflight import scan_bytes as preflight_bytes, scan_file as preflight_file
from kobra_models import discover_model, model_for_id, model_for_name
from kobra_gcode_compat import inspect_gcode, check_compatibility, derive_gcode, CONVERTER_VERSION


try:
    import imageio_ffmpeg
    def _find_ffmpeg() -> str:
        return imageio_ffmpeg.get_ffmpeg_exe()
except ImportError:
    def _find_ffmpeg() -> str:
        exe_name = "ffmpeg.exe" if sys.platform == "win32" else "ffmpeg"
        local = os.path.join(_BASE, exe_name)
        if os.path.isfile(local):
            return local
        return "ffmpeg"

try:
    from aiohttp import web
    import aiohttp
except ImportError:
    print("Error: aiohttp is not installed. Run: pip install aiohttp")
    sys.exit(1)

try:
    import base64 as _base64
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import unpad as _unpad
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _kx_generate_signature(token: str, ts: int, nonce: str) -> str:
    first = hashlib.md5(token[:16].encode()).hexdigest()
    return hashlib.md5((first + str(ts) + nonce).encode()).hexdigest()


def _kx_decrypt_info(encrypted_b64: str, key: str, iv: str) -> dict:
    cipher = _AES.new(key.encode(), _AES.MODE_CBC, iv.encode())
    raw = _base64.b64decode(encrypted_b64)
    return json.loads(_unpad(cipher.decrypt(raw), _AES.block_size).decode())


async def _kx_fetch_credentials(ip: str, port: int = 18910) -> dict:
    """Fetches + decrypts printer credentials via HTTP /info + /ctrl.

    Raises an exception on network/decrypt errors. Algorithm from
    tools/fetch_credentials.py (AES-256-CBC, Key=token[16:32], IV=ctrl-token).
    """
    if not _HAS_CRYPTO:
        raise RuntimeError("pycryptodome is not installed")
    import random, string
    nonce = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(6))
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession() as s:
        async with s.get(f"http://{ip}:{port}/info", timeout=timeout) as r:
            r.raise_for_status()
            info = await r.json()
        token = info["token"]
        ts = int(time.time() * 1000)
        sign = _kx_generate_signature(token, ts, nonce)
        params = {"ts": ts, "nonce": nonce, "sign": sign, "did": "random"}
        async with s.post(f"http://{ip}:{port}/ctrl", params=params, timeout=timeout) as r:
            r.raise_for_status()
            data = await r.json()
    result = _kx_decrypt_info(data["data"]["info"], token[16:32], data["data"]["token"])
    if "error" in result:
        raise RuntimeError(result.get("error", "decrypt failed"))
    model_id = str(info.get("modelId") or result.get("modeId") or "")
    return {
        "printer_ip": result.get("ip", ip),
        "username":   result.get("username", ""),
        "password":   result.get("password", ""),
        "device_id":  result.get("deviceId", ""),
        "mode_id":    model_id,
        "model_id":   model_id,
        "model":      info.get("modelName") or result.get("modelName") or "Anycubic Kobra",
    }

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(levelname)-5s %(name)s: %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("bridge")
# aiohttp logs one INFO line per HTTP request (access log) — with 2s frontend
# polling that drowns out the bridge's own logs by default. Toggleable at
# runtime via the verbose_http_log setting (see handle_api_settings_post).
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


def _set_verbose_http_log(enabled: bool):
    logging.getLogger("aiohttp.access").setLevel(logging.INFO if enabled else logging.WARNING)

# Web UI: subdirectory under web/themes/<name>/index.html
_UI_THEME_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
# Allowed static theme files under /kx/ui/<name>
_KX_UI_ASSETS: dict[str, str] = {
    "style.css": "text/css",
    "app.js":    "application/javascript",
    # Static, script-free page the dashboard navigates to when it closes itself.
    "closed.html": "text/html",
}
# Files from lib/ are served based on their extension (no whitelist entry needed)
_KX_UI_LIB_TYPES: dict[str, str] = {
    ".js":  "application/javascript",
    ".css": "text/css",
}
_KX_UI_TRANSLATION_RE = re.compile(r"^translations/([a-z]{2}(?:-[a-z]{2})?)\.json$")

# Ring buffer for the browser log stream (last 200 entries)
import collections as _collections
_log_buffer: "_collections.deque[dict]" = _collections.deque(maxlen=500)
_log_sse_queues: "list[asyncio.Queue]" = []

class _BrowserLogHandler(logging.Handler):
    """Sends log records to the ring buffer and all open SSE queues."""
    _fmt = logging.Formatter(datefmt="%H:%M:%S")

    def emit(self, record: logging.LogRecord):
        msg = record.getMessage()
        # Pass exceptions with traceback through to the browser (otherwise the
        # user only sees "Error: X" without context).
        if record.exc_info:
            try:
                msg += "\n" + self._fmt.formatException(record.exc_info)
            except Exception:
                pass
        entry = {
            "ts":    self._fmt.formatTime(record, "%H:%M:%S"),
            "lvl":   record.levelname,
            "name":  record.name,
            "msg":   msg,
        }
        _log_buffer.append(entry)
        for q in list(_log_sse_queues):
            try:
                q.put_nowait(entry)
            except Exception:
                pass

_browser_handler = _BrowserLogHandler()
logging.getLogger().addHandler(_browser_handler)

KOBRA_TO_KLIPPER_STATE = {
    "free":          "standby",
    "busy":          "printing",
    "printing":      "printing",
    "preheating":    "printing",
    "auto_leveling": "printing",
    "checking":      "printing",
    "updated":       "printing",
    "init":          "printing",
    "pausing":       "paused",
    "pause":         "paused",
    "paused":        "paused",
    "resuming":      "printing",
    "resumed":       "printing",
    "stopping":      "printing",
    "stoped":        "standby",
    "finished":      "complete",
    "failed":        "error",
    "canceled":      "standby",
}

MOONRAKER_VERSION = "v0.9.3-1"
KLIPPER_VERSION   = "v0.12.0-1"
# Long enough for preflight + a 200 MB printer upload + print/start ACK; bounded
# so a printer that never leaves "free" cannot stay "Starting" forever.
PRINT_PENDING_TTL = 180.0

# A poll thread that has not iterated for this long is wedged: the loop sleeps
# at most poll_interval (default 3 s) between iterations, and even offline
# probing wakes every 10 s. Six printers share one process, so /health fails
# if any thread stalls.
POLL_STALE_SEC = 120.0


def _parse_gcode_estimated_time(data: bytes) -> int:
    """Reads the estimated print time from GCode (OrcaSlicer + PrusaSlicer).
    Returns seconds, 0 when not found.
    PrusaSlicer writes the time into the header (first 16KB),
    OrcaSlicer writes it at the end of the file (last 16KB)."""
    import re
    # Search the beginning + end of the file (OrcaSlicer writes the time at the end)
    search_text = (data[:16384] + data[-65536:]).decode("utf-8", errors="ignore")
    # OrcaSlicer:  ; total estimated time: 9m 20s
    # PrusaSlicer: ; estimated printing time (normal mode) = 1h 9m 20s
    m = (re.search(r";\s*total estimated time:\s*(.*)", search_text) or
         re.search(r";\s*estimated printing time \(normal mode\)\s*=\s*(.*)", search_text))
    if not m:
        return 0
    parts = re.findall(r"(\d+)\s*([hms])", m.group(1))
    secs = 0
    for val, unit in parts:
        if unit == "h":   secs += int(val) * 3600
        elif unit == "m": secs += int(val) * 60
        elif unit == "s": secs += int(val)
    if secs:
        log.info(f"Slicer estimate: {secs}s ({m.group(1).strip()})")
    return secs


def _parse_gcode_layer_heights(data: bytes) -> tuple[float, float]:
    """Reads (layer_height, initial_layer_height) from the OrcaSlicer/PrusaSlicer
    GCode header. Both are stored as a config block at the end of the GCode.

    Beispiel-Zeilen:
      ; layer_height = 0.2
      ; initial_layer_print_height = 0.2

    Returns (0.0, 0.0) when not found - the caller decides what to do
    (typisch: keinen Z-Wert anzeigen)."""
    import re
    head = data[:16384].decode("utf-8", errors="ignore")
    tail = data[-65536:].decode("utf-8", errors="ignore")
    search = head + "\n" + tail
    def _grab(pat):
        m = re.search(pat, search)
        if not m:
            return 0.0
        try:
            return float(m.group(1))
        except Exception:
            return 0.0
    layer_h   = _grab(r";\s*layer_height\s*=\s*([0-9.]+)")
    first_h   = (_grab(r";\s*initial_layer_print_height\s*=\s*([0-9.]+)") or
                 _grab(r";\s*first_layer_height\s*=\s*([0-9.]+)") or
                 layer_h)
    return layer_h, first_h


def _extract_thumbnail(data: bytes) -> str:
    """Extracts the base64 PNG thumbnail from GCode (OrcaSlicer format)."""
    try:
        marker = b"; thumbnail begin"
        end_marker = b"; thumbnail end"
        start = data.find(marker)
        if start == -1:
            return ""
        start = data.find(b"\n", start) + 1
        end = data.find(end_marker, start)
        if end == -1:
            return ""
        lines = data[start:end].split(b"\n")
        b64 = b"".join(
            line[2:].strip() if line.startswith(b"; ") else line.strip()
            for line in lines
        )
        return b64.decode("ascii")
    except Exception:
        return ""


def _extract_filament_info(data: bytes) -> list[dict]:
  """Reads filament colors/materials incl. tool order from Orca/Prusa GCode.

  Gibt Liste von {slot_index, color_hex, material} in Tool-/Paint-Reihenfolge
  (T0, T1, ...).
  Searches both the start and the end of the file since Orca can insert
  large thumbnail blocks, pushing the metadata into the tail.
  """
  try:
    head = data[:131072]
    tail = data[-131072:] if len(data) > 131072 else b""
    header = (head + b"\n" + tail).decode("utf-8", errors="ignore")
    colors, materials = [], []
    paint_count_hint = 0
    tool_filament_order = []
    for line in header.splitlines():
      if re.match(r"^\s*;\s*filament_colour\s*=", line):
        val = line.split("=", 1)[-1].strip()
        colors = [c.strip().lstrip("#") for c in val.split(";") if c.strip()]
      elif re.match(r"^\s*;\s*filament_multi_colour\s*=", line) and not colors:
        val = line.split("=", 1)[-1].strip()
        colors = [c.strip().lstrip("#") for c in val.split(";") if c.strip()]
      elif re.match(r"^\s*;\s*filament_type\s*=", line):
        val = line.split("=", 1)[-1].strip()
        parts = [m.strip() for m in re.split(r"[;,]", val) if m.strip()]
        materials = parts
        paint_count_hint = max(paint_count_hint, len(parts))
      elif re.match(r"^\s*;\s*filament_density\s*:", line):
        val = line.split(":", 1)[-1].strip()
        parts = [x.strip() for x in re.split(r"[;,]", val) if x.strip()]
        paint_count_hint = max(paint_count_hint, len(parts))
      elif re.match(r"^\s*;\s*filament_diameter\s*:", line):
        val = line.split(":", 1)[-1].strip()
        parts = [x.strip() for x in re.split(r"[;,]", val) if x.strip()]
        paint_count_hint = max(paint_count_hint, len(parts))
      elif re.match(r"^\s*;\s*filament\s*:", line):
        raw = line.split(":", 1)[-1]
        parsed = []
        for p in [x.strip() for x in raw.split(",") if x.strip()]:
          try:
            parsed.append(int(p))
          except Exception:
            pass
        if parsed:
          tool_filament_order = parsed
    total_paints = max(len(colors), len(materials), paint_count_hint)
    if tool_filament_order:
      total_paints = max(total_paints, max(tool_filament_order))
    if total_paints <= 0:
      return []

    # Keep full paint list visible; mark paints referenced by Orca tool order as used.
    if len(colors) < total_paints:
      colors.extend(["FFFFFF"] * (total_paints - len(colors)))
    if len(materials) < total_paints:
      materials.extend(["PLA"] * (total_paints - len(materials)))
    # Prefer actual tool-change commands from the GCode body.
    # This avoids forwarding paints that are present in metadata but never used.
    used_paints_zero_based = set()
    try:
      for m in re.finditer(br"(?m)^[ \t]*T([0-9]+)\b", data):
        used_paints_zero_based.add(int(m.group(1)))
    except Exception:
      used_paints_zero_based = set()

    # Fallback for slicers that only provide paint usage in header metadata.
    used_paints_from_header = set()
    for n in tool_filament_order:
      try:
        # Orca/Prusa filament: list is typically 1-based.
        used_paints_from_header.add(max(0, int(n) - 1))
      except Exception:
        pass

    result = []
    for i in range(total_paints):
      hex_color = colors[i] if i < len(colors) else "FFFFFF"
      result.append({
        "slot_index": i,
        "color_hex":  "#" + hex_color.upper() if hex_color else "#FFFFFF",
        "material":   materials[i] if i < len(materials) else "PLA",
        "is_used":    (i in used_paints_zero_based) if used_paints_zero_based else ((i in used_paints_from_header) if used_paints_from_header else True),
      })
    return result
  except Exception:
    return []


class GCodeStore:
    """Persistenter GCode-Store pro Bridge-Instanz (SQLite)."""

    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self._gcode_dir = os.path.join(data_dir, "gcodes")
        os.makedirs(self._gcode_dir, exist_ok=True)
        self._derived_dir = os.path.join(data_dir, "derived")
        os.makedirs(self._derived_dir, exist_ok=True)
        self._gcode_facts_cache: dict[tuple, object] = {}
        self._gcode_facts_locks: dict[str, threading.Lock] = {}
        self._gcode_facts_progress: dict[str, dict] = {}
        db_path = os.path.join(data_dir, "kx-bridge.db")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS gcode_files (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    uploaded_at TEXT NOT NULL,
                    thumbnail_b64 TEXT,
                    est_print_time_sec INTEGER,
                    filament_used_mm REAL,
                    layer_count INTEGER,
                    gcode_filaments TEXT,
                    objects_skip_parts TEXT,
                    svg_image TEXT,
                    web_unverified INTEGER NOT NULL DEFAULT 0,
                    content_sha256 TEXT
                );
                CREATE TABLE IF NOT EXISTS print_jobs (
                    id TEXT PRIMARY KEY,
                    gcode_file_id TEXT NOT NULL,
                    printer_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    status TEXT NOT NULL,
                    duration_sec INTEGER,
                    filament_assignments TEXT,
                    abort_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS printer_file_hashes (
                    printer_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL,
                    PRIMARY KEY (printer_id, filename)
                );
                CREATE TABLE IF NOT EXISTS printer_maintenance (
                    printer_id TEXT PRIMARY KEY,
                    maintenance_mode INTEGER NOT NULL DEFAULT 0,
                    reason TEXT NOT NULL DEFAULT '',
                    serviced_at TEXT,
                    service_print_hours REAL NOT NULL DEFAULT 0,
                    service_jobs INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS maintenance_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    printer_id TEXT NOT NULL,
                    event_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT ''
                );
            """)
            # Migration: add gcode_filaments column for older databases
            try:
                self._conn.execute("ALTER TABLE gcode_files ADD COLUMN gcode_filaments TEXT")
                self._conn.commit()
            except Exception:
                pass
            # Migration: columns objects_skip_parts + svg_image (part-skip feature, v0.9.10)
            # Plus layer_height / first_layer_height (Obico Z height, v0.9.18)
            for col, typ in (
                ("objects_skip_parts", "TEXT"),
                ("svg_image", "TEXT"),
                ("layer_height", "REAL"),
                ("first_layer_height", "REAL"),
            ):
                try:
                    self._conn.execute(f"ALTER TABLE gcode_files ADD COLUMN {col} {typ}")
                    self._conn.commit()
                except Exception:
                    pass
            # Migration: flag for web uploads (warning before print)
            try:
                self._conn.execute("ALTER TABLE gcode_files ADD COLUMN web_unverified INTEGER NOT NULL DEFAULT 0")
                self._conn.commit()
            except Exception:
                pass
            # Farm dedup: cache the store-side content hash once per file.
            try:
                self._conn.execute("ALTER TABLE gcode_files ADD COLUMN content_sha256 TEXT")
                self._conn.commit()
            except Exception:
                pass

    def save_file(self, file_id: str, filename: str, data: bytes,
                  est_time_sec: int = 0, thumbnail_b64: str = "",
                  gcode_filaments: list | None = None,
                  web_unverified: bool = False,
                  layer_height: float = 0.0,
                  first_layer_height: float = 0.0) -> str:
        """Saves a GCode file to disk and DB. Returns the path."""
        safe_name = os.path.basename(filename)
        path = os.path.join(self._gcode_dir, safe_name)
        # Write to a temp file, then os.replace(): a printer pulling /serve/<file>
        # or a concurrent re-upload of the same name must see complete old bytes
        # or complete new bytes, never a half-written file.
        fd, tmp_path = tempfile.mkstemp(dir=self._gcode_dir, prefix=".upload-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            try:
                os.replace(tmp_path, path)
            except Exception:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
                raise
            filaments_json = json.dumps(gcode_filaments) if gcode_filaments else None
            # The disk path is filename-based, while the DB primary key is the
            # content MD5. Uploading new content under an existing filename
            # therefore overwrites the bytes but used to leave the old row
            # pointing at that same path: clicking the old card printed the new
            # file with stale metadata/hash. A filename represents one current
            # library object, so retire every older content row atomically.
            self._conn.execute(
                "DELETE FROM gcode_files WHERE filename=? AND id<>?",
                (filename, file_id),
            )
            self._conn.execute(
                """INSERT OR REPLACE INTO gcode_files
                   (id, filename, path, size_bytes, uploaded_at, thumbnail_b64, est_print_time_sec, gcode_filaments, web_unverified, layer_height, first_layer_height)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (file_id, filename, path, len(data), now, thumbnail_b64 or None, est_time_sec or None, filaments_json, 1 if web_unverified else 0, layer_height or None, first_layer_height or None)
            )
            self._conn.commit()
        return path

    def list_files(self, with_blobs: bool = True) -> list:
        # with_blobs=False skips thumbnail_b64/svg_image (~2.3 MB across 53 rows)
        # for list views that only need has_thumbnail. Reading the blobs on the
        # event loop stalled every printer's HTTP for 100-800 ms per /kx/files.
        cols = "*" if with_blobs else (
            "id, filename, path, size_bytes, uploaded_at, est_print_time_sec, "
            "filament_used_mm, layer_count, gcode_filaments, objects_skip_parts, "
            "web_unverified, layer_height, first_layer_height, content_sha256, "
            "(thumbnail_b64 IS NOT NULL AND thumbnail_b64 != '') AS has_thumbnail")
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {cols} FROM gcode_files ORDER BY uploaded_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_file(self, file_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM gcode_files WHERE id=?", (file_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_file_by_name(self, filename: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM gcode_files WHERE filename=? ORDER BY uploaded_at DESC LIMIT 1",
                (filename,)
            ).fetchone()
        return dict(row) if row else None

    def update_file_objects(self, filename: str, objects: list, svg: str = "") -> None:
        """Saves the object list + optional SVG for a file (matched via filename)."""
        if not filename:
            return
        with self._lock:
            self._conn.execute(
                "UPDATE gcode_files SET objects_skip_parts=?, svg_image=? "
                "WHERE filename=?",
                (json.dumps(objects), svg or "", filename),
            )
            self._conn.commit()

    def update_file_filaments(self, file_id: str, gcode_filaments: list | None) -> None:
      """Updates parsed GCode filaments for an existing DB entry."""
      with self._lock:
        self._conn.execute(
          "UPDATE gcode_files SET gcode_filaments=? WHERE id=?",
          (json.dumps(gcode_filaments) if gcode_filaments else None, file_id),
        )
        self._conn.commit()

    def clear_web_unverified(self, file_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE gcode_files SET web_unverified=0 WHERE id=?",
                (file_id,),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def delete_file(self, file_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM gcode_files WHERE id=?", (file_id,)
            ).fetchone()
            if not row:
                return False
            row = dict(row)
            # Legacy rows can still share one disk path (same filename, different
            # content hash), so an unconditional unlink here deleted the OTHER
            # row's bytes: its card kept rendering, then Print failed with
            # "G-code file missing" and Download 404'd. New uploads can no longer
            # create that state, but historical pairs must not be destroyed.
            shared = self._conn.execute(
                "SELECT 1 FROM gcode_files WHERE path=? AND id<>? LIMIT 1",
                (row["path"], file_id),
            ).fetchone()
            self._conn.execute("DELETE FROM gcode_files WHERE id=?", (file_id,))
            self._conn.commit()
            # Unlink under the same lock as save_file's os.replace(); otherwise a
            # concurrent re-upload of this filename could land between the DB
            # delete and this unlink and lose its freshly written bytes.
            if not shared:
                try:
                    os.remove(row["path"])
                except OSError:
                    pass
        return True

    def start_job(self, gcode_file_id: str, printer_id: str,
                  filament_assignments: list | None = None) -> str:
        job_id = str(uuid.uuid4())
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        assignments_json = json.dumps(filament_assignments) if filament_assignments else None
        with self._lock:
            self._conn.execute(
                """INSERT INTO print_jobs
                   (id, gcode_file_id, printer_id, started_at, status, filament_assignments)
                   VALUES (?,?,?,?,'printing',?)""",
                (job_id, gcode_file_id, printer_id, now, assignments_json)
            )
            self._conn.commit()
        return job_id

    def finish_job(self, job_id: str, status: str = "completed",
                   abort_reason: str = "") -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            row = self._conn.execute(
                "SELECT started_at FROM print_jobs WHERE id=?", (job_id,)
            ).fetchone()
            duration = None
            if row:
                try:
                    import calendar
                    start = time.strptime(row["started_at"], "%Y-%m-%dT%H:%M:%SZ")
                    duration = int(time.time() - calendar.timegm(start))
                except Exception:
                    pass
            self._conn.execute(
                """UPDATE print_jobs SET ended_at=?, status=?, duration_sec=?, abort_reason=?
                   WHERE id=?""",
                (now, status, duration, abort_reason or None, job_id)
            )
            self._conn.commit()

    @staticmethod
    def _job_epoch(iso: str) -> float:
        try:
            import calendar
            return float(calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")))
        except Exception:
            return 0.0

    def claim_job(self, gcode_file_id: str, printer_id: str,
                  aliases: list | None = None, started_at_epoch: float | None = None,
                  filament_assignments: list | None = None) -> str:
        """Adopt the current open job or create exactly one.

        HTTP /kx/print and MQTT `printing` can arrive concurrently, and a bridge
        restart loses `_current_job_id` while the physical print continues.
        Reconcile both at the durable boundary so they converge on one row.
        """
        keys = list(dict.fromkeys([printer_id] + [a for a in (aliases or []) if a]))
        placeholders = ",".join("?" for _ in keys)
        now = time.time()
        expected = float(started_at_epoch if started_at_epoch is not None else now)
        assignments_json = json.dumps(filament_assignments) if filament_assignments else None
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM print_jobs WHERE ended_at IS NULL AND printer_id IN ({placeholders}) "
                "ORDER BY started_at DESC", keys,
            ).fetchall()
            matching = [r for r in rows if r["gcode_file_id"] == gcode_file_id]
            chosen = min(matching, key=lambda r: abs(self._job_epoch(r["started_at"]) - expected)) if matching else None
            # Same filename can be printed again later; only adopt a row near the
            # printer-reported start (10 min covers minute-rounded telemetry).
            if chosen and abs(self._job_epoch(chosen["started_at"]) - expected) > 600:
                chosen = None
            keep_id = chosen["id"] if chosen else str(uuid.uuid4())
            for row in rows:
                if row["id"] == keep_id:
                    continue
                self._conn.execute(
                    "UPDATE print_jobs SET ended_at=started_at,status='superseded',duration_sec=0,abort_reason='duplicate open row' WHERE id=?",
                    (row["id"],),
                )
            if chosen:
                self._conn.execute(
                    "UPDATE print_jobs SET printer_id=?, filament_assignments=COALESCE(?,filament_assignments) WHERE id=?",
                    (printer_id, assignments_json, keep_id),
                )
            else:
                started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expected))
                self._conn.execute(
                    """INSERT INTO print_jobs
                       (id,gcode_file_id,printer_id,started_at,status,filament_assignments)
                       VALUES (?,?,?,?,'printing',?)""",
                    (keep_id, gcode_file_id, printer_id, started_at, assignments_json),
                )
            self._conn.commit()
        return keep_id

    def finish_open_jobs(self, printer_id: str, aliases: list | None = None,
                         status: str = "completed", current_job_id: str = "") -> str:
        """Finish one real open row and retire leaked duplicates atomically."""
        keys = list(dict.fromkeys([printer_id] + [a for a in (aliases or []) if a]))
        placeholders = ",".join("?" for _ in keys)
        now_epoch = time.time()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM print_jobs WHERE ended_at IS NULL AND printer_id IN ({placeholders}) "
                "ORDER BY started_at DESC", keys,
            ).fetchall()
            if not rows:
                return ""
            chosen = next((r for r in rows if r["id"] == current_job_id), rows[0])
            for row in rows:
                if row["id"] == chosen["id"]:
                    duration = max(0, int(now_epoch - self._job_epoch(row["started_at"])))
                    self._conn.execute(
                        "UPDATE print_jobs SET ended_at=?,status=?,duration_sec=? WHERE id=?",
                        (now, status, duration, row["id"]),
                    )
                else:
                    self._conn.execute(
                        "UPDATE print_jobs SET ended_at=started_at,status='superseded',duration_sec=0,abort_reason='duplicate open row' WHERE id=?",
                        (row["id"],),
                    )
            self._conn.commit()
            return chosen["id"]

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list:
        # No thumbnail_b64 here: the join used to drag ~6 MB of base64 (500 jobs
        # x per-file thumbnail) through SQLite on every /kx/files, /kx/history
        # and history RPC, on the event loop shared by all six printers. No
        # caller reads it - the UI fetches /kx/files/{id}/thumbnail on demand.
        with self._lock:
            rows = self._conn.execute(
                """SELECT j.*, f.filename
                   FROM print_jobs j
                   LEFT JOIN gcode_files f ON j.gcode_file_id = f.id
                   WHERE j.status <> 'superseded'
                   ORDER BY j.started_at DESC LIMIT ? OFFSET ?""",
                (limit, offset)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Farm additions: upload dedup, maintenance, utilization ──────────────
    # All three are plain SQLite reads/writes on the shared store, so every
    # bridge instance sees the same farm-wide picture without extra services.

    def file_sha256(self, path: str) -> str:
        """Content hash of a store file. Streamed: G-code is often 100-200 MB."""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def store_file_sha256(self, gcode_file: dict) -> str:
        """Cached content hash for a store row.

        Sending one file to four printers must hash it once, not four times:
        on a 200 MB file each extra pass is real NAS I/O. The cache is
        invalidated by size, so a re-sliced file with the same name rehashes.
        """
        file_id = gcode_file.get("id")
        path = gcode_file.get("path") or ""
        size = int(gcode_file.get("size_bytes") or 0)
        if not file_id or not path:
            return ""
        with self._lock:
            row = self._conn.execute(
                "SELECT content_sha256, size_bytes FROM gcode_files WHERE id=?", (file_id,)
            ).fetchone()
        if row and row["content_sha256"] and int(row["size_bytes"] or 0) == size:
            return str(row["content_sha256"])
        digest = self.file_sha256(path)
        with self._lock:
            self._conn.execute(
                "UPDATE gcode_files SET content_sha256=? WHERE id=?", (digest, file_id)
            )
            self._conn.commit()
        return digest

    def gcode_facts_progress(self, gcode_file: dict) -> dict:
        path = gcode_file.get("path") or ""
        stat = os.stat(path)
        key = (path, stat.st_size, stat.st_mtime_ns)
        with self._lock:
            if key in self._gcode_facts_cache:
                return {"active": False, "phase": "done", "percent": 100,
                        "processed_bytes": stat.st_size, "size_bytes": stat.st_size}
            progress = dict(self._gcode_facts_progress.get(path) or {})
        if progress.get("cache_key") != key:
            return {"active": False, "phase": "idle", "percent": 0,
                    "processed_bytes": 0, "size_bytes": stat.st_size}
        progress.pop("cache_key", None)
        return progress

    def gcode_facts(self, gcode_file: dict):
        path = gcode_file.get("path") or ""
        stat = os.stat(path)
        key = (path, stat.st_size, stat.st_mtime_ns)
        with self._lock:
            cached = self._gcode_facts_cache.get(key)
            scan_lock = self._gcode_facts_locks.setdefault("scan:" + path, threading.Lock())
        if cached is not None:
            return cached
        with scan_lock:
            with self._lock:
                cached = self._gcode_facts_cache.get(key)
            if cached is not None:
                return cached

            def on_progress(done: int, total: int, phase: str) -> None:
                file_done = min(stat.st_size, done if phase == "hashing" else max(0, done - stat.st_size))
                with self._lock:
                    self._gcode_facts_progress[path] = {
                        "cache_key": key, "active": done < total, "phase": phase,
                        "percent": min(100, int(done * 100 / total)) if total else 0,
                        "processed_bytes": file_done, "size_bytes": stat.st_size,
                    }
            try:
                facts = inspect_gcode(path, on_progress)
            except Exception as e:
                with self._lock:
                    self._gcode_facts_progress[path] = {
                        "cache_key": key, "active": False, "phase": "error", "percent": 0,
                        "processed_bytes": 0, "size_bytes": stat.st_size, "error": str(e),
                    }
                raise
            with self._lock:
                # One current cache entry per path; old versions cannot grow forever.
                self._gcode_facts_cache = {
                    k: v for k, v in self._gcode_facts_cache.items() if k[0] != path
                }
                self._gcode_facts_cache[key] = facts
                self._gcode_facts_progress[path] = {
                    "cache_key": key, "active": False, "phase": "done", "percent": 100,
                    "processed_bytes": stat.st_size, "size_bytes": stat.st_size,
                }
            return facts

    def gcode_for_model(self, gcode_file: dict, target, *, target_nozzle_mm: float = 0.4,
                        available_ace_slots: int = 1) -> tuple[dict, object]:
        """Return source or an immutable target-derived file plus its report."""
        facts = self.gcode_facts(gcode_file)
        report = check_compatibility(facts, target, target_nozzle_mm, available_ace_slots)
        if report.decision == "blocked":
            raise ValueError("; ".join(report.reasons))
        if report.decision == "native":
            return dict(gcode_file), report
        source_id = str(gcode_file.get("id") or facts.sha256)
        derived_id = f"{source_id}@{target.model_id}@{CONVERTER_VERSION}"
        derived_path = os.path.join(
            self._derived_dir,
            f"{hashlib.sha256(derived_id.encode()).hexdigest()[:24]}.gcode",
        )
        with self._lock:
            derive_lock = self._gcode_facts_locks.setdefault(derived_path, threading.Lock())
        # ponytail: one lock per derived path; six printers dispatching the same
        # file share a single derivation instead of racing on a 300 MB rewrite.
        with derive_lock:
            if not os.path.isfile(derived_path):
                derive_gcode(
                    gcode_file["path"], target, derived_path,
                    target_nozzle_mm=target_nozzle_mm,
                    available_ace_slots=available_ace_slots,
                )
        prepared = dict(gcode_file)
        prepared.update({
            "id": derived_id,
            "path": derived_path,
            "size_bytes": os.path.getsize(derived_path),
            "source_file_id": source_id,
            "source_model_id": facts.source_model_id,
            "target_model_id": target.model_id,
            "converted": True,
        })
        return prepared, report

    def get_printer_file_hash(self, printer_id: str, filename: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM printer_file_hashes WHERE printer_id=? AND filename=?",
                (printer_id, filename),
            ).fetchone()
        return dict(row) if row else None

    def record_printer_file_hash(self, printer_id: str, filename: str,
                                 size_bytes: int, sha256: str) -> None:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO printer_file_hashes
                   (printer_id, filename, size_bytes, sha256, uploaded_at)
                   VALUES (?,?,?,?,?)""",
                (printer_id, filename, size_bytes, sha256, now),
            )
            self._conn.commit()

    def forget_printer_file_hash(self, printer_id: str, filename: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM printer_file_hashes WHERE printer_id=? AND filename=?",
                (printer_id, filename),
            )
            self._conn.commit()

    def get_maintenance(self, printer_id: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM printer_maintenance WHERE printer_id=?", (printer_id,)
            ).fetchone()
        if row:
            out = dict(row)
            out["maintenance_mode"] = bool(out.get("maintenance_mode"))
            return out
        return {
            "printer_id": printer_id, "maintenance_mode": False, "reason": "",
            "serviced_at": None, "service_print_hours": 0.0, "service_jobs": 0,
            "updated_at": None,
        }

    def set_maintenance_mode(self, printer_id: str, enabled: bool, reason: str = "") -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self.get_maintenance(printer_id)
        with self._lock:
            self._conn.execute(
                """INSERT INTO printer_maintenance
                   (printer_id, maintenance_mode, reason, serviced_at,
                    service_print_hours, service_jobs, updated_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(printer_id) DO UPDATE SET
                     maintenance_mode=excluded.maintenance_mode,
                     reason=excluded.reason,
                     updated_at=excluded.updated_at""",
                (printer_id, 1 if enabled else 0, reason or "", cur.get("serviced_at"),
                 cur.get("service_print_hours") or 0.0, cur.get("service_jobs") or 0, now),
            )
            self._conn.execute(
                "INSERT INTO maintenance_events (printer_id, event_at, kind, note) VALUES (?,?,?,?)",
                (printer_id, now, "maintenance_on" if enabled else "maintenance_off", reason or ""),
            )
            self._conn.commit()
        return self.get_maintenance(printer_id)

    def record_service(self, printer_id: str, note: str = "") -> dict:
        """Mark maintenance as just performed: resets the since-service counters."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        totals = self.printer_totals(printer_id)
        cur = self.get_maintenance(printer_id)
        with self._lock:
            self._conn.execute(
                """INSERT INTO printer_maintenance
                   (printer_id, maintenance_mode, reason, serviced_at,
                    service_print_hours, service_jobs, updated_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(printer_id) DO UPDATE SET
                     serviced_at=excluded.serviced_at,
                     service_print_hours=excluded.service_print_hours,
                     service_jobs=excluded.service_jobs,
                     updated_at=excluded.updated_at""",
                (printer_id, 1 if cur.get("maintenance_mode") else 0, cur.get("reason") or "",
                 now, totals["print_hours"], totals["jobs"], now),
            )
            self._conn.execute(
                "INSERT INTO maintenance_events (printer_id, event_at, kind, note) VALUES (?,?,?,?)",
                (printer_id, now, "serviced", note or ""),
            )
            self._conn.commit()
        return self.get_maintenance(printer_id)

    def printer_totals(self, printer_id: str, aliases: list | None = None) -> dict:
        """Lifetime finished-job counters for one printer.

        `aliases` folds in historical rows written under a different key (older
        builds stored the MQTT device_id in printer_id), so lifetime hours and
        the service counters reflect the machine, not the key that was current
        when the job ran.
        """
        keys = [printer_id] + [a for a in (aliases or []) if a and a != printer_id]
        placeholders = ",".join("?" for _ in keys)
        with self._lock:
            row = self._conn.execute(
                f"""SELECT COUNT(*) AS jobs, COALESCE(SUM(duration_sec),0) AS secs
                    FROM print_jobs WHERE printer_id IN ({placeholders})
                      AND ended_at IS NOT NULL AND status IN ('completed','cancelled','failed')""",
                keys,
            ).fetchone()
        jobs = int(row["jobs"] or 0)
        secs = int(row["secs"] or 0)
        return {"jobs": jobs, "print_seconds": secs, "print_hours": round(secs / 3600.0, 2)}

    def farm_stats(self, days: int = 7, aliases: dict | None = None) -> dict:
        """Per-printer utilization over a window, plus lifetime totals.

        `since` is compared against started_at, which is stored as an ISO-8601
        UTC string, so plain string comparison is correct and index-friendly.
        `aliases` maps printer_id -> extra historical keys for lifetime totals.
        """
        aliases = aliases or {}
        days = max(1, min(365, int(days)))
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
        window_seconds = days * 86400
        with self._lock:
            rows = self._conn.execute(
                """SELECT printer_id,
                          COUNT(*) AS jobs,
                          SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed,
                          SUM(CASE WHEN status IN ('cancelled','failed') THEN 1 ELSE 0 END) AS failed,
                          COALESCE(SUM(duration_sec),0) AS secs
                   FROM print_jobs
                   WHERE started_at >= ? AND ended_at IS NOT NULL
                     AND status IN ('completed','cancelled','failed')
                   GROUP BY printer_id""",
                (since,),
            ).fetchall()
        per = {}
        for r in rows:
            pid = str(r["printer_id"])
            jobs = int(r["jobs"] or 0)
            completed = int(r["completed"] or 0)
            secs = int(r["secs"] or 0)
            totals = self.printer_totals(pid, aliases.get(pid))
            maint = self.get_maintenance(pid)
            per[pid] = {
                "printer_id": pid,
                "jobs": jobs,
                "completed": completed,
                "failed": int(r["failed"] or 0),
                "print_seconds": secs,
                "print_hours": round(secs / 3600.0, 2),
                # Utilization is capped at 100%: overlapping/stale rows must not
                # produce a nonsensical >100% busy figure.
                "utilization_pct": round(min(100.0, secs * 100.0 / window_seconds), 1),
                "success_rate_pct": round(completed * 100.0 / jobs, 1) if jobs else None,
                "lifetime_jobs": totals["jobs"],
                "lifetime_print_hours": totals["print_hours"],
                "hours_since_service": round(
                    max(0.0, totals["print_hours"] - float(maint.get("service_print_hours") or 0.0)), 2),
                "jobs_since_service": max(0, totals["jobs"] - int(maint.get("service_jobs") or 0)),
                "serviced_at": maint.get("serviced_at"),
                "maintenance_mode": bool(maint.get("maintenance_mode")),
                "maintenance_reason": maint.get("reason") or "",
            }
        return {"days": days, "since": since, "printers": per}


# Camera master switch. 0 disables every camera path in the bridge: no ffmpeg
# workers, no video/startCapture MQTT publishes, no stream/snapshot endpoints,
# and an empty Moonraker webcam list. Set via [bridge] camera_enabled in
# config.ini or the CAMERA_ENABLED env var.
CAMERA_ENABLED = str(env_loader.get("CAMERA_ENABLED", "1")).strip().lower() not in ("0", "false", "no", "off")

# Slicer upload bodies are buffered whole (client_max_size 1 GiB). Two at a
# time is the most the ~4 GB NAS can hold alongside six MQTT sessions.
# ponytail: process-wide semaphore; stream multipart to disk if plates grow.
_UPLOAD_SLOTS = asyncio.Semaphore(2)


class CameraCache:
    """Zentraler Kamera-Demuxer.

    Keeps ONE ffmpeg process per output type open that reads the FLV stream
    from the printer and produces:
      - MJPEG @ 2fps -> last frame in RAM for /api/camera/snapshot
      - MPEG-TS (-c:v copy) -> fanout to all /api/camera/h264 subscribers
      - MJPEG @ 15fps/640px -> fanout to all /api/camera/stream subscribers
        (the live-view used by the dashboard AND by every Moonraker-compatible
        client, since server.webcams.list advertises this same stream_url)

    Damit:
      * Only ONE FLV connection to the printer per output type (solves the
        single-client limit / 429) - previously /api/camera/stream opened a
        brand-new, uncached ffmpeg + printer connection per HTTP client, which
        competed with the cached jpeg/h264 connections for the printer's very
        limited number of concurrent camera clients and caused intermittent
        "stream unavailable" failures.
      * Snapshots are instant (memory read, no ffmpeg spawn per request)
      * Multiple parallel H.264/MJPEG consumers possible (plugin + web UI + ...)

    Lazy start on the first consumer, auto-restart on ffmpeg crash.
    """

    JPEG_SOI = b"\xff\xd8"
    JPEG_EOI = b"\xff\xd9"
    TS_CHUNK = 65536

    def __init__(self):
        self._url: str = ""
        self.latest_jpeg: bytes = b""
        self.latest_jpeg_ts: float = 0.0
        self.h264_subscribers: "set[asyncio.Queue[bytes]]" = set()
        self.mjpeg_subscribers: "set[asyncio.Queue[bytes]]" = set()
        self._proc_jpeg: "asyncio.subprocess.Process | None" = None
        self._proc_h264: "asyncio.subprocess.Process | None" = None
        self._proc_mjpeg: "asyncio.subprocess.Process | None" = None
        self._task_jpeg: "asyncio.Task | None" = None
        self._task_h264: "asyncio.Task | None" = None
        self._task_mjpeg: "asyncio.Task | None" = None
        self._lock = asyncio.Lock()
        self._fail_count_jpeg: int = 0
        self._fail_count_h264: int = 0
        self._fail_count_mjpeg: int = 0

    def set_url(self, url: str):
        # A changed URL means the printer rotated its stream token (typically
        # after a reboot). Running ffmpeg processes still hold the stale URL
        # and will never pick it up on their own - they only re-read self._url
        # at the top of their outer loop, which they never reach while blocked
        # in a stdout read on the old, now-silent connection. Tear them down;
        # the next ensure_running() respawns them against the new URL.
        changed = bool(url and self._url and url != self._url)
        self._url = url
        if changed:
            self.reset()

    def reset(self):
        """Reset backoff counters and forcefully tear down any running
        ffmpeg loops - including cancelling their background tasks.

        Only killing the ffmpeg subprocess is not enough: the owning task
        might currently be sitting in `await asyncio.sleep(delay)` from a
        previous exponential backoff (up to 300s) after an earlier failure.
        Resetting the fail-count doesn't wake it up early, so a user
        clicking "reset" could see nothing happen for minutes. Cancelling
        the task guarantees an immediate, clean restart on the next
        ensure_running() call.
        """
        self._fail_count_jpeg = 0
        self._fail_count_h264 = 0
        self._fail_count_mjpeg = 0
        for task in (self._task_jpeg, self._task_h264, self._task_mjpeg):
            if task is not None and not task.done():
                task.cancel()
        for proc in (self._proc_jpeg, self._proc_h264, self._proc_mjpeg):
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._task_jpeg = self._task_h264 = self._task_mjpeg = None
        self._proc_jpeg = self._proc_h264 = self._proc_mjpeg = None

    async def ensure_running(self):
        # Global kill switch (config: [bridge] camera_enabled = 0). The printer's
        # RV1106 serves the camera itself, so three concurrent ffmpeg pulls are
        # real load on the same host that must feed the MCUs. When disabled we
        # never spawn a worker and therefore never open a printer connection.
        if not CAMERA_ENABLED:
            return
        # NOTE: we check the *task* state, not self._proc_* - the process
        # handle is only assigned later, inside the task body, once ffmpeg
        # has actually been spawned. Checking self._proc_* here left a race
        # window: two callers arriving before the newly-created task got a
        # chance to run would both see "no process yet" and each spawn a
        # duplicate ffmpeg + duplicate printer connection, silently
        # orphaning the older one (whichever task's coroutine runs last
        # overwrites the shared self._proc_* reference, so nobody keeps a
        # handle to kill the earlier orphaned process). Task creation is
        # synchronous, so checking self._task_* here is race-free.
        if self._task_jpeg is None or self._task_jpeg.done():
            self._task_jpeg = asyncio.create_task(self._run_jpeg_loop())
        if self._task_h264 is None or self._task_h264.done():
            self._task_h264 = asyncio.create_task(self._run_h264_loop())
        if self._task_mjpeg is None or self._task_mjpeg.done():
            self._task_mjpeg = asyncio.create_task(self._run_mjpeg_loop())

    def _input_args(self, url: str) -> list[str]:
        args = ["-fflags", "nobuffer", "-flags", "low_delay",
                 # Bail out if the source goes silent. A printer reboot or
                 # network loss leaves the TCP connection ESTABLISHED with no
                 # data and no FIN, so a passive stdout read blocks forever
                 # without this (Issue #99). Value is microseconds.
                 "-timeout", "10000000"]
        if url.lower().startswith("rtsp://"):
            args += ["-probesize", "32", "-analyzeduration", "0", "-rtsp_transport", "tcp"]
        else:
            # The printer's FLV source occasionally emits non-monotonic container
            # timestamps (PTS jumps of days) while the video data itself stays
            # valid. Without this flag ffmpeg's realtime pacing breaks on such a
            # jump and the stream stalls after ~15-30 min (Issue #90).
            args += ["-use_wallclock_as_timestamps", "1",
                     "-probesize", "500000", "-analyzeduration", "500000"]
        return args

    async def _run_jpeg_loop(self):
        """Keeps an ffmpeg process alive that writes MJPEG@2fps into the cache."""
        while True:
            url = self._url
            if not url:
                await asyncio.sleep(2.0)
                continue
            try:
                self._proc_jpeg = await asyncio.create_subprocess_exec(
                    _find_ffmpeg(), "-loglevel", "warning",
                    *self._input_args(url), "-i", url,
                    "-vf", "fps=2",
                    "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "3",
                    "-flush_packets", "1", "pipe:1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except Exception as e:
                log.warning(f"CameraCache: ffmpeg-jpeg start failed: {e}")
                await asyncio.sleep(3.0)
                continue

            buf = b""
            rc = None
            try:
                while True:
                    chunk = await self._proc_jpeg.stdout.read(self.TS_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    # extract complete JPEG frames
                    while True:
                        start = buf.find(self.JPEG_SOI)
                        if start == -1:
                            buf = b""
                            break
                        end = buf.find(self.JPEG_EOI, start + 2)
                        if end == -1:
                            buf = buf[start:]
                            break
                        self.latest_jpeg = buf[start:end + 2]
                        self.latest_jpeg_ts = time.time()
                        buf = buf[end + 2:]
            except Exception as e:
                log.debug(f"CameraCache: jpeg-loop unterbrochen: {e}")
            finally:
                # Kill + wait - otherwise the child process lingers as a zombie and
                # asyncio reports "Unknown child pid ..." on the next reaper tick.
                if self._proc_jpeg is not None:
                    try:
                        self._proc_jpeg.kill()
                    except Exception:
                        pass
                    try:
                        await self._proc_jpeg.wait()
                    except Exception:
                        pass
                    rc = self._proc_jpeg.returncode
                    if rc:
                        try:
                            err = await self._proc_jpeg.stderr.read(500)
                            if err:
                                log.warning(f"CameraCache: ffmpeg-jpeg stderr: {err.decode(errors='replace').strip()}")
                        except Exception:
                            pass
                self._proc_jpeg = None
            if rc:
                self._fail_count_jpeg += 1
                delay = min(2.0 * (2 ** self._fail_count_jpeg), 300.0)
                log.warning(f"CameraCache: ffmpeg-jpeg exit {rc}, retry in {delay:.0f}s (Versuch {self._fail_count_jpeg})")
                await asyncio.sleep(delay)
            else:
                self._fail_count_jpeg = 0
                await asyncio.sleep(2.0)

    async def _run_h264_loop(self):
        """Keeps an ffmpeg process alive that fans out MPEG-TS to all subscribers."""
        while True:
            url = self._url
            if not url:
                await asyncio.sleep(2.0)
                continue
            try:
                self._proc_h264 = await asyncio.create_subprocess_exec(
                    _find_ffmpeg(), "-loglevel", "warning",
                    *self._input_args(url), "-i", url,
                    "-c:v", "copy", "-an",
                    "-f", "mpegts", "pipe:1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except Exception as e:
                log.warning(f"CameraCache: ffmpeg-h264 start failed: {e}")
                await asyncio.sleep(3.0)
                continue

            rc = None
            try:
                while True:
                    chunk = await self._proc_h264.stdout.read(self.TS_CHUNK)
                    if not chunk:
                        break
                    # Fanout: non-blocking per subscriber; slow clients
                    # get their oldest chunk dropped (queue full -> drop).
                    for q in list(self.h264_subscribers):
                        if q.full():
                            try:
                                q.get_nowait()
                            except Exception:
                                pass
                        try:
                            q.put_nowait(chunk)
                        except Exception:
                            pass
            except Exception as e:
                log.debug(f"CameraCache: h264-loop unterbrochen: {e}")
            finally:
                if self._proc_h264 is not None:
                    try:
                        self._proc_h264.kill()
                    except Exception:
                        pass
                    try:
                        await self._proc_h264.wait()
                    except Exception:
                        pass
                    rc = self._proc_h264.returncode
                    if rc:
                        try:
                            err = await self._proc_h264.stderr.read(500)
                            if err:
                                log.warning(f"CameraCache: ffmpeg-h264 stderr: {err.decode(errors='replace').strip()}")
                        except Exception:
                            pass
                self._proc_h264 = None
            if rc:
                self._fail_count_h264 += 1
                delay = min(2.0 * (2 ** self._fail_count_h264), 300.0)
                log.warning(f"CameraCache: ffmpeg-h264 exit {rc}, retry in {delay:.0f}s (Versuch {self._fail_count_h264})")
                await asyncio.sleep(delay)
            else:
                self._fail_count_h264 = 0
                await asyncio.sleep(2.0)

    async def _run_mjpeg_loop(self):
        """Keeps an ffmpeg process alive that fans out MJPEG@15fps/640px
        (complete JPEG frames) to all /api/camera/stream subscribers."""
        while True:
            url = self._url
            if not url:
                await asyncio.sleep(2.0)
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    _find_ffmpeg(), "-loglevel", "warning",
                    *self._input_args(url), "-i", url,
                    "-vf", "fps=15,scale=640:-1",
                    "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "3",
                    "-flush_packets", "1", "pipe:1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                self._proc_mjpeg = proc
            except Exception as e:
                log.warning(f"CameraCache: ffmpeg-mjpeg start failed: {e}")
                await asyncio.sleep(3.0)
                continue

            buf = b""
            rc = None
            try:
                while True:
                    chunk = await proc.stdout.read(self.TS_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    # extract complete JPEG frames and fan them out whole
                    # (so every subscriber gets clean multipart boundaries,
                    # not arbitrary byte chunks like the h264/mpegts fanout)
                    while True:
                        start = buf.find(self.JPEG_SOI)
                        if start == -1:
                            buf = b""
                            break
                        end = buf.find(self.JPEG_EOI, start + 2)
                        if end == -1:
                            buf = buf[start:]
                            break
                        frame = buf[start:end + 2]
                        buf = buf[end + 2:]
                        for q in list(self.mjpeg_subscribers):
                            if q.full():
                                try:
                                    q.get_nowait()
                                except Exception:
                                    pass
                            try:
                                q.put_nowait(frame)
                            except Exception:
                                pass
            except Exception as e:
                log.debug(f"CameraCache: mjpeg-loop unterbrochen: {e}")
            finally:
                # NOTE: cleanup operates on the local `proc` reference, not
                # on self._proc_mjpeg. If this task got cancelled (e.g. by
                # reset()) a new task may already have started and assigned
                # its own process to self._proc_mjpeg by the time we reach
                # here - killing that shared attribute instead of our own
                # local proc would kill the WRONG (newer) process.
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
                rc = proc.returncode
                if rc:
                    try:
                        err = await proc.stderr.read(500)
                        if err:
                            log.warning(f"CameraCache: ffmpeg-mjpeg stderr: {err.decode(errors='replace').strip()}")
                    except Exception:
                        pass
                if self._proc_mjpeg is proc:
                    self._proc_mjpeg = None
            if rc:
                self._fail_count_mjpeg += 1
                delay = min(2.0 * (2 ** self._fail_count_mjpeg), 300.0)
                log.warning(f"CameraCache: ffmpeg-mjpeg exit {rc}, retry in {delay:.0f}s (Versuch {self._fail_count_mjpeg})")
                await asyncio.sleep(delay)
            else:
                self._fail_count_mjpeg = 0
                await asyncio.sleep(2.0)


class SpoolmanClient:
    """Thin synchronous HTTP client for Spoolman filament tracking.

    Designed to be called from daemon threads (poll loop, _on_print callbacks).
    Uses requests (already in requirements) so no event-loop dependency.
    """

    def __init__(self, server_url: str, sync_rate: int = 0):
        self.server_url = server_url.rstrip("/")
        self.sync_rate = sync_rate

    def _req(self, method: str, path: str, **kwargs):
        import requests
        r = requests.request(method, f"{self.server_url}{path}", timeout=5, **kwargs)
        r.raise_for_status()
        return r.json()

    def health_check(self) -> bool:
        try:
            self._req("GET", "/api/v1/health")
            return True
        except Exception:
            return False

    def list_spools(self) -> list:
        return self._req("GET", "/api/v1/spool")

    def use_filament(self, spool_id: int, use_length_mm: float) -> None:
        """Report consumed filament length in mm. Spoolman converts to weight
        using the spool's filament profile density."""
        self._req("PUT", f"/api/v1/spool/{spool_id}/use",
                  json={"use_length": round(use_length_mm, 2)})


class _JsonBodyRequest:
    """Minimal internal request adapter for routing compatibility APIs safely."""
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


class KobraXBridge:
    def __init__(self, client: KobraXClient, args=None, store=None, printer_id: str = "1", all_bridges=None):
        self.client = client
        self._args = args
        self._printer_id = printer_id
        self._all_bridges = all_bridges if all_bridges is not None else {}
        self._model = model_for_id(getattr(args, "model_id", "") or getattr(args, "mode_id", ""))
        self.ws_clients: set[web.WebSocketResponse] = set()
        # In-memory KV store for Moonraker /server/database/item (moonraker-obico,
        # mainsail presets etc.). Not persistent - does not survive a restart.
        self._moonraker_kv_store: dict[str, dict] = {}
        # Slot -> Orca filament profile mapping (from config.ini [filament_profiles]).
        # Format: {slot_idx: {"id": "OGFL01", "vendor": "Polymaker"}}.
        # Used in _build_lane_data so OrcaSlicer shows the concrete
        # brand ("PolyTerra PLA - Polymaker") instead of just "Generic PLA".
        try:
            import config_loader as _cl
            self._filament_profiles: dict[int, dict] = _cl.list_filament_profiles(self._printer_id)
        except Exception:
            self._filament_profiles = {}
        # Vendor visibility filter for the slot profile dropdown (Issue #41 option A).
        # Empty list = all vendors visible (backwards compatible).
        try:
            import config_loader as _cl
            self._visible_vendors: list[str] = _cl.list_visible_vendors(self._printer_id)
        except Exception:
            self._visible_vendors = []
        self._last_state: dict = {}
        self._last_ams_set_request: dict | None = None
        self._state = {
          "nozzle_temp":        0.0,
          "nozzle_target":      0.0,
          "bed_temp":           0.0,
          "bed_target":         0.0,
          "chamber_temp":       0.0,
          "chamber_target":     0.0,
          "model_id":           self._model.model_id if self._model else str(getattr(args, "model_id", "") or getattr(args, "mode_id", "") or ""),
          "model_name":         self._model.name if self._model else "",
          "print_state":        "standby",
          "kobra_state":        "free",
          "filename":           "",
          "slicer_time":        0,
          "progress":           0.0,
          "print_duration":     0,
          "remain_time":        0,
          "curr_layer":         0,
          "total_layers":       0,
          # Layer heights for the currently running file (parsed from the
          # GCode header). Set in the upload path + in _fetch_from_store.
          # Obico uses currentZ from gcode_position[2] - the bridge computes
          # currentZ from curr_layer + these values in build_print_payload.
          "layer_height":       0.0,
          "first_layer_height": 0.0,
          "printer_name":       env_loader.get("BRIDGE_PRINTER_NAME", "Anycubic Kobra X"),
          "firmware_version":   "unknown",
          "upload_url":         "",
          "camera_url":         "",
          "fan_speed":          0,
          "aux_fan_speed":      0,
          "box_fan_speed":      0,
          "light_on":           False,
          "light_brightness":   80,
          "taskid":             "-1",
          "print_speed_mode":   2,
          "connection_error":   "",
          "file_ready":         "",
          "filament_mismatch":  None,
          # Bridge -> printer transfer state. Written from executor threads;
          # each update replaces the dict atomically, so /api/state never sees
          # a partially mutated object.
          "upload_progress":    {"active": False, "filename": "", "sent": 0, "total": 0, "percent": 0, "phase": "idle", "error": ""},
          # Filename of a /kx/print that has been accepted but not yet reflected
          # by the printer's own state reports. Lives in the bridge, not the
          # browser, so a tab closed mid-dispatch cannot make the farm view
          # fall back to "Ready" for a printer that is about to start.
          # {filename, token, ts}; token prevents one request/error callback
          # from clearing a newer dispatch for the same printer.
          "print_pending":      None,
          "print_start_dialog": getattr(args, "print_start_dialog", 1),
          "filament_mode":      "toolhead",
          "supplies_usage":     0,
          "ace_drying": {"status": 0, "target_temp": 0, "duration": 0, "remain_time": 0, "humidity": None, "current_temp": None},
          "error_code":         0,
          "pause_msg":          "",
        }
        self._ams_slots: list[dict] = []       # flat global list; each entry has global_index + box_id
        self._ams_loaded_slot: int = -1        # global slot index of currently loaded slot
        self._pending_load_slot: int = -1      # global slot index requested via /api/ams/feed type=1
        self._last_feed_status: dict[int, tuple[int, int]] = {}  # box -> (status, slot), for edge-triggered tip forming
        self._ace_box_ids: list[int] = []      # detected ACE unit IDs (0..3)
        self._ace_auto_feed: dict[int, int] = {}   # per-box auto_feed state (0/1)
        self._head_tools_model: int = -1
        self._filament_mode: str = "toolhead"
        self._last_uploaded_file: str = ""
        # Pending waiter + lock per file/report action. The printer response has
        # only an action name (no request id), so concurrent same-action calls
        # cannot be correlated safely: serialize them instead of overwriting one
        # waiter or handing a deleteBatch reply to the wrong caller.
        self._file_action_waiters: dict[str, dict] = {}
        self._file_action_locks: dict[str, threading.Lock] = {}
        # Thumbnail cache for files on the printer's own storage (filename ->
        # base64 PNG string, "" if the file has no embedded thumbnail).
        # In-memory only - not persisted, cleared on restart.
        self._printer_thumbnail_cache: dict[str, str] = {}
        self._store = store if store is not None else GCodeStore(args.data_dir)
        self._serve_dir_path: str = self._store._gcode_dir
        self._print_pending_lock = threading.Lock()
        self._current_job_id: str = ""
        self._history_reconciled: bool = False
        self._camera_autostarted: bool = False
        self._camera_user_stopped: bool = False  # user manually stopped the camera during a print
        self._camera_source: str = "anycubic"
        self._camera_anycubic_url: str = ""
        self.camera_cache: CameraCache = CameraCache()

        self._thumbnail_b64: str = ""
        self._ace_dry_presets: dict[str, dict] = self._load_ace_dry_presets_config()

        # Part skip: most recent skip list reported by the printer (v0.9.10)
        self._skip_state: dict = {"objects": [], "skipped": [], "ts": 0}
        # Pre-Print-Skip: pending until printer enters printing state
        self._pending_preprint_skip: list[str] = []
        self._pending_preprint_skip_deadline: float = 0.0

        # Spoolman filament tracking
        _sm_url = (getattr(args, "spoolman_server", "") or "").strip()
        self._spoolman: SpoolmanClient | None = (
            SpoolmanClient(_sm_url, getattr(args, "spoolman_sync_rate", 0))
            if _sm_url else None
        )
        # Persistierte Spool-Zuordnung (AMS-Slot → Spoolman-Spool) je Drucker laden.
        # Fix: this used to reference `config_loader`, but the module alias is
        # `env_loader` (line 32) -> NameError swallowed by the bare `except`,
        # so persistence never loaded. Now via the local import + per printer.
        try:
            import config_loader as _cl
            self._spoolman_slot_spools: dict[int, int] = _cl.list_spool_map(self._printer_id)
        except Exception as _e:
            log.warning("Spoolman: failed to load slot map: %s", _e)
            self._spoolman_slot_spools = {}  # {ams_slot_idx: spoolman_spool_id}
        self._spoolman_slot_usage: dict[int, float] = {}   # per-slot accumulated mm this print
        self._spoolman_slot_reported: dict[int, float] = {}  # per-slot mm already sent to Spoolman
        self._spoolman_last_usage: float = 0.0   # supplies_usage at last attribution tick
        self._spoolman_last_sync: float = 0.0

        # Validate theme name (no special characters or umlauts)
        raw_theme = (getattr(args, "ui_theme", None) or "default").strip()
        if not _UI_THEME_NAME_RE.match(raw_theme):
            log.warning("Invalid UI theme name %r – using default", raw_theme)
            raw_theme = "default"
        self._ui_theme = raw_theme
        self._index_tpl_cache: str | None = None
        self._index_tpl_cache_key: tuple[str, float] | None = None
        # The complete Orca-compatible page inlines ~390 KB of CSS/JS. Build it
        # once per bridge process; deploy/update restarts the process anyway.
        self._index_page_cache: str | None = None

        # Register MQTT push callbacks
        client.callbacks["tempature/report"]      = self._on_temp
        client.callbacks["print/report"]          = self._on_print
        client.callbacks["info/report"]           = self._on_info
        client.callbacks["file/report"]           = self._on_file
        client.callbacks["multiColorBox/report"]  = self._on_multicolor_box
        client.callbacks["light/report"]          = self._on_light
        client.callbacks["skip/report"]           = self._on_skip

        # Reachability is rechecked periodically (not just once at boot) so the
        # UI status dot reflects the printer's/Spoolman's actual current state
        # instead of freezing on the boot-time result.
        self._spoolman_reachable: bool = False
        self._spoolman_last_health_check: float = 0.0
        if self._spoolman:
            def _check():
                ok = self._spoolman.health_check()
                self._spoolman_reachable = ok
                self._spoolman_last_health_check = time.time()
                log.info(f"Spoolman: {'OK' if ok else 'unreachable'} at {self._spoolman.server_url}")
            threading.Thread(target=_check, daemon=True, name="spoolman-health").start()

    # ── Spoolman helpers ──────────────────────────────────────────────────────

    def _spoolman_filament_mm(self) -> float:
        """Total filament_used_mm for the current print file from the GCode DB."""
        filename = self._state.get("filename", "")
        if not filename:
            return 0.0
        try:
            gf = self._store.get_file_by_name(filename)
            return float(gf.get("filament_used_mm") or 0.0) if gf else 0.0
        except Exception:
            return 0.0

    def _spoolman_attribute_tick(self, activity_map: dict) -> None:
        """Attribute the supplies_usage delta since last tick to the active slot.

        Skips attribution during loading/unloading transitions (tool changes +
        purges) to avoid charging the wrong spool for purge material."""
        if not self._spoolman or not self._spoolman_slot_spools:
            return
        if self._state.get("print_state") != "printing":
            return
        current = self._state.get("supplies_usage", 0)
        delta = current - self._spoolman_last_usage
        self._spoolman_last_usage = current
        if delta <= 0:
            return
        loaded = self._ams_loaded_slot
        if loaded < 0:
            return
        if activity_map.get(loaded):
            return
        self._spoolman_slot_usage[loaded] = self._spoolman_slot_usage.get(loaded, 0.0) + delta

    def _spoolman_unreported(self) -> dict[int, float]:
        """Return {slot_idx: mm} of usage not yet reported to Spoolman.

        Falls back to equal split of total supplies_usage when per-slot
        attribution data is absent (e.g. single-extruder with no AMS)."""
        total_used = self._state.get("supplies_usage", 0)
        if self._spoolman_slot_usage:
            return {
                slot: self._spoolman_slot_usage.get(slot, 0.0)
                       - self._spoolman_slot_reported.get(slot, 0.0)
                for slot in self._spoolman_slot_spools
            }
        n = len(self._spoolman_slot_spools)
        already = sum(self._spoolman_slot_reported.values())
        per = (total_used - already) / n if n else 0.0
        return {slot: per for slot in self._spoolman_slot_spools}

    def _spoolman_report(self, unreported: dict[int, float], min_mm: float = 0.1) -> None:
        """Fire-and-forget report of unreported mm to each mapped spool."""
        sm = self._spoolman
        for slot_idx, mm in unreported.items():
            if mm < min_mm:
                continue
            spool_id = self._spoolman_slot_spools.get(slot_idx)
            if not spool_id:
                continue
            self._spoolman_slot_reported[slot_idx] = (
                self._spoolman_slot_reported.get(slot_idx, 0.0) + mm
            )
            def _send(sid=spool_id, length=mm):
                try:
                    sm.use_filament(sid, length)
                    log.info(f"Spoolman: {length:.1f} mm → spool {sid}")
                except Exception as e:
                    log.warning(f"Spoolman: report failed (spool {sid}): {e}")
            threading.Thread(target=_send, daemon=True, name="spoolman-report").start()

    def _spoolman_notify_end(self):
        """Report remaining filament on print end."""
        if not self._spoolman or not self._spoolman_slot_spools:
            return
        self._spoolman_report(self._spoolman_unreported())

    def _spoolman_sync_midprint(self):
        """Report incremental filament usage during a print (sync_rate interval)."""
        if not self._spoolman or not self._spoolman_slot_spools:
            return
        self._spoolman_report(self._spoolman_unreported(), min_mm=10.0)

    # ── Spoolman API handlers ─────────────────────────────────────────────────

    async def handle_kx_spoolman_status(self, request):
        """GET /kx/spoolman/status"""
        return self._json_cors({
            "configured":   bool(self._spoolman),
            "reachable":    self._spoolman_reachable if self._spoolman else False,
            "server":       self._spoolman.server_url if self._spoolman else "",
            "sync_rate":    self._spoolman.sync_rate if self._spoolman else 0,
            "slot_spools":  {str(k): v for k, v in self._spoolman_slot_spools.items()},
        })

    async def handle_kx_spoolman_spools(self, request):
        """GET /kx/spoolman/spools — proxied from Spoolman."""
        if not self._spoolman:
            return self._json_cors({"error": "Spoolman not configured"}, status=503)
        try:
            spools = await asyncio.get_event_loop().run_in_executor(
                None, self._spoolman.list_spools
            )
            return self._json_cors({"spools": spools})
        except Exception as e:
            log.warning(f"Spoolman: list_spools failed: {e}")
            return self._json_cors({"error": str(e)}, status=502)

    async def handle_kx_spoolman_set_active(self, request):
        """POST /kx/spoolman/active-spool
        Body: {"slot_map": {"0": 42, "2": 17}}  — AMS slot index → Spoolman spool ID."""
        try:
            data = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid JSON"}, status=400)
        slot_map = data.get("slot_map") or data.get("slot_spools") or {}
        self._spoolman_slot_spools = {
            int(k): int(v) for k, v in slot_map.items()
            if str(v).isdigit() and int(v) > 0
        }
        # Persist per printer (own [spoolman_<id>] section) so the
        # assignment survives bridge restarts and two AMS units don't overwrite each other.
        # (Previously: NameError on `config_loader` -> nothing was ever saved.)
        try:
            import config_loader as _cl
            _cl.save_spool_map(self._spoolman_slot_spools, self._printer_id)
        except Exception as _e:
            log.warning("Spoolman: failed to save slot map: %s", _e)
        self._spoolman_slot_usage = {}
        self._spoolman_slot_reported = {}
        self._spoolman_last_usage = 0.0
        return self._json_cors({"slot_spools": {str(k): v for k, v in self._spoolman_slot_spools.items()}})

    def _default_ace_dry_presets(self) -> dict[str, dict]:
        return {
            "pla": {"temp": 45, "duration_sec": 4 * 3600},
        "pla_plus": {"temp": 45, "duration_sec": 4 * 3600},
        "petg": {"temp": 50, "duration_sec": 4 * 3600},
        "tpu": {"temp": 55, "duration_sec": 4 * 3600},
        "abs_asa": {"temp": 45, "duration_sec": 8 * 3600},
        "pa_pc": {"temp": 55, "duration_sec": 12 * 3600},
        "custom_1": {"name": "Custom 1", "temp": 45, "duration_sec": 4 * 3600},
        "custom_2": {"name": "Custom 2", "temp": 45, "duration_sec": 4 * 3600},
        "custom_3": {"name": "Custom 3", "temp": 45, "duration_sec": 4 * 3600},
        }

    def _sanitize_ace_dry_presets(self, presets: dict) -> dict[str, dict]:
        out = self._default_ace_dry_presets()
        for key in list(out.keys()):
            src = presets.get(key) if isinstance(presets, dict) else None
            if not isinstance(src, dict):
                continue
            try:
                t = int(src.get("temp", out[key]["temp"]))
            except Exception:
                t = out[key]["temp"]
            try:
                d = int(src.get("duration_sec", out[key]["duration_sec"]))
            except Exception:
                d = out[key]["duration_sec"]
            out[key]["temp"] = max(30, min(80, t))
            out[key]["duration_sec"] = max(10 * 60, min(24 * 3600, d))
            if key.startswith("custom_"):
                name = str(src.get("name", out[key].get("name", key.replace("_", " ").title()))).strip()
                out[key]["name"] = name or out[key].get("name", "Custom")
        return out

    def _load_ace_dry_presets_config(self) -> dict[str, dict]:
        import configparser
        defaults = self._default_ace_dry_presets()
        cfg_path = self._find_config_path()
        if not cfg_path.is_file():
            return defaults
        cfg = configparser.ConfigParser()
        cfg.read(cfg_path, encoding="utf-8")
        sec = "ace_dry_presets"
        if not cfg.has_section(sec):
            return defaults
        out = {}
        for key, d in defaults.items():
            temp_k = f"{key}_temp"
            dur_k = f"{key}_duration_sec"
            try:
                temp = int(cfg.get(sec, temp_k, fallback=str(d["temp"])))
            except Exception:
                temp = d["temp"]
            try:
                dur = int(cfg.get(sec, dur_k, fallback=str(d["duration_sec"])))
            except Exception:
                dur = d["duration_sec"]
            out[key] = {
                "temp": max(30, min(80, temp)),
                "duration_sec": max(10 * 60, min(24 * 3600, dur)),
            }
            if key.startswith("custom_"):
              name_k = f"{key}_name"
              name = cfg.get(sec, name_k, fallback=str(d.get("name", key.replace("_", " ").title()))).strip()
              out[key]["name"] = name or str(d.get("name", "Custom"))
        return out

    # -------------------------------------------------------------------------
    # MQTT callbacks (called from reader thread)
    # -------------------------------------------------------------------------

    def _on_temp(self, payload: dict):
        d = payload.get("data") or {}
        self._state["nozzle_temp"]   = float(d.get("curr_nozzle_temp", 0))
        self._state["nozzle_target"] = float(d.get("target_nozzle_temp", 0))
        self._state["bed_temp"]      = float(d.get("curr_hotbed_temp", 0))
        self._state["bed_target"]    = float(d.get("target_hotbed_temp", 0))
        self._push_status_update()

    def _set_print_pending(self, filename: str) -> str:
        """Atomically reserve this printer for one dispatch; returns its token."""
        with self._print_pending_lock:
            pending = self._state.get("print_pending")
            if isinstance(pending, dict):
                age = time.time() - float(pending.get("ts") or 0.0)
                if pending.get("filename") and age <= PRINT_PENDING_TTL:
                    return ""
            token = uuid.uuid4().hex
            self._state["print_pending"] = {
                "filename": filename, "token": token, "ts": time.time(),
            }
            return token

    def _clear_print_pending(self, token: str = "") -> bool:
        with self._print_pending_lock:
            pending = self._state.get("print_pending")
            if token and (not isinstance(pending, dict) or pending.get("token") != token):
                return False
            self._state["print_pending"] = None
            return True

    def _pending_active(self) -> str:
        """Pending filename, or "" once it has aged past PRINT_PENDING_TTL."""
        with self._print_pending_lock:
            pending = self._state.get("print_pending")
            if not isinstance(pending, dict):
                return ""
            name = pending.get("filename") or ""
            if name and time.time() - float(pending.get("ts") or 0.0) > PRINT_PENDING_TTL:
                self._state["print_pending"] = None
                return ""
            return name

    def _model_payload(self) -> dict:
        model = self._model
        if not model:
            return {
                "model_id": self._state.get("model_id", ""),
                "model_name": self._state.get("model_name", ""),
                "model_supported": False,
            }
        return {
            "model_id": model.model_id,
            "model_name": model.name,
            "model_supported": True,
            "build_volume_mm": list(model.build_volume_mm),
            "nozzle_diameters_mm": list(model.nozzle_diameters_mm),
            "max_nozzle_c": model.max_nozzle_c,
            "max_bed_c": model.max_bed_c,
            "max_chamber_c": model.max_chamber_c,
            "max_colors": model.max_colors,
            "max_ace_units": model.max_ace_units,
            "enclosed": model.enclosed,
        }

    def _history_aliases(self) -> list[str]:
        device_id = getattr(self._args, "device_id", "") or ""
        return [device_id] if device_id and device_id != self._printer_id else []

    def _claim_history_job(self, filename: str, elapsed_sec: int = 0,
                           assignments: list | None = None) -> str:
        if not filename:
            return ""
        # Normal telemetry repeats every few seconds. Once this process owns a
        # row, only the HTTP path with assignments needs to touch it again.
        if self._current_job_id and assignments is None:
            return self._current_job_id
        gcode_file = self._store.get_file_by_name(filename)
        if not gcode_file:
            return ""
        job_id = self._store.claim_job(
            gcode_file["id"], self._printer_id,
            aliases=self._history_aliases(),
            started_at_epoch=time.time() - max(0, int(elapsed_sec or 0)),
            filament_assignments=assignments,
        )
        self._current_job_id = job_id
        self._history_reconciled = True
        return job_id

    def _finish_history_jobs(self, status: str) -> str:
        job_id = self._store.finish_open_jobs(
            self._printer_id, aliases=self._history_aliases(),
            status=status, current_job_id=self._current_job_id,
        )
        self._current_job_id = ""
        self._history_reconciled = True
        return job_id

    def _reset_terminal_state(self):
        self._state.update({
            "progress": 0.0, "filename": "", "file_ready": "",
            "print_duration": 0, "remain_time": 0, "slicer_time": 0,
            "layer_height": 0.0, "first_layer_height": 0.0,
            "supplies_usage": 0, "curr_layer": 0, "total_layers": 0,
        })
        self._thumbnail_b64 = ""

    def _on_print(self, payload: dict):
        d = payload.get("data") or {}
        kobra_state = payload.get("state", "")
        # Command acknowledgements also arrive on print/report with state="done".
        # "done" is not a lifecycle state and used to overwrite a real
        # printing/paused state, letting safety checks misclassify the printer.
        # Only known lifecycle states may mutate the cached printer state.
        if kobra_state in KOBRA_TO_KLIPPER_STATE:
            self._state["print_state"] = KOBRA_TO_KLIPPER_STATE[kobra_state]
            self._state["kobra_state"] = kobra_state
            # Clear only when the printer proves it picked up THIS dispatch.
            # A delayed terminal/free report from the previous job can arrive
            # after the next /kx/print was accepted and must not clear it.
            if kobra_state in (
                    "busy", "printing", "preheating", "auto_leveling",
                    "checking", "updated", "init", "pausing", "pause",
                    "paused", "resuming", "resumed"):
                self._clear_print_pending()

        # Automatically switch on the camera at print start (settings option).
        # Centralized here so it covers all print start paths (OrcaSlicer + UI).
        # _camera_autostarted verhindert Mehrfach-Trigger pro Druck.
        if kobra_state == "printing":
            if (CAMERA_ENABLED
                    and getattr(self._args, "camera_on_print", 0)
                    and not self._camera_autostarted
                    and not self._camera_user_stopped):
                self._camera_autostarted = True
                try:
                    self.client.start_camera()
                    log.info("Camera switched on automatically at print start")
                except Exception as e:
                    log.warning(f"Camera auto-start failed: {e}")
        elif kobra_state in ("free", "finished", "stoped", "canceled"):
            self._camera_autostarted = False
            self._camera_user_stopped = False  # release for the next print

        if kobra_state in ("pause", "paused"):
            pause_msg = payload.get("msg", "")
            if pause_msg:
                error_code = payload.get("code", 0)
                self._state["error_code"] = error_code
                self._state["pause_msg"] = pause_msg
                log.warning(f"Printer paused: [{error_code}] {pause_msg}")
        elif kobra_state in ("resuming", "resumed", "printing", "finished", "stoped", "canceled"):
            self._state["error_code"] = 0
            self._state["pause_msg"] = ""

        # Job history must be durable across callback/HTTP races and bridge
        # restarts. Both paths claim the same DB row atomically.
        if kobra_state == "printing":
            filename = d.get("filename", self._state.get("filename", ""))
            job_id = self._claim_history_job(filename, int(d.get("print_time") or 0) * 60)
            if job_id:
                log.info(f"Job active: {job_id} for {filename}")
            self._spoolman_slot_usage = {}
            self._spoolman_slot_reported = {}
            self._spoolman_last_usage = 0.0
            self._spoolman_last_sync = 0.0

        # A terminal report may arrive only on info/report on some firmware, so
        # this helper is idempotent and shared with _on_info.
        if kobra_state == "finished":
            job_id = self._finish_history_jobs("completed")
            if job_id:
                log.info(f"Job completed: {job_id}")
                self._spoolman_notify_end()
        elif kobra_state in ("stoped", "canceled"):
            job_id = self._finish_history_jobs("cancelled")
            if job_id:
                log.info(f"Job cancelled: {job_id}")
                self._spoolman_notify_end()

        # Terminal payloads often still contain the just-finished project's
        # filename/progress/time. Reset once and do not copy those stale fields
        # back in below.
        terminal = kobra_state in ("finished", "stoped", "canceled")
        if terminal:
            self._reset_terminal_state()
        else:
            self._state["filename"] = d.get("filename", self._state["filename"])
            # Pre-print progress is not print progress; it resets when extrusion starts.
            if "progress" in d and kobra_state not in ("preheating", "auto_leveling", "checking", "updated", "init"):
                self._state["progress"] = float(d["progress"]) / 100.0
            if "print_time" in d:
                self._state["print_duration"] = int(d["print_time"]) * 60
            if "remain_time" in d:
                self._state["remain_time"] = int(d["remain_time"]) * 60
            if "curr_layer" in d:
                self._state["curr_layer"] = d["curr_layer"]
            if "total_layers" in d:
                self._state["total_layers"] = d["total_layers"]
            if "supplies_usage" in d:
                self._state["supplies_usage"] = int(d["supplies_usage"])
        if "taskid" in d:
            self._state["taskid"] = str(d["taskid"])
        settings = d.get("settings") or {}
        if "print_speed_mode" in settings:
            self._state["print_speed_mode"] = int(settings["print_speed_mode"])
        self._push_status_update()

    def _on_info(self, payload: dict):
        d = payload.get("data") or {}
        detected = (model_for_id(getattr(self._args, "model_id", "") or getattr(self._args, "mode_id", ""))
                    or model_for_name(d.get("model") or d.get("printerName")))
        if detected:
            self._model = detected
            self._state["model_id"] = detected.model_id
            self._state["model_name"] = detected.name
        # Only adopt the MQTT name if no custom name is set (env or per-printer config)
        if not env_loader.get("BRIDGE_PRINTER_NAME") and not getattr(self, "_name_locked", False):
            self._state["printer_name"] = d.get("printerName", self._state["printer_name"])
        self._state["firmware_version"] = d.get("version", self._state["firmware_version"])
        # The real print state lives in info/report inside the nested
        # project.state ("printing"/"paused"/...). The top-level data.state is only
        # the device state ("busy"/"free") and would swallow "paused".
        project = d.get("project") or {}
        proj_state = project.get("state", "")
        kobra_state = proj_state or d.get("state", "")
        terminal = kobra_state in ("finished", "stoped", "canceled")
        # Same ACK filter as _on_print: info/report also carries envelope
        # states such as "done" that are not lifecycle states. Adopting them
        # here would reset kobra_state mid-print and mislead safety checks.
        if kobra_state in KOBRA_TO_KLIPPER_STATE:
            self._state["print_state"] = KOBRA_TO_KLIPPER_STATE[kobra_state]
            self._state["kobra_state"] = kobra_state
            # Same pickup-only rule as _on_print; terminal/free can belong to
            # the previous job and must not erase a newer dispatch.
            if kobra_state in (
                    "busy", "printing", "preheating", "auto_leveling",
                    "checking", "updated", "init", "pausing", "pause",
                    "paused", "resuming", "resumed"):
                self._clear_print_pending()
            # Reconcile durable history from info/report too: on some firmware
            # this is the only lifecycle source, and it is the first state after
            # a bridge restart while a physical print keeps running.
            active_states = ("busy", "printing", "preheating", "auto_leveling", "checking", "updated", "init")
            if kobra_state in active_states:
                filename = project.get("filename") or self._state.get("filename", "")
                self._claim_history_job(filename, int(project.get("print_time") or 0) * 60)
            elif terminal:
                self._finish_history_jobs("completed" if kobra_state == "finished" else "cancelled")
                self._reset_terminal_state()
            elif kobra_state == "free" and not self._history_reconciled:
                # First idle report after restart proves every inherited open row
                # is stale. Keep one as interrupted; retire duplicates.
                self._finish_history_jobs("interrupted")
            # Camera auto-start here as well (OrcaSlicer often reports the start via info/report).
            # The _camera_autostarted guard prevents a double start with _on_print.
            if kobra_state == "printing":
                if (CAMERA_ENABLED
                        and getattr(self._args, "camera_on_print", 0)
                        and not self._camera_autostarted
                        and not self._camera_user_stopped):
                    self._camera_autostarted = True
                    try:
                        self.client.start_camera()
                        log.info("Camera switched on automatically at print start")
                    except Exception as e:
                        log.warning(f"Camera auto-start failed: {e}")
            elif kobra_state in ("free", "finished", "stoped", "canceled"):
                self._camera_autostarted = False
                self._camera_user_stopped = False  # release for the next print
        if project and not terminal:
            if "filename" in project:
                self._state["filename"] = project["filename"]
            # Same non-monotonic-progress guard as _on_print (Issue #102).
            if "progress" in project and kobra_state not in ("preheating", "auto_leveling", "checking", "updated", "init"):
                self._state["progress"] = float(project["progress"]) / 100.0
            if "print_time" in project:
                self._state["print_duration"] = int(project["print_time"]) * 60
            if "remain_time" in project:
                self._state["remain_time"] = int(project["remain_time"]) * 60
            if "curr_layer" in project:
                self._state["curr_layer"] = project["curr_layer"]
            if "total_layers" in project:
                self._state["total_layers"] = project["total_layers"]
        t = d.get("temp") or {}
        if t:
            self._state["nozzle_temp"]   = float(t.get("curr_nozzle_temp", 0))
            self._state["nozzle_target"] = float(t.get("target_nozzle_temp", 0))
            self._state["bed_temp"]      = float(t.get("curr_hotbed_temp", 0))
            self._state["bed_target"]    = float(t.get("target_hotbed_temp", 0))
            self._state["chamber_temp"]  = float(t.get("curr_chamber_temp", 0))
            self._state["chamber_target"] = float(t.get("target_chamber_temp", 0))
        urls = d.get("urls") or {}
        if urls.get("fileUploadurl"):
            self._state["upload_url"] = urls["fileUploadurl"]
        if urls.get("rtspUrl") and CAMERA_ENABLED:
            self._camera_anycubic_url = urls["rtspUrl"]
            if getattr(self, "_camera_source", "anycubic") != "rinkhals":
                self._state["camera_url"] = urls["rtspUrl"]
                self.camera_cache.set_url(urls["rtspUrl"])
        fan = d.get("fan_speed_pct")
        if fan is not None:
            self._state["fan_speed"] = int(fan)
        aux_fan = d.get("aux_fan_speed_pct")
        if aux_fan is not None:
            self._state["aux_fan_speed"] = int(aux_fan)
        box_fan = d.get("box_fan_level")
        if box_fan is not None:
            self._state["box_fan_speed"] = int(box_fan)
        speed_mode = d.get("print_speed_mode")
        if speed_mode is not None:
            self._state["print_speed_mode"] = int(speed_mode)
        self._push_status_update()

    def _on_skip(self, payload: dict):
        """skip/report-Callback (Part-Skip-Feature, v0.9.10).

        The printer ALWAYS reports the list of already-skipped objects here
        (objects_skip_parts), whether on query_obj or after skip/start.
        The full object list comes from file/report.
        """
        d = payload.get("data") or {}
        skipped = d.get("objects_skip_parts") or d.get("skipped") or d.get("skipped_parts") or []
        # While a pre-print skip is still pending, ignore empty early reports
        # so the UI doesn't snap back before the printer confirms the skip.
        now = time.time()
        if (not skipped and self._pending_preprint_skip
                and now <= self._pending_preprint_skip_deadline):
            return

        # During an active print, skip states are effectively monotonic.
        # Some firmware reports come back empty/partial in between;
        # those must not remove already-confirmed skip objects from the UI.
        existing_skipped = [str(n) for n in (self._skip_state.get("skipped") or []) if n]
        existing_set = set(existing_skipped)
        incoming_skipped = [str(n) for n in (skipped or []) if n]
        incoming_set = set(incoming_skipped)
        active_print = self._state.get("print_state") in ("printing", "paused")
        if active_print and existing_set:
            if not incoming_set:
                skipped = list(existing_skipped)
            elif not incoming_set.issuperset(existing_set):
                merged = list(existing_skipped)
                for n in incoming_skipped:
                    if n not in existing_set:
                        merged.append(n)
                skipped = merged

        # Release the pending lock once the printer confirms the requested objects
        if self._pending_preprint_skip and set(skipped) >= set(self._pending_preprint_skip):
            self._pending_preprint_skip = []
            self._pending_preprint_skip_deadline = 0.0
        self._skip_state = {
            "skipped":  list(skipped),
            "ts":       int(time.time()),
        }
        if payload.get("state") == "done" or payload.get("code") == 200:
            log.info(f"Skip response: state={payload.get('state')} code={payload.get('code')} skipped={skipped}")

    def _wait_for_file_action(self, action: str, send_fn, timeout: float = 8.0) -> dict | None:
        """Sends a file/* MQTT request (via send_fn, which must call
        self.client.publish(..., timeout=0) fire-and-forget) and blocks the
        calling thread until a matching file/report with this `action`
        arrives via _on_file, or the timeout elapses.

        Needed because the printer's publish() return value for actions like
        listLocal/deleteBatch is just a generic immediate ACK skeleton
        (code=0, empty fields) - the real response is a separate, later
        file/report message, same as the existing fileDetails pattern.
        Must be called from a worker thread (e.g. via run_in_executor), not
        the asyncio event loop, since it blocks on a threading.Event.
        """
        # Replies carry only the action name, never a request id, so two
        # concurrent listLocal/deleteBatch calls cannot tell whose answer
        # arrived. A per-action lock serializes them: the second caller waits for
        # the first round trip, then sends its own request. Before, a Browser-tab
        # refresh racing a farm dispatch overwrote the print path's waiter
        # (8 s stall, 502, possible redundant 200 MB re-upload).
        lock = self._file_action_locks.setdefault(action, threading.Lock())
        with lock:
            event = threading.Event()
            waiter = {"event": event, "result": None}
            self._file_action_waiters[action] = waiter
            try:
                send_fn()
                event.wait(timeout)
                return waiter["result"]
            finally:
                if self._file_action_waiters.get(action) is waiter:
                    del self._file_action_waiters[action]

    def _on_file(self, payload: dict):
        # Deliver to the pending listLocal/deleteBatch waiter first (see
        # _wait_for_file_action) - these actions carry no file_details/
        # thumbnail payload of their own, so this doesn't interfere with the
        # handling below.
        action = payload.get("action") or ""
        waiter = self._file_action_waiters.get(action)
        if waiter is not None:
            waiter["result"] = payload
            waiter["event"].set()

        d = payload.get("data") or {}
        details = d.get("file_details") or {}
        thumb = details.get("thumbnail") or details.get("png_image") or ""
        file_name = d.get("filename") or details.get("filename") or self._last_uploaded_file
        active_print = self._state.get("print_state") in ("printing", "paused")
        current_print_file = self._state.get("filename") or ""
        # Uploads during a running print must not overwrite the active
        # progress preview.
        if thumb and (not active_print or (file_name and file_name == current_print_file)):
            self._thumbnail_b64 = thumb
            log.info(f"Thumbnail received: {len(thumb)} base64 chars")
        # Part-Skip: Objekt-Liste + optionales SVG (v0.9.10)
        objs = details.get("objects_skip_parts") or []
        svg  = details.get("svg_image") or ""
        if objs:
            filename = file_name
            if filename:
                try:
                    self._store.update_file_objects(filename, objs, svg)
                    log.info(f"Skip objects for {filename}: {len(objs)} ({'with SVG' if svg else 'no SVG'})")
                except Exception as e:
                    log.warning(f"update_file_objects failed: {e}")
        self._push_status_update()

    def _apply_preprint_skip_after_start(self, names: list[str], retries: int = 20, delay_s: float = 0.75):
        """Sends the skip command only after the printer switched to the printing state.

        Before that, the command goes nowhere (no active print).
        """
        wanted = [str(n) for n in (names or []) if isinstance(n, str) and n]
        if not wanted:
            return False
        for i in range(max(1, int(retries))):
            try:
                if self._state.get("print_state") not in ("printing", "paused"):
                    time.sleep(max(0.1, float(delay_s)))
                    continue
                resp = self.client.skip_objects(wanted)
                if resp is not None:
                    log.info(f"Pre-Print skip applied ({len(wanted)} objects) on attempt {i+1}/{retries}")
                    self._pending_preprint_skip = []
                    self._pending_preprint_skip_deadline = 0.0
                    return True
            except Exception as e:
                log.debug(f"Pre-Print skip attempt {i+1}/{retries} failed: {e}")
            time.sleep(max(0.1, float(delay_s)))
        log.warning(f"Pre-Print skip could not be confirmed after {retries} attempts")
        self._pending_preprint_skip = []
        self._pending_preprint_skip_deadline = 0.0
        return False

    @staticmethod
    def _detect_filament_mode(boxes: list, head_tools_model: int = -1) -> str:
        """Detect active filament topology mode.

        Modes:
        - toolhead: only toolhead slots
        - ace_direct: ACE channels directly mapped, no toolhead box present.
          Covers one unit (Kobra X) as well as multiple daisy-chained units
          (Kobra S1 with 2+ ACE Pro, Issue #95) — each unit contributes a
          block of 4 global slots at box_id * 4.
        - ace_hub: toolhead + ACE via hub (slot 4 as hub path)
        """
        toolhead = any(b.get("id") == -1 for b in boxes)
        ace = any(b.get("id", -1) >= 0 for b in boxes)
        if ace and toolhead:
            return "ace_hub"
        if ace:
            return "ace_direct"
        return "toolhead"

    @staticmethod
    def _aggregate_slots(boxes: list, mode: str = "toolhead") -> tuple:
        """Aggregate multi_color_box list into a flat global slot list."""
        toolhead = next((b for b in boxes if b.get("id") == -1), None)
        ace_boxes = sorted(
            [b for b in boxes if b.get("id", -1) >= 0],
            key=lambda b: b["id"]
        )

        global_slots: list = []
        global_loaded: int = -1

        if mode == "toolhead":
            if toolhead:
                for local_idx, s in enumerate(toolhead.get("slots") or []):
                    s = dict(s)
                    s["global_index"] = local_idx
                    s["box_id"] = -1
                    global_slots.append(s)
                loaded = toolhead.get("loaded_slot", -1)
                if loaded >= 0:
                    global_loaded = loaded
            return global_slots, global_loaded

        if mode == "ace_direct":
            # One or more ACE units, no toolhead buffer (Kobra X: 1 unit,
            # Kobra S1: up to 2+ units, Issue #95). Global index =
            # box_id * 4 + local slot, so the numbering matches
            # _global_to_box_slot's //4-%4 fallback and stays stable
            # regardless of report order.
            for ace in ace_boxes:
                ace_id = int(ace["id"])
                base = ace_id * 4
                for local_idx, s in enumerate((ace.get("slots") or [])[:4]):
                    s = dict(s)
                    s["global_index"] = base + local_idx
                    s["box_id"] = ace_id
                    global_slots.append(s)
                ace_loaded = ace.get("loaded_slot", -1)
                if 0 <= ace_loaded < 4:
                    global_loaded = base + ace_loaded
            return global_slots, global_loaded

        # ace_hub
        if toolhead:
            for local_idx, s in enumerate((toolhead.get("slots") or [])[:3]):
                s = dict(s)
                s["global_index"] = local_idx
                s["box_id"] = -1
                global_slots.append(s)
            th_loaded = toolhead.get("loaded_slot", -1)
            if 0 <= th_loaded <= 2:
                global_loaded = th_loaded

        for ace in ace_boxes:
            ace_id = ace["id"]
            base = 3 + ace_id * 4
            for local_idx, s in enumerate(ace.get("slots") or []):
                s = dict(s)
                s["global_index"] = base + local_idx
                s["box_id"] = ace_id
                global_slots.append(s)
            ace_loaded = ace.get("loaded_slot", -1)
            if ace_loaded >= 0:
                global_loaded = base + ace_loaded

        return global_slots, global_loaded

    def _global_to_box_slot(self, global_index: int) -> tuple:
        """Convert a global slot index to (box_id, local_slot_index)."""
        for s in self._ams_slots:
            if s.get("global_index") == global_index:
                return s.get("box_id", -1), s.get("index", global_index)

        ace_present = any(s.get("box_id", -1) >= 0 for s in self._ams_slots)
        if self._filament_mode == "ace_direct" and ace_present:
            return global_index // 4, global_index % 4
        if not ace_present or global_index < 3:
            return -1, global_index
        offset = global_index - 3
        return offset // 4, offset % 4

    def _slot_to_print_ams_index(self, global_index: int) -> int:
      """Convert UI/global slot index to printer print/start ams_index.

      In ace_hub mode, print/start uses global channel numbering where
      toolhead channels occupy 1..3 and ACE0 starts at index 4.
      """
      idx = int(global_index)
      if self._filament_mode == "ace_hub":
        box_id, local_slot = self._global_to_box_slot(idx)
        if box_id >= 0:
          return 4 + box_id * 4 + int(local_slot)
        return idx
      return idx

    def _slot_usable_for_print(self, global_index: int) -> bool:
        """Whether a global slot can be used for current filament mode."""
        slot = next((s for s in self._ams_slots if int(s.get("global_index", -1)) == int(global_index)), None)
        if not slot:
            return False
        # S1 firmware reports status=5 for empty ACE slots too; material/type
        # is the occupancy signal shared across Kobra X, S1 and S1 Max.
        if int(slot.get("status", 0)) != 5 or not str(slot.get("type") or "").strip():
            return False

        box_id = int(slot.get("box_id", -1))
        if self._filament_mode == "ace_hub":
          # In hub mode, toolhead channels (0..2) and ACE channels are both printable.
          return box_id == -1 or box_id >= 0
        if self._filament_mode == "ace_direct":
            return box_id >= 0
        return box_id == -1

    def _loaded_slots_for_print(self) -> list[tuple[int, dict]]:
        """Loaded slots filtered for current filament mode."""
        loaded = [
            (int(s.get("global_index", i)), s)
            for i, s in enumerate(self._ams_slots)
        if s.get("status") == 5 and self._slot_usable_for_print(int(s.get("global_index", i)))
        ]
        return loaded

    def _select_loaded_slots_for_print(self, warn_on_empty_default: bool = False) -> list[tuple[int, dict]]:
        """Return loaded slots, honoring default_ams_slot when configured."""
        default_slot = getattr(self._args, "default_ams_slot", "auto")
        all_loaded = self._loaded_slots_for_print()
        if default_slot == "auto":
            return all_loaded

        try:
            slot_idx = int(default_slot)
        except ValueError:
            return all_loaded

        selected = [(i, s) for i, s in all_loaded if i == slot_idx]
        if selected:
            return selected

        if warn_on_empty_default:
            log.warning(f"Default slot {slot_idx} is empty - falling back to auto")
        return all_loaded

    @staticmethod
    def _slot_color_rgba(slot: dict) -> list[int]:
        color = slot.get("color", [255, 255, 255])
        if isinstance(color, list) and len(color) >= 3:
            return [int(color[0]), int(color[1]), int(color[2]), 255]
        return [255, 255, 255, 255]

    def _build_auto_ams_box_mapping(
        self,
        warn_on_empty_default: bool = False,
        loaded_slots: list[tuple[int, dict]] | None = None,
    ) -> list[dict]:
        """Build print mapping from currently loaded slots (no explicit dialog assignments)."""
        loaded = loaded_slots
        if loaded is None:
            loaded = self._select_loaded_slots_for_print(warn_on_empty_default=warn_on_empty_default)
        if not loaded:
            return []
        loaded_map = {gidx: s for gidx, s in loaded}
        max_idx = max(loaded_map.keys())
        # The printer interprets ams_box_mapping as an ordered list (entry N = TN).
        # Missing slots must be inserted as placeholders, otherwise everything shifts.
        # A placeholder must NOT reference a physically empty tray: the printer
        # rejects such an entry even for a tool the GCode never calls (printing
        # Filament 4 with the slot below it empty fails; all-full works). Point
        # gap placeholders at a definitely-loaded tray instead of the gap's own
        # (empty) index.
        fallback_gidx = max_idx  # highest loaded slot -> loaded + printable
        fallback_slot = loaded_map[fallback_gidx]
        fallback_ams = self._slot_to_print_ams_index(fallback_gidx)
        result = []
        for i in range(max_idx + 1):
            if i in loaded_map:
                s = loaded_map[i]
                result.append({
                    "paint_index": i,
                    "ams_index": self._slot_to_print_ams_index(i),
                    "paint_color": [255, 255, 255, 255],
                    "ams_color": self._slot_color_rgba(s),
                    "material_type": s.get("type", "PLA"),
                })
            else:
                result.append({
                    "paint_index": i,
                    "ams_index": fallback_ams,
                    "paint_color": [255, 255, 255, 255],
                    "ams_color": self._slot_color_rgba(fallback_slot),
                    "material_type": fallback_slot.get("type", "PLA"),
                })
        return result

    def _build_assigned_ams_box_mapping(self, assignments: list) -> tuple[list[dict], int, int]:
        """Build print mapping from UI filament assignments.

        Returns (mapping, unused_count, invalid_count).
        """
        slot_by_global_index = {
            int(s.get("global_index", i)): s
            for i, s in enumerate(self._ams_slots)
        }
        ams_box_mapping: list[dict] = []
        unused_count = 0
        invalid_count = 0

        for i, a in enumerate(assignments):
            try:
                if a.get("is_used") is False:
                    unused_count += 1
                    continue
                global_slot = int(a["slot_index"])
            except (ValueError, TypeError, KeyError):
                invalid_count += 1
                continue

            if global_slot < 0:
                unused_count += 1
                continue
            if not self._slot_usable_for_print(global_slot):
                invalid_count += 1
                continue

            slot = slot_by_global_index.get(global_slot, {})
            ams_box_mapping.append({
                # Preserve slicer paint indices (can be sparse when paint 0 is unused).
                "paint_index": a.get("paint_index", i),
                "ams_index": self._slot_to_print_ams_index(global_slot),
                "paint_color": a.get("paint_color", [255, 255, 255, 255]),
                "ams_color": self._slot_color_rgba(slot),
                "material_type": slot.get("type", a.get("material", "PLA")),
            })

        return ams_box_mapping, unused_count, invalid_count

    def _box_local_to_global(self, box_id: int, local_slot: int, boxes: list) -> int:
        """Convert (box_id, local slot) to global slot index for current topology."""
        if box_id == -1:
            return local_slot
        if self._filament_mode == "ace_direct":
            # Multi-ACE (Issue #95): each unit occupies its own block of 4.
            # Identical to the old `return local_slot` for a single unit (id 0).
            return box_id * 4 + local_slot
        return 3 + box_id * 4 + local_slot

    def _slot_activity_map(self, boxes: list, global_loaded: int = -1) -> dict:
        """Build {global_slot_index: loading|unloading} from feed_status data."""
        # Note: all boxes are considered — the old primary_ace_id filter (skip
        # every ACE box except the first in ace_direct mode) is gone since the
        # slot aggregation now handles multiple ACE units (Issue #95).
        activity: dict = {}
        for box in boxes:
            fs = box.get("feed_status") or {}
            current_status = int(fs.get("current_status", -1))
            local_slot = int(fs.get("slot_index", -1))
            feed_type = int(fs.get("type", -1))
            if current_status in (-1, 10, 11) or local_slot < 0:
                continue
            box_slots = box.get("slots") or []
            if local_slot >= len(box_slots) or (box_slots[local_slot] or {}).get("status") != 5:
                continue
            if feed_type == 1:
                act = "loading"
            elif feed_type == 2:
                act = "unloading"
            else:
                continue
            global_slot = self._box_local_to_global(int(box.get("id", -1)), local_slot, boxes)
            if feed_type == 1 and self._pending_load_slot >= 0 and global_slot != self._pending_load_slot:
                # Ignore transient firmware-reported loading slots that differ from the requested target.
                if global_loaded >= 0 and global_loaded != self._pending_load_slot:
                    activity[global_loaded] = "unloading"
                continue
            if feed_type == 1 and global_loaded >= 0 and global_slot != global_loaded:
                # During a slot swap the firmware reports the target slot immediately,
                # while the previously loaded slot is still being unloaded first.
                activity[global_loaded] = "unloading"
            activity[global_slot] = act
        return activity

    def _new_tip_form_events(self, boxes: list) -> list[tuple[int, int, int]]:
        """Return feed completion transitions once, not on every status poll."""
        events = []
        for box in boxes:
            box_id = int(box.get("id", -1))
            fs = box.get("feed_status")
            if not isinstance(fs, dict) or "current_status" not in fs:
                continue  # Sparse slot-only reports must not erase feed state.
            current = (int(fs["current_status"]), int(fs.get("slot_index", 0)))
            previous = self._last_feed_status.get(box_id)
            if int(fs.get("type", -1)) in (1, 2) and previous is not None and current[0] in (10, 11) and previous != current:
                events.append((box_id, current[1], current[0]))
            self._last_feed_status[box_id] = current
        return events

    def _on_multicolor_box(self, payload: dict):
        if payload.get("state") == "failed":
            req = getattr(self, "_last_ams_set_request", None)
            log.warning(
                f"multiColorBox setInfo rejected by printer: request={req}  raw_response={payload.get('data')}"
            )
            self._state["last_ams_set_error"] = True
            return
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            log.warning(f"multiColorBox/report: unexpected data shape: {data!r}")
            return
        boxes = data.get("multi_color_box") or []
        if not boxes:
            return
        self._state["last_ams_set_error"] = False
        self._head_tools_model = int(data.get("head_tools_model", self._head_tools_model))
        self._filament_mode = self._detect_filament_mode(boxes, self._head_tools_model)
        self._state["filament_mode"] = self._filament_mode

        global_slots, global_loaded = self._aggregate_slots(boxes, self._filament_mode)
        self._ams_loaded_slot = global_loaded
        self._update_ace_drying_state(data, boxes)
        for box in boxes:
            bid = int(box.get("id", -1))
            if 0 <= bid <= 3 and "auto_feed" in box:
                self._ace_auto_feed[bid] = int(box["auto_feed"])
        if self._pending_load_slot >= 0 and global_loaded == self._pending_load_slot:
          self._pending_load_slot = -1
        activity_map = self._slot_activity_map(boxes, global_loaded)
        for s in global_slots:
            s["activity"] = activity_map.get(s.get("global_index"), "")

        # Tip forming is edge-triggered. S1 Max keeps terminal feed_status=10
        # in every getInfo reply; treating that level as a new event resent
        # type=3 once/minute and interfered with the native preparation workflow.
        for box_id, slot_index, current_status in self._new_tip_form_events(boxes):
            def _tip_form(bi=box_id, si=slot_index, cs=current_status):
                import time; time.sleep(2)
                self.client.publish(
                    "multiColorBox", "feedFilament",
                    {"multi_color_box": [{"id": bi, "feed_status": {"slot_index": si, "type": 3}}]},
                    timeout=0
                )
                log.info(f"Tip forming (type=3) after status={cs} box={bi} slot={si}")
            threading.Thread(target=_tip_form, daemon=True).start()

        if global_slots:
            self._ams_slots = global_slots
            log.info(f"AMS slots received: {len(global_slots)}, loaded_slot={self._ams_loaded_slot}")
            self._push_status_update()

    def _update_ace_drying_state(self, data: dict, boxes: list):
        """Extract ACE drying state from multiColorBox report/getInfo payloads."""
        ace_ids = sorted({int(b.get("id", -1)) for b in boxes if int(b.get("id", -1)) >= 0})
        self._ace_box_ids = [i for i in ace_ids if 0 <= i <= 3]

        def _num_from(src: dict, keys: tuple[str, ...], default=None):
            for k in keys:
                v = src.get(k)
                if v is not None:
                    try:
                        return float(v)
                    except Exception:
                        return default
            return default

        def _humidity_from(src: dict, default=None):
            return _num_from(src, ("humidity", "current_humidity", "cur_humidity", "relative_humidity", "humidity_value"), default)

        def _current_temp_from(src: dict, default=None):
            return _num_from(src, ("current_temp", "cur_temp", "temperature", "temp", "drying_temp", "chamber_temp"), default)

        def _minutes_from(src: dict, key: str, default=0):
          raw = src.get(key, default)
          try:
            value = int(float(raw))
          except Exception:
            return int(default)
          # Some firmware payloads report dryer times in seconds while the UI uses minutes.
          if value > (24 * 60):
            return max(0, int(round(value / 60.0)))
          return max(0, value)

        per_unit: list[dict] = []
        for box in boxes:
            bid = int(box.get("id", -1))
            if bid < 0:
                continue

            bs = box.get("drying_status") or box.get("drying_settings")
            bs = bs if isinstance(bs, dict) else {}
            hu = _humidity_from(bs, _humidity_from(box))
            ct = _current_temp_from(bs, _current_temp_from(box))

            if bs or hu is not None or ct is not None:
                per_unit.append({
                    "id": bid,
                    "status": int(bs.get("status", 0)),
                    "target_temp": int(bs.get("target_temp", 0)),
                "duration": _minutes_from(bs, "duration", 0),
                "remain_time": _minutes_from(bs, "remain_time", 0),
                    "humidity": hu,
                    "current_temp": ct,
                })

        src = data.get("drying_status") or data.get("drying_settings")
        if not isinstance(src, dict):
            for box in boxes:
                if int(box.get("id", -1)) < 0:
                    continue
                cand = box.get("drying_status") or box.get("drying_settings")
                if isinstance(cand, dict):
                    src = cand
                    break

        if isinstance(src, dict):
          cur = self._state.get("ace_drying") or {}
          active = [u for u in per_unit if u.get("status", 0)]
          primary = active[0] if active else (per_unit[0] if per_unit else {})
          self._state["ace_drying"] = {
            "status": int(src.get("status", cur.get("status", 0))),
            "target_temp": int(src.get("target_temp", cur.get("target_temp", 0))),
            "duration": _minutes_from(src, "duration", cur.get("duration", 0)),
            "remain_time": _minutes_from(src, "remain_time", cur.get("remain_time", 0)),
            "humidity": _humidity_from(src, primary.get("humidity", cur.get("humidity"))),
            "current_temp": _current_temp_from(src, primary.get("current_temp", cur.get("current_temp"))),
            "units": per_unit,
          }
        elif per_unit:
            active = [u for u in per_unit if u.get("status", 0)]
            primary = active[0] if active else per_unit[0]
            self._state["ace_drying"] = {
                "status": int(primary.get("status", 0)),
                "target_temp": int(primary.get("target_temp", 0)),
                "duration": int(primary.get("duration", 0)),
                "remain_time": int(primary.get("remain_time", 0)),
                "humidity": primary.get("humidity"),
                "current_temp": primary.get("current_temp"),
                "units": per_unit,
            }

    def _on_light(self, payload: dict):
        d = payload.get("data") or {}
        self._state["light_on"]         = bool(d.get("status", 0))
        self._state["light_brightness"] = int(d.get("brightness", 80))
        self._push_status_update()

    # OrcaSlicer filament preset IDs (MoonrakerPrinterAgent.cpp mapping)
    # Default mapping per material type when the user has not set a slot
    # profile override. For the Kobra X we prefer Anycubic's own
    # filament IDs from the `@Anycubic Kobra X 0.4 nozzle` profiles - those
    # are printer-specific is_compatible and are picked up by OrcaSlicer directly
    # matched. Library fallbacks (OGF*) only for material types without
    # Kobra X-specific Anycubic profile - their @system profiles have
    # `compatible_printers: []` (= compatible with all printers).
    _TRAY_INFO_IDX = {
        # Anycubic-eigene Kobra-X-Profile
        "PLA":        "GFPLA",
        "PLA+":       "GFPLA+",
        "PLA SILK":   "GFPLA Silk",
        "PLA-SILK":   "GFPLA Silk",
        "PLASILK":    "GFPLA Silk",
        "SILK PLA":   "GFPLA Silk",
        "PLA MATTE":  "GFPLA",
        "PLA-MATTE":  "GFPLA",
        "PLA MARBLE": "GFPLA",
        "PLA WOOD":   "GFPLA",
        "PETG":       "GFPETG",
        "PETG+":      "GFPETG",
        "ABS":        "GFABS",
        "ASA":        "GFASA",
        "TPU":        "GFTPU 95A",
        "TPE":        "GFTPU 95A",
        "PVA":        "GFPVA",
        # Kein Anycubic-Kobra-X-Profil → Library-Fallback
        "PLA-CF":     "OGFL98",
        "PLA CF":     "OGFL98",
        "PETG-CF":    "OGFG98",
        "PETG CF":    "OGFG98",
        "PA":         "OGFN99",
        "PA-CF":      "OGFN98",
        "PA CF":      "OGFN98",
        "PC":         "OGFC99",
        "HIPS":       "OGFS98",
    }

    # Normalizes material type strings to the canonical key for _TRAY_INFO_IDX
    # and _default_filament_name. PLA variants without an exact match fall
    # back to their base family (PLA+ -> PLA+, PLA Matte -> PLA, etc.).
    @staticmethod
    def _normalize_material(mat: str) -> str:
        m = mat.upper().strip().replace("-", " ").replace("_", " ")
        # Bekannte Varianten normalisieren
        _ALIASES = {
            "PLAPLUS": "PLA+", "PLA PLUS": "PLA+",
            "SILK PLA": "PLA SILK", "PLASILK": "PLA SILK",
            "PLA MATTE": "PLA MATTE", "PLA MARBLE": "PLA MARBLE",
            "PLA WOOD": "PLA WOOD",
            "TPE": "TPU",
            "PETG PLUS": "PETG+",
            "PA6": "PA", "PA12": "PA", "PA66": "PA",
        }
        if m in _ALIASES:
            return _ALIASES[m]
        return m

    @staticmethod
    def _material_family(mat: str) -> str:
        """Reduce a material to its base polymer family.

        PLA / PLA+ / PLA SILK / PLA MATTE -> "PLA"; PETG / PETG+ -> "PETG"; etc.
        Used by the stale-profile guard: only a change of *family* (e.g. PETG ->
        PLA) invalidates a saved slot profile — a change within the family
        (PLA -> PLA SILK) must not discard an otherwise valid profile.
        """
        if not mat:
            return ""
        m = KobraXBridge._normalize_material(mat)
        # Longer prefixes first so "PETG" is not swallowed by "PET".
        for fam in ("PETG", "PLA", "ABS", "ASA", "TPU", "PVA", "HIPS", "PA", "PC", "PET"):
            if m.startswith(fam):
                return fam
        return m

    def _parse_combined_rfid_type(self, raw_type: str) -> tuple[str, str]:
        """Split a combined ACE-RFID "VENDOR TYPE SERIAL" string (e.g.
        "GEEETECH PLA Bas", written via third-party RFID tools) into
        (vendor, material_family).

        Anycubic's ACE RFID system concatenates vendor + material + a
        truncated serial/variant into one `type` string for custom tags -
        unlike a normal spool report where `type` is just "PLA"/"PETG"/etc.
        Returns ("", "") when the first token isn't a known vendor (from the
        merged system+user filament library), which leaves plain type
        strings like "PLA" completely unaffected (Issue #101).
        """
        tokens = raw_type.split()
        if len(tokens) < 2:
            return "", ""
        first = tokens[0].strip().lower()
        vendors = {p.get("vendor", "").lower(): p.get("vendor", "") for p in self._load_orca_filaments()}
        vendor = vendors.get(first)
        if not vendor:
            return "", ""
        family = self._material_family(" ".join(tokens[1:]))
        if not family:
            return "", ""
        return vendor, family

    def _match_profile_by_vendor_family(self, vendor: str, family: str) -> dict:
        """Find an imported/system filament profile by (vendor, material
        family) - used to auto-resolve a combined ACE-RFID type string to
        the user's already-imported OrcaSlicer profile (Issue #101), since
        the exact profile `name` never appears verbatim in the truncated
        RFID string."""
        matches = [
            p for p in self._load_orca_filaments()
            if p.get("vendor", "").lower() == vendor.lower()
            and self._material_family(p.get("type", "")) == family
        ]
        if not matches:
            return {}
        if len(matches) > 1:
            log.debug(
                f"_match_profile_by_vendor_family: {len(matches)} profiles match "
                f"vendor={vendor!r} family={family!r}, using first: {matches[0].get('name')}"
            )
        return matches[0]

    def _profile_material(self, profile: dict) -> str:
        """Material type (e.g. "PETG") of a saved slot profile, resolved by
        (vendor, name) from the Orca filament library. Returns "" when the
        profile is not in the library — we do NOT guess in that case."""
        name = (profile or {}).get("name", "")
        if not name:
            return ""
        vendor = profile.get("vendor", "")
        for p in self._load_orca_filaments():
            if p.get("vendor") == vendor and p.get("name") == name:
                return p.get("type", "") or ""
        return ""

    def _effective_slot_profile(self, global_idx: int, ams_material: str) -> dict:
        """Saved slot-profile override — but only while its material *family*
        still matches the material currently loaded in the AMS.

        Non-destructive suppression (Option A): when the family no longer matches
        (e.g. a PETG profile but PLA loaded) we return {} → the slot falls back to
        the generic default. The override stays in config.ini and reactivates as
        soon as the matching material is loaded again. When the profile's family
        is unknown we do NOT suppress (fail-safe)."""
        profile = self._filament_profiles.get(global_idx) or {}
        if not profile.get("name"):
            return {}
        prof_fam = self._material_family(self._profile_material(profile))
        ams_fam  = self._material_family(ams_material)
        if prof_fam and ams_fam and prof_fam != ams_fam:
            return {}
        return profile

    def _build_lane_data(self) -> dict:
      """Builds BBL AMS JSON for OrcaSlicer DevFilaSystemParser::ParseV1_0.

      POSITION-FAITHFUL: every physical slot keeps its position (tray id =
      slot position). Empty slots are reported as placeholder trays, NOT
      filtered out/compacted - otherwise colors shift to wrong positions
      (e.g. slot 1=yellow, 2=empty, 3=red -> red must not land on position 2).
      """
      slots = self._ams_slots
      total = len(slots)
      if total == 0:
        return {"ams": [], "ams_exist_bits": "0", "tray_exist_bits": "0"}

      ams_count = (total + 3) // 4
      ams_exist_bits = 0
      tray_exist_bits = 0
      ams_array = []

      for ams_id in range(ams_count):
        ams_exist_bits |= (1 << ams_id)
        tray_array = []
        max_slot = min(3, total - ams_id * 4 - 1)
        for slot_id in range(max_slot + 1):
          slot_index = ams_id * 4 + slot_id
          slot = slots[slot_index] if slot_index < total else {}
          occupied = slot.get("status") == 5

          if occupied:
            tray_exist_bits |= (1 << slot_index)
            color_raw = slot.get("color", [255, 255, 255])
            if isinstance(color_raw, list) and len(color_raw) >= 3:
              color_hex = "{:02X}{:02X}{:02X}FF".format(
                int(color_raw[0]), int(color_raw[1]), int(color_raw[2])
              )
            elif isinstance(color_raw, str) and len(color_raw) >= 6:
              color_hex = color_raw[:6].upper() + "FF"
            else:
              color_hex = "FFFFFFFF"
            material = self._normalize_material(slot.get("type", "PLA"))
            # User override from config.ini [filament_profiles].slot_N_id
            # takes precedence over the default mapping by material type.
            # The vendor is sent along (tray_sub_brands + filament_vendor),
            # so a patched OrcaSlicer can match by brand + type +
            # color (analogous to SnapmakerPrinterAgent).
            # Two-layer resolution for the filament hint sent to OrcaSlicer:
            #   1. User-Wahl (config.ini [filament_profiles]) — exakte Kontrolle
            #   2. Generic fallback (_TRAY_INFO_IDX) per material type - no
            #      vendor hint; OrcaSlicer then picks its own generic preset
            # Stale-profile guard: only apply the override while its material
            # family still matches the loaded filament (PETG profile + PLA
            # loaded -> dropped).
            user_profile = self._effective_slot_profile(slot_index, material)
            if not user_profile.get("name"):
                # Third layer: auto-resolve a combined ACE-RFID "VENDOR TYPE
                # SERIAL" string (e.g. "GEEETECH PLA Bas", from third-party
                # RFID tools) against the user's already-imported profile
                # library, instead of falling through to the neutral Generic
                # fallback (Issue #101). Not persisted to config.ini - this
                # re-derives on every _build_lane_data() call, so a
                # differently-tagged spool loaded later isn't stuck with a
                # stale match.
                vendor_guess, family_guess = self._parse_combined_rfid_type(slot.get("type", ""))
                if vendor_guess:
                    auto_profile = self._match_profile_by_vendor_family(vendor_guess, family_guess)
                    if auto_profile.get("name"):
                        user_profile = auto_profile
                        material = family_guess
            if user_profile.get("name"):
                vendor    = user_profile.get("vendor", "")
                fila_name = user_profile.get("name", "")
                tray_info_idx = user_profile.get("id") or self._TRAY_INFO_IDX.get(material, "OGFL99")
            else:
                # Default: Library-Generic-Profil (siehe _default_filament_name) —
                # is compatible with all printers and guaranteed to be visible.
                # The user deliberately picks a concrete brand per slot if they
                # want one; the default stays neutral.
                fila_name = self._default_filament_name(material)
                vendor    = "Generic" if fila_name.startswith("Generic ") else ""
                tray_info_idx = self._lookup_filament_id(vendor, fila_name) or self._TRAY_INFO_IDX.get(material, "OGFL99")
            tray_array.append({
              "id": str(slot_id),
              "tag_uid": "0000000000000000",
              "tray_info_idx": tray_info_idx,
              "tray_type": material,
              "tray_color": color_hex,
              "tray_sub_brands": vendor,
              # OrcaSlicer-Empfangs-Patch PR #13719 erwartet `name` +
              # `vendor_name` pro Lane (Stufen-Matching: Vendor+Name → Name →
              # filament_id_by_type). We send both spellings so that
              # older patch variants + future upstream PRs are both
              # covered.
              "name":         fila_name,
              "vendor_name":  vendor,
              # Aliases for older patch variants (variant 2,
              # MoonrakerPrinterAgent.cpp): filament_id direkt (exakt),
              # otherwise resolve the preset name via find_preset().
              "filament_id":     tray_info_idx,
              "filament_vendor": vendor,
              "filament_name":   fila_name,
              "preset":          fila_name,
            })
          else:
            tray_array.append({
              "id": str(slot_id),
              "tag_uid": "0000000000000000",
              "tray_info_idx": "",
              "tray_type": "",
              "tray_color": "00000000",
              "tray_slot_placeholder": "1",
            })

        ams_array.append({"id": str(ams_id), "info": "0002", "tray": tray_array})

      return {
        "ams": ams_array,
        "ams_exist_bits": format(ams_exist_bits, "X"),
        "tray_exist_bits": format(tray_exist_bits, "X"),
      }

    @staticmethod
    def _layer_height_from_filename(fname: str) -> float:
        """OrcaSlicer-Default-Filename-Pattern: `<plate>_<material>_<layer>_<dur>.gcode`
        z.B. `adapter_e27_plate(01)_PLA_0.2_41m1s.gcode` → 0.2.

        Fallback when the GCode header was not parsed (e.g. file started directly
        on the slicer, or uploaded before v0.9.18). Returns 0.0 when the
        pattern does not match."""
        import re
        if not fname:
            return 0.0
        m = re.search(r"_(0\.\d+)_(\d+[hms])", fname)
        if not m:
            return 0.0
        try:
            return float(m.group(1))
        except Exception:
            return 0.0

    def _estimate_current_z(self) -> float:
        """Estimates the current Z height from curr_layer + layer heights.

        The printer provides no real Z position via MQTT, but Obico
        (moonraker-obico/printer.py:267) reads currentZ from `gcode_position[2]`.
        We back-compute it with the layer_height from the GCode header:
          z = first_layer_height + (curr_layer - 1) * layer_height

        Values are set in the upload path and only reset on print cancel/end
        (slot/color changes do not affect them). If the values are
        missing (e.g. because the print was started directly on the slicer
        without an upload through the bridge), they are reloaded once from
        the GCode store. Returns 0.0 when nothing is known - Obico then shows
        keinen Z-Wert."""
        s = self._state
        layer_h = float(s.get("layer_height") or 0.0)
        first_h = float(s.get("first_layer_height") or 0.0)
        fname = s.get("filename", "")
        if not layer_h and fname:
            try:
                gf = self._store.get_file_by_name(fname)
                if gf:
                    layer_h = float(gf.get("layer_height") or 0.0)
                    first_h = float(gf.get("first_layer_height") or layer_h)
            except Exception:
                pass
        if not layer_h and fname:
            # Last fallback: the OrcaSlicer default filename contains the layer height
            layer_h = self._layer_height_from_filename(fname)
            if layer_h and not first_h:
                first_h = layer_h
        if layer_h:
            # cache in state so not every build queries the store again
            s["layer_height"] = layer_h
            s["first_layer_height"] = first_h
        if not layer_h:
            return 0.0
        curr = int(s.get("curr_layer") or 0)
        if curr <= 0:
            return 0.0
        # Layer 1 = first_layer_height, Layer 2 = first + layer_h, …
        return round(first_h + max(0, curr - 1) * layer_h, 3)

    # -------------------------------------------------------------------------
    # WebSocket push
    # -------------------------------------------------------------------------

    # Static objects that never change at runtime. They are delivered once
    # via objects.query/subscribe, but NOT included in every
    # notify_status_update - otherwise Mobileraker's
    # ConfigFile.parse (expensive + strict) runs on every status tick and the app
    # hangs/crashes on refresh (Issue #48).
    _STATIC_STATUS_OBJECTS = ("configfile", "webhooks", "heaters", "history")

    def _push_status_update(self):
        if not self.ws_clients:
            return
        objs = self._build_printer_objects()
        live = {k: v for k, v in objs.items() if k not in self._STATIC_STATUS_OBJECTS}
        msg = {
            "jsonrpc": "2.0",
            "method":  "notify_status_update",
            "params": [live, time.time()],
        }
        text = json.dumps(msg)
        dead = set()
        for ws in self.ws_clients:
            try:
                asyncio.run_coroutine_threadsafe(ws.send_str(text), ws._loop)
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead

    def _build_mmu_object(self) -> dict:
      # POSITIONSTREU: ein Gate je physischem Slot, in Reihenfolge. Leere Slots
      # get gate_status=0 (instead of being omitted) - otherwise the
      # Farben in OrcaSlicer auf falsche Gates (Slot 1=gelb, 2=leer, 3=rot →
      # red must not land on gate 1). gate_status 0=empty, 1=available.
      slots = sorted(
        ((int(s.get("global_index", i)), s) for i, s in enumerate(self._ams_slots)),
        key=lambda item: item[0],
      )
      if not slots:
        return {}

      _TEMP = {"PLA": 210, "PETG": 230, "ABS": 240, "ASA": 250,
           "TPU": 220, "PA": 260, "PC": 270, "HIPS": 220}
      num_gates = len(slots)
      gate_status, gate_material, gate_color, gate_temperature, gate_color_rgb = [], [], [], [], []
      gate_filament_name = []
      gate_spool_id = []
      for _global_index, slot in slots:
        occupied = slot.get("status") == 5
        gate_status.append(1 if occupied else 0)
        material = self._normalize_material(slot.get("type") or "PLA") if occupied else ""
        gate_material.append(material)
        c = slot.get("color", [0, 0, 0]) if occupied else [0, 0, 0]
        # Happy Hare expects gate_color as RRGGBB WITHOUT '#' (Klipper limitation).
        # Leerer Gate: leerer String + RGB [0,0,0].
        gate_color.append("{:02X}{:02X}{:02X}".format(*c[:3]) if occupied else "")
        gate_color_rgb.append([round(c[0]/255, 3), round(c[1]/255, 3), round(c[2]/255, 3)] if occupied else [0.0, 0.0, 0.0])
        gate_temperature.append(_TEMP.get(material, 210) if occupied else 0)
        # gate_filament_name from user override or material default for the
        # HH-Pfad in OrcaSlicer (fetch_hh_filament_info). Wenn Orca den
        # HH path (MMU detection), PR #13719 evaluates this field as a
        # preset name -> 'Anycubic PLA' matches the printer-specific
        # preset; an empty string previously led to Generic PLA.
        if occupied:
          # Stale-profile guard (see _effective_slot_profile): only apply the
          # override while its material family still matches the loaded filament.
          user_profile = self._effective_slot_profile(_global_index, material)
          fila_name = user_profile.get("name") or self._default_filament_name(material)
          gate_filament_name.append(fila_name)
        else:
          gate_filament_name.append("")
        # Spoolman spool ID per gate from the (printer-specific) slot map so
        # Happy Hare/OrcaSlicer can show the bound spool (-1 = none).
        gate_spool_id.append(self._spoolman_slot_spools.get(_global_index, -1) if occupied else -1)

      loaded_index_map = {global_index: idx for idx, (global_index, _) in enumerate(slots)}
      active_gate = loaded_index_map.get(int(self._ams_loaded_slot), -1)
      return {
        "num_gates":          num_gates,
        "enabled":            True,
        "gate_status":        gate_status,
        "gate_material":      gate_material,
        "gate_color":         gate_color,
        "gate_temperature":   gate_temperature,
        "gate_color_rgb":     gate_color_rgb,
        "gate_filament_name": gate_filament_name,
        "gate_spool_id":      gate_spool_id,
        "ttg_map":            list(range(num_gates)),
        "tool":               active_gate,
        "gate":               active_gate,
      }

    def _default_filament_name(self, material: str) -> str:
      """Default name for `gate_filament_name`/`name` in lane_data when no
      user override is set. Deliberate design decision: **always
      Generic <type>** as the default - the library profile is `compatible_printers:[]`
      (= compatible with every printer) and therefore guaranteed to be visible.

      OrcaSlicer then matches the neutral generic preset and the user
      can set a concrete brand per slot if they want to."""
      if not material:
        return ""
      mat = self._normalize_material(material)
      profs = self._load_orca_filaments()
      # Varianten-Mapping: Drucker meldet z.B. "PLA SILK", OrcaSlicer speichert
      # all variants under type=PLA with the variant name in the name field.
      _VARIANT_NAME = {
          "PLA SILK":   "Generic PLA Silk",
          "PLA MATTE":  "Generic PLA Matte",
          "PLA+":       "Generic PLA",
          "PLA-CF":     "Generic PLA-CF",
          "PETG-CF":    "Generic PETG-CF",
      }
      if mat in _VARIANT_NAME:
          target = _VARIANT_NAME[mat]
          for p in profs:
              if p.get("vendor") == "Generic" and p.get("name") == target:
                  return p["name"]
      def _match_type(p: dict) -> bool:
        pt = (p.get("type") or "").upper()
        return pt == mat or pt.startswith(mat + "-") or pt.startswith(mat + " ")
      # Library-Generic-Profil (immer is_visible+is_compatible)
      for p in profs:
        if p.get("vendor") == "Generic" and p.get("name", "").startswith("Generic ") and _match_type(p):
          return p.get("name", "")
      # If the library generic for this exotic material type is missing,
      # we return nothing - OrcaSlicer falls back to filament_id_by_type.
      return ""

    def _build_printer_objects(self) -> dict:
        s = self._state
        return {
            "extruder": {
                "temperature": s["nozzle_temp"],
                "target":      s["nozzle_target"],
                "power":       0.0,
            },
            "heater_bed": {
                "temperature": s["bed_temp"],
                "target":      s["bed_target"],
                "power":       0.0,
            },
            "print_stats": {
                "state":          s["print_state"],
                "filename":       s["filename"],
                "print_duration": s["print_duration"],
                "total_duration": s["print_duration"],
                "remain_time":    s["remain_time"],
                "info": {
                    "current_layer": s["curr_layer"],
                    "total_layer":   s["total_layers"],
                },
            },
            "display_status": {
                "progress": s["progress"],
                "message":  "",
            },
            "virtual_sdcard": {
                "progress":  s["progress"],
                "is_active": s["print_state"] == "printing",
                "file_path": s["filename"],
                # file_position approximiert: fraction × est_total_size.
                # The printer does not provide an exact value; Obico only uses it for display.
                "file_position": int(s["progress"] * 1_000_000) if s["progress"] else 0,
            },
            "toolhead": {
                "position":         [0, 0, 0, 0],
                "homed_axes":       "xyz",
                "print_time":       s["print_duration"],
                "estimated_print_time": s["print_duration"],
            },
            "mmu": self._build_mmu_object(),
            # -- Moonraker compatibility for moonraker-obico --
            "heaters": {
                "available_heaters": ["extruder", "heater_bed"],
                "available_sensors": [],
                "available_monitors": [],
            },
            "webhooks": {
                "state":         "ready",
                "state_message": "Printer is ready",
            },
            # speed_factor: 1=silent(0.5) / 2=standard(1.0) / 3=high(1.3) / 4=ultra(1.5)
            # Estimate the current Z height for Obico from curr_layer + layer heights
            # (the printer provides no real Z position via MQTT). gcode_position[2]
            # is the value moonraker-obico reads as currentZ in printer.py.
            "gcode_move": {
                "speed_factor":   {1: 0.5, 2: 1.0, 3: 1.3, 4: 1.5}.get(int(s.get("print_speed_mode") or 2), 1.0),
                "extrude_factor": 1.0,
                "speed":          0,
                "gcode_position": [0, 0, self._estimate_current_z(), 0],
                "absolute_coordinates": True,
                "absolute_extrude":     True,
                "homing_origin":  [0, 0, 0, 0],
                "position":       [0, 0, self._estimate_current_z(), 0],
            },
            # motion_report: Mobileraker reads the live velocity here
            # (live_velocity). The Kobra X MQTT provides NO real mm/s, only
            # a print_speed_mode (1-4). live_velocity therefore stays 0 - but the
            # object must exist, otherwise Mobileraker displays nothing
            # (motion_report used to be null). live_position mirrors the
            # estimated Z height (like gcode_move).
            "motion_report": {
                "live_position":          [0, 0, self._estimate_current_z(), 0],
                "live_velocity":          0.0,
                "live_extruder_velocity": 0.0,
            },
            "fan": {
                "speed": (int(s.get("fan_speed") or 0)) / 100.0,
                "rpm":   None,
            },
            # history (object): Obico subscribes to it as an object; the actual
            # /server/history/list endpoint delivers the real list separately.
            "history": {
                "job_totals": {
                    "total_jobs":  0,
                    "total_time":  0,
                    "total_print_time": 0,
                    "total_filament_used": 0.0,
                    "longest_job": 0,
                    "longest_print": 0,
                },
                "current_job": None,
            },
            # Pseudo Klipper macros for moonraker-obico:
            # - _OBICO_LAYER_CHANGE reports the current layer number. Obico uses this
            #   for "first layer scan" triggers and layer-aligned time-lapse frames.
            #   We feed this from the MQTT stream (s["curr_layer"]).
            # - TIMELAPSE_TAKE_FRAME signals that the current pause comes from the
            #   time-lapse (otherwise Obico would interpret the pause as a user
            #   pause). We set is_paused=False because our pauses are
            #   never time-lapse pauses.
            "gcode_macro _OBICO_LAYER_CHANGE": {
                "current_layer":         int(s.get("curr_layer") or 0),
                "first_layer_scanning":  False,
                "first_layer_scan_enabled": False,
            },
            "gcode_macro TIMELAPSE_TAKE_FRAME": {
                "is_paused": False,
            },
            # configfile stub - Mobileraker and other clients crash without
            # this object (Missing field: configFile). Values from the
            # decrypted avata_main.conf (ACCFG1.0 - Kobra X firmware).
            # Mobileraker (Issue #48) parses BOTH branches config + settings via
            # denselben ConfigFile.parse → ConfigExtruder.fromJson; ein leeres
            # config:{} crashed the non-nullable Dart parser. Therefore
            # config identisch zu settings gespiegelt.
            "configfile": self._klipper_configfile_stub(),
        }

    def _klipper_configfile_stub(self) -> dict:
        """Minimal Klipper configfile stub for Mobileraker/OctoApp (Issue #48).

        Mobileraker parses BOTH branches `config` and `settings` through the same
        ConfigFile.parse → ConfigExtruder.fromJson. Ein leeres `config: {}`
        crashed the non-nullable Dart parser, therefore `config` is
        mirrored identically to `settings`. Values from the decrypted
        avata_main.conf (ACCFG1.0 — Kobra X Firmware).
        """
        settings = {
            "printer": {
                "kinematics":              "cartesian",
                "max_velocity":            450,
                "max_accel":               10000,
                "max_z_velocity":          12,
                "max_z_accel":             100,
                "square_corner_velocity":  20.0,
            },
            "extruder": {
                "nozzle_diameter":    float(getattr(self._args, "nozzle_diameter", 0.4) or 0.4),
                "filament_diameter":  1.75,
                "sensor_type":        "ATC Semitec 104GT-2",
                "min_temp":           0,
                "max_temp":           320,
                "min_extrude_temp":   10,
                # Mobileraker ConfigExtruder erwartet diese Felder non-nullable
                # (max_extrude_only_distance, max_power) or present as a key
                # (max_extrude_only_velocity/accel may be null). Missing =
                # Crash in ConfigExtruder.fromJson (Issue #48).
                "max_extrude_only_distance": 100.0,
                "max_power":                 1.0,
                "max_extrude_only_velocity": None,
                "max_extrude_only_accel":    None,
            },
            "heater_bed": {
                # Mobileraker ConfigHeaterBed: heater_pin, sensor_type, control
                # are non-nullable. Values are placeholders (the bridge does not know
                # the real pins - Anycubic firmware, no Klipper printer.cfg).
                "heater_pin":  "PA0",
                "sensor_type": "ATC Semitec 104GT-2",
                "control":     "pid",
                "min_temp":    0,
                "max_temp":    120,
            },
            # Fill stepper_* with non-nullable required fields (step_pin, dir_pin,
            # rotation_distance), otherwise ConfigStepper.fromJson crashes.
            "stepper_x": {"step_pin": "PA1", "dir_pin": "PA2", "rotation_distance": 40,
                          "position_min": -18.5, "position_max": 280},
            "stepper_y": {"step_pin": "PA3", "dir_pin": "PA4", "rotation_distance": 40,
                          "position_min": -6.5,  "position_max": 272.5},
            "stepper_z": {"step_pin": "PA5", "dir_pin": "PA6", "rotation_distance": 8,
                          "position_min": -4,    "position_max": 262},
            "virtual_sdcard": {"path": "/data/gcodes"},
            "pause_resume":   {},
            "display_status": {},
        }
        # config + settings must contain the same fields - Mobileraker
        # parses both. deepcopy so no client is affected by a shared reference
        # versehentlich beide Zweige mutiert.
        return {
            "config":   copy.deepcopy(settings),
            "settings": settings,
            "warnings": [],
            "save_config_pending": False,
            "save_config_pending_items": {},
        }

    # -------------------------------------------------------------------------
    # /kx/ API handlers (GCode Store, History, Filament)
    # -------------------------------------------------------------------------

    _CORS = {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }

    def _json_cors(self, data, status=200):
        resp = web.json_response(data, status=status, headers=self._CORS)
        # Compress the /kx/* JSON. These payloads are highly repetitive
        # (base64 thumbnails, repeated key names), so gzip is a large win on a
        # phone over wifi and costs little CPU on already-serialised bytes.
        # ponytail: per-response instead of middleware, because the streaming
        # endpoints (MJPEG, SSE, file downloads) must NOT be wrapped.
        resp.enable_compression()
        return resp

    async def handle_kx_options(self, request):
        return web.Response(status=204, headers=self._CORS)

    async def handle_kx_files(self, request):
        # Everything below is SQLite + optional G-code file reads. On the event
        # loop (shared by all six printer ports) one call stalled every other
        # request 200-2300 ms under NAS I/O pressure. One executor hop, same
        # rule as handle_file_upload.
        return self._json_cors({"result": await asyncio.get_event_loop().run_in_executor(
            None, self._kx_files_payload)})

    def _kx_files_payload(self) -> list:
        # svg_image / thumbnail_b64 are never read from this list (the browser
        # lazy-loads /kx/files/{id}/thumbnail), so do not pull ~2.3 MB of blobs
        # out of SQLite just to drop them; has_thumbnail is computed in SQL.
        files = self._store.list_files(with_blobs=False)
        for f in files:
            f["has_thumbnail"] = bool(f.get("has_thumbnail"))
        # Backfill legacy entries without stored filament metadata
        # so the dialog's left side shows GCode colors instead of AMS slots.
        for f in files:
            needs_refresh = not f.get("gcode_filaments")
            if not needs_refresh:
                try:
                    cached = f.get("gcode_filaments")
                    parsed_cached = cached if isinstance(cached, list) else json.loads(cached)
                    needs_refresh = any("is_used" not in item for item in (parsed_cached or []))
                except Exception:
                    needs_refresh = True
            if not needs_refresh:
                continue
            path = f.get("path") or ""
            if not path or not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as fh:
                    parsed_filaments = _extract_filament_info(fh.read())
                if parsed_filaments:
                    f["gcode_filaments"] = json.dumps(parsed_filaments)
                    self._store.update_file_filaments(f["id"], parsed_filaments)
            except Exception as e:
                log.debug(f"Filament metadata backfill failed for {f.get('filename')}: {e}")
        # Add last job status + duration per file
        jobs = self._store.list_jobs(limit=500)
        last_job: dict = {}
        for j in reversed(jobs):
            last_job[j["gcode_file_id"]] = j
        for f in files:
            f["web_unverified"] = bool(f.get("web_unverified"))
            lj = last_job.get(f["id"])
            f["last_print_status"]   = lj["status"]       if lj else None
            f["last_print_duration"] = lj["duration_sec"] if lj else None
            f["last_print_at"]       = lj["started_at"]   if lj else None
        return files

    async def handle_kx_file_delete(self, request):
        file_id = request.match_info["file_id"]
        if self._store.delete_file(file_id):
            return self._json_cors({"result": "ok"})
        return self._json_cors({"error": "not found"}, status=404)

    async def handle_kx_printer_files(self, request):
        """GET /kx/printer-files - lists files on the printer's OWN internal
        storage (file/listLocal MQTT action), as opposed to /kx/files which
        lists what the bridge itself has stored. Needed because prints
        started directly from Anycubic Slicer Next (bypassing the bridge)
        leave files on the printer that were previously only visible/
        deletable from the printer's own display (Issue #102 context)."""
        loop = asyncio.get_event_loop()
        def _fetch():
            return self._wait_for_file_action(
                "listLocal",
                lambda: self.client.publish(
                    "file", "listLocal",
                    {"page_num": 1, "page_size": 200, "path": "/"},
                    timeout=0,
                ),
                timeout=8.0,
            )
        result = await loop.run_in_executor(None, _fetch)
        if not result or result.get("code") != 200:
            return self._json_cors({"error": "printer unreachable or query failed"}, status=502)
        records = (result.get("data") or {}).get("records") or []
        files = [r for r in records if not r.get("is_dir")]
        return self._json_cors({"result": files})

    async def handle_kx_printer_file_start(self, request):
        """Start an existing root-level printer file without uploading it again."""
        try:
            body = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid json"}, status=400)
        filename = str(body.get("filename") or "").strip()
        if (not filename or filename != os.path.basename(filename)
                or "/" in filename or "\\" in filename
                or not filename.lower().endswith((".gcode", ".bgcode"))):
            return self._json_cors({"error": "invalid printer filename"}, status=400)
        if self._state.get("print_state") in (
                "printing", "paused", "preheating", "auto_leveling", "checking", "init"):
            return self._json_cors({"error": "printer is already busy"}, status=409)

        pending_token = self._set_print_pending(filename)
        if not pending_token:
            return self._json_cors({"error": "another print is already starting"}, status=409)
        loop = asyncio.get_event_loop()
        try:
            listing = await loop.run_in_executor(None, lambda: self._wait_for_file_action(
                "listLocal",
                lambda: self.client.publish(
                    "file", "listLocal",
                    {"page_num": 1, "page_size": 200, "path": "/"},
                    timeout=0,
                ),
                timeout=8.0,
            ))
            records = (listing.get("data") or {}).get("records") if listing else None
            if not isinstance(records, list):
                raise RuntimeError("printer file list timed out; retry")
            if not any(r.get("filename") == filename and not r.get("is_dir") for r in records):
                self._clear_print_pending(pending_token)
                return self._json_cors({"error": "file not found on printer"}, status=404)

            # The printer already owns the matching .acm sidecar. Omitting
            # ams_settings preserves that mapping instead of guessing from every
            # currently loaded slot (which selected the wrong material on S1 Max).
            payload = {
                "filename": filename,
                "filepath": "/",
                "taskid": str(uuid.uuid4().int % 1000000),
                "task_mode": 1,
                "filetype": 1,
                "task_settings": {
                    "auto_leveling": 1 if body.get("auto_leveling", getattr(self._args, "auto_leveling", 1)) in (1, True) else 0,
                    "vibration_compensation": 1 if body.get("vibration_compensation") in (1, True) else 0,
                    "flow_calibration": 1 if body.get("flow_calibration") in (1, True) else 0,
                },
            }
            result = await loop.run_in_executor(
                None, lambda: self.client.publish("print", "start", payload, timeout=15.0))
        except Exception as e:
            self._clear_print_pending(pending_token)
            log.error(f"Printer-local start failed for {filename}: {e}")
            return self._json_cors({"error": str(e)}, status=502)
        if result is None:
            self._clear_print_pending(pending_token)
            return self._json_cors({"error": "no response from printer"}, status=504)
        try:
            bad_code = result.get("code") is not None and int(result.get("code")) != 200
        except (TypeError, ValueError):
            bad_code = True
        if result.get("state") == "failed" or bad_code:
            self._clear_print_pending(pending_token)
            return self._json_cors({"error": result.get("msg") or result.get("message") or "printer rejected print start"}, status=502)
        log.info(f"Printer-local print start: {filename} auto_leveling={payload['task_settings']['auto_leveling']}")
        return self._json_cors({"result": "ok", "filename": filename})

    async def handle_kx_printer_file_delete(self, request):
        """POST /kx/printer-files/delete - body: {"filenames": ["a.gcode", ...]}.
        Single endpoint for both single and multi-select delete - the
        printer's file/deleteBatch MQTT action natively accepts a list."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        filenames = body.get("filenames") or []
        # A bare string would otherwise iterate character-by-character and send
        # one bogus delete entry per letter.
        if not isinstance(filenames, list):
            return self._json_cors({"error": "filenames must be a list"}, status=400)
        filenames = [fn for fn in filenames if isinstance(fn, str) and fn.strip()]
        if not filenames:
            return self._json_cors({"error": "no filenames given"}, status=400)
        files = [{"path": "/", "filename": fn} for fn in filenames]
        loop = asyncio.get_event_loop()
        def _delete():
            return self._wait_for_file_action(
                "deleteBatch",
                lambda: self.client.publish(
                    "file", "deleteBatch",
                    {"root": "local", "files": files},
                    timeout=0,
                ),
                timeout=8.0,
            )
        result = await loop.run_in_executor(None, _delete)
        if not result or result.get("state") != "success":
            return self._json_cors({"error": "delete failed", "detail": result}, status=502)
        # Evict the per-filename thumbnail cache, or a different file later
        # uploaded under the same name keeps serving the deleted file's preview
        # (the cache has no eviction and lives for the process lifetime).
        for fn in filenames:
            self._printer_thumbnail_cache.pop(fn, None)
        return self._json_cors({"result": "ok"})

    async def handle_kx_printer_file_thumbnail(self, request):
        """GET /kx/printer-files/{filename}/thumbnail - fetches the embedded
        GCode thumbnail for a file on the printer's own storage, via
        file/fileDetails. The printer extracts and base64-encodes the
        "; thumbnail begin"-block from the GCode header on demand and
        returns it inline in data.file_details.thumbnail - no separate
        download/presigned-URL step needed (verified live against a real
        Kobra X). Cached in-memory per filename since a file's thumbnail
        never changes while it exists on the printer, and re-querying on
        every render/scroll would mean one MQTT roundtrip per visible card."""
        filename = request.match_info.get("filename", "")
        if not filename:
            return self._json_cors({"error": "no filename given"}, status=400)
        cached = self._printer_thumbnail_cache.get(filename)
        if cached is not None:
            return self._json_cors({"result": {"thumbnail": cached}})
        # Extracting one thumbnail means an MQTT fileDetails roundtrip and
        # printer-side G-code parsing/base64 work. Never fan that out across a
        # file grid while the weak single-core host is feeding an active print.
        if self._state.get("print_state") in ("printing", "paused", "preheating", "auto_leveling", "checking", "init"):
            return self._json_cors({"error": "thumbnail disabled while printer is busy"}, status=409)
        loop = asyncio.get_event_loop()
        def _fetch():
            return self._wait_for_file_action(
                "fileDetails",
                lambda: self.client.publish(
                    "file", "fileDetails",
                    {"root": "local", "filename": filename},
                    timeout=0,
                ),
                timeout=8.0,
            )
        result = await loop.run_in_executor(None, _fetch)
        if not result or result.get("code") != 200:
            return self._json_cors({"error": "printer unreachable or query failed"}, status=502)
        thumb = ((result.get("data") or {}).get("file_details") or {}).get("thumbnail") or ""
        self._printer_thumbnail_cache[filename] = thumb
        return self._json_cors({"result": {"thumbnail": thumb}})

    async def handle_kx_file_thumbnail(self, request):
        """GET /kx/files/{file_id}/thumbnail - one stored thumbnail as a real PNG.

        The thumbnails used to ride along inside /kx/files: 39 files meant 308KB
        of base64 in a single JSON blob, re-fetched on every refresh, before a
        single card could render. Served individually the browser fetches only
        what is on screen and can cache each one, because a given file_id's
        thumbnail never changes (file_id is the content hash).
        """
        f = self._store.get_file(request.match_info["file_id"])
        b64 = (f or {}).get("thumbnail_b64") or ""
        if not b64:
            return web.Response(status=404, text="no thumbnail")
        try:
            raw = _base64.b64decode(b64)
        except Exception:
            return web.Response(status=404, text="bad thumbnail")
        return web.Response(body=raw, content_type="image/png", headers={
            # Immutable: keyed by content hash, so a changed file is a new id.
            "Cache-Control": "public, max-age=31536000, immutable",
            **self._CORS,
        })

    async def handle_kx_file_download(self, request):
        file_id = request.match_info["file_id"]
        f = self._store.get_file(file_id)
        if not f:
            return self._json_cors({"error": "not found"}, status=404)
        path = f.get("path") or ""
        if not path or not os.path.isfile(path):
            return self._json_cors({"error": "not found"}, status=404)
        filename = os.path.basename(f.get("filename") or path)
        # RFC 5987: filename* with URL encoding for special chars/UTF-8,
        # plus ASCII fallback (strip all " and \ from filename for the
        # quoted-string-Part).
        ascii_fallback = filename.encode("ascii", "replace").decode("ascii").replace('"', "").replace("\\", "")
        encoded = quote(filename, safe="")
        disposition = f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded}'
        return web.FileResponse(path, headers={"Content-Disposition": disposition})

    async def handle_kx_file_verify(self, request):
        file_id = request.match_info["file_id"]
        if self._store.clear_web_unverified(file_id):
            return self._json_cors({"result": "ok"})
        return self._json_cors({"error": "not found"}, status=404)

    async def handle_kx_filament_slots(self, request):
        slots = []
        for i, s in enumerate(self._ams_slots):
            gidx = int(s.get("global_index", i))
            # Stale-profile guard: only show the override while its material
            # family matches the loaded AMS material (else slot has no brand).
            profile = self._effective_slot_profile(gidx, s.get("type", ""))
            slots.append({
                "slot_index":  gidx,
                "material":    s.get("type", ""),
                "color_hex":   "#{:02X}{:02X}{:02X}".format(*s.get("color", [0,0,0])[:3]),
                "status":      "loaded" if s.get("status") == 5 and str(s.get("type") or "").strip() else "empty",
                "nozzle_temp": 0,
                # Current user override from config.ini [filament_profiles]
                # - (vendor,name) is unique, id is only a hint.
                "filament_id":     profile.get("id", ""),
                "filament_vendor": profile.get("vendor", ""),
                "filament_name":   profile.get("name", ""),
            })
        return self._json_cors({"result": slots})

    async def handle_kx_filament_profiles(self, request):
        """Returns the static list of OrcaSlicer filament profiles
        (from bridge/data/orca_filaments.json - produced by the generator script
        tools/gen_orca_filament_list.py erzeugt).

        Optional Filter via ?type=PLA / ?vendor=Polymaker.
        The frontend uses this for the slot profile dropdown.
        """
        type_filter = request.rel_url.query.get("type", "").upper().strip()
        vendor_filter = request.rel_url.query.get("vendor", "").strip()
        profiles = self._load_orca_filaments()
        if type_filter:
            profiles = [p for p in profiles if p.get("type", "").upper() == type_filter]
        if vendor_filter:
            profiles = [p for p in profiles if p.get("vendor", "") == vendor_filter]
        return self._json_cors({"result": profiles})

    async def handle_kx_filament_profiles_user_list(self, request):
        """GET /kx/filament/profiles/user - only the user-imported profiles,
        for the settings tab (management with delete buttons)."""
        path = self._orca_filaments_user_path()
        if not os.path.isfile(path):
            return self._json_cors({"result": []})
        try:
            with open(path, encoding="utf-8") as f:
                user_profiles = json.load(f) or []
        except Exception:
            user_profiles = []
        return self._json_cors({"result": user_profiles})

    async def handle_kx_filament_profiles_import(self, request):
        """POST /kx/filament/profiles/user - multipart upload with one
        ZIP file or multiple `.json` files from
        ~/.config/OrcaSlicer/user/<id>/filament/.

        Existing user profiles with the same (vendor, name) key are
        overwritten. Parsed profiles use the same schema as
        orca_filaments.json (id, name, vendor, type, color)."""
        import io, zipfile
        from orca_filaments import parse_profile_bytes
        added: list[dict] = []
        skipped: int = 0
        # System index for inherits resolution: user profiles reference
        # System-Parents via "inherits" (z.B. "Generic PLA @System"). Damit
        # we can pull filament_id/vendor/type/color from the system parent
        # when the user profile does not set them itself.
        sys_idx = [p for p in self._load_orca_filaments() if not p.get("is_user")]
        try:
            reader = await request.multipart()
        except Exception:
            return self._json_cors({"error": "expected multipart"}, status=400)
        async for part in reader:
            if part.name not in ("file", "files", "upload"):
                continue
            blob = await part.read()
            fn   = (part.filename or "").lower()
            if fn.endswith(".zip"):
                try:
                    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                        for inner in zf.namelist():
                            if not inner.lower().endswith(".json"):
                                continue
                            try:
                                with zf.open(inner) as zf_in:
                                    p = parse_profile_bytes(zf_in.read(), source_name=inner, system_index=sys_idx)
                            except Exception:
                                skipped += 1
                                continue
                            if p:
                                added.append(p)
                            else:
                                skipped += 1
                except zipfile.BadZipFile:
                    return self._json_cors({"error": "bad zip"}, status=400)
            elif fn.endswith(".json"):
                p = parse_profile_bytes(blob, source_name=fn, system_index=sys_idx)
                if p:
                    added.append(p)
                else:
                    skipped += 1

        if not added:
            return self._json_cors({"result": "ok", "added": 0, "skipped": skipped})

        # Merge with existing user JSON (same (vendor,name) -> replace)
        path = self._orca_filaments_user_path()
        existing: list[dict] = []
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    existing = json.load(f) or []
            except Exception:
                existing = []
        by_key = {(p.get("vendor"), p.get("name")): p for p in existing}
        for p in added:
            by_key[(p.get("vendor"), p.get("name"))] = p
        merged = sorted(by_key.values(), key=lambda x: (x.get("vendor",""), x.get("name","")))
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(merged, f, indent=2, ensure_ascii=False)
                f.write("\n")
        except Exception as e:
            return self._json_cors({"error": f"write failed: {e}"}, status=500)
        self._invalidate_filaments_cache()
        return self._json_cors({"result": "ok",
                                "added": len(added),
                                "skipped": skipped,
                                "total_user": len(merged)})

    async def handle_kx_filament_profiles_user_delete(self, request):
        """DELETE /kx/filament/profiles/user - deletes a single entry
        (?vendor=...&name=...), or every user profile with an explicit
        ?all=true. A partial identifier is rejected rather than treated as
        "delete everything"."""
        vendor = request.rel_url.query.get("vendor", "").strip()
        name   = request.rel_url.query.get("name", "").strip()
        wipe_all = str(request.rel_url.query.get("all", "")).lower() == "true"
        # Validate BEFORE the empty-store shortcut, or a malformed request
        # reports success and the caller never learns it was wrong.
        if not (vendor and name) and not wipe_all:
            return self._json_cors(
                {"error": "vendor and name are required (use ?all=true to clear every user profile)"},
                status=400)
        path = self._orca_filaments_user_path()
        if not os.path.isfile(path):
            return self._json_cors({"result": "ok", "removed": 0})
        try:
            with open(path, encoding="utf-8") as f:
                existing = json.load(f) or []
        except Exception:
            existing = []
        before = len(existing)
        if vendor and name:
            existing = [p for p in existing
                        if not (p.get("vendor") == vendor and p.get("name") == name)]
        else:
            # Explicit bulk wipe. Previously any request that merely lost one of
            # the two identifying fields fell through to here and silently
            # erased the operator's whole imported profile library.
            existing = []
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
                f.write("\n")
        except Exception as e:
            return self._json_cors({"error": str(e)}, status=500)
        self._invalidate_filaments_cache()
        return self._json_cors({"result": "ok",
                                "removed": before - len(existing),
                                "total_user": len(existing)})

    def _find_orca_filaments_json(self) -> str | None:
        """Finds the static JSON file. Sits next to web/ under _WEB_BASE/data/
        — in allen 3 Deployment-Modi:
          • Dev:     bridge/data/orca_filaments.json
          * Docker:  /app/data/orca_filaments.json (static in the image, NOT the
                     volume data/ holding runtime state - see Dockerfile)
          • Onefile: sys._MEIPASS/data/orca_filaments.json
        When the volume-mounted /app/data/ shadows the static data, a copy
        also sits under _WEB_BASE/data/ (= /app/ in Docker = the same path).
        On conflict: second lookup under ../bridge/data/ as a fallback for dev setups."""
        candidates = [
            # Docker: COPY bridge/data -> /app/static/ (data/ is a volume -> shadowed)
            os.path.join(_WEB_BASE, "static", "orca_filaments.json"),
            os.path.join(_WEB_BASE, "data", "orca_filaments.json"),
        ]
        here = os.path.dirname(os.path.abspath(__file__))
        candidates.append(os.path.join(here, "data", "orca_filaments.json"))
        candidates.append(os.path.join(here, "..", "bridge", "data", "orca_filaments.json"))
        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    async def handle_kx_filament_slot_profile(self, request):
        """POST /kx/filament/slots/<idx>/profile - saves or deletes
        a user override mapping for a single AMS slot.

        The primary selector is (vendor, name) - the ID is not unique in the Orca
        data model (136 profiles share e.g. 'OGFL99'). The ID is looked up
        from orca_filaments.json on save and carried along as a hint
        for OrcaSlicer's `tray_info_idx`.

        Body: {"vendor": "Polymaker", "name": "PolyTerra PLA"}
              {"vendor": "", "name": ""} → Mapping entfernen
              (Backwards compat: {"id":..., "vendor":...} is accepted,
              but `name` has been the primary selector since v0.9.18.)
        """
        try:
            slot_idx = int(request.match_info.get("idx", "-1"))
        except ValueError:
            return self._json_cors({"error": "bad slot index"}, status=400)
        if slot_idx < 0:
            return self._json_cors({"error": "bad slot index"}, status=400)
        try:
            data = await request.json()
        except Exception:
            data = {}
        new_vendor = (data.get("vendor") or "").strip()
        new_name   = (data.get("name")   or "").strip()
        new_id     = (data.get("id")     or "").strip()  # Backwards-Kompat-Hint
        if new_vendor and new_name:
            # Look up the ID from JSON (not from the request body, which could
            # be stale or a generic fallback).
            looked_up_id = self._lookup_filament_id(new_vendor, new_name)
            self._filament_profiles[slot_idx] = {
                "vendor": new_vendor,
                "name":   new_name,
                "id":     looked_up_id or new_id,
            }
        else:
            self._filament_profiles.pop(slot_idx, None)
        # Persistieren in config.ini
        try:
            import config_loader as _cl
            _cl.save_filament_profiles(self._filament_profiles, self._printer_id)
        except Exception as e:
            log.warning(f"save_filament_profiles failed: {e}")
            return self._json_cors({"error": str(e)}, status=500)
        entry = self._filament_profiles.get(slot_idx, {})
        return self._json_cors({"result": "ok",
                                "slot_index": slot_idx,
                                "vendor": entry.get("vendor", ""),
                                "name":   entry.get("name", ""),
                                "id":     entry.get("id", "")})

    async def handle_kx_visible_vendors(self, request):
        """GET/POST /kx/filament/visible_vendors — Vendor-Sichtbarkeitsfilter
        for the slot profile dropdown (Issue #41 option A).

        GET  → {"result": ["Polymaker", "eSUN", ...]}
        POST {"vendors": [...]} → speichert in config.ini [filament_profiles]
             visible_vendors. Empty list = all visible. NO bridge restart
             needed (display filter only)."""
        if request.method == "POST":
            try:
                data = await request.json()
            except Exception:
                data = {}
            vendors = data.get("vendors") or []
            if not isinstance(vendors, list):
                return self._json_cors({"error": "vendors must be a list"}, status=400)
            self._visible_vendors = [str(v).strip() for v in vendors if str(v).strip()]
            try:
                import config_loader as _cl
                _cl.save_visible_vendors(self._visible_vendors, self._printer_id)
            except Exception as e:
                log.warning(f"save_visible_vendors failed: {e}")
                return self._json_cors({"error": str(e)}, status=500)
        return self._json_cors({"result": self._visible_vendors})

    def _load_orca_filaments(self) -> list[dict]:
        """Loads system + user profiles from the cache. System profiles come
        from bridge/data/orca_filaments.json (image-embedded), user profiles
        from <KX_DATA_DIR>/orca_filaments.user.json (volume-persistent -
        survives image updates). User profiles get an `is_user: True`
        flag so the frontend can mark them."""
        if getattr(self, "_orca_filaments_cache", None) is not None:
            return self._orca_filaments_cache
        merged: list[dict] = []
        # System
        sys_path = self._find_orca_filaments_json()
        if sys_path and os.path.isfile(sys_path):
            try:
                with open(sys_path, encoding="utf-8") as f:
                    merged.extend(json.load(f) or [])
            except Exception as e:
                log.warning(f"orca_filaments.json read error: {e}")
        # User
        usr_path = self._orca_filaments_user_path()
        if usr_path and os.path.isfile(usr_path):
            try:
                with open(usr_path, encoding="utf-8") as f:
                    for p in (json.load(f) or []):
                        p["is_user"] = True
                        merged.append(p)
            except Exception as e:
                log.warning(f"orca_filaments.user.json read error: {e}")
        self._orca_filaments_cache = merged
        return self._orca_filaments_cache

    def _orca_filaments_user_path(self) -> str:
        """Path to the user profiles JSON. Lives in the volume mount (KX_DATA_DIR)
        so image updates do not destroy the data."""
        data_dir = os.environ.get("KX_DATA_DIR") or os.path.join(_WEB_BASE, "data")
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "orca_filaments.user.json")

    def _invalidate_filaments_cache(self):
        self._orca_filaments_cache = None

    def _lookup_filament_id(self, vendor: str, name: str) -> str:
        """Looks up the filament_id for a (vendor,name) tuple in
        orca_filaments.json. Returns '' when not found."""
        for p in self._load_orca_filaments():
            if p.get("vendor") == vendor and p.get("name") == name:
                return p.get("id", "")
        return ""

    async def handle_kx_history(self, request):
        limit  = int(request.rel_url.query.get("limit", 50))
        offset = int(request.rel_url.query.get("offset", 0))
        # 653 jobs: the join was the single worst loop stall measured (2.7 s
        # with six ports fanned out). Off the loop like /kx/files.
        jobs   = await asyncio.get_event_loop().run_in_executor(
            None, self._store.list_jobs, limit, offset)
        return self._json_cors({"result": jobs})

    async def handle_kx_file_objects(self, request):
        """Returns the object list + optional SVG for a file.

        GET /kx/files/{id}/objects → {"names": [...], "svg_b64": "..."}
        If the file has no objects yet (old entry): querying file/fileDetails
        from the printer and awaiting the response is the frontend's job
        (reload after upload). Only return the database state here.
        """
        fid = request.match_info.get("id", "")
        f = self._store.get_file(fid)
        if not f:
            return self._json_cors({"error": "file not found"}, status=404)
        try:
            names = json.loads(f.get("objects_skip_parts") or "[]")
        except Exception:
            names = []
        # No objects in the store yet (fresh Orca/web upload): actively request
        # file/fileDetails from the printer once. _on_file() backfills the store,
        # the frontend polls this endpoint and receives the list on the next
        # attempt (Issue #57 - skip parity outside the file browser too).
        if not names:
            fn = f.get("filename") or ""
            if fn:
                try:
                    self.client.publish("file", "fileDetails",
                                        {"root": "local", "filename": fn}, timeout=0)
                except Exception as e:
                    log.debug(f"fileDetails request failed: {e}")
        return self._json_cors({
            "result": {
                "names":   names,
                "svg_b64": f.get("svg_image") or "",
            }
        })

    async def handle_kx_skip(self, request):
        """Trigger a mid-print skip.

        POST /kx/skip  body={"names": ["..", ".."]}
        """
        try:
            body = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid json"}, status=400)
        names = body.get("names") or []
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            return self._json_cors({"error": "names must be list[str]"}, status=400)
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self.client.skip_objects(names))
        except Exception as e:
            return self._json_cors({"error": str(e)}, status=502)
        return self._json_cors({"result": "ok", "names": names})

    def _build_skip_state_result(self) -> dict:
        """Builds the combined skip state for UI endpoints."""
        filename = self._state.get("filename", "")
        all_objects: list[str] = []
        svg = ""
        if filename:
            try:
                f = self._store.get_file_by_name(filename)
                if f:
                    all_objects = json.loads(f.get("objects_skip_parts") or "[]")
                    svg = f.get("svg_image") or ""
            except Exception as e:
                log.warning(f"skip_state lookup failed: {e}")
        return {
            "objects":  all_objects,
            "skipped":  list(self._skip_state.get("skipped", [])),
            "svg_b64":  svg,
            "ts":       self._skip_state.get("ts", 0),
            "filename": filename,
        }

    async def handle_kx_skip_query(self, request):
        """Re-request the print object list from the printer.

        POST /kx/skip/query  → triggert skip/query_obj, wartet kurz auf den
        async skip/report and returns the merged skip state.
        """
        prev_ts = int(self._skip_state.get("ts", 0) or 0)
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self.client.query_skip_objects())
        except Exception as e:
            return self._json_cors({"error": str(e)}, status=502)

        deadline = time.time() + 1.5
        while time.time() < deadline:
            if int(self._skip_state.get("ts", 0) or 0) > prev_ts:
                break
            await asyncio.sleep(0.1)

        return self._json_cors({"result": self._build_skip_state_result()})

    async def handle_kx_skip_state(self, request):
        """Aktueller Skip-State.

        Kombiniert:
        - Full object list: from the GCode store, matched via the currently
          running filename (file/report at print start populated the list).
          skip/query_obj only returns the already-skipped ones,
          not the full list.
        - Skipped: from self._skip_state (updated by skip/report).
        """
        return self._json_cors({"result": self._build_skip_state_result()})

    async def handle_kx_printers(self, request):
        # Collect active printers (with IP)
        active = [(pid, br) for pid, br in self._all_bridges.items()
                  if (br._args.printer_ip or "").strip()]
        # Host for bridge_url: keep the browser view, but never export "localhost" -
        # otherwise browser fetches fail when the UI is opened via the LAN IP.
        host = request.host.split(":")[0]
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            host = ""
        out = []
        for pid, br in active:
            port = getattr(br._args, "port", 7125)
            # Only set a concrete bridge_url for multi-printer setups (cross-instance fetch).
            # Single printer: empty bridge_url -> JS uses relative paths (same origin as the UI).
            bridge_url = ""
            if len(active) > 1 and host:
                bridge_url = f"http://{host}:{port}"
            out.append({
                "id":         pid,
                "name":       br._state.get("printer_name") or f"Printer {pid}",
                "bridge_url": bridge_url,
                "printer_ip": br._args.printer_ip,
                "device_id":  br._args.device_id or "",
                **br._model_payload(),
            })
        return self._json_cors({"result": out})

    @staticmethod
    def _preflight_error(report: dict) -> str:
        reasons = report.get("reasons") or ["unknown preflight failure"]
        return "Unsafe G-code blocked: " + "; ".join(reasons)

    # ── Farm endpoints ─────────────────────────────────────────────────────
    # One request returns every printer's live state. The browser previously
    # had to fan out one /api/state per printer per refresh; in-process this is
    # a dict read per bridge, so the farm view can refresh continuously without
    # multiplying HTTP load on the weak printer hosts.

    def _farm_printer_entry(self, pid: str, br: "KobraXBridge") -> dict:
        s = br._state
        maint = self._store.get_maintenance(pid)
        totals = self._store.printer_totals(pid, [br._args.device_id or ""])
        service_hours = float(maint.get("service_print_hours") or 0.0)
        service_jobs = int(maint.get("service_jobs") or 0)
        return {
            "id": pid,
            "name": s.get("printer_name") or f"Printer {pid}",
            "port": getattr(br._args, "port", 7125),
            "printer_ip": br._args.printer_ip,
            **br._model_payload(),
            "kobra_state": s.get("kobra_state", ""),
            "print_state": s.get("print_state", ""),
            "filename": s.get("filename", ""),
            "progress": s.get("progress", 0),
            "remain_time": s.get("remain_time", 0),
            "print_duration": s.get("print_duration", 0),
            "curr_layer": s.get("curr_layer", 0),
            "total_layers": s.get("total_layers", 0),
            "nozzle_temp": s.get("nozzle_temp", 0.0),
            "nozzle_target": s.get("nozzle_target", 0.0),
            "bed_temp": s.get("bed_temp", 0.0),
            "bed_target": s.get("bed_target", 0.0),
            "chamber_temp": s.get("chamber_temp", 0.0),
            "chamber_target": s.get("chamber_target", 0.0),
            "fan_speed": s.get("fan_speed", 0),
            "aux_fan_speed": s.get("aux_fan_speed", 0),
            "box_fan_speed": s.get("box_fan_speed", 0),
            "connection_error": s.get("connection_error", ""),
            "pause_msg": s.get("pause_msg", ""),
            "error_code": s.get("error_code", 0),
            "upload_progress": s.get("upload_progress") or {"active": False, "percent": 0, "phase": "idle"},
            "print_pending": br._pending_active(),
            # Ledger farm view: ACE slots straight from bridge memory. No printer
            # query - same source handle_kx_filament_slots() reads.
            "slots": [
                {
                    "slot_index": int(sl.get("global_index", i)),
                    "material": sl.get("type", ""),
                    "color_hex": "#{:02X}{:02X}{:02X}".format(*(sl.get("color") or [0, 0, 0])[:3]),
                    "status": "loaded" if sl.get("status") == 5 and str(sl.get("type") or "").strip() else "empty",
                }
                for i, sl in enumerate(getattr(br, "_ams_slots", None) or [])
            ],
            "maintenance_mode": bool(maint.get("maintenance_mode")),
            "maintenance_reason": maint.get("reason") or "",
            "serviced_at": maint.get("serviced_at"),
            "lifetime_jobs": totals["jobs"],
            "lifetime_print_hours": totals["print_hours"],
            "hours_since_service": round(max(0.0, totals["print_hours"] - service_hours), 2),
            "jobs_since_service": max(0, totals["jobs"] - service_jobs),
        }

    async def handle_kx_farm_overview(self, request):
        """GET /kx/farm/overview - live state of every configured printer."""
        printers = [
            self._farm_printer_entry(pid, br)
            for pid, br in self._all_bridges.items()
            if (br._args.printer_ip or "").strip()
        ]
        printers.sort(key=lambda p: str(p["id"]))
        return self._json_cors({"result": {"printers": printers, "ts": int(time.time())}})

    async def handle_kx_farm_stats(self, request):
        """GET /kx/farm/stats?days=7 - utilization and reliability per printer."""
        try:
            days = int(request.rel_url.query.get("days", 7))
        except ValueError:
            days = 7
        stats = self._store.farm_stats(days, {
            pid: [br._args.device_id or ""] for pid, br in self._all_bridges.items()
        })
        # Older bridge builds wrote the MQTT device_id into print_jobs.printer_id
        # instead of the slot number, so history splits one machine across two
        # keys. Fold those rows onto the printer that owns the device_id rather
        # than showing phantom printers with no name.
        by_device = {
            (br._args.device_id or ""): pid
            for pid, br in self._all_bridges.items() if (br._args.device_id or "")
        }
        for key in list(stats["printers"].keys()):
            pid = by_device.get(key)
            if not pid or pid == key:
                continue
            legacy = stats["printers"].pop(key)
            cur = stats["printers"].get(pid)
            if not cur:
                legacy["printer_id"] = pid
                stats["printers"][pid] = legacy
                continue
            for f in ("jobs", "completed", "failed", "print_seconds"):
                cur[f] = int(cur.get(f) or 0) + int(legacy.get(f) or 0)
            cur["print_hours"] = round(cur["print_seconds"] / 3600.0, 2)
            cur["utilization_pct"] = round(
                min(100.0, cur["print_seconds"] * 100.0 / (stats["days"] * 86400)), 1)
            cur["success_rate_pct"] = (
                round(cur["completed"] * 100.0 / cur["jobs"], 1) if cur["jobs"] else None)
        # Printers with no jobs in the window are absent from the GROUP BY, but
        # the farm view must still show them (an idle printer is a real signal).
        for pid, br in self._all_bridges.items():
            if not (br._args.printer_ip or "").strip() or pid in stats["printers"]:
                continue
            totals = self._store.printer_totals(pid, [br._args.device_id or ""])
            maint = self._store.get_maintenance(pid)
            stats["printers"][pid] = {
                "printer_id": pid, "jobs": 0, "completed": 0, "failed": 0,
                "print_seconds": 0, "print_hours": 0.0, "utilization_pct": 0.0,
                "success_rate_pct": None,
                "lifetime_jobs": totals["jobs"],
                "lifetime_print_hours": totals["print_hours"],
                "hours_since_service": round(
                    max(0.0, totals["print_hours"] - float(maint.get("service_print_hours") or 0.0)), 2),
                "jobs_since_service": max(0, totals["jobs"] - int(maint.get("service_jobs") or 0)),
                "serviced_at": maint.get("serviced_at"),
                "maintenance_mode": bool(maint.get("maintenance_mode")),
                "maintenance_reason": maint.get("reason") or "",
            }
        for pid, br in self._all_bridges.items():
            if pid in stats["printers"]:
                stats["printers"][pid]["name"] = br._state.get("printer_name") or f"Drucker {pid}"
        return self._json_cors({"result": stats})

    async def handle_kx_maintenance_get(self, request):
        """GET /kx/maintenance - maintenance record for this bridge's printer."""
        return self._json_cors({"result": self._store.get_maintenance(self._printer_id)})

    async def handle_kx_maintenance_post(self, request):
        """POST /kx/maintenance - {"maintenance_mode": bool, "reason": str}
        or {"action": "serviced", "note": str}.

        Maintenance mode is bookkeeping only: it flags the printer in the UI
        and in send targeting. It never moves, heats, or stops hardware.
        """
        try:
            body = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid json"}, status=400)
        if str(body.get("action", "")).lower() == "serviced":
            rec = self._store.record_service(self._printer_id, str(body.get("note", "")))
            return self._json_cors({"result": rec})
        if "maintenance_mode" not in body:
            return self._json_cors({"error": "maintenance_mode or action=serviced required"}, status=400)
        rec = self._store.set_maintenance_mode(
            self._printer_id, bool(body.get("maintenance_mode")), str(body.get("reason", "")))
        return self._json_cors({"result": rec})

    def _preflight_store_file(self, gcode_file: dict) -> dict:
        path = gcode_file.get("path") or ""
        if not path or not os.path.isfile(path):
            raise RuntimeError("G-code file missing from bridge storage")
        report = preflight_file(path, gcode_file.get("filename") or os.path.basename(path))
        if not report.get("safe"):
            log.warning(f"{self._preflight_error(report)} ({path}) - advisory only")
        return report

    def _set_upload_progress(self, filename: str, sent: int, total: int,
                             phase: str, error: str = "") -> None:
        """Publish bridge->printer transfer state for /api/state pollers."""
        percent = int(sent * 100 / total) if total else 0
        self._state["upload_progress"] = {
            "active": phase in ("sending", "processing"),
            "filename": filename,
            "sent": sent,
            "total": total,
            "percent": percent,
            "phase": phase,
            "error": error,
        }

    def _prepare_gcode_for_target(self, gcode_file: dict) -> tuple[dict, object]:
        """Return a native or safely-derived file for this printer model."""
        if not self._model:
            raise ValueError("target printer model is unsupported or unknown")
        nozzle = float(getattr(self._args, "nozzle_diameter", 0.4) or 0.4)
        slots = max(1, len(self._ams_slots))
        return self._store.gcode_for_model(
            gcode_file, self._model,
            target_nozzle_mm=nozzle,
            available_ace_slots=slots,
        )

    def _compatibility_payload(self, gcode_file: dict) -> dict:
        if not self._model:
            return {
                "decision": "blocked", "source_model_id": "",
                "target_model_id": self._state.get("model_id", ""),
                "reasons": ["target printer model is unsupported or unknown"],
                "warnings": [],
            }
        facts = self._store.gcode_facts(gcode_file)
        report = check_compatibility(
            facts, self._model,
            float(getattr(self._args, "nozzle_diameter", 0.4) or 0.4),
            max(1, len(self._ams_slots)),
        )
        return {
            "decision": report.decision,
            "source_model_id": report.source_model_id,
            "source_model_name": facts.source_model_name,
            "target_model_id": report.target_model_id,
            "target_model_name": self._model.name,
            "reasons": list(report.reasons),
            "warnings": list(report.warnings),
            "bounds_min": list(facts.bounds_min),
            "bounds_max": list(facts.bounds_max),
            "nozzle_mm": facts.nozzle_mm,
        }

    async def handle_kx_file_compatibility(self, request):
        gcode_file = self._store.get_file(request.match_info.get("file_id", ""))
        if not gcode_file:
            return self._json_cors({"error": "file not found"}, status=404)
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._compatibility_payload(gcode_file)
            )
        except Exception as e:
            return self._json_cors({"error": str(e)}, status=422)
        return self._json_cors({"result": result})

    async def handle_kx_file_compatibility_progress(self, request):
        file_id = request.match_info.get("file_id", "")
        def read_progress():
            gcode_file = self._store.get_file(file_id)
            return self._store.gcode_facts_progress(gcode_file) if gcode_file else None
        try:
            result = await asyncio.get_event_loop().run_in_executor(None, read_progress)
        except OSError as e:
            return self._json_cors({"error": str(e)}, status=404)
        if result is None:
            return self._json_cors({"error": "file not found"}, status=404)
        return self._json_cors({"result": result})

    def _upload_to_printer(self, path: str, filename: str) -> dict:
        """Upload one file to this printer, publishing progress as it goes."""
        self._set_upload_progress(filename, 0, 0, "sending")
        last = [0.0]

        def on_chunk(sent: int, total: int) -> None:
            now = time.time()
            # Throttle: the UI polls every few seconds, so per-chunk writes on a
            # 200 MB file would be ~800 pointless dict rebuilds.
            if sent >= total or now - last[0] >= 0.25:
                last[0] = now
                self._set_upload_progress(filename, sent, total, "sending")

        try:
            result = self.client.upload_gcode(
                path, filename, self._state.get("upload_url") or None,
                progress_cb=on_chunk,
            )
        except Exception as e:
            self._set_upload_progress(filename, 0, 0, "error", str(e))
            raise
        if not result or result.get("code") != 200:
            self._set_upload_progress(filename, 0, 0, "error", f"printer rejected upload: {result}")
            raise RuntimeError(f"target printer upload failed: {result}")
        self._set_upload_progress(filename, 0, 0, "done")
        return result

    def _ensure_gcode_on_printer(self, gcode_file: dict) -> bool:
        """Copy a store file to this printer when it is not already there.

        Identity is content-based: filename+size alone cannot tell a re-sliced
        file from the original when the size happens to match, and re-uploading
        a 200 MB file that is already byte-identical wastes minutes of farm
        time. The sha256 is cached per (printer, filename) in the shared store,
        so the hash is computed once per file, not once per printer.
        """
        filename = gcode_file["filename"]
        self._set_upload_progress(filename, 0, 0, "processing")
        try:
            self._preflight_store_file(gcode_file)
            listing = self._wait_for_file_action(
                "listLocal",
                lambda: self.client.publish(
                    "file", "listLocal",
                    {"page_num": 1, "page_size": 200, "path": "/"},
                    timeout=0,
                ),
                timeout=8.0,
            )
            # Unknown is not absent. Treating a timeout as [] discarded the
            # verified hash and forced a redundant 200 MB upload.
            if listing is None:
                raise RuntimeError("printer file list timed out; retry")
            records = (listing.get("data") or {}).get("records") or []
            expected_size = gcode_file.get("size_bytes", 0) or 0
            on_printer = any(
                r.get("filename") == filename and (r.get("size") or 0) == expected_size
                for r in records
            )
            try:
                local_hash = self._store.store_file_sha256(gcode_file)
            except OSError:
                local_hash = ""
            if on_printer:
                known = self._store.get_printer_file_hash(self._printer_id, filename)
                # Only a recorded hash that still matches proves the printer's
                # copy is byte-identical. Name+size alone is not proof.
                if known and local_hash and known.get("sha256") == local_hash:
                    self._set_upload_progress(filename, expected_size, expected_size, "done")
                    return False
                if known:
                    log.info(f"Content changed for {filename} on {self._state.get('printer_name')}; re-uploading")
                else:
                    log.info(f"Unverified copy of {filename} on {self._state.get('printer_name')} "
                             f"(name+size match only); uploading once to establish content identity")
            else:
                # Only a successful listing proves absence; then a stale hash
                # row really must be forgotten.
                self._store.forget_printer_file_hash(self._printer_id, filename)
            log.info(f"Uploading shared-store file to {self._state.get('printer_name')}: {filename}")
            self._upload_to_printer(gcode_file["path"], filename)
            if local_hash:
                self._store.record_printer_file_hash(
                    self._printer_id, filename, expected_size, local_hash)
            return True
        except Exception as e:
            if (self._state.get("upload_progress") or {}).get("phase") != "error":
                self._set_upload_progress(filename, 0, 0, "error", str(e))
            raise

    async def handle_kx_upload_local(self, request):
        """Copy one shared-store file to this printer without starting it."""
        try:
            body = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid json"}, status=400)
        gcode_file = self._store.get_file(body.get("file_id"))
        if not gcode_file:
            return self._json_cors({"error": "file not found"}, status=404)
        try:
            prepared, compatibility = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._prepare_gcode_for_target(gcode_file)
            )
            uploaded = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._ensure_gcode_on_printer(prepared)
            )
        except ValueError as e:
            log.warning(f"Blocked incompatible upload {gcode_file['filename']}: {e}")
            return self._json_cors({"error": str(e)}, status=422)
        except Exception as e:
            log.error(f"Cannot upload {gcode_file['filename']} to target printer: {e}")
            return self._json_cors({"error": str(e)}, status=502)
        return self._json_cors({
            "result": "ok",
            "filename": gcode_file["filename"],
            "uploaded": uploaded,
            "compatibility": compatibility.decision,
            "converted": bool(prepared.get("converted")),
            "target_model_id": self._model.model_id,
        })

    async def handle_kx_print(self, request):
        """Print start from the GCode store with optional filament assignments."""
        try:
            body = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid json"}, status=400)

        file_id = body.get("file_id")
        if not file_id:
            return self._json_cors({"error": "file_id required"}, status=400)

        gcode_file = self._store.get_file(file_id)
        if not gcode_file:
            return self._json_cors({"error": "file not found"}, status=404)

        # filament_assignments: [{slot_index, material, color_hex}, …]
        assignments = body.get("filament_assignments")
        # excluded_objects: ["name1","name2",...] – Pre-Print Skip (v0.9.10)
        excluded_objects = body.get("excluded_objects") or []
        if not isinstance(excluded_objects, list):
            excluded_objects = []

        if assignments:
          ams_box_mapping, unused_count, invalid_count = self._build_assigned_ams_box_mapping(assignments)
          if unused_count:
            log.debug(f"Skipped {unused_count} unused filament assignment(s) for mode={self._filament_mode}")
          if invalid_count:
            log.warning(f"Ignored {invalid_count} unusable filament assignment(s) for mode={self._filament_mode}")
            if not ams_box_mapping:
                return self._json_cors({"error": "no usable filament assignments for current filament mode"}, status=400)
        else:
            # No dialog -> all occupied slots as with a normal upload print
            ams_box_mapping = self._build_auto_ams_box_mapping()

        auto_leveling = int(body.get("auto_leveling", getattr(self._args, "auto_leveling", 1)))
        filename = gcode_file["filename"]

        if self._state.get("print_state") in (
                "printing", "paused", "preheating", "auto_leveling", "checking", "init"):
            return self._json_cors({"error": "printer is already busy"}, status=409)

        # Atomically reserve before the slow part (200 MB upload + 15 s
        # print/start). The token stops an older request's failure from clearing
        # a newer dispatch; a second concurrent start is rejected.
        pending_token = self._set_print_pending(filename)
        if not pending_token:
            return self._json_cors({"error": "another print is already starting"}, status=409)

        # Select/derive the target-model file before touching the printer. This
        # is the single path for uploads and starts, so cross-model safety cannot
        # be bypassed by a different UI action.
        loop = asyncio.get_event_loop()
        try:
            prepared, compatibility = await loop.run_in_executor(
                None, lambda: self._prepare_gcode_for_target(gcode_file)
            )
            file_path = prepared["path"]
            url = self._serve_url(file_path)
            payload = self._build_print_payload(
                filename, url, "", prepared.get("size_bytes", 0),
                ams_box_mapping=ams_box_mapping,
                auto_leveling=auto_leveling,
                excluded_objects=excluded_objects,
            )
        except ValueError as e:
            self._clear_print_pending(pending_token)
            log.warning(f"Blocked incompatible print {filename}: {e}")
            return self._json_cors({"error": str(e)}, status=422)
        except Exception as e:
            self._clear_print_pending(pending_token)
            log.error(f"Cannot build print request for {filename}: {e}")
            return self._json_cors({"error": str(e)}, status=500)

        # The requesting tab may be gone by now; all remaining status lives in
        # bridge memory and is visible from a fresh /kx/farm/overview request.
        self._reset_skip_state(excluded_objects)
        try:
            await loop.run_in_executor(None, lambda: self._ensure_gcode_on_printer(prepared))
        except ValueError as e:
            self._clear_print_pending(pending_token)
            log.warning(f"Blocked unsafe print {filename}: {e}")
            return self._json_cors({"error": str(e)}, status=422)
        except Exception as e:
            self._clear_print_pending(pending_token)
            log.error(f"Cannot prepare {filename} on target printer: {e}")
            return self._json_cors({"error": str(e)}, status=502)

        log.info(f"Kobra store print start: {filename}  target={self._model.model_id} "
                 f"compat={compatibility.decision} converted={bool(prepared.get('converted'))} "
                 f"ams={len(ams_box_mapping)} slots assignments={bool(assignments)} excluded={len(excluded_objects)}")
        try:
            result = await loop.run_in_executor(
                None, lambda: self.client.publish("print", "start", payload, timeout=15.0)
            )
        except Exception as e:
            self._clear_print_pending(pending_token)
            log.error(f"Print start failed for {filename}: {e}")
            return self._json_cors({"error": str(e)}, status=502)
        if result is None:
            self._clear_print_pending(pending_token)
            return self._json_cors({"error": "no response from printer"}, status=504)
        code = result.get("code")
        try:
            bad_code = code is not None and int(code) != 200
        except (TypeError, ValueError):
            bad_code = True
        if result.get("state") == "failed" or bad_code:
            self._clear_print_pending(pending_token)
            err = result.get("msg") or result.get("message") or f"printer rejected print start: {result}"
            return self._json_cors({"error": err}, status=502)

        if excluded_objects:
            loop.run_in_executor(None, lambda: self._apply_preprint_skip_after_start(excluded_objects))

        # HTTP and MQTT may report the same start concurrently; both claim one
        # canonical per-printer row instead of leaking a second device-id row.
        self._claim_history_job(filename, assignments=assignments)

        return self._json_cors({
            "result": "ok", "filename": filename,
            "compatibility": compatibility.decision,
            "converted": bool(prepared.get("converted")),
            "target_model_id": self._model.model_id,
        })

    # -------------------------------------------------------------------------
    # HTTP handlers
    # -------------------------------------------------------------------------

    async def handle_server_info(self, request):
        return web.json_response({
            "result": {
                "klippy_connected": True,
                "klippy_state":     "ready",
                "components":       ["file_manager", "job_state", "virtual_sdcard"],
                "failed_components":[],
                "registered_directories": ["gcodes"],
                "warnings":         [],
                "websocket_count":  len(self.ws_clients),
                "moonraker_version": MOONRAKER_VERSION,
                "api_version":      [1, 3, 0],
                "api_version_string": "1.3.0",
            }
        })

    async def handle_health(self, request):
        """Process liveness for Docker/watchdog: every poll thread must be alive.

        /server/info is a Moonraker-compat constant and cannot see a dead MQTT
        poll loop. Poll threads stamp poll_heartbeat each iteration.
        """
        now = time.time()
        stale = [
            pid for pid, br in self._all_bridges.items()
            if (br._args.printer_ip or "").strip()
            and now - float(br._state.get("poll_heartbeat") or 0.0) > POLL_STALE_SEC
        ]
        body = {"ok": not stale, "stale": stale, "printers": len(self._all_bridges)}
        return web.json_response(body, status=200 if not stale else 503)

    async def handle_printer_info(self, request):
        s = self._state
        return web.json_response({
            "result": {
                "state":           "ready",
                "state_message":   "Printer is ready",
                "hostname":        "kobrax-bridge",
                "klipper_path":    "/home/pi/klipper",
                "python_path":     "/home/pi/klippy-env/bin/python",
                "log_file":        "/tmp/klippy.log",
                "config_file":     "/home/pi/printer.cfg",
                "software_version": KLIPPER_VERSION,
                "cpu_info":        s["printer_name"],
            }
        })

    async def handle_machine_system_info(self, request):
        return web.json_response({
            "result": {
                "system_info": {
                    "cpu_info": {"cpu_count": 4, "bits": "64bit", "processor": "armv7l",
                                 "cpu_desc": "Anycubic Kobra X Bridge", "serial_number": "",
                                 "hardware_desc": "", "model": "Kobra X Bridge",
                                 "total_memory": 524288, "memory_units": "kB"},
                    "sd_info": {},
                    "distribution": {"name": "Linux", "id": "linux", "version": "1.0",
                                     "version_parts": {}, "like": "", "codename": ""},
                    "available_services": [],
                    "service_state": {},
                    "python": {"version": list(sys.version_info[:3]), "version_string": sys.version},
                    "network": {},
                    "canbus": {},
                }
            }
        })

    async def handle_objects_query(self, request):
        objects = self._build_printer_objects()
        requested = []
        query = request.rel_url.query
        if "objects" in query:
            requested = [x.strip() for x in str(query.get("objects", "")).split(",") if x.strip()]
        elif query:
            requested = [k for k in query.keys() if k]

        filtered = {k: objects[k] for k in requested if k in objects} if requested else objects
        return web.json_response({"result": {"status": filtered, "eventtime": time.time()}})

    async def handle_objects_list(self, request):
        return web.json_response({
            "result": {
                "objects": list(self._build_printer_objects().keys())
            }
        })

    async def handle_objects_subscribe(self, request):
        return web.json_response({
            "result": {
                "status": self._build_printer_objects(),
                "eventtime": time.time(),
            }
        })

    async def handle_files_list(self, request):
        filename = self._state.get("filename", "")
        files = []
        if filename:
            files.append({
                "path":     filename,
                "modified": time.time(),
                "size":     0,
                "permissions": "rw",
            })
        return web.json_response({"result": files})

    def _build_file_metadata(self, filename: str) -> dict:
        """Builds the Moonraker file metadata for a file. Shared source
        for HTTP /server/files/metadata AND the WS RPC server.files.metadata
        (previously the WS path had its own broken logic with a non-existent
        existierenden Store-Methode → leere Antwort → Mobileraker fragte in
        endless loop, app hung on refresh, Issue #48).

        Liefert Mobileraker-kompatible Pflichtfelder: `filename`, `size`,
        `modified` are non-nullable in GCodeFile; `print_start_time` and the
        Slicer-Felder optional."""
        s = self._state
        # Live _state values are only relevant for the currently/last tracked
        # job's own file - using them as a starting point for a DIFFERENT
        # filename leaked the tracked job's layer count/time into unrelated
        # metadata queries (Issue #102). For any other filename, rely solely
        # on that file's own GCodeStore row.
        is_tracked_file = bool(filename) and filename == s.get("filename")
        layer_h = float(s.get("layer_height") or 0.0) if is_tracked_file else 0.0
        first_h = float(s.get("first_layer_height") or 0.0) if is_tracked_file else 0.0
        total_layers = int(s.get("total_layers") or 0) if is_tracked_file else 0
        est_time = int(s.get("slicer_time") or 0) if is_tracked_file else 0
        size_bytes = 0
        try:
            gf = self._store.get_file_by_name(filename) or {}
            if not layer_h:
                layer_h = float(gf.get("layer_height") or 0.0)
                first_h = float(gf.get("first_layer_height") or layer_h)
            if not total_layers:
                total_layers = int(gf.get("layer_count") or 0)
            if not est_time:
                est_time = int(gf.get("est_print_time_sec") or 0)
            size_bytes = int(gf.get("size_bytes") or 0)
        except Exception:
            pass
        if not layer_h:
            layer_h = self._layer_height_from_filename(filename)
            if layer_h and not first_h:
                first_h = layer_h
        object_height = round(first_h + max(0, total_layers - 1) * layer_h, 3) if (layer_h and total_layers) else 0.0
        return {
            "filename":           filename,
            # GCodeFile (Mobileraker) requires size as a non-nullable int.
            "size":               size_bytes or 1,
            "modified":           time.time(),
            "estimated_time":     est_time or None,
            "layer_height":       layer_h or None,
            "first_layer_height": first_h or None,
            "layer_count":        total_layers or None,
            "object_height":      object_height or None,
            "thumbnails":         [],
        }

    async def handle_files_metadata(self, request):
        """Moonraker /server/files/metadata — moonraker-obico + Mobileraker
        holen Datei-Metadaten (Slicer-Zeit, Layer, object_height).
        Logic in _build_file_metadata (shared with WS RPC)."""
        filename = request.rel_url.query.get("filename", "") or self._state.get("filename", "")
        if not filename:
            return web.json_response({"result": {}})
        return web.json_response({"result": self._build_file_metadata(filename)})

    # -- Moonraker stubs for moonraker-obico ----------------------------------
    async def handle_access_api_key(self, request):
        """Moonraker /access/api_key - we have no auth, return a dummy.
        moonraker-obico logs a WARNING otherwise."""
        return web.json_response({"result": "kx-bridge-no-auth-required"})

    async def handle_machine_update_status(self, request):
        """Moonraker /machine/update/status - Obico uses this to show installed plugins."""
        return web.json_response({
            "result": {
                "busy":         False,
                "github_rate_limit":     60,
                "github_requests_remaining": 60,
                "github_limit_reset_time":   time.time() + 3600,
                "version_info": {},
            }
        })

    async def handle_history_list(self, request):
        """Moonraker /server/history/list - job history from the GCodeStore.

        moonraker-obico only uses the last element (limit=1, order=desc)."""
        try:
            limit = int(request.rel_url.query.get("limit", "50"))
        except ValueError:
            limit = 50
        try:
            jobs = await asyncio.get_event_loop().run_in_executor(
                None, self._store.list_jobs, limit, 0) or []
        except Exception:
            jobs = []
        # Mapping to the Moonraker schema. Moonraker returns start_time as a Unix
        # timestamp (float), not an ISO string - moonraker-obico parses it with
        # int(start_time) and crashes otherwise.
        def _to_unix_ts(iso: str | None) -> float:
            if not iso:
                return 0.0
            try:
                from datetime import datetime
                # Format from GCodeStore: "2026-05-27T21:22:25Z"
                dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
                return dt.replace(tzinfo=__import__("datetime").timezone.utc).timestamp()
            except Exception:
                return 0.0
        result_jobs = []
        for j in jobs:
            start_ts = _to_unix_ts(j.get("started_at"))
            dur = j.get("duration_sec") or 0
            result_jobs.append({
                "job_id":       j.get("id"),
                "exists":       True,
                "end_time":     (start_ts + dur) if start_ts and dur else None,
                "filament_used": 0.0,
                "filename":     j.get("filename", ""),
                "metadata":     {},
                "print_duration": dur,
                "status":       j.get("status") or "completed",
                "start_time":   start_ts,
                "total_duration": dur,
            })
        return web.json_response({"result": {"count": len(result_jobs), "jobs": result_jobs}})

    async def handle_webcams_list(self, request):
        """Moonraker /server/webcams/list - Obico fetches the webcam URLs here.

        When the client comes from another host (e.g. moonraker-obico on a
        separate server), it needs absolute URLs to reach the stream.
        A Host header with localhost/127.0.0.1 is replaced by the real LAN IP."""
        host_hdr = request.headers.get("Host", "") if request else ""
        host_name = (host_hdr or "").split(":")[0]
        port_part = f":{host_hdr.split(':')[1]}" if ":" in (host_hdr or "") else f":{self._args.port}"
        local_ip  = getattr(self, "_local_ip", None) or host_name
        if host_name in ("localhost", "127.0.0.1", ""):
            host_name = local_ip
        base         = f"http://{host_name}{port_part}"
        stream_url   = f"{base}/api/camera/stream"
        snapshot_url = f"{base}/api/camera/snapshot"
        if not CAMERA_ENABLED:
            # Advertise no webcam at all, otherwise Moonraker clients (OrcaSlicer,
            # Mainsail, mobile apps) keep opening the stream endpoint.
            return web.json_response({"result": {"webcams": []}})
        return web.json_response({
            "result": {
                "webcams": [
                    {
                        "name":         "Kobra Bridge",
                        "location":     "printer",
                        "service":      "mjpegstreamer",
                        "enabled":      True,
                        "icon":         "mdiWebcam",
                        "target_fps":   5,
                        "target_fps_idle": 2,
                        "stream_url":   stream_url,
                        "snapshot_url": snapshot_url,
                        "flip_horizontal": False,
                        "flip_vertical":   False,
                        "rotation":     0,
                        "aspect_ratio": "16:9",
                        "extra_data":   {},
                    }
                ]
            }
        })

    async def handle_file_upload(self, request):
        # Bodies are buffered whole (up to client_max_size); bound how many can
        # sit in RAM at once so parallel slicer uploads cannot OOM the process
        # that serves all six printers.
        async with _UPLOAD_SLOTS:
            return await self._handle_file_upload_buffered(request)

    async def _handle_file_upload_buffered(self, request):
        log.info(f"Upload-Request: {request.method} {request.path_qs}  CT={request.headers.get('Content-Type','')[:60]}")
        ct = request.headers.get("Content-Type", "")
        if "multipart" not in ct:
            return web.json_response({"error": "expected multipart"}, status=400)
        auto_print = False
        web_upload = False
        reader = await request.multipart()
        file_data = None
        remote_filename = self._last_uploaded_file or "upload.gcode"

        async for part in reader:
            if part.name in ("file", "gcode", "upload_file"):
                remote_filename = part.filename or remote_filename
                file_data = await part.read()
                log.info(f"Multipart-Feld '{part.name}': {remote_filename} ({len(file_data)} bytes)")
            elif part.name == "path":
                val = (await part.read()).decode("utf-8", errors="replace").strip()
                if val:
                    remote_filename = val
            elif part.name == "print":
                val = (await part.read()).decode("utf-8", errors="replace").strip().lower()
                auto_print = val == "true"
            elif part.name == "web_upload":
                val = (await part.read()).decode("utf-8", errors="replace").strip().lower()
                web_upload = val == "true"
            else:
                log.debug(f"Unbekanntes Multipart-Feld: {part.name}")

        if not file_data:
            return web.json_response({"error": "no file received"}, status=400)

        # Only allow printable files (Issue #59) - the Kobra X accepts
        # only .gcode and .bgcode; .3mf uploads are not processed by the
        # printer and are therefore rejected (Issue #59, @gangoke).
        _allowed_ext = (".gcode", ".bgcode")
        _fn_lower = (remote_filename or "").lower()
        if not _fn_lower.endswith(_allowed_ext):
            log.warning(f"Upload rejected (not GCode): {remote_filename}")
            return web.json_response(
                {"error": f"only GCode files allowed ({', '.join(_allowed_ext)})"},
                status=400,
            )

        # Advisory GoKlipper starvation scan. Every current farm profile trips
        # the strict gate (11/12 stored files), so blocking would stop the farm.
        # Log the reasons, keep the object list, let the upload through.
        # Full line-by-line scan (~2 s per 230 MB): off the event loop, same
        # reason as _ingest below.
        loop = asyncio.get_event_loop()
        preflight = await loop.run_in_executor(None, preflight_bytes, file_data, remote_filename)
        if not preflight.get("safe"):
            log.warning(f"{self._preflight_error(preflight)} ({remote_filename}) - advisory only")

        # Hashing, G-code parsing and the disk write are pure CPU/IO on a
        # possibly 200MB buffer. Run on the event loop they froze every HTTP
        # request and MQTT callback for ALL SIX printers for the duration of a
        # single Orca upload. One executor hop keeps the farm responsive.

        def _ingest():
            md5 = hashlib.md5(file_data).hexdigest()
            est = _parse_gcode_estimated_time(file_data)
            thumb = _extract_thumbnail(file_data)
            filaments = _extract_filament_info(file_data)
            lh, fh = _parse_gcode_layer_heights(file_data)
            self._store.save_file(
                file_id=md5,
                filename=remote_filename,
                data=file_data,
                est_time_sec=est,
                thumbnail_b64=thumb,
                gcode_filaments=filaments or None,
                web_unverified=web_upload,
                layer_height=lh,
                first_layer_height=fh,
            )
            # Objects from the local scan so the skip UI works before the
            # printer ever sees the file; fileDetails later adds the SVG.
            if preflight.get("objects"):
                self._store.update_file_objects(remote_filename, preflight["objects"])
            return md5, est, filaments, lh, fh

        file_size = len(file_data)
        file_md5, est_time, gcode_filaments, layer_h, first_h = await loop.run_in_executor(
            None, _ingest)
        self._state["slicer_time"] = est_time
        self._state["layer_height"] = layer_h
        self._state["first_layer_height"] = first_h
        del file_data  # free RAM

        self._last_uploaded_file = remote_filename
        log.info(f"Upload: {remote_filename} ({file_size} bytes) md5={file_md5} -> store only")

        # Library-only upload. A slicer upload used to be copied straight into
        # this port's printer (and started when print=true), so slicing always
        # pushed G-code to whichever printer owned the port OrcaSlicer targets.
        # Operator picks the destination explicitly via /kx/upload-local, so the
        # transfer and the auto-print are both refused here.
        # ponytail: unconditional policy, make it a config flag if a printer ever
        # needs the old upload-and-print behaviour back.
        if request.rel_url.query.get("print", "").lower() == "true" or auto_print:
            log.info(f"Ignoring slicer print=true for {remote_filename}: "
                     f"library-only upload, start it from the UI instead")
        auto_print = False

        serve_url = self._serve_url(remote_filename)
        self._state["last_upload_url"]  = serve_url
        self._state["last_upload_md5"]  = file_md5
        self._state["last_upload_size"] = file_size
        # file_ready drives the UI's "ready to print" affordance, which is still
        # correct: the file is in the shared library, just not on any printer.
        self._state["file_ready"] = remote_filename

        return self._octoprint_upload_response(request, remote_filename, file_id=file_md5)

    @staticmethod
    def _octoprint_upload_response(request, remote_filename: str, extra: dict | None = None,
                                   file_id: str = ""):
        """OctoPrint-compatible upload response (OrcaSlicer evaluates refs)."""
        # `/api/files/local/{filename}` was advertised but only ever registered
        # for POST, so any client that followed refs.download got the catch-all.
        # Point at the real route; fall back to the served copy when the caller
        # has no file id (the printer fetches G-code from /serve/).
        if file_id:
            download = f"http://{request.host}/kx/files/{quote(file_id, safe='')}/download"
        else:
            download = f"http://{request.host}/serve/{quote(remote_filename, safe='')}"
        body = {
            "done": True,
            "files": {
                "local": {
                    "name": remote_filename,
                    "origin": "local",
                    "path": remote_filename,
                    "refs": {
                        "download": download,
                        "resource": download,
                    }
                }
            },
            "result": {
                "item": {"path": remote_filename, "root": "gcodes"},
                "action": "create_file",
            }
        }
        if extra:
            body.update(extra)
        return web.json_response(body, status=201)

    def _check_filament_mismatch(self, gcode_filaments: list | None) -> list[dict] | None:
        """Compares GCode filaments (is_used=True) with currently occupied AMS slots.

        Returns a list of mismatch entries when at least one used
        GCode slot has no matching material in the AMS - otherwise None.
        Only triggered when AMS data is present (at least 1 occupied slot)."""
        if not gcode_filaments:
            return None
        slots = self._ams_slots or []
        occupied = {s["global_index"]: s for s in slots if s.get("type") and s.get("status") == 5}
        if not occupied:
            return None
        mismatches = []
        for f in gcode_filaments:
            if not f.get("is_used"):
                continue
            idx = int(f.get("slot_index", -1))
            gcode_mat = (f.get("material") or "").upper().strip()
            if not gcode_mat:
                continue
            slot = occupied.get(idx)
            if slot is None:
                mismatches.append({
                    "slot_index": idx,
                    "gcode_material": gcode_mat,
                    "ams_material": None,
                    "reason": "empty",
                })
            else:
                ams_mat = (slot.get("type") or "").upper().strip()
                if ams_mat and ams_mat != gcode_mat:
                    mismatches.append({
                        "slot_index": idx,
                        "gcode_material": gcode_mat,
                        "ams_material": ams_mat,
                        "reason": "mismatch",
                    })
        return mismatches if mismatches else None

    def _build_print_payload(self, filename: str, url: str, md5: str, filesize: int,
                             ams_box_mapping: list, auto_leveling: int,
                             excluded_objects: list | None = None,
                             ai_type: int = 1, timelapse_type: int = 64) -> dict:
        """Builds the complete print/start MQTT payload. Single source for all
        three print start paths (upload, KX store, Moonraker API)."""
        return {
            "taskid":       "-1",
            "url":          url,
            "filename":     filename,
            "md5":          md5,
            "filepath":     None,
            "filetype":     1,
            "project_type": 1,
            "filesize":     filesize,
            "ams_settings": {
                "use_ams":         len(ams_box_mapping) > 0,
                "ams_box_mapping": ams_box_mapping,
            },
            "task_settings": {
                "auto_leveling":          auto_leveling,
                "vibration_compensation": getattr(self._args, "vibration_compensation", 0),
                "flow_calibration":       0,
                "dry_mode":               0,
                "ai_settings":   {"status": 0, "count": 0, "type": ai_type},
                "timelapse":     {"status": 0, "count": 0, "type": timelapse_type},
                "drying_settings": {"status": 0, "target_temp": 0, "duration": 0, "remain_time": 0},
                "model_objects_skip_parts": excluded_objects or [],
            },
        }

    def _serve_url(self, file_path: str) -> str:
        host = getattr(self, "_local_ip", "")
        if not host or host in ("localhost", "127.0.0.1", "0.0.0.0"):
            raise RuntimeError("BRIDGE_HOST_IP must be the bridge LAN address")
        return f"http://{host}:{self._args.port}/serve/{quote(os.path.basename(file_path))}"

    def _reset_skip_state(self, excluded_objects: list | None = None):
        """Resets the skip state before a print start. The UI is marked as
        "skipped" only after real printer confirmation."""
        self._skip_state = {"skipped": [], "ts": int(time.time())}
        if excluded_objects:
            self._pending_preprint_skip = [str(n) for n in excluded_objects if isinstance(n, str) and n]
            self._pending_preprint_skip_deadline = time.time() + 12.0
        else:
            self._pending_preprint_skip = []
            self._pending_preprint_skip_deadline = 0.0

    def _theme_index_path(self) -> str:
        return os.path.join(_WEB_BASE, "web", "themes", self._ui_theme, "index.html")

    def _load_index_template_cached(self) -> str:
        path = self._theme_index_path()
        mtime = os.path.getmtime(path)
        key = (path, mtime)
        if self._index_tpl_cache is not None and self._index_tpl_cache_key == key:
            return self._index_tpl_cache
        with open(path, "r", encoding="utf-8") as f:
            self._index_tpl_cache = f.read()
        self._index_tpl_cache_key = key
        return self._index_tpl_cache

    def _ui_asset_cache_buster(self) -> str:
        base = os.path.join(_WEB_BASE, "web", "themes", self._ui_theme)
        mt = 0.0
        for fn in ("index.html", "style.css", "app.js"):
            try:
                mt = max(mt, os.path.getmtime(os.path.join(base, fn)))
            except OSError:
                pass
        return str(int(mt)) if mt else "0"

    async def handle_print_start(self, request):
        """Moonraker alias routed through the canonical safe store print path."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = dict(body) if isinstance(body, dict) else {}
        filename = (request.rel_url.query.get("filename")
                    or body.get("filename")
                    or self._last_uploaded_file)
        if not body.get("file_id"):
            gcode_file = self._store.get_file_by_name(filename) if filename else None
            if not gcode_file:
                return web.json_response(
                    {"error": f"{filename or 'file'} is not in bridge storage; re-upload for safety validation"},
                    status=409)
            body["file_id"] = gcode_file["id"]
        return await self.handle_kx_print(_JsonBodyRequest(body))

    async def handle_print_pause(self, request):
        loop = asyncio.get_event_loop()
        taskid = self._state.get("taskid", "-1")
        await loop.run_in_executor(None, lambda: self.client.pause_print(taskid))
        return web.json_response({"result": "ok"})

    async def handle_print_resume(self, request):
        loop = asyncio.get_event_loop()
        taskid = self._state.get("taskid", "-1")
        await loop.run_in_executor(None, lambda: self.client.resume_print(taskid))
        return web.json_response({"result": "ok"})

    async def handle_print_cancel(self, request):
        loop = asyncio.get_event_loop()
        taskid = self._state.get("taskid", "-1")
        await loop.run_in_executor(None, lambda: self.client.stop_print(taskid))
        return web.json_response({"result": "ok"})

    async def handle_api_file_ready_clear(self, request):
        self._state["file_ready"] = ""
        self._state["filament_mismatch"] = None
        self._thumbnail_b64 = ""
        self._push_status_update()
        return web.json_response({"result": "ok"})

    async def handle_octoprint_version(self, request):
        return web.json_response({
            "api":     "0.1",
            "server":  "1.9.0",
            "text":    "OctoPrint (Kobra X Bridge)",
        })

    async def handle_kx_ui_asset(self, request):
        name = request.match_info.get("name", "").lstrip("/")
        ctype = _KX_UI_ASSETS.get(name)
        cache_control = "public, max-age=86400"

        if ctype is not None:
            path = os.path.join(_WEB_BASE, "web", "themes", self._ui_theme, name)
        elif name.startswith("lib/"):
            ext = os.path.splitext(name)[1].lower()
            ctype = _KX_UI_LIB_TYPES.get(ext)
            if not ctype:
                raise web.HTTPNotFound()
            lib_root = pathlib.Path(_WEB_BASE, "web", "themes", self._ui_theme, "lib").resolve()
            candidate = pathlib.Path(_WEB_BASE, "web", "themes", self._ui_theme, name).resolve()
            # aiohttp preserves encoded dot-segments in match_info. Extension
            # validation alone is not containment: lib/../../secret.css still
            # ends in .css and used to escape the theme tree.
            try:
                candidate.relative_to(lib_root)
            except ValueError:
                raise web.HTTPNotFound()
            path = str(candidate)
        else:
            m = _KX_UI_TRANSLATION_RE.match(name)
            if not m:
                raise web.HTTPNotFound()
            lang = m.group(1)
            ctype = "application/json"
            cache_control = "no-store"
            path = os.path.join(_WEB_BASE, "web", "translations", f"{lang}.json")

        try:
            raw = pathlib.Path(path).read_text(encoding="utf-8")
        except OSError:
            raise web.HTTPNotFound()
        if name == "app.js":
            raw = raw.replace("'__VERSION__'", f"'{self._read_version()}'")
        resp = web.Response(
            text=raw,
            content_type=ctype,
            headers={"Cache-Control": cache_control},
        )
        # app.js is ~211KB and style.css ~33KB of plain text; both were served
        # uncompressed on every cold load. gzip cuts this by roughly 4-5x.
        resp.enable_compression()
        return resp

    async def handle_closed(self, request):
        """Static low-load page used while a printer is printing.

        Deliberately contains no JavaScript, timers, camera, websocket or API
        polling. Reopening requires an explicit click.
        """
        return web.Response(text="""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kobra Bridge closed</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#16181b;color:#e6e8ea;font:14px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}.box{width:min(420px,calc(100vw - 32px));border:1px solid #2c3136;background:#1c1f23;padding:24px;border-radius:5px}.box h1{margin:0 0 8px;font-size:18px;font-weight:600}.box p{margin:0 0 18px;color:#9aa2aa;line-height:1.5}.box a{display:inline-flex;min-height:44px;align-items:center;padding:0 14px;border:1px solid #456684;background:#31465c;color:#dce8f2;border-radius:4px;text-decoration:none}</style></head>
<body><main class="box"><h1>Kobra Bridge closed</h1><p>Polling, camera, timers and dashboard activity are stopped while the printer runs.</p><a href="/">Reopen Kobra Bridge</a></main></body></html>""", content_type="text/html", headers={"Cache-Control": "no-store"})

    async def handle_index(self, request):
        if self._index_page_cache is None:
            try:
                tpl = self._load_index_template_cached()
            except OSError:
                p = self._theme_index_path()
                log.error("Web UI theme file missing or unreadable: %s (theme: %s)", p, self._ui_theme)
                return web.Response(
                    text="<pre>Kobra Bridge: index.html not found.\nExpected:\n"
                    + html.escape(p, quote=True)
                    + "</pre>",
                    status=500,
                    content_type="text/html; charset=utf-8",
                )
            # Five file reads + four str.replace passes over ~460 KB, previously
            # on the event loop for every page load. Measured: 12 parallel loads
            # stalled /server/info for 1.9 s on the NAS. Assemble once, reuse.
            self._index_page_cache = await asyncio.get_event_loop().run_in_executor(
                None, self._build_index_page, tpl)
        resp = web.Response(text=self._index_page_cache, content_type="text/html",
                            headers={"Cache-Control": "no-store, no-cache, must-revalidate"})
        # This page inlines style.css + app.js (the OrcaSlicer webview ignores
        # external <link>/<script src>), so it is ~391KB of text and is served
        # no-store - i.e. re-downloaded in full on every single load. It is the
        # largest thing the UI transfers; gzip is the single biggest win here.
        resp.enable_compression()
        return resp

    def _build_index_page(self, tpl: str) -> str:
        page = tpl.replace("__UI_ASSETS_VER__", self._ui_asset_cache_buster())

        # Embed CSS + JS INLINE instead of just linking. OrcaSlicer's
        # embedded device tab webview does NOT load external <link>/<script src>
        # (only the bare HTML) -> without inlining neither
        # a single button works there (Issue #29). It is equally correct in a normal browser.
        base = os.path.join(_WEB_BASE, "web", "themes", self._ui_theme)

        # Inline vendored lib CSS/JS too — the OrcaSlicer webview loads no
        # external <link>/<script src>, so GridStack (and its stylesheet) must
        # be embedded like style.css/app.js. Order matters: GridStack's <script>
        # sits in <head>, before app.js, so it is defined when app.js inits.
        def _inline_css(rel_path: str, link_tag: str):
            nonlocal page
            try:
                data = pathlib.Path(os.path.join(base, rel_path)).read_text(encoding="utf-8")
                page = page.replace(link_tag, "<style>\n" + data + "\n</style>")
            except OSError:
                pass

        def _inline_js(rel_path: str, script_tag: str, version_sub: bool = False):
            nonlocal page
            try:
                data = pathlib.Path(os.path.join(base, rel_path)).read_text(encoding="utf-8")
                if version_sub:
                    data = data.replace("'__VERSION__'", f"'{self._read_version()}'")
                page = page.replace(script_tag, "<script>\n" + data + "\n</script>")
            except OSError:
                pass

        _inline_css("lib/gridstack.min.css", '<link rel="stylesheet" href="/kx/ui/lib/gridstack.min.css">')
        _inline_js("lib/gridstack-all.min.js", '<script src="/kx/ui/lib/gridstack-all.min.js"></script>')
        _inline_css("style.css", '<link rel="stylesheet" href="/kx/ui/style.css">')
        _inline_js("app.js", '<script src="/kx/ui/app.js"></script>', version_sub=True)
        return page

    async def handle_api_light(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        on         = bool(body.get("on", True))
        brightness = int(body.get("brightness", self._state["light_brightness"]))
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.client.publish(
            "light", "control",
            {"type": 3, "status": 1 if on else 0, "brightness": brightness},
            timeout=0
        ))
        self._state["light_on"]         = on
        self._state["light_brightness"] = brightness
        return web.json_response({"result": "ok"})

    # Control input bounds. The web UI only limits values via HTML min/max; the
    # bridge is the trust boundary for every LAN client, so it must refuse
    # 900 C or NaN itself. Limits mirror the UI (nozzle 300, bed 120).
    # ponytail: fixed Kobra X limits; read them from printer info if a
    # different model ever joins the farm.
    CONTROL_LIMITS = {"nozzle": (0, 300), "bed": (0, 120), "fan": (0, 100),
                      "axis_distance": (-300, 300)}

    def _bounded(self, value, kind: str, cast=float):
        lo, hi = self.CONTROL_LIMITS[kind]
        model = getattr(self, "_model", None)
        if model and kind == "nozzle":
            hi = model.max_nozzle_c
        elif model and kind == "bed":
            hi = model.max_bed_c
        try:
            if isinstance(value, bool):
                raise ValueError
            v = cast(float(value))
        except (TypeError, ValueError):
            raise ValueError(f"{kind} must be a number")
        if isinstance(v, float) and v != v:
            raise ValueError(f"{kind} must be a number")
        if not lo <= v <= hi:
            raise ValueError(f"{kind} out of range {lo}..{hi}")
        return v

    async def handle_api_fan(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        try:
            speed = self._bounded(body.get("speed", 0), "fan", int)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.client.publish(
            "fan", "setSpeed", {"fan_speed_pct": speed}, timeout=0
        ))
        self._state["fan_speed"] = speed
        return web.json_response({"result": "ok"})

    async def handle_api_connect(self, request):
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self.client.connect)
            self._state["print_state"] = "standby"
            self._state["kobra_state"] = "free"
            log.info("Connected manually")
            return web.json_response({"result": "connected"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_api_disconnect(self, request):
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self.client.disconnect)
        except Exception:
            pass
        self._state["print_state"] = "error"
        self._state["kobra_state"] = "offline"
        log.info("Manuell getrennt")
        return web.json_response({"result": "disconnected"})

    async def handle_api_restart(self, request):
        log.info("Restart requested via API")
        response = web.json_response({"status": "restarting"})
        asyncio.get_event_loop().call_later(0.3, self._restart_bridge)
        return response

    async def handle_api_speed(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        try:
            mode = int(body.get("mode", 2))
        except (TypeError, ValueError):
            return web.json_response({"error": "mode must be 1, 2, or 3"}, status=400)
        if mode not in (1, 2, 3):
            return web.json_response({"error": "mode must be 1, 2, or 3"}, status=400)
        loop = asyncio.get_event_loop()
        taskid = self._state.get("taskid", "-1")
        await loop.run_in_executor(None, lambda: self.client.publish_web(
            "print", "update",
            {"taskid": taskid, "settings": {"print_speed_mode": mode}},
        ))
        self._state["print_speed_mode"] = mode
        return web.json_response({"result": "ok"})

    async def handle_api_ams_set_slot(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        index  = int(body.get("index", 0))   # global slot index
        mat    = str(body.get("type", "PLA")).upper()
        color  = body.get("color", [255, 255, 255])
        if not (isinstance(color, list) and len(color) == 3):
            return web.json_response({"error": "color must be [r,g,b]"}, status=400)
        box_id, local_slot = self._global_to_box_slot(index)
        loop = asyncio.get_event_loop()
        self._state["last_ams_set_error"] = False
        # Remembered so a later state="failed" report (which carries no slot
        # info of its own, see _on_multicolor_box) can be logged alongside the
        # request that triggered it - otherwise the failure is unattributable.
        self._last_ams_set_request = {"global": index, "box": box_id, "local_slot": local_slot, "type": mat, "color": color}
        # setInfo goes via the web/printer topic (like tempature/set). Verified via
        # Workbench-Vue mqtt_setInfo verifiziert — via slicer/printer/ wurden
        # slot changes are ignored by the printer and overwritten with the old
        # material on the next multiColorBox/report.
        def _send():
            self.client.publish_web(
                "multiColorBox", "setInfo",
                {"multi_color_box": [{"id": box_id, "slots": [{"index": local_slot, "type": mat, "color": color}]}]},
            )
            log.info(f"setInfo (web) global={index} box={box_id} local_slot={local_slot} type={mat} color={color}")
        await loop.run_in_executor(None, _send)
        # Optimistisches Update: cached slot sofort anpassen (Drucker echoed
        # gleich via multiColorBox/report — falls er den Befehl ignoriert,
        # the report overwrites it again).
        for s in self._ams_slots:
            if s.get("global_index") == index:
                s["type"]  = mat
                s["color"] = color
                break
        return web.json_response({"result": "ok"})

    async def handle_api_ams_feed(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        slot_index = int(body.get("slot_index", 0))
        feed_type  = int(body.get("type", 1))
        if feed_type == 1:
          self._pending_load_slot = slot_index
        # Feed-out (type=2): if no slot was explicitly chosen, use the last loaded one
        if feed_type == 2 and self._ams_loaded_slot >= 0:
            slot_index = self._ams_loaded_slot
        box_id, local_slot = self._global_to_box_slot(slot_index)
        loop = asyncio.get_event_loop()
        def _send():
            resp = self.client.publish(
                "multiColorBox", "feedFilament",
                {"multi_color_box": [{"id": box_id, "feed_status": {"slot_index": local_slot, "type": feed_type}}]},
                timeout=5
            )
            log.info(f"feedFilament type={feed_type} global_slot={slot_index} box={box_id} local_slot={local_slot} loaded_slot={self._ams_loaded_slot} → {resp}")
        await loop.run_in_executor(None, _send)
        return web.json_response({"result": "ok"})

    async def handle_api_ace_auto_feed(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}

        ace_id_raw = body.get("ace_id", None)
        on_raw = body.get("on", None)
        if ace_id_raw is None or on_raw is None:
            return web.json_response({"error": "ace_id and on are required"}, status=400)
        try:
            ace_id = int(ace_id_raw)
            on = int(bool(on_raw))
        except Exception:
            return web.json_response({"error": "invalid parameters"}, status=400)
        if not (0 <= ace_id <= 3):
            return web.json_response({"error": "ace_id must be 0-3"}, status=400)

        payload = {"multi_color_box": [{"id": ace_id, "auto_feed": on}]}
        loop = asyncio.get_event_loop()
        # Fire-and-forget: setAutoFeed ACK arrives via multiColorBox/report callback.
        # Waiting for a response on that busy push topic causes false "code:0" rejections.
        await loop.run_in_executor(
            None,
            lambda: self.client.publish("multiColorBox", "setAutoFeed", payload, timeout=0)
        )
        self._ace_auto_feed[ace_id] = on
        self._state_dirty = True
        return web.json_response({"result": "ok", "ace_id": ace_id, "auto_feed": on})

    async def handle_api_ace_dry(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}

        action = str(body.get("action", "start")).lower()
        if action not in ("start", "stop"):
            return web.json_response({"error": "action must be 'start' or 'stop'"}, status=400)

        ace_ids = [i for i in self._ace_box_ids if 0 <= i <= 3]
        if not ace_ids:
            ace_ids = sorted({
                int(s.get("box_id", -1))
                for s in self._ams_slots
                if 0 <= int(s.get("box_id", -1)) <= 3
            })
        if not ace_ids and self._state.get("filament_mode") != "toolhead":
            ace_ids = [0]
        if not ace_ids:
            return web.json_response({"error": "ACE not detected"}, status=400)

        ace_id_raw = body.get("ace_id", None)
        if ace_id_raw is not None:
          try:
            ace_id = int(ace_id_raw)
          except Exception:
            return web.json_response({"error": "ace_id must be an integer"}, status=400)
          if ace_id not in ace_ids:
            return web.json_response({"error": f"ACE {ace_id + 1} not detected"}, status=400)
          ace_ids = [ace_id]

        if action == "start":
            target_temp = int(body.get("target_temp", 45))
            duration = int(body.get("duration", 240))
            target_temp = max(30, min(80, target_temp))
            duration = max(10, min(24 * 60, duration))
            humidity = (self._state.get("ace_drying") or {}).get("humidity")
            current_temp = (self._state.get("ace_drying") or {}).get("current_temp")
            drying_status = {
                "status": 1,
                "target_temp": target_temp,
                "duration": duration,
                "remain_time": duration,
            }
            ui_state = {
                "status": 1,
                "target_temp": target_temp,
                "duration": duration,
                "remain_time": duration,
                "humidity": humidity,
                "current_temp": current_temp,
            }
        else:
            drying_status = {"status": 0}
            humidity = (self._state.get("ace_drying") or {}).get("humidity")
            current_temp = (self._state.get("ace_drying") or {}).get("current_temp")
            ui_state = {
                "status": 0,
                "target_temp": 0,
                "duration": 0,
                "remain_time": 0,
                "humidity": humidity,
                "current_temp": current_temp,
            }

        payload = {
            "multi_color_box": [
                {"id": bid, "drying_status": dict(drying_status)}
                for bid in ace_ids
            ]
        }

        loop = asyncio.get_event_loop()

        def _send():
            return self.client.publish("multiColorBox", "setDry", payload, timeout=0)
        # Fire-and-forget: setDry ACK arrives via multiColorBox/report callback.
        # Waiting for a response on that busy push topic causes false "code:0" rejections.
        await loop.run_in_executor(None, _send)

        self._state["ace_drying"] = ui_state
        self._state_dirty = True
        return web.json_response({"result": "ok"})

    async def handle_api_axis(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}

        loop = asyncio.get_event_loop()
        action = str(body.get("action", "")).lower()

        if action == "turnoff":
            await loop.run_in_executor(None, lambda: self.client.publish(
                "axis", "turnOff", None, timeout=0
            ))
        else:
            try:
                axis = int(body.get("axis", 4))
                move_type = int(body.get("move_type", 2))
                distance = self._bounded(body.get("distance", 0), "axis_distance")
            except (TypeError, ValueError) as e:
                return web.json_response({"error": str(e) or "invalid axis command"}, status=400)
            valid = ((move_type == 1 and axis in (1, 2, 3)) or
                     (move_type == 2 and axis in (3, 4, 5) and distance == 0))
            if not valid:
                return web.json_response({"error": "invalid axis or move type"}, status=400)
            await loop.run_in_executor(None, lambda: self.client.publish(
                "axis", "move",
                {"axis": axis, "move_type": move_type, "distance": distance},
                timeout=0
            ))

        return web.json_response({"result": "ok"})

    async def handle_api_temperature(self, request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        nozzle = body.get("nozzle")
        bed    = body.get("bed")
        try:
            if nozzle is not None:
                nozzle = self._bounded(nozzle, "nozzle", int)
            if bed is not None:
                bed = self._bounded(bed, "bed", int)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        loop = asyncio.get_event_loop()
        printing = self._state.get("print_state") == "printing"
        if printing:
            # During print: runtime update via web/printer topic, one setting at a time
            taskid = self._state.get("taskid", "-1")
            if nozzle is not None:
                n = nozzle
                await loop.run_in_executor(None, lambda: self.client.publish_web(
                    "print", "update",
                    {"taskid": taskid, "settings": {"target_nozzle_temp": n}},
                ))
            if bed is not None:
                b = bed
                await loop.run_in_executor(None, lambda: self.client.publish_web(
                    "print", "update",
                    {"taskid": taskid, "settings": {"target_hotbed_temp": b}},
                ))
        else:
            # Idle: tempature/set via the `web/printer` topic with a `type` field.
            # Confirmed by live sniffing the Anycubic Slicer Next on 2026-05-29:
            #   topic = web/printer/.../tempature
            #   data  = {"type": 0|1|2, "target_hotbed_temp": B, "target_nozzle_temp": N}
            # type values (from Workbench Vue): 0=nozzle, 1=bed, 2=both.
            # Ohne `type` ODER auf `slicer/printer`-Topic → Systemfehler am Drucker.
            if nozzle is not None and bed is not None:
                t, n, b = 2, nozzle, bed
            elif nozzle is not None:
                t, n, b = 0, nozzle, 0
            elif bed is not None:
                t, n, b = 1, 0, bed
            else:
                return web.json_response({"result": "ok"})
            await loop.run_in_executor(None, lambda: self.client.publish_web(
                "tempature", "set",
                {"type": t, "target_nozzle_temp": n, "target_hotbed_temp": b},
            ))
        return web.json_response({"result": "ok"})

    async def _resolve_camera_url(self) -> str:
        """Prefer Rinkhals' working MJPEG stream on S1-family printers."""
        fallback = getattr(self, "_camera_anycubic_url", "") or self._state.get("camera_url", "")
        if getattr(self._model, "camera_transport", "") == "rinkhals-or-anycubic":
            ip = str(getattr(self._args, "printer_ip", "") or "").strip()
            try:
                timeout = aiohttp.ClientTimeout(total=2)
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{ip}/server/webcams/list", timeout=timeout) as response:
                        if response.status == 200:
                            webcams = (await response.json()).get("result", {}).get("webcams", [])
                            camera = next((cam for cam in webcams
                                           if cam.get("enabled") and cam.get("stream_url")), None)
                            stream = str((camera or {}).get("stream_url") or "")
                            snapshot = str((camera or {}).get("snapshot_url") or "")
                            def absolute(url):
                                parsed = urlsplit(url)
                                if url.startswith("/"):
                                    return f"http://{ip}{url}"
                                if parsed.scheme in ("http", "https") and parsed.hostname == ip:
                                    return url
                                return ""
                            stream, snapshot = absolute(stream), absolute(snapshot)
                            if stream and snapshot:
                                async with session.get(snapshot, timeout=timeout) as snap:
                                    valid = snap.status == 200 and await snap.content.read(2) == b"\xff\xd8"
                                if valid:
                                    self._camera_source = "rinkhals"
                                    self._state["camera_url"] = stream
                                    self.camera_cache.set_url(stream)
                                    return stream
            except Exception as exc:
                log.info(f"Rinkhals camera unavailable, using Anycubic stream: {exc}")
        self._camera_source = "anycubic"
        if fallback:
            self._state["camera_url"] = fallback
            self.camera_cache.set_url(fallback)
        return fallback

    async def handle_api_camera(self, request):
        if not CAMERA_ENABLED:
            return web.json_response({"url": "", "disabled": True})
        return web.json_response({"url": self._state["camera_url"]})

    async def handle_api_camera_start(self, request):
        if not CAMERA_ENABLED:
            return web.json_response({"result": "disabled", "state": "disabled"})
        await self._resolve_camera_url()
        if self._camera_source == "rinkhals":
            return web.json_response({"result": "ok", "state": "ready", "source": "rinkhals"})
        loop = asyncio.get_event_loop()
        # Wait for pushStarted confirmation before returning
        result = await loop.run_in_executor(None, lambda: self.client.publish(
            "video", "startCapture", None, timeout=8.0
        ))
        state = (result or {}).get("state", "")
        log.info(f"Camera startCapture: state={state}")
        return web.json_response({"result": "ok", "state": state, "source": "anycubic"})

    async def handle_api_camera_stop(self, request):
        if not CAMERA_ENABLED:
            return web.json_response({"result": "disabled"})
        try:
            body = await request.json()
        except Exception:
            body = {}
        if getattr(self, "_camera_source", "anycubic") == "rinkhals":
            self.camera_cache.reset()
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self.client.publish(
                "video", "stopCapture", None, timeout=0
            ))
        # Prevents the auto-start guard from restarting the camera during the
        # laufenden Drucks wieder einschaltet (State-Flicker-Problem).
        # A timed farm preview ending is not the operator opting out, so it
        # must not suppress camera_on_print for the running job.
        if not (isinstance(body, dict) and body.get("preview")):
            self._camera_user_stopped = True
        return web.json_response({"result": "ok"})

    async def handle_api_camera_reset(self, request):
        if not CAMERA_ENABLED:
            return web.json_response({"result": "disabled"})
        """Reset the backoff counter and restart ffmpeg immediately.
        Useful after a 429 lock (Retry-After expired) or after a printer restart."""
        self.camera_cache.reset()
        url = self._state.get("camera_url", "")
        if not url:
            log.warning("Camera reset requested but no camera_url is known yet (waiting for printer status)")
            return web.json_response({
                "result": "no_url",
                "message": "No camera URL known yet - wait for the next printer status update, or start a print/enable the camera first.",
            })
        self.camera_cache.set_url(url)
        await self.camera_cache.ensure_running()
        return web.json_response({"result": "ok", "url": url})

    async def handle_api_camera_snapshot(self, request):
        """Last JPEG frame from the CameraCache - instant from RAM,
        no separate ffmpeg instance anymore (prevents the single-client 429 at the
        printer and is ~1 s faster)."""
        if not CAMERA_ENABLED:
            return web.Response(status=503, text="Camera disabled in bridge config")
        url = self._state.get("camera_url", "")
        if not url:
            return web.Response(status=503, text="No camera URL known")
        self.camera_cache.set_url(url)
        await self.camera_cache.ensure_running()
        # Initial warmup: wait up to 5s for the first frame
        deadline = time.time() + 5.0
        while not self.camera_cache.latest_jpeg and time.time() < deadline:
            await asyncio.sleep(0.1)
        jpeg = self.camera_cache.latest_jpeg
        if not jpeg:
            return web.Response(status=503, text="No frame in cache yet")
        # If the last frame is older than 10 s -> the cache ffmpeg is probably
        # no longer running stably; deliver anyway but with a stale header.
        age = time.time() - self.camera_cache.latest_jpeg_ts
        headers = {"Cache-Control": "no-cache"}
        if age > 10:
            headers["X-Frame-Age"] = f"{age:.1f}"
        return web.Response(body=jpeg, content_type="image/jpeg", headers=headers)

    async def handle_camera_stream(self, request):
        if not CAMERA_ENABLED:
            return web.Response(status=503, text="Camera disabled in bridge config")
        """MJPEG live view, served as multipart/x-mixed-replace.

        Fed from the central CameraCache fanout (same pattern as
        handle_camera_h264) instead of spawning a dedicated ffmpeg process
        per HTTP client. The printer's camera server only tolerates a very
        limited number of concurrent connections (see CameraCache docstring)
        - previously every consumer of this endpoint (dashboard, OrcaSlicer,
        moonraker-obico, a second browser tab, ...) opened its own separate
        connection, so two simultaneous viewers could already exhaust the
        printer's connection limit and cause intermittent "stream
        unavailable" failures. Now all consumers share one connection.
        """
        url = self._state.get("camera_url", "")
        if not url:
            return web.Response(status=503, text="No camera URL known")
        self.camera_cache.set_url(url)
        await self.camera_cache.ensure_running()

        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=8)
        self.camera_cache.mjpeg_subscribers.add(q)

        # Wait for the first frame BEFORE resp.prepare() - once prepare() sends
        # the response headers the status is committed to 200, so a stalled
        # source (Issue #99) must be caught here to actually return a 503
        # instead of hanging the client forever with no frame ever arriving.
        try:
            first_frame = await asyncio.wait_for(q.get(), timeout=5.0)
        except asyncio.TimeoutError:
            self.camera_cache.mjpeg_subscribers.discard(q)
            return web.Response(status=503, text="No frame in cache yet")

        boundary = "kobraxframe"
        resp = web.StreamResponse(headers={
            "Content-Type": f"multipart/x-mixed-replace;boundary={boundary}",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        })
        await resp.prepare(request)
        try:
            frame = first_frame
            while True:
                header = (
                    f"--{boundary}\r\n"
                    f"Content-Type: image/jpeg\r\n"
                    f"Content-Length: {len(frame)}\r\n\r\n"
                ).encode()
                try:
                    await resp.write(header + frame + b"\r\n")
                except (ConnectionResetError, asyncio.CancelledError):
                    break
                except Exception:
                    break
                frame = await q.get()
        except Exception as e:
            log.warning(f"Camera stream interrupted: {e}")
        finally:
            self.camera_cache.mjpeg_subscribers.discard(q)

        return resp

    async def handle_camera_h264(self, request):
        """H.264 passthrough as MPEG-TS, fed from the central
        CameraCache fanout. Allows multiple parallel consumers without an
        additional FLV connection to the printer (single-client limit)."""
        if not CAMERA_ENABLED:
            return web.Response(status=503, text="Camera disabled in bridge config")
        url = self._state.get("camera_url", "")
        if not url:
            return web.Response(status=503, text="No camera URL known")
        self.camera_cache.set_url(url)
        await self.camera_cache.ensure_running()

        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=64)
        self.camera_cache.h264_subscribers.add(q)

        resp = web.StreamResponse(headers={
            "Content-Type": "video/mp2t",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        })
        await resp.prepare(request)
        try:
            while True:
                chunk = await q.get()
                try:
                    await resp.write(chunk)
                except (ConnectionResetError, asyncio.CancelledError):
                    break
        except Exception as e:
            log.warning(f"H.264-Stream unterbrochen: {e}")
        finally:
            self.camera_cache.h264_subscribers.discard(q)
        return resp

    async def handle_serve_file(self, request):
        """Serves uploaded G-code files from the temp directory (for printer download)."""
        filename = os.path.basename(request.match_info.get("filename", ""))
        serve_path = os.path.join(self._serve_dir_path, filename)
        if not os.path.isfile(serve_path):
            return web.Response(status=404, text="not found")
        size = os.path.getsize(serve_path)
        log.info(f"Printer downloading file: {filename} ({size} bytes)")
        return web.FileResponse(serve_path, headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        })

    async def handle_api_state(self, request):
        s = self._state
        # Slicer time + thumbnail are only transient in state (set during upload).
        # After a browser reload or an OrcaSlicer direct print (file did not come
        # through the UI upload) they are missing -> restore from the GCode store via the
        # laufenden Dateinamens nachladen.
        slicer_time = s["slicer_time"]
        thumbnail = self._thumbnail_b64
        fname = s.get("filename", "")
        if fname and (not slicer_time or not thumbnail):
            try:
                gf = self._store.get_file_by_name(fname)
                if gf:
                    if not slicer_time and gf.get("est_print_time_sec"):
                        slicer_time = int(gf["est_print_time_sec"])
                    if not thumbnail and gf.get("thumbnail_b64"):
                        thumbnail = gf["thumbnail_b64"]
            except Exception:
                pass
        resp = web.json_response({
            "printer_name":     s["printer_name"],
            "firmware_version": s["firmware_version"],
            **self._model_payload(),
            "print_state":      s["print_state"],
            "kobra_state":      s["kobra_state"],
            "nozzle_temp":      s["nozzle_temp"],
            "nozzle_target":    s["nozzle_target"],
            "bed_temp":         s["bed_temp"],
            "bed_target":       s["bed_target"],
            "chamber_temp":     s.get("chamber_temp", 0.0),
            "chamber_target":   s.get("chamber_target", 0.0),
            "progress":         s["progress"],
            "print_duration":   s["print_duration"],
            "remain_time":      s["remain_time"],
            "curr_layer":       s["curr_layer"],
            "total_layers":     s["total_layers"],
            "z_mm":             self._estimate_current_z(),
            "filename":         s["filename"],
            "slicer_time":      slicer_time,
            "camera_url":       s["camera_url"] if CAMERA_ENABLED else "",
            "camera_enabled":   1 if CAMERA_ENABLED else 0,
            "fan_speed":        s["fan_speed"],
            "aux_fan_speed":    s.get("aux_fan_speed", 0),
            "box_fan_speed":    s.get("box_fan_speed", 0),
            "print_speed_mode": s["print_speed_mode"],
            "auto_leveling":          getattr(self._args, "auto_leveling", 1),
            "vibration_compensation": getattr(self._args, "vibration_compensation", 0),
            "camera_on_print":        getattr(self._args, "camera_on_print", 0),
            "web_upload_warning":     getattr(self._args, "web_upload_warning", 1),
            "light_on":               s["light_on"],
            "light_brightness": s["light_brightness"],
            "upload_progress":  s.get("upload_progress") or {"active": False, "percent": 0, "phase": "idle"},
            "print_pending":    self._pending_active(),
            "ams_slots":        self._ams_slots,
            "ams_loaded_slot":  self._ams_loaded_slot,
            "filament_mode":    s.get("filament_mode", self._filament_mode),
            "ace_drying":       s.get("ace_drying", {"status": 0, "target_temp": 0, "duration": 0, "remain_time": 0, "humidity": None, "current_temp": None}),
            "ace_units":        list(self._ace_box_ids),
            "ace_auto_feed":    dict(self._ace_auto_feed),
            "ace_dry_presets":  self._ace_dry_presets,
            "thumbnail":        thumbnail,
            "connection_error": s["connection_error"],
            "file_ready":       s["file_ready"],
            "print_start_dialog": s.get("print_start_dialog", getattr(self._args, "print_start_dialog", 1)),
            "version":          self._read_version(),
            "pause_msg":        s.get("pause_msg", ""),
            "error_code":       s.get("error_code", 0),
        })
        # /api/state is the poll endpoint - every open tab fetches it on a timer,
        # and ~77% of its 11.3KB is the base64 thumbnail. Compressing it is the
        # difference between ~11KB and ~2KB per poll per tab.
        resp.enable_compression()
        return resp

    async def handle_moonraker_database(self, request):
        """OrcaSlicer Filament-Sync: /server/database/item?namespace=lane_data&key=lanes (AFC-Format)"""
        namespace = request.rel_url.query.get("namespace", "")
        key       = request.rel_url.query.get("key", "")

        if namespace == "lane_data":
            await asyncio.get_event_loop().run_in_executor(None, self._get_ams_slots_fresh)
            lanes = self._build_lane_data()
            log.info(f"AMS-Sync: {len(lanes)} Lanes an OrcaSlicer")
            return web.json_response({
                "result": {
                    "namespace": "lane_data",
                    "key":       key or "lanes",
                    "value":     lanes,
                }
            })

        if namespace in ("AFC", "afc-install", "happy_hare"):
            return web.json_response({
                "result": {"namespace": namespace, "key": key, "value": None}
            })

        # mainsail/presets: Obico asks for temperature presets. The schema is evaluated in
        # find_all_thermal_presets as data['value']['presets'].values(),
        # so we need at least {presets: {}} to avoid a crash.
        if namespace == "mainsail":
            if key == "presets":
                return web.json_response({
                    "result": {"namespace": "mainsail", "key": "presets",
                               "value": {"presets": {}}}
                })
            return web.json_response({
                "result": {"namespace": "mainsail", "key": key, "value": {}}
            })

        # obico namespace: in-memory KV store for plugin settings (key=printer_id etc.)
        if namespace == "obico":
            store = self._moonraker_kv_store.setdefault("obico", {})
            if key and key in store:
                return web.json_response({
                    "result": {"namespace": "obico", "key": key, "value": store[key]}
                })
            return web.json_response({
                "result": {"namespace": "obico", "key": key, "value": store if not key else None}
            })

        return web.json_response(
            {"error": {"code": 404, "message": f"Namespace '{namespace}' not found"}},
            status=404
        )

    async def handle_moonraker_database_post(self, request):
        """POST /server/database/item — KV-Store-Write (von moonraker-obico verwendet).
        moonraker-obico sends namespace/key/value as form-urlencoded POST params."""
        # Versuche JSON, fallback auf form-data, fallback auf Query-Params
        namespace = ""
        key       = ""
        value     = None
        try:
            data = await request.json()
            if isinstance(data, dict):
                namespace = data.get("namespace", "")
                key       = data.get("key", "")
                value     = data.get("value")
        except Exception:
            try:
                form = await request.post()
                namespace = form.get("namespace", "") or ""
                key       = form.get("key", "") or ""
                value     = form.get("value")
            except Exception:
                pass
        if not namespace:
            namespace = request.rel_url.query.get("namespace", "")
        if not key:
            key = request.rel_url.query.get("key", "")
        if namespace and key:
            store = self._moonraker_kv_store.setdefault(namespace, {})
            store[key] = value
            return web.json_response({
                "result": {"namespace": namespace, "key": key, "value": value}
            })
        return web.json_response({"error": {"code": 400, "message": "namespace + key required"}}, status=400)

    async def handle_database_list(self, request):
        """OrcaSlicer checks which namespaces exist to detect the MMU type."""
        return web.json_response({"result": {"namespaces": ["lane_data", "mainsail", "obico"]}})

    def _get_ams_slots_fresh(self):
        """Frische Slot-Daten per getInfo holen, Fallback auf gecachte."""
        resp = self.client.publish("multiColorBox", "getInfo", None, timeout=5)
        if resp and resp.get("data"):
            data = resp["data"]
            self._head_tools_model = int(data.get("head_tools_model", self._head_tools_model))
            boxes = data.get("multi_color_box") or []
            if boxes:
                self._update_ace_drying_state(data, boxes)
                self._filament_mode = self._detect_filament_mode(boxes, self._head_tools_model)
                self._state["filament_mode"] = self._filament_mode
                global_slots, global_loaded = self._aggregate_slots(boxes, self._filament_mode)
                activity_map = self._slot_activity_map(boxes, global_loaded)
                for s in global_slots:
                    s["activity"] = activity_map.get(s.get("global_index"), "")
                if global_slots:
                    self._ams_slots = global_slots
                self._ams_loaded_slot = global_loaded
        return self._ams_slots

    # ─── Settings ────────────────────────────────────────────────────────────

    def _find_config_path(self) -> pathlib.Path:
        """Returns the path to config.ini."""
        if hasattr(env_loader, "find_config_path"):
            return env_loader.find_config_path()
        # Fallback for the old env_loader
        script_dir = pathlib.Path(_BASE)
        for base in (script_dir, script_dir.parent):
            p = base / "config" / "config.ini"
            if p.is_file():
                return p
        return script_dir / "config" / "config.ini"

    async def handle_api_settings_get(self, request):
        return web.json_response({
            "printer_name":     self._state.get("printer_name", ""),
            "printer_ip":       self._args.printer_ip,
            "mqtt_port":        self._args.mqtt_port,
            "username":         self._args.username,
            # Never return the printer password to a browser. The settings form
            # leaves this blank; blank-on-save preserves the current value.
            "password":         "",
            "password_set":     bool(self._args.password),
            "mode_id":          self._args.mode_id,
            "device_id":        self._args.device_id,
            "default_ams_slot": getattr(self._args, "default_ams_slot", "auto"),
            "auto_leveling":          getattr(self._args, "auto_leveling", 1),
            "vibration_compensation": getattr(self._args, "vibration_compensation", 0),
            "camera_on_print":        getattr(self._args, "camera_on_print", 0),
            "camera_enabled":         1 if CAMERA_ENABLED else 0,
            "web_upload_warning":     getattr(self._args, "web_upload_warning", 1),
            "print_start_dialog":     getattr(self._args, "print_start_dialog", 1),
            "poll_interval":    getattr(self._args, "poll_interval", 3),
            "verbose_http_log": getattr(self._args, "verbose_http_log", 0),
            "filament_profiles": {str(k): v for k, v in self._filament_profiles.items()},
            "visible_vendors":  self._visible_vendors,
            "ace_dry_presets":  self._ace_dry_presets,
            "spoolman_server":  getattr(self._args, "spoolman_server", "") or "",
            "spoolman_sync_rate": getattr(self._args, "spoolman_sync_rate", 0),
        })

    async def handle_api_settings_post(self, request):
        import configparser
        data = await request.json()
        config_path = self._find_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Read the existing config.ini (comments are lost, but values are kept)
        cfg = configparser.ConfigParser()
        if config_path.is_file():
            cfg.read(config_path, encoding="utf-8")

        # Sections sicherstellen
        for section in ("connection", "print", "bridge", "ace_dry_presets", "spoolman"):
            if not cfg.has_section(section):
                cfg.add_section(section)

        printer_ip = str(data.get("printer_ip", self._args.printer_ip or "")).split(":")[0]
        cfg.set("connection", "printer_ip", printer_ip)
        cfg.set("connection", "mqtt_port",  str(data.get("mqtt_port",  self._args.mqtt_port or 9883)))
        cfg.set("connection", "username",   str(data.get("username",   self._args.username  or "")))
        # An empty password means "unchanged": the GET no longer hands the
        # secret to the browser, so a blank field is the normal case on save.
        _pw = str(data.get("password", "") or "")
        cfg.set("connection", "password",   _pw if _pw else str(self._args.password or ""))
        cfg.set("connection", "mode_id",    str(data.get("mode_id",    self._args.mode_id   or "")))
        cfg.set("connection", "device_id",  str(data.get("device_id",  self._args.device_id or "")))
        cfg.set("print",      "default_ams_slot", str(data.get("default_ams_slot", getattr(self._args, "default_ams_slot", "auto"))))
        cfg.set("print",      "auto_leveling",           str(data.get("auto_leveling",           getattr(self._args, "auto_leveling",           1))))
        cfg.set("print",      "vibration_compensation",  str(int(bool(data.get("vibration_compensation", getattr(self._args, "vibration_compensation", 0))))))
        cfg.set("print",      "camera_on_print",         str(int(bool(data.get("camera_on_print",        getattr(self._args, "camera_on_print",        0))))))
        cfg.set("print",      "web_upload_warning", str(int(bool(data.get("web_upload_warning", getattr(self._args, "web_upload_warning", 1))))))
        cfg.set("print",      "print_start_dialog", str(int(bool(data.get("print_start_dialog", getattr(self._args, "print_start_dialog", 1))))))
        if "poll_interval" in data:
            try:
                pi = max(1, min(60, int(data["poll_interval"])))
            except (TypeError, ValueError):
                pi = 3
            cfg.set("bridge", "poll_interval", str(pi))
        elif not cfg.has_option("bridge", "poll_interval"):
            cfg.set("bridge", "poll_interval", "3")
        verbose_http_log = int(bool(data.get("verbose_http_log", getattr(self._args, "verbose_http_log", 0))))
        cfg.set("bridge", "verbose_http_log", str(verbose_http_log))
        _set_verbose_http_log(bool(verbose_http_log))
        self._args.verbose_http_log = verbose_http_log
        printer_name = str(data.get("printer_name", "")).strip()
        if printer_name:
            cfg.set("bridge", "printer_name", printer_name)
        elif cfg.has_option("bridge", "printer_name"):
            cfg.remove_option("bridge", "printer_name")

        # Spoolman
        if "spoolman_server" in data:
            cfg.set("spoolman", "server", str(data["spoolman_server"]).strip())
        if "spoolman_sync_rate" in data:
            try:
                sr = max(0, int(data["spoolman_sync_rate"]))
            except (TypeError, ValueError):
                sr = 30
            cfg.set("spoolman", "sync_rate", str(sr))

        incoming_presets = data.get("ace_dry_presets") if isinstance(data, dict) else None
        presets = self._sanitize_ace_dry_presets(incoming_presets if isinstance(incoming_presets, dict) else self._ace_dry_presets)
        for key, val in presets.items():
          cfg.set("ace_dry_presets", f"{key}_temp", str(val["temp"]))
          cfg.set("ace_dry_presets", f"{key}_duration_sec", str(val["duration_sec"]))
          if key.startswith("custom_"):
            cfg.set("ace_dry_presets", f"{key}_name", str(val.get("name", key.replace("_", " ").title())))
        self._ace_dry_presets = presets

        with open(config_path, "w", encoding="utf-8") as f:
            f.write("# Kobra Bridge configuration (based on KX-Bridge)\n\n")
            cfg.write(f)
        log.info(f"Settings saved to {config_path}")
        # Send the response, then restart
        response = web.json_response({"status": "restarting"})
        asyncio.get_event_loop().call_later(0.3, self._restart_bridge)
        return response

    async def handle_kx_printer_add(self, request):
        """Adds a printer: fetches credentials via IP, writes [printer_N], restarts."""
        try:
            body = await request.json()
        except Exception:
            return self._json_cors({"error": "invalid json"}, status=400)
        ip   = str(body.get("printer_ip", "")).strip().split(":")[0]
        name = str(body.get("name", "")).strip()
        if not ip:
            return self._json_cors({"error": "printer_ip required"}, status=400)
        try:
            creds = await _kx_fetch_credentials(ip)
        except Exception as e:
            return self._json_cors({"error": f"printer unreachable or error: {e}"}, status=502)

        import configparser
        config_path = self._find_config_path()
        cfg = configparser.ConfigParser()
        if config_path.is_file():
            cfg.read(config_path, encoding="utf-8")

        # Vorhandene [printer_N]-Sektionen + belegte http_ports ermitteln
        n = 1
        existing_ports: set[int] = set()
        while cfg.has_section(f"printer_{n}"):
            p = cfg[f"printer_{n}"]
            if p.get("http_port"):
                try:
                    existing_ports.add(int(p["http_port"]))
                except ValueError:
                    pass
            n += 1

        # No [printer_N], but a populated [connection]? -> migrate as printer_1
        # (empty [connection] = no existing printer -> don't migrate, the new one becomes printer_1)
        if n == 1 and cfg.has_section("connection") and (cfg["connection"].get("printer_ip") or "").strip():
            c = cfg["connection"]
            cfg.add_section("printer_1")
            cfg.set("printer_1", "name", self._state.get("printer_name") or "Kobra X")
            for k in ("printer_ip", "mqtt_port", "username", "password", "mode_id", "device_id"):
                if c.get(k):
                    cfg.set("printer_1", k, c.get(k))
            cfg.set("printer_1", "http_port", "7125")
            existing_ports.add(7125)
            n = 2

        # Create the new printer as [printer_n], pick a free port
        new_port = 7125 + (n - 1)
        while new_port in existing_ports:
            new_port += 1
        sec = f"printer_{n}"
        cfg.add_section(sec)
        cfg.set(sec, "name",       name or creds["model"])
        cfg.set(sec, "printer_ip", creds["printer_ip"])
        cfg.set(sec, "mqtt_port",  "9883")
        cfg.set(sec, "username",   creds["username"])
        cfg.set(sec, "password",   creds["password"])
        cfg.set(sec, "mode_id",    creds["mode_id"])
        cfg.set(sec, "model_id",   creds["model_id"])
        cfg.set(sec, "device_id",  creds["device_id"])
        cfg.set(sec, "http_port",  str(new_port))

        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            f.write("# Kobra Bridge configuration (based on KX-Bridge)\n\n")
            cfg.write(f)
        log.info(f"Printer '{name or creds['model']}' added as {sec} (port {new_port})")
        response = self._json_cors({"status": "restarting", "section": sec, "http_port": new_port})
        asyncio.get_event_loop().call_later(0.5, self._restart_bridge)
        return response

    async def handle_kx_printer_remove(self, request):
        """Removes a printer from config.ini, then restarts.

        - Multi mode: [printer_N] is deleted, the rest renumbered (printer_3 -> printer_2),
          printer_1 bekommt immer http_port 7125.
        - Single mode (no [printer_N], only [connection]): pid "1" clears the [connection] block
          → Bridge startet im Offline-Modus auf 7125, UI bleibt erreichbar.
        - When the last [printer_N] is removed: all gone -> also the "empty" state.
        """
        pid = str(request.match_info.get("pid", "")).strip()
        if not pid:
            return self._json_cors({"error": "printer id required"}, status=400)

        import configparser
        config_path = self._find_config_path()
        cfg = configparser.ConfigParser()
        if config_path.is_file():
            cfg.read(config_path, encoding="utf-8")

        has_printer_sections = cfg.has_section("printer_1")
        target = f"printer_{pid}"

        if has_printer_sections:
            if not cfg.has_section(target):
                return self._json_cors({"error": f"{target} not found"}, status=404)
            # Collect all [printer_N] (except the one being deleted), renumber
            kept = []
            n = 1
            while cfg.has_section(f"printer_{n}"):
                if str(n) != pid:
                    kept.append(dict(cfg[f"printer_{n}"]))
                cfg.remove_section(f"printer_{n}")
                n += 1
            for i, sec_data in enumerate(kept, start=1):
                sec = f"printer_{i}"
                cfg.add_section(sec)
                for k, v in sec_data.items():
                    cfg.set(sec, k, v)
                cfg.set(sec, "http_port", str(7125 + i - 1))
            remaining = len(kept)
            # Was that the last printer? Then also clear [connection] -> truly "no printer"
            if remaining == 0 and cfg.has_section("connection"):
                for k in ("printer_ip", "username", "password", "device_id"):
                    cfg.set("connection", k, "")
        else:
            # Single mode: only pid "1" is valid (pseudo entry from handle_kx_printers)
            if pid != "1":
                return self._json_cors({"error": "no printer with this ID"}, status=404)
            # Clear [connection] values -> bridge starts without a printer
            if cfg.has_section("connection"):
                for k in ("printer_ip", "username", "password", "device_id"):
                    cfg.set("connection", k, "")
            remaining = 0

        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            f.write("# Kobra Bridge configuration (based on KX-Bridge)\n\n")
            cfg.write(f)
        log.info(f"Printer {target} removed ({remaining} remaining)")
        response = self._json_cors({"status": "restarting", "removed": target, "remaining": remaining})
        asyncio.get_event_loop().call_later(0.5, self._restart_bridge)
        return response

    def _restart_bridge(self):
        log.info("Restarting bridge...")
        # config_loader caches config.ini values in os.environ ("only if not set").
        # On restart, environ must be cleaned, otherwise the new process reads
        # the old values instead of the modified config.ini. Keys are derived
        # from config_loader.CONFIG_ENV_MAPPING (single source of truth) so a
        # newly added setting can never be forgotten here again.
        try:
            import config_loader as _cl
            _restart_env_keys = set(_cl.CONFIG_ENV_MAPPING.keys()) | {"FILE_READY_DIALOG"}
        except Exception:
            _restart_env_keys = ()
        for _k in _restart_env_keys:
            os.environ.pop(_k, None)

        in_docker = os.path.exists("/.dockerenv") or os.environ.get("KX_IN_DOCKER")
        if in_docker:
            # Docker/systemd: exiting the process is enough - the supervisor restarts (fresh environ)
            log.info("Container environment detected – exiting for supervisor restart")
            os._exit(0)

        frozen = getattr(sys, "frozen", False)

        # Linux: os.execv replaces the process image directly - clean even with PyInstaller onefile
        # (subprocess+exit would fail there on the deleted _MEIxxxx temp directory).
        if sys.platform != "win32":
            exe = sys.executable
            try:
                if frozen:
                    os.execv(exe, [exe] + sys.argv[1:])
                else:
                    os.execv(exe, [exe] + sys.argv)
            except Exception as e:
                log.error(f"Restart (execv) failed: {e} - please restart the bridge manually")
                os._exit(1)

        # Windows: os.execv is broken there (new PID, old process returns) -> subprocess
        cmd = ([sys.executable] + sys.argv[1:]) if frozen else ([sys.executable] + sys.argv)
        try:
            subprocess.Popen(cmd, cwd=os.getcwd(),
                             creationflags=(subprocess.DETACHED_PROCESS
                                            | subprocess.CREATE_NEW_PROCESS_GROUP))
        except Exception as e:
            log.error(f"Restart failed: {e} - please restart the bridge manually")
        os._exit(0)

    # ─── Update ──────────────────────────────────────────────────────────────

    def _read_version(self) -> str:
        # PyInstaller onefile unpacks VERSION (via kx-bridge.spec datas) to
        # sys._MEIPASS - therefore use _WEB_BASE instead of _BASE.
        for base in (pathlib.Path(_WEB_BASE), pathlib.Path(_BASE), pathlib.Path(_BASE).parent):
            p = base / "VERSION"
            if p.is_file():
                return p.read_text(encoding="utf-8").strip()
        return "unknown"

    async def handle_api_log_stream(self, request):
        """SSE endpoint: streams log entries live to the browser."""
        resp = web.StreamResponse(headers={
            "Content-Type":  "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })
        await resp.prepare(request)
        # Zuerst Ring-Buffer senden
        for entry in list(_log_buffer):
            data = json.dumps(entry, ensure_ascii=False)
            await resp.write(f"data: {data}\n\n".encode())
        # Dann live streamen
        q: asyncio.Queue = asyncio.Queue()
        _log_sse_queues.append(q)
        try:
            while True:
                try:
                    entry = await asyncio.wait_for(q.get(), timeout=25)
                except asyncio.TimeoutError:
                    # A keepalive is not EOF. The old outer catch returned the
                    # response after 25 quiet seconds; EventSource reconnected
                    # and replayed all 500 buffered logs forever.
                    await resp.write(b": keepalive\n\n")
                    continue
                data = json.dumps(entry, ensure_ascii=False)
                await resp.write(f"data: {data}\n\n".encode())
        except (ConnectionResetError, Exception):
            pass
        finally:
            _log_sse_queues.remove(q) if q in _log_sse_queues else None
        return resp

    async def handle_api_log_download(self, request):
        """Returns all buffered log entries as plaintext for download."""
        header = (f"# Kobra Bridge Log  |  Version {self._read_version()}  |  "
                  f"{time.strftime('%Y-%m-%d %H:%M:%S')}  |  {len(_log_buffer)} entries\n")
        lines = [f"[{e['ts']}] {e['lvl']:<7} {e['name']}: {e['msg']}" for e in _log_buffer]
        text = header + "\n".join(lines) + "\n"
        fname = f"kx-bridge-log_{time.strftime('%Y%m%d-%H%M%S')}.txt"
        return web.Response(
            body=text.encode("utf-8"),
            content_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    async def handle_api_update_check(self, request):
        # Do not compare this fork against upstream KX-Bridge releases: their
        # files omit Kobra Bridge modules and are not valid updates for this tree.
        return web.json_response({
            "current": self._read_version(),
            "latest": self._read_version(),
            "update_available": False,
            "repository": "https://github.com/cluzl/kobra-bridge",
            "manual_update": True,
            "changelog": "Updates are installed from the Kobra Bridge repository.",
        })

    async def handle_api_update_apply(self, request):
        # Kobra Bridge is a fork. The upstream KX-Bridge release files do not
        # contain kobra_models.py / kobra_gcode_compat.py or the S1 changes, so
        # pulling them over this tree would crash the next start. Update checks
        # still show upstream releases for information; applying is manual:
        # git pull / docker compose pull on the Kobra Bridge repository.
        return web.json_response(
            {"error": "In-app self-update is disabled in Kobra Bridge. Update from the "
                      "Kobra Bridge repository (git pull or docker compose pull) instead."},
            status=400)

    async def handle_catchall(self, request):
        # Log the unknown route for diagnostics, but never the body: settings
        # POSTs carry the printer password, and this line lands in the log ring
        # buffer that /api/log/download serves. Path only, query stripped.
        log.warning(f"UNBEKANNT {request.method} {request.path}")
        # 404, not 200. Returning `{"result": {}}` for every typo and every
        # wrong-method request made broken clients look healthy - a GET to a
        # POST-only control endpoint "succeeded" with an empty result.
        return web.json_response({"error": "not found"}, status=404)

    async def handle_favicon(self, request):
        # Minimal 1x1 ICO so the browser doesn't log a 404
        ico = bytes([
            0,0,1,0,1,0,1,1,0,0,1,0,24,0,40,0,0,0,22,0,0,0,40,0,0,0,
            1,0,0,0,2,0,0,0,1,0,24,0,0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,255,102,0,0,0,0,0,0
        ])
        return web.Response(body=ico, content_type="image/x-icon")

    # -------------------------------------------------------------------------
    # Klipper G-code script emulation for moonraker-obico
    # -------------------------------------------------------------------------

    async def _exec_gcode_script(self, script: str) -> str:
        """Maps a Klipper or Marlin G-code line to an MQTT command
        for the Kobra X. Supports:
        - PAUSE / M25, RESUME / M24, CANCEL_PRINT / M0/M1/M524/ABORT
        - M104 S<temp>                         → Nozzle-Temperatur
        - M140 S<temp>                         → Bett-Temperatur
        - SET_HEATER_TEMPERATURE HEATER=extruder TARGET=200   (Klipper)
        - SET_HEATER_TEMPERATURE HEATER=heater_bed TARGET=60  (Klipper)
        Unknown scripts are acknowledged with 'ok' (Obico e.g. sends G28
        for homing, which the bridge silently ignores)."""
        if not script:
            return "ok"
        s = script.strip().upper()
        loop = asyncio.get_event_loop()

        def _parse_marlin_temp(line: str) -> int | None:
            """Extract the temperature value from 'M104 S200' or 'M140 S60'."""
            try:
                return int(line.split("S", 1)[1].split()[0])
            except Exception:
                return None

        def _parse_klipper_set_heater(line: str) -> tuple[str | None, int | None]:
            """Extract heater + target from 'SET_HEATER_TEMPERATURE HEATER=extruder TARGET=143'.
            Heater ID + target. Heater is 'extruder' or
            'heater_bed', target is int. Returns (None,None) on error."""
            heater = None
            target = None
            for part in line.split():
                if part.startswith("HEATER="):
                    heater = part.split("=", 1)[1].strip().lower()
                elif part.startswith("TARGET="):
                    try:
                        target = int(float(part.split("=", 1)[1]))
                    except Exception:
                        pass
            return heater, target

        async def _set_temps(nozzle: int | None, bed: int | None):
            """Sets nozzle/bed temperature via the correct MQTT path -
            printing: print/update with taskid, idle: tempature/set with both."""
            if nozzle is not None:
                nozzle = self._bounded(nozzle, "nozzle", int)
            if bed is not None:
                bed = self._bounded(bed, "bed", int)
            is_printing = self._state.get("print_state") in ("printing", "paused")
            if is_printing:
                taskid = self._state.get("taskid", "")
                if nozzle is not None:
                    await loop.run_in_executor(None, lambda: self.client.publish_web(
                        "print", "update",
                        {"taskid": taskid, "settings": {"target_nozzle_temp": int(nozzle)}},
                    ))
                if bed is not None:
                    await loop.run_in_executor(None, lambda: self.client.publish_web(
                        "print", "update",
                        {"taskid": taskid, "settings": {"target_hotbed_temp": int(bed)}},
                    ))
            else:
                # Idle: tempature/set via the web/printer topic with a type field
                # (Live-Sniff 2026-05-29). type: 0=Nozzle, 1=Bed, 2=beide.
                if nozzle is not None and bed is not None:
                    t, n, b = 2, int(nozzle), int(bed)
                elif nozzle is not None:
                    t, n, b = 0, int(nozzle), 0
                elif bed is not None:
                    t, n, b = 1, 0, int(bed)
                else:
                    return
                await loop.run_in_executor(None, lambda: self.client.publish_web(
                    "tempature", "set",
                    {"type": t, "target_nozzle_temp": n, "target_hotbed_temp": b},
                ))

        try:
            if s in ("PAUSE", "M25"):
                await loop.run_in_executor(None, self.client.pause_print)
            elif s in ("RESUME", "M24"):
                await loop.run_in_executor(None, self.client.resume_print)
            elif s in ("CANCEL_PRINT", "M0", "M1", "M524", "ABORT"):
                await loop.run_in_executor(None, self.client.stop_print)
            elif s.startswith("M104 "):
                t = _parse_marlin_temp(s)
                if t is not None:
                    log.info(f"gcode.script: Nozzle-Target {t}°C (M104)")
                    await _set_temps(t, None)
            elif s.startswith("M140 "):
                t = _parse_marlin_temp(s)
                if t is not None:
                    log.info(f"gcode.script: Bed-Target {t}°C (M140)")
                    await _set_temps(None, t)
            elif s.startswith("SET_HEATER_TEMPERATURE"):
                heater, target = _parse_klipper_set_heater(s)
                if target is not None and heater:
                    if heater == "extruder":
                        log.info(f"gcode.script: Nozzle-Target {target}°C (Klipper)")
                        await _set_temps(target, None)
                    elif heater in ("heater_bed", "bed"):
                        log.info(f"gcode.script: Bed-Target {target}°C (Klipper)")
                        await _set_temps(None, target)
                    else:
                        log.debug(f"gcode.script: unbekannter Heater '{heater}' ignoriert")
            else:
                # Unbekanntes Script: stillschweigend OK quittieren.
                log.debug(f"gcode.script ignored: {s[:60]}")
        except ValueError:
            raise
        except Exception as e:
            log.warning(f"gcode.script {s[:30]}: {e}")
        return "ok"

    async def handle_printer_gcode_script(self, request):
        """HTTP POST /printer/gcode/script — Klipper-G-Code-Wrapper (siehe _exec_gcode_script)."""
        script = ""
        if request.method == "POST":
            try:
                body = await request.json()
                if isinstance(body, dict):
                    script = body.get("script", "") or ""
            except Exception:
                pass
        if not script:
            script = request.rel_url.query.get("script", "")
        try:
            result = await self._exec_gcode_script(script)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        return web.json_response({"result": result})

    # -------------------------------------------------------------------------
    # WebSocket handler
    # -------------------------------------------------------------------------

    async def handle_websocket(self, request):
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        ws._loop = asyncio.get_event_loop()
        self.ws_clients.add(ws)
        log.info(f"WS client connected ({len(self.ws_clients)} total)")

        # Send klippy_ready notification
        await ws.send_str(json.dumps({
            "jsonrpc": "2.0",
            "method":  "notify_klippy_ready",
            "params":  [],
        }))
        # Send initial status
        await ws.send_str(json.dumps({
            "jsonrpc": "2.0",
            "method":  "notify_status_update",
            "params":  [self._build_printer_objects(), time.time()],
        }))

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await self._handle_ws_rpc(ws, msg.data)
            elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break

        self.ws_clients.discard(ws)
        log.info(f"WS client disconnected ({len(self.ws_clients)} remaining)")
        return ws

    async def _handle_ws_rpc(self, ws: web.WebSocketResponse, raw: str):
        try:
            req = json.loads(raw)
        except Exception:
            return
        rpc_id = req.get("id")
        method  = req.get("method", "")
        log.info(f"WS RPC: {method}  params={str(req.get('params',''))[:120]}")
        params  = req.get("params") or {}
        if isinstance(params, list):
            params = params[0] if params else {}

        result = None
        error  = None

        try:
            if method in ("printer.info", "printer_info"):
                result = {
                    "state":           "ready",
                    "state_message":   "Printer is ready",
                    "hostname":        "kobrax-bridge",
                    "software_version": KLIPPER_VERSION,
                    "cpu_info":        self._state["printer_name"],
                    "klipper_path":    "/home/pi/klipper",
                    "python_path":     "/home/pi/klippy-env/bin/python",
                }
            elif method in ("server.info", "server_info"):
                result = {
                    "klippy_connected": True,
                    "klippy_state":     "ready",
                    "moonraker_version": MOONRAKER_VERSION,
                    "components":       [],
                    "failed_components": [],
                    "registered_directories": ["gcodes"],
                    "warnings":         [],
                }
            elif method in ("printer.objects.list",):
                result = {"objects": list(self._build_printer_objects().keys())}
            elif method in ("printer.objects.query", "printer.objects.get"):
                objects = params.get("objects", {})
                all_objs = self._build_printer_objects()
                if objects:
                    filtered = {k: all_objs.get(k, {}) for k in objects}
                else:
                    filtered = all_objs
                result = {"status": filtered, "eventtime": time.time()}
            elif method == "printer.objects.subscribe":
                objects = params.get("objects", {})
                all_objs = self._build_printer_objects()
                if objects:
                    filtered = {k: all_objs.get(k, {}) for k in objects}
                else:
                    filtered = all_objs
                result = {"status": filtered, "eventtime": time.time()}
            elif method == "printer.print.start":
                start_body = dict(params) if isinstance(params, dict) else {}
                filename = start_body.get("filename") or self._last_uploaded_file
                if not start_body.get("file_id"):
                    gcode_file = self._store.get_file_by_name(filename) if filename else None
                    if not gcode_file:
                        raise ValueError(f"{filename or 'file'} is not in bridge storage; re-upload for safety validation")
                    start_body["file_id"] = gcode_file["id"]
                response = await self.handle_kx_print(_JsonBodyRequest(start_body))
                body = json.loads(response.body)
                if response.status >= 400:
                    raise ValueError(body.get("error", "print start failed"))
                result = body
            elif method == "printer.print.pause":
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.client.pause_print)
                result = "ok"
            elif method == "printer.print.resume":
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.client.resume_print)
                result = "ok"
            elif method == "printer.print.cancel":
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.client.stop_print)
                result = "ok"
            elif method == "machine.system_info":
                result = {"system_info": {"cpu_info": {"cpu_desc": "Kobra X Bridge"}}}
            elif method == "server.files.list":
                result = []
            # ── moonraker-obico passthru-Targets ──
            elif method == "printer.gcode.script":
                script = (params.get("script") or "").strip().upper() if isinstance(params, dict) else ""
                result = await self._exec_gcode_script(script)
            elif method in ("server.connection.identify",):
                # Obico identifies itself on connect. Connection ID doesn't matter.
                result = {"connection_id": 1}
            elif method == "connection.register_remote_method":
                # Obico registriert obico_remote_event-Callback. Wir akzeptieren leer.
                result = "ok"
            elif method == "server.webcams.list":
                # WS variant: absolute URL with the real LAN IP instead of localhost
                _lip = getattr(self, "_local_ip", None) or "127.0.0.1"
                _base = f"http://{_lip}:{self._args.port}"
                result = {"webcams": [{
                    "name": "Kobra Bridge", "location": "printer", "service": "mjpegstreamer",
                    "enabled": True,
                    "stream_url":   f"{_base}/api/camera/stream",
                    "snapshot_url": f"{_base}/api/camera/snapshot",
                    "flip_horizontal": False, "flip_vertical": False, "rotation": 0,
                    "target_fps": 5, "aspect_ratio": "16:9",
                }]}
            elif method == "server.history.list":
                # Reuse the HTTP handler logic (Moonraker schema with Unix TS).
                try:
                    jobs = self._store.list_jobs(limit=50) or []
                except Exception:
                    jobs = []
                from datetime import datetime, timezone as _tz
                def _ts(iso):
                    try:
                        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_tz.utc).timestamp()
                    except Exception:
                        return 0.0
                result = {"count": len(jobs), "jobs": [
                    {"job_id": j.get("id"), "exists": True, "filename": j.get("filename",""),
                     "status": j.get("status") or "completed",
                     "print_duration": j.get("duration_sec") or 0,
                     "total_duration": j.get("duration_sec") or 0,
                     "start_time": _ts(j.get("started_at")),
                     "end_time":   (_ts(j.get("started_at")) + (j.get("duration_sec") or 0)) if j.get("started_at") and j.get("duration_sec") else None,
                     "filament_used": 0.0, "metadata": {}}
                    for j in jobs
                ]}
            elif method == "machine.update.status":
                result = {"busy": False, "version_info": {}}
            elif method == "server.files.metadata":
                # Obico + Mobileraker request metadata for a file. Same
                # logic as the HTTP endpoint (previously a separate broken path with
                # a non-existent store method -> empty response ->
                # Mobileraker-Endlosschleife, Issue #48).
                fname = (params or {}).get("filename") if isinstance(params, dict) else None
                fname = fname or self._state.get("filename", "")
                result = self._build_file_metadata(fname) if fname else {}
            else:
                log.debug(f"Unbekannte RPC-Methode: {method}")
                result = {}
        except Exception as e:
            log.error(f"RPC error for {method}: {e}")
            error = {"code": -32603, "message": str(e)}

        if rpc_id is not None:
            response = {"jsonrpc": "2.0", "id": rpc_id}
            if error:
                response["error"] = error
            else:
                response["result"] = result
            await ws.send_str(json.dumps(response))

    # -------------------------------------------------------------------------
    # Poll loop (sync, runs in executor)
    # -------------------------------------------------------------------------

    def _printer_reachable(self) -> bool:
        """TCP probe on the MQTT port - no ICMP needed, no root required."""
        import socket as _socket
        try:
            with _socket.create_connection(
                (self._args.printer_ip, self._args.mqtt_port), timeout=2.0
            ):
                return True
        except OSError:
            return False

    def _poll_loop(self, stop_event: threading.Event):
        _offline = self._state["kobra_state"] == "offline"
        _probe_interval = 10.0   # Sekunden zwischen TCP-Probes im Offline-Modus
        _last_busy_info = 0.0
        _last_busy_box = 0.0
        _last_busy_print = 0.0
        # An idle printer has nothing to report, but it is the same weak
        # single-core host that must stay responsive when a job starts. Poll it
        # on a slow cadence and let the printer's own pushed reports (info/
        # print/tempature on the subscribed topic) carry any state change.
        # ponytail: fixed 60s idle cadence; make it configurable only if an
        # operator actually wants faster idle updates.
        _idle_interval = max(getattr(self._args, "poll_interval", 3), 60.0)
        _last_idle_poll = 0.0

        while not stop_event.is_set():
            # One timestamp per iteration keeps poll cadence deterministic and
            # doubles as liveness for /health.
            now = time.time()
            self._state["poll_heartbeat"] = now
            # ── Offline-Modus: warten bis Drucker wieder erreichbar ──────────
            if _offline:
                if self._printer_reachable():
                    log.info("Printer reachable - establishing MQTT connection...")
                    try:
                        self.client.connect()
                        _offline = False
                        self._state["print_state"] = "standby"
                        self._state["kobra_state"] = "free"
                        self._state["connection_error"] = ""
                        log.info("MQTT connection re-established")
                    except Exception as e:
                        err = _mqtt_error_msg(e)
                        self._state["connection_error"] = err
                        log.warning(f"Connection attempt failed: {err}")
                        stop_event.wait(_probe_interval)
                        continue
                else:
                    stop_event.wait(_probe_interval)
                    continue

            # ── Online-Modus: normaler Poll ──────────────────────────────────
            try:
                busy = self._state["print_state"] in (
                    "printing", "paused", "preheating", "auto_leveling", "checking", "init")
                # Idle: skip this tick entirely until the slow cadence is due.
                # The MQTT subscription still delivers pushed reports, so a job
                # started from the printer's own screen is still noticed.
                if not busy and now - _last_idle_poll < _idle_interval:
                    stop_event.wait(getattr(self._args, "poll_interval", 3))
                    continue
                if not busy:
                    _last_idle_poll = now
                # During a print, print/query is the essential source. info/query
                # and multiColorBox parsing are reduced to once/minute to avoid
                # competing with GoKlipper's motion/MCU feed on the single core.
                if not busy or now - _last_busy_info >= 60.0:
                    info = self.client.query_info()
                    if info:
                        self._on_info(info)
                    if busy:
                        _last_busy_info = now
                # While printing: query print/report directly. The printer also
                # pushes print/report on its own, so an explicit query every
                # tick is redundant work on the busiest host; 30s is enough to
                # cover a missed push without competing with the motion feed.
                # ponytail: fixed 30s floor, tune only if progress feels stale.
                if busy and now - _last_busy_print >= 30.0:
                    _last_busy_print = now
                    print_r = self.client.publish("print", "query", timeout=3.0)
                    if print_r:
                        self._on_print(print_r)
                if busy:
                    # Spoolman mid-print sync
                    if (self._spoolman and self._spoolman.sync_rate > 0
                            and self._spoolman_slot_spools
                            and self._state.get("print_state") == "printing"):
                        now = time.time()
                        if now - self._spoolman_last_sync >= self._spoolman.sync_rate:
                            self._spoolman_sync_midprint()
                            self._spoolman_last_sync = now
                box = None
                if not busy or now - _last_busy_box >= 60.0:
                    box = self.client.query_multicolor_box()
                    if busy:
                        _last_busy_box = now
                if box:
                    data = box.get("data") or {}
                    self._head_tools_model = int(data.get("head_tools_model", self._head_tools_model))
                    boxes = data.get("multi_color_box") or []
                    if boxes:
                        self._update_ace_drying_state(data, boxes)
                        self._filament_mode = self._detect_filament_mode(boxes, self._head_tools_model)
                        self._state["filament_mode"] = self._filament_mode
                        global_slots, global_loaded = self._aggregate_slots(boxes, self._filament_mode)
                        activity_map = self._slot_activity_map(boxes, global_loaded)
                        for s in global_slots:
                            s["activity"] = activity_map.get(s.get("global_index"), "")
                        if global_slots:
                            self._ams_slots = global_slots
                        self._ams_loaded_slot = global_loaded
                        self._spoolman_attribute_tick(activity_map)
                    else:
                        # No multiColorBox data — still attribute (no transitions to skip)
                        self._spoolman_attribute_tick({})
                # Recheck Spoolman reachability periodically so the UI status
                # dot reflects the current state, not just the boot-time result.
                if self._spoolman and time.time() - self._spoolman_last_health_check >= 30.0:
                    self._spoolman_reachable = self._spoolman.health_check()
                    self._spoolman_last_health_check = time.time()
            except Exception as e:
                log.warning(f"Poll error: {e}")
                # Check whether the printer is really gone
                if not self._printer_reachable():
                    log.info("Printer unreachable - switching to offline mode")
                    self._state["print_state"] = "error"
                    self._state["kobra_state"] = "offline"
                    self._state["connection_error"] = f"Printer unreachable ({self._args.printer_ip})"
                    try:
                        self.client.disconnect()
                    except Exception:
                        pass
                    _offline = True
            stop_event.wait(getattr(self._args, "poll_interval", 3))


# ---------------------------------------------------------------------------
# App factory + main
# ---------------------------------------------------------------------------

def _mqtt_error_msg(exc: Exception) -> str:
    msg = str(exc)
    if "20020005" in msg:
        return "Wrong MQTT credentials (username, password or device ID incorrect)"
    return msg


def _cors_origin_for(request) -> str:
    """Echo the Origin only when it is another bridge instance on this host.

    The bridge has no authentication, so `Access-Control-Allow-Origin: *` let
    ANY website an operator happened to visit read printer state and fire
    state-changing requests cross-origin (start/cancel prints, move axes, set
    temperatures) at every LAN address it could guess.

    The farm UI genuinely is cross-origin - printer 3 on :7127 talks to :7128 -
    so the fix is same-host, any-port rather than a blanket deny. Requests with
    no Origin header (OrcaSlicer, curl, moonraker-obico) are unaffected: the
    browser only enforces CORS on browser-issued cross-origin requests.

    ponytail: origin reflection, not auth. It stops the drive-by-website class,
    not a hostile device already on the LAN. Real auth needs a token that
    OrcaSlicer/obico can carry too - separate change.
    """
    origin = request.headers.get("Origin", "")
    if not origin:
        return ""
    try:
        host = urlsplit(origin).hostname
    except ValueError:
        return ""
    if host and host == request.url.host:
        return origin
    return ""


@web.middleware
async def cors_middleware(request, handler):
    allow = _cors_origin_for(request)
    # CORS headers alone are not authorization: without this early rejection a
    # hostile website could submit a no-cors form to /printer/print/cancel or
    # /api/restart. The browser hides the response but still executes the action.
    # No-Origin clients (OrcaSlicer, curl, Obico) remain compatible.
    mutating = request.method in ("POST", "PUT", "PATCH", "DELETE") or request.path == "/websocket"
    if mutating and request.headers.get("Origin") and not allow:
        return web.Response(status=403, text="cross-origin request denied")
    if request.method == "OPTIONS":
        headers = {
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Vary": "Origin",
        }
        if allow:
            headers["Access-Control-Allow-Origin"] = allow
        return web.Response(status=204, headers=headers)
    resp = await handler(request)
    # Vary: Origin so a shared cache never serves one origin's allowance to
    # another; drop any wildcard a handler set for itself.
    resp.headers["Vary"] = "Origin"
    if allow:
        resp.headers["Access-Control-Allow-Origin"] = allow
    elif resp.headers.get("Access-Control-Allow-Origin") == "*":
        del resp.headers["Access-Control-Allow-Origin"]
    return resp


def build_app(bridge: KobraXBridge) -> web.Application:
    app = web.Application(
        # ponytail: whole body is buffered in RAM by handle_file_upload
        # (part.read()); NAS has ~4 GB. Stream to disk before raising past 1 GiB.
        client_max_size=1024 * 1024 * 1024,
        middlewares=[cors_middleware],
    )
    r = app.router

    # Moonraker API
    r.add_get("/server/info",                bridge.handle_server_info)
    r.add_get("/health",                     bridge.handle_health)
    r.add_get("/printer/info",               bridge.handle_printer_info)
    r.add_get("/machine/system_info",        bridge.handle_machine_system_info)
    r.add_get("/printer/objects/list",       bridge.handle_objects_list)
    r.add_get("/printer/objects/query",      bridge.handle_objects_query)
    r.add_get("/printer/objects/subscribe",  bridge.handle_objects_subscribe)
    r.add_post("/printer/objects/subscribe", bridge.handle_objects_subscribe)
    r.add_get("/server/files/list",          bridge.handle_files_list)
    r.add_get("/server/files/metadata",      bridge.handle_files_metadata)
    r.add_post("/server/files/upload",       bridge.handle_file_upload)
    r.add_post("/printer/print/start",       bridge.handle_print_start)
    r.add_post("/printer/print/pause",       bridge.handle_print_pause)
    r.add_post("/printer/print/resume",      bridge.handle_print_resume)
    r.add_post("/printer/print/cancel",      bridge.handle_print_cancel)

    # Moonraker stubs for moonraker-obico
    r.add_get("/access/api_key",             bridge.handle_access_api_key)
    r.add_get("/machine/update/status",      bridge.handle_machine_update_status)
    r.add_get("/server/history/list",        bridge.handle_history_list)
    r.add_get("/server/webcams/list",        bridge.handle_webcams_list)
    r.add_post("/printer/gcode/script",      bridge.handle_printer_gcode_script)

    # OctoPrint compatibility (OrcaSlicer probes this + uploads here)
    r.add_get("/api/version",                bridge.handle_octoprint_version)
    r.add_post("/api/files/local",           bridge.handle_file_upload)
    r.add_post("/api/files/{path:.*}",       bridge.handle_file_upload)

    # Moonraker database (OrcaSlicer AMS-Sync)
    r.add_get("/server/database/item",       bridge.handle_moonraker_database)
    r.add_post("/server/database/item",      bridge.handle_moonraker_database_post)
    r.add_get("/server/database/list",       bridge.handle_database_list)

    # New API endpoints
    r.add_post("/api/light",               bridge.handle_api_light)
    r.add_post("/api/fan",                 bridge.handle_api_fan)
    r.add_post("/api/connect",             bridge.handle_api_connect)
    r.add_post("/api/disconnect",          bridge.handle_api_disconnect)
    r.add_post("/api/restart",             bridge.handle_api_restart)
    r.add_post("/api/speed",               bridge.handle_api_speed)
    r.add_post("/api/ams/feed",            bridge.handle_api_ams_feed)
    r.add_post("/api/ams/set_slot",        bridge.handle_api_ams_set_slot)
    r.add_post("/api/ace/auto_feed",        bridge.handle_api_ace_auto_feed)
    r.add_post("/api/ace/dry",             bridge.handle_api_ace_dry)
    r.add_post("/api/axis",                bridge.handle_api_axis)
    r.add_post("/api/temperature",         bridge.handle_api_temperature)
    r.add_get("/api/camera",               bridge.handle_api_camera)
    r.add_get("/api/camera/stream",        bridge.handle_camera_stream)
    r.add_get("/api/camera/h264",          bridge.handle_camera_h264)
    r.add_get("/api/camera/snapshot",      bridge.handle_api_camera_snapshot)
    r.add_post("/api/camera/start",        bridge.handle_api_camera_start)
    r.add_post("/api/camera/stop",         bridge.handle_api_camera_stop)
    r.add_post("/api/camera/reset",        bridge.handle_api_camera_reset)
    r.add_get("/api/state",                bridge.handle_api_state)
    r.add_get("/api/settings",             bridge.handle_api_settings_get)
    r.add_post("/api/settings",            bridge.handle_api_settings_post)
    r.add_get("/api/update/check",         bridge.handle_api_update_check)
    r.add_post("/api/update/apply",        bridge.handle_api_update_apply)
    r.add_post("/api/file_ready/clear",    bridge.handle_api_file_ready_clear)
    r.add_get("/api/log/stream",           bridge.handle_api_log_stream)
    r.add_get("/api/log/download",         bridge.handle_api_log_download)
    r.add_get("/serve/{filename}",         bridge.handle_serve_file)
    # /kx/ GCode Store + History + Filament
    r.add_get("/kx/printers",              bridge.handle_kx_printers)
    r.add_get("/kx/farm/overview",         bridge.handle_kx_farm_overview)
    r.add_get("/kx/farm/stats",            bridge.handle_kx_farm_stats)
    r.add_get("/kx/maintenance",           bridge.handle_kx_maintenance_get)
    r.add_post("/kx/maintenance",          bridge.handle_kx_maintenance_post)
    r.add_post("/kx/printers/add",         bridge.handle_kx_printer_add)
    r.add_delete("/kx/printers/{pid}",     bridge.handle_kx_printer_remove)
    r.add_post("/kx/print",               bridge.handle_kx_print)
    r.add_post("/kx/upload-local",        bridge.handle_kx_upload_local)
    r.add_get("/kx/files",                bridge.handle_kx_files)
    r.add_delete("/kx/files/{file_id}",    bridge.handle_kx_file_delete)
    r.add_get("/kx/files/{file_id}/compatibility", bridge.handle_kx_file_compatibility)
    r.add_get("/kx/files/{file_id}/compatibility/progress", bridge.handle_kx_file_compatibility_progress)
    r.add_get("/kx/files/{file_id}/download", bridge.handle_kx_file_download)
    r.add_get("/kx/files/{file_id}/thumbnail", bridge.handle_kx_file_thumbnail)
    r.add_post("/kx/files/{file_id}/verify", bridge.handle_kx_file_verify)
    r.add_get("/kx/printer-files",         bridge.handle_kx_printer_files)
    r.add_post("/kx/printer-files/start",  bridge.handle_kx_printer_file_start)
    r.add_post("/kx/printer-files/delete", bridge.handle_kx_printer_file_delete)
    r.add_get("/kx/printer-files/{filename}/thumbnail", bridge.handle_kx_printer_file_thumbnail)
    r.add_get("/kx/filament/slots",        bridge.handle_kx_filament_slots)
    r.add_get("/kx/filament/profiles",     bridge.handle_kx_filament_profiles)
    r.add_post("/kx/filament/slots/{idx}/profile", bridge.handle_kx_filament_slot_profile)
    r.add_get("/kx/filament/visible_vendors",  bridge.handle_kx_visible_vendors)
    r.add_post("/kx/filament/visible_vendors", bridge.handle_kx_visible_vendors)
    # Custom profile import (Issue #41) - the user uploads their own Orca filament
    # profiles as ZIP/JSON (e.g. from ~/.config/OrcaSlicer/user/<id>/filament/),
    # because the bridge typically does not run on the same host as OrcaSlicer.
    r.add_get("/kx/filament/profiles/user",    bridge.handle_kx_filament_profiles_user_list)
    r.add_post("/kx/filament/profiles/user",   bridge.handle_kx_filament_profiles_import)
    r.add_delete("/kx/filament/profiles/user", bridge.handle_kx_filament_profiles_user_delete)
    r.add_get("/kx/history",               bridge.handle_kx_history)
    r.add_get("/kx/ui/{name:.*}",          bridge.handle_kx_ui_asset)
    r.add_get("/kx/files/{id}/objects",    bridge.handle_kx_file_objects)
    r.add_post("/kx/skip",                 bridge.handle_kx_skip)
    r.add_post("/kx/skip/query",           bridge.handle_kx_skip_query)
    r.add_get("/kx/skip/state",            bridge.handle_kx_skip_state)
    r.add_get("/kx/spoolman/status",       bridge.handle_kx_spoolman_status)
    r.add_get("/kx/spoolman/spools",       bridge.handle_kx_spoolman_spools)
    r.add_post("/kx/spoolman/active-spool", bridge.handle_kx_spoolman_set_active)
    r.add_route("OPTIONS", "/kx/{path:.*}", bridge.handle_kx_options)

    # Root + Printer-Routen (Single-Page, JS liest Pathname)
    r.add_get("/closed",                      bridge.handle_closed)
    r.add_get("/",                           bridge.handle_index)
    r.add_get(r"/printer{num:\d+}",          bridge.handle_index)
    r.add_get("/favicon.ico",               bridge.handle_favicon)

    # WebSocket
    r.add_get("/websocket",                  bridge.handle_websocket)

    # Catch-all: log all unknown requests instead of 404
    r.add_route("*", "/{path:.*}",           bridge.handle_catchall)

    return app


def _build_per_printer_args(base_args, p: dict):
    """Copy CLI args, override with the printer entry from config.ini."""
    import copy
    a = copy.copy(base_args)
    a.printer_ip = p.get("printer_ip") or base_args.printer_ip
    a.mqtt_port  = int(p.get("mqtt_port") or base_args.mqtt_port)
    a.username   = p.get("username")  or base_args.username
    a.password   = p.get("password")  or base_args.password
    a.mode_id    = p.get("mode_id")   or base_args.mode_id
    a.model_id   = p.get("model_id")  or a.mode_id
    a.device_id  = p.get("device_id") or base_args.device_id
    a.port       = int(p.get("http_port") or base_args.port)
    if p.get("nozzle_diameter"):
        a.nozzle_diameter = float(p["nozzle_diameter"])
    return a


async def run_bridge(args):
    _set_verbose_http_log(bool(getattr(args, "verbose_http_log", 0)))
    printers = env_loader.list_printers()
    multi_mode = bool(printers)
    if not printers:
        printers = [{
            "id":         "1",
            "name":       getattr(args, "printer_name", None) or "Anycubic Kobra X",
            "printer_ip": args.printer_ip,
            "mqtt_port":  args.mqtt_port,
            "username":   args.username,
            "password":   args.password,
            "mode_id":    args.mode_id,
            "device_id":  args.device_id,
            "http_port":  args.port,
        }]

    store = GCodeStore(args.data_dir)
    all_bridges: dict = {}
    runners = []
    stop_event = threading.Event()
    loop = asyncio.get_event_loop()

    for idx, p in enumerate(printers):
        pid = str(p.get("id") or (idx + 1))
        per_args = _build_per_printer_args(args, p)
        # Default port convention: 7125 + (id-1) when no http_port is set
        if not p.get("http_port") and multi_mode:
            try:
                per_args.port = 7125 + (int(pid) - 1)
            except ValueError:
                per_args.port = 7125 + idx

        client = KobraXClient(
            host=per_args.printer_ip,
            port=per_args.mqtt_port,
            username=per_args.username,
            password=per_args.password,
            mode_id=per_args.mode_id,
            device_id=per_args.device_id,
            client_id=f"kobrax_bridge_{pid}",
        )
        bridge = KobraXBridge(
            client, args=per_args, store=store,
            printer_id=pid, all_bridges=all_bridges,
        )
        # Adopt printer_name from config.ini if set
        if p.get("name"):
            bridge._state["printer_name"] = p["name"]
            bridge._name_locked = True
        all_bridges[pid] = bridge

        log.info(f"[Printer {pid}] Connecting to {per_args.printer_ip}:{per_args.mqtt_port}...")
        try:
            await loop.run_in_executor(None, client.connect)
            log.info(f"[Printer {pid}] MQTT connected")
        except Exception as e:
            err = _mqtt_error_msg(e)
            log.warning(f"[Printer {pid}] Connection failed: {err} - offline mode")
            bridge._state["print_state"] = "error"
            bridge._state["kobra_state"] = "offline"
            bridge._state["connection_error"] = err

        threading.Thread(
            target=bridge._poll_loop, args=(stop_event,),
            daemon=True, name=f"poll-{pid}",
        ).start()

        app = build_app(bridge)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, args.host, per_args.port)
        await site.start()
        runners.append((runner, client, pid))

    import socket as _socket
    _in_docker = os.path.exists("/.dockerenv")
    _host_ip_override = env_loader.BRIDGE_HOST_IP.strip()
    if _host_ip_override:
        _local_ip = _host_ip_override
    else:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
                _s.connect(("8.8.8.8", 80))
                _local_ip = _s.getsockname()[0]
        except Exception:
            _local_ip = args.host
    # Propagate to all bridge instances - used for absolute webcam URLs
    for _b in all_bridges.values():
        _b._local_ip = _local_ip
    ports = ", ".join(str(getattr(b._args, 'port', 0)) for b in all_bridges.values())
    if _in_docker and not _host_ip_override:
        # In a container the UDP trick only yields the Docker-internal IP - don't show it
        log.info(f"OrcaSlicer → Klipper → http://<IP of this Docker host>:{ports}")
        log.info("Running in Docker — set BRIDGE_HOST_IP to show the exact address")
    else:
        log.info(f"OrcaSlicer → Klipper → http://{_local_ip}:{ports}")
    log.info("Press Ctrl-C to stop")

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        stop_event.set()
        for runner, client, pid in runners:
            try:
                await runner.cleanup()
            except Exception:
                pass
            try:
                client.disconnect()
            except Exception:
                pass
        log.info("Bridge stopped")


def _default_data_dir() -> str:
    """Persistenz-Verzeichnis: Docker setzt KX_DATA_DIR, Binary nutzt <exe-dir>/data,
    Dev script uses <repo>/data (or /app/data if present)."""
    if os.environ.get("KX_DATA_DIR"):
        return os.environ["KX_DATA_DIR"]
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "data")
    if os.path.isdir("/app"):
        return "/app/data"
    return os.path.normpath(os.path.join(_BASE, "..", "data"))


def main():
    parser = argparse.ArgumentParser(description="Moonraker bridge for the Anycubic Kobra X")
    parser.add_argument("--printer-ip",  default=env_loader.PRINTER_IP,
                        help="IP-Adresse des Druckers")
    parser.add_argument("--mqtt-port",   type=int, default=env_loader.MQTT_PORT)
    parser.add_argument("--username",    default=env_loader.USERNAME)
    parser.add_argument("--password",    default=env_loader.PASSWORD)
    parser.add_argument("--mode-id",     default=env_loader.MODE_ID)
    parser.add_argument("--device-id",       default=env_loader.DEVICE_ID)
    parser.add_argument("--default-ams-slot",default=env_loader.DEFAULT_AMS_SLOT)
    parser.add_argument("--auto-leveling",           type=int, default=env_loader.AUTO_LEVELING)
    parser.add_argument("--vibration-compensation",  type=int, default=env_loader.VIBRATION_COMPENSATION)
    parser.add_argument("--camera-on-print",         type=int, default=env_loader.CAMERA_ON_PRINT)
    parser.add_argument("--web-upload-warning", type=int, default=env_loader.WEB_UPLOAD_WARNING)
    parser.add_argument("--print-start-dialog", dest="print_start_dialog", type=int, default=env_loader.PRINT_START_DIALOG)
    parser.add_argument("--file-ready-dialog",  dest="print_start_dialog", type=int)
    parser.add_argument("--spoolman-server",    default=env_loader.SPOOLMAN_SERVER,
                        help="Spoolman URL (e.g. http://192.168.x.x:7912); leave empty to disable")
    parser.add_argument("--spoolman-sync-rate", type=int, default=env_loader.SPOOLMAN_SYNC_RATE,
                        help="Mid-print filament sync interval in seconds (0 = only on print end)")
    parser.add_argument("--poll-interval", type=int, default=env_loader.POLL_INTERVAL,
                        help="Printer poll interval in seconds")
    parser.add_argument("--verbose-http-log", type=int, default=env_loader.VERBOSE_HTTP_LOG,
                        help="Log every HTTP request (aiohttp access log)")
    parser.add_argument("--nozzle-diameter", type=float, default=env_loader.NOZZLE_DIAMETER,
                        help="Mounted nozzle diameter in mm; G-code sliced for a "
                             "different nozzle is blocked")

    parser.add_argument("--host",            default="0.0.0.0",
                        help="Bind address for the bridge server")
    parser.add_argument("--port",        type=int, default=7125,
                        help="HTTP/WS-Port (Moonraker-Standard: 7125)")
    parser.add_argument("--data-dir",    default=_default_data_dir(),
                        help="Persistence directory for the GCode store and DB")
    parser.add_argument(
        "--ui-theme",
        default=os.environ.get("KX_UI_THEME", "default"),
        metavar="NAME",
        help="Web-UI-Theme (Ordner web/themes/NAME/, Standard: default). "
        "Alternativ: Umgebungsvariable KX_UI_THEME.",
    )
    args = parser.parse_args()
    if args.printer_ip and ":" in args.printer_ip:
        args.printer_ip = args.printer_ip.split(":")[0]

    # Windows needs ProactorEventLoop for asyncio.create_subprocess_exec
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    asyncio.run(run_bridge(args))


if __name__ == "__main__":
    main()
