"""
config_loader.py - loads connection parameters from config/config.ini (primary)
or .env (fallback / migration).
Environment variables always take precedence.
"""
import os
import sys
import pathlib
import configparser
from typing import Optional

_BASE = pathlib.Path(sys.executable).parent if getattr(sys, "frozen", False) else pathlib.Path(__file__).parent

CONFIG_SECTION_CONNECTION = "connection"
CONFIG_SECTION_PRINT      = "print"
CONFIG_SECTION_BRIDGE     = "bridge"
CONFIG_SECTION_SPOOLMAN   = "spoolman"


def _find_config_file() -> pathlib.Path | None:
    for base in (_BASE, _BASE.parent):
        p = base / "config" / "config.ini"
        if p.is_file():
            return p
    return None


def _find_env_file() -> pathlib.Path | None:
    for base in (_BASE, _BASE.parent):
        p = base / ".env"
        if p.is_file():
            return p
    return None


def _load_env_file(path: pathlib.Path):
    """Loads the .env file as a fallback - only sets keys not yet in os.environ."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key and key not in os.environ:
                os.environ[key] = val


# Single source of truth for env-var <-> config.ini mapping. _restart_bridge()
# in kobrax_moonraker_bridge.py clears exactly these keys from os.environ
# before restarting, so a value removed here or in the UI settings save can
# never survive as a stale env var read by the new process. Add new settings
# here ONLY - no second list to keep in sync.
CONFIG_ENV_MAPPING = {
    "PRINTER_IP":       (CONFIG_SECTION_CONNECTION, "printer_ip"),
    "MQTT_PORT":        (CONFIG_SECTION_CONNECTION, "mqtt_port"),
    "MQTT_USERNAME":    (CONFIG_SECTION_CONNECTION, "username"),
    "MQTT_PASSWORD":    (CONFIG_SECTION_CONNECTION, "password"),
    "MODE_ID":          (CONFIG_SECTION_CONNECTION, "mode_id"),
    "DEVICE_ID":        (CONFIG_SECTION_CONNECTION, "device_id"),
    "DEFAULT_AMS_SLOT":     (CONFIG_SECTION_PRINT,   "default_ams_slot"),
    "AUTO_LEVELING":            (CONFIG_SECTION_PRINT,   "auto_leveling"),
    "VIBRATION_COMPENSATION":   (CONFIG_SECTION_PRINT,   "vibration_compensation"),
    "CAMERA_ON_PRINT":          (CONFIG_SECTION_PRINT,   "camera_on_print"),
    "WEB_UPLOAD_WARNING":   (CONFIG_SECTION_PRINT,   "web_upload_warning"),
    "PRINT_START_DIALOG":   (CONFIG_SECTION_PRINT,   "print_start_dialog"),
    "NOZZLE_DIAMETER":      (CONFIG_SECTION_PRINT,   "nozzle_diameter"),
    "BRIDGE_PRINTER_NAME":  (CONFIG_SECTION_BRIDGE,  "printer_name"),
    "BRIDGE_HOST_IP":       (CONFIG_SECTION_BRIDGE,  "host_ip"),
    "POLL_INTERVAL":        (CONFIG_SECTION_BRIDGE,  "poll_interval"),
    "VERBOSE_HTTP_LOG":     (CONFIG_SECTION_BRIDGE,  "verbose_http_log"),
    "SPOOLMAN_SERVER":      (CONFIG_SECTION_SPOOLMAN, "server"),
    "SPOOLMAN_SYNC_RATE":   (CONFIG_SECTION_SPOOLMAN, "sync_rate"),
}


def _load_config_file(path: pathlib.Path):
    """Loads config.ini and sets keys in os.environ (only if not already set)."""
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")

    for env_key, (section, option) in CONFIG_ENV_MAPPING.items():
        if env_key not in os.environ:
            try:
                val = cfg.get(section, option)
                if val:
                    os.environ[env_key] = val
            except (configparser.NoSectionError, configparser.NoOptionError):
                pass


    # Backward compatibility: old key FILE_READY_DIALOG → PRINT_START_DIALOG
    if "PRINT_START_DIALOG" not in os.environ:
        try:
            legacy = cfg.get(CONFIG_SECTION_PRINT, "file_ready_dialog")
            if legacy:
                os.environ["PRINT_START_DIALOG"] = legacy
        except (configparser.NoSectionError, configparser.NoOptionError):
            pass
    if "PRINT_START_DIALOG" not in os.environ and "FILE_READY_DIALOG" in os.environ:
        os.environ["PRINT_START_DIALOG"] = os.environ["FILE_READY_DIALOG"]


def migrate_env_to_config(env_path: pathlib.Path, config_path: pathlib.Path):
    """Einmalige Migration: .env → config.ini anlegen."""
    env_vals: dict[str, str] = {}
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env_vals[k.strip()] = v.strip()

    config_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg[CONFIG_SECTION_CONNECTION] = {
        "printer_ip": env_vals.get("PRINTER_IP", ""),
        "mqtt_port":  env_vals.get("MQTT_PORT",  "9883"),
        "username":   env_vals.get("MQTT_USERNAME", ""),
        "password":   env_vals.get("MQTT_PASSWORD", ""),
        "mode_id":    env_vals.get("MODE_ID",    ""),
        "device_id":  env_vals.get("DEVICE_ID",  ""),
    }
    cfg[CONFIG_SECTION_PRINT] = {
        "default_ams_slot": env_vals.get("DEFAULT_AMS_SLOT", "auto"),
        "auto_leveling":          env_vals.get("AUTO_LEVELING",           "1"),
        "vibration_compensation": env_vals.get("VIBRATION_COMPENSATION",  "0"),
        "camera_on_print":        env_vals.get("CAMERA_ON_PRINT",         "0"),
        "web_upload_warning": env_vals.get("WEB_UPLOAD_WARNING", "1"),
    }
    cfg[CONFIG_SECTION_BRIDGE] = {
        "poll_interval": "3",
    }
    with open(config_path, "w", encoding="utf-8") as f:
        f.write("# KX-Bridge Konfigurationsdatei\n")
        f.write("# Automatically migrated from .env\n\n")
        cfg.write(f)


def find_config_path() -> pathlib.Path:
    """Returns the path to config.ini (even if it does not exist yet)."""
    for base in (_BASE, _BASE.parent):
        config_dir = base / "config"
        if config_dir.is_dir():
            return config_dir / "config.ini"
    return _BASE / "config" / "config.ini"


# ─── Laden ───────────────────────────────────────────────────────────────────

_config_path = _find_config_file()
_env_path    = _find_env_file()

if _config_path:
    _load_config_file(_config_path)
elif _env_path:
    # No config.ini present -> migrate from .env
    _target = find_config_path()
    migrate_env_to_config(_env_path, _target)
    _load_config_file(_target)
    _config_path = _target


def list_printers() -> list[dict]:
    """Reads all [printer_N] sections from config.ini.

    Each section may contain the following keys:
      name, printer_ip, mqtt_port, username, password, mode_id, device_id,
      bridge_url, default_ams_slot, auto_leveling, nozzle_diameter

    Returns an empty list when no [printer_N] sections exist
    (Single-Printer-Betrieb via [connection]).
    """
    path = _find_config_file()
    if not path:
        return []
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    printers: list[dict] = []
    idx = 1
    while True:
        section = f"printer_{idx}"
        if not cfg.has_section(section):
            break
        p = dict(cfg[section])
        p.setdefault("id", str(idx))
        if "mqtt_port" in p:
            try:
                p["mqtt_port"] = int(p["mqtt_port"])
            except ValueError:
                p["mqtt_port"] = 9883
        printers.append(p)
        idx += 1
    return printers


def _filament_section(printer_id: Optional[str] = None) -> str:
    """Section name holding a printer's filament-profile mapping.

    Multi-printer (one bridge, N printers): each printer keeps its own
    ``[filament_profiles_<id>]`` section so the mappings cannot overwrite each
    other. ``printer_id is None`` (single-printer / legacy callers) maps to the
    original global ``[filament_profiles]`` section — full backward compatibility.
    """
    pid = str(printer_id).strip() if printer_id is not None else ""
    if pid and pid != "0":
        return f"filament_profiles_{pid}"
    return "filament_profiles"


def list_filament_profiles(printer_id: Optional[str] = None) -> dict[int, dict]:
    """Reads the [filament_profiles] section from config.ini.

    With ``printer_id`` set, reads the per-printer ``[filament_profiles_<id>]``
    section and falls back to the legacy global ``[filament_profiles]`` while
    that printer has no own section yet.

    Format per AMS slot - the primary selector is (vendor, name); the `id` is
    looked up from orca_filaments.json on save and carried along
    (as a hint for OrcaSlicer; the Orca data model has ~136 profiles sharing
    the same filament_id like 'OGFL99', i.e. the ID is not unique):

      [filament_profiles]
      slot_0_vendor = Polymaker
      slot_0_name   = PolyTerra PLA
      slot_0_id     = OGFL01

    Returns a dict {slot_index: {"id": ..., "vendor": ..., "name": ...}}.
    Empty/missing slots are NOT included - the default mapping
    (per filament_type) in the bridge then stays active.

    Backwards compat: old configs with only (vendor, id) stay readable; `name`
    is then missing and the caller can optionally resolve it from orca_filaments.json
    rekonstruieren.
    """
    path = _find_config_file()
    if not path:
        return {}
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    section = _filament_section(printer_id)
    if not cfg.has_section(section):
        section = "filament_profiles"          # fallback: legacy global section
    if not cfg.has_section(section):
        return {}
    result: dict[int, dict] = {}
    for key, value in cfg.items(section):
        # Expects: slot_<idx>_id or slot_<idx>_vendor or slot_<idx>_name
        if not key.startswith("slot_"):
            continue
        parts = key.split("_", 2)
        if len(parts) < 3:
            continue
        try:
            slot_idx = int(parts[1])
        except ValueError:
            continue
        field = parts[2]
        if field not in ("id", "vendor", "name"):
            continue
        if not value.strip():
            continue
        result.setdefault(slot_idx, {})[field] = value.strip()
    return result


def save_filament_profiles(profiles: dict[int, dict], printer_id: Optional[str] = None) -> bool:
    """Writes the given slot profiles into the [filament_profiles]
    section of config.ini. Existing entries are completely replaced.

    profiles: {slot_index: {"id": "OGFL01", "vendor": "Polymaker", "name": "PolyTerra PLA"}}
    At least vendor+name must be set; id is optional (hint).

    With ``printer_id`` set, writes the per-printer ``[filament_profiles_<id>]``
    section only — other printers and the legacy global section are untouched.
    """
    path = _find_config_file()
    if not path:
        return False
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    section = _filament_section(printer_id)
    # visible_vendors (Issue #41) is not a slot mapping - preserve it when
    # replacing the section, otherwise the vendor filter is lost on slot save.
    # First save of a per-printer section inherits the legacy global filter.
    preserved_vendors = None
    if cfg.has_option(section, "visible_vendors"):
        preserved_vendors = cfg.get(section, "visible_vendors")
    elif cfg.has_option("filament_profiles", "visible_vendors"):
        preserved_vendors = cfg.get("filament_profiles", "visible_vendors")
    if cfg.has_section(section):
        cfg.remove_section(section)
    if profiles or preserved_vendors:
        cfg[section] = {}
        if preserved_vendors:
            cfg[section]["visible_vendors"] = preserved_vendors
        for slot_idx in sorted(profiles.keys()):
            entry = profiles[slot_idx] or {}
            if entry.get("vendor"):
                cfg[section][f"slot_{slot_idx}_vendor"] = entry["vendor"]
            if entry.get("name"):
                cfg[section][f"slot_{slot_idx}_name"] = entry["name"]
            if entry.get("id"):
                cfg[section][f"slot_{slot_idx}_id"] = entry["id"]
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)
    return True


def list_visible_vendors(printer_id: Optional[str] = None) -> list[str]:
    """Reads [filament_profiles] visible_vendors (comma-separated) from config.ini.

    Vendor visibility filter for the slot profile dropdown (Issue #41 option A).
    Empty list = no restriction (backwards compatible: all vendors).

    With ``printer_id`` set, reads the per-printer section and falls back to the
    legacy global ``[filament_profiles]`` filter.
    """
    path = _find_config_file()
    if not path:
        return []
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    section = _filament_section(printer_id)
    if not cfg.has_option(section, "visible_vendors"):
        section = "filament_profiles"          # fallback: legacy global section
    if not cfg.has_option(section, "visible_vendors"):
        return []
    raw = cfg.get(section, "visible_vendors")
    return [v.strip() for v in raw.split(",") if v.strip()]


def save_visible_vendors(vendors: list[str], printer_id: Optional[str] = None) -> bool:
    """Writes visible_vendors into [filament_profiles] without touching the
    (slot_N_*) zu verlieren. Leere Liste entfernt den Key wieder.

    With ``printer_id`` set, writes the per-printer section. When that section is
    created here for the first time, the slot mappings are seeded from the legacy
    global section so they are not orphaned by the read-fallback in
    ``list_filament_profiles``."""
    path = _find_config_file()
    if not path:
        return False
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    section = _filament_section(printer_id)
    if not cfg.has_section(section):
        cfg.add_section(section)
        if section != "filament_profiles" and cfg.has_section("filament_profiles"):
            for key, value in cfg.items("filament_profiles"):
                if key.startswith("slot_"):
                    cfg[section][key] = value
    clean = [v.strip() for v in (vendors or []) if v and v.strip()]
    if clean:
        cfg[section]["visible_vendors"] = ", ".join(clean)
    elif cfg.has_option(section, "visible_vendors"):
        cfg.remove_option(section, "visible_vendors")
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)
    return True


def _spoolman_map_section(printer_id: Optional[str] = None) -> str:
    """Section name holding a printer's AMS-slot → Spoolman-spool map.

    Multi-printer (one bridge, N printers): each printer keeps its map in its
    own ``[spoolman_<id>]`` section so two AMS units cannot overwrite each
    other's mapping. ``printer_id is None`` (single-printer / legacy callers)
    uses the original ``[spoolman] slot_spools`` key — full backward
    compatibility. The global ``[spoolman]`` section keeps ``server`` /
    ``sync_rate`` regardless.
    """
    pid = str(printer_id).strip() if printer_id is not None else ""
    if pid and pid != "0":
        return f"{CONFIG_SECTION_SPOOLMAN}_{pid}"
    return CONFIG_SECTION_SPOOLMAN


def _parse_slot_spools(raw: str) -> dict[int, int]:
    """Parse ``"0:42,1:17"`` → ``{0: 42, 1: 17}`` (positive spool ids only)."""
    result: dict[int, int] = {}
    for pair in (raw or "").split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        k, _, v = pair.partition(":")
        k, v = k.strip(), v.strip()
        if k.isdigit() and v.lstrip("-").isdigit() and int(v) > 0:
            result[int(k)] = int(v)
    return result


def list_spool_map(printer_id: Optional[str] = None) -> dict[int, int]:
    """Read the AMS-slot → Spoolman-spool-id map from config.ini.

    With ``printer_id`` set, reads the per-printer ``[spoolman_<id>]
    slot_spools`` key and falls back to the legacy global ``[spoolman]
    slot_spools`` while that printer has no own section yet. Returns
    ``{slot_index: spool_id}`` (only positive ids).
    """
    path = _find_config_file()
    if not path:
        return {}
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    section = _spoolman_map_section(printer_id)
    if cfg.has_option(section, "slot_spools"):
        return _parse_slot_spools(cfg.get(section, "slot_spools", fallback=""))
    if cfg.has_option(CONFIG_SECTION_SPOOLMAN, "slot_spools"):   # legacy global fallback
        return _parse_slot_spools(cfg.get(CONFIG_SECTION_SPOOLMAN, "slot_spools", fallback=""))
    return {}


def save_spool_map(slot_spools: dict[int, int], printer_id: Optional[str] = None) -> bool:
    """Persist the AMS-slot → Spoolman-spool-id map to config.ini.

    With ``printer_id`` set, writes only the per-printer ``[spoolman_<id>]``
    section so other printers and the global ``[spoolman]`` server config stay
    untouched. An empty map clears the key.
    """
    path = _find_config_file()
    if not path:
        return False
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    section = _spoolman_map_section(printer_id)
    clean = {int(k): int(v) for k, v in (slot_spools or {}).items() if int(v) > 0}
    if clean:
        if not cfg.has_section(section):
            cfg.add_section(section)
        cfg[section]["slot_spools"] = ",".join(f"{k}:{v}" for k, v in sorted(clean.items()))
    elif cfg.has_option(section, "slot_spools"):
        cfg.remove_option(section, "slot_spools")
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)
    return True


def get(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


# Frequently used shortcuts
PRINTER_IP       = get("PRINTER_IP",       "")
MQTT_PORT        = int(get("MQTT_PORT",    "9883"))
USERNAME         = get("MQTT_USERNAME",    "")
PASSWORD         = get("MQTT_PASSWORD",    "")
MODE_ID          = get("MODE_ID",          "")
DEVICE_ID        = get("DEVICE_ID",        "")
DEFAULT_AMS_SLOT = get("DEFAULT_AMS_SLOT", "auto")
AUTO_LEVELING           = int(get("AUTO_LEVELING",          "1"))
VIBRATION_COMPENSATION  = int(get("VIBRATION_COMPENSATION", "0"))
CAMERA_ON_PRINT         = int(get("CAMERA_ON_PRINT",        "0"))
WEB_UPLOAD_WARNING = int(get("WEB_UPLOAD_WARNING", "1"))
PRINT_START_DIALOG = int(get("PRINT_START_DIALOG", get("FILE_READY_DIALOG", "1")))
NOZZLE_DIAMETER    = float(get("NOZZLE_DIAMETER", "0.4"))
SPOOLMAN_SERVER    = get("SPOOLMAN_SERVER",    "")
SPOOLMAN_SYNC_RATE = int(get("SPOOLMAN_SYNC_RATE", "0"))
BRIDGE_HOST_IP     = get("BRIDGE_HOST_IP",     "")
POLL_INTERVAL      = int(get("POLL_INTERVAL",  "3"))
VERBOSE_HTTP_LOG   = int(get("VERBOSE_HTTP_LOG", "0"))
