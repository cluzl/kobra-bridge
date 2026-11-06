#!/usr/bin/env python3
# Copyright (C) 2026 Kobra Bridge contributors
# SPDX-License-Identifier: GPL-3.0-only
"""Fail-closed G-code compatibility checks for supported Kobra printers.

Only machine-owned prologue/epilogue/purge blocks and motion limits are changed.
The sliced object toolpath is never scaled, translated, or otherwise reshaped.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import tempfile

from kobra_models import KobraModel, model_for_name

CONVERTER_VERSION = "2"
_NUM = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)"
_SETTING = re.compile(r"^;\s*([a-z_0-9]+)\s*=\s*(.*)$")
_MOVE = re.compile(r"^G([01])(?:\s|$)", re.I)
_ARC = re.compile(r"^G([23])(?:\s|$)", re.I)
_AXIS = {axis: re.compile(rf"(?:^|\s){axis}({_NUM})", re.I) for axis in "XYZFIJR"}
_TEMP = {
    "nozzle": re.compile(rf"^M10[49](?:\s|$).*?(?:^|\s)S({_NUM})", re.I),
    "bed": re.compile(rf"^M1[49]0(?:\s|$).*?(?:^|\s)S({_NUM})", re.I),
    "chamber": re.compile(rf"^M1[49]1(?:\s|$).*?(?:^|\s)S({_NUM})", re.I),
}
_G9111_TEMP = {
    "bed": re.compile(rf"\bBEDTEMP\s*=\s*({_NUM})", re.I),
    "nozzle": re.compile(rf"\bEXTRUDERTEMP\s*=\s*({_NUM})", re.I),
}
_TOOL = re.compile(r"^T(\d+)(?:\s|$)", re.I)
_NUMBER = re.compile(_NUM)
_AFTER_FIRST_LAYER = re.compile(r"^;\s*AFTER_LAYER_CHANGE\s+0(?:\s|@|$)")
# Fast lane: a G1 with only X/Y/Z/E/F words. Covers >95 % of a sliced body and
# skips the temperature/tool/acceleration checks for those lines.
_XYZ_FAST = re.compile(rf"^G1(?: X({_NUM}))?(?: Y({_NUM}))?(?: Z({_NUM}))?(?: E{_NUM})?(?: F({_NUM}))?$")


@dataclass(frozen=True)
class GCodeFacts:
    path: str
    sha256: str
    source_model_id: str
    source_model_name: str
    nozzle_mm: float
    bounds_min: tuple[float, float, float]
    bounds_max: tuple[float, float, float]
    max_nozzle_c: float
    max_bed_c: float
    max_chamber_c: float
    tool_indices: tuple[int, ...]
    max_feed_mm_s: float
    max_accel_mm_s2: float
    first_layer_min: tuple[float, float]
    first_layer_max: tuple[float, float]
    settings: dict[str, str]
    has_machine_start: bool
    has_machine_end: bool
    ambiguous_motion: bool
    unsupported_commands: tuple[str, ...]


@dataclass(frozen=True)
class CompatibilityReport:
    decision: str
    source_model_id: str
    target_model_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class DerivationResult:
    path: str
    sha256: str
    size_bytes: int
    source_sha256: str
    target_model_id: str
    converter_version: str = CONVERTER_VERSION


_MACHINE = {
    "20030": {
        "start": "G9111 bedTemp={bed:g} extruderTemp={nozzle:g}\nM117\n",
        "purge": "",
        "end": "M400\nM140 S0 ; turn off heatbed\nM104 S0 ; turn off temperature\nM107 ; turn off fan\nM84 ; disable motors\n",
        "pause": "M600", "structure": "i3", "disable_m73": "0",
        "clearance": (250, 30, 65),
    },
    "20025": {
        "start": "G9111 bedTemp={bed:g} extruderTemp={nozzle:g}\nM117\n",
        "purge": "",
        "end": "G92 E0\nG1 E-2 F3000\nG1 F12000\nG1 X44\nG1 Y270\nM140 S0\nM104 S0\nM106 P1 S0\nM106 P2 S0\nM106 P3 S0\nM84\n",
        "pause": "M601", "structure": "corexy", "disable_m73": "1",
        "clearance": (240, 48, 60),
    },
    "20029": {
        "start": "G9111 bedTemp={bed:g} extruderTemp={nozzle:g}\nM117\n",
        "purge": "; PURGE LINE\nM204 P500\nSET_VELOCITY_LIMIT SQUARE_CORNER_VELOCITY=9\nG1 Z0.75 F900\nG1 X135 Y352 F18000\nG1 Z.25 F900\nG1 E0.8 F2400\nG1 E0.6 F2400\nG1 F3000\nG1 X205 Y352 E3.72454\nG1 X205 Y352.45 E.0252\nG1 X135 Y352.45 E3.72454\nG1 X135 Y352.02 E.02305\nG1 Z0.5 F600\n",
        "end": "M400\nM140 S0\nM104 S0\nM141 S0\nM106 P1 S0\nM106 P2 S0\nM106 P3 S0\nM84\n",
        "pause": "M600", "structure": "corexy", "disable_m73": "0",
        "clearance": (340, 30, 55),
    },
}


def _numbers(value: str) -> list[float]:
    return [float(x) for x in _NUMBER.findall(value or "")]


def _max_setting(settings: dict[str, str], names: tuple[str, ...]) -> float:
    values = [n for name in names for n in _numbers(settings.get(name, ""))]
    return max(values, default=0.0)


def _xy_setting(value: str) -> tuple[float, float]:
    vals = _numbers(value)
    return (vals[0], vals[1]) if len(vals) >= 2 else (math.nan, math.nan)


def _arc_contains(angle: float, start: float, end: float, clockwise: bool,
                  full_circle: bool) -> bool:
    if full_circle:
        return True
    tau = math.tau
    sweep = ((start - end) if clockwise else (end - start)) % tau
    offset = ((start - angle) if clockwise else (angle - start)) % tau
    return offset <= sweep + 1e-9


def inspect_gcode(path: str | os.PathLike, progress_cb=None) -> GCodeFacts:
    """Inspect G-code without loading it into RAM; report real two-pass progress."""
    path = str(path)
    size = os.path.getsize(path)
    total_work = max(1, size * 2)
    settings: dict[str, str] = {}
    digest = hashlib.sha256()
    absolute = True
    pos = {"X": math.nan, "Y": math.nan, "Z": math.nan}
    mins = {"X": math.inf, "Y": math.inf, "Z": math.inf}
    maxs = {"X": -math.inf, "Y": -math.inf, "Z": -math.inf}
    body = False
    purge_region = False
    end = False
    ambiguous = False
    plane = "G17"
    arc_centers_absolute = False
    unsupported: set[str] = set()
    tools: set[int] = set()
    max_feed = max_accel = max_nozzle = max_bed = max_chamber = 0.0
    has_start = has_end = False
    done = 0
    if progress_cb:
        progress_cb(0, total_work, "hashing")

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
            done += len(chunk)
            if progress_cb:
                progress_cb(done, total_work, "hashing")

    def track(axis: str, value: float) -> None:
        nonlocal ambiguous
        if absolute:
            pos[axis] = value
        elif math.isnan(pos[axis]):
            ambiguous = True
            return
        else:
            pos[axis] += value
        if pos[axis] < mins[axis]: mins[axis] = pos[axis]
        if pos[axis] > maxs[axis]: maxs[axis] = pos[axis]

    scanned = 0
    next_report = 0
    if progress_cb:
        progress_cb(size, total_work, "scanning")
    with open(path, "rb") as fh:
        for raw in fh:
            scanned += len(raw)
            if progress_cb and scanned >= next_report:
                progress_cb(min(total_work, size + scanned), total_work, "scanning")
                next_report = scanned + (1 << 20)
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            if line[0] == ";":
                sm = _SETTING.match(line)
                if sm:
                    settings[sm.group(1)] = sm.group(2)
                elif line == "; filament start gcode":
                    has_start = True
                    body = True
                elif line == "; filament end gcode":
                    has_end = True
                    end = True
                elif line.lstrip("; ") == "PURGE LINE":
                    purge_region = True
                elif _AFTER_FIRST_LAYER.match(line):
                    body = True
                    purge_region = False
                continue
            if purge_region:
                continue
            if body and not end:
                fast = _XYZ_FAST.match(line)
                if fast:
                    x, y, z, f = fast.groups()
                    if x is not None: track("X", float(x))
                    if y is not None: track("Y", float(y))
                    if z is not None: track("Z", float(z))
                    if f is not None:
                        feed = float(f) / 60.0
                        if feed > max_feed: max_feed = feed
                    continue
            code = line.split(";", 1)[0].strip()
            if not code:
                continue
            upper = code.upper()
            if upper == "G90":
                absolute = True
            elif upper == "G91":
                absolute = False
            elif upper == "G90.1":
                arc_centers_absolute = True
            elif upper == "G91.1":
                arc_centers_absolute = False
            elif upper in ("G17", "G18", "G19"):
                plane = upper
            if upper.startswith("G9111"):
                for kind, pattern in _G9111_TEMP.items():
                    match = pattern.search(code)
                    if match:
                        value = float(match.group(1))
                        if kind == "nozzle": max_nozzle = max(max_nozzle, value)
                        else: max_bed = max(max_bed, value)
                if body and not end:
                    unsupported.add("body G9111")
            if body and not end:
                if upper == "G20" or upper.startswith(("G53 ", "SET_GCODE_OFFSET")):
                    unsupported.add(upper.split(None, 1)[0])
                elif upper.startswith("G92 ") and any(_AXIS[a].search(code) for a in "XYZ"):
                    unsupported.add("G92 XYZ")
            tm = _TOOL.match(code)
            if tm:
                tools.add(int(tm.group(1)))
            if upper.startswith("M1"):
                for kind, pattern in _TEMP.items():
                    match = pattern.search(code)
                    if match:
                        value = float(match.group(1))
                        if kind == "nozzle": max_nozzle = max(max_nozzle, value)
                        elif kind == "bed": max_bed = max(max_bed, value)
                        else: max_chamber = max(max_chamber, value)
            if upper.startswith(("SET_VELOCITY_LIMIT", "M204")):
                for value in re.findall(r"\b(?:ACCEL|S)(?:=)?(-?\d+(?:\.\d*)?)", code):
                    max_accel = max(max_accel, float(value))
            if body and not end and _ARC.match(code):
                x0, y0 = pos["X"], pos["Y"]
                im, jm, rm = _AXIS["I"].search(code), _AXIS["J"].search(code), _AXIS["R"].search(code)
                if plane != "G17" or rm or (not im and not jm):
                    unsupported.add(f"{upper.split(None, 1)[0]} unsupported arc form")
                elif math.isnan(x0) or math.isnan(y0):
                    ambiguous = True
                else:
                    i = float(im.group(1)) if im else 0.0
                    j = float(jm.group(1)) if jm else 0.0
                    cx = i if arc_centers_absolute else x0 + i
                    cy = j if arc_centers_absolute else y0 + j
                    xm, ym = _AXIS["X"].search(code), _AXIS["Y"].search(code)
                    x1 = (float(xm.group(1)) if absolute else x0 + float(xm.group(1))) if xm else x0
                    y1 = (float(ym.group(1)) if absolute else y0 + float(ym.group(1))) if ym else y0
                    radius = max(math.hypot(x0 - cx, y0 - cy), math.hypot(x1 - cx, y1 - cy))
                    start_angle = math.atan2(y0 - cy, x0 - cx)
                    end_angle = math.atan2(y1 - cy, x1 - cx)
                    full_circle = math.isclose(x0, x1, abs_tol=1e-9) and math.isclose(y0, y1, abs_tol=1e-9)
                    points = [(x0, y0), (x1, y1)]
                    for angle in (0.0, math.pi / 2, math.pi, 3 * math.pi / 2):
                        if _arc_contains(angle, start_angle, end_angle,
                                         _ARC.match(code).group(1) == "2", full_circle):
                            points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
                    mins["X"] = min(mins["X"], *(p[0] for p in points))
                    maxs["X"] = max(maxs["X"], *(p[0] for p in points))
                    mins["Y"] = min(mins["Y"], *(p[1] for p in points))
                    maxs["Y"] = max(maxs["Y"], *(p[1] for p in points))
                for axis in "XYZ":
                    match = _AXIS[axis].search(code)
                    if match:
                        track(axis, float(match.group(1)))
                fm = _AXIS["F"].search(code)
                if fm: max_feed = max(max_feed, float(fm.group(1)) / 60.0)
                continue
            if body and not end and _MOVE.match(code):
                fm = _AXIS["F"].search(code)
                if fm: max_feed = max(max_feed, float(fm.group(1)) / 60.0)
                for axis in "XYZ":
                    match = _AXIS[axis].search(code)
                    if match:
                        track(axis, float(match.group(1)))

    source = model_for_name(settings.get("printer_model") or settings.get("printer_settings_id"))
    nozzle = _max_setting(settings, ("nozzle_diameter",))
    max_nozzle = max(max_nozzle, _max_setting(settings, ("nozzle_temperature", "nozzle_temperature_initial_layer")))
    max_bed = max(max_bed, _max_setting(settings, ("hot_plate_temp", "hot_plate_temp_initial_layer", "textured_plate_temp", "textured_plate_temp_initial_layer")))
    max_chamber = max(max_chamber, _max_setting(settings, ("chamber_temperature",)))
    max_z_meta = _numbers(settings.get("printable_height", ""))
    header_z = 0.0
    with open(path, "rb") as fh:
        for raw in fh:
            if raw.startswith(b"; max_z_height:"):
                vals = _numbers(raw.decode("ascii", "ignore")); header_z = vals[0] if vals else 0.0; break
            if raw.startswith(b"; EXECUTABLE_BLOCK_START"):
                break
    if header_z:
        mins["Z"] = min(mins["Z"], 0.0)
        maxs["Z"] = max(maxs["Z"], header_z)
    bound_min = tuple(0.0 if math.isinf(mins[a]) else mins[a] for a in "XYZ")
    bound_max = tuple(0.0 if math.isinf(-maxs[a]) else maxs[a] for a in "XYZ")
    if progress_cb:
        progress_cb(total_work, total_work, "scanning")
    return GCodeFacts(
        path=path, sha256=digest.hexdigest(), source_model_id=source.model_id if source else "",
        source_model_name=source.name if source else settings.get("printer_model", ""),
        nozzle_mm=nozzle, bounds_min=bound_min, bounds_max=bound_max,
        max_nozzle_c=max_nozzle, max_bed_c=max_bed, max_chamber_c=max_chamber,
        tool_indices=tuple(sorted(tools)), max_feed_mm_s=max_feed,
        max_accel_mm_s2=max_accel, first_layer_min=_xy_setting(settings.get("first_layer_print_min", "")),
        first_layer_max=_xy_setting(settings.get("first_layer_print_max", "")),
        settings=settings, has_machine_start=has_start, has_machine_end=has_end,
        ambiguous_motion=ambiguous, unsupported_commands=tuple(sorted(unsupported)),
    )


def check_compatibility(facts: GCodeFacts, target: KobraModel,
                        target_nozzle_mm: float = 0.4,
                        available_ace_slots: int = 0) -> CompatibilityReport:
    reasons: list[str] = []
    warnings: list[str] = []
    if not facts.source_model_id:
        reasons.append("source printer model is unknown")
    if not facts.has_machine_start or not facts.has_machine_end:
        reasons.append("machine start/end markers are missing")
    if facts.ambiguous_motion:
        reasons.append("relative motion begins before a known absolute position")
    if not facts.nozzle_mm or abs(facts.nozzle_mm - float(target_nozzle_mm)) > 0.001:
        reasons.append(f"nozzle {facts.nozzle_mm:g} mm does not match target {target_nozzle_mm:g} mm")
    if not target.supports_nozzle(target_nozzle_mm):
        reasons.append(f"configured target nozzle {float(target_nozzle_mm):g} mm is not supported by {target.name}")
    bx, by, bz = target.build_volume_mm
    lo, hi = facts.bounds_min, facts.bounds_max
    if lo[0] < 0 or lo[1] < 0 or lo[2] < 0 or hi[0] > bx or hi[1] > by or hi[2] > bz:
        reasons.append(f"toolpath {lo}..{hi} exceeds target build volume {target.build_volume_mm}")
    if facts.max_nozzle_c > target.max_nozzle_c:
        reasons.append(f"nozzle temperature {facts.max_nozzle_c:g}C exceeds target limit {target.max_nozzle_c}C")
    if facts.max_bed_c > target.max_bed_c:
        reasons.append(f"bed temperature {facts.max_bed_c:g}C exceeds target limit {target.max_bed_c}C")
    if facts.max_chamber_c > target.max_chamber_c:
        reasons.append(f"chamber temperature {facts.max_chamber_c:g}C exceeds target limit {target.max_chamber_c}C")
    used_tools = max(facts.tool_indices, default=0) + 1
    if used_tools > max(1, available_ace_slots):
        reasons.append(f"file uses {used_tools} tools but target has {available_ace_slots} available slots")
    if facts.source_model_id != target.model_id and any(t > 0 for t in facts.tool_indices):
        reasons.append("cross-model multicolour tool-change choreography is not safely convertible")
    if facts.source_model_id != target.model_id and facts.unsupported_commands:
        reasons.append("unsupported cross-model command(s): " + ", ".join(facts.unsupported_commands))
    if facts.max_feed_mm_s > target.max_xy_speed_mm_s:
        warnings.append(f"motion speed will be clamped to {target.max_xy_speed_mm_s} mm/s")
    if facts.max_accel_mm_s2 > target.max_xy_accel_mm_s2:
        warnings.append(f"acceleration will be clamped to {target.max_xy_accel_mm_s2} mm/s2")
    decision = "blocked" if reasons else ("native" if facts.source_model_id == target.model_id else "convertible")
    return CompatibilityReport(decision, facts.source_model_id, target.model_id,
                               tuple(reasons), tuple(warnings))


def _start_gcode(target: KobraModel, facts: GCodeFacts) -> str:
    template = _MACHINE[target.model_id]["start"]
    first_min = facts.first_layer_min
    first_max = facts.first_layer_max
    text = template.format(bed=facts.max_bed_c, nozzle=facts.max_nozzle_c)
    bx, by, _ = target.build_volume_mm
    return (text + f"; print_bed_min = 0,0\n; print_bed_max = {bx},{by}\n"
            f"; print_bed_size = {bx},{by}\n"
            f"; first_layer_print_min = {first_min[0]:g},{first_min[1]:g}\n"
            f"; first_layer_print_max = {first_max[0]:g},{first_max[1]:g}\n"
            f"; first_layer_print_size = {first_max[0]-first_min[0]:g},{first_max[1]-first_min[1]:g}\n")


def _clamp_motion(line: str, target: KobraModel) -> str:
    if _MOVE.match(line) or _ARC.match(line):
        fm = _AXIS["F"].search(line)
        limit = target.max_xy_speed_mm_s * 60
        if fm and float(fm.group(1)) > limit:
            line = line[:fm.start(1)] + f"{limit:g}" + line[fm.end(1):]
    if line.upper().startswith("SET_VELOCITY_LIMIT"):
        def clamp_named(match):
            key, raw = match.group(1), match.group(2)
            limit = target.max_xy_speed_mm_s if key.upper() == "VELOCITY" else target.max_xy_accel_mm_s2
            return f"{key}={min(float(raw), limit):g}"
        line = re.sub(r"\b(VELOCITY|ACCEL)=(-?\d+(?:\.\d*)?)", clamp_named, line, flags=re.I)
    if line.upper().startswith("M204"):
        line = re.sub(r"\b([PST])(-?\d+(?:\.\d*)?)",
                      lambda m: f"{m.group(1)}{min(float(m.group(2)), target.max_xy_accel_mm_s2):g}", line)
    return line


def derive_gcode(source_path: str | os.PathLike, target: KobraModel,
                 output_path: str | os.PathLike, *, target_nozzle_mm: float = 0.4,
                 available_ace_slots: int = 1) -> DerivationResult:
    facts = inspect_gcode(source_path)
    report = check_compatibility(facts, target, target_nozzle_mm, available_ace_slots)
    if report.decision == "blocked":
        raise ValueError("; ".join(report.reasons))
    output_path = str(output_path)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(output_path) or ".", prefix=".derive-", suffix=".tmp")
    os.close(fd)
    start = _start_gcode(target, facts)
    purge = _MACHINE[target.model_id]["purge"]
    end_code = _MACHINE[target.model_id]["end"]
    machine = _MACHINE[target.model_id]
    metadata = {
        "printer_model": target.name,
        "printer_settings_id": target.orca_profile,
        "printable_area": f"0x0,{target.build_volume_mm[0]}x0,{target.build_volume_mm[0]}x{target.build_volume_mm[1]},0x{target.build_volume_mm[1]}",
        "printable_height": str(target.build_volume_mm[2]),
        "machine_start_gcode": start.rstrip().replace("\n", "\\n"),
        "machine_end_gcode": end_code.rstrip().replace("\n", "\\n"),
        "before_layer_change_gcode": purge.rstrip().replace("\n", "\\n"),
        "machine_pause_gcode": machine["pause"],
        "printer_structure": machine["structure"],
        "disable_m73": machine["disable_m73"],
        "support_chamber_temp_control": "1" if target.max_chamber_c else "0",
        "machine_max_speed_x": str(target.max_xy_speed_mm_s),
        "machine_max_speed_y": str(target.max_xy_speed_mm_s),
        "machine_max_acceleration_x": str(target.max_xy_accel_mm_s2),
        "machine_max_acceleration_y": str(target.max_xy_accel_mm_s2),
        "retract_lift_below": str(target.build_volume_mm[2] - 1),
        "extruder_clearance_height_to_lid": str(machine["clearance"][0]),
        "extruder_clearance_height_to_rod": str(machine["clearance"][1]),
        "extruder_clearance_radius": str(machine["clearance"][2]),
    }
    in_start = False
    in_purge = False
    in_end = False
    body = False
    wrote_note = False
    # GoKlipper (S1 family) panics on this Orca metadata key; Kobra X ignores it.
    drop_keys = {"filament_colour_type"} if target.model_id in ("20025", "20029") else set()
    try:
        with open(source_path, "r", encoding="utf-8", errors="replace", newline="") as src, \
                open(tmp, "w", encoding="utf-8", newline="") as out:
            for raw in src:
                line = raw.rstrip("\r\n")
                nl = "\n"
                if line == "; EXECUTABLE_BLOCK_START" and not wrote_note:
                    out.write(line + nl)
                    out.write(f"; KOBRA_BRIDGE_DERIVED target_model_id={target.model_id} source_sha256={facts.sha256} converter={CONVERTER_VERSION}\n")
                    wrote_note = True
                    continue
                if not body and line == ";TYPE:Custom":
                    in_start = True
                    out.write(line + nl)
                    out.write(start)
                    continue
                if in_start:
                    if line == "; filament start gcode":
                        in_start = False
                        out.write(line + nl)
                    continue
                if line.lstrip("; ") == "PURGE LINE":
                    in_purge = True
                    continue
                if _AFTER_FIRST_LAYER.match(line):
                    if in_purge:
                        in_purge = False
                    if not body and purge:
                        out.write(purge)
                    body = True
                    out.write(line + nl)
                    continue
                if in_purge:
                    continue
                if line == "; filament end gcode":
                    in_end = True
                    body = False
                    out.write(line + nl)
                    out.write(end_code)
                    continue
                if in_end:
                    if line.startswith("M73 P100"):
                        in_end = False
                        out.write(line + nl)
                    elif line == "; EXECUTABLE_BLOCK_END":
                        in_end = False
                        out.write(line + nl)
                    continue
                setting = _SETTING.match(line)
                if setting and setting.group(1) in drop_keys:
                    continue
                if setting and setting.group(1) in metadata:
                    out.write(f"; {setting.group(1)} = {metadata[setting.group(1)]}\n")
                    continue
                out.write((_clamp_motion(line, target) if body else line) + nl)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, output_path)
    except Exception:
        try: os.remove(tmp)
        except OSError: pass
        raise
    data_hash = hashlib.sha256()
    with open(output_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            data_hash.update(chunk)
    return DerivationResult(output_path, data_hash.hexdigest(), os.path.getsize(output_path),
                            facts.sha256, target.model_id)
