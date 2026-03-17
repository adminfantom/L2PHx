#!/usr/bin/env python
"""
L2PHx Modern v3 — Lineage 2 Packet Interceptor / Analyzer

Полная замена оригинального L2PHx (Delphi, 2010):
  - Современный Web GUI (aiohttp, единый async-сервер)
  - Реалтайм WebSocket обновления
  - Парсер PacketsFreya.ini с Loop/Get.
  - Крипто: XOR + Blowfish ECB (Ertheia+)
  - WinDivert kernel redirect (обходит Frost/Teros)
  - MCP интеграция для Claude Agent

Архитектура (по реверсу оригинала l2ph.exe):
  Game Client ←→ [WinDivert NAT] ←→ L2MitmProxy ←→ Real Server
                                          ↕
                                     Web GUI (ws)
                                          ↕
                                     MCP (stdio)

Запуск:
  python l2phx.py                         # GUI + Proxy
  python l2phx.py --divert                # + WinDivert (Admin)
  python l2phx.py --target 5.63.128.2:7777

Авторизованный пентест Innova/4Game, Dec 2025 - Mar 2026.
"""

import asyncio
import json
import os
import re
import struct
import sys
import time
import threading
import webbrowser
import argparse
from collections import deque
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════════════
# Конфигурация
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_DIR = os.path.join(BASE_DIR, "settings")
ENGINE_PATH = os.path.join(BASE_DIR, "l2_mcp_proxy.py")
WEB_PORT = 8877
VERSION = "3.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
# Парсер определений пакетов (PacketsFreya.ini)
# ═══════════════════════════════════════════════════════════════════════════════

class PacketField:
    __slots__ = ('name', 'dtype', 'lookup', 'loop_start', 'loop_end', 'skip_bytes')
    SIZES = {'c': 1, 'h': 2, 'd': 4, 'i': 4, 'f': 8, 'q': 8, 'o': 4}

    def __init__(self, name, dtype, lookup="", loop_start=-1, loop_end=-1, skip_bytes=0):
        self.name = name
        self.dtype = dtype
        self.lookup = lookup
        self.loop_start = loop_start
        self.loop_end = loop_end
        self.skip_bytes = skip_bytes

    @property
    def size(self):
        return self.skip_bytes if self.dtype == '-' else self.SIZES.get(self.dtype, 0)


class PacketDef:
    __slots__ = ('opcode', 'name', 'fields')
    def __init__(self, opcode, name, fields):
        self.opcode = opcode
        self.name = name
        self.fields = fields


class PacketDefDB:
    def __init__(self):
        self.client: Dict[int, PacketDef] = {}
        self.server: Dict[int, PacketDef] = {}
        self.lookups: Dict[str, Dict[int, str]] = {}

    def load_ini(self, path: str):
        try:
            with open(path, 'r', encoding='cp1251', errors='replace') as f:
                lines = f.readlines()
        except FileNotFoundError:
            return
        section = None
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            if line == '[Client]':
                section = 'client'; continue
            if line == '[Server]':
                section = 'server'; continue
            if section and '=' in line:
                self._parse_line(line, section)

    def _parse_line(self, line, section):
        eq = line.index('=')
        op_str = line[:eq].strip()
        rest = line[eq+1:].strip()
        try:
            opcode = int(op_str, 16)
        except ValueError:
            return
        if ':' in rest:
            c = rest.index(':')
            name, fields_str = rest[:c], rest[c+1:]
        else:
            name, fields_str = rest, ""
        fields = self._parse_fields(fields_str) if fields_str else []
        target = self.client if section == 'client' else self.server
        target[opcode] = PacketDef(opcode, name, fields)

    def _parse_fields(self, s):
        fields = []
        for m in re.finditer(r'([chdifqsbon])\(([^)]*)\)|(-)\((\d+)\)', s):
            if m.group(3) == '-':
                fields.append(PacketField('-', '-', skip_bytes=int(m.group(4))))
                continue
            dtype, inner = m.group(1), m.group(2)
            name, lookup, ls, le = inner, "", -1, -1
            if ':' in inner:
                parts = inner.split(':')
                name = parts[0]
                for mod in parts[1:]:
                    if mod.startswith('Loop.'):
                        lp = mod[5:].split('.')
                        if len(lp) == 2:
                            ls, le = int(lp[0]), int(lp[1])
                    elif mod.startswith('Get.'):
                        lookup = mod[4:]
                    else:
                        lookup = mod
            fields.append(PacketField(name, dtype, lookup, ls, le))
        return fields

    def load_lookup(self, name, path):
        table = {}
        try:
            with open(path, 'r', encoding='cp1251', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('//') or line.startswith('['):
                        continue
                    if '=' in line:
                        k, v = line.split('=', 1)
                        try: table[int(k.strip())] = v.strip()
                        except ValueError: pass
        except FileNotFoundError:
            pass
        self.lookups[name] = table

    def load_all_lookups(self, d):
        for name, fname in {
            'ClassID': 'ClassId.ini', 'Func01': 'ItemsID.ini',
            'ItemID': 'ItemsID.ini', 'NpcId': 'NpcsId.ini',
            'Skill': 'SkillsId.ini', 'MsgID': 'SysMsgId.ini',
            'AugmentID': 'augmentsid.ini',
        }.items():
            p = os.path.join(d, fname)
            if os.path.exists(p):
                self.load_lookup(name, p)

    def resolve_opcode(self, data, direction):
        if not data:
            return 0, "Unknown"
        opcode = data[0]
        full_op = opcode
        if direction == "C2S" and opcode == 0xD0 and len(data) >= 3:
            full_op = 0xD000 | struct.unpack_from("<H", data, 1)[0]
        elif direction == "S2C" and opcode == 0xFE and len(data) >= 3:
            full_op = 0xFE00 | struct.unpack_from("<H", data, 1)[0]
        db = self.client if direction == "C2S" else self.server
        pdef = db.get(full_op) or db.get(opcode)
        name = pdef.name if pdef else "Unknown"
        return full_op, name

    def parse_packet(self, data, direction):
        if not data:
            return {"error": "empty"}
        full_op, name = self.resolve_opcode(data, direction)
        result = {
            "opcode": f"0x{full_op:04X}" if full_op > 0xFF else f"0x{full_op:02X}",
            "name": name, "fields": [], "raw_hex": data.hex(),
        }
        db = self.client if direction == "C2S" else self.server
        pdef = db.get(full_op) or db.get(data[0])
        if not pdef or not pdef.fields:
            return result
        offset = 3 if full_op > 0xFF else 1
        try:
            result["fields"] = self._parse_data(data, offset, pdef.fields)
        except Exception as e:
            result["parse_error"] = str(e)
        return result

    def _parse_data(self, data, offset, fields):
        result = []
        i = 0
        while i < len(fields):
            f = fields[i]
            if offset >= len(data) and f.dtype != '-':
                break
            if f.dtype == '-':
                offset += f.skip_bytes; i += 1; continue
            if f.loop_start >= 0:
                val, offset = self._read(data, offset, f)
                count = val if isinstance(val, int) else 0
                result.append({"name": f.name, "type": f.dtype, "value": count,
                               "display": f"{count} (loop)"})
                lfc = f.loop_end - f.loop_start + 1
                loop_fields = fields[i+1:i+1+lfc]
                for it in range(min(count, 200)):
                    for lf in loop_fields:
                        if offset >= len(data): break
                        if lf.dtype == '-':
                            offset += lf.skip_bytes; continue
                        val, offset = self._read(data, offset, lf)
                        result.append({"name": f"[{it}].{lf.name}", "type": lf.dtype,
                                       "value": val if not isinstance(val, bytes) else val.hex(),
                                       "display": self._fmt(val, lf)})
                i += 1 + lfc; continue
            val, offset = self._read(data, offset, f)
            result.append({"name": f.name, "type": f.dtype,
                           "value": val if not isinstance(val, bytes) else val.hex(),
                           "display": self._fmt(val, f)})
            i += 1
        return result

    def _read(self, data, offset, f):
        dt, rem = f.dtype, len(data) - offset
        if dt == 'c' and rem >= 1: return data[offset], offset + 1
        if dt == 'h' and rem >= 2: return struct.unpack_from("<H", data, offset)[0], offset + 2
        if dt in ('d', 'o') and rem >= 4: return struct.unpack_from("<I", data, offset)[0], offset + 4
        if dt == 'i' and rem >= 4: return struct.unpack_from("<i", data, offset)[0], offset + 4
        if dt == 'q' and rem >= 8: return struct.unpack_from("<q", data, offset)[0], offset + 8
        if dt == 'f' and rem >= 8: return struct.unpack_from("<d", data, offset)[0], offset + 8
        if dt == 's':
            end = offset
            while end + 1 < len(data):
                if data[end] == 0 and data[end+1] == 0: break
                end += 2
            return data[offset:end].decode('utf-16-le', errors='replace'), end + 2
        return "?", offset + 1

    def _fmt(self, val, f):
        if f.lookup and isinstance(val, int):
            n = self.lookups.get(f.lookup, {}).get(val)
            if n: return f"{val} ({n})"
        if isinstance(val, int) and val > 0xFFFF:
            return f"{val} (0x{val:X})"
        if isinstance(val, float):
            return f"{val:.2f}"
        return str(val)


# ═══════════════════════════════════════════════════════════════════════════════
# HTML — Современный интерфейс
# ═══════════════════════════════════════════════════════════════════════════════

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>L2PHx Modern v3</title>
<style>
:root {
  --bg0:#0b0e14;--bg1:#11151c;--bg2:#171c26;--bg3:#1e2530;--bg4:#262e3a;
  --fg:#cdd6e4;--fg2:#7a8599;--fg3:#555d6e;
  --accent:#4d9bff;--accent2:#3a7fd5;
  --green:#39d353;--red:#f47067;--yellow:#e3b341;--orange:#db8b2e;--purple:#b083f0;--cyan:#26d9d0;
  --border:#1c2333;--border2:#2a3345;
  --font:'JetBrains Mono','Cascadia Code','Fira Code','Consolas',monospace;
  --radius:6px;
}
*{margin:0;padding:0;box-sizing:border-box}
::selection{background:var(--accent2);color:#fff}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg1)}
::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--fg3)}

body{background:var(--bg0);color:var(--fg);font:12px var(--font);height:100vh;display:flex;flex-direction:column;overflow:hidden;user-select:none}

/* ─── Header ─── */
.header{background:linear-gradient(180deg,var(--bg2),var(--bg1));border-bottom:1px solid var(--border);padding:0 16px;height:42px;display:flex;align-items:center;gap:16px;flex-shrink:0}
.logo{font-size:15px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:0.5px}
.logo span{font-weight:400;font-size:11px;-webkit-text-fill-color:var(--fg2)}
.hdr-sep{width:1px;height:20px;background:var(--border2)}
.indicator{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--fg2)}
.indicator .led{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.led-on{background:var(--green);box-shadow:0 0 6px var(--green)}
.led-off{background:var(--red);box-shadow:0 0 4px rgba(244,112,103,0.3)}
.led-wait{background:var(--yellow);box-shadow:0 0 4px rgba(227,179,65,0.3);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.hdr-stats{font-size:11px;color:var(--fg2);margin-left:auto;display:flex;gap:12px}
.hdr-stats b{color:var(--fg);font-weight:600}

/* ─── Main layout ─── */
.main{flex:1;display:flex;overflow:hidden}

/* ─── Left panel (packets) ─── */
.panel-left{flex:1;display:flex;flex-direction:column;min-width:200px}
.toolbar{background:var(--bg1);padding:4px 8px;display:flex;gap:6px;align-items:center;border-bottom:1px solid var(--border);flex-shrink:0}
.tb-input{background:var(--bg3);color:var(--fg);border:1px solid var(--border2);padding:4px 8px;border-radius:var(--radius);font:11px var(--font);outline:none;transition:border-color .15s}
.tb-input:focus{border-color:var(--accent)}
.tb-input::placeholder{color:var(--fg3)}
.tb-select{background:var(--bg3);color:var(--fg);border:1px solid var(--border2);padding:4px 6px;border-radius:var(--radius);font:11px var(--font);outline:none;cursor:pointer}
.tb-btn{background:var(--bg3);color:var(--fg);border:1px solid var(--border2);padding:4px 10px;border-radius:var(--radius);font:11px var(--font);cursor:pointer;transition:all .15s;white-space:nowrap}
.tb-btn:hover{background:var(--accent);color:#000;border-color:var(--accent)}
.tb-btn.active{background:var(--accent2);color:#fff;border-color:var(--accent)}
.tb-btn.danger:hover{background:var(--red);border-color:var(--red)}
.tb-gap{flex:1}
#filterInput{width:220px}

/* ─── Packet table ─── */
.pkt-wrap{flex:1;overflow-y:auto;overflow-x:hidden}
.pkt-table{width:100%;border-collapse:collapse;table-layout:fixed}
.pkt-table thead{position:sticky;top:0;z-index:2}
.pkt-table th{background:var(--bg2);padding:5px 6px;text-align:left;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:var(--fg3);border-bottom:1px solid var(--border2)}
.pkt-table td{padding:3px 6px;border-bottom:1px solid rgba(28,35,51,0.5);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pkt-table tr{cursor:pointer;transition:background .1s}
.pkt-table tr:hover{background:var(--bg3)}
.pkt-table tr.sel{background:rgba(77,155,255,0.12);border-left:2px solid var(--accent)}
.pkt-table .dir-c2s{color:var(--accent);font-weight:600}
.pkt-table .dir-s2c{color:var(--purple);font-weight:600}
.pkt-table .pkt-name{color:var(--fg)}
.pkt-table tr.injected{font-style:italic}
.pkt-table tr.injected .pkt-name{color:var(--orange)}

/* ─── Status bar ─── */
.statusbar{background:var(--bg1);border-top:1px solid var(--border);padding:3px 10px;font-size:10px;color:var(--fg3);display:flex;gap:16px;flex-shrink:0}
.statusbar b{color:var(--fg2)}

/* ─── Right panel ─── */
.panel-right{width:420px;border-left:1px solid var(--border);display:flex;flex-direction:column;background:var(--bg1);flex-shrink:0}

/* Tabs */
.tabs{display:flex;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0}
.tab{padding:8px 14px;font-size:11px;cursor:pointer;color:var(--fg2);border-bottom:2px solid transparent;transition:all .15s;font-weight:500}
.tab:hover{color:var(--fg);background:rgba(255,255,255,0.03)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}

/* Tab content */
.tab-content{flex:1;overflow:hidden;display:flex;flex-direction:column}
.tab-pane{display:none;flex:1;overflow:hidden;flex-direction:column}
.tab-pane.active{display:flex}

/* Detail panel */
.detail-hdr{padding:8px 10px;font-size:12px;font-weight:600;color:var(--accent);background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0}
.detail-fields{flex:1;overflow-y:auto;padding:2px 0}
.field-row{display:flex;padding:3px 10px;transition:background .1s}
.field-row:hover{background:var(--bg3)}
.field-name{color:var(--yellow);width:130px;flex-shrink:0;font-weight:500}
.field-type{color:var(--fg3);width:20px;flex-shrink:0;text-align:center}
.field-val{color:var(--fg);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* Hex viewer */
.hex-view{background:var(--bg0);padding:6px 8px;font-size:11px;line-height:1.6;overflow-y:auto;max-height:200px;border-top:1px solid var(--border);white-space:pre;flex-shrink:0}
.hex-off{color:var(--fg3)}
.hex-byte{color:var(--fg2)}
.hex-ascii{color:var(--green)}
.hex-hi{background:rgba(77,155,255,0.2);color:var(--accent)}

/* ─── Inject panel ─── */
.inject-area{border-top:1px solid var(--border);flex-shrink:0;background:var(--bg2)}
.inject-tabs{display:flex;border-bottom:1px solid var(--border);background:var(--bg1)}
.itab{padding:5px 12px;font-size:10px;cursor:pointer;color:var(--fg3);text-transform:uppercase;letter-spacing:0.5px;transition:all .15s}
.itab:hover{color:var(--fg)}
.itab.active{color:var(--accent);border-bottom:2px solid var(--accent)}
.inject-body{padding:8px 10px}
.inject-body textarea{width:100%;background:var(--bg0);color:var(--fg);border:1px solid var(--border2);padding:6px;font:11px var(--font);resize:vertical;border-radius:var(--radius);outline:none}
.inject-body textarea:focus{border-color:var(--accent)}
.inject-body input[type=text],.inject-body input[type=number]{width:100%;background:var(--bg0);color:var(--fg);border:1px solid var(--border2);padding:5px 8px;font:11px var(--font);border-radius:var(--radius);outline:none;margin-bottom:4px}
.inject-body input:focus{border-color:var(--accent)}
.inject-body select{background:var(--bg0);color:var(--fg);border:1px solid var(--border2);padding:4px;font:11px var(--font);border-radius:var(--radius)}
.irow{display:flex;gap:6px;margin-top:6px;align-items:center}
.ibtn{background:linear-gradient(180deg,var(--accent),var(--accent2));color:#000;border:none;padding:5px 14px;border-radius:var(--radius);cursor:pointer;font:11px var(--font);font-weight:600;transition:opacity .15s}
.ibtn:hover{opacity:0.85}
.ibtn.danger{background:linear-gradient(180deg,var(--red),#c44)}

/* ─── Log panel ─── */
.log-area{flex:1;overflow-y:auto;padding:4px 8px;font-size:11px;line-height:1.6}
.log-entry{color:var(--fg2)}
.log-entry .ts{color:var(--fg3)}
.log-entry .ok{color:var(--green)}
.log-entry .err{color:var(--red)}
.log-entry .warn{color:var(--yellow)}
.log-entry .info{color:var(--cyan)}

/* ─── Empty state ─── */
.empty{display:flex;align-items:center;justify-content:center;flex:1;color:var(--fg3);font-size:12px;flex-direction:column;gap:6px}
.empty .icon{font-size:28px;opacity:0.3}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="logo">L2PHx Modern <span>v""" + VERSION + r"""</span></div>
  <div class="hdr-sep"></div>
  <div class="indicator"><div class="led led-off" id="ledProxy"></div><span id="txtProxy">Proxy: waiting</span></div>
  <div class="indicator"><div class="led led-off" id="ledCrypto"></div><span id="txtCrypto">Crypto: --</span></div>
  <div class="indicator"><div class="led led-off" id="ledDivert"></div><span id="txtDivert">WinDivert: off</span></div>
  <div class="hdr-stats">
    <span>C2S: <b id="cntC2S">0</b></span>
    <span>S2C: <b id="cntS2C">0</b></span>
    <span>Total: <b id="cntTotal">0</b></span>
    <span id="txtRate">0 pkt/s</span>
  </div>
</div>

<!-- Main -->
<div class="main">
  <!-- Left: packet table -->
  <div class="panel-left">
    <div class="toolbar">
      <input class="tb-input" id="filterInput" type="text" placeholder="&#x1F50D; Filter: name, opcode, hex...">
      <select class="tb-select" id="dirFilter">
        <option value="all">All</option>
        <option value="C2S">C2S</option>
        <option value="S2C">S2C</option>
      </select>
      <div class="tb-gap"></div>
      <button class="tb-btn" id="btnAutoScroll" onclick="toggleAuto()">Auto-scroll ON</button>
      <button class="tb-btn" id="btnPause" onclick="togglePause()">Pause</button>
      <button class="tb-btn danger" onclick="clearAll()">Clear</button>
    </div>
    <div class="pkt-wrap" id="pktWrap">
      <table class="pkt-table">
        <thead><tr>
          <th style="width:40px">#</th>
          <th style="width:65px">Time</th>
          <th style="width:36px">Dir</th>
          <th style="width:64px">Opcode</th>
          <th style="width:150px">Name</th>
          <th style="width:44px">Size</th>
          <th>Data</th>
        </tr></thead>
        <tbody id="pktBody"></tbody>
      </table>
    </div>
    <div class="statusbar">
      <span>Shown: <b id="statShown">0</b></span>
      <span>BF: <b id="statBF">--</b></span>
      <span>XOR: <b id="statXOR">--</b></span>
      <span>Target: <b id="statTarget">--</b></span>
    </div>
  </div>

  <!-- Right panel -->
  <div class="panel-right">
    <div class="tabs">
      <div class="tab active" data-tab="details" onclick="switchTab('details',this)">Details</div>
      <div class="tab" data-tab="inject" onclick="switchTab('inject',this)">Inject</div>
      <div class="tab" data-tab="log" onclick="switchTab('log',this)">Log</div>
    </div>

    <div class="tab-content">
      <!-- Details -->
      <div class="tab-pane active" id="pane-details">
        <div class="detail-hdr" id="detailHdr">Select a packet</div>
        <div class="detail-fields" id="detailFields">
          <div class="empty"><div class="icon">&#9776;</div>Click a packet row to inspect</div>
        </div>
        <div class="hex-view" id="hexView"></div>
      </div>

      <!-- Inject -->
      <div class="tab-pane" id="pane-inject">
        <div class="inject-tabs">
          <div class="itab active" onclick="switchITab('raw',this)">Raw C2S</div>
          <div class="itab" onclick="switchITab('raws2c',this)">Raw S2C</div>
          <div class="itab" onclick="switchITab('chat',this)">Chat</div>
          <div class="itab" onclick="switchITab('bypass',this)">Bypass</div>
          <div class="itab" onclick="switchITab('admin',this)">Admin</div>
          <div class="itab" onclick="switchITab('item',this)">Item</div>
          <div class="itab" onclick="switchITab('enchant',this)">Enchant</div>
        </div>
        <div class="inject-body" id="injectBody">
          <textarea id="injectHex" rows="3" placeholder="Hex C2S: 49 00480065006C006C006F000000 00000000"></textarea>
          <div class="irow">
            <button class="ibtn" onclick="doInject('raw')">Inject C2S</button>
            <input type="number" id="floodN" value="1" min="1" max="99999" style="width:70px">
            <button class="ibtn danger" onclick="doInject('flood')">Flood</button>
          </div>
        </div>
        <div class="inject-body" id="injectBodyS2C" style="display:none">
          <textarea id="injectHexS2C" rows="3" placeholder="Hex S2C: 62 0100 ... (спуфинг пакета от сервера клиенту)"></textarea>
          <div class="irow">
            <button class="ibtn" style="background:#c05" onclick="doInject('raws2c')">Inject S2C (spoof)</button>
          </div>
        </div>
      </div>

      <!-- Log -->
      <div class="tab-pane" id="pane-log">
        <div class="log-area" id="logArea">
          <div class="empty"><div class="icon">&#128221;</div>Connection log</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const WS = location.protocol==='https:'?'wss://':'ws://';
let ws, packets=[], autoScroll=true, paused=false, selSeq=-1;
let cC2S=0, cS2C=0, rate=0, rateT=0;

function conn(){
  ws=new WebSocket(WS+location.host+'/ws');
  ws.onopen=()=>{addLog('WebSocket connected','ok');};
  ws.onclose=()=>{addLog('WebSocket disconnected','err');setTimeout(conn,2000);};
  ws.onmessage=e=>{
    const m=JSON.parse(e.data);
    if(m.type==='packet') onPacket(m.data);
    else if(m.type==='status') onStatus(m.data);
    else if(m.type==='crypto') onCrypto(m.data);
    else if(m.type==='parsed') onParsed(m.data);
    else if(m.type==='inject_result') onInjectResult(m.data);
    else if(m.type==='log') addLog(m.data.text, m.data.level||'info');
  };
}

function onPacket(p){
  if(paused) return;
  packets.push(p);
  if(packets.length>15000) packets=packets.slice(-10000);
  if(p.dir==='C2S') cC2S++; else cS2C++;
  rate++;
  $('cntC2S').textContent=cC2S;
  $('cntS2C').textContent=cS2C;
  $('cntTotal').textContent=cC2S+cS2C;
  if(matchFilter(p)) addRow(p);
}

function matchFilter(p){
  const d=$('dirFilter').value;
  if(d!=='all'&&p.dir!==d) return false;
  const t=$('filterInput').value.toLowerCase();
  if(!t) return true;
  return (p.name||'').toLowerCase().includes(t)||(p.opcode_hex||'').toLowerCase().includes(t)||(p.preview||'').toLowerCase().includes(t);
}

function addRow(p){
  const tb=$('pktBody'),tr=document.createElement('tr');
  tr.className=(p.injected?'injected ':'')+(selSeq===p.seq?'sel':'');
  tr.dataset.seq=p.seq;
  tr.onclick=()=>selectPkt(p);
  const dc=p.dir==='C2S'?'dir-c2s':'dir-s2c';
  tr.innerHTML=`<td>${p.seq}</td><td>${p.time||''}</td><td class="${dc}">${p.dir}</td><td>${p.opcode_hex||''}</td><td class="pkt-name" title="${p.name||''}">${p.name||'?'}</td><td>${p.size||0}</td><td style="color:var(--fg3)" title="${p.preview||''}">${(p.preview||'').substring(0,50)}</td>`;
  tb.appendChild(tr);
  $('statShown').textContent=tb.children.length;
  if(autoScroll) $('pktWrap').scrollTop=$('pktWrap').scrollHeight;
}

function selectPkt(p){
  selSeq=p.seq;
  document.querySelectorAll('.pkt-table tr.sel').forEach(r=>r.classList.remove('sel'));
  const row=document.querySelector(`tr[data-seq="${p.seq}"]`);
  if(row) row.classList.add('sel');
  $('detailHdr').textContent=`#${p.seq} ${p.dir} ${p.opcode_hex} ${p.name}`;
  renderHex(p.dec_hex||p.raw_hex||'');
  if(ws&&ws.readyState===1) ws.send(JSON.stringify({action:'parse',seq:p.seq,dir:p.dir,hex:p.dec_hex}));
}

function onParsed(d){
  const div=$('detailFields');
  if(!d.fields||!d.fields.length){div.innerHTML='<div class="empty">No field definitions</div>';return;}
  div.innerHTML=d.fields.map(f=>`<div class="field-row"><span class="field-name">${f.name}</span><span class="field-type">${f.type}</span><span class="field-val">${f.display||f.value}</span></div>`).join('');
}

function renderHex(h){
  const el=$('hexView');
  if(!h){el.textContent='';return;}
  const b=[];for(let i=0;i<h.length;i+=2)b.push(parseInt(h.substr(i,2),16));
  let o='';
  for(let i=0;i<b.length;i+=16){
    let hx='',asc='';
    for(let j=0;j<16;j++){
      if(i+j<b.length){const c=b[i+j];hx+=c.toString(16).padStart(2,'0')+' ';asc+=(c>=0x20&&c<0x7f)?String.fromCharCode(c):'.';}
      else{hx+='   ';asc+=' ';}
      if(j===7)hx+=' ';
    }
    o+=`<span class="hex-off">${i.toString(16).padStart(4,'0')}</span>  <span class="hex-byte">${hx}</span> <span class="hex-ascii">${asc}</span>\n`;
  }
  el.innerHTML=o;
}

function onStatus(s){
  const led=$('ledProxy'),txt=$('txtProxy');
  if(s.connected){led.className='led led-on';txt.textContent='Proxy: '+s.target;}
  else if(s.running){led.className='led led-wait';txt.textContent='Proxy: listening';}
  else{led.className='led led-off';txt.textContent='Proxy: off';}
  if(s.target)$('statTarget').textContent=s.target;
  if(s.divert){$('ledDivert').className='led led-on';$('txtDivert').textContent='WinDivert: active';}
}
function onCrypto(c){
  const led=$('ledCrypto'),txt=$('txtCrypto');
  if(c.initialized){led.className='led led-on';txt.textContent='Crypto: OK';
    $('statBF').textContent=(c.bf_key||'').substring(0,12)+'...';
    $('statXOR').textContent=(c.xor_key||'').substring(0,12)+'...';
  }else{led.className='led led-off';txt.textContent='Crypto: waiting';}
}
function onInjectResult(r){if(r.error)addLog('Inject error: '+r.error,'err');else addLog('Injected: '+JSON.stringify(r),'ok');}

// Controls
function toggleAuto(){autoScroll=!autoScroll;const b=$('btnAutoScroll');b.textContent='Auto-scroll '+(autoScroll?'ON':'OFF');b.classList.toggle('active',autoScroll);}
function togglePause(){paused=!paused;const b=$('btnPause');b.textContent=paused?'Resume':'Pause';b.classList.toggle('active',paused);}
function clearAll(){packets=[];cC2S=cS2C=0;$('pktBody').innerHTML='';$('cntC2S').textContent='0';$('cntS2C').textContent='0';$('cntTotal').textContent='0';$('statShown').textContent='0';}

// Tabs
function switchTab(id,el){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));$('pane-'+id).classList.add('active');}

// Inject tabs
function switchITab(id,el){
  document.querySelectorAll('.itab').forEach(t=>t.classList.remove('active'));el.classList.add('active');
  const b=$('injectBody'), bs=$('injectBodyS2C');
  b.style.display='none'; bs.style.display='none';
  if(id==='raw'){b.style.display='';b.innerHTML=`<textarea id="injectHex" rows="3" placeholder="Hex C2S bytes"></textarea><div class="irow"><button class="ibtn" onclick="doInject('raw')">Inject C2S</button><input type="number" id="floodN" value="1" min="1" max="99999" style="width:70px"><button class="ibtn danger" onclick="doInject('flood')">Flood</button></div>`;}
  else if(id==='raws2c'){bs.style.display='';}
  else if(id==='chat'){b.style.display='';b.innerHTML=`<input type="text" id="chatText" placeholder="Message text"><div class="irow"><select id="chatType"><option value="0">All</option><option value="1">Shout</option><option value="2">Tell</option><option value="3">Party</option><option value="4">Clan</option><option value="8">Trade</option><option value="15">Hero</option></select><input type="text" id="chatTarget" placeholder="Target" style="width:120px"><button class="ibtn" onclick="doInject('chat')">Send</button></div>`;}
  else if(id==='bypass'){b.style.display='';b.innerHTML=`<input type="text" id="bypassCmd" placeholder="Bypass: _bbshome"><div class="irow"><button class="ibtn" onclick="doInject('bypass')">Send Bypass</button></div>`;}
  else if(id==='admin'){b.style.display='';b.innerHTML=`<input type="text" id="adminCmd" placeholder="Admin: admin_gmspeed 5"><div class="irow"><button class="ibtn" onclick="doInject('admin')">Send Admin</button></div>`;}
  else if(id==='item'){b.style.display='';b.innerHTML=`<div class="irow"><input type="number" id="itemObjId" placeholder="Object ID" style="flex:1"><button class="ibtn" onclick="doInject('useitem')">Use Item</button><button class="ibtn" onclick="doInject('action')">Action</button></div><div class="irow"><label style="font-size:11px;display:flex;align-items:center;gap:4px"><input type="checkbox" id="shiftAct"> Shift-click</label></div>`;}
  else if(id==='enchant'){b.style.display='';b.innerHTML=`<input type="number" id="enchObjId" placeholder="Scroll Object ID"><input type="number" id="enchTargetId" placeholder="Target Object ID"><div class="irow"><button class="ibtn" onclick="doInject('enchant')">Enchant</button><input type="number" id="enchRepeat" value="1" min="1" max="999" style="width:60px" placeholder="x"><button class="ibtn danger" onclick="doInject('enchant_flood')">Enchant x N</button></div>`;}
}

function doInject(type){
  if(!ws||ws.readyState!==1){alert('Not connected');return;}
  let msg={};
  if(type==='raw'){const h=(document.getElementById('injectHex')||{}).value||'';msg={action:'inject_raw',hex_data:h.replace(/\s/g,'')};}
  else if(type==='raws2c'){const h=(document.getElementById('injectHexS2C')||{}).value||'';msg={action:'inject_s2c',hex_data:h.replace(/\s/g,'')};}
  else if(type==='flood'){const h=(document.getElementById('injectHex')||{}).value||'';msg={action:'flood',hex_data:h.replace(/\s/g,''),count:parseInt((document.getElementById('floodN')||{}).value)||10};}
  else if(type==='chat'){msg={action:'inject_say2',text:$v('chatText'),chat_type:parseInt($v('chatType'))||0,target:$v('chatTarget')};}
  else if(type==='bypass'){msg={action:'inject_bypass',command:$v('bypassCmd')};}
  else if(type==='admin'){msg={action:'inject_admin',command:$v('adminCmd')};}
  else if(type==='useitem'){msg={action:'inject_use_item',object_id:parseInt($v('itemObjId'))||0};}
  else if(type==='action'){msg={action:'inject_action',object_id:parseInt($v('itemObjId'))||0,shift:document.getElementById('shiftAct')?.checked?1:0};}
  else if(type==='enchant'){msg={action:'inject_enchant',object_id:parseInt($v('enchObjId'))||0,target_id:parseInt($v('enchTargetId'))||0};}
  else if(type==='enchant_flood'){msg={action:'inject_enchant_flood',object_id:parseInt($v('enchObjId'))||0,target_id:parseInt($v('enchTargetId'))||0,count:parseInt($v('enchRepeat'))||10};}
  ws.send(JSON.stringify(msg));
}

// Log
function addLog(text,level){
  const a=$('logArea');
  if(a.querySelector('.empty'))a.innerHTML='';
  const d=document.createElement('div');d.className='log-entry';
  const ts=new Date().toLocaleTimeString();
  d.innerHTML=`<span class="ts">[${ts}]</span> <span class="${level||'info'}">${text}</span>`;
  a.appendChild(d);a.scrollTop=a.scrollHeight;
}

// Filter
$('filterInput').addEventListener('input',rebuild);
$('dirFilter').addEventListener('change',rebuild);
function rebuild(){$('pktBody').innerHTML='';packets.filter(matchFilter).forEach(addRow);}

// Rate
setInterval(()=>{$('txtRate').textContent=rate+' pkt/s';rate=0;},1000);

// Keyboard shortcuts
document.addEventListener('keydown',e=>{
  if(e.ctrlKey&&e.key==='l'){e.preventDefault();clearAll();}
  if(e.ctrlKey&&e.key==='p'){e.preventDefault();togglePause();}
  if(e.key==='Escape'){$('filterInput').value='';rebuild();}
});

function $(id){return document.getElementById(id);}
function $v(id){return (document.getElementById(id)||{}).value||'';}

conn();
addLog('L2PHx Modern v""" + VERSION + r""" ready','info');
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# Async Web Server (aiohttp)
# ═══════════════════════════════════════════════════════════════════════════════

class WebServer:
    """Единый async-сервер: HTTP + WebSocket + broadcast."""

    def __init__(self, pkt_db: PacketDefDB, proxy, store, port: int):
        self.pkt_db = pkt_db
        self.proxy = proxy
        self.store = store
        self.port = port
        self.ws_clients: set = set()
        self._last_seq = 0
        self._log_buffer: deque = deque(maxlen=200)

    def log(self, text, level="info"):
        self._log_buffer.append({"text": text, "level": level})
        print(f"[{level.upper()}] {text}", file=sys.stderr)

    async def handle_index(self, request):
        from aiohttp import web
        return web.Response(text=HTML_PAGE, content_type='text/html')

    async def handle_ws(self, request):
        from aiohttp import web
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.ws_clients.add(ws)
        self.log(f"WS client connected ({len(self.ws_clients)})")

        # Отправить начальный статус
        await self._send_status(ws)

        # Отправить историю пакетов (последние 300) и обновить _last_seq
        recent = self.store.get_recent(300)
        for pkt in recent:
            try:
                seq = pkt.get("seq", 0)
                self._last_seq = max(self._last_seq, seq)
                dec_hex = pkt.get("dec_hex", "")
                name = pkt.get("opname", "") or ""
                opcode_int = pkt.get("opcode", -1)
                opcode_hex = f"0x{opcode_int:04X}" if isinstance(opcode_int, int) and opcode_int >= 0 else str(opcode_int)
                size = pkt.get("len", 0)
                ts = pkt.get("ts", "")
                preview = dec_hex[:80] + ("..." if len(dec_hex) > 80 else "") if dec_hex else ""
                msg = {"type": "packet", "data": {
                    "seq": seq,
                    "time": ts,
                    "dir": pkt.get("dir", "C2S"),
                    "opcode_hex": opcode_hex,
                    "name": name,
                    "size": size,
                    "dec_hex": dec_hex,
                    "raw_hex": pkt.get("raw_hex", ""),
                    "preview": preview,
                    "injected": "INJECT" in (name or ""),
                }}
                await ws.send_json(msg)
            except Exception:
                break
        self.log(f"Sent {len(recent)} history packets to new client")

        try:
            async for msg in ws:
                if msg.type == 1:  # TEXT
                    try:
                        data = json.loads(msg.data)
                        await self._handle_ws_msg(ws, data)
                    except Exception as e:
                        await ws.send_json({"type": "error", "data": {"error": str(e)}})
        finally:
            self.ws_clients.discard(ws)
            self.log(f"WS client disconnected ({len(self.ws_clients)})")

        return ws

    async def _send_status(self, ws):
        status = {"running": False, "connected": False, "target": "", "divert": False}
        if self.proxy:
            status["running"] = self.proxy.running
            status["connected"] = getattr(self.proxy, 'connected', False)
            t = self.proxy._get_target() if hasattr(self.proxy, '_get_target') else ("", 0)
            status["target"] = f"{t[0]}:{t[1]}"
        await ws.send_json({"type": "status", "data": status})

        crypto_data = {"initialized": False}
        if self.proxy and hasattr(self.proxy, 'crypto') and self.proxy.crypto:
            c = self.proxy.crypto
            crypto_data = {
                "initialized": c.initialized,
                "bf_key": c.bf_key.hex() if c.bf_key else None,
                "xor_key": c.xor_key.hex() if c.xor_key else None,
            }
        await ws.send_json({"type": "crypto", "data": crypto_data})

    async def _handle_ws_msg(self, ws, data):
        action = data.get("action", "")
        if action == "parse":
            hex_data = data.get("hex", "")
            direction = data.get("dir", "C2S")
            if hex_data:
                parsed = self.pkt_db.parse_packet(bytes.fromhex(hex_data), direction)
                await ws.send_json({"type": "parsed", "data": parsed})
        elif action.startswith("inject") or action == "flood":
            result = self._handle_inject(action, data)
            await ws.send_json({"type": "inject_result", "data": result})

    def _handle_inject(self, action, data):
        if not self.proxy or not self.proxy.running:
            return {"error": "Proxy not running"}
        plaintext = None
        if action == "inject_raw":
            plaintext = bytes.fromhex(data.get("hex_data", ""))
        elif action == "inject_say2":
            plaintext = _build_say2(data.get("text", ""),
                                     data.get("chat_type", 0),
                                     data.get("target", ""))
        elif action == "inject_bypass":
            plaintext = b'\x23' + _encode_str(data.get("command", ""))
        elif action == "inject_admin":
            plaintext = b'\x74' + _encode_str(data.get("command", ""))
        elif action == "inject_use_item":
            plaintext = struct.pack("<BII", 0x19, data.get("object_id", 0), 0)
        elif action == "inject_enchant":
            oid = data.get("object_id", 0)
            plaintext = struct.pack("<BI", 0x5F, oid)
        elif action == "inject_enchant_flood":
            oid = data.get("object_id", 0)
            pkt = struct.pack("<BI", 0x5F, oid)
            count = min(data.get("count", 10), 99999)
            for _ in range(count):
                self.proxy.inject_c2s.append(pkt)
            return {"status": "enchant_flood", "count": count}
        elif action == "inject_action":
            plaintext = struct.pack("<BIIIIb", 0x1F, data.get("object_id", 0),
                                    0, 0, 0, data.get("shift", 0))
        elif action == "inject_s2c":
            s2c_data = bytes.fromhex(data.get("hex_data", ""))
            self.proxy.inject_s2c.append(s2c_data)
            return {"status": "queued_s2c", "size": len(s2c_data)}
        elif action == "flood":
            pkt = bytes.fromhex(data.get("hex_data", ""))
            count = min(data.get("count", 10), 99999)
            for _ in range(count):
                self.proxy.inject_c2s.append(pkt)
            return {"status": "flooding", "count": count}
        if plaintext:
            self.proxy.inject_c2s.append(plaintext)
            return {"status": "queued", "size": len(plaintext)}
        return {"error": f"Unknown action: {action}"}

    async def _broadcast_loop(self):
        """Бесконечный цикл: новые пакеты из store → WS клиенты."""
        self.log("Broadcast loop started")
        _heartbeat = 0
        while True:
            try:
                await asyncio.sleep(0.04)  # 25 fps
                _heartbeat += 1

                # Периодический heartbeat + статус каждые ~5 сек
                if _heartbeat % 125 == 0:
                    store_count = len(self.store.packets) if self.store else 0
                    self.log(f"[broadcast] heartbeat: ws_clients={len(self.ws_clients)}, "
                             f"store={store_count}, last_seq={self._last_seq}", "debug")
                    if self.ws_clients:
                        await self._broadcast_status_all()

                if not self.ws_clients:
                    continue

                recent = self.store.get_recent(300)
                new_pkts = [p for p in recent if p.get("seq", 0) > self._last_seq]

                if new_pkts and _heartbeat % 25 == 0:
                    self.log(f"[broadcast] sending {len(new_pkts)} new packets", "debug")

                for pkt in new_pkts:
                    self._last_seq = max(self._last_seq, pkt.get("seq", 0))
                    dec_hex = pkt.get("dec_hex", "")
                    direction = pkt.get("dir", "C2S")
                    name = pkt.get("opname", "") or pkt.get("name", "")
                    opcode_int = pkt.get("opcode", -1)
                    opcode_hex = f"0x{opcode_int:04X}" if isinstance(opcode_int, int) and opcode_int >= 0 else str(opcode_int)
                    size = pkt.get("len", 0) or pkt.get("size", 0)
                    ts = pkt.get("ts", "") or pkt.get("time", "")
                    preview = dec_hex[:80] + ("..." if len(dec_hex) > 80 else "") if dec_hex else ""

                    msg = {"type": "packet", "data": {
                        "seq": pkt.get("seq", 0),
                        "time": ts,
                        "dir": direction,
                        "opcode_hex": opcode_hex,
                        "name": name,
                        "size": size,
                        "dec_hex": dec_hex,
                        "raw_hex": pkt.get("raw_hex", ""),
                        "preview": preview,
                        "injected": "INJECT" in (name or ""),
                    }}
                    await self._broadcast(msg)

            except Exception as e:
                self.log(f"[broadcast] ERROR: {e}", "err")
                import traceback
                traceback.print_exc(file=sys.stderr)
                await asyncio.sleep(1)

    async def _broadcast_status_all(self):
        status = {"running": False, "connected": False, "target": "", "divert": False}
        if self.proxy:
            status["running"] = self.proxy.running
            status["connected"] = getattr(self.proxy, 'connected', False)
            t = self.proxy._get_target() if hasattr(self.proxy, '_get_target') else ("", 0)
            status["target"] = f"{t[0]}:{t[1]}"

        crypto_data = {"initialized": False}
        if self.proxy and hasattr(self.proxy, 'crypto') and self.proxy.crypto:
            c = self.proxy.crypto
            crypto_data = {
                "initialized": c.initialized,
                "bf_key": c.bf_key.hex() if c.bf_key else None,
                "xor_key": c.xor_key.hex() if c.xor_key else None,
            }

        await self._broadcast({"type": "status", "data": status})
        await self._broadcast({"type": "crypto", "data": crypto_data})

    async def _broadcast(self, msg):
        dead = set()
        data = json.dumps(msg, ensure_ascii=False)
        for ws in list(self.ws_clients):
            try:
                await ws.send_str(data)
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead

    async def handle_api(self, request):
        """REST API для MCP и внешних инструментов."""
        from aiohttp import web
        try:
            data = await request.json()
        except Exception:
            data = {}

        action = data.get("action", request.match_info.get("action", ""))

        if action == "get_packets":
            count = data.get("count", 50)
            d = data.get("direction", "all")
            d = None if d == "all" else d
            op = {int(data["opcode"], 16)} if data.get("opcode") else None
            nf = data.get("name_filter")
            pkts = self.store.get_recent(count, d, op, nf)
            return web.json_response({"count": len(pkts), "packets": pkts})

        if action == "get_stats":
            return web.json_response(self.store.get_stats())

        if action == "get_crypto":
            crypto_data = {"status": "no session"}
            if self.proxy and hasattr(self.proxy, 'crypto') and self.proxy.crypto:
                c = self.proxy.crypto
                crypto_data = {
                    "initialized": c.initialized,
                    "bf_key": c.bf_key.hex() if c.bf_key else None,
                    "xor_key": c.xor_key.hex() if c.xor_key else None,
                    "running": self.proxy.running,
                }
            return web.json_response(crypto_data)

        if action == "get_status":
            status = {
                "running": self.proxy.running if self.proxy else False,
                "connected": getattr(self.proxy, 'connected', False),
                "store_count": len(self.store.packets),
                "ws_clients": len(self.ws_clients),
            }
            return web.json_response(status)

        if action in ("inject_raw", "inject_say2", "inject_bypass", "inject_admin",
                       "inject_use_item", "inject_enchant", "inject_action",
                       "inject_s2c", "flood"):
            result = self._handle_inject(action, data)
            return web.json_response(result)

        return web.json_response({"error": f"Unknown action: {action}"}, status=400)

    async def start(self):
        from aiohttp import web
        app = web.Application()
        app.router.add_get('/', self.handle_index)
        app.router.add_get('/ws', self.handle_ws)
        app.router.add_post('/api/{action}', self.handle_api)
        app.router.add_post('/api', self.handle_api)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', self.port, reuse_address=True)
        await site.start()

        self.log(f"Web GUI: http://127.0.0.1:{self.port}")
        self.log(f"REST API: http://127.0.0.1:{self.port}/api/{{action}}")

        # Запустить broadcast в фоне
        asyncio.create_task(self._broadcast_loop())

        # Блокировать навечно
        await asyncio.Event().wait()


def _encode_str(s):
    return s.encode("utf-16-le") + b'\x00\x00'

def _build_say2(text, chat_type=0, target=""):
    return b'\x49' + _encode_str(text) + struct.pack("<I", chat_type) + _encode_str(target)


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="L2PHx Modern v3 — Lineage 2 Packet Interceptor")
    parser.add_argument("--port", type=int, default=WEB_PORT)
    parser.add_argument("--target", default="5.63.128.2:7777")
    parser.add_argument("--divert", action="store_true",
                        help="Enable WinDivert kernel redirect (Admin required)")
    parser.add_argument("--mcp", action="store_true",
                        help="Start MCP server on stdio")
    parser.add_argument("--packets-ini", default=None)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    print("=" * 60, file=sys.stderr)
    print("  L2PHx Modern v3 — Lineage 2 Packet Interceptor", file=sys.stderr)
    print("  Ertheia+ | Web GUI | MCP | WinDivert", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # 1. Пакетные определения
    pkt_db = PacketDefDB()
    ini_path = args.packets_ini
    if not ini_path:
        for name in ["PacketsFreya.ini", "PacketsGraciaFinal.ini",
                      "packetsInterlude.ini"]:
            candidate = os.path.join(SETTINGS_DIR, name)
            if os.path.exists(candidate):
                ini_path = candidate
                break
    if ini_path and os.path.exists(ini_path):
        pkt_db.load_ini(ini_path)
        pkt_db.load_all_lookups(os.path.dirname(ini_path))
        print(f"[PKTDEF] Loaded: {len(pkt_db.client)} C2S, "
              f"{len(pkt_db.server)} S2C", file=sys.stderr)
    else:
        print("[PKTDEF] No packet definitions found", file=sys.stderr)

    # 2. Движок (l2_mcp_proxy.py)
    print("[ENGINE] Loading...", file=sys.stderr)
    import importlib.util
    spec = importlib.util.spec_from_file_location("l2_engine", ENGINE_PATH)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)

    target_ip, target_port = args.target.rsplit(":", 1)
    engine.DEFAULT_TARGET = (target_ip, int(target_port))

    store = engine.PacketStore()
    store.open_log(engine.LOG_FILE)
    proxy = engine.L2MitmProxy(store, engine.PROXY_PORT)
    print(f"[ENGINE] Target: {target_ip}:{target_port}", file=sys.stderr)
    print(f"[ENGINE] Proxy: 127.0.0.1:{engine.PROXY_PORT}", file=sys.stderr)

    # 3. Запуск proxy
    threading.Thread(target=proxy.run, daemon=True, name="proxy").start()

    # 4. WinDivert
    if args.divert:
        divert = engine.WinDivertRedirector(engine.PROXY_PORT)
        threading.Thread(target=divert.run, daemon=True, name="divert").start()
    else:
        print("[DIVERT] Off (use --divert)", file=sys.stderr)

    # 5. MCP
    if args.mcp:
        mcp = engine.L2McpServer(store, proxy)
        threading.Thread(target=lambda: asyncio.run(mcp.run()),
                         daemon=True, name="mcp").start()

    # 5.1. Тестовый пакет — проверка pipeline store → WebSocket → browser
    time.sleep(0.5)
    store.add("S2C", b'\x00\x01', b'\x00\x01', 0x0000, "L2PHx:STARTUP",
              extra={"note": "Pipeline test — if you see this, WebSocket works!"})
    print(f"[PIPELINE] Test packet added to store (seq={store.seq})", file=sys.stderr)

    # 6. Открыть браузер
    url = f"http://127.0.0.1:{args.port}"
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    # 7. Web GUI (async main loop)
    server = WebServer(pkt_db, proxy, store, args.port)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n[EXIT] Bye", file=sys.stderr)


if __name__ == "__main__":
    main()
