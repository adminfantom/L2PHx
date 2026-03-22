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
ENGINE_PATH = os.path.join(BASE_DIR, "_engine.py")
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
# Packet Category Classifier
# Источник: реконструкция протокола (спецификация операционных плоскостей)
# ═══════════════════════════════════════════════════════════════════════════════

# Категории: action (действия игрока), world (фоновый мир), service (UI/lists),
#             system (сессия/keepalive), unknown
# Используются для разделения потока в UI на две колонки.

_C2S_ACTION_OPS = {
    0x00, 0x01,  # Logout, Attack
    0x19,  # UseItem
    0x1A, 0x1B, 0x1C, 0x55,  # Trade: start, addItem, done, answer
    0x1F,  # Action
    0x23,  # RequestBypassToServer
    0x30, 0x31, 0x37,  # PrivateStoreListSell, RequestSellItem
    0x38, 0x39, 0x50,  # RequestMagicSkillUse, skills
    0x57,  # RequestRestart (confirmed 0x57, NOT 0x46)
    0x7D,  # RequestRestartPoint
    0x3B, 0x3C,  # Warehouse deposit/withdraw
    0x40,  # RequestBuyItem (NPC shop / бакалейная лавка!)
    0x5F,  # RequestEnchantItem
    0x6F, 0x70, 0x71, 0x72,  # Henna equip/unequip
    0x73, 0x7C,  # Skill learn/acquire
    0x74,  # SendBypassBuildCmd
    0x83,  # RequestPrivateStoreBuy
    0x94, 0x95, 0x98,  # PetUseItem, enchant etc
    0x96, 0x97, 0x99, 0x9A, 0x9C, 0x9D, 0x9F,  # Private store ops
    0xA7, 0xA8,  # Package/Mail
    0xB0,  # MultiSellChoose
    0xC3, 0xC4, 0xC5, 0xC7,  # Henna/BuySeed
    0xF8,  # ExRequestNewEnchantRemoveTwo
}

_S2C_ACTION_OPS = {
    0x06,  # S_SELL_LIST (carrier — но важен для отображения действий)
    0x07,  # S_BUY_LIST
    0x14,  # S_TRADE_START
    0x15, 0x16, 0x17,  # Trade own/other/done
    0x28,  # S_MAGIC_SKILL_USE
    0x32,  # S_MAGIC_SKILL_LAUNCHED
    0x33,  # S_SKILL_LIST
    0x41, 0x42, 0x43,  # Warehouse deposit/withdraw/done
    0x5A, 0x5E,  # S_MAGIC_LIST
    0xA0, 0xA1, 0xA2,  # Private store manage/list/msg
    0xE4, 0xE5, 0xEE,  # Henna item info/info/equip list
}

_SYSTEM_OPS_C2S = {0x0E, 0x11, 0x12, 0x2B, 0xCB}  # Proto, Enter, CharSel, Auth, GG
_SYSTEM_OPS_S2C = {0x09, 0x0A, 0x0B, 0x0E, 0x2E, 0xCB, 0xD9}  # CharSel, Login, KeyInit, GG, Ping

# S2C ambient world (фоновый шум — отдельная категория)
_S2C_WORLD_OPS = {
    0x0C,  # S_NPC_INFO
    0x12,  # S_STATUS_UPDATE
    0x13,  # S_MOVE_TO_LOCATION
    0x18,  # S_CHAR_INFO
    0x19,  # S_USER_INFO
    0x1D,  # S_TELEPORT_TO_LOCATION
    0x1E, 0x1F,  # TARGET_SELECTED/UNSELECTED
    0x20, 0x21,  # AUTO_ATTACK start/stop
    0x22,  # S_SOCIAL_ACTION
    0x31,  # S_STOP_MOVE
    0x39,  # S_VEHICLE_INFO
    0x4B,  # S_MOVE_TO_PAWN
    0x4C,  # S_VALIDATE_LOCATION
    0x4E, 0x4F,  # START/STOP_ROTATING
    0x52,  # S_SYSTEM_MESSAGE
    0x65,  # S_ABNORMAL_STATUS_UPDATE
}


def classify_packet(direction: str, opcode: int, name: str = "") -> str:
    """Classify packet into category for UI split view.
    Returns: 'action', 'world', 'service', 'system', 'unknown'
    """
    # Injected packets are always "action"
    if "INJECT" in name or "RACE" in name:
        return "action"
    # game:* relay inner packets — classify by inner opcode
    if name.startswith("game:"):
        name = name[5:]  # strip prefix for classification
    if direction == "C2S":
        if opcode in _SYSTEM_OPS_C2S:
            return "system"
        if opcode in _C2S_ACTION_OPS:
            return "action"
        # Relay outer 0x06 is transport, not action
        if opcode == 0x06:
            return "service"
        return "unknown"
    else:  # S2C
        if opcode in _SYSTEM_OPS_S2C:
            return "system"
        if opcode in _S2C_ACTION_OPS:
            return "action"
        if opcode in _S2C_WORLD_OPS:
            return "world"
        return "world"  # default S2C = world background


# ═══════════════════════════════════════════════════════════════════════════════
# Game Event Interpreter — пакеты → человекочитаемый лог
# ═══════════════════════════════════════════════════════════════════════════════

def _read_u32(data: bytes, off: int) -> int:
    if off + 4 > len(data): return 0
    return struct.unpack_from("<I", data, off)[0]

def _read_u64(data: bytes, off: int) -> int:
    if off + 8 > len(data): return 0
    return struct.unpack_from("<q", data, off)[0]

def _read_u16(data: bytes, off: int) -> int:
    if off + 2 > len(data): return 0
    return struct.unpack_from("<H", data, off)[0]

def _read_str16(data: bytes, off: int) -> str:
    """Read null-terminated UTF-16LE string."""
    end = off
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    try:
        return data[off:end].decode('utf-16-le', errors='replace')
    except Exception:
        return "?"


def interpret_packet(direction: str, opcode: int, name: str, dec_hex: str) -> Optional[str]:
    """Interpret a packet into human-readable game event description.
    Returns None if packet is not interesting enough for game log.

    ВАЖНО:
    - Работает ТОЛЬКО с game:* и sniff:* пакетами (inner game body).
    - Outer relay 0x06 и ambient world noise пропускаются.
    - Field values НЕ парсятся из carrier_plain (могут быть обфусцированы).
    - Для Ertheia+ опкоды обфусцированы; hardcoded таблица из L2J Mobius
      может не совпадать с live Innova. Поэтому основная логика работает
      по имени пакета (name), а не по числовому опкоду.
    """
    if not name or not dec_hex:
        return None

    # ─── Фильтр: только inner game / sniff / inject пакеты ──────
    # Outer relay контейнеры, ambient transport — не интерпретируем.
    # Login sequence придёт через sniff:* с порта 7777.
    if name in ("Relay_0x06", "RequestReplyStopPledgeWar"):
        return None
    if not name.startswith("game:") and not name.startswith("sniff:") \
       and not name.startswith("INJECT:") and not name.startswith("RACE:"):
        return None

    is_inject = "INJECT" in name or "RACE" in name
    prefix = "[INJECT] " if is_inject else ""
    # C2S opcode table из L2J Mobius частично совпадает с live Innova.
    # Пропускаем ТОЛЬКО подтверждённые inject-ready opcodes (0xB0, 0x23, 0x40 и др.)
    # Остальные game:C2S фильтруем — имена могут быть ложными.
    if name.startswith("game:") and direction == "C2S":
        _CONFIRMED_C2S = {
            "RequestBuyItem", "RequestSellItem", "UseItem", "Action",
            "RequestBypassToServer", "SendBypassBuildCmd",
            "RequestEnchantItem", "MultiSellChoose",
            "SendWareHouseDepositList", "SendWareHouseWithDrawList",
            "AddTradeItem", "TradeDone", "TradeRequest", "AnswerTradeRequest",
            "Say2", "RequestMagicSkillUse", "RequestRestart", "RequestRestartPoint",
            "RequestActionUse", "RequestBuySeed", "RequestCrystallizeItem",
            "RequestDestroyItem", "RequestHennaEquip", "RequestHennaRemove",
            "RequestHennaItemList", "RequestHennaItemInfo",
            "RequestPrivateStoreBuy", "RequestPrivateStoreSell",
            "SetPrivateStoreListSell", "SetPrivateStoreListBuy",
            "SetPrivateStoreMsgSell", "SetPrivateStoreMsgBuy",
            "RequestPackageSend", "DlgAnswer",
            "RequestAcquireSkill", "RequestAcquireSkillInfo",
        }
        clean_check = name[5:]  # strip "game:"
        if clean_check not in _CONFIRMED_C2S:
            return None

    # Извлекаем чистое имя без префиксов
    clean = name
    for pfx in ("game:", "sniff:", "INJECT:", "RACE:"):
        if clean.startswith(pfx):
            clean = clean[len(pfx):]

    try:
        data = bytes.fromhex(dec_hex) if dec_hex else b""
    except (ValueError, TypeError):
        data = b""

    # ─── По ИМЕНИ пакета (надёжнее чем по opcode на Ertheia+) ──

    # Login / Session
    if clean == "S_VERSION_CHECK" or (opcode == 0x2E and direction == "S2C"):
        return "Сервер: проверка версии (KEY_INIT)"
    if clean == "S_LOGIN_RESULT" or (opcode == 0x0A and direction == "S2C"):
        return "Сервер: результат авторизации"
    if clean in ("CharSelectionInfo", "S_CHAR_SELECTION_INFO", "S_CHARACTER_SELECTION_INFO"):
        # Показываем только от sniff (реальный login flow), не от game: relay (шум)
        if name.startswith("sniff:"):
            return "Сервер: список персонажей"
        return None
    if clean in ("CharSelected", "S_CHAR_SELECTED", "S_CHARACTER_SELECTED"):
        if name.startswith("sniff:"):
            return "Сервер: персонаж выбран"
        return None
    if clean == "ProtocolVersion":
        return f"{prefix}Отправлена версия протокола"
    if clean == "AuthLogin":
        return f"{prefix}Авторизация"
    if clean == "CharacterSelect":
        return f"{prefix}Выбор персонажа"
    if clean == "EnterWorld":
        return f"{prefix}Вход в игровой мир"
    if clean == "Logout":
        # На relay game:Logout — почти всегда padding/noise (opcode 0x00 = zero byte).
        # Настоящий Logout показываем только от sniff или inject.
        if name.startswith("sniff:") or is_inject:
            return f"{prefix}Выход из игры"
        return None
    if clean == "GameGuardReply" or clean == "GameGuardQuery" or clean == "S_GAMEGUARD_QUERY":
        return None  # спам
    if clean in ("S_DIE", "S_REVIVE"):
        # Частые ambient события — не спамить
        return None
    # Общий шум S2C: status/move/entity updates (высокочастотные, не показываем)
    if clean in ("S_STATUS_UPDATE", "S_MOVE_TO_LOCATION", "S_VALIDATE_LOCATION",
                 "S_NPC_INFO", "S_CHAR_INFO", "S_USER_INFO",
                 "S_STOP_MOVE", "S_MOVE_TO_PAWN", "S_TARGET_SELECTED",
                 "S_TARGET_UNSELECTED", "S_COMBAT_MODE_START", "S_COMBAT_MODE_FINISH",
                 "S_SOCIAL_ACTION", "S_CHANGE_MOVE_TYPE", "S_CHANGE_WAIT_TYPE",
                 "S_ABNORMAL_STATUS_UPDATE", "S_DELETE_OBJECT",
                 "S_SUNRISE", "S_SUNSET",
                 "S_ATTACK_OUT_OF_RANGE", "S_ATTACK_IN_COOLTIME", "S_ATTACK_DEAD_TARGET",
                 "S_ACTION_FAIL", "S_SERVER_CLOSE", "S_NET_PING",
                 "S_START_ROTATING", "S_STOP_ROTATING",
                 "S_SSQ_STATUS", "S_PETITION_VOTE", "S_AGIT_DECO_INFO",
                 "S_PARTY_MEMBER_POSITION", "S_PARTY_SPELL_INFO"):
        return None

    # ─── NPC Shop / Торговля ───────────────────────────────────
    if clean == "RequestBuyItem":
        return f"{prefix}Покупка у NPC"
    if clean == "RequestSellItem":
        return f"{prefix}Продажа NPC"
    if clean in ("S_BUY_LIST", "BuyList"):
        return "Сервер: список товаров магазина"
    if clean in ("S_SELL_LIST", "SellList"):
        return "Сервер: список для продажи"
    if clean == "RequestBypassToServer":
        # Пробуем прочитать bypass команду (надёжно: UTF-16 строка)
        if data and len(data) >= 3:
            cmd = _read_str16(data, 1)
            if cmd and len(cmd) >= 2 and all(0x20 <= ord(c) < 0xFFFE for c in cmd[:10]):
                short_cmd = cmd[:50] + ("..." if len(cmd) > 50 else "")
                return f"{prefix}NPC диалог: «{short_cmd}»"
        return f"{prefix}NPC диалог (bypass)"
    if clean == "SendBypassBuildCmd":
        if data and len(data) >= 3:
            cmd = _read_str16(data, 1)
            if cmd and len(cmd) >= 2:
                return f"{prefix}Admin: «{cmd[:40]}»"
        return f"{prefix}Admin команда"

    # ─── Склад ─────────────────────────────────────────────────
    if clean == "SendWareHouseDepositList":
        return f"{prefix}Положить на склад"
    if clean == "SendWareHouseWithDrawList":
        return f"{prefix}Забрать со склада"
    if clean in ("S_WAREHOUSE_DEPOSIT_LIST", "WareHouseDepositList"):
        return "Сервер: содержимое склада (депозит)"
    if clean in ("S_WAREHOUSE_WITHDRAW_LIST", "WareHouseWithdrawList"):
        return "Сервер: содержимое склада (изъятие)"
    if clean in ("S_WAREHOUSE_DONE", "WareHouseDone"):
        return "Сервер: операция со складом завершена"

    # ─── Мультиселл ────────────────────────────────────────────
    if clean == "MultiSellChoose" or clean == "RequestMultiSellChoose":
        return f"{prefix}Мультиселл: покупка"

    # ─── Обмен ─────────────────────────────────────────────────
    if clean in ("RequestStartTrade", "TradeRequest"):
        return f"{prefix}Запрос обмена"
    if clean == "AddTradeItem":
        return f"{prefix}Добавление предмета в обмен"
    if clean == "TradeDone":
        return f"{prefix}Подтверждение обмена"
    if clean in ("AnswerTradeRequest", "AnswerTrade"):
        return f"{prefix}Ответ на запрос обмена"
    if clean in ("S_TRADE_START", "TradeStart"):
        return "Сервер: начало обмена"
    if clean in ("S_TRADE_DONE", "TradeDone") and direction == "S2C":
        return "Сервер: обмен завершён"

    # ─── Личный магазин ────────────────────────────────────────
    if clean == "RequestPrivateStoreBuy":
        return f"{prefix}Покупка в личном магазине"
    if clean in ("RequestPrivateStoreSell", "SetPrivateStoreListSell"):
        return f"{prefix}Личный магазин (продажа)"
    if clean in ("S_PRIVATE_STORE_MANAGE_LIST", "PrivateStoreManageListSell"):
        return "Сервер: настройка личного магазина"
    if clean in ("S_PRIVATE_STORE_LIST", "PrivateStoreListSell"):
        return "Сервер: товары личного магазина"

    # ─── Предметы ──────────────────────────────────────────────
    if clean == "UseItem":
        return f"{prefix}Использование предмета"
    if clean == "RequestEnchantItem":
        return f"{prefix}Заточка предмета"
    if clean == "Action":
        return f"{prefix}Действие с объектом"
    if clean == "Attack":
        return f"{prefix}Атака цели"

    # ─── Скиллы ────────────────────────────────────────────────
    if clean in ("RequestMagicSkillUse", "MagicSkillUse"):
        return f"{prefix}Использование скилла"
    if clean in ("S_MAGIC_SKILL_USE", "MagicSkillUse") and direction == "S2C":
        return "Сервер: применение скилла"
    if clean == "RequestAcquireSkill":
        return f"{prefix}Изучение умения"
    if clean in ("S_SKILL_LIST", "SkillList"):
        return "Сервер: список умений"

    # ─── Сессия ────────────────────────────────────────────────
    if clean == "RequestRestart":
        return f"{prefix}Возврат к выбору персонажа"
    if clean == "RequestRestartPoint":
        return f"{prefix}Выбор точки воскрешения"

    # ─── Телепорт ──────────────────────────────────────────────
    if clean in ("S_TELEPORT_TO_LOCATION", "TeleportToLocation"):
        return "Телепорт"

    # ─── Чат ──────────────────────────────────────────────────
    if clean in ("Say2", "CreatureSay") and direction == "C2S":
        return f"{prefix}Сообщение в чат"
    if clean in ("S_SAY2", "Say2", "CreatureSay") and direction == "S2C" and data and len(data) >= 10:
        # Field parse надёжен только для sniff:* (plaintext после XOR).
        # Для game:* (relay carrier_plain) поля могут быть обфусцированы.
        is_sniff = name.startswith("sniff:")
        chat_type = _read_u32(data, 5) if is_sniff else -1
        chat_names = {0: "Все", 1: "Крик", 2: "Личное", 3: "Группа",
                      4: "Клан", 8: "Торговля", 15: "Герой", 17: "Осада"}
        if is_sniff and chat_type in chat_names:
            chat_label = chat_names[chat_type]
            try:
                rest = data[9:]
                char_name = _read_str16(rest, 0)
                off2 = len(char_name.encode('utf-16-le')) + 2
                text = _read_str16(rest, off2) if off2 < len(rest) else ""
                if char_name and text and len(char_name) < 30:
                    return f"[Чат:{chat_label}] {char_name}: {text[:80]}"
            except Exception:
                pass
            return f"[Чат:{chat_label}]"
        return "Чат: сообщение"

    # ─── NPC HTML ──────────────────────────────────────────────
    if clean in ("S_NPC_HTML_MESSAGE", "NpcHtmlMessage"):
        return "Сервер: диалог NPC"

    # ─── Почта ─────────────────────────────────────────────────
    if clean in ("RequestPackageSend", "RequestSendMail"):
        return f"{prefix}Отправка почты/посылки"

    # ─── Хна ───────────────────────────────────────────────────
    if clean == "RequestHennaEquip":
        return f"{prefix}Нанесение хны"
    if clean == "RequestHennaRemove":
        return f"{prefix}Снятие хны"
    if clean in ("RequestHennaItemList", "RequestHennaItemInfo",
                 "RequestHennaUnEquipList", "RequestHennaUnEquipInfo"):
        return f"{prefix}Просмотр хны"
    if "Henna" in clean and direction == "S2C":
        return None  # ambient S2C carrier — не спамить

    # ─── Предметы (S2C) ─────────────────────────────────────────
    if clean in ("S_INVENTORY_UPDATE", "InventoryUpdate"):
        return "Инвентарь обновлён"
    if clean in ("S_ITEMLIST", "ItemList"):
        return "Сервер: список предметов"

    # ─── Кристаллизация / Destroy ────────────────────────────────
    if clean == "RequestCrystallizeItem":
        return f"{prefix}Кристаллизация предмета"
    if clean == "RequestDestroyItem":
        return f"{prefix}Уничтожение предмета"

    # ─── Клан / Альянс ──────────────────────────────────────────
    if clean in ("RequestJoinPledge", "RequestPledgeInfo"):
        return f"{prefix}Клан: запрос"
    if clean in ("RequestJoinAlly", "AllyLeave", "AllyDismiss"):
        return f"{prefix}Альянс: действие"

    # ─── Группа ─────────────────────────────────────────────────
    if clean == "RequestJoinParty":
        return f"{prefix}Приглашение в группу"
    if clean == "RequestAnswerJoinParty":
        return f"{prefix}Ответ на приглашение в группу"
    if clean in ("RequestWithDrawalParty", "RequestOustPartyMember"):
        return f"{prefix}Выход из группы"
    if clean in ("S_PARTY_SMALL_WINDOW_ALL", "PartySmallWindowAll"):
        return "Сервер: состав группы"

    # ─── Рецепты / Крафт ────────────────────────────────────────
    if clean in ("RequestRecipeItemMakeSelf", "RequestRecipeShopMakeItem"):
        return f"{prefix}Крафт предмета"
    if clean in ("RequestRecipeBookOpen", "RequestRecipeShopListSet"):
        return f"{prefix}Рецептурная книга"

    # ─── Семена / Manor ─────────────────────────────────────────
    if clean == "RequestBuySeed":
        return f"{prefix}Покупка семян"

    # ─── S2C FE extended — login sequence ──────────────────────
    if clean in ("S_EX_QUEUETICKET_LOGIN", "ExQueueTicketLogin"):
        return "Сервер: очередь входа"
    if clean in ("S_EX_BR_VERSION", "ExBrVersion"):
        return "Сервер: версия (BR)"
    if clean in ("S_EX_QUEUETICKET", "ExQueueTicket"):
        return "Сервер: позиция в очереди"

    # ─── Действие ──────────────────────────────────────────────
    if clean == "RequestActionUse":
        return f"{prefix}Использование действия"
    if clean == "DlgAnswer":
        return f"{prefix}Ответ на диалог"

    # ─── Зачарование (расширенные) ──────────────────────────────
    if "EnchantTargetItem" in clean or "EnchantSupportItem" in clean:
        return f"{prefix}Заточка: подготовка"
    if clean == "RequestExCancelEnchantItem":
        return f"{prefix}Заточка: отмена"

    # ─── Покупка семян (множественная) ──────────────────────────
    if clean == "RequestRefundItem":
        return f"{prefix}Возврат предмета"

    # ─── S2C значимые события (из дампа памяти l2_opcodes.json) ─
    if clean == "S_TELEPORT_TO_LOCATION":
        return "Телепорт"
    if clean == "S_GET_ITEM":
        return "Получен предмет"
    if clean == "S_DROP_ITEM":
        return "Предмет выброшен"
    if clean == "S_SPAWN_ITEM":
        return "Предмет появился"
    if clean == "S_BUY_LIST":
        return "Сервер: список покупки"
    if clean == "S_MAGIC_SKILL_USE":
        return "Скилл применён"
    if clean == "S_MAGIC_SKILL_LAUNCHED":
        return "Скилл запущен"
    if clean == "S_ATTACK":
        return "Атака"
    if clean == "S_SYSTEM_MESSAGE":
        return "Системное сообщение"
    if clean in ("S_TRADE_OWN_ADD", "S_TRADE_OTHER_ADD"):
        return "Обмен: предмет добавлен"
    if clean == "S_TRADE_DONE":
        return "Обмен завершён"
    if clean == "S_TRADE_START":
        return "Начало обмена"
    if clean == "S_WAREHOUSE_DEPOSIT_LIST":
        return "Сервер: склад (депозит)"
    if clean == "S_WAREHOUSE_WITHDRAW_LIST":
        return "Сервер: склад (изъятие)"
    if clean in ("S_ENCHANT_RESULT", "S_EX_ENCHANT_ONE_OK", "S_EX_ENCHANT_ONE_FAIL"):
        return "Результат заточки"
    if clean == "S_ACQUIRE_SKILL_DONE":
        return "Скилл изучен"
    if clean == "S_NPC_SAY":
        return "NPC говорит"
    if clean in ("S_PARTY_MEMBER_POSITION", "S_PARTY_SPELL_INFO"):
        return None  # ambient party data
    if clean in ("S_QUEST_LIST", "S_QUEST_COMPLETED"):
        return "Квест обновлён"
    if clean == "S_MULTISELL_LIST":
        return "Сервер: мультиселл лист"
    if clean in ("S_PLEDGE_POWER_GRADE_LIST", "S_PLEDGE_SHOW_MEMBER_LIST_ALL"):
        return "Клан: данные"
    if clean in ("S_EX_SHOW_SCREEN_MESSAGE", "S_TUTORIAL_SHOW_HTML"):
        return "Системное уведомление"
    if clean == "S_RECIPE_SHOP_ITEM_INFO":
        return "Сервер: крафт рецепт"

    # ─── Fallback: inject всегда показываем ────────────────────
    if is_inject and clean:
        return f"{prefix}{clean}"

    # ─── Catch-all: ТОЛЬКО для sniff/inject (правильные опкоды) ───
    # C2S opcode table из L2J Mobius НЕ совпадает с live Innova!
    # game:C2S имена ЛОЖНЫЕ — показываем только через sniff/inject.
    # S2C из дампа памяти ПРАВИЛЬНАЯ, но через relay всё равно ambient noise.
    # Catch-all: только sniff: и INJECT: пакеты.
    if (name.startswith("sniff:") or name.startswith("INJECT:")) \
       and clean and not clean.startswith("0x"):
        # S2C blacklist: ambient шум
        _AMBIENT_BLACKLIST = {
            "Logout",  # padding/noise на relay (opcode 0x00)
            "GameGuardReply", "S_GAMEGUARD_QUERY",
            "CannotMoveAnymore", "CannotMoveAnymoreInVehicle",
            "S_STATUS_UPDATE", "S_MOVE_TO_LOCATION", "S_VALIDATE_LOCATION",
            "S_NPC_INFO", "S_CHAR_INFO", "S_USER_INFO",
            "S_STOP_MOVE", "S_MOVE_TO_PAWN", "S_TARGET_SELECTED",
            "S_TARGET_UNSELECTED", "S_SOCIAL_ACTION",
            "S_CHANGE_MOVE_TYPE", "S_CHANGE_WAIT_TYPE",
            "S_ABNORMAL_STATUS_UPDATE", "S_DELETE_OBJECT",
            "S_SUNRISE", "S_SUNSET",
            "S_ATTACK_OUT_OF_RANGE", "S_ATTACK_IN_COOLTIME",
            "S_ATTACK_DEAD_TARGET", "S_ACTION_FAIL",
            "S_SERVER_CLOSE", "S_NET_PING",
            "S_START_ROTATING", "S_STOP_ROTATING", "S_FINISH_ROTATING",
            "S_SSQ_STATUS", "S_PETITION_VOTE", "S_AGIT_DECO_INFO",
            "S_DIE", "S_REVIVE", "S_COMBAT_MODE_START", "S_COMBAT_MODE_FINISH",
            "S_ABNORMAL_VISUAL_EFFECT", "S_CLIENT_SETTIME",
            "S_PARTY_MEMBER_POSITION", "S_PARTY_SMALL_WINDOW_UPDATE",
            "S_VALIDATE_LOCATION_IN_VEHICLE", "S_VEHICLE_CHECK_LOCATION",
            "S_EVENT_TRIGGER", "S_RELATION_CHANGED", "S_NICKNAME_CHANGED",
            "S_PLEDGE_STATUS_CHANGED", "S_PLEDGE_INFO",
            "S_MY_TARGET_SELECTED", "S_SETUP_GAUGE",
            "S_HENNA_INFO", "S_HENNA_ITEM_INFO", "S_HENNA_EQUIP_LIST",
            "S_SKILL_COOL_TIME", "S_ETC_STATUS_UPDATE",
            "S_SHORT_BUFF_STATUS_UPDATE", "S_DOOR_STATUS_UPDATE",
            "S_FRIEND_LIST", "S_FRIEND_STATUS", "S_BLOCK_PACKET_LIST",
            "S_PLEDGE_EXTENDED_INFO", "S_PLEDGE_SHOW_INFO_UPDATE",
            "RequestPledgeCrest", "RequestAllianceCrest",
            "RequestPrivateStoreQuitSe", "RequestWithdrawalPledge",
            "RequestShortCutDel", "RequestShortCutReg",
            "RequestFriendDel", "RequestFriendList",
            "RequestSiegeDefenderList", "RequestSiegeAttackerList",
            "RequestJoinSiege", "RequestConfirmSiegeWaitingList",
            "RequestSetCastleSiegeTime",
            "AllyLeave", "AllyDismiss",
            "RequestDismissAlly",
            "RequestMoveToLocationInVe",
            "RequestBlock", "RequestTutorialPassCmdToS",
            "RequestPrivateStoreManage",
            "RequestHennaRemoveList",
            # Периодический спам клиента
            "RequestLinkHtml", "RequestSendFriendMsg",
            "RequestExFriendDetailInfo", "RequestFriendDetailInfo",
            "BypassUserCmd", "SendBypassBuildCmd",
            "RequestShowBoard", "RequestBBSwrite",
            "RequestAutoSoulShot", "RequestAutoPlay",
            "RequestTargetCanceld", "RequestTargetActionMenu",
            "RequestExAutoFish", "RequestPledgePower",
            "RequestPledgePowerGradeList",
            "RequestAcquireSkillInfo", "RequestSkillList",
            "RequestMagicSkillList", "RequestGMList",
            "RequestPartyMatchConfig", "RequestPartyMatchList",
            "RequestManorList", "RequestSeedSetting",
            "RequestProcureCropList", "RequestSetSeed",
            "RequestSetCrop", "RequestWriteHeroWords",
            "RequestExOlympiadMatchList",
            "RequestExMPCCShowPartyMembersInfo",
            "RequestPledgeMemberInfo",
            "RequestExBlockDetail", "RequestBlockListDetail",
            "RequestRecipeBookOpen", "RequestRecipeBookDestroy",
            "RequestQuestList", "RequestQuestAbort",
            "RequestTutorialLinkHtml", "RequestTutorialQuestionMark",
            "RequestTutorialClientEvent",
            "RequestPetition", "RequestPetitionCancel",
            "RequestGiveNickName", "RequestChangePetName",
            "RequestShowMiniMap", "RequestRecordInfo",
            "RequestSaveBookMarkSlot", "RequestDeleteBookMarkSlot",
            "RequestModifyBookMarkSlot", "RequestTeleportBookMark",
            # S2C ambient events не пойманные ранее
            "S_SPAWN_ITEM", "S_DROP_ITEM",
            "S_NPC_INFO_ABNORMALVISUA", "S_NPC_INFO_STATE",
            "S_DOOR_INFO", "S_VEHICLE_INFO", "S_VEHICLE_START_PACKET",
            "S_SUMMON_INFO", "S_PET_INFO", "S_PET_STATUS_UPDATE",
            "S_PET_STATUS_SHOW", "S_PET_ITEMLIST", "S_PET_INVENTORY_UPDATE",
            "S_OBSERVER_START", "S_OBSERVER_END",
            "S_CASTLE_SIEGE_INFO", "S_CASTLE_SIEGE_ATTACKER_",
            "S_CASTLE_SIEGE_DEFENDER_",
            "S_ALLIANCE_INFO", "S_ASK_JOIN_ALLIANCE",
            "S_ALLIANCE_CREST", "S_PLEDGE_CREST",
            "S_RECIPE_BOOK_ITEM_LIST",
            "S_SHOW_BOARD", "S_SHOW_MINIMAP",
            "S_SHOW_RADAR", "S_DELETE_RADAR",
            "S_CONFIRM_DLG", "S_SHOW_CALC",
            "S_L2_FRIEND_LIST", "S_L2_FRIEND", "S_L2_FRIEND_STATUS",
            "S_CAMERA_MODE", "S_SPECIAL_CAMERA", "S_NORMAL_CAMERA",
            "S_SKILL_REMAIN_SEC", "S_SET_SUMMON_REMAIN_TIME",
            "S_EARTHQUAKE", "S_FLY_TO_LOCATION",
            "S_CLIENT_ACTION", "S_RIDE",
            "S_DICE", "S_SNOOP",
            "S_CHAIR_SIT", "S_GM_HIDE",
            "S_PACKAGE_TO_LIST", "S_PACKAGE_SENDABLE_LIST",
            "S_MACRO_LIST", "S_SHORTCUT_REG", "S_INIT_SHORTCUT",
            "S_SHORTCUT_DELETE",
            "S_PLAY_SOUND", "S_STATIC_OBJECT_INFO",
            "S_RADAR_CONTROL", "S_MONRACE_INFO",
            "S_SELL_LIST_PROCURE", "S_BUY_LIST_SEED",
            "S_BUY_PREVIEW_LIST", "S_BUY_PREVIEW_INFO",
            "S_SHOW_XMASSEAL", "S_MAX",
            "S_GM_VIEW_CHARACTER_INFO", "S_GM_VIEW_PLEDGE_INFO",
            "S_GM_VIEW_SKILL_INFO", "S_GM_VIEW_MAGIC_INFO",
            "S_GM_VIEW_QUEST_INFO", "S_GM_VIEW_ITEMLIST",
            "S_GM_VIEW_WAREHOUSE_WITH", "S_GM_HENNA_INFO",
            "S_SERVER_OBJECT_INFO",
            "S_PARTY_SMALL_WINDOW_ALL", "S_PARTY_SMALL_WINDOW_ADD",
            "S_PARTY_SMALL_WINDOW_DEL", "S_PARTY_SPELLED_INFO",
            "S_LIST_PARTY_WAITING", "S_PARTY_ROOM_INFO",
            "S_PLEDGE_SHOW_MEMBER_LIS",
            "S_VEHICLE_DEPARTURE", "S_VEHICLE_CHECK_LOCATION",
            "S_MOVE_TO_LOCATION_IN_VE", "S_STOP_MOVE_IN_VEHICLE",
            "S_GETON_VEHICLE", "S_GETOFF_VEHICLE",
            "S_TUTORIAL_SHOW_HTML", "S_SHOW_TUTORIAL_MARK",
            "S_TUTORIAL_ENABLE_CLIENT", "S_TUTORIAL_CLOSE_HTML",
            "S_EX_SUBJOB_INFO", "S_EX_USER_BAN_INFO",
            "S_EX_BR_SERVER_ID_LIST",
        }
        if clean not in _AMBIENT_BLACKLIST:
            # Формируем человекочитаемое описание
            if direction == "C2S":
                return f"{clean}"
            else:
                return f"Сервер: {clean}"

    return None  # не интересно


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

/* ─── Game log ─── */
.gl-entry{padding:2px 0;border-bottom:1px solid rgba(28,35,51,0.3)}
.gl-ts{color:var(--fg3);font-size:10px;margin-right:6px}
.gl-c2s{color:var(--accent)}
.gl-s2c{color:var(--purple)}
.gl-inject{color:var(--orange);font-weight:600}
.gl-chat{color:var(--green)}
.gl-system{color:var(--yellow)}
.gl-trade{color:var(--cyan)}

/* ─── Category markers (single view) ─── */
.pkt-table tr.cat-action{border-left:2px solid var(--green)}
.pkt-table tr.cat-world{border-left:2px solid var(--fg3)}
.pkt-table tr.cat-system{border-left:2px solid var(--yellow)}

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
  <!-- Left: SPLIT packet tables -->
  <div class="panel-left" style="display:flex;flex-direction:column">
    <div class="toolbar">
      <input class="tb-input" id="filterInput" type="text" placeholder="&#x1F50D; Filter: name, opcode, hex...">
      <select class="tb-select" id="dirFilter">
        <option value="all">All</option>
        <option value="C2S">C2S</option>
        <option value="S2C">S2C</option>
      </select>
      <select class="tb-select" id="catFilter">
        <option value="all">All Categories</option>
        <option value="action">Actions Only</option>
        <option value="world">World Only</option>
        <option value="system">System Only</option>
      </select>
      <select class="tb-select" id="viewMode">
        <option value="split">Split View</option>
        <option value="single">Single Stream</option>
      </select>
      <div class="tb-gap"></div>
      <button class="tb-btn" id="btnAutoScroll" onclick="toggleAuto()">Auto-scroll ON</button>
      <button class="tb-btn" id="btnPause" onclick="togglePause()">Pause</button>
      <button class="tb-btn danger" onclick="clearAll()">Clear</button>
    </div>
    <!-- Split view: two columns -->
    <div id="splitView" style="flex:1;display:flex;overflow:hidden">
      <!-- Actions column -->
      <div style="flex:1;display:flex;flex-direction:column;border-right:1px solid var(--border)">
        <div style="background:var(--bg2);padding:4px 8px;font-size:10px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between">
          <span>Player Actions</span><span id="cntActions" style="color:var(--fg2)">0</span>
        </div>
        <div class="pkt-wrap" id="pktWrapActions">
          <table class="pkt-table"><thead><tr>
            <th style="width:32px">#</th><th style="width:55px">Time</th><th style="width:30px">Dir</th>
            <th style="width:54px">Op</th><th style="width:140px">Name</th><th style="width:36px">Sz</th><th>Data</th>
          </tr></thead><tbody id="pktBodyActions"></tbody></table>
        </div>
      </div>
      <!-- World column -->
      <div style="flex:1;display:flex;flex-direction:column">
        <div style="background:var(--bg2);padding:4px 8px;font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between">
          <span>World / System</span><span id="cntWorld" style="color:var(--fg2)">0</span>
        </div>
        <div class="pkt-wrap" id="pktWrapWorld">
          <table class="pkt-table"><thead><tr>
            <th style="width:32px">#</th><th style="width:55px">Time</th><th style="width:30px">Dir</th>
            <th style="width:54px">Op</th><th style="width:140px">Name</th><th style="width:36px">Sz</th><th>Data</th>
          </tr></thead><tbody id="pktBodyWorld"></tbody></table>
        </div>
      </div>
    </div>
    <!-- Single view (hidden by default) -->
    <div id="singleView" style="flex:1;overflow:hidden;display:none">
      <div class="pkt-wrap" id="pktWrap">
        <table class="pkt-table"><thead><tr>
          <th style="width:40px">#</th><th style="width:65px">Time</th><th style="width:36px">Dir</th>
          <th style="width:64px">Opcode</th><th style="width:150px">Name</th><th style="width:44px">Size</th><th>Data</th>
        </tr></thead><tbody id="pktBody"></tbody></table>
      </div>
    </div>
    <div class="statusbar">
      <span>Actions: <b id="statActions">0</b></span>
      <span>World: <b id="statWorld">0</b></span>
      <span>Total: <b id="statShown">0</b></span>
      <span>BF: <b id="statBF">--</b></span>
      <span>XOR: <b id="statXOR">--</b></span>
      <span>Target: <b id="statTarget">--</b></span>
    </div>
  </div>

  <!-- Right panel -->
  <div class="panel-right">
    <div class="tabs">
      <div class="tab active" data-tab="details" onclick="switchTab('details',this)">Details</div>
      <div class="tab" data-tab="gamelog" onclick="switchTab('gamelog',this)">Game Log</div>
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

      <!-- Game Log -->
      <div class="tab-pane" id="pane-gamelog" style="overflow-y:auto;padding:0">
        <div id="gameLogArea" style="padding:4px 8px;font-size:12px;line-height:1.8">
          <div class="empty"><div class="icon">&#127918;</div>Game events will appear here</div>
        </div>
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
let nActions=0, nWorld=0;

function conn(){
  ws=new WebSocket(WS+location.host+'/ws');
  ws.onopen=()=>{addLog('WebSocket connected','ok');};
  ws.onclose=()=>{addLog('WebSocket disconnected','err');setTimeout(conn,2000);};
  ws.onmessage=e=>{
    const m=JSON.parse(e.data);
    if(m.type==='packet') onPacket(m.data);
    else if(m.type==='gamelog') onGameLog(m.data);
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
  const cf=$('catFilter').value;
  if(cf!=='all'&&(p.category||'unknown')!==cf) return false;
  const t=$('filterInput').value.toLowerCase();
  if(!t) return true;
  return (p.name||'').toLowerCase().includes(t)||(p.opcode_hex||'').toLowerCase().includes(t)||(p.preview||'').toLowerCase().includes(t);
}

function isActionPkt(p){
  const c=p.category||'unknown';
  return c==='action'||c==='service'||p.injected;
}

function addRow(p){
  const isSplit=$('viewMode').value==='split';
  const dc=p.dir==='C2S'?'dir-c2s':'dir-s2c';
  const html=`<td>${p.seq}</td><td>${p.time||''}</td><td class="${dc}">${p.dir}</td><td>${p.opcode_hex||''}</td><td class="pkt-name" title="${p.name||''}">${p.name||'?'}</td><td>${p.size||0}</td><td style="color:var(--fg3)" title="${p.preview||''}">${(p.preview||'').substring(0,50)}</td>`;

  if(isSplit){
    const isAct=isActionPkt(p);
    const tb=isAct?$('pktBodyActions'):$('pktBodyWorld');
    const wr=isAct?$('pktWrapActions'):$('pktWrapWorld');
    const tr=document.createElement('tr');
    tr.className=(p.injected?'injected ':'')+(selSeq===p.seq?'sel':'');
    tr.dataset.seq=p.seq;
    tr.onclick=()=>selectPkt(p);
    tr.innerHTML=html;
    tb.appendChild(tr);
    if(isAct){nActions++;$('cntActions').textContent=nActions;$('statActions').textContent=nActions;}
    else{nWorld++;$('cntWorld').textContent=nWorld;$('statWorld').textContent=nWorld;}
    if(autoScroll) wr.scrollTop=wr.scrollHeight;
  } else {
    const tb=$('pktBody'),tr=document.createElement('tr');
    const catClass=p.category==='action'?' cat-action':p.category==='world'?' cat-world':p.category==='system'?' cat-system':'';
    tr.className=(p.injected?'injected ':'')+(selSeq===p.seq?'sel':'')+catClass;
    tr.dataset.seq=p.seq;
    tr.onclick=()=>selectPkt(p);
    tr.innerHTML=html;
    tb.appendChild(tr);
    if(autoScroll) $('pktWrap').scrollTop=$('pktWrap').scrollHeight;
  }
  $('statShown').textContent=packets.filter(matchFilter).length;
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
  if(s.divert){$('ledDivert').className='led led-on';$('txtDivert').textContent='WinDivert: active'+(s.sniffer?' + Sniff 7777':'');}
  else if(s.sniffer){$('ledDivert').className='led led-on';$('txtDivert').textContent='Sniffer 7777: active';}
  else{$('ledDivert').className='led led-off';$('txtDivert').textContent='WinDivert: off';}
}
function onCrypto(c){
  const led=$('ledCrypto'),txt=$('txtCrypto');
  if(c.initialized){led.className='led led-on';txt.textContent='Crypto: OK';
    $('statBF').textContent=(c.bf_key||'').substring(0,12)+'...';
    $('statXOR').textContent=(c.xor_key||'').substring(0,12)+'...';
  }else{led.className='led led-off';txt.textContent='Crypto: waiting';}
}
function onInjectResult(r){if(r.error)addLog('Inject error: '+r.error,'err');else addLog('Injected: '+JSON.stringify(r),'ok');}

// Game Log
function onGameLog(d){
  const a=$('gameLogArea');
  if(a.querySelector('.empty'))a.innerHTML='';
  const div=document.createElement('div');
  div.className='gl-entry';
  let cls='gl-c2s';
  if(d.dir==='S2C') cls='gl-s2c';
  if(d.text.includes('INJECT')) cls='gl-inject';
  if(d.text.includes('[Чат:')) cls='gl-chat';
  if(d.text.includes('Системное') || d.text.includes('Сервер:')) cls='gl-system';
  if(d.text.includes('обмен') || d.text.includes('магазин') || d.text.includes('Покупка') || d.text.includes('Продажа') || d.text.includes('склад')) cls='gl-trade';
  div.innerHTML=`<span class="gl-ts">${d.time||''}</span><span class="${cls}">${d.text}</span>`;
  a.appendChild(div);
  if(a.children.length>500)a.removeChild(a.firstChild);
  a.scrollTop=a.scrollHeight;
}

// Controls
function toggleAuto(){autoScroll=!autoScroll;const b=$('btnAutoScroll');b.textContent='Auto-scroll '+(autoScroll?'ON':'OFF');b.classList.toggle('active',autoScroll);}
function togglePause(){paused=!paused;const b=$('btnPause');b.textContent=paused?'Resume':'Pause';b.classList.toggle('active',paused);}
function clearAll(){packets=[];cC2S=cS2C=nActions=nWorld=0;$('pktBody').innerHTML='';$('pktBodyActions').innerHTML='';$('pktBodyWorld').innerHTML='';$('cntC2S').textContent='0';$('cntS2C').textContent='0';$('cntTotal').textContent='0';$('cntActions').textContent='0';$('cntWorld').textContent='0';$('statShown').textContent='0';$('statActions').textContent='0';$('statWorld').textContent='0';}

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

// Filter & view mode
$('filterInput').addEventListener('input',rebuild);
$('dirFilter').addEventListener('change',rebuild);
$('catFilter').addEventListener('change',rebuild);
$('viewMode').addEventListener('change',function(){
  const s=$('viewMode').value==='split';
  $('splitView').style.display=s?'flex':'none';
  $('singleView').style.display=s?'none':'';
  rebuild();
});
function rebuild(){$('pktBody').innerHTML='';$('pktBodyActions').innerHTML='';$('pktBodyWorld').innerHTML='';nActions=nWorld=0;packets.filter(matchFilter).forEach(addRow);}

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
        self.divert = None   # WinDivertRedirector reference (set from main)
        self.sniffer = None  # WinDivertSniffer reference (set from main)

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
        self.log(f"WS client connecting...")

        # Отправить начальный статус ДО добавления в clients
        await self._send_status(ws)

        # Отправить историю и обновить _last_seq ДО добавления в broadcast list
        # (иначе broadcast loop может отправить дубли)
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
                direction = pkt.get("dir", "C2S")
                category = classify_packet(direction, opcode_int, name)
                msg = {"type": "packet", "data": {
                    "seq": seq,
                    "time": ts,
                    "dir": direction,
                    "opcode_hex": opcode_hex,
                    "name": name,
                    "size": size,
                    "dec_hex": dec_hex,
                    "raw_hex": pkt.get("raw_hex", ""),
                    "preview": preview,
                    "injected": "INJECT" in (name or ""),
                    "category": category,
                }}
                await ws.send_json(msg)
            except Exception:
                break
        # Теперь добавляем в broadcast list — все последующие пакеты пойдут через broadcast loop
        self.ws_clients.add(ws)
        self.log(f"WS client connected ({len(self.ws_clients)}), sent {len(recent)} history packets")

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
        status = {"running": False, "connected": False, "target": "", "divert": False, "sniffer": False}
        if self.proxy:
            status["running"] = self.proxy.running
            status["connected"] = getattr(self.proxy, 'connected', False)
            t = self.proxy._get_target() if hasattr(self.proxy, '_get_target') else ("", 0)
            status["target"] = f"{t[0]}:{t[1]}"
        # WinDivert: проверяем наличие объекта И его running-атрибут
        divert_obj = self.divert
        sniffer_obj = self.sniffer
        if divert_obj is not None:
            status["divert"] = bool(getattr(divert_obj, 'running', False))
        if sniffer_obj is not None:
            status["sniffer"] = bool(getattr(sniffer_obj, 'running', False))
        self.log(f"[status] proxy.running={status['running']} connected={status['connected']} "
                 f"divert={status['divert']} sniffer={status['sniffer']} "
                 f"divert_obj={divert_obj is not None} sniffer_obj={sniffer_obj is not None}",
                 "debug")
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
                raw = bytes.fromhex(hex_data)
                parsed = self.pkt_db.parse_packet(raw, direction)
                # Fallback: если INI не дал полей, используем hardcoded parsers
                if (not parsed.get("fields") or len(parsed.get("fields", [])) == 0) \
                        and direction == "C2S" and raw:
                    from _engine import _parse_known_c2s
                    known = _parse_known_c2s(raw[0], raw)
                    if known:
                        # Определяем источник: sniff (чистый) vs game (carrier_plain)
                        pkt_name = data.get("name", "") if isinstance(data, dict) else ""
                        is_sniff = "sniff:" in str(pkt_name) or "INJECT:" in str(pkt_name)
                        parsed["fields"] = [
                            {"name": k, "type": "d" if isinstance(v, int) else
                             "list" if isinstance(v, list) else "?",
                             "value": v,
                             "display": str(v)}
                            for k, v in known.items()
                        ]
                        if is_sniff:
                            parsed["note"] = "Clean values (sniff/inject)"
                        else:
                            parsed["note"] = "Field values from relay carrier_plain (may be obfuscated)"
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

                new_pkts = self.store.get_since_seq(self._last_seq, max_count=500)

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

                    category = classify_packet(direction, opcode_int, name)
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
                        "category": category,
                    }}
                    await self._broadcast(msg)

                    # Game log — интерпретация пакета в человекочитаемый текст
                    gl_text = interpret_packet(direction, opcode_int, name, dec_hex)
                    if gl_text:
                        await self._broadcast({"type": "gamelog", "data": {
                            "time": ts, "dir": direction, "text": gl_text,
                            "opcode": opcode_hex, "seq": pkt.get("seq", 0),
                        }})

            except Exception as e:
                self.log(f"[broadcast] ERROR: {e}", "err")
                import traceback
                traceback.print_exc(file=sys.stderr)
                await asyncio.sleep(1)

    async def _broadcast_status_all(self):
        status = {"running": False, "connected": False, "target": "", "divert": False, "sniffer": False}
        if self.proxy:
            status["running"] = self.proxy.running
            status["connected"] = getattr(self.proxy, 'connected', False)
            t = self.proxy._get_target() if hasattr(self.proxy, '_get_target') else ("", 0)
            status["target"] = f"{t[0]}:{t[1]}"
        if self.divert and getattr(self.divert, 'running', False):
            status["divert"] = True
        if self.sniffer and getattr(self.sniffer, 'running', False):
            status["sniffer"] = True

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
                    "passthrough": c.passthrough,
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

        # ═══ WAREHOUSE RACE HOOK API ═══
        if action == "race_hook":
            from _engine import _RACE_HOOK
            if "enabled" in data:
                _RACE_HOOK["enabled"] = bool(data["enabled"])
            if "count" in data:
                _RACE_HOOK["count"] = int(data["count"])
            if "opcode" in data:
                _RACE_HOOK["opcode"] = int(data["opcode"], 16) if isinstance(data["opcode"], str) else int(data["opcode"])
            if data.get("reset"):
                _RACE_HOOK["fired"] = False
                _RACE_HOOK["log"] = []
            return web.json_response({
                "enabled": _RACE_HOOK["enabled"],
                "opcode": f"0x{_RACE_HOOK['opcode']:02X}",
                "count": _RACE_HOOK["count"],
                "fired": _RACE_HOOK["fired"],
                "log": _RACE_HOOK["log"],
            })

        # ═══ MULTISELL CAPTURE + REPLAY API ═══
        if action == "multisell_cap":
            from _engine import _MULTISELL_CAP, multisell_replay_modify, wrap_relay_0x06
            import struct as _struct

            sub = data.get("sub", "status")

            if sub == "status":
                return web.json_response({
                    "enabled": _MULTISELL_CAP["enabled"],
                    "count": len(_MULTISELL_CAP["captured"]),
                    "captured": _MULTISELL_CAP["captured"][-5:],
                })

            if sub == "clear":
                _MULTISELL_CAP["captured"] = []
                return web.json_response({"ok": True})

            if sub == "replay":
                # Replay last captured packet (exact copy or modified)
                caps = _MULTISELL_CAP["captured"]
                if not caps:
                    return web.json_response({"error": "No captured MultiSellChoose packets"}, status=400)

                idx = int(data.get("idx", -1))
                cap = caps[idx]
                game_hex = cap["game_hex"]

                new_entry = data.get("entry_id")
                old_entry = data.get("old_entry_id")
                new_amount = data.get("amount")
                old_amount = data.get("old_amount")
                count = int(data.get("count", 1))

                if new_entry is not None or new_amount is not None:
                    game_body = multisell_replay_modify(
                        game_hex,
                        new_entry_id=int(new_entry) if new_entry is not None else None,
                        old_entry_id=int(old_entry) if old_entry is not None else None,
                        new_amount=int(new_amount) if new_amount is not None else None,
                        old_amount=int(old_amount) if old_amount is not None else None,
                    )
                else:
                    game_body = bytes.fromhex(game_hex)

                # Wrap and inject
                wrapped = wrap_relay_0x06(game_body)
                pkt_len = len(wrapped) + 2
                single_l2 = _struct.pack("<H", pkt_len) + wrapped
                burst = single_l2 * count

                if self.proxy and hasattr(self.proxy, 'server_sock') and self.proxy.server_sock:
                    import threading
                    lock = getattr(self.proxy, 'relay_server_lock', threading.Lock())
                    with lock:
                        self.proxy.server_sock.sendall(burst)
                    return web.json_response({
                        "ok": True,
                        "copies": count,
                        "game_len": len(game_body),
                        "modified": new_entry is not None or new_amount is not None,
                        "game_hex": game_body.hex()[:64],
                    })
                else:
                    # Нет активного соединения — inject_c2s в PLAINTEXT_INTERMEDIATE
                    # режиме НЕ работает (relay оборачивает в 0x06, сервер XOR-декодирует
                    # мусор). Сообщаем об ошибке — нельзя слать без server_sock.
                    return web.json_response({
                        "error": "not_connected",
                        "msg": "server_sock is None — нет активной relay-сессии. Дождитесь подключения игрока.",
                    }, status=503)

            return web.json_response({"error": f"Unknown sub: {sub}"}, status=400)

        # ═══ UNIVERSAL GAME BODY CAPTURE API ═══
        if action == "game_cap":
            from _engine import _GAME_CAP, wrap_relay_0x06
            import struct as _struct

            sub = data.get("sub", "status")

            if sub == "status":
                caps = _GAME_CAP["captured"]
                # Filter by min_len, first_byte, time range
                min_len = int(data.get("min_len", 0))
                max_len = int(data.get("max_len", 99999))
                first_byte = data.get("first_byte")  # hex string like "b0"
                since = data.get("since")  # timestamp like "00:05:00"
                limit = int(data.get("limit", 50))

                filtered = []
                for c in caps:
                    if c["game_len"] < min_len or c["game_len"] > max_len:
                        continue
                    if first_byte is not None and c["first_byte"] != int(first_byte, 16):
                        continue
                    if since and c["ts"] < since:
                        continue
                    filtered.append(c)

                return web.json_response({
                    "total_captured": len(caps),
                    "total_unique_seen": len(_GAME_CAP["_seen_hashes"]),
                    "filtered": len(filtered),
                    "packets": filtered[-limit:],
                })

            if sub == "clear":
                _GAME_CAP["captured"] = []
                _GAME_CAP["_seen_hashes"] = set()
                return web.json_response({"ok": True})

            if sub == "replay":
                # Replay specific captured game_body by index or game_hex
                caps = _GAME_CAP["captured"]
                idx = data.get("idx")
                game_hex = data.get("game_hex")
                count = int(data.get("count", 1))

                if game_hex:
                    game_body = bytes.fromhex(game_hex)
                elif idx is not None:
                    game_body = bytes.fromhex(caps[int(idx)]["game_hex"])
                else:
                    return web.json_response({"error": "Need idx or game_hex"}, status=400)

                # Optional XOR field modification
                mods = data.get("xor_mods")  # list of {offset, old_hex, new_hex}
                if mods:
                    game_body = bytearray(game_body)
                    for m in mods:
                        off = int(m["offset"])
                        old_b = bytes.fromhex(m["old_hex"])
                        new_b = bytes.fromhex(m["new_hex"])
                        for i in range(min(len(old_b), len(new_b))):
                            if off + i < len(game_body):
                                game_body[off + i] ^= old_b[i] ^ new_b[i]
                    game_body = bytes(game_body)

                wrapped = wrap_relay_0x06(game_body)
                pkt_len = len(wrapped) + 2
                single_l2 = _struct.pack("<H", pkt_len) + wrapped
                burst = single_l2 * count

                if self.proxy and hasattr(self.proxy, 'server_sock') and self.proxy.server_sock:
                    import threading
                    lock = getattr(self.proxy, 'relay_server_lock', threading.Lock())
                    with lock:
                        self.proxy.server_sock.sendall(burst)
                    return web.json_response({
                        "ok": True,
                        "copies": count,
                        "game_len": len(game_body),
                        "game_hex": game_body.hex()[:80],
                    })
                else:
                    return web.json_response({"error": "No server socket"}, status=500)

            return web.json_response({"error": f"Unknown sub: {sub}"}, status=400)

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
    divert = None
    sniffer = None
    if args.divert:
        divert = engine.WinDivertRedirector(engine.PROXY_PORT)
        threading.Thread(target=divert.run, daemon=True, name="divert").start()
        # Пассивный сниффер порта 7777 (без перехвата)
        sniffer = engine.WinDivertSniffer(store, proxy=proxy)
        threading.Thread(target=sniffer.run, daemon=True, name="sniff-7777").start()
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

    # 7. Web GUI — запуск в отдельном потоке с авто-перезапуском.
    # Если WebServer упадёт → перезапустится. WinDivert и relay-proxy НЕ трогаются.
    server = WebServer(pkt_db, proxy, store, args.port)
    server.divert = divert
    server.sniffer = sniffer

    def _run_webserver():
        while True:
            try:
                asyncio.run(server.start())
            except KeyboardInterrupt:
                return
            except Exception as e:
                print(f"[WEBSERVER] Crashed: {e}, restart in 3s...", file=sys.stderr)
                time.sleep(3)

    t_web = threading.Thread(target=_run_webserver, daemon=True, name="webserver")
    t_web.start()

    # Основной поток держит процесс живым (daemon-треды умирают вместе с ним)
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[EXIT] Bye", file=sys.stderr)


if __name__ == "__main__":
    main()
