#!/usr/bin/env python
"""
L2 MCP Proxy v3 — Lineage 2 MITM-перехватчик пакетов + MCP сервер для Claude.

Архитектура:
  Game Client ←→ WinDivert (ядро, прозрачный redirect) ←→ L2MitmProxy ←→ Real Server
                                                              ↕
                                                     MCP Server (stdio)
                                                              ↕
                                                        Claude Agent

Крипто-пайплайн (Ertheia+):
  Отправка (C→S): plaintext → XOR encrypt → Blowfish ECB encrypt → TCP
  Приём   (S→C): TCP → Blowfish ECB decrypt → XOR decrypt → plaintext
  KeyInit (0x2E, первый S→C) всегда в открытом виде.

Для инъекции используются 4 независимых XOR state (client_c2s, server_c2s,
server_s2c, client_s2c) с полным re-encrypt обоих направлений.

Авторизованный пентест Innova/4Game, Dec 2025 - Mar 2026.
"""

import asyncio
import socket
import struct
import threading
import json
import sys
import os
import time
import copy
import argparse
from datetime import datetime
from collections import deque
from typing import Optional, Tuple, Dict, Any

# ═══════════════════════════════════════════════════════════════════════════════
# Конфигурация
# ═══════════════════════════════════════════════════════════════════════════════

# ДИАГНОСТИКА: 7777 убран — клиент пойдёт напрямую к game server
# Если заработает — значит прокси мешает подключению к 7777
GAME_PORTS = {2106, 17453} | set(range(7900, 7921))
PROXY_PORT = 17777
LISTEN_HOST = "0.0.0.0"
DEFAULT_TARGET = ("5.63.132.147", 2106)
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_DIR = os.path.join(_APP_DIR, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)
TARGET_FILE = os.path.join(_LOG_DIR, "l2_proxy_target.txt")
LOG_FILE = os.path.join(_LOG_DIR, "l2_mcp.log")
DEBUG_FILE = os.path.join(_LOG_DIR, "l2_debug.log")

# Фиксированный диапазон портов для proxy→server соединений.
# Эти порты ИСКЛЮЧЕНЫ из WinDivert фильтра — трафик не перехватывается.
PROXY_OUT_PORT_BASE = 18000
PROXY_OUT_PORT_MAX = 18099
_proxy_out_port_next = PROXY_OUT_PORT_BASE

# IP которые НЕ надо NAT'ить (placeholder из L2.ini, недоступны)
SKIP_DST_IPS = {"10.10.10.10"}


def _dbg(msg: str):
    """Пишет отладочное сообщение в DEBUG_FILE и stderr."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line, file=sys.stderr)
    try:
        with open(DEBUG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
    except Exception:
        pass

# Динамическое отслеживание proxy→server портов
# WinDivert проверяет этот set и пропускает proxy трафик без NAT
_proxy_out_ports: set = set()
_proxy_out_ports_lock = threading.Lock()

# NAT таблица: client_port → (game_ip, game_port)
# WinDivert пишет на SYN, proxy читает в _handle_connection.
# Заменяет TARGET_FILE для устранения race condition.
_nat_target: Dict[int, Tuple[str, int]] = {}
_nat_target_lock = threading.Lock()


def _get_local_ip() -> str:
    """Получить реальный IP локальной машины (не 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ═══════════════════════════════════════════════════════════════════════════════
# L2 XOR Cipher — точная реплика coding.pas из newxor
#
# Два режима:
#   Standard (C1-C3):   keyLen=7,  8-byte key  (4 base + 4 suffix)
#   Interlude+ (C4+):   keyLen=15, 16-byte key (8 base + 8 suffix)
#
# Key rotation: после каждого пакета GKey[keyLen-7..keyLen-4] += packet_size
# Для Interlude+ (keyLen=15): ротация в байтах [8..11]
# ═══════════════════════════════════════════════════════════════════════════════

INTERLUDE_SUFFIX = bytes([0xC8, 0x27, 0x93, 0x01, 0xA1, 0x6C, 0x31, 0x97])
STANDARD_SUFFIX = bytes([0xA1, 0x6C, 0x54, 0x87])


class L2XorCipher:
    """XOR потоковый шифр L2 — один экземпляр на направление."""

    def __init__(self, base_key: bytes, interlude: bool = True):
        """
        base_key: 8 байт (Interlude+) или 4 байта (Standard).
        interlude: True для C4+ протокола (16-byte key, keyLen=15).
        """
        if interlude:
            self.key_len = 15  # AND-маска и размер - 1
            k = bytearray(base_key[:8])
            if len(k) < 8:
                k.extend(b'\x00' * (8 - len(k)))
            self.key = k + bytearray(INTERLUDE_SUFFIX)
        else:
            self.key_len = 7
            k = bytearray(base_key[:4])
            if len(k) < 4:
                k.extend(b'\x00' * (4 - len(k)))
            self.key = k + bytearray(STANDARD_SUFFIX)

        self._rotation_offset = self.key_len - 7
        # Interlude: 15-7=8, Standard: 7-7=0

    def clone(self) -> 'L2XorCipher':
        """Создать копию с идентичным state."""
        c = L2XorCipher.__new__(L2XorCipher)
        c.key = bytearray(self.key)
        c.key_len = self.key_len
        c._rotation_offset = self._rotation_offset
        return c

    def _rotate_key(self, size: int):
        """Инкремент 4 байт ключа на размер пакета (rolling counter)."""
        off = self._rotation_offset
        v = struct.unpack_from("<I", self.key, off)[0]
        v = (v + size) & 0xFFFFFFFF
        struct.pack_into("<I", self.key, off, v)

    def decrypt(self, data: bytes) -> bytes:
        """Расшифровать пакет (S→C).

        Порядок операций (из DecryptGP в coding.pas):
        1. Обратный цикл: for k = size-1 downto 1: buf[k] ^= key[k AND keyLen] ^ buf[k-1]
        2. buf[0] ^= key[0]
        3. Ротация ключа
        """
        size = len(data)
        if size == 0:
            return data

        buf = bytearray(data)
        kl = self.key_len

        # 1. Обратный цикл
        for k in range(size - 1, 0, -1):
            buf[k] ^= self.key[k & kl] ^ buf[k - 1]

        # 2. Первый байт
        buf[0] ^= self.key[0]

        # 3. Ротация
        self._rotate_key(size)

        return bytes(buf)

    def encrypt(self, data: bytes) -> bytes:
        """Зашифровать пакет (C→S).

        Порядок операций (из EncryptGP в coding.pas):
        1. buf[0] ^= key[0]
        2. Прямой цикл: for i = 1 to size-1: buf[i] ^= key[i AND keyLen] ^ buf[i-1]
        3. Ротация ключа
        """
        size = len(data)
        if size == 0:
            return data

        buf = bytearray(data)
        kl = self.key_len

        # 1. Первый байт
        buf[0] ^= self.key[0]

        # 2. Прямой цикл
        for i in range(1, size):
            buf[i] ^= self.key[i & kl] ^ buf[i - 1]

        # 3. Ротация
        self._rotate_key(size)

        return bytes(buf)


# ═══════════════════════════════════════════════════════════════════════════════
# L2 Blowfish ECB — pycryptodome
# ═══════════════════════════════════════════════════════════════════════════════

class L2BlowfishCipher:
    """Blowfish ECB для L2. Данные кратны 8 байт (padding нулями)."""

    # Дефолтный ключ до получения KeyInit
    DEFAULT_KEY = bytes([
        0x6B, 0x60, 0xCB, 0x5B, 0x82, 0xCE, 0x90, 0xB1,
        0xCC, 0x2B, 0x6C, 0x55, 0x6C, 0x6C, 0x6C, 0x6C,
    ])

    def __init__(self, key: bytes = None):
        self.set_key(key or self.DEFAULT_KEY)

    def set_key(self, key: bytes):
        from Crypto.Cipher import Blowfish
        self.key = bytes(key)
        self._cipher_enc = Blowfish.new(self.key, Blowfish.MODE_ECB)
        self._cipher_dec = Blowfish.new(self.key, Blowfish.MODE_ECB)

    def decrypt(self, data: bytes) -> bytes:
        pad = (8 - len(data) % 8) % 8
        padded = data + b'\x00' * pad
        from Crypto.Cipher import Blowfish
        c = Blowfish.new(self.key, Blowfish.MODE_ECB)
        return c.decrypt(padded)[:len(data)]

    def encrypt(self, data: bytes) -> bytes:
        pad = (8 - len(data) % 8) % 8
        padded = data + b'\x00' * pad
        from Crypto.Cipher import Blowfish
        c = Blowfish.new(self.key, Blowfish.MODE_ECB)
        return c.encrypt(padded)[:len(data)]


# ═══════════════════════════════════════════════════════════════════════════════
# Опкоды L2
#
# ВАЖНО: Опкоды Ertheia+ обфусцированы и меняются с каждым патчем.
# Здесь только стабильные (протокольные) опкоды, которые не меняются.
# Остальные загружаются из PacketsXXX.ini через PacketDefDB в l2phx.py.
# Для live-серверов таблицу нужно извлекать из клиента (NWindow.dll RE).
# ═══════════════════════════════════════════════════════════════════════════════

# Стабильные C2S опкоды (не меняются между версиями)
C2S_OPCODES = {
    0x00: "Logout",
    0x0E: "ProtocolVersion",
    0x11: "EnterWorld",
    0x12: "CharacterSelect",
    0x2B: "AuthLogin",
    0xCB: "GameGuardReply",
}

# Стабильные S2C опкоды
S2C_OPCODES = {
    0x2E: "KeyInit",
    0x0E: "AuthLoginOk",
    0x09: "CharSelectionInfo",
    0x0B: "CharSelected",
    0xCB: "GameGuardQuery",
}

# Extended опкоды (0xD0/0xFE prefix) — тоже нестабильны
C2S_EX = {}
S2C_EX = {}

# Дополнительная таблица, загружаемая из .ini файлов или runtime
# Формат: {opcode: name}. Обновляется через load_opcodes_from_ini()
_custom_c2s: Dict[int, str] = {}
_custom_s2c: Dict[int, str] = {}
_custom_c2s_ex: Dict[int, str] = {}
_custom_s2c_ex: Dict[int, str] = {}


def load_opcodes_from_ini(ini_path: str):
    """Загрузить опкоды из PacketsXXX.ini (формат L2PHx).

    Секции [Client] и [Server], строки вида:
      49=Say2:s(Text)d(Type)s(Target)
    """
    global _custom_c2s, _custom_s2c, _custom_c2s_ex, _custom_s2c_ex
    section = None
    try:
        with open(ini_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("[Client]"):
                    section = "c2s"
                    continue
                elif line.startswith("[Server]"):
                    section = "s2c"
                    continue
                elif line.startswith("["):
                    section = None
                    continue
                if not section or "=" not in line or line.startswith(";"):
                    continue
                hex_op, rest = line.split("=", 1)
                hex_op = hex_op.strip()
                name = rest.split(":")[0].strip()
                try:
                    op = int(hex_op, 16)
                except ValueError:
                    continue
                if section == "c2s":
                    if op > 0xFF:
                        _custom_c2s_ex[op] = name
                    else:
                        _custom_c2s[op] = name
                else:
                    if op > 0xFF:
                        _custom_s2c_ex[op] = name
                    else:
                        _custom_s2c[op] = name
        print(f"[OPCODES] Loaded {len(_custom_c2s)}+{len(_custom_c2s_ex)} C2S, "
              f"{len(_custom_s2c)}+{len(_custom_s2c_ex)} S2C from {ini_path}",
              file=sys.stderr)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[OPCODES] Error loading {ini_path}: {e}", file=sys.stderr)


def decode_opcode(data: bytes, direction: str) -> Tuple[int, str]:
    """Извлечь опкод + имя из расшифрованного тела пакета.

    Порядок поиска: стабильные → загруженные из .ini → hex-fallback.
    """
    if not data:
        return -1, "EMPTY"
    op = data[0]
    if direction == "C2S":
        if op == 0xD0 and len(data) >= 3:
            ex = struct.unpack_from("<H", data, 1)[0]
            name = (C2S_EX.get(ex) or _custom_c2s_ex.get(ex)
                    or f"Ex:0x{ex:04X}")
            return (0xD000 | ex), name
        name = (C2S_OPCODES.get(op) or _custom_c2s.get(op)
                or f"0x{op:02X}")
        return op, name
    else:
        if op == 0xFE and len(data) >= 3:
            ex = struct.unpack_from("<H", data, 1)[0]
            name = (S2C_EX.get(ex) or _custom_s2c_ex.get(ex)
                    or f"Ex:0x{ex:04X}")
            return (0xFE00 | ex), name
        name = (S2C_OPCODES.get(op) or _custom_s2c.get(op)
                or f"0x{op:02X}")
        return op, name


# ═══════════════════════════════════════════════════════════════════════════════
# KeyInit Parsing
# ═══════════════════════════════════════════════════════════════════════════════

def parse_key_init(body: bytes) -> Optional[Dict[str, Any]]:
    """Парсинг KeyInit (0x2E) — первый S→C пакет, всегда в открытом виде.

    Два формата:
    1. Короткий (Freya game server):
       opcode(1) + xorKey(8) + 0x01(1) + serverID(4) + 0x01(1) + obfuscationKey(4) = 19 bytes

    2. Длинный (Ertheia+ game server):
       opcode(1) + sessionId(4) + protocolVer(4) + rsaKey(128) +
       gameGuard(16) + blowfishKey(variable)

    Автоопределение по размеру.
    """
    if not body:
        return None

    # Ertheia+ обфусцирует ВСЕ опкоды включая KeyInit — определяем по размеру, не по опкоду.
    actual_op = body[0]
    _dbg(f"[KEYINIT] parse_key_init: op=0x{actual_op:02X} size={len(body)}")
    result = {"opcode": actual_op, "format": "unknown", "body_size": len(body)}

    if len(body) >= 153:
        # Длинный формат (Ertheia+ с RSA) — опкод обфусцирован, определяем по размеру
        result["format"] = "ertheia"
        result["session_id"] = struct.unpack_from("<I", body, 1)[0]
        result["protocol_version"] = struct.unpack_from("<I", body, 5)[0]
        result["rsa_key"] = body[9:9+128]
        result["game_guard"] = body[137:153]
        bf_data = body[153:]
        if bf_data:
            result["bf_key"] = bf_data[:min(len(bf_data), 21)]
            # XOR key = first 8 bytes of BF key
            result["xor_key"] = result["bf_key"][:8]
        _dbg(f"[KEYINIT] Ertheia+ detected! session=0x{result['session_id']:08X} "
             f"proto={result['protocol_version']} bf_key={result.get('bf_key', b'').hex()}")
        return result

    elif 15 <= len(body) <= 23:
        # Короткий формат (Freya) — строго 15-23 байт (xorKey+serverId+obfKey)
        result["format"] = "freya"
        result["xor_key"] = body[1:9]
        if len(body) >= 14:
            result["server_id"] = struct.unpack_from("<I", body, 10)[0]
        if len(body) >= 19:
            result["obfuscation_key"] = struct.unpack_from("<I", body, 15)[0]
        # BF key = xor key (same in Freya)
        result["bf_key"] = result["xor_key"]
        return result

    # Не KeyInit — слишком мало/много для Freya, мало для Ertheia
    _dbg(f"[KEYINIT] NOT a KeyInit: size={len(body)} (need >=153 for Ertheia or 15-23 for Freya)")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Packet Store — кольцевой буфер перехваченных пакетов
# ═══════════════════════════════════════════════════════════════════════════════

class PacketStore:
    def __init__(self, max_packets=10000):
        self.packets: deque = deque(maxlen=max_packets)
        self.lock = threading.Lock()
        self.seq = 0
        self.log_file = None

    def open_log(self, path: str):
        self.log_file = open(path, "a", buffering=1)

    def add(self, direction: str, raw: bytes, decrypted: bytes = None,
            opcode: int = -1, opname: str = "", extra: dict = None) -> dict:
        with self.lock:
            self.seq += 1
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            pkt = {
                "seq": self.seq,
                "ts": ts,
                "dir": direction,
                "len": len(raw),
                "opcode": opcode,
                "opname": opname,
                "raw_hex": raw[:64].hex() if raw else "",
                "dec_hex": decrypted[:256].hex() if decrypted else "",
                "extra": extra or {},
            }
            self.packets.append(pkt)

            line = (f"[{ts}] {direction} #{self.seq} "
                    f"op=0x{opcode:04X}({opname}) len={len(raw)}")
            if decrypted:
                line += f" | {decrypted[:48].hex()}"

            if self.log_file:
                self.log_file.write(line + "\n")

            print(line, file=sys.stderr)
            return pkt

    def get_recent(self, count=50, direction=None,
                   opcode_filter=None, name_filter=None) -> list:
        with self.lock:
            result = []
            for pkt in reversed(self.packets):
                if direction and pkt["dir"] != direction:
                    continue
                if opcode_filter is not None and pkt["opcode"] not in opcode_filter:
                    continue
                if name_filter and name_filter.lower() not in pkt["opname"].lower():
                    continue
                result.append(pkt)
                if len(result) >= count:
                    break
            return list(reversed(result))

    def get_by_seq(self, seq: int) -> Optional[dict]:
        with self.lock:
            for pkt in self.packets:
                if pkt["seq"] == seq:
                    return pkt
        return None

    def get_stats(self) -> dict:
        with self.lock:
            c2s = s2c = 0
            opcodes: Dict[str, int] = {}
            for p in self.packets:
                if p["dir"] == "C2S":
                    c2s += 1
                else:
                    s2c += 1
                key = f"{p['dir']}:0x{p['opcode']:04X}:{p['opname']}"
                opcodes[key] = opcodes.get(key, 0) + 1
            top = sorted(opcodes.items(), key=lambda x: -x[1])[:40]
            return {"total": len(self.packets), "c2s": c2s, "s2c": s2c,
                    "top_opcodes": dict(top)}


# ═══════════════════════════════════════════════════════════════════════════════
# L2 Session — крипто-состояние одного TCP соединения
# ═══════════════════════════════════════════════════════════════════════════════

class L2CryptoSession:
    """Управляет 4 XOR state + 1 BF key для полного MITM с инъекцией.

    Четыре XOR экземпляра:
    - client_c2s:  декодирует то, что клиент отправляет
    - server_c2s:  кодирует то, что мы отправляем серверу (вкл. инъекции)
    - server_s2c:  декодирует то, что сервер отправляет
    - client_s2c:  кодирует то, что мы отправляем клиенту (вкл. инъекции)

    При обычной пересылке (без инъекций) все 4 state синхронны попарно.
    При инъекции C→S: server_c2s опережает client_c2s.
    При инъекции S→C: client_s2c опережает server_s2c.
    """

    def __init__(self):
        self.bf = L2BlowfishCipher()
        self.client_c2s: Optional[L2XorCipher] = None
        self.server_c2s: Optional[L2XorCipher] = None
        self.server_s2c: Optional[L2XorCipher] = None
        self.client_s2c: Optional[L2XorCipher] = None
        self.bf_key: Optional[bytes] = None
        self.xor_key: Optional[bytes] = None
        self.key_init_data: Optional[dict] = None
        self.initialized = False
        self.passthrough = False  # True = no crypto, forward raw

    def init_from_key_init(self, body: bytes) -> Optional[dict]:
        """Инициализировать крипто из KeyInit пакета."""
        info = parse_key_init(body)
        if not info:
            return None

        self.key_init_data = info
        bf_key = info.get("bf_key")
        xor_key = info.get("xor_key")

        if bf_key:
            self.bf_key = bytes(bf_key)
            self.bf.set_key(self.bf_key)

        if xor_key:
            self.xor_key = bytes(xor_key)
            self.client_c2s = L2XorCipher(self.xor_key, interlude=True)
            self.server_c2s = L2XorCipher(self.xor_key, interlude=True)
            self.server_s2c = L2XorCipher(self.xor_key, interlude=True)
            self.client_s2c = L2XorCipher(self.xor_key, interlude=True)
            self.initialized = True

        return info

    def decrypt_s2c(self, body: bytes) -> bytes:
        """Расшифровать S→C пакет: BF → XOR (server_s2c state)."""
        dec = self.bf.decrypt(body)
        if self.server_s2c:
            dec = self.server_s2c.decrypt(dec)
        return dec

    def encrypt_s2c(self, plaintext: bytes) -> bytes:
        """Зашифровать S→C пакет для клиента: XOR (client_s2c) → BF."""
        enc = plaintext
        if self.client_s2c:
            enc = self.client_s2c.encrypt(enc)
        return self.bf.encrypt(enc)

    def decrypt_c2s(self, body: bytes) -> bytes:
        """Расшифровать C→S пакет: BF → XOR (client_c2s state)."""
        dec = self.bf.decrypt(body)
        if self.client_c2s:
            dec = self.client_c2s.decrypt(dec)
        return dec

    def encrypt_c2s(self, plaintext: bytes) -> bytes:
        """Зашифровать C→S пакет для сервера: XOR (server_c2s) → BF."""
        enc = plaintext
        if self.server_c2s:
            enc = self.server_c2s.encrypt(enc)
        return self.bf.encrypt(enc)


# ═══════════════════════════════════════════════════════════════════════════════
# TCP Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Принять ровно n байт."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_l2_packet(sock: socket.socket) -> Optional[bytes]:
    """Принять один L2 пакет: [len:2 LE][body:len-2]."""
    hdr = recv_exact(sock, 2)
    if hdr is None:
        return None
    pkt_len = struct.unpack_from("<H", hdr)[0]
    if pkt_len < 3 or pkt_len > 65535:
        return None
    return recv_exact(sock, pkt_len - 2)


def send_l2_packet(sock: socket.socket, body: bytes):
    """Отправить L2 пакет с 2-байтным заголовком длины."""
    sock.sendall(struct.pack("<H", len(body) + 2) + body)


# ═══════════════════════════════════════════════════════════════════════════════
# L2 MITM Proxy — полный re-encrypt, поддержка инъекций
# ═══════════════════════════════════════════════════════════════════════════════

class L2MitmProxy:
    def __init__(self, store: PacketStore, listen_port=PROXY_PORT):
        self.store = store
        self.listen_port = listen_port
        self.running = False
        self.connected = False
        self.crypto: Optional[L2CryptoSession] = None
        self.client_sock: Optional[socket.socket] = None
        self.server_sock: Optional[socket.socket] = None
        self.pkt_c2s = 0
        self.pkt_s2c = 0
        self.inject_c2s: deque = deque()  # plaintext packets to inject C→S
        self.inject_s2c: deque = deque()  # plaintext packets to inject S→C
        self._server_lock = threading.Lock()
        self._client_lock = threading.Lock()

    def _get_target(self, client_port: int = 0) -> Tuple[str, int]:
        """Получить оригинальный адрес сервера для соединения.

        Приоритет: NAT таблица (по client_port) → TARGET_FILE → DEFAULT_TARGET.
        """
        # 1. NAT таблица (без race condition!)
        if client_port:
            with _nat_target_lock:
                entry = _nat_target.get(client_port)
            if entry:
                return entry
        # 2. Fallback: файл (для ручного --target или совместимости)
        try:
            if os.path.exists(TARGET_FILE):
                with open(TARGET_FILE) as f:
                    line = f.read().strip()
                if ":" in line:
                    ip, port = line.rsplit(":", 1)
                    return (ip, int(port))
        except Exception:
            pass
        return DEFAULT_TARGET

    def _OLD_relay_s2c(self):
        """OLD — НЕ ВЫЗЫВАЕТСЯ. Оставлено как reference."""
        try:
            _dbg(f"[S2C] Waiting for first server packet... server={self.server_sock.getpeername()}")
            while self.running:
                # Debug: попробуем raw recv с таймаутом чтобы увидеть есть ли данные
                if self.pkt_s2c == 0:
                    self.server_sock.settimeout(60)
                    try:
                        peek = self.server_sock.recv(4, socket.MSG_PEEK)
                        _dbg(f"[S2C DEBUG] Peek first 4 bytes: {peek.hex() if peek else 'EMPTY'} len={len(peek)}")
                        self.server_sock.settimeout(None)
                    except socket.timeout:
                        _dbg(f"[S2C DEBUG] No data from server in 60s! Server silent.")
                        self.server_sock.settimeout(None)
                        break
                    except Exception as e:
                        _dbg(f"[S2C DEBUG] Peek error: {type(e).__name__}: {e}")
                        self.server_sock.settimeout(None)

                body = recv_l2_packet(self.server_sock)
                if body is None:
                    _dbg(f"[S2C] recv_l2_packet returned None (connection closed)")
                    break

                self.pkt_s2c += 1
                n = self.pkt_s2c

                if n == 1:
                    # Первый S2C пакет — пробуем распарсить как KeyInit
                    info = self.crypto.init_from_key_init(body)
                    if not info:
                        self.crypto.passthrough = True
                        _dbg(f"[S2C] No KeyInit (op=0x{body[0]:02X} size={len(body)}), passthrough mode")
                    elif self._target_port != 7777:
                        # Login(2106)/Intermediate(17453): BF-ONLY, нет XOR!
                        # Наша криптосистема предполагает BF+XOR — passthrough безопаснее.
                        self.crypto.passthrough = True
                        _dbg(f"[S2C] Port {self._target_port} != 7777: BF-only protocol, PASSTHROUGH mode "
                             f"(format={info.get('format')} session=0x{info.get('session_id',0):08X})")
                    else:
                        _dbg(f"[S2C] KeyInit OK on game port 7777: "
                             f"format={info.get('format')} session=0x{info.get('session_id',0):08X} "
                             f"FULL CRYPTO (BF+XOR) enabled")
                    opcode, opname = decode_opcode(body, "S2C")
                    self.store.add("S2C", body, body, opcode, opname,
                                   extra={"key_init": {
                                       k: v.hex() if isinstance(v, (bytes, bytearray)) else v
                                       for k, v in (info or {}).items()
                                   }} if info else {"passthrough": True})
                    with self._client_lock:
                        send_l2_packet(self.client_sock, body)
                    _dbg(f"[S2C] KeyInit forwarded to client, relay continues...")
                    continue

                # Passthrough — просто пересылаем как есть
                if self.crypto.passthrough:
                    opcode, opname = decode_opcode(body, "S2C")
                    _dbg(f"[S2C PASS] #{n} len={len(body)} op=0x{body[0]:02X}")
                    self.store.add("S2C", body, body, opcode, opname)
                    with self._client_lock:
                        send_l2_packet(self.client_sock, body)
                    continue

                # Расшифровать от сервера
                try:
                    plaintext = self.crypto.decrypt_s2c(body)
                except Exception as e:
                    _dbg(f"[S2C DECRYPT ERR #{n}] {e}")
                    plaintext = None

                opcode, opname = decode_opcode(plaintext, "S2C") if plaintext else (-1, "ERR")
                _dbg(f"[S2C] #{n} cipher_len={len(body)} op=0x{opcode:02X}({opname}) plain={plaintext[:16].hex() if plaintext else 'ERR'}")
                self.store.add("S2C", body, plaintext, opcode, opname)

                # Re-encrypt для клиента (используя client_s2c XOR state)
                if plaintext is not None:
                    re_enc = self.crypto.encrypt_s2c(plaintext)
                else:
                    re_enc = body  # fallback: forward as-is

                with self._client_lock:
                    send_l2_packet(self.client_sock, re_enc)

                # Проверяем очередь инъекций S→C
                while self.inject_s2c:
                    inj_plain = self.inject_s2c.popleft()
                    inj_enc = self.crypto.encrypt_s2c(inj_plain)
                    op, nm = decode_opcode(inj_plain, "S2C")
                    self.store.add("S2C", inj_enc, inj_plain, op,
                                   f"INJECT:{nm}")
                    with self._client_lock:
                        send_l2_packet(self.client_sock, inj_enc)

        except Exception as e:
            if self.running:
                print(f"[S2C ERROR] {e}", file=sys.stderr)
        finally:
            self.running = False
            # Закрываем оба сокета чтобы разблокировать recv в другом relay треде
            for s in (self.client_sock, self.server_sock):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

    def _OLD_relay_c2s(self):
        """OLD — НЕ ВЫЗЫВАЕТСЯ. Оставлено как reference."""
        try:
            _dbg(f"[C2S] Relay started, waiting for client data...")
            while self.running:
                # Raw debug: peek чтобы увидеть приходят ли вообще данные от клиента
                if self.pkt_c2s == 0:
                    try:
                        self.client_sock.settimeout(30)
                        raw_peek = self.client_sock.recv(4, socket.MSG_PEEK)
                        _dbg(f"[C2S RAW] First peek from client: {raw_peek.hex() if raw_peek else 'EMPTY'} len={len(raw_peek)}")
                        self.client_sock.settimeout(None)
                    except socket.timeout:
                        _dbg(f"[C2S RAW] No data from client in 30s! Client silent.")
                        self.client_sock.settimeout(None)
                    except Exception as e:
                        _dbg(f"[C2S RAW] Peek error: {type(e).__name__}: {e}")
                        self.client_sock.settimeout(None)

                body = recv_l2_packet(self.client_sock)
                if body is None:
                    _dbg(f"[C2S] recv_l2_packet returned None (client closed)")
                    break

                self.pkt_c2s += 1
                n = self.pkt_c2s

                if n == 1 and not self.crypto.initialized:
                    # Первый C→S до инициализации крипто — пропускаем как есть
                    opcode, opname = decode_opcode(body, "C2S")
                    self.store.add("C2S", body, body, opcode, opname,
                                   extra={"note": "pre-crypto"})
                    _dbg(f"[C2S DEBUG] Forwarding pre-crypto pkt to server: "
                         f"op=0x{body[0]:02X} len={len(body)} "
                         f"server={self.server_sock.getpeername()}")
                    _dbg(f"[C2S HEX] first 64: {body[:64].hex()}")
                    _dbg(f"[C2S HEX] L2 header sent: {struct.pack('<H', len(body)+2).hex()}")
                    with self._server_lock:
                        send_l2_packet(self.server_sock, body)
                    _dbg(f"[C2S DEBUG] send_l2_packet OK (total {len(body)+2} bytes)")
                    continue

                # Passthrough — просто пересылаем как есть
                if self.crypto.passthrough:
                    opcode, opname = decode_opcode(body, "C2S")
                    _dbg(f"[C2S PASS] #{n} len={len(body)} op=0x{body[0]:02X}")
                    self.store.add("C2S", body, body, opcode, opname)
                    with self._server_lock:
                        send_l2_packet(self.server_sock, body)
                    continue

                # Расшифровать от клиента
                try:
                    plaintext = self.crypto.decrypt_c2s(body)
                except Exception as e:
                    _dbg(f"[C2S DECRYPT ERR #{n}] {e}")
                    plaintext = None

                opcode, opname = decode_opcode(plaintext, "C2S") if plaintext else (-1, "ERR")
                _dbg(f"[C2S] #{n} cipher_len={len(body)} op=0x{opcode:02X}({opname}) plain={plaintext[:16].hex() if plaintext else 'ERR'}")
                self.store.add("C2S", body, plaintext, opcode, opname)

                # Re-encrypt для сервера (используя server_c2s XOR state)
                if plaintext is not None:
                    re_enc = self.crypto.encrypt_c2s(plaintext)
                else:
                    re_enc = body

                with self._server_lock:
                    send_l2_packet(self.server_sock, re_enc)

                # Инъекции C→S
                while self.inject_c2s:
                    inj_plain = self.inject_c2s.popleft()
                    inj_enc = self.crypto.encrypt_c2s(inj_plain)
                    op, nm = decode_opcode(inj_plain, "C2S")
                    self.store.add("C2S", inj_enc, inj_plain, op,
                                   f"INJECT:{nm}")
                    with self._server_lock:
                        send_l2_packet(self.server_sock, inj_enc)

        except Exception as e:
            if self.running:
                print(f"[C2S ERROR] {e}", file=sys.stderr)
        finally:
            self.running = False
            for s in (self.client_sock, self.server_sock):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

    def _handle_connection(self, client_sock: socket.socket, addr):
        """Обработка одного соединения с ИЗОЛИРОВАННЫМ состоянием.

        Каждое соединение создаёт локальные переменные (не instance vars),
        поэтому можно запускать несколько _handle_connection параллельно.
        """
        # Локальное состояние — НЕ self.*, чтобы не было race condition
        crypto = L2CryptoSession()
        pkt_c2s = [0]  # list для мутации из вложенных функций
        pkt_s2c = [0]
        running = [True]
        inject_c2s = deque()
        inject_s2c = deque()
        client_lock = threading.Lock()
        server_lock = threading.Lock()

        client_port = addr[1]
        target = self._get_target(client_port)
        target_port = target[1]
        _dbg(f"[PROXY] {addr} → {target[0]}:{target[1]}")

        # Сохраняем для MCP доступа (последняя активная сессия)
        self.crypto = crypto
        self._target_port = target_port
        self.inject_c2s = inject_c2s
        self.inject_s2c = inject_s2c

        out_port = None
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            global _proxy_out_port_next
            out_port = _proxy_out_port_next
            _proxy_out_port_next += 1
            if _proxy_out_port_next > PROXY_OUT_PORT_MAX:
                _proxy_out_port_next = PROXY_OUT_PORT_BASE
            server_sock.bind(('', out_port))
            _dbg(f"[PROXY] Outbound port {out_port} (fixed range), connecting to {target}...")
            server_sock.settimeout(10)
            server_sock.connect(target)
            server_sock.settimeout(None)
            _dbg(f"[PROXY] Connected to {target[0]}:{target[1]}")
        except Exception as e:
            _dbg(f"[PROXY] Connect to {target} failed: {e}")
            client_sock.close()
            return

        self.connected = True
        self.client_sock = client_sock
        self.server_sock = server_sock

        def relay_s2c():
            """Server → Client relay с локальным состоянием."""
            try:
                _dbg(f"[S2C:{target_port}] Waiting for first server packet...")
                while running[0]:
                    if pkt_s2c[0] == 0:
                        server_sock.settimeout(60)
                        try:
                            peek = server_sock.recv(4, socket.MSG_PEEK)
                            _dbg(f"[S2C:{target_port}] Peek first 4 bytes: {peek.hex() if peek else 'EMPTY'}")
                            server_sock.settimeout(None)
                        except socket.timeout:
                            _dbg(f"[S2C:{target_port}] No data from server in 60s!")
                            server_sock.settimeout(None)
                            break
                        except Exception as e:
                            _dbg(f"[S2C:{target_port}] Peek error: {type(e).__name__}: {e}")
                            server_sock.settimeout(None)

                    body = recv_l2_packet(server_sock)
                    if body is None:
                        _dbg(f"[S2C:{target_port}] Connection closed")
                        break

                    pkt_s2c[0] += 1
                    n = pkt_s2c[0]

                    if n == 1:
                        info = crypto.init_from_key_init(body)
                        if not info:
                            crypto.passthrough = True
                            _dbg(f"[S2C:{target_port}] No KeyInit (op=0x{body[0]:02X} size={len(body)}), passthrough")
                        elif target_port != 7777:
                            crypto.passthrough = True
                            _dbg(f"[S2C:{target_port}] BF-only protocol, PASSTHROUGH "
                                 f"(session=0x{info.get('session_id',0):08X})")
                        else:
                            _dbg(f"[S2C:{target_port}] FULL CRYPTO BF+XOR "
                                 f"(session=0x{info.get('session_id',0):08X})")
                        opcode, opname = decode_opcode(body, "S2C")
                        self.store.add("S2C", body, body, opcode, opname,
                                       extra={"key_init": {
                                           k: v.hex() if isinstance(v, (bytes, bytearray)) else v
                                           for k, v in (info or {}).items()
                                       }} if info else {"passthrough": True})
                        with client_lock:
                            send_l2_packet(client_sock, body)
                        _dbg(f"[S2C:{target_port}] KeyInit forwarded, relay continues...")
                        continue

                    if crypto.passthrough:
                        _dbg(f"[S2C:{target_port}] #{n} PASS len={len(body)} op=0x{body[0]:02X}")
                        opcode, opname = decode_opcode(body, "S2C")
                        self.store.add("S2C", body, body, opcode, opname)
                        with client_lock:
                            send_l2_packet(client_sock, body)
                        continue

                    try:
                        plaintext = crypto.decrypt_s2c(body)
                    except Exception as e:
                        _dbg(f"[S2C:{target_port}] DECRYPT ERR #{n}: {e}")
                        plaintext = None

                    opcode, opname = decode_opcode(plaintext, "S2C") if plaintext else (-1, "ERR")
                    _dbg(f"[S2C:{target_port}] #{n} op=0x{opcode:02X}({opname}) len={len(body)}")
                    self.store.add("S2C", body, plaintext, opcode, opname)

                    if plaintext is not None:
                        re_enc = crypto.encrypt_s2c(plaintext)
                    else:
                        re_enc = body
                    with client_lock:
                        send_l2_packet(client_sock, re_enc)

                    while inject_s2c:
                        inj_plain = inject_s2c.popleft()
                        inj_enc = crypto.encrypt_s2c(inj_plain)
                        op, nm = decode_opcode(inj_plain, "S2C")
                        self.store.add("S2C", inj_enc, inj_plain, op, f"INJECT:{nm}")
                        with client_lock:
                            send_l2_packet(client_sock, inj_enc)

            except Exception as e:
                if running[0]:
                    _dbg(f"[S2C:{target_port}] ERROR: {e}")
            finally:
                running[0] = False
                for s in (client_sock, server_sock):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        def relay_c2s():
            """Client → Server relay с локальным состоянием."""
            try:
                _dbg(f"[C2S:{target_port}] Relay started, waiting for client data...")
                while running[0]:
                    if pkt_c2s[0] == 0:
                        try:
                            client_sock.settimeout(30)
                            raw_peek = client_sock.recv(4, socket.MSG_PEEK)
                            _dbg(f"[C2S:{target_port}] First peek: {raw_peek.hex() if raw_peek else 'EMPTY'} len={len(raw_peek)}")
                            client_sock.settimeout(None)
                        except socket.timeout:
                            _dbg(f"[C2S:{target_port}] No data from client in 30s!")
                            client_sock.settimeout(None)
                        except Exception as e:
                            _dbg(f"[C2S:{target_port}] Peek error: {type(e).__name__}: {e}")
                            client_sock.settimeout(None)

                    body = recv_l2_packet(client_sock)
                    if body is None:
                        _dbg(f"[C2S:{target_port}] Client closed")
                        break

                    pkt_c2s[0] += 1
                    n = pkt_c2s[0]

                    if n == 1 and not crypto.initialized:
                        opcode, opname = decode_opcode(body, "C2S")
                        _dbg(f"[C2S:{target_port}] #{n} pre-crypto op=0x{body[0]:02X} len={len(body)}")
                        self.store.add("C2S", body, body, opcode, opname, extra={"note": "pre-crypto"})
                        with server_lock:
                            send_l2_packet(server_sock, body)
                        continue

                    if crypto.passthrough:
                        _dbg(f"[C2S:{target_port}] #{n} PASS len={len(body)} op=0x{body[0]:02X}")
                        opcode, opname = decode_opcode(body, "C2S")
                        self.store.add("C2S", body, body, opcode, opname)
                        with server_lock:
                            send_l2_packet(server_sock, body)
                        continue

                    try:
                        plaintext = crypto.decrypt_c2s(body)
                    except Exception as e:
                        _dbg(f"[C2S:{target_port}] DECRYPT ERR #{n}: {e}")
                        plaintext = None

                    opcode, opname = decode_opcode(plaintext, "C2S") if plaintext else (-1, "ERR")
                    _dbg(f"[C2S:{target_port}] #{n} op=0x{opcode:02X}({opname}) len={len(body)}")
                    self.store.add("C2S", body, plaintext, opcode, opname)

                    if plaintext is not None:
                        re_enc = crypto.encrypt_c2s(plaintext)
                    else:
                        re_enc = body
                    with server_lock:
                        send_l2_packet(server_sock, re_enc)

                    while inject_c2s:
                        inj_plain = inject_c2s.popleft()
                        inj_enc = crypto.encrypt_c2s(inj_plain)
                        op, nm = decode_opcode(inj_plain, "C2S")
                        self.store.add("C2S", inj_enc, inj_plain, op, f"INJECT:{nm}")
                        with server_lock:
                            send_l2_packet(server_sock, inj_enc)

            except Exception as e:
                if running[0]:
                    _dbg(f"[C2S:{target_port}] ERROR: {e}")
            finally:
                running[0] = False
                for s in (client_sock, server_sock):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        t1 = threading.Thread(target=relay_s2c, daemon=True, name=f"s2c-{target_port}")
        t2 = threading.Thread(target=relay_c2s, daemon=True, name=f"c2s-{target_port}")
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.connected = False
        _dbg(f"[PROXY] Session end port={target_port}: {pkt_c2s[0]} C→S, {pkt_s2c[0]} S→C")

        for s in (client_sock, server_sock):
            try:
                s.close()
            except Exception:
                pass

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((LISTEN_HOST, self.listen_port))
        srv.listen(16)
        self.running = True
        print(f"[PROXY] Listening {LISTEN_HOST}:{self.listen_port} (multi-threaded)",
              file=sys.stderr)

        while True:
            try:
                client, addr = srv.accept()
                # МНОГОПОТОЧНАЯ обработка: каждое соединение в отдельном потоке!
                # Клиент L2 может открывать login + intermediate одновременно.
                # Состояние изолировано в локальных переменных _handle_connection.
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(client, addr),
                    daemon=True,
                    name=f"conn-{addr[1]}"
                )
                t.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[PROXY] Accept: {e}", file=sys.stderr)
                time.sleep(1)


# ═══════════════════════════════════════════════════════════════════════════════
# WinDivert 2.2 ctypes wrapper + NAT Redirect
# ═══════════════════════════════════════════════════════════════════════════════

import ctypes
from ctypes import (
    c_void_p, c_uint, c_uint8, c_uint16, c_uint32, c_uint64,
    c_int16, c_char_p, POINTER, Structure, sizeof, byref, create_string_buffer,
)
from ctypes.wintypes import HANDLE, BOOL

# WinDivert 2.2 WINDIVERT_ADDRESS (80 bytes)
# https://reqrypt.org/windivert-doc.html#divert_address
class WINDIVERT_ADDRESS(Structure):
    _fields_ = [
        ("Timestamp",    c_uint64),   # 0: Timestamp
        ("Layer",        c_uint8),    # 8: Layer (NETWORK=0)
        ("Event",        c_uint8),    # 9: Event
        ("Flags",        c_uint8),    # 10: Sniffed(1), Outbound(2), Loopback(4), Impostor(8)
        ("_reserved1",   c_uint8),    # 11
        ("_data_len",    c_uint32),   # 12: Data length
        # Union starts at offset 16 — Network layer fields
        ("IfIdx",        c_uint32),   # 16: Interface index
        ("SubIfIdx",     c_uint32),   # 20: Sub-interface index
        # Padding to 80 bytes
        ("_padding",     c_uint8 * 56),  # 24..79
    ]

WINDIVERT_FLAG_SNIFF    = 0x01
WINDIVERT_FLAG_OUTBOUND = 0x02
WINDIVERT_FLAG_LOOPBACK = 0x04
WINDIVERT_FLAG_IMPOSTOR = 0x08

WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_DIRECTION_OUTBOUND = 0
WINDIVERT_DIRECTION_INBOUND  = 1

WINDIVERT_PARAM_QUEUE_LENGTH = 0
WINDIVERT_PARAM_QUEUE_TIME   = 1
WINDIVERT_PARAM_QUEUE_SIZE   = 2

INVALID_HANDLE_VALUE = HANDLE(-1).value


class WinDivert2:
    """Ctypes-обёртка для WinDivert 2.2 DLL.

    WinDivert 2.2 — перехват пакетов на уровне ядра через WFP.
    Работает на Windows 10/11 (в отличие от WinDivert 1.3 из pydivert).
    """

    # Путь к DLL (рядом с проектом или в PATH)
    DLL_SEARCH_PATHS = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "WinDivert.dll"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "WinDivert.dll"),
        "WinDivert.dll",
    ]

    def __init__(self):
        self._dll = None
        self._handle = None

    def _load_dll(self):
        if self._dll:
            return
        for path in self.DLL_SEARCH_PATHS:
            if os.path.exists(path):
                # Добавить директорию с DLL в DLL search path
                # чтобы WinDivert.dll нашёл WinDivert64.sys
                dll_dir = os.path.dirname(os.path.abspath(path))
                try:
                    ctypes.windll.kernel32.SetDllDirectoryW(dll_dir)
                except Exception:
                    pass
                try:
                    # Загрузить с полным путём
                    self._dll = ctypes.WinDLL(path)
                    self._setup_prototypes()
                    print(f"[DIVERT] Loaded WinDivert 2.x from {path}",
                          file=sys.stderr)
                    return
                except OSError as e:
                    print(f"[DIVERT] Failed to load {path}: {e}", file=sys.stderr)
                    continue
        raise FileNotFoundError(
            "WinDivert.dll not found. Place WinDivert.dll + WinDivert64.sys "
            "in ./bin/ directory")

    def _setup_prototypes(self):
        d = self._dll

        # HANDLE WinDivertOpen(filter, layer, priority, flags)
        d.WinDivertOpen.argtypes = [c_char_p, c_uint8, c_int16, c_uint64]
        d.WinDivertOpen.restype = HANDLE

        # BOOL WinDivertRecv(handle, pPacket, packetLen, pRecvLen, pAddr)
        d.WinDivertRecv.argtypes = [HANDLE, c_void_p, c_uint, POINTER(c_uint), POINTER(WINDIVERT_ADDRESS)]
        d.WinDivertRecv.restype = BOOL

        # BOOL WinDivertSend(handle, pPacket, packetLen, pSendLen, pAddr)
        d.WinDivertSend.argtypes = [HANDLE, c_void_p, c_uint, POINTER(c_uint), POINTER(WINDIVERT_ADDRESS)]
        d.WinDivertSend.restype = BOOL

        # BOOL WinDivertClose(handle)
        d.WinDivertClose.argtypes = [HANDLE]
        d.WinDivertClose.restype = BOOL

        # BOOL WinDivertSetParam(handle, param, value)
        d.WinDivertSetParam.argtypes = [HANDLE, c_uint, c_uint64]
        d.WinDivertSetParam.restype = BOOL

        # BOOL WinDivertHelperCalcChecksums(pPacket, packetLen, pAddr, flags)
        d.WinDivertHelperCalcChecksums.argtypes = [c_void_p, c_uint, POINTER(WINDIVERT_ADDRESS), c_uint64]
        d.WinDivertHelperCalcChecksums.restype = BOOL

    def open(self, filter_str: str, layer: int = 0, priority: int = 0, flags: int = 0):
        """Открыть WinDivert handle с заданным фильтром."""
        self._load_dll()
        # WinDivert 2.x ожидает ANSI строку для фильтра
        filt = filter_str.encode('ascii')
        handle = self._dll.WinDivertOpen(filt, layer, priority, flags)
        if handle == INVALID_HANDLE_VALUE or handle is None:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise OSError(f"WinDivertOpen failed (error={err}). Run as Administrator!")
        self._handle = handle

        # Увеличить буферы (по умолчанию маленькие)
        try:
            self._dll.WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192)
            self._dll.WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048)
            self._dll.WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, 4194304)
        except Exception:
            pass

    def recv(self) -> tuple:
        """Получить пакет. Возвращает (raw_bytes, address)."""
        buf = create_string_buffer(65535)
        recv_len = c_uint(0)
        addr = WINDIVERT_ADDRESS()
        ok = self._dll.WinDivertRecv(
            self._handle, buf, 65535, byref(recv_len), byref(addr))
        if not ok:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise OSError(f"WinDivertRecv failed (error={err})")
        return bytes(buf[:recv_len.value]), addr

    def send(self, packet_bytes: bytes, addr: WINDIVERT_ADDRESS):
        """Отправить (переинъектировать) пакет."""
        send_len = c_uint(0)
        ok = self._dll.WinDivertSend(
            self._handle, packet_bytes, len(packet_bytes),
            byref(send_len), byref(addr))
        if not ok:
            err = ctypes.get_last_error() or ctypes.windll.kernel32.GetLastError()
            raise OSError(f"WinDivertSend failed (error={err})")
        return send_len.value

    def calc_checksums(self, packet_bytes, addr: WINDIVERT_ADDRESS):
        """Пересчитать IP/TCP/UDP checksums после модификации пакета."""
        buf = create_string_buffer(bytes(packet_bytes), len(packet_bytes))
        self._dll.WinDivertHelperCalcChecksums(
            buf, len(packet_bytes), byref(addr), 0)
        return bytes(buf)

    def close(self):
        if self._handle:
            self._dll.WinDivertClose(self._handle)
            self._handle = None


def _parse_ipv4_packet(raw: bytes):
    """Разобрать IPv4 + TCP заголовки. Возвращает dict или None."""
    if len(raw) < 20:
        return None
    ver_ihl = raw[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl:
        return None
    protocol = raw[9]
    if protocol != 6:  # не TCP
        return None
    src_ip = f"{raw[12]}.{raw[13]}.{raw[14]}.{raw[15]}"
    dst_ip = f"{raw[16]}.{raw[17]}.{raw[18]}.{raw[19]}"

    if len(raw) < ihl + 20:
        return None
    tcp_off = ihl
    src_port = (raw[tcp_off] << 8) | raw[tcp_off + 1]
    dst_port = (raw[tcp_off + 2] << 8) | raw[tcp_off + 3]

    return {
        "ihl": ihl, "tcp_off": tcp_off,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
    }


def _modify_ipv4_packet(raw: bytes, info: dict,
                         new_dst_ip=None, new_dst_port=None,
                         new_src_ip=None, new_src_port=None) -> bytearray:
    """Модифицировать IP/TCP заголовки пакета. Возвращает bytearray."""
    pkt = bytearray(raw)
    if new_dst_ip:
        parts = [int(x) for x in new_dst_ip.split('.')]
        pkt[16:20] = bytes(parts)
    if new_src_ip:
        parts = [int(x) for x in new_src_ip.split('.')]
        pkt[12:16] = bytes(parts)
    tcp_off = info["tcp_off"]
    if new_dst_port is not None:
        pkt[tcp_off + 2] = (new_dst_port >> 8) & 0xFF
        pkt[tcp_off + 3] = new_dst_port & 0xFF
    if new_src_port is not None:
        pkt[tcp_off] = (new_src_port >> 8) & 0xFF
        pkt[tcp_off + 1] = new_src_port & 0xFF
    # Обнулить checksums — WinDivert пересчитает
    pkt[10:12] = b'\x00\x00'  # IP checksum
    pkt[tcp_off + 16:tcp_off + 18] = b'\x00\x00'  # TCP checksum
    return pkt


class WinDivertRedirector:
    """Прозрачный TCP redirect через WinDivert 2.2 — чистый NAT (без смены direction).

    Предыдущий reflect-подход менял direction (outbound→inbound), что не работает
    с VPN (AmneziaVPN блокирует инъекцию inbound пакетов).

    Новый подход — пакеты ВСЕГДА реинжектируются в том же направлении (outbound):
      CASE 1 (outbound, VPN):      client→game → меняем dst на 127.0.0.1:proxy_port
      CASE 2 (outbound, loopback): proxy→client → меняем src на game_server:port

    WinDivert 2.x для outbound пакетов игнорирует IfIdx и маршрутизирует
    по dst address. Поэтому dst=127.0.0.1 автоматически уходит в loopback.

    Реинжектированные пакеты НЕ перехватываются повторно тем же handle (WinDivert гарантия).
    Proxy→real_server исключён динамически через _proxy_out_ports set.
    """

    def __init__(self, proxy_port=PROXY_PORT):
        self.proxy_port = proxy_port
        self.running = False
        # client_src_port → (game_ip, game_port, client_ip)
        self.nat: Dict[int, Tuple[str, int, str]] = {}
        self.lock = threading.Lock()
        self._send_errors = 0
        self._pkt_count = 0

    def run(self):
        wd = WinDivert2()
        try:
            wd._load_dll()
        except FileNotFoundError as e:
            print(f"[DIVERT] {e}", file=sys.stderr)
            return
        except Exception as e:
            print(f"[DIVERT] DLL load error: {e}", file=sys.stderr)
            return

        # Определяем локальный IP (VPN) — НЕ 127.0.0.1!
        # Windows дропает пакеты с dst=127.0.0.1 на не-loopback пути.
        # dst=VPN_IP распознаётся как "свой" и корректно маршрутизируется в loopback.
        local_ip = _get_local_ip()
        print(f"[DIVERT] Local IP (NAT target): {local_ip}", file=sys.stderr)

        # Два условия в одном фильтре:
        # 1. Outbound на VPN: клиент → game server
        #    ИСКЛЮЧАЕМ proxy→server порты (PROXY_OUT_PORT_BASE..MAX) через SrcPort
        # 2. Outbound на loopback: proxy → клиент (NAT src → game_server:port)
        port_cond = " or ".join(f"tcp.DstPort == {p}" for p in sorted(GAME_PORTS))
        filt = (
            f"(outbound and not loopback and ip and tcp and "
            f"({port_cond}) and "
            f"(tcp.SrcPort < {PROXY_OUT_PORT_BASE} or tcp.SrcPort > {PROXY_OUT_PORT_MAX}))"
            f" or "
            f"(outbound and loopback and ip and tcp and "
            f"tcp.SrcPort == {self.proxy_port})"
        )

        try:
            wd.open(filt)
        except OSError as e:
            print(f"[DIVERT] FAILED: {e}", file=sys.stderr)
            print("[DIVERT] Run as Administrator!", file=sys.stderr)
            return

        self.running = True
        self._send_errors = 0
        self._pkt_count = 0
        print("[DIVERT] WinDivert 2.2 active — NAT mode (outbound only, no direction change)",
              file=sys.stderr)
        print(f"[DIVERT] Game ports: {sorted(GAME_PORTS)} → {local_ip}:{self.proxy_port}",
              file=sys.stderr)
        print(f"[DIVERT] Proxy outbound ports {PROXY_OUT_PORT_BASE}-{PROXY_OUT_PORT_MAX} EXCLUDED from filter",
              file=sys.stderr)

        try:
            while self.running:
                try:
                    raw, addr = wd.recv()
                except OSError as e:
                    if self.running:
                        print(f"[DIVERT] recv: {e}", file=sys.stderr)
                    continue

                info = _parse_ipv4_packet(raw)
                if not info:
                    try:
                        wd.send(raw, addr)
                    except OSError:
                        pass
                    continue

                tcp_off = info["tcp_off"]
                tcp_flags = raw[tcp_off + 13] if len(raw) > tcp_off + 13 else 0
                flags_s = "".join(c for c, m in [("S",0x02),("A",0x10),("F",0x01),("R",0x04),("P",0x08)] if tcp_flags & m)
                is_loopback = bool(addr.Flags & WINDIVERT_FLAG_LOOPBACK)
                is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)  # SYN without ACK

                if is_loopback and info["src_port"] == self.proxy_port:
                    # ═══ CASE 2: Proxy → Client (outbound на loopback) ═══
                    # Пакет: local_ip:proxy_port → local_ip:client_port
                    # Меняем src на game_server:game_port (обратный NAT)
                    client_port = info["dst_port"]

                    with self.lock:
                        entry = self.nat.get(client_port)

                    if not entry:
                        try:
                            wd.send(raw, addr)
                        except OSError:
                            pass
                        continue

                    game_ip, game_port, _ = entry

                    if self._pkt_count < 50:
                        print(f"[DIVERT] CASE2 [{flags_s}] "
                              f"{info['src_ip']}:{self.proxy_port}→{info['dst_ip']}:{client_port} "
                              f"→ src={game_ip}:{game_port} (loopback)",
                              file=sys.stderr)

                    modified = _modify_ipv4_packet(
                        raw, info,
                        new_src_ip=game_ip,
                        new_src_port=game_port)

                    # FIN/RST cleanup
                    if tcp_flags & 0x05:
                        with self.lock:
                            self.nat.pop(client_port, None)

                else:
                    # ═══ CASE 1: Outbound на VPN к game port ═══
                    # proxy→server трафик (порты 18000-18099) ИСКЛЮЧЁН на уровне фильтра
                    src_port = info["src_port"]
                    game_ip = info["dst_ip"]

                    # Пропускаем фейковые/недоступные IP (placeholder из L2.ini)
                    if game_ip in SKIP_DST_IPS:
                        try:
                            wd.send(raw, addr)
                        except OSError:
                            pass
                        continue

                    client_ip = info["src_ip"]
                    client_port = src_port
                    game_port = info["dst_port"]

                    # NAT запись: создаём на SYN, переиспользуем для остальных
                    with self.lock:
                        existing = self.nat.get(client_port)
                        if is_syn:
                            if existing and existing[0] == game_ip and existing[1] == game_port:
                                is_new = False  # SYN retransmission
                            else:
                                self.nat[client_port] = (game_ip, game_port, client_ip)
                                is_new = True
                        elif existing:
                            is_new = False
                        else:
                            # Не SYN и нет в NAT — stale пакет, пропускаем
                            try:
                                wd.send(raw, addr)
                            except OSError:
                                pass
                            continue

                    if is_new:
                        # NAT таблица для proxy (без race condition!)
                        with _nat_target_lock:
                            _nat_target[client_port] = (game_ip, game_port)
                        # Файл для совместимости (deprecated)
                        try:
                            tmp = TARGET_FILE + ".tmp"
                            with open(tmp, "w") as f:
                                f.write(f"{game_ip}:{game_port}\n")
                            os.replace(tmp, TARGET_FILE)
                        except Exception:
                            pass
                        print(f"[DIVERT] CASE1 [{flags_s}] "
                              f"{client_ip}:{client_port}→{game_ip}:{game_port} "
                              f"→ dst={local_ip}:{self.proxy_port} "
                              f"(if={addr.IfIdx} *NEW)",
                              file=sys.stderr)
                    elif self._pkt_count < 50:
                        print(f"[DIVERT] CASE1 [{flags_s}] "
                              f"{client_ip}:{client_port}→{game_ip}:{game_port}",
                              file=sys.stderr)

                    # FIN/RST cleanup
                    if tcp_flags & 0x05:
                        with self.lock:
                            self.nat.pop(client_port, None)
                        with _nat_target_lock:
                            _nat_target.pop(client_port, None)

                    modified = _modify_ipv4_packet(
                        raw, info,
                        new_dst_ip=local_ip,
                        new_dst_port=self.proxy_port)

                # Пересчитать checksums и реинжектировать (direction НЕ меняем!)
                modified = wd.calc_checksums(modified, addr)
                try:
                    wd.send(modified, addr)
                    self._pkt_count += 1
                except OSError as e:
                    self._send_errors += 1
                    if self._send_errors <= 5:
                        print(f"[DIVERT] send: {e} (#{self._send_errors})",
                              file=sys.stderr)

        except Exception as e:
            if self.running:
                print(f"[DIVERT] Error: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
        finally:
            wd.close()
            print(f"[DIVERT] Closed (pkts={self._pkt_count}, "
                  f"errors={self._send_errors})", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# Packet Builder Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _write_string(s: str) -> bytes:
    """L2 string: UTF-16LE null-terminated."""
    return s.encode("utf-16-le") + b'\x00\x00'


def build_say2(text: str, chat_type: int = 0, target: str = "") -> bytes:
    return b'\x49' + _write_string(text) + struct.pack("<I", chat_type) + _write_string(target)


def build_bypass(command: str) -> bytes:
    return b'\x23' + _write_string(command)


def build_admin_cmd(command: str) -> bytes:
    return b'\x74' + _write_string(command)


def build_use_item(object_id: int) -> bytes:
    return struct.pack("<BII", 0x19, object_id, 0)


def build_enchant_item(object_id: int) -> bytes:
    return struct.pack("<BI", 0x5F, object_id)


def build_action(object_id: int, x=0, y=0, z=0, shift=0) -> bytes:
    return struct.pack("<BIIIIb", 0x1F, object_id, x, y, z, shift)


def build_multisell_choose(list_id: int, entry_id: int, amount: int = 1) -> bytes:
    return struct.pack("<BIIq", 0xB0, list_id, entry_id, amount) + b'\x00' * 24


# ═══════════════════════════════════════════════════════════════════════════════
# MCP Server
# ═══════════════════════════════════════════════════════════════════════════════

class L2McpServer:
    def __init__(self, store: PacketStore, proxy: L2MitmProxy):
        self.store = store
        self.proxy = proxy

    async def run(self):
        from mcp.server import Server
        import mcp.types as types

        server = Server("l2-packet-proxy")

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            return self._define_tools(types)

        @server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list:
            try:
                result = self._dispatch(name, arguments)
                return [types.TextContent(
                    type="text",
                    text=json.dumps(result, ensure_ascii=False, indent=2),
                )]
            except Exception as e:
                import traceback
                return [types.TextContent(
                    type="text",
                    text=json.dumps({
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    }, ensure_ascii=False),
                )]

        from mcp.server.stdio import stdio_server
        async with stdio_server() as (rs, ws):
            print("[MCP] Serving on stdio", file=sys.stderr)
            await server.run(rs, ws, server.create_initialization_options())

    @staticmethod
    def _define_tools(types):
        T = types.Tool

        def _schema(**props):
            req = [k for k, v in props.items() if v.pop("required", False)]
            return {"type": "object", "properties": props,
                    **({"required": req} if req else {})}

        return [
            T(name="l2_get_packets",
              description="Последние перехваченные L2 пакеты. "
                          "Фильтр по направлению, опкоду, имени.",
              inputSchema=_schema(
                  count={"type": "integer", "default": 50,
                         "description": "Количество пакетов"},
                  direction={"type": "string", "enum": ["C2S", "S2C", "all"],
                             "default": "all"},
                  opcode={"type": "string",
                          "description": "Hex опкод ('49' для Say2)"},
                  name_filter={"type": "string",
                               "description": "Подстрока в имени пакета"},
              )),
            T(name="l2_get_stats",
              description="Статистика пакетов: кол-во по типам и направлениям.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_get_crypto",
              description="Состояние криптографии: BF/XOR ключи, счётчики.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_inject_raw",
              description="Инъекция сырого C→S пакета (hex). "
                          "Первый байт = опкод.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True,
                            "description": "Hex данные пакета без заголовка длины"},
              )),
            T(name="l2_inject_say2",
              description="Отправить сообщение в чат.",
              inputSchema=_schema(
                  text={"type": "string", "required": True},
                  chat_type={"type": "integer", "default": 0,
                             "description": "0=all,1=shout,2=tell,3=party,"
                                            "4=clan,8=trade,15=hero"},
                  target={"type": "string", "default": "",
                          "description": "Получатель (для tell)"},
              )),
            T(name="l2_inject_bypass",
              description="BypassToServer (0x23) — NPC диалоги, внутренние команды.",
              inputSchema=_schema(
                  command={"type": "string", "required": True,
                           "description": "Bypass строка"},
              )),
            T(name="l2_inject_admin",
              description="SendBypassBuildCmd (0x74) — GM/Admin команды.",
              inputSchema=_schema(
                  command={"type": "string", "required": True,
                           "description": "admin_gmspeed 5, admin_enchant 65535, "
                                          "admin_spawn <npcId>"},
              )),
            T(name="l2_inject_use_item",
              description="UseItem (0x19) — использовать предмет.",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True},
              )),
            T(name="l2_inject_enchant",
              description="RequestEnchantItem (0x5F).",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True},
              )),
            T(name="l2_inject_action",
              description="Action (0x1F) — клик по объекту.",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True},
                  shift={"type": "integer", "default": 0,
                         "description": "0=простой клик, 1=shift-клик"},
              )),
            T(name="l2_replay",
              description="Повторно отправить C→S пакет по номеру seq.",
              inputSchema=_schema(
                  seq={"type": "integer", "required": True},
              )),
            T(name="l2_flood",
              description="Отправить пакет N раз — race condition тест.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True},
                  count={"type": "integer", "default": 10},
                  delay_ms={"type": "integer", "default": 0,
                            "description": "Задержка между пакетами (мс)"},
              )),
            T(name="l2_multisell",
              description="MultiSellChoose (0xB0) — покупка в мультиселе.",
              inputSchema=_schema(
                  list_id={"type": "integer", "required": True},
                  entry_id={"type": "integer", "required": True},
                  amount={"type": "integer", "default": 1},
              )),
            T(name="l2_inject_s2c",
              description="Инъекция S→C пакета (hex) — спуфинг от имени сервера клиенту. "
                          "Первый байт = опкод S2C.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True,
                            "description": "Hex данные S2C пакета"},
              )),
        ]

    def _dispatch(self, name: str, args: dict) -> dict:
        if name == "l2_get_packets":
            count = args.get("count", 50)
            d = args.get("direction", "all")
            d = None if d == "all" else d
            op = {int(args["opcode"], 16)} if args.get("opcode") else None
            nf = args.get("name_filter")
            pkts = self.store.get_recent(count, d, op, nf)
            return {"count": len(pkts), "packets": pkts}

        if name == "l2_get_stats":
            return self.store.get_stats()

        if name == "l2_get_crypto":
            c = self.proxy.crypto
            if not c:
                return {"status": "no session"}
            return {
                "bf_key": c.bf_key.hex() if c.bf_key else None,
                "xor_key": c.xor_key.hex() if c.xor_key else None,
                "initialized": c.initialized,
                "key_init": {k: v.hex() if isinstance(v, (bytes, bytearray)) else v
                             for k, v in (c.key_init_data or {}).items()},
                "packets_c2s": self.proxy.pkt_c2s,
                "packets_s2c": self.proxy.pkt_s2c,
                "running": self.proxy.running,
            }

        if name == "l2_inject_raw":
            return self._inject(bytes.fromhex(args["hex_data"]))

        if name == "l2_inject_say2":
            return self._inject(build_say2(
                args["text"], args.get("chat_type", 0), args.get("target", "")))

        if name == "l2_inject_bypass":
            return self._inject(build_bypass(args["command"]))

        if name == "l2_inject_admin":
            return self._inject(build_admin_cmd(args["command"]))

        if name == "l2_inject_use_item":
            return self._inject(build_use_item(args["object_id"]))

        if name == "l2_inject_enchant":
            return self._inject(build_enchant_item(args["object_id"]))

        if name == "l2_inject_action":
            return self._inject(build_action(
                args["object_id"], shift=args.get("shift", 0)))

        if name == "l2_replay":
            pkt = self.store.get_by_seq(args["seq"])
            if not pkt or pkt["dir"] != "C2S" or not pkt["dec_hex"]:
                return {"error": f"C2S packet #{args['seq']} not found"}
            return self._inject(bytes.fromhex(pkt["dec_hex"]))

        if name == "l2_flood":
            data = bytes.fromhex(args["hex_data"])
            count = args.get("count", 10)
            delay_ms = args.get("delay_ms", 0)

            def flood():
                for _ in range(count):
                    self.proxy.inject_c2s.append(data)
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)

            threading.Thread(target=flood, daemon=True).start()
            op, nm = decode_opcode(data, "C2S")
            return {"status": "flooding", "opcode": f"0x{op:04X}",
                    "name": nm, "count": count}

        if name == "l2_multisell":
            return self._inject(build_multisell_choose(
                args["list_id"], args["entry_id"], args.get("amount", 1)))

        if name == "l2_inject_s2c":
            return self._inject_s2c(bytes.fromhex(args["hex_data"]))

        return {"error": f"Unknown tool: {name}"}

    def _inject(self, plaintext: bytes) -> dict:
        """Inject C→S packet (as if client sent it to server)."""
        if not self.proxy.running:
            return {"error": "Proxy not running — no active game session"}
        op, nm = decode_opcode(plaintext, "C2S")
        self.proxy.inject_c2s.append(plaintext)
        return {"status": "queued", "direction": "C2S",
                "opcode": f"0x{op:04X}", "name": nm, "size": len(plaintext)}

    def _inject_s2c(self, plaintext: bytes) -> dict:
        """Inject S→C packet (as if server sent it to client)."""
        if not self.proxy.running:
            return {"error": "Proxy not running — no active game session"}
        op, nm = decode_opcode(plaintext, "S2C")
        self.proxy.inject_s2c.append(plaintext)
        return {"status": "queued", "direction": "S2C",
                "opcode": f"0x{op:04X}", "name": nm, "size": len(plaintext)}


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="L2 MCP Proxy v2 — packet interceptor + MCP server")
    parser.add_argument("--mode", choices=["mcp", "proxy", "divert", "all"],
                        default="all")
    parser.add_argument("--port", type=int, default=PROXY_PORT)
    parser.add_argument("--log", default=LOG_FILE)
    parser.add_argument("--no-divert", action="store_true",
                        help="Не использовать WinDivert (нужен внешний redirect)")
    parser.add_argument("--target", default=None,
                        help="Адрес сервера ip:port (вместо файла)")
    parser.add_argument("--packets-ini", default=None,
                        help="Путь к PacketsXXX.ini для загрузки опкодов")
    args = parser.parse_args()

    if args.target:
        ip, port = args.target.rsplit(":", 1)
        global DEFAULT_TARGET
        DEFAULT_TARGET = (ip, int(port))
        try:
            with open(TARGET_FILE, "w") as f:
                f.write(f"{ip}:{port}\n")
        except Exception:
            pass

    # Загрузить опкоды из .ini если указано, иначе — попробовать PacketsFreya.ini
    if args.packets_ini:
        load_opcodes_from_ini(args.packets_ini)
    else:
        default_ini = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "soft", "l2phx", "settings", "PacketsFreya.ini")
        if os.path.exists(default_ini):
            load_opcodes_from_ini(default_ini)

    # Очистить debug log для чистого теста
    try:
        with open(DEBUG_FILE, "w") as f:
            f.write(f"=== L2 MCP Proxy started {datetime.now().isoformat()} ===\n")
    except Exception:
        pass

    store = PacketStore()
    store.open_log(args.log)

    proxy = L2MitmProxy(store, args.port)
    mcp = L2McpServer(store, proxy)

    if args.mode in ("proxy", "all"):
        threading.Thread(target=proxy.run, daemon=True, name="proxy").start()

    if args.mode in ("divert", "all") and not args.no_divert:
        threading.Thread(
            target=WinDivertRedirector(args.port).run,
            daemon=True, name="divert").start()

    if args.mode in ("mcp", "all"):
        asyncio.run(mcp.run())
    else:
        print(f"[L2MCP] Running mode={args.mode}. Ctrl+C to stop.",
              file=sys.stderr)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
