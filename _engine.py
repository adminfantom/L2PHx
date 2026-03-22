#!/usr/bin/env python
"""
L2 MCP Proxy v3 — Lineage 2 MITM-перехватчик пакетов + MCP сервер для Claude.

Архитектура (двухкомпонентная):

  Порт 2106/17453 — MITM-proxy через WinDivert NAT redirect:
    Game Client ←→ WinDivert NAT ←→ L2MitmProxy ←→ Real Server
                                          ↕
                                     MCP Server (stdio) + Web GUI
                                          ↕
                                     Claude Agent

  Порт 7777 — пассивный сниффер (НЕ MITM, intercept+reinject):
    Game Client ←→ WinDivertSniffer (копия пакетов) ←→ Real Server
                         ↓                                (напрямую)
                    XOR decrypt + opcode parse (read-only)

  Инъекция пакетов идёт через relay-канал 17453, НЕ через 7777.

Крипто-пайплайн:
  Порт 2106: shadow-init (Ertheia KeyInit, короткое PASSTHROUGH окно).
  Порт 17453: plaintext intermediate relay.
    Пакеты обёрнуты в outer protocol (relay 0x06 с double-XOR обфускацией).
    PLAINTEXT_INTERMEDIATE=True: шифрование на wire отсутствует.
    KeyInit пакет пересылается для совместимости, но сам relay plaintext.
  Порт 7777: XOR stream cipher (Interlude+ 16-byte key).
    Первый S2C = VERSION_CHECK (plaintext), содержит base_key[8].
    Все последующие пакеты зашифрованы с раздельным XOR state для S2C/C2S.
    Rolling counter: key[8..11] += body_size после каждого пакета.
    MITM невозможен без синхронизации rolling state — используем пассивный sniff.

Формат L2 пакетов: [2b LE length (включая 2b)] [1-3b opcode] [body]
Опкоды: 0x01-0xFD=1 байт, 0xFE+LE16=ExOp (S2C), 0xD0+LE16=ExOp2 (C2S).

Авторизованный пентест Innova/4Game, Dec 2025 - Mar 2026.
"""

import asyncio
import socket
import struct
import threading
import queue as _queue_mod
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

# Порты для MITM-proxy (WinDivert NAT redirect → L2MitmProxy).
# НЕ включает 7777: на нём XOR stream cipher, MITM ломает rolling state.
# 7777 обрабатывается отдельным WinDivertSniffer (пассивный intercept+reinject).
GAME_PORTS = {2106, 17453} | set(range(7900, 7921))
PROXY_PORT = 17777
# Relay-канал 17453: plaintext (Blowfish удалён, KeyInit для совместимости).
# XOR шифрование на 7777 обрабатывается сниффером, не прокси.
PLAINTEXT_INTERMEDIATE = True
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

# ═══ WAREHOUSE RACE CONDITION HOOK ═══
# При обнаружении C2S 0x3C (withdraw) в relay — мгновенный replay N копий.
# Включается через API: POST /api/race_hook {"enabled": true, "count": 20}
_RACE_HOOK = {
    "enabled": True,   # активен по умолчанию
    "opcode": 0x3C,    # withdraw warehouse
    "count": 30,       # кол-во дополнительных копий
    "fired": False,    # одноразовый (сбрасывается через API)
    "log": [],         # лог срабатываний
}

# ═══ MULTISELL CAPTURE + REPLAY ═══
# Перехватывает C2S MultiSellChoose (0xB0) game_body (с field-XOR),
# позволяет replay с модификацией entry_id через XOR-арифметику.
_MULTISELL_CAP = {
    "enabled": True,
    "captured": [],       # list of {ts, game_hex, game_len, opcode, list_id_enc, entry_id_enc}
    "max_captures": 10,   # хранить последние N
}

# ═══ UNIVERSAL GAME BODY CAPTURE ═══
# Ловит ВСЕ не-padding game_body из relay 0x06 фреймов.
# Опкоды зашифрованы game-cipher, поэтому ловим всё и фильтруем по размеру/времени.
_GAME_CAP = {
    "enabled": True,
    "captured": [],       # list of {ts, game_hex, game_len, first_byte, pkt_type}
    "max_captures": 200,
    "min_len": 5,         # минимальная длина game_body для захвата
    "unique_only": True,  # пропускать дубликаты по game_hex
    "_seen_hashes": set(), # для дедупликации
}

# State for l2_identify_action MCP tool
_IDENTIFY_STATE = {"active": False, "start_seq": 0, "label": "", "start_ts": ""}


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

# ═══ C2S опкоды Ertheia (L2J Mobius 1.0 Ertheia) ═══
# Источник: L2J_Mobius_1.0_Ertheia IncomingPackets.java
C2S_OPCODES = {
    0x00: "Logout",
    0x01: "Attack",
    0x03: "RequestStartPledgeWar",
    0x04: "RequestReplyStartPledgeWar",
    0x05: "RequestStopPledgeWar",
    0x06: "Relay_0x06",  # На 17453: relay container; legacy: RequestReplyStopPledgeWar
    0x07: "RequestSurrenderPledgeWar",
    0x08: "RequestReplySurrenderPledgeWar",
    0x09: "RequestSetPledgeCrest",
    0x0B: "RequestGiveNickName",
    0x0C: "CharacterCreate",
    0x0D: "CharacterDelete",
    0x0E: "ProtocolVersion",
    0x0F: "MoveBackwardToLocation",
    0x11: "EnterWorld",
    0x12: "CharacterSelect",
    0x13: "NewCharacter",
    0x14: "RequestItemList",
    0x16: "RequestUnEquipItem",
    0x17: "RequestDropItem",
    0x19: "UseItem",
    0x1A: "TradeRequest",
    0x1B: "AddTradeItem",
    0x1C: "TradeDone",
    0x1F: "Action",
    0x22: "RequestLinkHtml",
    0x23: "RequestBypassToServer",
    0x24: "RequestBBSwrite",
    0x26: "RequestJoinPledge",
    0x27: "RequestAnswerJoinPledge",
    0x28: "RequestWithdrawalPledge",
    0x29: "RequestOustPledgeMember",
    0x2B: "AuthLogin",
    0x2C: "RequestGetItemFromPet",
    0x2E: "RequestAllyInfo",
    0x2F: "RequestCrystallizeItem",
    0x30: "RequestPrivateStoreManageSell",
    0x31: "SetPrivateStoreListSell",
    0x32: "AttackRequest",
    0x37: "RequestSellItem",
    0x38: "RequestMagicSkillList",
    0x39: "RequestMagicSkillUse",
    0x3A: "Appearing",
    0x3B: "SendWareHouseDepositList",
    0x3C: "SendWareHouseWithDrawList",
    0x3D: "RequestShortCutReg",
    0x3F: "RequestShortCutDel",
    0x40: "RequestBuyItem",
    0x42: "RequestJoinParty",
    0x43: "RequestAnswerJoinParty",
    0x44: "RequestWithDrawalParty",
    0x45: "RequestOustPartyMember",
    0x47: "CannotMoveAnymore",
    0x48: "RequestTargetCanceld",
    0x49: "Say2",
    0x4D: "RequestPledgeMemberList",
    0x50: "RequestSkillList",
    0x52: "MoveWithDelta",
    0x53: "RequestGetOnVehicle",
    0x54: "RequestGetOffVehicle",
    0x55: "AnswerTradeRequest",
    0x56: "RequestActionUse",
    0x57: "RequestRestart",
    0x59: "ValidatePosition",
    0x5B: "StartRotating",
    0x5C: "FinishRotating",
    0x5E: "RequestShowBoard",
    0x5F: "RequestEnchantItem",
    0x60: "RequestDestroyItem",
    0x62: "RequestQuestList",
    0x63: "RequestQuestAbort",
    0x65: "RequestPledgeInfo",
    0x66: "RequestPledgeExtendedInfo",
    0x67: "RequestPledgeCrest",
    0x6B: "RequestSendFriendMsg",
    0x6C: "RequestShowMiniMap",
    0x6E: "RequestRecordInfo",
    0x6F: "RequestHennaEquip",
    0x70: "RequestHennaRemoveList",
    0x71: "RequestHennaItemRemoveInfo",
    0x72: "RequestHennaRemove",
    0x73: "RequestAcquireSkillInfo",
    0x74: "SendBypassBuildCmd",
    0x75: "RequestMoveToLocationInVehicle",
    0x76: "CannotMoveAnymoreInVehicle",
    0x77: "RequestFriendInvite",
    0x78: "RequestAnswerFriendInvite",
    0x79: "RequestFriendList",
    0x7A: "RequestFriendDel",
    0x7B: "CharacterRestore",
    0x7C: "RequestAcquireSkill",
    0x7D: "RequestRestartPoint",
    0x7E: "RequestGMCommand",
    0x7F: "RequestPartyMatchConfig",
    0x80: "RequestPartyMatchList",
    0x81: "RequestPartyMatchDetail",
    0x83: "RequestPrivateStoreBuy",
    0x85: "RequestTutorialLinkHtml",
    0x86: "RequestTutorialPassCmdToServer",
    0x87: "RequestTutorialQuestionMark",
    0x88: "RequestTutorialClientEvent",
    0x89: "RequestPetition",
    0x8A: "RequestPetitionCancel",
    0x8B: "RequestGmList",
    0x8C: "RequestJoinAlly",
    0x8D: "RequestAnswerJoinAlly",
    0x8E: "AllyLeave",
    0x8F: "AllyDismiss",
    0x90: "RequestDismissAlly",
    0x91: "RequestSetAllyCrest",
    0x92: "RequestAllyCrest",
    0x93: "RequestChangePetName",
    0x94: "RequestPetUseItem",
    0x95: "RequestGiveItemToPet",
    0x96: "RequestPrivateStoreQuitSell",
    0x97: "SetPrivateStoreMsgSell",
    0x98: "RequestPetGetItem",
    0x99: "RequestPrivateStoreManageBuy",
    0x9A: "SetPrivateStoreListBuy",
    0x9C: "RequestPrivateStoreQuitBuy",
    0x9D: "SetPrivateStoreMsgBuy",
    0x9F: "RequestPrivateStoreSell",
    0xA7: "RequestPackageSendableItemList",
    0xA8: "RequestPackageSend",
    0xA9: "RequestBlock",
    0xAA: "RequestSiegeInfo",
    0xAB: "RequestSiegeAttackerList",
    0xAC: "RequestSiegeDefenderList",
    0xAD: "RequestJoinSiege",
    0xAE: "RequestConfirmSiegeWaitingList",
    0xAF: "RequestSetCastleSiegeTime",
    0xB0: "MultiSellChoose",
    0xB3: "BypassUserCmd",
    0xB4: "SnoopQuit",
    0xB5: "RequestRecipeBookOpen",
    0xB6: "RequestRecipeBookDestroy",
    0xB7: "RequestRecipeItemMakeInfo",
    0xB8: "RequestRecipeItemMakeSelf",
    0xBA: "RequestRecipeShopMessageSet",
    0xBB: "RequestRecipeShopListSet",
    0xBE: "RequestRecipeShopMakeInfo",
    0xBF: "RequestRecipeShopMakeItem",
    0xC0: "RequestRecipeShopManagePrev",
    0xC1: "ObserverReturn",
    0xC3: "RequestHennaItemList",
    0xC4: "RequestHennaItemInfo",
    0xC5: "RequestBuySeed",
    0xC6: "DlgAnswer",
    0xC7: "RequestPreviewItem",
    0xC9: "RequestPetitionFeedback",
    0xCB: "GameGuardReply",
    0xCC: "RequestPledgePower",
    0xCD: "RequestMakeMacro",
    0xCE: "RequestDeleteMacro",
    0xD0: "ExPacket",
}

# S2C опкоды — базовая таблица (дополняется из l2_opcodes.json / INI)
# Источник: реконструкция протокола + L2J Mobius Ertheia
S2C_OPCODES = {
    0x00: "S_DIE",
    0x01: "S_REVIVE",
    0x02: "S_ATTACK_OUT_OF_RANGE",
    0x03: "S_ATTACK_IN_COOLTIME",
    0x04: "S_ATTACK_DEAD_TARGET",
    0x05: "S_SPAWN_ITEM",
    0x06: "S_SELL_LIST",
    0x07: "S_BUY_LIST",
    0x08: "S_DELETE_OBJECT",
    0x09: "S_CHAR_SELECTION_INFO",
    0x0A: "S_LOGIN_RESULT",
    0x0B: "S_CHAR_SELECTED",
    0x0C: "S_NPC_INFO",
    0x0D: "S_NEW_CHAR_SUCCESS",
    0x0E: "S_AUTH_LOGIN_OK",
    0x0F: "S_CHAR_CREATE_FAIL",
    0x10: "S_ITEM_LIST",
    0x11: "S_ITEMLIST",
    0x12: "S_STATUS_UPDATE",
    0x13: "S_MOVE_TO_LOCATION",
    0x14: "S_TRADE_START",
    0x15: "S_TRADE_OWN_ADD",
    0x16: "S_TRADE_OTHER_ADD",
    0x17: "S_TRADE_DONE",
    0x18: "S_CHAR_INFO",
    0x19: "S_USER_INFO",
    0x1A: "S_ATTACK",
    0x1B: "S_DROP_ITEM",
    0x1C: "S_GET_ITEM",
    0x1D: "S_TELEPORT_TO_LOCATION",
    0x1E: "S_TARGET_SELECTED",
    0x1F: "S_TARGET_UNSELECTED",
    0x20: "S_AUTO_ATTACK_START",
    0x21: "S_AUTO_ATTACK_STOP",
    0x22: "S_SOCIAL_ACTION",
    0x23: "S_CHANGE_MOVE_TYPE",
    0x24: "S_CHANGE_WAIT_TYPE",
    0x25: "S_MANAGE_PLEDGE_POWER",
    0x27: "S_ACTION_FAILED",
    0x28: "S_MAGIC_SKILL_USE",
    0x29: "S_MAGIC_SKILL_CANCELED",
    0x2A: "S_SAY2",
    0x2B: "S_NPC_SAY",
    0x2C: "S_CHAR_CREATE_OK",
    0x2D: "S_PLEDGE_SHOW_MEMBER_LIST",
    0x2E: "S_VERSION_CHECK",
    0x2F: "S_PLEDGE_STATUS_CHANGED",
    0x31: "S_STOP_MOVE",
    0x32: "S_MAGIC_SKILL_LAUNCHED",
    0x33: "S_SKILL_LIST",
    0x36: "S_SAY",
    0x37: "S_NPC_HTML_MESSAGE",
    0x39: "S_VEHICLE_INFO",
    0x3A: "S_VEHICLE_DEPARTURE",
    0x3D: "S_CHAR_DELETE_OK",
    0x3E: "S_CHAR_DELETE_FAIL",
    0x3F: "S_INVENTORY_UPDATE",
    0x41: "S_WAREHOUSE_DEPOSIT_LIST",
    0x42: "S_WAREHOUSE_WITHDRAW_LIST",
    0x43: "S_WAREHOUSE_DONE",
    0x44: "S_SHORT_CUT_REG",
    0x45: "S_SHORT_CUT_INIT",
    0x48: "S_SKILL_COOL_TIME",
    0x4B: "S_MOVE_TO_PAWN",
    0x4C: "S_VALIDATE_LOCATION",
    0x4E: "S_START_ROTATING",
    0x4F: "S_STOP_ROTATING",
    0x52: "S_SYSTEM_MESSAGE",
    0x53: "S_START_PLEDGE_WAR",
    0x58: "S_FRIEND_LIST",
    0x5A: "S_MAGIC_LIST",
    0x5E: "S_MAGIC_LIST_2",
    0x62: "S_QUEST_LIST",
    0x65: "S_ABNORMAL_STATUS_UPDATE",
    0x67: "S_QUEST_ACCEPT",
    0x68: "S_PLEDGE_INFO",
    0x6C: "S_SHOW_BOARD",
    0x6D: "S_CLOSE_BOARD",
    0x71: "S_PRIVATE_STORE_MANAGE_LIST_SELL",
    0x75: "S_FRIEND_PACKET",
    0x76: "S_L2_FRIEND_SAY",
    0x7A: "S_SHOW_MINIMAP",
    0x7F: "S_REVIVE_REQUEST",
    0x84: "S_ABNORMAL_VISUAL_EFFECT",
    0x86: "S_TUTORIAL_SHOW_HTML",
    0x88: "S_TUTORIAL_ENABLE_CLIENT_EVENT",
    0xA0: "S_PRIVATE_STORE_MANAGE_LIST",
    0xA1: "S_PRIVATE_STORE_LIST",
    0xA2: "S_PRIVATE_STORE_MSG",
    0xA4: "S_SHOW_XMASSEAL",
    0xC7: "S_SKILL_COOL_TIME_2",
    0xCB: "S_GAMEGUARD_QUERY",
    0xD9: "S_NET_PING",
    0xE4: "S_HENNA_ITEM_INFO",
    0xE5: "S_HENNA_INFO",
    0xEE: "S_HENNA_EQUIP_LIST",
    0xF8: "S_SHOW_XMASSEAL_2",
}

# S2C Extended опкоды — базовые (дополняются из l2_opcodes.json)
S2C_EX = {
    0x01B0: "S_EX_QUEUETICKET",
    0x01B6: "S_EX_QUEUETICKET_LOGIN",
    0x030B: "S_EX_BR_VERSION",
}

# ═══ C2S Extended опкоды Ertheia (0xD0 + 2B sub-opcode) ═══
# Источник: L2J_Mobius_1.0_Ertheia ExIncomingPackets.java
C2S_EX = {
    0x01: "RequestManorList",
    0x02: "RequestProcureCropList",
    0x03: "RequestSetSeed",
    0x04: "RequestSetCrop",
    0x05: "RequestWriteHeroWords",
    0x06: "RequestExAskJoinMPCC",
    0x07: "RequestExAcceptJoinMPCC",
    0x08: "RequestExOustFromMPCC",
    0x09: "RequestOustFromPartyRoom",
    0x0A: "RequestDismissPartyRoom",
    0x0B: "RequestWithdrawPartyRoom",
    0x0C: "RequestChangePartyLeader",
    0x0D: "RequestAutoSoulShot",
    0x0E: "RequestExEnchantSkillInfo",
    0x0F: "RequestExEnchantSkill",
    0x10: "RequestExPledgeCrestLarge",
    0x11: "RequestExSetPledgeCrestLarge",
    0x12: "RequestPledgeSetAcademyMaster",
    0x13: "RequestPledgePowerGradeList",
    0x14: "RequestPledgeMemberPowerInfo",
    0x15: "RequestPledgeSetMemberPowerGrade",
    0x16: "RequestPledgeMemberInfo",
    0x17: "RequestPledgeWarList",
    0x18: "RequestExFishRanking",
    0x19: "RequestPCCafeCouponUse",
    0x1B: "RequestDuelStart",
    0x1C: "RequestDuelAnswerStart",
    0x1E: "RequestExSetTutorial",
    0x20: "RequestExRqItemLink",
    0x21: "CannotMoveAnymoreAirShip",
    0x22: "MoveToLocationInAirShip",
    0x23: "RequestKeyMapping",
    0x24: "RequestSaveKeyMapping",
    0x25: "RequestExRemoveItemAttribute",
    0x26: "RequestSaveInventoryOrder",
    0x27: "RequestExitPartyMatchingWaitingRoom",
    0x28: "RequestConfirmTargetItem",
    0x29: "RequestConfirmRefinerItem",
    0x2A: "RequestConfirmGemStone",
    0x2B: "RequestOlympiadObserverEnd",
    0x2C: "RequestCursedWeaponLocation",
    0x2D: "RequestCursedWeaponInfo",
    0x2E: "RequestFortressMapInfo",
    0x2F: "RequestAllFortressInfo",
    0x30: "RequestFortressSiegeInfo",
    0x31: "RequestGetBossRecord",
    0x32: "RequestRefine",
    0x33: "RequestConfirmCancelItem",
    0x34: "RequestRefineCancel",
    0x35: "RequestExMagicSkillUseGround",
    0x36: "RequestDuelSurrender",
    0x37: "RequestExEnchantSkillInfoDetail",
    0x39: "RequestAllCastleInfo",
    0x3A: "RequestAllFortressInfo2",
    0x3B: "RequestFortressSiegeInfo2",
    0x3C: "RequestCastleSiegeInfo",
    0x3E: "RequestBrProductList",
    0x3F: "RequestBrProductInfo",
    0x40: "RequestBrBuyProduct",
    0x41: "RequestBrRecentProductList",
    0x42: "RequestBrMinigameLoadScores",
    0x43: "RequestBrMinigameInsertScore",
    0x44: "RequestExBrLectureMark",
    0x45: "RequestCrystallizeEstimate",
    0x46: "RequestCrystallizeItemCancel",
    0x47: "SetPrivateStoreWholeMsg",
    0x48: "RequestExStepThrough",
    0x49: "RequestExTryToPutEnchantTargetItem",
    0x4A: "RequestExTryToPutEnchantSupportItem",
    0x4B: "RequestExCancelEnchantItem",
    0x4C: "RequestChangeNicknameColor",
    0x4D: "RequestResetNickname",
    0x51: "RequestBookMarkSlotInfo",
    0x52: "RequestSaveBookMarkSlot",
    0x53: "RequestModifyBookMarkSlot",
    0x54: "RequestDeleteBookMarkSlot",
    0x55: "RequestTeleportBookMark",
    0x57: "RequestBuySellUIClose",
    0x5E: "NotifyStartMiniGame",
    0x5F: "RequestJoinDominionWar",
    0x60: "RequestDominionInfo",
    0x63: "RequestExCleftEnter",
    0x67: "RequestChangeBookMarkSlot",
    0x6B: "RequestExJump",
    0x6C: "RequestExStartShowCrataeCubeRank",
    0x6D: "RequestExStopShowCrataeCubeRank",
    0x6E: "NotifyStartMiniGame2",
    0x6F: "RequestExSeedPhase",
    0x70: "RequestExCubeGameChangeTeam",
    0x71: "EndScenePlayer",
    0x72: "RequestExVoteNew",
    0x73: "RequestCheckAgitDecoAvailability",
    0x78: "RequestShowAgitDecoInfo",
    0x79: "RequestExChangeAgitDecoInfo",
    0x7A: "RequestCheckAgitName",
    0x7B: "RequestAgitDecoConfirm",
    0x7C: "RequestSetAgitAccessLevel",
    0x7D: "RequestAgitAccessLevel",
    0x7E: "RequestAgitBid",
    0x7F: "RequestAgitCancel",
    0x80: "RequestExAddContactToContactList",
    0x81: "RequestExDeleteContactFromContactList",
    0x82: "RequestExShowContactList",
    0x83: "RequestExFriendListExtended",
    0x84: "RequestExOlympiadMatchListRefresh",
    0x85: "RequestBrGamePoint",
    0x86: "RequestBrPaymentHistory",
    0x88: "RequestGoodsInventoryInfo",
    0x89: "RequestUseGoodsInventoryItem",
    0x8A: "RequestExBREventRankerList",
    0x8D: "RequestAddExpandQuestAlarm",
    0x8E: "RequestVoteNew",
    0x8F: "RequestGetOnShuttle",
    0x90: "RequestGetOffShuttle",
    0x91: "MoveToLocationInShuttle",
    0x92: "CannotMoveAnymoreInShuttle",
    0x93: "RequestSubPledgeInfo",
    0x95: "RequestExLotteryList",
    0x96: "RequestExRaidDamageMeter",
    0x97: "RequestExGoodsShopEvent",
    0x98: "RequestRegistBeauty",
    0x99: "RequestResetBeauty",
    0x9B: "RequestExRefundItem",
    0x9C: "RequestExBuySellShowNewYearSeals",
    0x9D: "RequestExBrNewIcons",
    0xA0: "RequestRegistPartySubstitute",
    0xA1: "RequestExDeletePartySubstitute",
    0xA2: "RequestExWaitForPartySubstitute",
    0xA3: "RequestExAcceptJoinMPCC2",
    0xA7: "RequestExTryToPutShapeShiftingTargetItem",
    0xA8: "RequestExTryToPutShapeShiftingEnchantSupportItem",
    0xA9: "RequestExCancelShapeShiftingItem",
    0xAA: "RequestShapeShiftingItem",
    0xB0: "RequestChangeAttributeItem",
    0xB1: "RequestChangeAttributeCancel",
    0xB4: "RequestBrPresentBuyProduct",
    0xB7: "ConfirmMenteeAdd",
    0xB8: "RequestMentorCancel",
    0xB9: "RequestMentorList",
    0xBA: "RequestMenteeAdd",
    0xBB: "RequestMenteeWaitingList",
    0xBC: "RequestClanAskJoinByName",
    0xBD: "RequestInzoneWaitingTime",
    0xBE: "RequestJoinCuriousHouse",
    0xBF: "RequestCancelCuriousHouse",
    0xC0: "RequestLeaveCuriousHouse",
    0xC1: "RequestObservingListCuriousHouse",
    0xC2: "RequestObservingCuriousHouse",
    0xC3: "RequestLeaveCuriousHouseObserving",
    0xC4: "RequestExSysstring",
    0xC5: "RequestExTryToPutEnchantTargetItem2",
    0xC6: "RequestExTryToPutEnchantSupportItem2",
    0xC7: "RequestExCancelEnchantItem2",
    0xC8: "ExRequestEnchantItem2",
    0xC9: "RequestExRemoveEnchantSupportItem2",
    0xCA: "RequestFlyMove",
    0xCE: "RequestExDynamicQuestHtmlProgress",
    0xCF: "RequestFortressSiegeInfo3",
    0xD0: "ExRequestChangeNicknameColor2",
    0xD1: "RequestExEnsoulWindow",
    0xD2: "RequestItemEnsoul",
    0xD3: "RequestCastleGate",
    0xD4: "RequestPvpMatchEvent",
    0xE6: "ExSendSelectedQuestZoneID",
    0xE7: "RequestAlchemySkillList",
    0xE8: "RequestAlchemyTryMixCube",
    0xE9: "RequestAbilityOpen",
    0xEA: "RequestAbilityAddLevel",
    0xEB: "RequestAbilityResetPoint",
    0xEC: "RequestAbilityWndOpen",
    0xED: "RequestAbilityWndClose",
    0xEE: "ExUserInfoStats",
    0xF0: "ExAutoPlay",
    0xF1: "ExAutoPlaySetting",
    0xF2: "ExRequestActivateAutoShortcut",
    0xF3: "ExRequestDeactivateAutoShortcut",
    0xF4: "RequestExEnchantItemAttribute",
    0xF5: "ExRequestNewEnchantPushOne",
    0xF6: "ExRequestNewEnchantRemoveOne",
    0xF7: "ExRequestNewEnchantPushTwo",
    0xF8: "ExRequestNewEnchantRemoveTwo",
    0xF9: "ExRequestNewEnchantClose",
    0xFA: "ExRequestCardReward",
    0xFB: "ExRequestDivideAdena",
    0xFC: "ExRequestDivideAdenaStart",
    0xFD: "ExRequestDivideAdenaCancel",
    0xFE: "ExRequestItemFortification",
    0xFF: "ExRequestCompoundOne",
    0x100: "ExRequestCompoundTwo",
    0x101: "ExRequestAlchemyConversion",
    0x104: "ExRequestAutoFish",
}

# Дополнительная таблица, загружаемая из .ini файлов или runtime
# Формат: {opcode: name}. Обновляется через load_opcodes_from_ini()
_custom_c2s: Dict[int, str] = {}
_custom_s2c: Dict[int, str] = {}
_custom_c2s_ex: Dict[int, str] = {}
_custom_s2c_ex: Dict[int, str] = {}


def load_opcodes_from_json(json_path: str):
    """Загрузить S2C опкоды из JSON-дампа памяти L2 клиента.

    Файл создаётся opcode_dumper.dll (injection через DSETUP.dll proxy).
    Содержит main_opcodes (0x00-0xFF) и ex_opcodes (0x0000-0x03CC).
    """
    global S2C_OPCODES, S2C_EX
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        loaded_main = 0
        for hex_op, name in data.get("main_opcodes", {}).items():
            op = int(hex_op, 16)
            S2C_OPCODES[op] = name
            loaded_main += 1

        loaded_ex = 0
        for hex_op, name in data.get("ex_opcodes", {}).items():
            op = int(hex_op, 16)
            S2C_EX[op] = name
            loaded_ex += 1

        print(f"[OPCODES] JSON dump: {loaded_main} main + {loaded_ex} ex S2C from {json_path}",
              file=sys.stderr)
    except FileNotFoundError:
        print(f"[OPCODES] JSON not found: {json_path}", file=sys.stderr)
    except Exception as e:
        print(f"[OPCODES] Error loading JSON {json_path}: {e}", file=sys.stderr)


def load_c2s_opcodes_from_json(json_path: str):
    """Загрузить C2S опкоды из JSON (L2J Mobius или дамп клиента).

    Поддерживает формат c2s_opcodes_ertheia.json:
      {main_opcodes: {hex: name}, ex_opcodes: {hex: name}}
    """
    global C2S_OPCODES, C2S_EX
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        loaded_main = 0
        for hex_op, name in data.get("main_opcodes", {}).items():
            op = int(hex_op, 16) if isinstance(hex_op, str) else hex_op
            C2S_OPCODES[op] = name
            loaded_main += 1

        loaded_ex = 0
        for hex_op, name in data.get("ex_opcodes", {}).items():
            op = int(hex_op, 16) if isinstance(hex_op, str) else hex_op
            C2S_EX[op] = name
            loaded_ex += 1

        print(f"[OPCODES] C2S JSON: {loaded_main} main + {loaded_ex} ex from {json_path}",
              file=sys.stderr)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[OPCODES] Error loading C2S JSON {json_path}: {e}", file=sys.stderr)


# Автозагрузка опкодов из дампа (ищем рядом с собой и в стандартных путях)
_OPCODE_JSON_PATHS = [
    os.path.join(_APP_DIR, "l2_opcodes.json"),
    os.path.join(_APP_DIR, "..", "..", "..", "_данные", "дампы", "l2_opcodes.json"),
    r"D:\tmp\l2_opcodes.json",
]
for _p in _OPCODE_JSON_PATHS:
    if os.path.isfile(_p):
        load_opcodes_from_json(_p)
        break

# Автозагрузка C2S опкодов
_C2S_JSON_PATHS = [
    os.path.join(_APP_DIR, "c2s_opcodes_ertheia.json"),
    os.path.join(_APP_DIR, "..", "..", "..", "_данные", "opcode_tables", "c2s_opcodes_ertheia.json"),
]
for _p in _C2S_JSON_PATHS:
    if os.path.isfile(_p):
        load_c2s_opcodes_from_json(_p)
        break


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

    if 153 <= len(body) <= 1024:
        # Длинный формат (Ertheia+ с RSA) — опкод обфусцирован, определяем по размеру
        # KeyInit 153-1024 байт. Современные версии могут иметь расширенные ключи.
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

    elif 24 <= len(body) < 153:
        # Средний формат (Intermediate) — нет RSA, но есть BF key
        # op(1) + session_id(4) + proto_ver(4) + [game_guard?] + bf_key
        result["format"] = "intermediate"
        result["session_id"] = struct.unpack_from("<I", body, 1)[0]
        result["protocol_version"] = struct.unpack_from("<I", body, 5)[0]
        # BF key в конце пакета (последние 16-21 байт) или сразу после заголовка
        # Пробуем: всё после заголовка (9 байт) как crypto material
        crypto_data = body[9:]
        if len(crypto_data) >= 21:
            # Если достаточно данных — берём последние 21 байт как BF key (как Ertheia)
            result["bf_key"] = crypto_data[-21:]
            result["xor_key"] = result["bf_key"][:8]
        elif len(crypto_data) >= 16:
            result["bf_key"] = crypto_data[-16:]
            result["xor_key"] = result["bf_key"][:8]
        elif len(crypto_data) >= 8:
            result["bf_key"] = crypto_data[:min(len(crypto_data), 21)]
            result["xor_key"] = crypto_data[:8]
        _dbg(f"[KEYINIT] Intermediate format! session=0x{result['session_id']:08X} "
             f"proto={result['protocol_version']} crypto_data={len(crypto_data)}b "
             f"bf_key={result.get('bf_key', b'').hex()}")
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
    _dbg(f"[KEYINIT] NOT a KeyInit: size={len(body)} (need >=153 for Ertheia, 24-152 for Intermediate, or 15-23 for Freya)")
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
            # Полное тело пакета для детального анализа
            pkt["_body"] = bytes(decrypted) if decrypted else (bytes(raw) if raw else b"")
            self.packets.append(pkt)

            # Дамп бинарных пакетов на диск
            dump_dir = os.path.join(_LOG_DIR, "pkt_dump")
            os.makedirs(dump_dir, exist_ok=True)
            safe_name = opname.replace(":", "_").replace("/", "_")[:30]
            fname = f"{self.seq:05d}_{direction}_{opcode:04X}_{safe_name}.bin"
            try:
                with open(os.path.join(dump_dir, fname), "wb") as df:
                    df.write(pkt["_body"])
            except Exception:
                pass
            # Дамп raw данных если отличается от decrypted (для анализа шифрования)
            if raw and decrypted and bytes(raw) != bytes(decrypted):
                raw_fname = f"{self.seq:05d}_{direction}_{opcode:04X}_RAW.bin"
                try:
                    with open(os.path.join(dump_dir, raw_fname), "wb") as rf:
                        rf.write(bytes(raw))
                except Exception:
                    pass

            line = (f"[{ts}] {direction} #{self.seq} "
                    f"op=0x{opcode:04X}({opname}) len={len(raw)}")
            if decrypted:
                line += f" | {decrypted[:48].hex()}"
            # Если raw отличается от decrypted, показать raw тоже (для анализа шифрования)
            if raw and decrypted and bytes(raw) != bytes(decrypted):
                line += f" raw={bytes(raw)[:32].hex()}"

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
                # Не включаем _body в JSON ответ (экономия трафика)
                pkt_copy = {k: v for k, v in pkt.items() if k != "_body"}
                result.append(pkt_copy)
                if len(result) >= count:
                    break
            return list(reversed(result))

    def get_since_seq(self, since_seq: int, max_count: int = 500) -> list:
        """Получить все пакеты с seq > since_seq (не пропуская ни одного)."""
        with self.lock:
            result = []
            for pkt in self.packets:
                if pkt["seq"] <= since_seq:
                    continue
                pkt_copy = {k: v for k, v in pkt.items() if k != "_body"}
                result.append(pkt_copy)
                if len(result) >= max_count:
                    break
            return result

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
        self.xor_only = False  # True = XOR without Blowfish (intermediate protocol)
        # Shadow crypto — для пассивной расшифровки без модификации потока
        self.shadow_enabled = False
        self.shadow_bf: Optional[L2BlowfishCipher] = None
        self.shadow_xor_s2c: Optional[L2XorCipher] = None
        self.shadow_xor_c2s: Optional[L2XorCipher] = None

    def enable_xor_only(self):
        """Переключить в XOR-only режим (без Blowfish). Сбросить shadow XOR."""
        self.xor_only = True
        if self.xor_key:
            self.shadow_xor_s2c = L2XorCipher(self.xor_key, interlude=True)
            self.shadow_xor_c2s = L2XorCipher(self.xor_key, interlude=True)
            self.shadow_enabled = True
            _dbg(f"[CRYPTO] XOR-ONLY mode enabled, shadow XOR reset (key={self.xor_key.hex()})")

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
            # Shadow BF — отдельный экземпляр для пассивной расшифровки
            self.shadow_bf = L2BlowfishCipher()
            self.shadow_bf.set_key(self.bf_key)

        if xor_key:
            self.xor_key = bytes(xor_key)
            self.client_c2s = L2XorCipher(self.xor_key, interlude=True)
            self.server_c2s = L2XorCipher(self.xor_key, interlude=True)
            self.server_s2c = L2XorCipher(self.xor_key, interlude=True)
            self.client_s2c = L2XorCipher(self.xor_key, interlude=True)
            self.initialized = True
            # Shadow XOR — отдельные экземпляры для пассивной расшифровки
            self.shadow_xor_s2c = L2XorCipher(self.xor_key, interlude=True)
            self.shadow_xor_c2s = L2XorCipher(self.xor_key, interlude=True)
            self.shadow_enabled = True

        return info

    def shadow_decrypt_s2c(self, body: bytes) -> Optional[bytes]:
        """Пассивная расшифровка S→C (не влияет на основной поток)."""
        if self.xor_only:
            # Intermediate protocol: XOR only, no Blowfish
            if not self.shadow_xor_s2c:
                return None
            try:
                return self.shadow_xor_s2c.decrypt(body)
            except Exception:
                return None
        if not self.shadow_bf:
            return None
        try:
            dec = self.shadow_bf.decrypt(body)
            if self.shadow_xor_s2c:
                dec = self.shadow_xor_s2c.decrypt(dec)
            return dec
        except Exception:
            return None

    def shadow_decrypt_c2s(self, body: bytes) -> Optional[bytes]:
        """Пассивная расшифровка C→S (не влияет на основной поток)."""
        if self.xor_only:
            # Intermediate protocol: XOR only, no Blowfish
            if not self.shadow_xor_c2s:
                return None
            try:
                return self.shadow_xor_c2s.decrypt(body)
            except Exception:
                return None
        if not self.shadow_bf:
            return None
        try:
            dec = self.shadow_bf.decrypt(body)
            if self.shadow_xor_c2s:
                dec = self.shadow_xor_c2s.decrypt(dec)
            return dec
        except Exception:
            return None

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
        # Реестр активных сессий: session_id → {client_sock, server_sock, inject_c2s, ...}
        # MCP и inject используют self.* (последняя сессия), но реестр позволяет
        # корректно освобождать ресурсы и не терять inject-пакеты при переподключении.
        self._sessions: Dict[int, dict] = {}
        self._session_counter = 0
        self._sessions_lock = threading.Lock()

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
                    else:
                        # Passthrough для пересылки, но shadow crypto для расшифровки копий
                        self.crypto.passthrough = True
                        shadow = "SHADOW CRYPTO ON" if self.crypto.shadow_enabled else "NO SHADOW"
                        _dbg(f"[S2C] Port {self._target_port}: PASSTHROUGH + {shadow} "
                             f"(format={info.get('format')} session=0x{info.get('session_id',0):08X})")
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

                # Passthrough — пересылаем как есть, но пробуем shadow decrypt
                if self.crypto.passthrough:
                    # Auto-detect XOR-only
                    if n <= 3 and not self.crypto.xor_only and len(body) % 8 != 0 and self.crypto.shadow_enabled:
                        self.crypto.enable_xor_only()
                        _dbg(f"[S2C] AUTO-DETECT: pkt #{n} len={len(body)} not %8 → XOR-ONLY mode")
                    dec_body = body  # по умолчанию — raw
                    if self.crypto.shadow_enabled:
                        shadow_dec = self.crypto.shadow_decrypt_s2c(body)
                        if shadow_dec:
                            dec_body = shadow_dec
                            _dbg(f"[S2C SHADOW] #{n} len={len(body)} dec_op=0x{shadow_dec[0]:02X}")
                    opcode, opname = decode_opcode(dec_body, "S2C")
                    _dbg(f"[S2C PASS] #{n} len={len(body)} op=0x{opcode:04X}({opname})")
                    self.store.add("S2C", body, dec_body, opcode, opname)
                    with self._client_lock:
                        send_l2_packet(self.client_sock, body)
                    continue

                # Full MITM: расшифровать от сервера
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

                # Passthrough — пересылаем как есть
                if self.crypto.passthrough:
                    # Auto-detect XOR-only
                    if n <= 3 and not self.crypto.xor_only and len(body) % 8 != 0 and self.crypto.shadow_enabled:
                        self.crypto.enable_xor_only()
                        _dbg(f"[C2S] AUTO-DETECT: pkt #{n} len={len(body)} not %8 → XOR-ONLY mode")
                    dec_body = body
                    if self.crypto.shadow_enabled:
                        shadow_dec = self.crypto.shadow_decrypt_c2s(body)
                        if shadow_dec:
                            dec_body = shadow_dec
                            _dbg(f"[C2S SHADOW] #{n} len={len(body)} dec_op=0x{shadow_dec[0]:02X}")
                    opcode, opname = decode_opcode(dec_body, "C2S")
                    _dbg(f"[C2S PASS] #{n} len={len(body)} op=0x{opcode:04X}({opname})")
                    self.store.add("C2S", body, dec_body, opcode, opname)
                    with self._server_lock:
                        send_l2_packet(self.server_sock, body)
                    continue

                # Full MITM: расшифровать от клиента
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

        # Регистрируем сессию в реестре и сохраняем для MCP доступа
        with self._sessions_lock:
            self._session_counter += 1
            session_id = self._session_counter
            self._sessions[session_id] = {
                "target_port": target_port,
                "inject_c2s": inject_c2s,
                "inject_s2c": inject_s2c,
                "crypto": crypto,
                "client_sock": None,  # будет заполнено после connect
                "server_sock": None,
            }
        # MCP доступ — последняя активная сессия (обратная совместимость)
        self.crypto = crypto
        self._target_port = target_port
        self.inject_c2s = inject_c2s
        self.inject_s2c = inject_s2c
        self._active_session_id = session_id

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
        self.relay_server_lock = server_lock  # для API replay
        # Обновляем реестр сессий
        with self._sessions_lock:
            if session_id in self._sessions:
                self._sessions[session_id]["client_sock"] = client_sock
                self._sessions[session_id]["server_sock"] = server_sock
        # Очищаем очередь при смене сессии — не инжектировать старые пакеты в
        # новую сессию (особенно в логин-сервер 2106).
        inject_c2s.clear()
        inject_s2c.clear()

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
                        elif PLAINTEXT_INTERMEDIATE:
                            # На plaintext relay (17453) — passthrough с shadow crypto для логов
                            crypto.passthrough = True
                            shadow = "SHADOW ON" if crypto.shadow_enabled else "NO SHADOW"
                            _dbg(f"[S2C:{target_port}] PASSTHROUGH + {shadow} "
                                 f"(session=0x{info.get('session_id',0):08X})")
                        else:
                            # Полное crypto-relay (если PLAINTEXT_INTERMEDIATE=False)
                            crypto.passthrough = False
                            _dbg(f"[S2C:{target_port}] FULL CRYPTO RELAY "
                                 f"(session=0x{info.get('session_id',0):08X} "
                                 f"format={info.get('format','?')})")
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
                        if PLAINTEXT_INTERMEDIATE:
                            opcode, opname = decode_opcode(body, "S2C")
                            inner_info = ""
                            if opcode == 0x06 and len(body) >= 3:
                                inner_body = body[1:]
                                # Double-XOR deobfuscation for Ertheia+ relay
                                # Layer 1: XOR all bytes with inner_body[0]
                                xor_mask = inner_body[0]
                                deobf = bytearray(len(inner_body))
                                for bi in range(len(inner_body)):
                                    deobf[bi] = inner_body[bi] ^ xor_mask
                                # Type A (padded): deobf[1:8] all zeros → data at deobf[8:]
                                # Type B (direct): data at deobf[1:]
                                if len(deobf) >= 9 and all(b == 0 for b in deobf[1:8]):
                                    layer1_data = bytes(deobf[8:])
                                    pkt_type = "A"
                                else:
                                    layer1_data = bytes(deobf[1:])
                                    pkt_type = "B"
                                # Layer 2: XOR all with layer1_data[0] (second mask)
                                if len(layer1_data) >= 2:
                                    mask2 = layer1_data[0]
                                    layer2 = bytes(b ^ mask2 for b in layer1_data)
                                    game_body = layer2[1:]
                                    is_padding = len(set(layer1_data[:8])) <= 1
                                else:
                                    game_body = layer1_data
                                    mask2 = 0
                                    is_padding = True
                                if is_padding:
                                    pkt_type += "0"
                                real_op, real_name = decode_opcode(game_body, "S2C")
                                game_hex = game_body[:32].hex()
                                inner_info = (f" \u2192 GAME[{pkt_type}] op=0x{real_op:04X}({real_name}) "
                                              f"game_len={len(game_body)} hex={game_hex}")
                                self.store.add("S2C", inner_body, game_body, real_op,
                                               f"game:{real_name}",
                                               extra={"inner": True, "wrap_op": 0x06,
                                                      "xor_mask": xor_mask,
                                                      "mask2": mask2,
                                                      "pkt_type": pkt_type,
                                                      "is_padding": is_padding})
                            _dbg(f"[S2C:{target_port}] #{n} PLAIN len={len(body)} "
                                 f"op=0x{opcode:04X}({opname}){inner_info}")
                            # Outer relay 0x06 не дублируем в store (inner game: уже записан)
                            if opcode != 0x06:
                                self.store.add("S2C", body, body, opcode, opname)
                        else:
                            # Auto-detect XOR-only: если первые пакеты не кратны 8 → нет Blowfish
                            if n <= 3 and not crypto.xor_only and len(body) % 8 != 0 and crypto.shadow_enabled:
                                crypto.enable_xor_only()
                                _dbg(f"[S2C:{target_port}] AUTO-DETECT: pkt #{n} len={len(body)} not %%8 → XOR-ONLY mode")
                            dec_body = body
                            if crypto.shadow_enabled:
                                shadow_dec = crypto.shadow_decrypt_s2c(body)
                                if shadow_dec:
                                    dec_body = shadow_dec
                            opcode, opname = decode_opcode(dec_body, "S2C")
                            _dbg(f"[S2C:{target_port}] #{n} PASS len={len(body)} op=0x{opcode:04X}({opname})")
                            self.store.add("S2C", body, dec_body, opcode, opname)
                        with client_lock:
                            send_l2_packet(client_sock, body)
                        # ══ S2C Inject в PLAINTEXT_INTERMEDIATE ══
                        if self.inject_s2c:
                            inj_plain = self.inject_s2c.popleft()
                            if target_port in (17453,):
                                inj_wrapped = wrap_relay_0x06(inj_plain)
                                op, nm = decode_opcode(inj_plain, "S2C")
                                _dbg(f"[S2C:{target_port}] INJECT op=0x{op:04X}({nm}) "
                                     f"game_len={len(inj_plain)} relay_len={len(inj_wrapped)}")
                                self.store.add("S2C", inj_wrapped, inj_plain, op,
                                               f"INJECT:{nm}",
                                               extra={"injected": True, "relay_wrapped": True})
                                with client_lock:
                                    send_l2_packet(client_sock, inj_wrapped)
                            else:
                                op, nm = decode_opcode(inj_plain, "S2C")
                                self.store.add("S2C", inj_plain, inj_plain, op,
                                               f"INJECT:{nm}", extra={"injected": True})
                                with client_lock:
                                    send_l2_packet(client_sock, inj_plain)
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
                        if PLAINTEXT_INTERMEDIATE:
                            # Шифрование удалено — body уже plaintext
                            opcode, opname = decode_opcode(body, "C2S")
                            # Для relay-пакетов (0x06): извлечь внутренний game opcode
                            inner_info = ""
                            if opcode == 0x06 and len(body) >= 3:
                                inner_body = body[1:]
                                # Double-XOR deobfuscation for Ertheia+ relay
                                # Layer 1: XOR all bytes with inner_body[0]
                                xor_mask = inner_body[0]
                                deobf = bytearray(len(inner_body))
                                for bi in range(len(inner_body)):
                                    deobf[bi] = inner_body[bi] ^ xor_mask
                                # deobf[0] = 0x00 (always)
                                # Type A (padded): deobf[1:8] all zeros → data at deobf[8:]
                                # Type B (direct): data at deobf[1:]
                                if len(deobf) >= 9 and all(b == 0 for b in deobf[1:8]):
                                    layer1_data = bytes(deobf[8:])
                                    pkt_type = "A"
                                else:
                                    layer1_data = bytes(deobf[1:])
                                    pkt_type = "B"
                                # Layer 2: XOR all with layer1_data[0] (second mask)
                                if len(layer1_data) >= 2:
                                    mask2 = layer1_data[0]
                                    layer2 = bytes(b ^ mask2 for b in layer1_data)
                                    # layer2[0]=0x00, layer2[1]=real_opcode
                                    game_body = layer2[1:]  # skip zero prefix
                                    is_padding = len(set(layer1_data[:8])) <= 1
                                else:
                                    game_body = layer1_data
                                    mask2 = 0
                                    is_padding = True
                                if is_padding:
                                    # Zero-payload keepalive, skip detailed logging
                                    pkt_type += "0"
                                real_op, real_name = decode_opcode(game_body, "C2S")
                                game_hex = game_body[:32].hex()
                                inner_info = (f" \u2192 GAME[{pkt_type}] op=0x{real_op:04X}({real_name}) "
                                              f"game_len={len(game_body)} hex={game_hex}")
                                self.store.add("C2S", inner_body, game_body, real_op,
                                               f"game:{real_name}",
                                               extra={"inner": True, "xor_mask": xor_mask,
                                                      "mask2": mask2,
                                                      "pkt_type": pkt_type,
                                                      "is_padding": is_padding})
                                # ═══ WAREHOUSE RACE HOOK ═══
                                # При обнаружении 0x3C withdraw — burst-отправка N копий
                                # одним TCP write для минимальной задержки между пакетами
                                if (not is_padding and _RACE_HOOK["enabled"]
                                        and not _RACE_HOOK["fired"]
                                        and real_op == _RACE_HOOK["opcode"]):
                                    race_n = _RACE_HOOK["count"]
                                    _RACE_HOOK["fired"] = True
                                    ts_race = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                                    _dbg(f"[RACE HOOK] !!!! C2S 0x{real_op:02X} DETECTED! "
                                         f"BURST {race_n} copies !!!!")
                                    _RACE_HOOK["log"].append({
                                        "ts": ts_race,
                                        "opcode": real_op,
                                        "game_len": len(game_body),
                                        "copies": race_n,
                                        "game_hex": game_body.hex(),
                                    })
                                    # Build single TCP burst: N copies as relay 0x06 packets
                                    single_wrapped = wrap_relay_0x06(bytes(game_body))
                                    # L2 packet: [2B LE length] [body]
                                    pkt_len = len(single_wrapped) + 2
                                    single_l2 = struct.pack("<H", pkt_len) + single_wrapped
                                    burst = single_l2 * race_n
                                    t0_race = time.perf_counter()
                                    try:
                                        with server_lock:
                                            server_sock.sendall(burst)
                                        t1_race = time.perf_counter()
                                        _dbg(f"[RACE HOOK] BURST SENT: {race_n} copies, "
                                             f"{len(burst)} bytes, "
                                             f"{(t1_race-t0_race)*1000:.2f}ms")
                                    except Exception as e:
                                        _dbg(f"[RACE HOOK] BURST FAILED: {e}")
                                    # Also log to store for visibility
                                    for _ri in range(min(3, race_n)):
                                        self.store.add("C2S", single_wrapped,
                                                       bytes(game_body), real_op,
                                                       f"RACE:{real_name}",
                                                       extra={"race": True,
                                                              "copy": _ri + 1,
                                                              "total": race_n})
                                # ═══ MULTISELL CAPTURE HOOK ═══
                                if (not is_padding and _MULTISELL_CAP["enabled"]
                                        and real_op == 0xB0
                                        and len(game_body) >= 9):
                                    ts_ms = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                                    cap = {
                                        "ts": ts_ms,
                                        "game_hex": game_body.hex(),
                                        "game_len": len(game_body),
                                        "opcode": real_op,
                                    }
                                    caps = _MULTISELL_CAP["captured"]
                                    caps.append(cap)
                                    if len(caps) > _MULTISELL_CAP["max_captures"]:
                                        caps.pop(0)
                                    _dbg(f"[MULTISELL CAP] Captured 0xB0: "
                                         f"game_len={len(game_body)} hex={game_body[:20].hex()}")
                                # ═══ UNIVERSAL GAME BODY CAPTURE ═══
                                if (not is_padding and _GAME_CAP["enabled"]
                                        and len(game_body) >= _GAME_CAP["min_len"]):
                                    ghex = game_body.hex()
                                    ghash = hash(ghex)
                                    skip = (_GAME_CAP["unique_only"]
                                            and ghash in _GAME_CAP["_seen_hashes"])
                                    if not skip:
                                        _GAME_CAP["_seen_hashes"].add(ghash)
                                        ts_ms = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                                        gcap = {
                                            "ts": ts_ms,
                                            "game_hex": ghex,
                                            "game_len": len(game_body),
                                            "first_byte": real_op,
                                            "pkt_type": pkt_type,
                                        }
                                        gcaps = _GAME_CAP["captured"]
                                        gcaps.append(gcap)
                                        if len(gcaps) > _GAME_CAP["max_captures"]:
                                            gcaps.pop(0)
                            _dbg(f"[C2S:{target_port}] #{n} PLAIN len={len(body)} "
                                 f"op=0x{opcode:04X}({opname}){inner_info}")
                            # Outer relay 0x06 не дублируем (inner game: уже записан)
                            if opcode != 0x06:
                                self.store.add("C2S", body, body, opcode, opname)
                        else:
                            # Auto-detect XOR-only для C2S тоже
                            if n <= 3 and not crypto.xor_only and len(body) % 8 != 0 and crypto.shadow_enabled:
                                crypto.xor_only = True
                                _dbg(f"[C2S:{target_port}] AUTO-DETECT: pkt #{n} len={len(body)} not %%8 → XOR-ONLY mode")
                            dec_body = body
                            if crypto.shadow_enabled:
                                shadow_dec = crypto.shadow_decrypt_c2s(body)
                                if shadow_dec:
                                    dec_body = shadow_dec
                            opcode, opname = decode_opcode(dec_body, "C2S")
                            _dbg(f"[C2S:{target_port}] #{n} PASS len={len(body)} op=0x{opcode:04X}({opname})")
                            self.store.add("C2S", body, dec_body, opcode, opname)
                        with server_lock:
                            send_l2_packet(server_sock, body)
                        # ══ Injection в PLAINTEXT_INTERMEDIATE mode ══
                        # RATE-LIMIT: не более 1 пакета на один C2S keepalive.
                        # "while" заменён на "if" — предотвращает burst-flood и
                        # disconnect по anti-flood сервера.
                        if inject_c2s:
                            inj_plain = inject_c2s.popleft()
                            inj_wrapped = wrap_relay_0x06(inj_plain)
                            op, nm = decode_opcode(inj_plain, "C2S")
                            _dbg(f"[C2S:{target_port}] INJECT op=0x{op:04X}({nm}) "
                                 f"game_len={len(inj_plain)} relay_len={len(inj_wrapped)}")
                            self.store.add("C2S", inj_wrapped, inj_plain, op,
                                           f"INJECT:{nm}",
                                           extra={"injected": True})
                            with server_lock:
                                send_l2_packet(server_sock, inj_wrapped)
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
        # Удаляем сессию из реестра
        with self._sessions_lock:
            self._sessions.pop(session_id, None)
        _dbg(f"[PROXY] Session #{session_id} end port={target_port}: "
             f"{pkt_c2s[0]} C→S, {pkt_s2c[0]} S→C")

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

    # TCP seq/ack (4 bytes each at offset 4 and 8 of TCP header)
    tcp_seq = struct.unpack_from(">I", raw, tcp_off + 4)[0]
    tcp_ack = struct.unpack_from(">I", raw, tcp_off + 8)[0]
    tcp_flags = raw[tcp_off + 13] if len(raw) > tcp_off + 13 else 0

    return {
        "ihl": ihl, "tcp_off": tcp_off,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "tcp_seq": tcp_seq, "tcp_ack": tcp_ack, "tcp_flags": tcp_flags,
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
# WinDivert Passive Sniffer — порт 7777 (копия трафика без перехвата)
# ═══════════════════════════════════════════════════════════════════════════════

SNIFF_PORTS = {7777}  # Порты для пассивного сниффинга

class WinDivertSniffer:
    """Пассивный захват TCP-трафика через WinDivert SNIFF mode.

    НЕ перехватывает пакеты — только читает копии. Игра работает нормально.
    Извлекает TCP payload, реассемблирует L2 пакеты из потока.
    """

    def __init__(self, store: PacketStore, ports=None, proxy=None):
        self.store = store
        self.proxy = proxy  # reference to L2MitmProxy for race injection
        self.ports = ports or SNIFF_PORTS
        self.running = False
        # Lock для всех shared state (streams, xor, counters).
        # recv-loop пишет в _streams и _stream_next_seq,
        # processing thread читает/модифицирует всё остальное.
        self._lock = threading.RLock()
        # TCP stream буферы: (src_ip, src_port, dst_ip, dst_port) → bytearray
        self._streams: Dict[tuple, bytearray] = {}
        self._stream_dirs: Dict[tuple, str] = {}  # stream_key → "C2S"/"S2C"
        self._stream_pkt_count: Dict[tuple, int] = {}  # кол-во L2 пакетов в потоке
        # XOR крипто per-connection: conn_id → {"s2c": L2XorCipher, "c2s": L2XorCipher}
        self._conn_xor: Dict[frozenset, dict] = {}
        # Маппинг stream_key → conn_id
        self._stream_conn: Dict[tuple, frozenset] = {}
        # TCP seq tracking: stream_key → next expected seq number
        self._stream_next_seq: Dict[tuple, int] = {}
        self._game_server_ip: Optional[str] = None
        self._pkt_count = 0
        # Соединения с потерянной XOR-синхронизацией (TCP gap).
        # Пересинхронизация возможна при новом S2C VERSION_CHECK (0x2E).
        self._conn_sync_lost: set = set()
        # TCP reorder buffer: stream_key → {seq: payload}
        # Holds out-of-order segments waiting for the missing one
        self._ooo_buffers: Dict[tuple, dict] = {}
        # Backup XOR cipher state before gap (for recovery)
        self._conn_xor_backup: Dict[str, dict] = {}

    def _extract_tcp_payload(self, raw: bytes) -> Optional[tuple]:
        """Извлечь TCP payload из IP пакета. Возвращает (info, payload) или None."""
        info = _parse_ipv4_packet(raw)
        if not info:
            return None
        tcp_off = info["tcp_off"]
        # TCP data offset (верхние 4 бита байта 12 заголовка TCP)
        if len(raw) < tcp_off + 13:
            return None
        tcp_data_off = ((raw[tcp_off + 12] >> 4) & 0x0F) * 4
        payload_start = tcp_off + tcp_data_off
        if payload_start >= len(raw):
            return info, b""
        return info, raw[payload_start:]

    def _get_stream_key(self, info: dict) -> tuple:
        return (info["src_ip"], info["src_port"], info["dst_ip"], info["dst_port"])

    def _determine_direction(self, info: dict) -> str:
        """Определить направление: C2S или S2C."""
        # Если dst_port в sniff ports — клиент шлёт серверу
        if info["dst_port"] in self.ports:
            return "C2S"
        return "S2C"

    @staticmethod
    def _parse_opcode(body: bytes, direction: str = "S2C") -> tuple:
        """Парсит L2 опкод из plaintext body.

        Формат опкодов (Samurai Crow / modern L2 Main):
          - 1 байт: 0x01-0xFD  → opcode = body[0]
          - 0xFE + LE16 → extended opcode (S2C ExOpcode)
          - 0xD0 + LE16 → extended opcode (C2S ExOpcode)

        Использует загруженные таблицы (S2C из JSON дампа, C2S из INI/hardcoded).
        Возвращает (full_opcode: int, opname: str, header_size: int).
        """
        if not body:
            return (-1, "EMPTY", 0)
        first = body[0]
        if first == 0xFE and len(body) >= 3:
            sub = struct.unpack_from("<H", body, 1)[0]
            full = 0xFE0000 | sub
            name = S2C_EX.get(sub) or _custom_s2c_ex.get(sub) or f"0xFE:{sub:04X}"
            return (full, name, 3)
        if first == 0xD0 and len(body) >= 3:
            sub = struct.unpack_from("<H", body, 1)[0]
            full = 0xD00000 | sub
            if direction == "C2S":
                name = C2S_EX.get(sub) or _custom_c2s_ex.get(sub) or f"0xD0:{sub:04X}"
            else:
                name = S2C_EX.get(sub) or _custom_s2c_ex.get(sub) or f"0xD0:{sub:04X}"
            return (full, name, 3)
        # Main opcode
        if direction == "C2S":
            name = C2S_OPCODES.get(first) or _custom_c2s.get(first) or f"0x{first:02X}"
        else:
            name = S2C_OPCODES.get(first) or _custom_s2c.get(first) or f"0x{first:02X}"
        return (first, name, 1)

    @staticmethod
    def _try_extract_strings(body: bytes, hdr_size: int) -> list:
        """Пытается извлечь UTF-16LE строки из тела пакета (plaintext).

        Ищет null-terminated UTF-16LE последовательности >= 2 символов.
        """
        strings = []
        data = body[hdr_size:]
        i = 0
        while i < len(data) - 1:
            # Ищем начало возможной UTF-16LE строки
            j = i
            chars = []
            while j + 1 < len(data):
                cp = struct.unpack_from("<H", data, j)[0]
                if cp == 0:  # null terminator
                    j += 2
                    break
                if 0x20 <= cp < 0xD800 or 0xE000 <= cp < 0xFFFE:
                    chars.append(chr(cp))
                    j += 2
                else:
                    break
            if len(chars) >= 2:
                strings.append("".join(chars))
                i = j
            else:
                i += 1
        return strings[:5]  # Максимум 5 строк

    def _get_conn_id(self, stream_key: tuple) -> frozenset:
        """Получить conn_id для stream_key (одинаков для обоих направлений)."""
        if stream_key in self._stream_conn:
            return self._stream_conn[stream_key]
        ep1 = (stream_key[0], stream_key[1])
        ep2 = (stream_key[2], stream_key[3])
        conn_id = frozenset({ep1, ep2})
        self._stream_conn[stream_key] = conn_id
        return conn_id

    def _process_stream(self, stream_key: tuple, direction: str):
        """Извлечь L2 пакеты из TCP буфера с XOR дешифровкой.

        L2 Main (Samurai Crow) использует XOR потоковый шифр (Blowfish удалён).
        Первый S2C пакет — VERSION_CHECK (plaintext), содержит XOR base key в body[2:10].
        Все последующие пакеты (S2C и C2S) зашифрованы XOR с раздельным состоянием ключа.

        Формат: [2b LE length (включая эти 2 байта)] [1-3b opcode] [body]
        """
        buf = self._streams.get(stream_key)
        if not buf or len(buf) < 2:
            return

        conn_id = self._get_conn_id(stream_key)

        while len(buf) >= 2:
            pkt_len = struct.unpack_from("<H", buf)[0]

            # --- RESYNC: если первый пакет не парсится, ищем L2 границу ---
            pkt_count = self._stream_pkt_count.get(stream_key, 0)
            need_resync = False
            if pkt_count == 0:
                if pkt_len < 3 or pkt_len > 32000:
                    need_resync = True
                elif len(buf) < pkt_len:
                    # Первый пакет неполный — может быть AUTH_LOGIN или mid-stream
                    resync_state = getattr(self, '_resync_state', {})
                    info = resync_state.get(stream_key, {'prev': 0, 'att': 0})
                    info['att'] += 1
                    info['prev'] = len(buf)
                    resync_state[stream_key] = info
                    self._resync_state = resync_state
                    if info['att'] >= 5:
                        need_resync = True
                    else:
                        _dbg(f"[SNIFF:7777] {direction} waiting for first pkt "
                             f"(need {pkt_len}, have {len(buf)}, attempt #{info['att']})")
                        break

            if need_resync and pkt_count == 0:
                synced = False
                crypto = self._conn_xor.get(conn_id)

                # --- Одноразовый hex-дамп буфера для диагностики ---
                dump_flag = f'_resync_dumped_{stream_key}'
                if not getattr(self, dump_flag, False) and len(buf) >= 300:
                    setattr(self, dump_flag, True)
                    _dbg(f"[SNIFF:7777] {direction} BUFFER DUMP ({len(buf)}B):")
                    _dbg(f"  offset 0: {bytes(buf[:32]).hex()}")
                    for off in [100, 200, 275, 300]:
                        if off + 32 <= len(buf):
                            _dbg(f"  offset {off}: {bytes(buf[off:off+32]).hex()}")
                    # Пробуем XOR-дешифровку с позиции 275 (типичный AUTH_LOGIN)
                    if crypto and direction == "C2S" and len(buf) > 280:
                        test_cipher = crypto["c2s"].clone()
                        test_data = bytes(buf[275:283])
                        test_dec = test_cipher.decrypt(test_data)
                        test_len = struct.unpack_from("<H", test_dec)[0]
                        _dbg(f"  XOR trial @275: enc={test_data.hex()} "
                             f"dec={test_dec.hex()} try_len={test_len}")

                # --- Метод 1: plaintext-длины (стандарт L2) ---
                chain_len = 4 if direction == "C2S" else 3
                max_pkt = 2000 if direction == "C2S" else 32000
                if len(buf) >= 12:
                    for scan_start in range(len(buf) - 6):
                        pos = scan_start
                        ok = True
                        chain_lens = []
                        for _ in range(chain_len):
                            if pos + 2 > len(buf):
                                ok = False
                                break
                            try_len = struct.unpack_from("<H", buf, pos)[0]
                            if try_len < 3 or try_len > max_pkt:
                                ok = False
                                break
                            chain_lens.append(try_len)
                            pos += try_len
                        if not ok:
                            continue
                        p = scan_start
                        full_count = 0
                        for cl in chain_lens[:-1]:
                            if p + cl > len(buf):
                                break
                            p += cl
                            full_count += 1
                        if full_count < chain_len - 1:
                            continue
                        _dbg(f"[SNIFF:7777] {direction} RESYNC plaintext at {scan_start}: "
                             f"chain={chain_lens}")
                        del buf[:scan_start]
                        self._stream_pkt_count[stream_key] = 1
                        resync_state = getattr(self, '_resync_state', {})
                        resync_state.pop(stream_key, None)
                        self._resync_state = resync_state
                        synced = True
                        break

                # --- Метод 2: XOR-зашифрованные длины (C2S stream encryption) ---
                if not synced and crypto and direction == "C2S" and len(buf) >= 50:
                    # Гипотеза: вся C2S stream (включая 2B length) зашифрована XOR.
                    # AUTH_LOGIN (первый пакет) = RSA, не XOR. Его размер из header.
                    # Пробуем разные стартовые позиции (AUTH_LOGIN мог быть разного размера).
                    # Типичные AUTH_LOGIN: 275B (1 RSA block) или pkt_len из header.
                    auth_len_candidates = set()
                    # Из header (если он plaintext)
                    hdr_len = struct.unpack_from("<H", buf)[0]
                    if 100 <= hdr_len <= 10000:
                        auth_len_candidates.add(hdr_len)
                    # Типичные размеры AUTH_LOGIN для разных версий клиента:
                    # Ertheia RSA: 275-287, Homunculus+: 512-520, иногда до 1024
                    for sz in [275, 277, 279, 281, 283, 285, 287,
                               289, 291, 293, 295, 297, 299,
                               512, 514, 516, 518, 520,
                               256, 258, 260, 262, 264,
                               1024, 1026]:
                        auth_len_candidates.add(sz)
                    # Динамический скан: ищем plaintext L2 length header в
                    # буфере с шагом 2 (L2 пакеты выровнены по 2)
                    for probe in range(200, min(len(buf) - 10, 2048), 2):
                        probe_len = struct.unpack_from("<H", buf, probe)[0]
                        if 3 <= probe_len <= 2000:
                            auth_len_candidates.add(probe)

                    for auth_sz in sorted(auth_len_candidates):
                        if auth_sz + 10 > len(buf):
                            continue
                        # XOR cipher начинается с позиции 0 после AUTH_LOGIN
                        test_cipher = crypto["c2s"].clone()
                        # Дешифруем поток начиная с auth_sz
                        test_data = bytes(buf[auth_sz:min(auth_sz + 200, len(buf))])
                        test_dec = bytearray(test_cipher.decrypt(test_data))
                        # Проверяем цепочку L2 пакетов в дешифрованном потоке
                        pos = 0
                        chain_lens = []
                        while pos + 2 <= len(test_dec) and len(chain_lens) < 4:
                            try_len = struct.unpack_from("<H", test_dec, pos)[0]
                            if try_len < 3 or try_len > 2000:
                                break
                            chain_lens.append(try_len)
                            pos += try_len
                        if len(chain_lens) >= 3:
                            _dbg(f"[SNIFF:7777] C2S XOR-RESYNC: AUTH_LOGIN={auth_sz}B, "
                                 f"game_pkt_chain={chain_lens}")
                            # Переключаем на режим "XOR covers length"
                            del buf[:auth_sz]
                            self._stream_pkt_count[stream_key] = 1
                            # Помечаем что C2S длины зашифрованы
                            self._c2s_xor_lengths = True
                            resync_state = getattr(self, '_resync_state', {})
                            resync_state.pop(stream_key, None)
                            self._resync_state = resync_state
                            synced = True
                            break

                if synced:
                    continue

                if len(buf) > 50000:
                    _dbg(f"[SNIFF:7777] {direction} RESYNC failed with {len(buf)}B, "
                         f"flushing to prevent memory growth")
                    buf.clear()
                    break

                _dbg(f"[SNIFF:7777] {direction} RESYNC: no valid chain in {len(buf)}B, "
                     f"waiting for more data...")
                break

            # --- Обычная обработка ---
            # Режим "C2S XOR covers length": длины зашифрованы, дешифруем весь поток
            c2s_xor_len = getattr(self, '_c2s_xor_lengths', False)
            crypto = self._conn_xor.get(conn_id)

            if c2s_xor_len and direction == "C2S" and crypto and pkt_count > 0:
                # Дешифруем первые 2 байта для получения реальной длины
                cipher = crypto["c2s"]
                enc_hdr = bytes(buf[:2])
                # Клонируем cipher чтобы узнать длину без порчи состояния
                cipher_peek = cipher.clone()
                dec_hdr = cipher_peek.decrypt(enc_hdr)
                pkt_len = struct.unpack_from("<H", dec_hdr)[0]
                if pkt_len < 3 or pkt_len > 32000:
                    _dbg(f"[SNIFF:7777] C2S XOR bad pkt_len={pkt_len} "
                         f"(enc={enc_hdr.hex()} dec={dec_hdr.hex()}), "
                         f"flushing {len(buf)} bytes")
                    buf.clear()
                    break
                if len(buf) < pkt_len:
                    break  # Ждём остаток пакета

                # Дешифруем весь пакет (length + body) одним вызовом
                enc_pkt = bytes(buf[:pkt_len])
                del buf[:pkt_len]
                dec_pkt = cipher.decrypt(enc_pkt)
                # dec_pkt[0:2] = length (уже знаем), dec_pkt[2:] = body
                raw_body = enc_pkt[2:]  # encrypted body (for raw logging)
                body = bytes(dec_pkt[2:])  # decrypted body

                if stream_key not in self._stream_pkt_count:
                    self._stream_pkt_count[stream_key] = 0
                self._stream_pkt_count[stream_key] += 1
                pkt_num = self._stream_pkt_count[stream_key]
            else:
                # Стандартный режим: plaintext length + encrypted body
                if pkt_len < 3 or pkt_len > 65535:
                    _dbg(f"[SNIFF:7777] Bad pkt_len={pkt_len}, flushing {len(buf)}B ({direction}) "
                         f"first_bytes={bytes(buf[:16]).hex()}")
                    buf.clear()
                    break
                if len(buf) < pkt_len:
                    break  # Ждём остаток пакета

                raw_body = bytes(buf[2:pkt_len])
                del buf[:pkt_len]

                if stream_key not in self._stream_pkt_count:
                    self._stream_pkt_count[stream_key] = 0
                self._stream_pkt_count[stream_key] += 1
                pkt_num = self._stream_pkt_count[stream_key]

                # --- Пересинхронизация после TCP gap ---
                # VERSION_CHECK (0x2E) идёт plaintext, 26 байт, формат:
                #   2E 01 <8B key> <16B tail>
                # Если мы видим такой пакет на S2C — пересинхронизируемся.
                is_version_check = (direction == "S2C"
                                    and len(raw_body) == 25  # 26 - 1 (opcode в body[0])... нет, raw_body = buf[2:pkt_len], pkt_len=26 → raw_body=24B...
                                    # VERSION_CHECK: pkt_len=26 (включая 2B length), raw_body=24B
                                    # Но body[0]=0x2E, body[1]=0x01, body[2:10]=key
                                    # Проверяем: opcode 0x2E и result=0x01
                                    )
                # Более надёжная проверка: plaintext body начинается с 0x2E 0x01
                is_version_check = (direction == "S2C"
                                    and len(raw_body) >= 10
                                    and raw_body[0] == 0x2E
                                    and raw_body[1] == 0x01)

                if is_version_check:
                    # VERSION_CHECK всегда plaintext — извлекаем новый XOR key
                    body = raw_body
                    xor_key = raw_body[2:10]
                    cipher_s2c = L2XorCipher(xor_key, interlude=True)
                    cipher_c2s = L2XorCipher(xor_key, interlude=True)
                    self._conn_xor[conn_id] = {"s2c": cipher_s2c, "c2s": cipher_c2s}
                    # Сбрасываем sync_lost и c2s_xor_lengths для этого соединения
                    self._conn_sync_lost.discard(conn_id)
                    self._c2s_xor_lengths = False
                    # Сбрасываем счётчик пакетов для обоих направлений
                    self._stream_pkt_count[stream_key] = 1
                    if pkt_num != 1:
                        _dbg(f"[SNIFF:7777] XOR RESYNC via VERSION_CHECK: "
                             f"key={xor_key.hex()} (was pkt #{pkt_num})")
                    else:
                        _dbg(f"[SNIFF:7777] XOR KEY EXTRACTED: {xor_key.hex()} "
                             f"(full S2C key: {bytes(cipher_s2c.key).hex()})")
                elif direction == "S2C" and pkt_num == 1:
                    body = raw_body
                    if len(raw_body) >= 10:
                        xor_key = raw_body[2:10]
                        cipher_s2c = L2XorCipher(xor_key, interlude=True)
                        cipher_c2s = L2XorCipher(xor_key, interlude=True)
                        self._conn_xor[conn_id] = {"s2c": cipher_s2c, "c2s": cipher_c2s}
                        _dbg(f"[SNIFF:7777] XOR KEY EXTRACTED: {xor_key.hex()} "
                             f"(full S2C key: {bytes(cipher_s2c.key).hex()})")
                    else:
                        _dbg(f"[SNIFF:7777] WARNING: First S2C pkt too short for XOR key: "
                             f"{len(raw_body)} bytes")
                elif direction == "C2S" and pkt_num == 1:
                    body = raw_body
                    _dbg(f"[SNIFF:7777] C2S #1 AUTH_LOGIN (RSA, no XOR) len={len(raw_body)}")
                elif crypto:
                    dir_key = "s2c" if direction == "S2C" else "c2s"
                    cipher = crypto[dir_key]
                    body = cipher.decrypt(raw_body)
                elif conn_id in self._conn_sync_lost:
                    # XOR sync потерян после TCP gap, дешифровка невозможна
                    body = raw_body
                else:
                    body = raw_body

            # Парсим опкод из расшифрованного тела
            is_sync_lost = (conn_id in self._conn_sync_lost and not crypto)
            opcode, opname, hdr_size = self._parse_opcode(body, direction)
            is_encrypted = crypto is not None and not (direction == "S2C" and pkt_num == 1)
            if is_sync_lost:
                opname = f"SYNC_LOST:{opname}"
            extra = {"xor_decrypted": is_encrypted, "hdr_size": hdr_size,
                     "body_len": len(body), "sync_lost": is_sync_lost}

            # ═══ WAREHOUSE RACE HOOK (SNIFFER) ═══
            # При обнаружении C2S 0x3C на 7777 — инжектим через relay
            if (direction == "C2S" and _RACE_HOOK["enabled"]
                    and not _RACE_HOOK["fired"]
                    and opcode == _RACE_HOOK["opcode"]
                    and self.proxy and hasattr(self.proxy, 'inject_c2s')):
                race_n = _RACE_HOOK["count"]
                _RACE_HOOK["fired"] = True
                ts_race = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                _dbg(f"[RACE HOOK SNIFF] !!!! C2S 0x{opcode:02X} on 7777! "
                     f"Injecting {race_n} via relay !!!!")
                _RACE_HOOK["log"].append({
                    "ts": ts_race, "source": "sniff_7777",
                    "opcode": opcode, "body_len": len(body),
                    "copies": race_n, "body_hex": body.hex()[:128],
                })
                # Инжектим тело пакета (XOR-расшифрованное) через relay
                for _ri in range(race_n):
                    self.proxy.inject_c2s.append(bytes(body))
                _dbg(f"[RACE HOOK SNIFF] Queued {race_n} copies into inject_c2s")

            # Пытаемся извлечь UTF-16LE строки из тела
            strings = self._try_extract_strings(body, hdr_size)
            if strings:
                extra["strings"] = strings

            # Первые 50 пакетов каждого потока логируем подробно
            if pkt_num <= 50:
                hex_preview = body[:32].hex() if body else ""
                raw_hex = raw_body[:16].hex() if raw_body else ""
                _dbg(f"[SNIFF:7777] {direction} #{pkt_num} op={opname} "
                     f"pkt_size={pkt_len} body_len={len(body)} "
                     f"{'[XOR]' if is_encrypted else '[PLAIN]'} "
                     f"hex={hex_preview} raw={raw_hex}"
                     + (f" str={strings}" if strings else ""))
            else:
                _dbg(f"[SNIFF:7777] {direction} #{pkt_num} op={opname} len={len(body)}")

            # ═══ MULTISELL CAPTURE HOOK (sniff:7777) ═══
            if (direction == "C2S" and _MULTISELL_CAP["enabled"]
                    and opcode == 0xB0
                    and len(body) >= 9):
                from datetime import datetime as _dt
                ts_ms = _dt.now().strftime("%H:%M:%S.%f")[:-3]
                cap = {
                    "ts": ts_ms,
                    "game_hex": body.hex(),
                    "game_len": len(body),
                    "opcode": opcode,
                    "source": "sniff7777",
                }
                caps = _MULTISELL_CAP["captured"]
                caps.append(cap)
                if len(caps) > _MULTISELL_CAP["max_captures"]:
                    caps.pop(0)
                _dbg(f"[MULTISELL CAP SNIFF] Captured 0xB0: "
                     f"body_len={len(body)} hex={body[:20].hex()}")

            self.store.add(direction, raw_body, body, opcode, f"sniff:{opname}", extra=extra)

    def _handle_raw_packet(self, raw: bytes):
        """Обработка одного сырого IP-пакета (вызывается из processing thread)."""
        with self._lock:
            self._handle_raw_packet_inner(raw)

    def _handle_raw_packet_inner(self, raw: bytes):
        result = self._extract_tcp_payload(raw)
        if not result:
            return
        info, payload = result

        tcp_flags = info["tcp_flags"]
        tcp_seq = info["tcp_seq"]
        is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
        is_syn_ack = bool(tcp_flags & 0x02) and bool(tcp_flags & 0x10)
        is_fin_rst = bool(tcp_flags & 0x05)

        if not payload:
            # SYN/ACK/FIN без данных
            if is_syn and not is_syn_ack:
                direction = self._determine_direction(info)
                _dbg(f"[SNIFF:7777] SYN {direction} "
                     f"{info['src_ip']}:{info['src_port']}→{info['dst_ip']}:{info['dst_port']}")
            if is_syn or is_syn_ack:
                key = self._get_stream_key(info)
                self._stream_next_seq[key] = (tcp_seq + 1) & 0xFFFFFFFF
            if is_fin_rst:
                key = self._get_stream_key(info)
                rev_key = (info["dst_ip"], info["dst_port"], info["src_ip"], info["src_port"])
                conn_id = self._stream_conn.get(key) or self._stream_conn.get(rev_key)
                if conn_id:
                    self._conn_xor.pop(conn_id, None)
                    self._conn_sync_lost.discard(conn_id)
                for k in (key, rev_key):
                    self._streams.pop(k, None)
                    self._stream_pkt_count.pop(k, None)
                    self._stream_conn.pop(k, None)
                    self._stream_next_seq.pop(k, None)
            return

        # --- TCP seq tracking: отфильтровать ретрансмиссии ---
        direction = self._determine_direction(info)
        stream_key = self._get_stream_key(info)
        payload_len = len(payload)

        # Debug: логируем каждый TCP сегмент с данными
        if payload_len > 0 and self._pkt_count < 200:
            _dbg(f"[SNIFF:TCP] {direction} {info['src_ip']}:{info['src_port']}→"
                 f"{info['dst_ip']}:{info['dst_port']} seq={tcp_seq} len={payload_len}")

        expected_seq = self._stream_next_seq.get(stream_key)
        if expected_seq is not None:
            diff = (tcp_seq - expected_seq) & 0xFFFFFFFF
            if diff > 0x80000000:
                seg_end = (tcp_seq + payload_len) & 0xFFFFFFFF
                new_diff = (seg_end - expected_seq) & 0xFFFFFFFF
                if new_diff > 0x80000000 or new_diff == 0:
                    _dbg(f"[SNIFF:TCP] RETRANSMIT {direction} seq={tcp_seq} "
                         f"len={payload_len} expected={expected_seq}")
                    return
                skip = (expected_seq - tcp_seq) & 0xFFFFFFFF
                payload = payload[skip:]
                payload_len = len(payload)
            elif diff > 0 and diff < 0x80000000:
                # ═══ TCP REORDER BUFFER ═══
                # WinDivert может доставлять сегменты не по порядку.
                # Вместо немедленного объявления gap — буферизуем out-of-order
                # сегмент и ждём пропущенный (он может прийти как retransmit).
                ooo = self._ooo_buffers.setdefault(stream_key, {})
                ooo[tcp_seq] = payload
                _dbg(f"[SNIFF:TCP] OOO {direction} expected={expected_seq} "
                     f"got={tcp_seq} gap={diff}B buffered={len(ooo)} segments")
                # Если буфер слишком большой или gap слишком широкий — объявляем потерю
                if len(ooo) > 50 or diff > 65536:
                    _dbg(f"[SNIFF:7777] TCP GAP CONFIRMED {direction} "
                         f"gap={diff}B — too large for reorder")
                    self._ooo_buffers.pop(stream_key, None)
                    self._streams.pop(stream_key, None)
                    self._stream_pkt_count.pop(stream_key, None)
                    conn_id = self._stream_conn.get(stream_key)
                    if conn_id:
                        # Сохраняем backup cipher для возможной recovery
                        xor_state = self._conn_xor.get(conn_id)
                        if xor_state:
                            self._conn_xor_backup[conn_id] = {
                                "s2c": xor_state.get("s2c").clone() if xor_state.get("s2c") else None,
                                "c2s": xor_state.get("c2s").clone() if xor_state.get("c2s") else None,
                                "gap_bytes": diff,
                            }
                        if conn_id not in self._conn_sync_lost:
                            self._conn_sync_lost.add(conn_id)
                            _dbg(f"[SNIFF:7777] XOR SYNC LOST due to TCP gap — "
                                 f"cipher backup saved for recovery")
                        self._conn_xor.pop(conn_id, None)
                    self._stream_next_seq[stream_key] = (tcp_seq + payload_len) & 0xFFFFFFFF
                return

        # Обновляем next expected seq
        self._stream_next_seq[stream_key] = (tcp_seq + payload_len) & 0xFFFFFFFF

        self._pkt_count += 1

        # ═══ DRAIN OOO BUFFER ═══
        # Если есть буферизованные out-of-order сегменты — проверим,
        # не закрыл ли текущий сегмент gap.
        ooo = self._ooo_buffers.get(stream_key)
        if ooo:
            drained = True
            while drained:
                drained = False
                next_exp = self._stream_next_seq.get(stream_key, 0)
                for ooo_seq in sorted(ooo.keys()):
                    ooo_diff = (ooo_seq - next_exp) & 0xFFFFFFFF
                    if ooo_diff == 0:
                        # Exact match — этот сегмент теперь по порядку!
                        ooo_payload = ooo.pop(ooo_seq)
                        _dbg(f"[SNIFF:TCP] OOO DRAIN {direction} seq={ooo_seq} "
                             f"len={len(ooo_payload)} — gap filled!")
                        self._stream_next_seq[stream_key] = \
                            (ooo_seq + len(ooo_payload)) & 0xFFFFFFFF
                        if stream_key not in self._streams:
                            self._streams[stream_key] = bytearray()
                        self._streams[stream_key].extend(ooo_payload)
                        self._process_stream(stream_key, direction)
                        drained = True
                        break
                    elif ooo_diff > 0x80000000:
                        # Этот сегмент уже обработан (retransmit)
                        ooo.pop(ooo_seq)
                        drained = True
                        break
            if not ooo:
                self._ooo_buffers.pop(stream_key, None)

        if stream_key not in self._streams:
            self._streams[stream_key] = bytearray()
            self._stream_dirs[stream_key] = direction

        self._streams[stream_key].extend(payload)
        self._process_stream(stream_key, direction)

    def run(self):
        wd = WinDivert2()
        try:
            wd._load_dll()
        except Exception as e:
            print(f"[SNIFF] DLL error: {e}", file=sys.stderr)
            return

        port_cond = " or ".join(
            f"tcp.DstPort == {p} or tcp.SrcPort == {p}" for p in sorted(self.ports))
        filt = f"ip and tcp and ({port_cond})"

        try:
            # INTERCEPT mode: перехватываем пакеты, мгновенно переинъецируем
            # Гарантирует захват 100% TCP сегментов (SNIFF mode терял C2S)
            wd.open(filt, priority=50, flags=0)
        except OSError as e:
            print(f"[SNIFF] FAILED: {e}", file=sys.stderr)
            return

        self.running = True
        print(f"[SNIFF] INTERCEPT+reinject on ports {sorted(self.ports)} "
              f"(guaranteed capture, ~0ms added latency)", file=sys.stderr)

        # Очередь для асинхронной обработки (recv loop не блокируется)
        pkt_q = _queue_mod.Queue(maxsize=100000)
        _dropped = [0]

        def _processing_thread():
            """Обработка пакетов из очереди (отдельный поток)."""
            while self.running or not pkt_q.empty():
                try:
                    raw = pkt_q.get(timeout=0.5)
                except _queue_mod.Empty:
                    continue
                try:
                    self._handle_raw_packet(raw)
                except Exception as e:
                    _dbg(f"[SNIFF] process error: {e}")

        proc_thread = threading.Thread(target=_processing_thread, daemon=True,
                                       name="sniff-process")
        proc_thread.start()

        try:
            while self.running:
                try:
                    raw, addr = wd.recv()
                except OSError as e:
                    if self.running:
                        print(f"[SNIFF] recv: {e}", file=sys.stderr)
                    continue

                # Мгновенная переинъекция — игра НЕ ждёт обработки
                try:
                    wd.send(raw, addr)
                except OSError:
                    pass

                # Данные в очередь на обработку
                try:
                    pkt_q.put_nowait(raw)
                except _queue_mod.Full:
                    _dropped[0] += 1
                    if _dropped[0] == 1:
                        # Первый дроп — пакеты потеряны, XOR state сниффера
                        # рассинхронизируется. Помечаем все соединения как sync_lost.
                        _dbg(f"[SNIFF] QUEUE OVERFLOW — XOR sync will be lost!")
                        with self._lock:
                            for cid in list(self._conn_xor.keys()):
                                self._conn_sync_lost.add(cid)
                                self._conn_xor.pop(cid, None)
                            self._streams.clear()
                            self._stream_pkt_count.clear()
                            self._c2s_xor_lengths = False
                    if _dropped[0] % 1000 == 0:
                        print(f"[SNIFF] Queue overflow, dropped {_dropped[0]} pkts total",
                              file=sys.stderr)

        except Exception as e:
            if self.running:
                print(f"[SNIFF] Error: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
        finally:
            self.running = False
            proc_thread.join(timeout=5)
            wd.close()
            dropped_msg = f", queue_dropped={_dropped[0]}" if _dropped[0] else ""
            print(f"[SNIFF] Closed (raw_pkts={self._pkt_count}{dropped_msg})",
                  file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
# Scapy Sniffer — пассивный захват порта 7777 через npcap
# 100% захват C2S и S2C, включая через VPN
# ═══════════════════════════════════════════════════════════════════════════════

class RawSocketSniffer:
    """Пассивный захват TCP трафика через scapy + npcap.

    Использует npcap для полного захвата пакетов (C2S + S2C).
    Не модифицирует трафик, не требует WinDivert.
    """

    def __init__(self, store: PacketStore, ports=None):
        self.store = store
        self.ports = ports or SNIFF_PORTS
        self.running = False
        self._streams: Dict[tuple, bytearray] = {}
        self._stream_dirs: Dict[tuple, str] = {}
        self._stream_pkt_count: Dict[tuple, int] = {}
        self._conn_xor: Dict[frozenset, dict] = {}
        self._stream_conn: Dict[tuple, frozenset] = {}
        self._stream_next_seq: Dict[tuple, int] = {}
        self._pkt_count = 0
        self._local_ips: set = set()
        self._game_server_ips: set = set()

    def _get_local_ips(self) -> set:
        ips = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ips.add(info[4][0])
        except Exception:
            pass
        ips.add(_get_local_ip())
        ips.add("127.0.0.1")
        return ips

    def _determine_direction(self, src_ip, src_port, dst_ip, dst_port) -> str:
        # Если src_port = game port И src_ip = game server → S2C
        if src_port in self.ports and src_ip in self._game_server_ips:
            return "S2C"
        # Если dst_port = game port → C2S
        if dst_port in self.ports:
            return "C2S"
        # Если src_port = game port → S2C
        if src_port in self.ports:
            return "S2C"
        return "S2C"

    def _get_conn_id(self, stream_key: tuple) -> frozenset:
        if stream_key in self._stream_conn:
            return self._stream_conn[stream_key]
        ep1 = (stream_key[0], stream_key[1])
        ep2 = (stream_key[2], stream_key[3])
        conn_id = frozenset({ep1, ep2})
        self._stream_conn[stream_key] = conn_id
        return conn_id

    def _process_stream(self, stream_key: tuple, direction: str):
        """Извлечь L2 пакеты из TCP буфера — XOR дешифровка."""
        buf = self._streams.get(stream_key)
        if not buf or len(buf) < 2:
            return

        conn_id = self._get_conn_id(stream_key)
        pkt_count = self._stream_pkt_count.get(stream_key, 0)

        while len(buf) >= 2:
            pkt_len = struct.unpack_from("<H", buf)[0]

            if pkt_len < 3 or pkt_len > 65000:
                if pkt_count == 0:
                    del buf[:1]
                    continue
                else:
                    _dbg(f"[SNIFF:7777] {direction} DESYNC pkt_len={pkt_len} "
                         f"after {pkt_count} pkts, resetting stream")
                    buf.clear()
                    break

            if len(buf) < pkt_len:
                break

            body = bytes(buf[2:pkt_len])
            del buf[:pkt_len]

            pkt_count += 1
            self._stream_pkt_count[stream_key] = pkt_count

            if not body:
                continue

            crypto = self._conn_xor.get(conn_id)

            if pkt_count == 1 and direction == "S2C":
                # Первый S2C = KeyInit (plaintext)
                info = parse_key_init(body)
                if info and info.get("xor_key"):
                    xor_key = info["xor_key"]
                    self._conn_xor[conn_id] = {
                        "s2c": L2XorCipher(xor_key, interlude=True),
                        "c2s": L2XorCipher(xor_key, interlude=True),
                        "xor_key": xor_key,
                    }
                    print(f"[SNIFF:7777] KeyInit OK! xor_key={xor_key.hex()} "
                          f"session=0x{info.get('session_id',0):08X}",
                          file=sys.stderr)
                opcode, opname = WinDivertSniffer._parse_opcode(body, "S2C")
                self.store.add("S2C", body, body, opcode, opname,
                               extra={"port": 7777, "sniffer": True,
                                      "key_init": True})
                continue

            if pkt_count == 1 and direction == "C2S":
                # Первый C2S = AUTH_LOGIN (RSA, не XOR)
                # НЕ пропускаем через XOR cipher — он не применяется к AUTH_LOGIN
                self.store.add("C2S", body, body, body[0] if body else 0,
                               "AuthLogin",
                               extra={"port": 7777, "sniffer": True,
                                      "auth_login": True, "len": len(body)})
                continue

            # XOR дешифровка
            dec_body = body
            if crypto:
                cipher_key = "s2c" if direction == "S2C" else "c2s"
                cipher = crypto.get(cipher_key)
                if cipher:
                    try:
                        dec_body = cipher.decrypt(body)
                    except Exception as e:
                        _dbg(f"[SNIFF:7777] XOR err: {e}")

            opcode, opname = WinDivertSniffer._parse_opcode(dec_body, direction)
            hdr_size = 3 if opcode > 0xFF else 1
            strings = WinDivertSniffer._try_extract_strings(dec_body, hdr_size)

            self.store.add(direction, body, dec_body, opcode, opname,
                           extra={"port": 7777, "sniffer": True,
                                  "strings": strings if strings else None})

            if pkt_count <= 10 or pkt_count % 50 == 0:
                _dbg(f"[SNIFF:7777] {direction} #{pkt_count} "
                     f"op=0x{opcode:04X}({opname}) len={len(body)}"
                     f"{' str=' + repr(strings[:2]) if strings else ''}")

    def _handle_packet(self, pkt):
        """Callback от scapy sniff — обработка одного пакета."""
        try:
            from scapy.layers.inet import IP, TCP
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            tcp = pkt[TCP]
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = tcp.sport
            dst_port = tcp.dport

            # Payload
            payload = bytes(tcp.payload)
            if not payload:
                return

            # Отслеживаем game server IP (кто слушает на 7777)
            if src_port in self.ports:
                self._game_server_ips.add(src_ip)

            self._pkt_count += 1

            direction = self._determine_direction(src_ip, src_port, dst_ip, dst_port)
            stream_key = (src_ip, src_port, dst_ip, dst_port)

            # TCP seq tracking
            tcp_seq = tcp.seq
            expected = self._stream_next_seq.get(stream_key)
            if expected is not None:
                diff = (tcp_seq - expected) & 0xFFFFFFFF
                if diff > 0 and diff < 0x80000000:
                    # Gap — сбросить stream и crypto
                    _dbg(f"[SNIFF:7777] TCP GAP {direction} expected={expected} "
                         f"got={tcp_seq} gap={diff}")
                    self._streams.pop(stream_key, None)
                    self._stream_pkt_count.pop(stream_key, None)
                    conn_id = self._stream_conn.get(stream_key)
                    if conn_id:
                        self._conn_xor.pop(conn_id, None)
                elif diff > 0x80000000:
                    # Retransmission — skip
                    return

            self._stream_next_seq[stream_key] = (tcp_seq + len(payload)) & 0xFFFFFFFF

            if stream_key not in self._streams:
                self._streams[stream_key] = bytearray()
                self._stream_dirs[stream_key] = direction

            self._streams[stream_key].extend(payload)
            self._process_stream(stream_key, direction)

            if self._pkt_count <= 5:
                print(f"[SNIFF:7777] pkt #{self._pkt_count} {direction} "
                      f"{src_ip}:{src_port}→{dst_ip}:{dst_port} "
                      f"payload={len(payload)}B", file=sys.stderr)

        except Exception as e:
            _dbg(f"[SNIFF:7777] handle error: {e}")

    def run(self):
        self._local_ips = self._get_local_ips()
        print(f"[SNIFF:7777] Starting scapy/npcap sniffer for ports "
              f"{sorted(self.ports)}", file=sys.stderr)
        print(f"[SNIFF:7777] Local IPs: {self._local_ips}", file=sys.stderr)

        try:
            from scapy.all import sniff as scapy_sniff, conf as scapy_conf
        except ImportError:
            print("[SNIFF:7777] scapy not installed! pip install scapy",
                  file=sys.stderr)
            return

        # BPF фильтр для npcap — только TCP на наших портах
        port_filter = " or ".join(f"port {p}" for p in sorted(self.ports))
        bpf = f"tcp and ({port_filter})"

        # Найти правильный интерфейс — VPN адаптер с game traffic
        sniff_iface = None
        local_ip = _get_local_ip()
        for iface in scapy_conf.ifaces.values():
            try:
                if getattr(iface, 'ip', '') == local_ip:
                    sniff_iface = iface.name
                    break
            except Exception:
                continue

        if not sniff_iface:
            # Fallback: ищем AmneziaVPN или WireGuard по имени
            for iface in scapy_conf.ifaces.values():
                try:
                    name = getattr(iface, 'name', '') + getattr(iface, 'description', '')
                    if any(k in name.lower() for k in ('amnezia', 'wireguard', 'vpn')):
                        sniff_iface = iface.name
                        break
                except Exception:
                    continue

        self.running = True
        print(f"[SNIFF:7777] Scapy sniff on iface={sniff_iface or 'DEFAULT'} "
              f"(local_ip={local_ip}) BPF: {bpf}", file=sys.stderr)

        try:
            # store=False чтобы не жрать RAM, prn=callback
            scapy_sniff(
                iface=sniff_iface,
                filter=bpf,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Exception as e:
            if self.running:
                print(f"[SNIFF:7777] Error: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
        finally:
            self.running = False
            print(f"[SNIFF:7777] Closed (pkts={self._pkt_count})",
                  file=sys.stderr)


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


def build_multisell_choose(list_id: int, entry_id: int, amount: int = 1,
                           enchant: int = 0, n_ensoul_slots: int = 3) -> bytes:
    """RequestMultiSellChoose (0xB0).

    Подтверждено IDA MCP анализом NWindow.dll (execRequestMultiSellChoose,
    backend slot 0x640). Все поля LE32.

    Структура (минимум 41 байт при n_ensoul_slots=3):
        byte[0]    = opcode 0xB0
        byte[1:5]  = MultiSellGroupID  (LE32)
        byte[5:9]  = MultiSellInfoID   (LE32)
        byte[9:13] = ItemCount         (LE32)
        byte[13:17]= Enchant           (LE32)
        byte[17:21]= AttrDefenseValueHoly (LE32)
        byte[21:25]= IsBlessedItem     (LE32)
        byte[25:29]= n_ensoul_slots    (LE32) — внешний loop
        byte[29:29+n*4] = EnsoulOptionNum_i (LE32) × n — 0 опций в каждом слоте
    """
    buf = struct.pack('<B', 0xB0)
    buf += struct.pack('<I', list_id)        # MultiSellGroupID
    buf += struct.pack('<I', entry_id)       # MultiSellInfoID
    buf += struct.pack('<I', amount)         # ItemCount
    buf += struct.pack('<I', enchant)        # Enchant
    buf += struct.pack('<I', 0)              # AttrDefenseValueHoly
    buf += struct.pack('<I', 0)              # IsBlessedItem
    buf += struct.pack('<I', n_ensoul_slots) # кол-во ensoul-слотов
    for _ in range(n_ensoul_slots):
        buf += struct.pack('<I', 0)          # EnsoulOptionNum_i = 0
    return buf  # 41 байт при n_ensoul_slots=3


def multisell_replay_modify(captured_hex: str,
                            new_entry_id: int | None = None,
                            old_entry_id: int | None = None,
                            new_amount: int | None = None,
                            old_amount: int | None = None) -> bytes:
    """Модифицировать захваченный MultiSellChoose через XOR-арифметику.

    Формат MultiSellChoose (C2S 0xB0) — подтверждено IDA MCP NWindow.dll:
        byte[0]    = opcode 0xB0 (plain)
        byte[1:5]  = listId   (LE int32)
        byte[5:9]  = entryId  (LE int32)
        byte[9:13] = amount   (LE int32)   ← int32, не int64!
        byte[13:]  = attributes (enchant, attr, blessed, ensoul slots)

    XOR-арифметика: new_enc = old_enc ^ old_plain ^ new_plain
    Не требует знания ключа шифрования!
    """
    data = bytearray.fromhex(captured_hex)
    if len(data) < 9:
        raise ValueError(f"Captured packet too short: {len(data)} bytes")

    # Modify entryId (bytes 5-8)
    if new_entry_id is not None:
        oid = old_entry_id if old_entry_id is not None else 1
        old_bytes = struct.pack("<I", oid)
        new_bytes = struct.pack("<I", new_entry_id)
        for i in range(4):
            data[5 + i] ^= old_bytes[i] ^ new_bytes[i]

    # Modify amount (bytes 9-12, LE int32)
    if new_amount is not None and len(data) >= 13:
        oamt = old_amount if old_amount is not None else 1
        old_bytes = struct.pack("<I", oamt)
        new_bytes = struct.pack("<I", new_amount)
        for i in range(4):
            data[9 + i] ^= old_bytes[i] ^ new_bytes[i]

    return bytes(data)


def build_warehouse_deposit(items: list) -> bytes:
    """SendWareHouseDepositList (0x3B).

    items = [(objectId: int, count: int), ...]
    Формат: opcode(1B) + listSize(4B) + [objectId(4B) + count(8B)] * N
    """
    buf = struct.pack("<BI", 0x3B, len(items))
    for obj_id, count in items:
        buf += struct.pack("<Iq", obj_id, count)
    return buf


def build_warehouse_withdraw(items: list) -> bytes:
    """SendWareHouseWithDrawList (0x3C).

    items = [(objectId: int, count: int), ...]
    Формат: opcode(1B) + listSize(4B) + [objectId(4B) + count(8B)] * N
    """
    buf = struct.pack("<BI", 0x3C, len(items))
    for obj_id, count in items:
        buf += struct.pack("<Iq", obj_id, count)
    return buf


def build_buy_item(merchant_id: int, items: list) -> bytes:
    """RequestBuyItem (0x40) — покупка у NPC (бакалейная лавка, оружейник, и т.д.).

    items = [(classId: int, count: int), ...]
    Формат: opcode(1) + merchantId(4) + listSize(4) + [classId(4) + count(8)] * N
    """
    buf = struct.pack("<BII", 0x40, merchant_id, len(items))
    for class_id, count in items:
        buf += struct.pack("<Iq", class_id, count)
    return buf


def build_sell_item(merchant_id: int, items: list) -> bytes:
    """RequestSellItem (0x37) — продажа NPC.

    items = [(objectId: int, classId: int, count: int), ...]
    Формат: opcode(1) + merchantId(4) + listSize(4) + [objectId(4) + classId(4) + count(8)] * N
    """
    buf = struct.pack("<BII", 0x37, merchant_id, len(items))
    for obj_id, class_id, count in items:
        buf += struct.pack("<IIq", obj_id, class_id, count)
    return buf


def build_request_buy_seed(manor_id: int, items: list) -> bytes:
    """RequestBuySeed (0xC5).

    items = [(seedId: int, count: int), ...]
    """
    buf = struct.pack("<BII", 0xC5, manor_id, len(items))
    for seed_id, count in items:
        buf += struct.pack("<Iq", seed_id, count)
    return buf


def wrap_relay_0x06(game_body: bytes) -> bytes:
    """Обернуть game body в relay-протокол 0x06 с double-XOR обфускацией.

    Обратная операция к deobfuscation в relay_c2s PLAINTEXT_INTERMEDIATE.
    Всегда Type B формат (без 8-byte padding) — соответствует реальному клиенту.

    Алгоритм:
      1. Layer 2: layer2 = [0x00] + game_body; layer1_data = XOR(layer2, mask2)
      2. Layer 1: inner_body = [mask1] + XOR(layer1_data, mask1)
      3. Result: [0x06] + inner_body

    При unwrap:
      1. XOR inner_body с mask1=inner_body[0] → deobf; layer1_data = deobf[1:]  (Type B)
      2. XOR layer1_data с mask2=layer1_data[0] → layer2; game_body = layer2[1:]
    """
    # Layer 2: prepend zero + XOR with mask2
    mask2 = game_body[0]  # use opcode as mask (matches observed traffic)
    if mask2 == 0x00:
        mask2 = game_body[1] if len(game_body) >= 2 and game_body[1] != 0 else 0x5A
    layer2 = bytes([0x00]) + game_body
    layer1_data = bytes(b ^ mask2 for b in layer2)

    # Layer 1: pick mask1 so that Type B is used (deobf[1:8] NOT all zeros).
    # deobf[1] = layer1_data[0] ^ mask1 = mask2 ^ mask1.
    # Для Type B нужно deobf[1] != 0, т.е. mask1 != mask2.
    mask1 = mask2 ^ 0x86  # гарантированно != mask2; даёт стабильный ненулевой результат
    if mask1 == 0:
        mask1 = 0xC6  # fallback
    inner_body = bytes([mask1]) + bytes(b ^ mask1 for b in layer1_data)
    return bytes([0x06]) + inner_body


def wrap_relay_raw(inner_body: bytes) -> bytes:
    """Обернуть raw inner_body в relay пакет 0x06 (без обфускации — для replay).

    inner_body — сырые байты из перехваченного relay пакета (после 0x06).
    """
    return bytes([0x06]) + inner_body


# ═══════════════════════════════════════════════════════════════════════════════
# MCP Server
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_known_c2s(opcode: int, data: bytes) -> dict:
    """Разобрать поля подтверждённых C2S пакетов (из спецификации field catalog).

    ВАЖНО: для live relay game_body значения полей могут быть обфусцированы
    (carrier_plain ≠ semantic_builder_plain). Структура (offsets) верна,
    но numeric values из live capture не доверенные — они проходят через
    field-XOR обфускацию на relay layer.
    Только builder-constructed или sniff-decrypted пакеты имеют чистые значения.
    """
    fields = {}
    try:
        if opcode == 0x19 and len(data) >= 9:  # UseItem
            fields = {"object_id": struct.unpack_from("<I", data, 1)[0],
                      "unknown": struct.unpack_from("<I", data, 5)[0]}
        elif opcode == 0x1F and len(data) >= 18:  # Action
            fields = {"object_id": struct.unpack_from("<I", data, 1)[0],
                      "origin_x": struct.unpack_from("<i", data, 5)[0],
                      "origin_y": struct.unpack_from("<i", data, 9)[0],
                      "origin_z": struct.unpack_from("<i", data, 13)[0],
                      "action_id": data[17]}
        elif opcode == 0x5F and len(data) >= 5:  # EnchantItem
            fields = {"object_id": struct.unpack_from("<I", data, 1)[0]}
        elif opcode == 0x1A and len(data) >= 5:  # TradeRequest
            fields = {"object_id": struct.unpack_from("<I", data, 1)[0]}
        elif opcode == 0x1B and len(data) >= 13:  # AddTradeItem (13B core)
            fields = {"trade_id": struct.unpack_from("<I", data, 1)[0],
                      "object_id": struct.unpack_from("<I", data, 5)[0],
                      "count": struct.unpack_from("<I", data, 9)[0]}
        elif opcode == 0x1C and len(data) >= 5:  # TradeDone
            fields = {"response": struct.unpack_from("<I", data, 1)[0],
                      "accept": bool(struct.unpack_from("<I", data, 1)[0])}
        elif opcode == 0x55 and len(data) >= 5:  # AnswerTradeRequest
            fields = {"answer": struct.unpack_from("<I", data, 1)[0]}
        elif opcode == 0x40 and len(data) >= 9:  # RequestBuyItem
            merchant = struct.unpack_from("<I", data, 1)[0]
            n = struct.unpack_from("<I", data, 5)[0]
            items = []
            off = 9
            for i in range(min(n, 50)):
                if off + 12 > len(data):
                    break
                cid = struct.unpack_from("<I", data, off)[0]
                cnt = struct.unpack_from("<q", data, off + 4)[0]
                items.append({"class_id": cid, "count": cnt})
                off += 12
            fields = {"merchant_id": merchant, "list_size": n, "items": items}
        elif opcode == 0x37 and len(data) >= 9:  # RequestSellItem
            merchant = struct.unpack_from("<I", data, 1)[0]
            n = struct.unpack_from("<I", data, 5)[0]
            items = []
            off = 9
            for i in range(min(n, 50)):
                if off + 16 > len(data):
                    break
                oid = struct.unpack_from("<I", data, off)[0]
                cid = struct.unpack_from("<I", data, off + 4)[0]
                cnt = struct.unpack_from("<q", data, off + 8)[0]
                items.append({"object_id": oid, "class_id": cid, "count": cnt})
                off += 16
            fields = {"merchant_id": merchant, "list_size": n, "items": items}
        elif opcode == 0x3B and len(data) >= 5:  # WHDeposit
            n = struct.unpack_from("<I", data, 1)[0]
            items = []
            off = 5
            for i in range(min(n, 50)):
                if off + 12 > len(data):
                    break
                oid = struct.unpack_from("<I", data, off)[0]
                cnt = struct.unpack_from("<q", data, off + 4)[0]
                items.append({"object_id": oid, "count": cnt})
                off += 12
            fields = {"list_size": n, "items": items}
        elif opcode == 0x3C and len(data) >= 5:  # WHWithdraw
            n = struct.unpack_from("<I", data, 1)[0]
            items = []
            off = 5
            for i in range(min(n, 50)):
                if off + 12 > len(data):
                    break
                oid = struct.unpack_from("<I", data, off)[0]
                cnt = struct.unpack_from("<q", data, off + 4)[0]
                items.append({"object_id": oid, "count": cnt})
                off += 12
            fields = {"list_size": n, "items": items}
        elif opcode == 0xB0 and len(data) >= 13:  # MultiSellChoose
            fields = {"list_id": struct.unpack_from("<I", data, 1)[0],
                      "entry_id": struct.unpack_from("<I", data, 5)[0],
                      "amount": struct.unpack_from("<I", data, 9)[0]}
            if len(data) >= 17:
                fields["enchant"] = struct.unpack_from("<I", data, 13)[0]
        elif opcode == 0x57 and len(data) >= 1:  # RequestRestart
            fields = {"opcode_only": True}
    except (struct.error, IndexError):
        pass
    return fields


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
              description="RequestMultiSellChoose (0xB0) — покупка в мультиселле. "
                          "Подтверждено IDA MCP NWindow.dll: все поля LE32, 3 ensoul-слота (пустые). "
                          "list_id: MultiSellGroupID (напр. 81381), "
                          "entry_id: MultiSellInfoID (запись в списке: 1/3/5/7), "
                          "amount: ItemCount, enchant: уровень зачарования входного предмета (0=нет).",
              inputSchema=_schema(
                  list_id={"type": "integer", "required": True,
                           "description": "MultiSellGroupID (ID мультиселл-листа)"},
                  entry_id={"type": "integer", "required": True,
                            "description": "MultiSellInfoID (номер записи в листе)"},
                  amount={"type": "integer", "default": 1,
                          "description": "ItemCount (количество)"},
                  enchant={"type": "integer", "default": 0,
                           "description": "Enchant (уровень зачарования входного предмета)"},
              )),
            T(name="l2_inject_s2c",
              description="Инъекция S→C пакета (hex) — спуфинг от имени сервера клиенту. "
                          "Первый байт = опкод S2C.",
              inputSchema=_schema(
                  hex_data={"type": "string", "required": True,
                            "description": "Hex данные S2C пакета"},
              )),
            T(name="l2_get_packet_hex",
              description="Полный hex дамп пакета по seq номеру. "
                          "Возвращает до max_bytes байт (по умолчанию 8192).",
              inputSchema=_schema(
                  seq={"type": "integer", "required": True,
                       "description": "Номер пакета (seq)"},
                  offset={"type": "integer", "default": 0,
                          "description": "Смещение в байтах от начала тела"},
                  max_bytes={"type": "integer", "default": 8192,
                             "description": "Макс. байт для возврата"},
              )),
            T(name="l2_warehouse_deposit",
              description="SendWareHouseDepositList (0x3B) — депозит предметов на склад. "
                          "items: [[objectId, count], ...] — массив пар [id, кол-во].",
              inputSchema=_schema(
                  items={"type": "array", "required": True,
                         "description": "Массив [[objectId, count], ...]",
                         "items": {"type": "array", "items": {"type": "integer"}}},
              )),
            T(name="l2_warehouse_withdraw",
              description="SendWareHouseWithDrawList (0x3C) — забрать предметы со склада. "
                          "items: [[objectId, count], ...] — массив пар [id, кол-во].",
              inputSchema=_schema(
                  items={"type": "array", "required": True,
                         "description": "Массив [[objectId, count], ...]",
                         "items": {"type": "array", "items": {"type": "integer"}}},
              )),
            T(name="l2_warehouse_race",
              description="Race condition тест: отправить N одинаковых withdraw/deposit пакетов "
                          "максимально быстро (без задержки между ними). "
                          "action: 'withdraw' или 'deposit'. items: [[objectId, count], ...].",
              inputSchema=_schema(
                  action={"type": "string", "required": True,
                          "description": "'withdraw' или 'deposit'",
                          "enum": ["withdraw", "deposit"]},
                  items={"type": "array", "required": True,
                         "description": "Массив [[objectId, count], ...]"},
                  count={"type": "integer", "default": 2,
                         "description": "Кол-во одинаковых пакетов (default: 2)"},
              )),
            # ═══ Новые инструменты ═══
            T(name="l2_get_status",
              description="Полный статус прокси: состояние proxy/divert/sniffer, "
                          "активные сессии, target, крипто-ключи, счётчики пакетов.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_get_game_log",
              description="Человекочитаемый игровой лог — последние N событий на русском языке. "
                          "Показывает: авторизацию, вход в мир, покупки, продажи, обмен, "
                          "склад, телепорт, чат, скиллы, инъекции.",
              inputSchema=_schema(
                  count={"type": "integer", "default": 50,
                         "description": "Макс. кол-во событий"},
              )),
            T(name="l2_buy_item",
              description="RequestBuyItem (0x40) — покупка у NPC (бакалейная лавка, оружейник). "
                          "merchant_id: objectId NPC, items: [[classId, count], ...].",
              inputSchema=_schema(
                  merchant_id={"type": "integer", "required": True,
                               "description": "ObjectId NPC-продавца"},
                  items={"type": "array", "required": True,
                         "description": "[[classId, count], ...] — classId предмета, количество",
                         "items": {"type": "array", "items": {"type": "integer"}}},
              )),
            T(name="l2_sell_item",
              description="RequestSellItem (0x37) — продажа NPC. "
                          "merchant_id: objectId NPC, items: [[objectId, classId, count], ...].",
              inputSchema=_schema(
                  merchant_id={"type": "integer", "required": True,
                               "description": "ObjectId NPC-продавца"},
                  items={"type": "array", "required": True,
                         "description": "[[objectId, classId, count], ...]",
                         "items": {"type": "array", "items": {"type": "integer"}}},
              )),
            T(name="l2_parse_packet",
              description="Разобрать пакет по seq номеру — field-level parse через PacketDefDB. "
                          "Показывает имена полей, типы, значения (если есть PacketsXXX.ini).",
              inputSchema=_schema(
                  seq={"type": "integer", "required": True,
                       "description": "Номер пакета (seq)"},
              )),
            T(name="l2_get_sessions",
              description="Список активных proxy-сессий с портами и счётчиками.",
              inputSchema={"type": "object", "properties": {}}),
            T(name="l2_search_packets",
              description="Поиск пакетов по содержимому hex (подстрока в dec_hex). "
                          "Полезно для поиска конкретных objectId, строк, паттернов в трафике.",
              inputSchema=_schema(
                  hex_pattern={"type": "string", "required": True,
                               "description": "Hex-подстрока для поиска (например '0019' для UseItem)"},
                  direction={"type": "string", "default": "all",
                             "enum": ["C2S", "S2C", "all"]},
                  count={"type": "integer", "default": 20,
                         "description": "Макс. результатов"},
              )),
            T(name="l2_get_opcode_table",
              description="Получить текущую таблицу опкодов (hardcoded + JSON + INI). "
                          "Полезно для отладки маппинга опкодов на имена.",
              inputSchema=_schema(
                  direction={"type": "string", "default": "C2S",
                             "enum": ["C2S", "S2C"],
                             "description": "C2S или S2C"},
              )),
            T(name="l2_get_workflow_context",
              description="Последние game:* пакеты, сгруппированные по workflow-эпизодам "
                          "(C2S action → S2C carriers → next). "
                          "Показывает контекст: какие S2C пакеты сервер отправил в ответ "
                          "на каждое C2S действие.",
              inputSchema=_schema(
                  count={"type": "integer", "default": 100,
                         "description": "Макс. пакетов для анализа"},
              )),
            T(name="l2_identify_action",
              description="Runtime opcode identification — записать снимок пакетов "
                          "ДО и ПОСЛЕ выполнения действия в игре. "
                          "Использование: 1) вызвать с mode='start', 2) выполнить действие в игре, "
                          "3) вызвать с mode='stop'. Покажет все C2S и S2C пакеты между start/stop. "
                          "Это позволяет определить РЕАЛЬНЫЕ opcodes на live Innova сервере.",
              inputSchema=_schema(
                  mode={"type": "string", "enum": ["start", "stop", "status"],
                        "description": "start=начать запись, stop=показать результат, status=текущий статус"},
                  label={"type": "string", "default": "",
                         "description": "Метка действия (напр. 'покупка_в_лавке')"},
              )),
            T(name="l2_trade_request",
              description="TradeRequest (0x1A) — инициировать обмен с игроком.",
              inputSchema=_schema(
                  object_id={"type": "integer", "required": True,
                             "description": "ObjectId целевого игрока"},
              )),
            T(name="l2_trade_add_item",
              description="AddTradeItem (0x1B) — добавить предмет в окно обмена. "
                          "Подтверждено IDA MCP: 13B = opcode + d(TradeID) + d(ObjectID) + d(Count).",
              inputSchema=_schema(
                  trade_id={"type": "integer", "required": True,
                            "description": "ID окна обмена"},
                  object_id={"type": "integer", "required": True,
                             "description": "ObjectId предмета"},
                  amount={"type": "integer", "default": 1},
              )),
            T(name="l2_trade_done",
              description="TradeDone (0x1C) — завершить/отменить обмен.",
              inputSchema=_schema(
                  accept={"type": "boolean", "default": True,
                          "description": "true=подтвердить, false=отменить"},
              )),
            T(name="l2_answer_trade",
              description="AnswerTradeRequest (0x55) — принять/отклонить входящий запрос обмена.",
              inputSchema=_schema(
                  accept={"type": "boolean", "default": True,
                          "description": "true=принять, false=отклонить"},
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
            sock = self.proxy.server_sock
            srv_lock = getattr(self.proxy, 'relay_server_lock', None)
            is_relay = getattr(self.proxy, '_target_port', 0) in (17453,)

            def flood():
                for i in range(count):
                    if sock and is_relay:
                        try:
                            wrapped = wrap_relay_0x06(data)
                            # Используем server_lock чтобы не конфликтовать
                            # с relay_c2s, который тоже пишет в server_sock
                            if srv_lock:
                                with srv_lock:
                                    send_l2_packet(sock, wrapped)
                            else:
                                send_l2_packet(sock, wrapped)
                        except Exception as e:
                            _dbg(f"[FLOOD] send #{i} failed: {e}")
                            break
                    else:
                        self.proxy.inject_c2s.append(data)
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)

            threading.Thread(target=flood, daemon=True).start()
            op, nm = decode_opcode(data, "C2S")
            return {"status": "flooding", "opcode": f"0x{op:04X}",
                    "name": nm, "count": count,
                    "direct": is_relay}

        if name == "l2_multisell":
            return self._inject(build_multisell_choose(
                args["list_id"], args["entry_id"],
                args.get("amount", 1), args.get("enchant", 0)))

        if name == "l2_inject_s2c":
            return self._inject_s2c(bytes.fromhex(args["hex_data"]))

        if name == "l2_get_packet_hex":
            pkt = self.store.get_by_seq(args["seq"])
            if not pkt:
                return {"error": f"Packet #{args['seq']} not found"}
            body = pkt.get("_body", b"")
            if not body:
                return {"error": f"Packet #{args['seq']} has no body data (old session?)"}
            offset = args.get("offset", 0)
            max_bytes = args.get("max_bytes", 8192)
            chunk = body[offset:offset + max_bytes]
            return {
                "seq": pkt["seq"],
                "dir": pkt["dir"],
                "opcode": f"0x{pkt['opcode']:04X}",
                "opname": pkt["opname"],
                "total_len": len(body),
                "offset": offset,
                "chunk_len": len(chunk),
                "hex": chunk.hex(),
            }

        if name == "l2_warehouse_deposit":
            items = [(it[0], it[1]) for it in args["items"]]
            return self._inject(build_warehouse_deposit(items))

        if name == "l2_warehouse_withdraw":
            items = [(it[0], it[1]) for it in args["items"]]
            return self._inject(build_warehouse_withdraw(items))

        if name == "l2_warehouse_race":
            action = args["action"]
            items = [(it[0], it[1]) for it in args["items"]]
            n = args.get("count", 2)
            if action == "withdraw":
                pkt = build_warehouse_withdraw(items)
            else:
                pkt = build_warehouse_deposit(items)
            # Все пакеты разом в очередь — минимальная задержка
            for _ in range(n):
                self.proxy.inject_c2s.append(pkt)
            op, nm = decode_opcode(pkt, "C2S")
            return {"status": "race_queued", "action": action,
                    "opcode": f"0x{op:04X}", "name": nm,
                    "count": n, "items": len(items),
                    "pkt_size": len(pkt)}

        # ═══ Новые инструменты ═══

        if name == "l2_get_status":
            result = {
                "proxy_running": self.proxy.running,
                "proxy_connected": self.proxy.connected,
                "target_port": getattr(self.proxy, '_target_port', None),
                "plaintext_intermediate": PLAINTEXT_INTERMEDIATE,
                "store_packets": len(self.store.packets),
                "store_seq": self.store.seq,
            }
            c = self.proxy.crypto
            if c:
                result["crypto"] = {
                    "initialized": c.initialized,
                    "passthrough": c.passthrough,
                    "xor_only": getattr(c, 'xor_only', False),
                    "bf_key": c.bf_key.hex() if c.bf_key else None,
                    "xor_key": c.xor_key.hex() if c.xor_key else None,
                }
            sessions = {}
            with self.proxy._sessions_lock:
                for sid, sess in self.proxy._sessions.items():
                    sessions[sid] = {
                        "target_port": sess["target_port"],
                        "has_client": sess["client_sock"] is not None,
                        "has_server": sess["server_sock"] is not None,
                    }
            result["active_sessions"] = sessions
            return result

        if name == "l2_get_game_log":
            # Используем interpret_packet из l2phx.py (если доступен),
            # иначе — простой fallback на opname
            count = args.get("count", 50)
            events = []
            try:
                # interpret_packet определён в l2phx.py, импортируем динамически
                import importlib
                l2phx_mod = sys.modules.get('__main__')
                interp = getattr(l2phx_mod, 'interpret_packet', None) if l2phx_mod else None
                if interp is None:
                    # Попробуем из l2phx напрямую
                    for mod in sys.modules.values():
                        interp = getattr(mod, 'interpret_packet', None)
                        if interp:
                            break
            except Exception:
                interp = None

            for pkt in reversed(list(self.store.packets)):
                if len(events) >= count:
                    break
                dec_hex = pkt.get("dec_hex", "")
                opcode = pkt.get("opcode", -1)
                opname = pkt.get("opname", "")
                direction = pkt.get("dir", "")
                ts = pkt.get("ts", "")
                text = None
                if interp:
                    text = interp(direction, opcode, opname, dec_hex)
                if not text and opname and "game:" in opname:
                    text = f"{direction} {opname}"
                if text:
                    events.append({"time": ts, "dir": direction, "text": text,
                                   "seq": pkt.get("seq", 0),
                                   "opcode": f"0x{opcode:04X}" if isinstance(opcode, int) and opcode >= 0 else str(opcode)})
            events.reverse()
            return {"count": len(events), "events": events}

        if name == "l2_buy_item":
            merchant_id = args["merchant_id"]
            items = [(it[0], it[1]) for it in args["items"]]
            return self._inject(build_buy_item(merchant_id, items))

        if name == "l2_sell_item":
            merchant_id = args["merchant_id"]
            items = [(it[0], it[1], it[2]) for it in args["items"]]
            return self._inject(build_sell_item(merchant_id, items))

        if name == "l2_parse_packet":
            pkt = self.store.get_by_seq(args["seq"])
            if not pkt:
                return {"error": f"Packet #{args['seq']} not found"}
            dec_hex = pkt.get("dec_hex", "")
            if not dec_hex:
                return {"error": "No decrypted data", "raw_hex": pkt.get("raw_hex", "")}
            data = bytes.fromhex(dec_hex)
            direction = pkt.get("dir", "C2S")
            # Ищем PacketDefDB в модулях
            pkt_db = None
            for mod in sys.modules.values():
                pkt_db = getattr(mod, '_pkt_db_instance', None)
                if pkt_db:
                    break
            if pkt_db and hasattr(pkt_db, 'parse_packet'):
                parsed = pkt_db.parse_packet(data, direction)
                parsed["seq"] = pkt.get("seq")
                parsed["dir"] = direction
                parsed["opname"] = pkt.get("opname", "")
                parsed["body_len"] = len(data)
                return parsed
            # Fallback: ручной минимальный разбор
            opcode = data[0] if data else -1
            result = {
                "seq": pkt.get("seq"), "dir": direction,
                "opcode": f"0x{opcode:02X}", "opname": pkt.get("opname", ""),
                "body_len": len(data), "hex": dec_hex[:512],
                "note": "PacketDefDB not available — raw hex only",
            }
            # Извлечь поля для подтверждённых пакетов (спецификация C2S field catalog)
            result["fields"] = _parse_known_c2s(opcode, data)
            return result

        if name == "l2_get_sessions":
            sessions = {}
            with self.proxy._sessions_lock:
                for sid, sess in self.proxy._sessions.items():
                    sessions[sid] = {
                        "target_port": sess["target_port"],
                        "has_client": sess["client_sock"] is not None,
                        "has_server": sess["server_sock"] is not None,
                    }
            return {"active_sessions": sessions,
                    "active_session_id": getattr(self.proxy, '_active_session_id', None),
                    "proxy_running": self.proxy.running,
                    "proxy_connected": self.proxy.connected}

        if name == "l2_search_packets":
            pattern = args["hex_pattern"].lower().replace(" ", "")
            direction = args.get("direction", "all")
            max_count = args.get("count", 20)
            results = []
            for pkt in reversed(list(self.store.packets)):
                if len(results) >= max_count:
                    break
                if direction != "all" and pkt.get("dir") != direction:
                    continue
                dec_hex = pkt.get("dec_hex", "")
                if pattern in dec_hex.lower():
                    pos = dec_hex.lower().index(pattern)
                    results.append({
                        "seq": pkt.get("seq"),
                        "dir": pkt.get("dir"),
                        "opcode": f"0x{pkt.get('opcode', -1):04X}",
                        "opname": pkt.get("opname", ""),
                        "size": pkt.get("len", 0),
                        "match_offset": pos // 2,  # byte offset
                        "context": dec_hex[max(0, pos-16):pos+len(pattern)+16],
                    })
            results.reverse()
            return {"pattern": pattern, "count": len(results), "results": results}

        if name == "l2_get_opcode_table":
            direction = args.get("direction", "C2S")
            if direction == "C2S":
                main = {f"0x{k:02X}": v for k, v in C2S_OPCODES.items()}
                ex = {f"0x{k:04X}": v for k, v in C2S_EX.items()}
                custom_main = {f"0x{k:02X}": v for k, v in _custom_c2s.items()}
                custom_ex = {f"0x{k:04X}": v for k, v in _custom_c2s_ex.items()}
            else:
                main = {f"0x{k:02X}": v for k, v in S2C_OPCODES.items()}
                ex = {f"0x{k:04X}": v for k, v in S2C_EX.items()}
                custom_main = {f"0x{k:02X}": v for k, v in _custom_s2c.items()}
                custom_ex = {f"0x{k:04X}": v for k, v in _custom_s2c_ex.items()}
            return {
                "direction": direction,
                "main_opcodes": main, "main_count": len(main),
                "ex_opcodes": ex, "ex_count": len(ex),
                "custom_main": custom_main, "custom_ex": custom_ex,
            }

        if name == "l2_identify_action":
            mode = args.get("mode", "status")
            label = args.get("label", "")
            if mode == "start":
                _IDENTIFY_STATE["active"] = True
                _IDENTIFY_STATE["start_seq"] = self.store.seq
                _IDENTIFY_STATE["label"] = label
                _IDENTIFY_STATE["start_ts"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                return {"status": "recording", "start_seq": _IDENTIFY_STATE["start_seq"],
                        "label": label, "message": "Запись начата. Выполните действие в игре, затем вызовите с mode='stop'."}
            elif mode == "stop":
                if not _IDENTIFY_STATE.get("active"):
                    return {"error": "Запись не была начата. Сначала вызовите с mode='start'."}
                start_seq = _IDENTIFY_STATE["start_seq"]
                _IDENTIFY_STATE["active"] = False
                end_seq = self.store.seq
                # Collect all non-padding game packets between start and end
                c2s_pkts = []
                s2c_pkts = []
                for pkt in self.store.packets:
                    seq = pkt.get("seq", 0)
                    if seq <= start_seq or seq > end_seq:
                        continue
                    opname = pkt.get("opname", "")
                    extra = pkt.get("extra", {})
                    if extra.get("is_padding"):
                        continue
                    if not opname.startswith("game:") and not opname.startswith("sniff:"):
                        continue
                    entry = {
                        "seq": seq, "dir": pkt.get("dir"),
                        "opcode": f"0x{pkt.get('opcode', 0):04X}",
                        "opname": opname,
                        "size": pkt.get("len", 0),
                        "hex_preview": pkt.get("dec_hex", "")[:64],
                    }
                    if pkt.get("dir") == "C2S":
                        c2s_pkts.append(entry)
                    else:
                        s2c_pkts.append(entry)
                return {
                    "label": _IDENTIFY_STATE.get("label", ""),
                    "start_seq": start_seq, "end_seq": end_seq,
                    "start_ts": _IDENTIFY_STATE.get("start_ts", ""),
                    "c2s_count": len(c2s_pkts), "s2c_count": len(s2c_pkts),
                    "c2s_packets": c2s_pkts[:50],
                    "s2c_packets": s2c_pkts[:50],
                    "summary": f"Записано {len(c2s_pkts)} C2S + {len(s2c_pkts)} S2C пакетов за действие '{_IDENTIFY_STATE.get('label', '')}'",
                }
            else:  # status
                return {
                    "active": _IDENTIFY_STATE.get("active", False),
                    "start_seq": _IDENTIFY_STATE.get("start_seq", 0),
                    "label": _IDENTIFY_STATE.get("label", ""),
                }

        if name == "l2_get_workflow_context":
            # Последние N game:* пакетов сгруппированные по workflow-эпизодам
            count = args.get("count", 100)
            episodes = []
            current = []
            last_dir = None
            for pkt in reversed(list(self.store.packets)):
                opname = pkt.get("opname", "")
                if not opname.startswith("game:") and not opname.startswith("sniff:"):
                    continue
                extra = pkt.get("extra", {})
                if extra.get("is_padding"):
                    continue
                entry = {
                    "seq": pkt.get("seq"), "dir": pkt.get("dir"),
                    "opcode": f"0x{pkt.get('opcode', -1):04X}",
                    "name": opname, "size": pkt.get("len", 0),
                }
                # Новый эпизод: смена C2S→S2C
                if pkt.get("dir") == "C2S" and last_dir == "S2C" and current:
                    episodes.append(list(reversed(current)))
                    current = []
                current.append(entry)
                last_dir = pkt.get("dir")
                if len(episodes) >= count:
                    break
            if current:
                episodes.append(list(reversed(current)))
            episodes.reverse()
            return {"episode_count": len(episodes), "episodes": episodes[-20:]}

        if name == "l2_trade_request":
            object_id = args["object_id"]
            pkt = struct.pack("<BI", 0x1A, object_id)
            return self._inject(pkt)

        if name == "l2_trade_add_item":
            trade_id = args["trade_id"]
            object_id = args["object_id"]
            amount = args.get("amount", 1)
            pkt = struct.pack("<BIII", 0x1B, trade_id, object_id, amount)
            return self._inject(pkt)

        if name == "l2_trade_done":
            # 0x1C TradeDone, 1 = accept, 0 = cancel
            accept = 1 if args.get("accept", True) else 0
            pkt = struct.pack("<BI", 0x1C, accept)
            return self._inject(pkt)

        if name == "l2_answer_trade":
            answer = 1 if args.get("accept", True) else 0
            pkt = struct.pack("<BI", 0x55, answer)
            return self._inject(pkt)

        return {"error": f"Unknown tool: {name}"}

    def _inject(self, plaintext: bytes) -> dict:
        """Inject C→S packet (as if client sent it to server).

        В PLAINTEXT_INTERMEDIATE: оборачивает в relay 0x06 и шлёт напрямую.
        В стандартном режиме: кладёт в очередь inject_c2s.
        """
        if not self.proxy.connected:
            return {"error": "Proxy not connected — no active game session"}
        op, nm = decode_opcode(plaintext, "C2S")

        # Прямая отправка через сокет (обход очереди — для PLAINTEXT_INTERMEDIATE)
        sock = self.proxy.server_sock
        if not sock:
            return {"error": "No server socket — relay session not active"}

        # Проверяем что сокет жив
        try:
            sock.getpeername()
        except (OSError, AttributeError):
            return {"error": "Server socket is closed — relay session ended"}

        target_port = getattr(self.proxy, '_target_port', 0)
        if target_port in (17453,) and PLAINTEXT_INTERMEDIATE:
            try:
                wrapped = wrap_relay_0x06(plaintext)
                send_l2_packet(sock, wrapped)
                self.proxy.store.add("C2S", wrapped, plaintext, op,
                                     f"INJECT:{nm}",
                                     extra={"injected": True})
                return {"status": "sent_direct", "direction": "C2S",
                        "opcode": f"0x{op:04X}", "name": nm,
                        "size": len(plaintext), "relay_size": len(wrapped)}
            except Exception as e:
                return {"error": f"Direct send failed: {e}"}

        # Стандартный режим — через очередь (relay loop обработает)
        self.proxy.inject_c2s.append(plaintext)
        return {"status": "queued", "direction": "C2S",
                "opcode": f"0x{op:04X}", "name": nm, "size": len(plaintext)}

    def _inject_s2c(self, plaintext: bytes) -> dict:
        """Inject S→C packet (as if server sent it to client).

        В PLAINTEXT_INTERMEDIATE на 17453: оборачивает в relay 0x06 и шлёт клиенту.
        Клиент ожидает outer-protocol пакеты, не голый game_body.
        """
        if not self.proxy.connected:
            return {"error": "Proxy not connected — no active game session"}
        op, nm = decode_opcode(plaintext, "S2C")

        sock = self.proxy.client_sock
        if not sock:
            return {"error": "No client socket — session not active"}

        # Проверяем что сокет жив
        try:
            sock.getpeername()
        except (OSError, AttributeError):
            return {"error": "Client socket is closed — session ended"}

        target_port = getattr(self.proxy, '_target_port', 0)
        if target_port in (17453,) and PLAINTEXT_INTERMEDIATE:
            # На 17453 клиент ожидает outer-protocol пакеты (relay 0x06).
            # Оборачиваем game_body в relay точно так же, как C2S inject.
            try:
                wrapped = wrap_relay_0x06(plaintext)
                send_l2_packet(sock, wrapped)
                self.proxy.store.add("S2C", wrapped, plaintext, op,
                                     f"INJECT:{nm}",
                                     extra={"injected": True,
                                            "relay_wrapped": True,
                                            "relay_size": len(wrapped)})
                return {"status": "sent_direct", "direction": "S2C",
                        "opcode": f"0x{op:04X}", "name": nm,
                        "size": len(plaintext),
                        "relay_size": len(wrapped)}
            except Exception as e:
                return {"error": f"S2C direct send failed: {e}"}

        # Стандартный режим (не relay) — через очередь
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
        # Пассивный сниффер для порта 7777 (raw socket, без WinDivert)
        threading.Thread(
            target=RawSocketSniffer(store).run,
            daemon=True, name="sniff-7777").start()

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
