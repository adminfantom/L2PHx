#!/usr/bin/env python
"""
Дамп таблиц опкодов L2 Main из памяти работающего клиента.

Читает GL2UserPacketTableName / GL2UserExPacketTableName из Core.dll
через ReadProcessMemory. Таблицы находятся в .bss секции и заполняются
только в runtime — из файла прочитать невозможно.

Использование:
  python dump_opcode_tables.py
  python dump_opcode_tables.py --pid 12345
  python dump_opcode_tables.py --output opcodes.json

Требует: запущенный L2.exe, права администратора (или SeDebugPrivilege).
Авторизованный пентест Innova/4Game, S59 2026-03-18.
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os
import json
import argparse
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════════════
# Windows API
# ═══════════════════════════════════════════════════════════════════════════════

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MAX_PATH = 260

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wt.HANDLE
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

CloseHandle = kernel32.CloseHandle
ReadProcessMemory = kernel32.ReadProcessMemory

EnumProcessModulesEx = psapi.EnumProcessModulesEx
GetModuleBaseNameW = psapi.GetModuleBaseNameW
GetModuleInformation = psapi.GetModuleInformation


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wt.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


def enable_debug_privilege():
    """Включить SeDebugPrivilege для доступа к чужим процессам."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wt.DWORD),
            ("Luid", LUID),
            ("Attributes", wt.DWORD),
        ]

    h_token = wt.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(h_token)
    ):
        return False

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        kernel32.CloseHandle(h_token)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Luid = luid
    tp.Attributes = SE_PRIVILEGE_ENABLED

    ok = advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)
    err = ctypes.get_last_error()
    kernel32.CloseHandle(h_token)
    return ok and err == 0


def find_pid(name="L2.exe"):
    """Найти PID процесса по имени."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["wmic", "process", "where", f"name='{name}'", "get", "processid"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in out.strip().split("\n"):
            line = line.strip()
            if line.isdigit():
                return int(line)
    except Exception:
        pass
    # Fallback через tasklist
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL
        )
        for line in out.decode("cp1251", errors="replace").split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return int(parts[1])
    except Exception:
        pass
    return None


def rpm(handle, addr, size):
    """ReadProcessMemory wrapper."""
    buf = ctypes.create_string_buffer(size)
    n_read = ctypes.c_size_t(0)
    ok = ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n_read))
    if not ok:
        err = ctypes.get_last_error()
        raise OSError(f"ReadProcessMemory failed at 0x{addr:08X} size={size}: error {err}")
    return buf.raw[:n_read.value]


def read_u32(handle, addr):
    return struct.unpack("<I", rpm(handle, addr, 4))[0]


def read_ptr(handle, addr):
    """Читает 32-bit pointer (L2.exe — 32-bit процесс)."""
    return struct.unpack("<I", rpm(handle, addr, 4))[0]


def read_wstring(handle, addr, max_chars=256):
    """Читает null-terminated wchar_t* строку из памяти."""
    if addr == 0:
        return None
    try:
        data = rpm(handle, addr, max_chars * 2)
    except OSError:
        return None
    # Ищем null terminator
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            return data[:i].decode("utf-16-le", errors="replace")
    return data.decode("utf-16-le", errors="replace")


def find_module_base(handle, module_name):
    """Найти базовый адрес модуля в процессе."""
    h_mods = (ctypes.c_void_p * 1024)()
    cb_needed = wt.DWORD(0)
    LIST_MODULES_ALL = 0x03

    if not EnumProcessModulesEx(handle, h_mods, ctypes.sizeof(h_mods),
                                 ctypes.byref(cb_needed), LIST_MODULES_ALL):
        raise OSError(f"EnumProcessModulesEx failed: {ctypes.get_last_error()}")

    n_mods = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
    name_buf = ctypes.create_unicode_buffer(MAX_PATH)
    mod_info = MODULEINFO()

    for i in range(n_mods):
        h = h_mods[i]
        if not h:
            continue
        GetModuleBaseNameW(handle, h, name_buf, MAX_PATH)
        if name_buf.value.lower() == module_name.lower():
            GetModuleInformation(handle, h, ctypes.byref(mod_info), ctypes.sizeof(mod_info))
            return mod_info.lpBaseOfDll, mod_info.SizeOfImage
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# Core.dll Export RVAs (из PE анализа)
# ═══════════════════════════════════════════════════════════════════════════════

# ImageBase Core.dll = 0x15000000, но может быть rebased (ASLR)
# Используем RVA (relative to module base):
EXPORTS = {
    "GL2UserPacketTableName":   0x001D7F98,  # wchar_t** — массив указателей на имена
    "GL2UserPacketTableSize":   0x001DD1D8,  # int — кол-во записей
    "GL2UserExPacketTableName": 0x001DBEE0,  # wchar_t** — Ex-таблица
    "GL2UserExPacketTableSize": 0x001D56B4,  # int — кол-во Ex-записей
    "GL2LastRecvPacketNum":     0x001D5674,  # int
    "GL2LastSendPacketNum":     0x001DD1DC,  # int
    "GL2LastRecvPacketNumEX":   0x001D7FA4,  # int
    "GL2LastSendPacketNumEX":   0x001D81E8,  # int
    "GL2PacketCheck":           0x001DD1C4,  # int
}


def dump_packet_table(handle, base, name_rva, size_rva, label):
    """Дамп таблицы опкодов: читает массив wchar_t* указателей и строки."""
    size_addr = base + size_rva
    name_addr = base + name_rva

    table_size = read_u32(handle, size_addr)
    print(f"\n{'='*60}")
    print(f"{label}: size = {table_size}")
    print(f"  Table pointer at: 0x{name_addr:08X}")
    print(f"  Size value at:    0x{size_addr:08X}")

    if table_size == 0 or table_size > 10000:
        print(f"  WARNING: suspicious size {table_size}, table may not be initialized")
        # Попробуем прочитать сам указатель — может это pointer на массив
        ptr_val = read_ptr(handle, name_addr)
        print(f"  Raw pointer value: 0x{ptr_val:08X}")
        if ptr_val == 0:
            print("  Table pointer is NULL — not initialized yet")
            return {}
        if table_size > 10000:
            print("  Clamping to 500 for safety")
            table_size = min(table_size, 500)

    # GL2UserPacketTableName — это wchar_t** (массив указателей)
    # Читаем указатель на массив
    table_ptr = read_ptr(handle, name_addr)
    print(f"  Array base pointer: 0x{table_ptr:08X}")

    if table_ptr == 0:
        print("  Array pointer is NULL")
        return {}

    # Читаем все указатели разом
    ptr_data = rpm(handle, table_ptr, table_size * 4)
    ptrs = struct.unpack(f"<{table_size}I", ptr_data)

    opcodes = {}
    null_count = 0
    for i, p in enumerate(ptrs):
        if p == 0:
            null_count += 1
            continue
        name = read_wstring(handle, p, 128)
        if name:
            opcodes[i] = name
            if len(opcodes) <= 30 or i < 10:
                print(f"  [0x{i:02X}] = {name}")

    if len(opcodes) > 30:
        print(f"  ... и ещё {len(opcodes) - 30} опкодов")

    print(f"  Итого: {len(opcodes)} опкодов, {null_count} NULL записей")
    return opcodes


def main():
    parser = argparse.ArgumentParser(description="Дамп таблиц опкодов L2 Main из памяти")
    parser.add_argument("--pid", type=int, help="PID процесса L2.exe")
    parser.add_argument("--output", "-o", default=None, help="Файл для сохранения JSON")
    args = parser.parse_args()

    # Найти PID
    pid = args.pid
    if not pid:
        pid = find_pid("L2.exe")
    if not pid:
        print("ERROR: L2.exe не найден. Запусти клиент и попробуй снова.")
        print("       Или укажи PID: python dump_opcode_tables.py --pid 12345")
        sys.exit(1)

    print(f"L2.exe PID: {pid}")

    # Включить SeDebugPrivilege
    if enable_debug_privilege():
        print("SeDebugPrivilege: ENABLED")
    else:
        print("SeDebugPrivilege: FAILED (may need admin rights)")

    # Открыть процесс
    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        print(f"ERROR: OpenProcess failed (error {err})")
        print("       Запусти от администратора!")
        sys.exit(1)

    try:
        # Найти Core.dll
        core_base, core_size = find_module_base(handle, "Core.dll")
        if not core_base:
            print("ERROR: Core.dll не найден в процессе")
            sys.exit(1)
        print(f"Core.dll base: 0x{core_base:08X}, size: 0x{core_size:08X}")

        # Проверка: прочитать простые значения
        for name in ["GL2PacketCheck", "GL2LastRecvPacketNum", "GL2LastSendPacketNum",
                      "GL2LastRecvPacketNumEX", "GL2LastSendPacketNumEX"]:
            rva = EXPORTS[name]
            try:
                val = read_u32(handle, core_base + rva)
                print(f"  {name} = {val} (0x{val:08X})")
            except OSError as e:
                print(f"  {name} = ERROR: {e}")

        # Дамп основной таблицы
        main_opcodes = dump_packet_table(
            handle, core_base,
            EXPORTS["GL2UserPacketTableName"],
            EXPORTS["GL2UserPacketTableSize"],
            "GL2UserPacketTable (основные опкоды)"
        )

        # Дамп Ex-таблицы
        ex_opcodes = dump_packet_table(
            handle, core_base,
            EXPORTS["GL2UserExPacketTableName"],
            EXPORTS["GL2UserExPacketTableSize"],
            "GL2UserExPacketTable (расширенные опкоды)"
        )

        # Найти Engine.dll и прочитать GL2PacketHistroryManager
        eng_base, eng_size = find_module_base(handle, "Engine.dll")
        if eng_base:
            print(f"\nEngine.dll base: 0x{eng_base:08X}")
            # GL2PacketHistroryManager @ RVA 0x011FB388 (from export 0x211FB388, base 0x20000000)
            # Но base может быть rebased, вычислим RVA
            hist_rva = 0x011FB388  # 0x211FB388 - 0x20000000
            try:
                hist_ptr = read_ptr(handle, eng_base + hist_rva)
                print(f"  GL2PacketHistroryManager ptr: 0x{hist_ptr:08X}")
            except OSError:
                print("  GL2PacketHistroryManager: read failed")

        # Сохранить результат
        result = {
            "timestamp": datetime.now().isoformat(),
            "pid": pid,
            "core_dll_base": f"0x{core_base:08X}",
            "main_opcodes": {f"0x{k:02X}": v for k, v in sorted(main_opcodes.items())},
            "main_count": len(main_opcodes),
            "ex_opcodes": {f"0x{k:04X}": v for k, v in sorted(ex_opcodes.items())},
            "ex_count": len(ex_opcodes),
        }

        out_path = args.output
        if not out_path:
            out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, "l2_opcodes.json")

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\nСохранено в: {out_path}")

        # Также вывести полный список
        if main_opcodes:
            print(f"\n{'='*60}")
            print(f"ПОЛНЫЙ СПИСОК ОСНОВНЫХ ОПКОДОВ ({len(main_opcodes)}):")
            print(f"{'='*60}")
            for i in sorted(main_opcodes.keys()):
                print(f"  0x{i:02X} = {main_opcodes[i]}")

        if ex_opcodes:
            print(f"\n{'='*60}")
            print(f"ПОЛНЫЙ СПИСОК EX-ОПКОДОВ ({len(ex_opcodes)}):")
            print(f"{'='*60}")
            for i in sorted(ex_opcodes.keys()):
                print(f"  0x{i:04X} = {ex_opcodes[i]}")

    finally:
        CloseHandle(handle)


if __name__ == "__main__":
    main()
