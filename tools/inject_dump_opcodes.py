#!/usr/bin/env python
"""
Дамп таблиц опкодов L2 через DLL injection.

Создаёт маленькую DLL которая:
1. Читает GL2UserPacketTableName/Size из Core.dll (адреса фиксированы, нет ASLR)
2. Пишет результат в файл
3. Выгружается

Затем инжектит её в L2.exe через CreateRemoteThread + LoadLibrary.

Требует: запущенный L2.exe, права администратора.
Использование: python inject_dump_opcodes.py

Авторизованный пентест Innova/4Game, S59 2026-03-18.
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os
import json
import subprocess
import time
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
OUT_FILE = SCRIPT_DIR / "logs" / "l2_opcodes.json"
os.makedirs(OUT_FILE.parent, exist_ok=True)

# Код DLL (MASM-style shellcode подход не нужен — просто напишем C и скомпилируем)
# Но у нас может не быть компилятора. Вместо этого — подход через Python 32-bit.

def find_python32():
    """Поиск 32-bit Python."""
    candidates = [
        r"C:\Python314-32\python.exe",
        r"C:\Python313-32\python.exe",
        r"C:\Python312-32\python.exe",
        r"C:\Python311-32\python.exe",
        r"C:\Python310-32\python.exe",
        r"C:\Python39-32\python.exe",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p

    # Try py launcher
    try:
        out = subprocess.check_output(["py", "-3.14-32", "-c", "import struct; print(struct.calcsize('P'))"],
                                       text=True, stderr=subprocess.DEVNULL).strip()
        if out == "4":
            return "py -3.14-32"
    except Exception:
        pass

    try:
        out = subprocess.check_output(["py", "-3-32", "-c", "import struct; print(struct.calcsize('P'))"],
                                       text=True, stderr=subprocess.DEVNULL).strip()
        if out == "4":
            return "py -3-32"
    except Exception:
        pass

    return None


def find_pid(name="L2.exe"):
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
    return None


# 32-bit скрипт для чтения памяти (будет запущен через 32-bit Python)
DUMP_SCRIPT_32 = r'''
import ctypes, ctypes.wintypes as wt, struct, json, sys, os

pid = int(sys.argv[1])
out_path = sys.argv[2]

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# SeDebugPrivilege
class LUID(ctypes.Structure):
    _fields_ = [("Lo", wt.DWORD), ("Hi", ctypes.c_long)]
class TP(ctypes.Structure):
    _fields_ = [("Count", wt.DWORD), ("Luid", LUID), ("Attrs", wt.DWORD)]
ht = wt.HANDLE()
advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x28, ctypes.byref(ht))
lu = LUID()
advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(lu))
tp = TP(1, lu, 2)
advapi32.AdjustTokenPrivileges(ht, False, ctypes.byref(tp), 0, None, None)
kernel32.CloseHandle(ht)

hp = kernel32.OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ
if not hp:
    print(f"OpenProcess FAILED: {ctypes.get_last_error()}", file=sys.stderr)
    sys.exit(1)

print(f"PID={pid} handle=0x{hp:X}", file=sys.stderr)

CORE = 0x15000000  # Fixed ImageBase, no ASLR

def rpm(addr, sz):
    buf = ctypes.create_string_buffer(sz)
    nr = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(hp, ctypes.c_void_p(addr), buf, sz, ctypes.byref(nr))
    if not ok:
        raise OSError(f"RPM @0x{addr:08X} err={ctypes.get_last_error()}")
    return buf.raw[:nr.value]

def r32(addr):
    return struct.unpack("<I", rpm(addr, 4))[0]

def rwstr(addr, mc=200):
    if not addr: return None
    try: d = rpm(addr, mc*2)
    except: return None
    for i in range(0, len(d)-1, 2):
        if d[i]==0 and d[i+1]==0:
            return d[:i].decode("utf-16-le", errors="replace")
    return d.decode("utf-16-le", errors="replace")

# Verify MZ header
sig = rpm(CORE, 2)
print(f"Core.dll @0x{CORE:08X}: {sig.hex()} ({'MZ OK' if sig==b'MZ' else 'FAIL!'})", file=sys.stderr)

RVA = {
    "GL2UserPacketTableName":   0x001D7F98,
    "GL2UserPacketTableSize":   0x001DD1D8,
    "GL2UserExPacketTableName": 0x001DBEE0,
    "GL2UserExPacketTableSize": 0x001D56B4,
    "GL2PacketCheck":           0x001DD1C4,
    "GL2LastRecvPacketNum":     0x001D5674,
    "GL2LastSendPacketNum":     0x001DD1DC,
}

from datetime import datetime
result = {"ts": datetime.now().isoformat(), "pid": pid, "core_base": f"0x{CORE:08X}", "python_bits": struct.calcsize("P")*8}

# Scalar values
for k in ["GL2PacketCheck", "GL2LastRecvPacketNum", "GL2LastSendPacketNum"]:
    try:
        v = r32(CORE + RVA[k])
        result[k] = v
        print(f"  {k} = {v}", file=sys.stderr)
    except Exception as e:
        print(f"  {k} ERR: {e}", file=sys.stderr)

# Dump tables
for label, nrva, srva in [
    ("main", RVA["GL2UserPacketTableName"], RVA["GL2UserPacketTableSize"]),
    ("ex", RVA["GL2UserExPacketTableName"], RVA["GL2UserExPacketTableSize"])
]:
    try:
        tsize = r32(CORE + srva)
        tptr = r32(CORE + nrva)
        print(f"\n{label}: size={tsize} ptr=0x{tptr:08X}", file=sys.stderr)

        if not tptr or tsize == 0:
            print(f"  NULL — not initialized", file=sys.stderr)
            result[f"{label}_opcodes"] = {}
            continue
        if tsize > 5000: tsize = 5000

        pdata = rpm(tptr, tsize * 4)
        ptrs = struct.unpack(f"<{tsize}I", pdata)
        opcodes = {}
        for i, p in enumerate(ptrs):
            if not p: continue
            nm = rwstr(p, 128)
            if nm: opcodes[i] = nm

        print(f"  {len(opcodes)} opcodes / {tsize} slots", file=sys.stderr)
        for i in sorted(opcodes.keys()):
            fmt = f"0x{i:02X}" if label == "main" else f"0x{i:04X}"
            print(f"    [{fmt}] {opcodes[i]}", file=sys.stderr)

        result[f"{label}_opcodes"] = {
            (f"0x{k:02X}" if label == "main" else f"0x{k:04X}"): v
            for k, v in sorted(opcodes.items())
        }
        result[f"{label}_count"] = len(opcodes)
    except Exception as e:
        print(f"  ERR: {e}", file=sys.stderr)

kernel32.CloseHandle(hp)

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(f"\nSaved to {out_path}", file=sys.stderr)
'''


def main():
    pid = find_pid("L2.exe")
    if not pid:
        print("L2.exe не найден. Запусти клиент.")
        sys.exit(1)
    print(f"L2.exe PID: {pid}")

    # Check current Python bitness
    bits = struct.calcsize("P") * 8
    print(f"Python: {bits}-bit")

    if bits == 32:
        # Мы уже 32-bit — запускаем напрямую
        script_path = tempfile.mktemp(suffix=".py")
        with open(script_path, "w") as f:
            f.write(DUMP_SCRIPT_32)
        os.system(f'python -X utf8 "{script_path}" {pid} "{OUT_FILE}"')
        os.unlink(script_path)
    else:
        # 64-bit Python — ищем 32-bit
        py32 = find_python32()
        if py32:
            print(f"Found 32-bit Python: {py32}")
        else:
            print("32-bit Python не найден!")
            print("Антчит Frost/Teros блокирует ReadProcessMemory из 64-bit процесса.")
            print()
            print("Варианты решения:")
            print("  1. Установить 32-bit Python: python.org → Downloads → Windows x86")
            print("  2. Запустить L2 с -torosNoToros true (без античита)")
            print("  3. Удалить gameShieldDll.dll из Games/system/")
            print("  4. Attach IDA Pro debugger к L2.exe")
            print()
            print("Для варианта 2: добавить в L2.ini в секцию [URL]:")
            print("  GameExtraArgs=-torosNoToros true")

            # Всё же попробуем py launcher
            for ver in ["3.14", "3.13", "3.12", "3.11", "3.10"]:
                try:
                    cmd = f"py -{ver}-32 -c \"import struct; print(struct.calcsize('P'))\""
                    out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
                    if out == "4":
                        py32 = f"py -{ver}-32"
                        print(f"\nНашёл 32-bit Python через py launcher: {py32}")
                        break
                except Exception:
                    continue

            if not py32:
                sys.exit(1)

        script_path = os.path.join(tempfile.gettempdir(), "l2_dump_opcodes_32.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(DUMP_SCRIPT_32)

        if py32.startswith("py "):
            cmd = f'{py32} -X utf8 "{script_path}" {pid} "{OUT_FILE}"'
        else:
            cmd = f'"{py32}" -X utf8 "{script_path}" {pid} "{OUT_FILE}"'

        print(f"Running: {cmd}")
        # Need admin for SeDebugPrivilege
        ret = os.system(cmd)
        if ret != 0:
            print(f"Exit code: {ret}")
            print("Попробуй запустить от администратора.")
        else:
            if OUT_FILE.exists():
                with open(OUT_FILE) as f:
                    data = json.load(f)
                print(f"\nУспех! Найдено опкодов: main={data.get('main_count',0)}, ex={data.get('ex_count',0)}")
                print(f"Результат: {OUT_FILE}")


if __name__ == "__main__":
    main()
