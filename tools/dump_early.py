"""
Early dump: read L2.exe opcode tables BEFORE GameGuard initializes.

Strategy: L2.exe loads Core.dll and fills opcode tables during startup.
GameGuard activates later (after a few seconds). We poll rapidly to
catch the window between table initialization and GameGuard lock.

Usage (as Administrator!):
  python tools/dump_early.py

The script will:
1. Find running L2.exe (or wait for it to appear)
2. Poll every 500ms trying to read Core.dll memory
3. As soon as read succeeds, dump opcode tables
4. Save to tools/l2_opcodes_early.json
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os
import json
import time
import subprocess
from datetime import datetime

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")


def find_pid(name="L2.exe"):
    try:
        out = subprocess.check_output(
            ["wmic", "process", "where", f"name='{name}'", "get", "processid"],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.strip().split("\n"):
            line = line.strip()
            if line.isdigit():
                return int(line)
    except:
        pass
    try:
        out = subprocess.check_output(["tasklist"], text=True, stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            if name.lower() in line.lower():
                for p in line.split():
                    if p.isdigit():
                        return int(p)
    except:
        pass
    return None


def enable_debug_priv():
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        class LUID(ctypes.Structure):
            _fields_ = [("Lo", wt.DWORD), ("Hi", wt.LONG)]
        class TP(ctypes.Structure):
            _fields_ = [("Cnt", wt.DWORD), ("L", LUID), ("A", wt.DWORD)]
        ht = wt.HANDLE()
        advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x28, ctypes.byref(ht))
        lu = LUID()
        advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(lu))
        tp = TP(1, lu, 2)
        advapi32.AdjustTokenPrivileges(ht, False, ctypes.byref(tp), 0, None, None)
        kernel32.CloseHandle(ht)
        return True
    except:
        return False


def try_read(handle, addr, size):
    """Try reading with NtReadVirtualMemory first, fallback to RPM."""
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_ulong(0)
    status = ntdll.NtReadVirtualMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    if status == 0 and n.value > 0:
        return buf.raw[:n.value]
    # Fallback
    n2 = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n2))
    if ok and n2.value > 0:
        return buf.raw[:n2.value]
    return None


def read_u32(handle, addr):
    data = try_read(handle, addr, 4)
    if not data or len(data) < 4:
        return None
    return struct.unpack("<I", data)[0]


def read_wstr(handle, addr, max_chars=128):
    if not addr:
        return None
    data = try_read(handle, addr, max_chars * 2)
    if not data:
        return None
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            return data[:i].decode("utf-16-le", errors="replace")
    return data.decode("utf-16-le", errors="replace")


def dump_table(handle, base, size_rva, name_rva, label):
    """Dump an opcode table from Core.dll."""
    table_size = read_u32(handle, base + size_rva)
    if not table_size or table_size > 2000:
        return None, f"bad size: {table_size}"

    table_ptr = read_u32(handle, base + name_rva)
    if not table_ptr:
        return None, "null ptr"

    opcodes = {}
    for i in range(table_size):
        str_ptr = read_u32(handle, table_ptr + i * 4)
        if str_ptr:
            name = read_wstr(handle, str_ptr)
            if name and len(name) >= 2:
                opcodes[f"0x{i:02X}" if table_size <= 256 else f"0x{i:04X}"] = name

    return opcodes, f"{len(opcodes)}/{table_size} names"


def main():
    print("=" * 60)
    print("L2 Early Opcode Dump — BEFORE GameGuard")
    print("=" * 60)
    print("Run this as Administrator!")
    print()

    dp = enable_debug_priv()
    print(f"SeDebugPrivilege: {'OK' if dp else 'FAILED — NOT ADMIN!'}")
    if not dp:
        print("ERROR: Must run as Administrator. Exiting.")
        sys.exit(1)

    CORE_BASE = 0x15000000
    RVA_TABLE_SIZE = 0x001DD1D8
    RVA_TABLE_NAME = 0x001D7F98
    RVA_EX_SIZE = 0x001D56B4
    RVA_EX_NAME = 0x001DBEE0

    print("\nWaiting for L2.exe...")
    print("(If L2.exe is already running, will try immediately)")
    print()

    max_attempts = 120  # 60 seconds
    attempt = 0

    while attempt < max_attempts:
        pid = find_pid()
        if not pid:
            if attempt % 4 == 0:
                sys.stdout.write(f"\r  Waiting for L2.exe... ({attempt // 2}s)")
                sys.stdout.flush()
            time.sleep(0.5)
            attempt += 1
            continue

        # Found L2.exe — try to read
        handle = kernel32.OpenProcess(0x001F0FFF, False, pid)
        if not handle:
            handle = kernel32.OpenProcess(0x0410, False, pid)
        if not handle:
            if attempt % 4 == 0:
                sys.stdout.write(f"\r  L2.exe PID={pid}, OpenProcess failed, retrying... ({attempt // 2}s)")
                sys.stdout.flush()
            time.sleep(0.5)
            attempt += 1
            continue

        # Try reading Core.dll MZ header
        test = try_read(handle, CORE_BASE, 2)
        if not test or test[:2] != b'MZ':
            kernel32.CloseHandle(handle)
            if attempt % 4 == 0:
                sys.stdout.write(f"\r  L2.exe PID={pid}, Core.dll not readable yet... ({attempt // 2}s)")
                sys.stdout.flush()
            time.sleep(0.5)
            attempt += 1
            continue

        # CAN READ! Try opcode tables
        print(f"\n\n  Core.dll READABLE at attempt {attempt} ({attempt*0.5:.1f}s)!")
        print(f"  L2.exe PID: {pid}")

        # Check if tables are initialized (size > 0)
        main_size = read_u32(handle, CORE_BASE + RVA_TABLE_SIZE)
        if not main_size or main_size == 0:
            kernel32.CloseHandle(handle)
            sys.stdout.write(f"\r  Tables not initialized yet (size=0), retrying...")
            sys.stdout.flush()
            time.sleep(0.5)
            attempt += 1
            continue

        print(f"  Main table size: {main_size}")

        # DUMP!
        main_opcodes, main_msg = dump_table(handle, CORE_BASE, RVA_TABLE_SIZE, RVA_TABLE_NAME, "S2C main")
        print(f"  S2C main: {main_msg}")

        ex_opcodes, ex_msg = dump_table(handle, CORE_BASE, RVA_EX_SIZE, RVA_EX_NAME, "S2C ex")
        print(f"  S2C ex: {ex_msg}")

        # Also scan nearby for C2S tables (within 0x10000 of known tables)
        # Scan .bss region for other pointer arrays
        c2s_candidates = []
        scan_start = 0x001D0000
        scan_end = 0x001E0000
        print(f"\n  Scanning for C2S tables in RVA 0x{scan_start:08X}-0x{scan_end:08X}...")

        for rva in range(scan_start, scan_end, 4):
            # Skip known S2C table locations
            if abs(rva - RVA_TABLE_NAME) < 8 or abs(rva - RVA_EX_NAME) < 8:
                continue
            val = read_u32(handle, CORE_BASE + rva)
            if not val or val < 0x01000000 or val > 0x7FFFFFFF:
                continue
            # This could be a pointer — check if it points to an array of string pointers
            first_ptr = read_u32(handle, val)
            if not first_ptr or first_ptr < 0x01000000 or first_ptr > 0x7FFFFFFF:
                continue
            # Try reading as string
            test_str = read_wstr(handle, first_ptr, 32)
            if test_str and len(test_str) >= 3 and test_str[0].isupper():
                # Check next few entries
                valid = 0
                for j in range(min(10, 256)):
                    sp = read_u32(handle, val + j * 4)
                    if sp:
                        s = read_wstr(handle, sp, 32)
                        if s and len(s) >= 2:
                            valid += 1
                if valid >= 5:
                    c2s_candidates.append({
                        "rva": f"0x{rva:08X}",
                        "ptr": f"0x{val:08X}",
                        "first_name": test_str,
                        "valid_count": valid,
                    })
                    print(f"    CANDIDATE at RVA 0x{rva:08X}: ptr=0x{val:08X} first={test_str} valid={valid}")

        kernel32.CloseHandle(handle)

        # Save results
        result = {
            "timestamp": datetime.now().isoformat(),
            "pid": pid,
            "attempt": attempt,
            "seconds": attempt * 0.5,
            "core_base": f"0x{CORE_BASE:08X}",
            "main_opcodes": main_opcodes or {},
            "main_count": len(main_opcodes) if main_opcodes else 0,
            "ex_opcodes": ex_opcodes or {},
            "ex_count": len(ex_opcodes) if ex_opcodes else 0,
            "c2s_candidates": c2s_candidates,
        }

        out_path = os.path.join(os.path.dirname(__file__), "l2_opcodes_early.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"\n  Saved to {out_path}")
        print(f"\n  Summary: {len(main_opcodes or {})} S2C main + {len(ex_opcodes or {})} S2C ex")
        if main_opcodes:
            print("  First 5 S2C main:")
            for k, v in list(main_opcodes.items())[:5]:
                print(f"    {k}: {v}")
        if c2s_candidates:
            print(f"  Found {len(c2s_candidates)} C2S table candidates!")
        else:
            print("  No C2S table found in .bss scan region")

        return

    print("\n\nTIMEOUT: Could not read Core.dll in 60 seconds.")
    print("GameGuard may have blocked access before tables were initialized.")
    print("Try closing L2.exe, running this script, then starting L2.exe.")


if __name__ == "__main__":
    main()
