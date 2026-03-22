#!/usr/bin/env python
"""
Scan Core.dll .bss section for C2S opcode table.

Strategy: The known S2C tables are at specific RVAs in Core.dll .bss.
We scan the ENTIRE .bss region for arrays of wchar_t* pointers that
look like opcode name tables (many non-null pointers to readable strings).

This will find both S2C (already known) and potentially C2S tables.

Usage: python dump_c2s_opcodes.py
Requires: running L2.exe, admin rights.
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os
import json
import subprocess
from datetime import datetime

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def find_pid(name="L2.exe"):
    try:
        out = subprocess.check_output(["tasklist"], text=True, stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            if name in line:
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


def find_module(pid, name):
    """Find module base in 32-bit process from 64-bit Python."""
    # Method 1: CreateToolhelp32Snapshot with TH32CS_SNAPMODULE32
    snap = kernel32.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
    if snap and snap != ctypes.c_void_p(-1).value and snap != -1:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(me)
        if kernel32.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                if me.szModule.lower() == name.lower():
                    base, size = me.modBaseAddr, me.modBaseSize
                    kernel32.CloseHandle(snap)
                    return base, size
                if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                    break
        kernel32.CloseHandle(snap)

    # Method 2: EnumProcessModulesEx with LIST_MODULES_32BIT (for WoW64)
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        hProc = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not hProc:
            return None, None
        h_mods = (ctypes.c_void_p * 1024)()
        cb_needed = wt.DWORD(0)
        LIST_MODULES_32BIT = 0x01
        ok = psapi.EnumProcessModulesEx(hProc, h_mods, ctypes.sizeof(h_mods),
                                         ctypes.byref(cb_needed), LIST_MODULES_32BIT)
        if ok:
            n_mods = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
            name_buf = ctypes.create_unicode_buffer(260)

            class MODULEINFO(ctypes.Structure):
                _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                            ("SizeOfImage", wt.DWORD),
                            ("EntryPoint", ctypes.c_void_p)]

            mod_info = MODULEINFO()
            for i in range(n_mods):
                h = h_mods[i]
                if not h:
                    continue
                psapi.GetModuleBaseNameW(hProc, ctypes.c_void_p(h), name_buf, 260)
                if name_buf.value.lower() == name.lower():
                    psapi.GetModuleInformation(hProc, ctypes.c_void_p(h),
                                                ctypes.byref(mod_info), ctypes.sizeof(mod_info))
                    kernel32.CloseHandle(hProc)
                    return mod_info.lpBaseOfDll, mod_info.SizeOfImage
        kernel32.CloseHandle(hProc)
    except Exception as e:
        print(f"  EnumProcessModulesEx fallback failed: {e}")

    # Method 3: known base addresses (L2.exe typical layout)
    known_bases = {
        "core.dll": 0x15000000,
        "nwindow.dll": 0x10000000,
        "engine.dll": 0x20000000,
    }
    kb = known_bases.get(name.lower())
    if kb:
        try:
            hProc = kernel32.OpenProcess(0x0010, False, pid)
            if hProc:
                test = rpm(hProc, kb, 2)
                kernel32.CloseHandle(hProc)
                if test and test[:2] == b'MZ':
                    print(f"  {name}: using known base 0x{kb:08X}")
                    return kb, 0x2000000  # estimate 32MB
        except:
            pass

    return None, None


def rpm(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    if not ok:
        return None
    return buf.raw[:n.value]


def read_u32(handle, addr):
    data = rpm(handle, addr, 4)
    if not data or len(data) < 4:
        return None
    return struct.unpack("<I", data)[0]


def read_wstr(handle, addr, max_chars=128):
    if addr == 0 or addr is None:
        return None
    data = rpm(handle, addr, max_chars * 2)
    if not data:
        return None
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i+1] == 0:
            return data[:i].decode("utf-16-le", errors="replace")
    return data.decode("utf-16-le", errors="replace")


def is_valid_name(s):
    """Check if string looks like an L2 packet name."""
    if not s or len(s) < 3 or len(s) > 60:
        return False
    if s[0] not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        return False
    return all(c.isalnum() or c == '_' for c in s)


def scan_for_pointer_arrays(handle, base, size, known_s2c_ptr):
    """Scan .bss for arrays of valid wchar_t* pointers (potential opcode tables)."""
    results = []
    CHUNK = 0x10000  # 64KB chunks
    MIN_VALID = 50   # At least 50 valid string pointers in a row

    print(f"Scanning 0x{base:08X} - 0x{base+size:08X} ({size} bytes)...")

    for offset in range(0, size - 1024, 4):
        if offset % 0x100000 == 0:
            print(f"  Progress: 0x{offset:08X} / 0x{size:08X}")

        addr = base + offset
        # Read 256 dwords (potential pointer array)
        data = rpm(handle, addr, 256 * 4)
        if not data or len(data) < 256 * 4:
            continue

        # Count how many consecutive dwords look like valid pointers
        valid_count = 0
        first_null = -1
        for i in range(256):
            ptr = struct.unpack_from("<I", data, i * 4)[0]
            if ptr == 0:
                if first_null == -1:
                    first_null = i
                continue
            # Check if ptr looks like a valid address (in typical L2 memory range)
            if 0x01000000 <= ptr <= 0x7FFFFFFF:
                valid_count += 1
            else:
                break

        if valid_count >= MIN_VALID:
            # Skip if this is the known S2C table
            if known_s2c_ptr and abs(addr - known_s2c_ptr) < 0x1000:
                continue

            # Try to read strings from first few pointers
            sample_names = []
            for i in range(min(10, 256)):
                ptr = struct.unpack_from("<I", data, i * 4)[0]
                if ptr == 0:
                    sample_names.append(None)
                    continue
                s = read_wstr(handle, ptr, 64)
                if s and is_valid_name(s):
                    sample_names.append(s)
                else:
                    sample_names.append(f"<invalid@0x{ptr:08X}>")

            named = [s for s in sample_names if s and not s.startswith("<")]
            results.append({
                "addr": f"0x{addr:08X}",
                "rva": f"0x{offset:08X}",
                "valid_ptrs": valid_count,
                "sample_names": sample_names,
                "named_count": len(named),
            })
            print(f"  FOUND: 0x{addr:08X} (RVA 0x{offset:08X}) — {valid_count} valid ptrs, "
                  f"names: {named[:5]}")

    return results


def main():
    pid = find_pid()
    if not pid:
        print("ERROR: L2.exe not found")
        sys.exit(1)
    print(f"L2.exe PID: {pid}")

    enable_debug_priv()

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print(f"ERROR: OpenProcess failed: {ctypes.get_last_error()}")
        sys.exit(1)

    # Find modules (pass handle for known-base fallback)
    _rpm_handle_for_find = handle  # used by Method 3

    modules = {}
    for mod_name in ["Core.dll", "NWindow.dll", "Engine.dll"]:
        base, size = find_module(pid, mod_name)
        # Method 3 fallback: try known base with our handle
        if not base:
            known = {"core.dll": 0x15000000, "nwindow.dll": 0x10000000, "engine.dll": 0x20000000}
            kb = known.get(mod_name.lower())
            if kb:
                test = rpm(handle, kb, 2)
                if test and test[:2] == b'MZ':
                    base, size = kb, 0x2000000
                    print(f"  {mod_name}: fallback to known base 0x{kb:08X}")
        if base:
            modules[mod_name] = {"base": base, "size": size}
            print(f"{mod_name}: base=0x{base:08X} size=0x{size:08X}")
        else:
            print(f"{mod_name}: NOT FOUND")

    if "Core.dll" not in modules:
        print("ERROR: Core.dll not found")
        kernel32.CloseHandle(handle)
        sys.exit(1)

    core = modules["Core.dll"]

    # Known S2C table RVAs (for exclusion)
    S2C_TABLE_RVA = 0x001D7F98
    S2C_EX_TABLE_RVA = 0x001DBEE0

    # First read the known S2C tables for comparison
    known_s2c_ptr = read_u32(handle, core["base"] + S2C_TABLE_RVA)
    print(f"\nKnown S2C main table ptr: 0x{known_s2c_ptr:08X}" if known_s2c_ptr else "S2C ptr: NULL")

    # Read first few S2C names for reference
    if known_s2c_ptr:
        print("S2C sample names:")
        for i in range(5):
            ptr = read_u32(handle, known_s2c_ptr + i * 4)
            if ptr:
                s = read_wstr(handle, ptr)
                print(f"  [{i}] = {s}")

    # Now scan the ENTIRE .bss region for OTHER pointer arrays
    # .bss is at the end of Core.dll, typically after .rdata
    # We'll scan from RVA 0x1D0000 to end (where .bss typically lives)
    BSS_START_RVA = 0x001D0000
    BSS_SIZE = min(core["size"] - BSS_START_RVA, 0x100000)  # up to 1MB

    print(f"\nScanning Core.dll .bss from RVA 0x{BSS_START_RVA:08X}, size=0x{BSS_SIZE:08X}")
    candidates = scan_for_pointer_arrays(
        handle, core["base"] + BSS_START_RVA, BSS_SIZE,
        core["base"] + S2C_TABLE_RVA
    )

    # Also scan NWindow.dll if present
    if "NWindow.dll" in modules:
        nw = modules["NWindow.dll"]
        NW_BSS_START = nw["size"] - 0x600000  # last 6MB
        if NW_BSS_START > 0:
            print(f"\nScanning NWindow.dll .bss from offset 0x{NW_BSS_START:08X}")
            nw_candidates = scan_for_pointer_arrays(
                handle, nw["base"] + NW_BSS_START,
                min(0x600000, nw["size"] - NW_BSS_START), None
            )
            candidates.extend(nw_candidates)

    # For each candidate, dump the full table
    full_tables = []
    for c in candidates:
        addr = int(c["addr"], 16)
        # Read up to 512 pointers
        data = rpm(handle, addr, 512 * 4)
        if not data:
            continue
        opcodes = {}
        for i in range(512):
            if i * 4 + 4 > len(data):
                break
            ptr = struct.unpack_from("<I", data, i * 4)[0]
            if ptr == 0:
                continue
            s = read_wstr(handle, ptr, 64)
            if s and is_valid_name(s):
                opcodes[f"0x{i:02X}"] = s
        c["opcodes"] = opcodes
        c["opcode_count"] = len(opcodes)
        full_tables.append(c)
        print(f"\n  Table at {c['addr']}: {len(opcodes)} named opcodes")
        for k, v in list(opcodes.items())[:10]:
            print(f"    {k}: {v}")

    # Save results
    result = {
        "timestamp": datetime.now().isoformat(),
        "pid": pid,
        "modules": {k: f"0x{v['base']:08X}" for k, v in modules.items()},
        "known_s2c_rva": f"0x{S2C_TABLE_RVA:08X}",
        "candidates": full_tables,
    }

    out_path = os.path.join(os.path.dirname(__file__), "c2s_opcode_scan_result.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {out_path}")

    kernel32.CloseHandle(handle)


if __name__ == "__main__":
    main()
