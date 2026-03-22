"""
Dump L2.exe opcode tables via process cloning (PssCaptureSnapshot).

GameGuard blocks ReadProcessMemory on the original L2.exe process.
PssCaptureSnapshot creates a COW clone that may not be protected.

Also tries: direct NtQueryVirtualMemory + manual page walking.

Usage: Run as Administrator!
  python tools/dump_clone.py
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
ntdll = ctypes.WinDLL("ntdll")

# PssCaptureSnapshot flags
PSS_CAPTURE_VA_CLONE = 0x00000001
PSS_CAPTURE_VA_SPACE = 0x00000002
PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00000004
PSS_CAPTURE_HANDLES = 0x00000020
PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def find_pid():
    try:
        out = subprocess.check_output(["tasklist"], text=True, stderr=subprocess.DEVNULL)
        for line in out.split("\n"):
            if "L2.exe" in line:
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
        err = ctypes.get_last_error()
        kernel32.CloseHandle(ht)
        return err == 0
    except:
        return False


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
    if not addr:
        return None
    data = rpm(handle, addr, max_chars * 2)
    if not data:
        return None
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            return data[:i].decode("utf-16-le", errors="replace")
    return data.decode("utf-16-le", errors="replace")


def try_clone_dump(pid):
    """Try PssCaptureSnapshot to clone the process, then read from clone."""
    print("\n--- Method 1: PssCaptureSnapshot (process clone) ---")

    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print(f"  OpenProcess failed: {ctypes.get_last_error()}")
        return None

    print(f"  Process handle: 0x{handle:X}")

    # PssCaptureSnapshot
    try:
        PssCaptureSnapshot = kernel32.PssCaptureSnapshot
        PssCaptureSnapshot.restype = wt.DWORD
        PssCaptureSnapshot.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    except AttributeError:
        print("  PssCaptureSnapshot not available (requires Windows 8.1+)")
        kernel32.CloseHandle(handle)
        return None

    snapshot = wt.HANDLE()
    flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE
    result = PssCaptureSnapshot(handle, flags, 0, ctypes.byref(snapshot))

    if result != 0:
        print(f"  PssCaptureSnapshot failed: error={result} (0x{result:08X})")
        # Try with fewer flags
        result = PssCaptureSnapshot(handle, PSS_CAPTURE_VA_CLONE, 0, ctypes.byref(snapshot))
        if result != 0:
            print(f"  PssCaptureSnapshot (minimal) failed: error={result}")
            kernel32.CloseHandle(handle)
            return None

    print(f"  Snapshot created: handle=0x{snapshot.value:X}")

    # The snapshot handle can be used with ReadProcessMemory!
    # Try reading Core.dll
    CORE_BASE = 0x15000000
    test = rpm(snapshot.value, CORE_BASE, 4)
    if test:
        print(f"  RPM from clone at 0x{CORE_BASE:08X}: {test.hex()} {'(MZ!)' if test[:2] == b'MZ' else ''}")
        if test[:2] == b'MZ':
            kernel32.CloseHandle(handle)
            return snapshot.value
    else:
        print(f"  RPM from clone failed: {ctypes.get_last_error()}")

    # Clean up snapshot
    try:
        kernel32.PssFreeSnapshot(kernel32.GetCurrentProcess(), snapshot)
    except:
        pass
    kernel32.CloseHandle(handle)
    return None


def try_debug_attach(pid):
    """Try DebugActiveProcess to attach as debugger, then read memory."""
    print("\n--- Method 2: DebugActiveProcess ---")

    ok = kernel32.DebugActiveProcess(pid)
    if not ok:
        print(f"  DebugActiveProcess failed: {ctypes.get_last_error()}")
        return None

    print("  Attached as debugger!")

    # Now open with full access
    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        print(f"  OpenProcess failed even as debugger: {ctypes.get_last_error()}")
        kernel32.DebugActiveProcessStop(pid)
        return None

    # Try reading
    CORE_BASE = 0x15000000
    test = rpm(handle, CORE_BASE, 4)
    if test:
        print(f"  RPM as debugger at 0x{CORE_BASE:08X}: {test.hex()} {'(MZ!)' if test[:2] == b'MZ' else ''}")
        if test[:2] == b'MZ':
            # DON'T detach yet — caller will read tables
            return handle, pid  # return handle + pid for cleanup
    else:
        print(f"  RPM as debugger failed: {ctypes.get_last_error()}")

    kernel32.DebugActiveProcessStop(pid)
    kernel32.CloseHandle(handle)
    return None


def try_suspend_read(pid):
    """Suspend all threads, then try reading. Sometimes works if anti-cheat
    is thread-based rather than kernel-driver based."""
    print("\n--- Method 3: NtSuspendProcess + read ---")

    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        handle = kernel32.OpenProcess(0x0800 | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        print(f"  OpenProcess failed: {ctypes.get_last_error()}")
        return None

    # NtSuspendProcess
    status = ntdll.NtSuspendProcess(handle)
    if status != 0:
        print(f"  NtSuspendProcess failed: 0x{status:08X}")
        kernel32.CloseHandle(handle)
        return None

    print("  Process suspended!")

    # Try reading
    CORE_BASE = 0x15000000
    test = rpm(handle, CORE_BASE, 4)
    if test:
        print(f"  RPM while suspended at 0x{CORE_BASE:08X}: {test.hex()}")
        if test[:2] == b'MZ':
            print("  SUCCESS! Core.dll readable while suspended!")
            return handle, pid  # caller must resume
    else:
        print(f"  RPM while suspended failed: {ctypes.get_last_error()}")

    # Resume
    ntdll.NtResumeProcess(handle)
    print("  Process resumed")
    kernel32.CloseHandle(handle)
    return None


def dump_tables(handle):
    """Dump S2C opcode tables from Core.dll."""
    CORE_BASE = 0x15000000
    RVA_TABLE_SIZE = 0x001DD1D8
    RVA_TABLE_NAME = 0x001D7F98
    RVA_EX_SIZE = 0x001D56B4
    RVA_EX_NAME = 0x001DBEE0

    main_size = read_u32(handle, CORE_BASE + RVA_TABLE_SIZE)
    main_ptr = read_u32(handle, CORE_BASE + RVA_TABLE_NAME)
    print(f"\n  S2C main: size={main_size}, ptr=0x{main_ptr:08X}" if main_size else "\n  S2C main: failed")

    main_opcodes = {}
    if main_size and main_ptr and 0 < main_size <= 512:
        for i in range(main_size):
            str_ptr = read_u32(handle, main_ptr + i * 4)
            if str_ptr:
                name = read_wstr(handle, str_ptr)
                if name and len(name) >= 2:
                    main_opcodes[f"0x{i:02X}"] = name

    ex_size = read_u32(handle, CORE_BASE + RVA_EX_SIZE)
    ex_ptr = read_u32(handle, CORE_BASE + RVA_EX_NAME)
    print(f"  S2C ex: size={ex_size}, ptr=0x{ex_ptr:08X}" if ex_size else "  S2C ex: failed")

    ex_opcodes = {}
    if ex_size and ex_ptr and 0 < ex_size <= 2000:
        for i in range(ex_size):
            str_ptr = read_u32(handle, ex_ptr + i * 4)
            if str_ptr:
                name = read_wstr(handle, str_ptr)
                if name and len(name) >= 2:
                    ex_opcodes[f"0x{i:04X}"] = name

    # Scan nearby .bss for unknown tables (potential C2S)
    print(f"\n  Scanning .bss for additional tables...")
    extra_tables = []
    for rva in range(0x001D0000, 0x001E2000, 4):
        if abs(rva - RVA_TABLE_NAME) < 8 or abs(rva - RVA_EX_NAME) < 8:
            continue
        val = read_u32(handle, CORE_BASE + rva)
        if not val or val < 0x10000000 or val > 0x7FFFFFFF:
            continue
        # Check if array of valid string pointers
        valid = 0
        first_name = None
        for j in range(10):
            sp = read_u32(handle, val + j * 4)
            if sp and 0x10000000 <= sp <= 0x7FFFFFFF:
                s = read_wstr(handle, sp, 32)
                if s and len(s) >= 2 and s[0].isalpha():
                    valid += 1
                    if not first_name:
                        first_name = s
        if valid >= 5:
            extra_tables.append({"rva": f"0x{rva:08X}", "ptr": f"0x{val:08X}",
                                  "first": first_name, "valid": valid})
            print(f"    TABLE at RVA 0x{rva:08X}: ptr=0x{val:08X} first='{first_name}' valid={valid}")

    return main_opcodes, ex_opcodes, extra_tables


def main():
    pid = find_pid()
    if not pid:
        print("ERROR: L2.exe not found")
        sys.exit(1)

    print(f"L2.exe PID: {pid}")
    dp = enable_debug_priv()
    print(f"SeDebugPrivilege: {'OK' if dp else 'FAILED'}")

    handle = None
    cleanup_pid = None
    method = None

    # Try Method 1: Clone
    result = try_clone_dump(pid)
    if result:
        handle = result
        method = "clone"

    # Try Method 2: Debug attach
    if not handle:
        result = try_debug_attach(pid)
        if result:
            handle, cleanup_pid = result
            method = "debug"

    # Try Method 3: Suspend
    if not handle:
        result = try_suspend_read(pid)
        if result:
            handle, cleanup_pid = result
            method = "suspend"

    if not handle:
        print("\n\nALL METHODS FAILED. GameGuard kernel driver blocks all access.")
        print("\nAlternatives:")
        print("  1. Use Cheat Engine (has kernel driver bypass)")
        print("  2. Use Process Hacker / System Informer")
        print("  3. Dump before GameGuard via boot-time injection")
        sys.exit(1)

    print(f"\n  Using method: {method}")
    main_opcodes, ex_opcodes, extra = dump_tables(handle)

    # Cleanup
    if method == "debug" and cleanup_pid:
        kernel32.DebugActiveProcessStop(cleanup_pid)
        print("  Debugger detached")
    elif method == "suspend" and cleanup_pid:
        ntdll.NtResumeProcess(handle)
        print("  Process resumed")

    kernel32.CloseHandle(handle)

    # Save
    result = {
        "timestamp": datetime.now().isoformat(),
        "pid": pid, "method": method,
        "main_opcodes": main_opcodes, "main_count": len(main_opcodes),
        "ex_opcodes": ex_opcodes, "ex_count": len(ex_opcodes),
        "extra_tables": extra,
    }

    out_path = os.path.join(os.path.dirname(__file__), "l2_opcodes_clone.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nSaved to {out_path}")
    print(f"S2C main: {len(main_opcodes)} opcodes")
    print(f"S2C ex: {len(ex_opcodes)} opcodes")
    print(f"Extra tables: {len(extra)}")

    if main_opcodes:
        print("\nFirst 10 S2C main:")
        for k, v in list(main_opcodes.items())[:10]:
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
