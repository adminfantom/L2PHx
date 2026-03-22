"""
Dump L2.exe opcode tables via direct NtReadVirtualMemory syscall.
Bypasses usermode hooks by calling ntdll directly.

Also tries MiniDumpWriteDump as alternative.

Usage: Run as Administrator!
  python tools/dump_via_ntdll.py
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import os
import json
import subprocess
from datetime import datetime

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbghelp = None
try:
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
except:
    pass


def find_pid(name="L2.exe"):
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
        err = ctypes.get_last_error()
        kernel32.CloseHandle(ht)
        return err == 0
    except:
        return False


def nt_rpm(handle, addr, size):
    """NtReadVirtualMemory — direct syscall, may bypass usermode hooks."""
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_ulong(0)
    status = ntdll.NtReadVirtualMemory(
        handle,
        ctypes.c_void_p(addr),
        buf,
        size,
        ctypes.byref(bytes_read)
    )
    if status != 0:
        return None, status
    return buf.raw[:bytes_read.value], 0


def rpm_kernel32(handle, addr, size):
    """Standard ReadProcessMemory."""
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    if not ok:
        return None, ctypes.get_last_error()
    return buf.raw[:n.value], 0


def try_minidump(pid, out_path):
    """Try MiniDumpWriteDump from dbghelp.dll."""
    if not dbghelp:
        return False, "dbghelp.dll not loaded"

    handle = kernel32.OpenProcess(0x001F0FFF, False, pid)  # PROCESS_ALL_ACCESS
    if not handle:
        handle = kernel32.OpenProcess(0x0450, False, pid)  # QUERY_INFO|VM_READ|DUP_HANDLE
    if not handle:
        return False, f"OpenProcess failed: {ctypes.get_last_error()}"

    f = kernel32.CreateFileW(
        out_path, 0x40000000, 0, None, 2, 0x80, None  # GENERIC_WRITE, CREATE_ALWAYS
    )
    if f == -1 or f == ctypes.c_void_p(-1).value:
        kernel32.CloseHandle(handle)
        return False, f"CreateFile failed: {ctypes.get_last_error()}"

    # MiniDumpWithFullMemory = 0x00000002
    ok = dbghelp.MiniDumpWriteDump(handle, pid, f, 2, None, None, None)
    err = ctypes.get_last_error()
    kernel32.CloseHandle(f)
    kernel32.CloseHandle(handle)

    if ok:
        sz = os.path.getsize(out_path)
        return True, f"OK, {sz} bytes"
    return False, f"MiniDumpWriteDump failed: err={err}"


def read_wstr_from_data(data, offset, max_chars=256):
    """Read null-terminated UTF-16LE string from raw bytes."""
    result = []
    for i in range(max_chars):
        pos = offset + i * 2
        if pos + 2 > len(data):
            break
        ch = struct.unpack_from("<H", data, pos)[0]
        if ch == 0:
            break
        result.append(chr(ch))
    return ''.join(result)


def main():
    pid = find_pid()
    if not pid:
        print("ERROR: L2.exe not found")
        sys.exit(1)
    print(f"L2.exe PID: {pid}")
    print(f"Python: {'64-bit' if struct.calcsize('P') == 8 else '32-bit'}")

    dp = enable_debug_priv()
    print(f"SeDebugPrivilege: {'OK' if dp else 'FAILED'}")

    # Try multiple OpenProcess flag sets
    handle = None
    for name, flags in [
        ("ALL_ACCESS", 0x001F0FFF),
        ("VM_READ|QUERY|DUP", 0x0450),
        ("VM_READ|QUERY", 0x0410),
        ("VM_READ", 0x0010),
    ]:
        h = kernel32.OpenProcess(flags, False, pid)
        if h:
            print(f"OpenProcess({name}): OK handle=0x{h:X}")
            handle = h
            break
        else:
            print(f"OpenProcess({name}): FAILED err={ctypes.get_last_error()}")

    if not handle:
        print("\nAll OpenProcess attempts failed.")
        print("Trying MiniDump approach...")
        dump_path = "D:\\tmp\\l2_minidump.dmp"
        os.makedirs("D:\\tmp", exist_ok=True)
        ok, msg = try_minidump(pid, dump_path)
        print(f"MiniDump: {msg}")
        if ok:
            print(f"Dump saved to {dump_path}")
            print("Run: python tools/parse_dump_opcodes.py " + dump_path)
        sys.exit(1)

    # Try reading known addresses with BOTH methods
    KNOWN_BASES = {
        "L2.exe": 0x00400000,
        "Core.dll": 0x15000000,
        "NWindow.dll": 0x10000000,
        "Engine.dll": 0x20000000,
    }

    print("\n--- Memory read tests ---")
    working_rpm = None

    for mod_name, base in KNOWN_BASES.items():
        # Method 1: NtReadVirtualMemory
        data1, status1 = nt_rpm(handle, base, 4)
        # Method 2: ReadProcessMemory
        data2, err2 = rpm_kernel32(handle, base, 4)

        nt_ok = data1 is not None and len(data1) >= 2
        k32_ok = data2 is not None and len(data2) >= 2

        mz1 = data1[:2] == b'MZ' if nt_ok else False
        mz2 = data2[:2] == b'MZ' if k32_ok else False

        print(f"  {mod_name:12s} @ 0x{base:08X}:  "
              f"NtRVM={'MZ!' if mz1 else ('OK' if nt_ok else f'FAIL(0x{status1:X})')}  "
              f"RPM={'MZ!' if mz2 else ('OK' if k32_ok else f'FAIL({err2})')}")

        if mz1 and working_rpm is None:
            working_rpm = ("nt", base, mod_name)
        elif mz2 and working_rpm is None:
            working_rpm = ("k32", base, mod_name)

    if not working_rpm:
        print("\nCannot read any module memory. Anti-cheat is blocking all access.")
        print("Trying MiniDump...")
        dump_path = "D:\\tmp\\l2_minidump.dmp"
        os.makedirs("D:\\tmp", exist_ok=True)
        ok, msg = try_minidump(pid, dump_path)
        print(f"MiniDump: {msg}")
        kernel32.CloseHandle(handle)
        sys.exit(1)

    method, found_base, found_mod = working_rpm
    rpm_func = nt_rpm if method == "nt" else rpm_kernel32
    print(f"\nUsing {method} method, found {found_mod} at 0x{found_base:08X}")

    # Now read Core.dll opcode tables
    CORE_BASE = 0x15000000
    test, _ = rpm_func(handle, CORE_BASE, 2)
    if not test or test[:2] != b'MZ':
        print("Core.dll not at expected base 0x15000000")
        kernel32.CloseHandle(handle)
        sys.exit(1)

    # RVAs from Core.dll exports
    RVA_TABLE_SIZE = 0x001DD1D8
    RVA_TABLE_NAME = 0x001D7F98
    RVA_EX_SIZE = 0x001D56B4
    RVA_EX_NAME = 0x001DBEE0

    def read_u32(addr):
        data, _ = rpm_func(handle, addr, 4)
        if not data or len(data) < 4:
            return None
        return struct.unpack("<I", data)[0]

    def read_wstr(addr, max_chars=128):
        if not addr:
            return None
        data, _ = rpm_func(handle, addr, max_chars * 2)
        if not data:
            return None
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                return data[:i].decode("utf-16-le", errors="replace")
        return data.decode("utf-16-le", errors="replace")

    # Read S2C main table
    main_size = read_u32(CORE_BASE + RVA_TABLE_SIZE)
    main_ptr = read_u32(CORE_BASE + RVA_TABLE_NAME)
    print(f"\nS2C main: size={main_size}, ptr=0x{main_ptr:08X}" if main_size else "S2C main: read failed")

    main_opcodes = {}
    if main_size and main_ptr and 0 < main_size <= 512:
        for i in range(main_size):
            str_ptr = read_u32(main_ptr + i * 4)
            if str_ptr:
                name = read_wstr(str_ptr)
                if name:
                    main_opcodes[f"0x{i:02X}"] = name

    # Read S2C ex table
    ex_size = read_u32(CORE_BASE + RVA_EX_SIZE)
    ex_ptr = read_u32(CORE_BASE + RVA_EX_NAME)
    print(f"S2C ex: size={ex_size}, ptr=0x{ex_ptr:08X}" if ex_size else "S2C ex: read failed")

    ex_opcodes = {}
    if ex_size and ex_ptr and 0 < ex_size <= 2000:
        for i in range(ex_size):
            str_ptr = read_u32(ex_ptr + i * 4)
            if str_ptr:
                name = read_wstr(str_ptr)
                if name:
                    ex_opcodes[f"0x{i:04X}"] = name

    print(f"\nDumped: {len(main_opcodes)} S2C main + {len(ex_opcodes)} S2C ex opcodes")

    # Save
    result = {
        "timestamp": datetime.now().isoformat(),
        "pid": pid,
        "method": method,
        "core_base": f"0x{CORE_BASE:08X}",
        "main_table_size": main_size,
        "main_opcodes": main_opcodes,
        "main_count": len(main_opcodes),
        "ex_table_size": ex_size,
        "ex_opcodes": ex_opcodes,
        "ex_count": len(ex_opcodes),
    }

    out_path = os.path.join(os.path.dirname(__file__), "l2_opcodes_ntdll.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Saved to {out_path}")

    # Show first 10
    print("\nFirst 10 S2C main:")
    for k, v in list(main_opcodes.items())[:10]:
        print(f"  {k}: {v}")

    kernel32.CloseHandle(handle)


if __name__ == "__main__":
    main()
