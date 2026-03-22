"""Inject a small stub into L2.exe that reads GL2LastSendPacketNum
and opcode tables from within the process, writing results to a shared file.

Uses WriteProcessMemory + CreateRemoteThread to bypass anticheat RPM hooks.
The injected code runs INSIDE L2.exe where reading own memory is not blocked.

Auto-elevates for admin rights. Must run from 32-bit context for WoW64 compatibility.
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

# This script must be run from 32-bit context.
# If 64-bit, re-launch via 32-bit PowerShell

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "l2_opcodes_live.json")
SHARED_FILE = os.path.join(tempfile.gettempdir(), "l2_opcode_dump.bin")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    print("Requesting admin...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
    sys.exit(0)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Enable SeDebugPrivilege
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
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

# Find L2.exe PID
def find_pid():
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq L2.exe", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL)
        for line in out.decode("cp1251", errors="replace").split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == "l2.exe":
                return int(parts[1])
    except: pass
    return None

pid = find_pid()
if not pid:
    with open(OUT, "w") as f: json.dump({"error": "L2.exe not found"}, f)
    input("L2.exe not found. Press Enter..."); sys.exit(1)

print(f"L2.exe PID: {pid}")
print(f"Python bits: {struct.calcsize('P')*8}")

CORE_BASE = 0x15000000  # Fixed, no ASLR

# Core.dll export RVAs
RVAS = {
    "GL2UserPacketTableName":   0x001D7F98,
    "GL2UserPacketTableSize":   0x001DD1D8,
    "GL2UserExPacketTableName": 0x001DBEE0,
    "GL2UserExPacketTableSize": 0x001D56B4,
    "GL2PacketCheck":           0x001DD1C4,
    "GL2LastRecvPacketNum":     0x001D5674,
    "GL2LastSendPacketNum":     0x001DD1DC,
    "GL2LastRecvPacketNumEX":   0x001D7FA4,
    "GL2LastSendPacketNumEX":   0x001D81E8,
}

# Strategy: Use CreateRemoteThread to call a Windows API function
# inside L2.exe. We'll use the LoadLibrary approach but instead of
# a DLL, we'll inject shellcode that:
# 1. Reads specific memory addresses
# 2. Writes results to a file using CreateFileA/WriteFile

# Open process with all needed rights
PROCESS_ALL_ACCESS = 0x001F0FFF
hp = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
err = ctypes.get_last_error()
print(f"OpenProcess: handle={hp}, err={err}")

if not hp:
    # Try with minimal rights
    hp = kernel32.OpenProcess(
        0x0010 | 0x0020 | 0x0008 | 0x0400,  # VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFO
        False, pid)
    err = ctypes.get_last_error()
    print(f"OpenProcess (minimal): handle={hp}, err={err}")

if not hp:
    with open(OUT, "w") as f:
        json.dump({"error": f"OpenProcess failed: {err}", "pid": pid}, f)
    input(f"OpenProcess failed (error {err}). Press Enter...")
    sys.exit(1)

# Try ReadProcessMemory first (might work with admin+SeDebugPrivilege from 32-bit)
def rpm(addr, size):
    buf = ctypes.create_string_buffer(size)
    nr = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(hp, ctypes.c_void_p(addr), buf, size, ctypes.byref(nr))
    if not ok:
        return None
    return buf.raw[:nr.value]

# Test RPM
print(f"\nTesting ReadProcessMemory from 32-bit admin context...")
sig = rpm(CORE_BASE, 4)
if sig:
    print(f"Core.dll @0x{CORE_BASE:08X}: {sig.hex()} ({'MZ!' if sig[:2]==b'MZ' else 'not MZ'})")

    if sig[:2] == b'MZ':
        print("RPM WORKS from 32-bit admin! Reading tables...")

        def r32(addr):
            d = rpm(addr, 4)
            return struct.unpack("<I", d)[0] if d else -1

        def rwstr(addr, mc=200):
            if not addr: return None
            try:
                d = rpm(addr, mc*2)
                if not d: return None
            except: return None
            for i in range(0, len(d)-1, 2):
                if d[i]==0 and d[i+1]==0:
                    return d[:i].decode("utf-16-le", errors="replace")
            return d.decode("utf-16-le", errors="replace")

        result = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "pid": pid,
            "core_base": f"0x{CORE_BASE:08X}",
            "python_bits": struct.calcsize("P") * 8,
            "rpm_works": True,
        }

        # Read scalars
        for name, rva in RVAS.items():
            v = r32(CORE_BASE + rva)
            result[name] = v
            print(f"  {name} = {v} (0x{v:08X})")

        # Dump tables
        def dump_tbl(label, nrva, srva, is_ex=False):
            sz = r32(CORE_BASE + srva)
            ptr = r32(CORE_BASE + nrva)
            print(f"\n{label}: size={sz} ptr=0x{ptr:08X}")
            if not ptr or sz <= 0: return {}
            if sz > 5000: sz = 5000
            pd = rpm(ptr, sz * 4)
            if not pd: return {}
            ops = {}
            for i in range(sz):
                p = struct.unpack_from("<I", pd, i*4)[0]
                if not p: continue
                nm = rwstr(p, 128)
                if nm:
                    fmt = f"0x{i:04X}" if is_ex else f"0x{i:02X}"
                    ops[fmt] = nm
                    print(f"    [{fmt}] {nm}")
            print(f"  Total: {len(ops)}")
            return ops

        main_ops = dump_tbl("S2C Main", RVAS["GL2UserPacketTableName"], RVAS["GL2UserPacketTableSize"])
        ex_ops = dump_tbl("S2C Ex", RVAS["GL2UserExPacketTableName"], RVAS["GL2UserExPacketTableSize"], True)

        result["s2c_main_opcodes"] = main_ops
        result["s2c_main_count"] = len(main_ops)
        result["s2c_ex_opcodes"] = ex_ops
        result["s2c_ex_count"] = len(ex_ops)

        # Monitor GL2LastSendPacketNum
        print("\nMonitoring GL2LastSendPacketNum (10s)...")
        samples = []
        last = -1
        for i in range(100):
            v = r32(CORE_BASE + RVAS["GL2LastSendPacketNum"])
            vex = r32(CORE_BASE + RVAS["GL2LastSendPacketNumEX"])
            if v != last:
                ts = time.strftime("%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}"
                print(f"  [{ts}] Send=0x{v:04X} SendEX=0x{vex:04X}")
                samples.append({"ts": ts, "send": v, "send_hex": f"0x{v:04X}", "send_ex": vex})
                last = v
            time.sleep(0.1)
        result["c2s_send_samples"] = samples

        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\nSaved to: {OUT}")
    else:
        print("Core.dll signature mismatch!")
        with open(OUT, "w") as f:
            json.dump({"error": "Core.dll MZ mismatch", "sig": sig.hex()}, f)
else:
    print(f"RPM FAILED (error {ctypes.get_last_error()})")
    print("Anticheat blocks ReadProcessMemory even from 32-bit admin.")

    # Fallback: try VirtualQueryEx to verify address range exists
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
        ]

    mbi = MEMORY_BASIC_INFORMATION()
    sz = kernel32.VirtualQueryEx(hp, ctypes.c_void_p(CORE_BASE), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if sz:
        print(f"VirtualQueryEx OK: base=0x{mbi.BaseAddress or 0:08X} "
              f"alloc=0x{mbi.AllocationBase or 0:08X} "
              f"size=0x{mbi.RegionSize:08X} state=0x{mbi.State:X} protect=0x{mbi.Protect:X}")
    else:
        print(f"VirtualQueryEx FAILED: {ctypes.get_last_error()}")

    with open(OUT, "w") as f:
        json.dump({"error": "RPM blocked by anticheat",
                    "pid": pid, "tried_32bit_admin": True}, f)

kernel32.CloseHandle(hp)
input("\nPress Enter to close...")
