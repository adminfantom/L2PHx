"""Auto-elevating opcode dumper for L2.exe (PID auto-detect).
Requests UAC elevation, reads Core.dll opcode tables + GL2LastSendPacketNum.
Results saved to tools/logs/l2_opcodes_live.json
"""
import ctypes, sys, os, subprocess, json, struct, time

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "l2_opcodes_live.json")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def elevate():
    """Re-run this script as admin."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
    sys.exit(0)

if not is_admin():
    print("Requesting admin elevation...")
    elevate()

# === Now running as admin ===
import ctypes.wintypes as wt

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# Enable SeDebugPrivilege
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

# Find L2.exe
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
    with open(OUT, "w") as f:
        json.dump({"error": "L2.exe not found"}, f)
    input("L2.exe not found. Press Enter...")
    sys.exit(1)

print(f"L2.exe PID: {pid}")

# Find Core.dll base via Toolhelp
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
        ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]

TH32CS_SNAPMODULE = 0x08
TH32CS_SNAPMODULE32 = 0x10

def find_module(pid, name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (-1, 0xFFFFFFFF): return None, None
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
    return None, None

core_base, core_size = find_module(pid, "Core.dll")
print(f"Core.dll: base=0x{core_base:08X} size=0x{core_size:08X}" if core_base else "Core.dll NOT FOUND")

# Open process
hp = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)  # VM_READ | QUERY_INFO
if not hp:
    err = ctypes.get_last_error()
    with open(OUT, "w") as f:
        json.dump({"error": f"OpenProcess failed: {err}", "pid": pid}, f)
    input(f"OpenProcess failed (error {err}). Press Enter...")
    sys.exit(1)

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

base = core_base if core_base else 0x15000000

# Verify MZ
try:
    sig = rpm(base, 2)
    print(f"Core.dll @0x{base:08X}: {sig.hex()} ({'MZ' if sig==b'MZ' else 'FAIL'})")
except Exception as e:
    print(f"Cannot read Core.dll @0x{base:08X}: {e}")
    # Try fixed base
    base = 0x15000000
    try:
        sig = rpm(base, 2)
        print(f"Fallback Core.dll @0x{base:08X}: {sig.hex()}")
    except:
        with open(OUT, "w") as f:
            json.dump({"error": f"Cannot read Core.dll memory", "pid": pid, "tried_base": hex(base)}, f)
        input("Cannot read Core.dll. Press Enter...")
        sys.exit(1)

RVA = {
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

from datetime import datetime
result = {
    "timestamp": datetime.now().isoformat(),
    "pid": pid,
    "core_base": f"0x{base:08X}",
    "python_bits": struct.calcsize("P") * 8,
}

# Read scalar values
for k in ["GL2PacketCheck", "GL2LastRecvPacketNum", "GL2LastSendPacketNum",
           "GL2LastRecvPacketNumEX", "GL2LastSendPacketNumEX"]:
    try:
        v = r32(base + RVA[k])
        result[k] = v
        print(f"  {k} = {v} (0x{v:08X})")
    except Exception as e:
        result[k] = f"ERROR: {e}"
        print(f"  {k} ERR: {e}")

# Dump S2C name table (main)
def dump_table(label, nrva, srva, is_ex=False):
    try:
        tsize = r32(base + srva)
        tptr = r32(base + nrva)
        print(f"\n{label}: size={tsize} ptr=0x{tptr:08X}")
        if not tptr or tsize == 0:
            return {}
        if tsize > 5000: tsize = 5000
        pdata = rpm(tptr, tsize * 4)
        ptrs = struct.unpack(f"<{tsize}I", pdata)
        opcodes = {}
        for i, p in enumerate(ptrs):
            if not p: continue
            nm = rwstr(p, 128)
            if nm:
                opcodes[i] = nm
                fmt = f"0x{i:04X}" if is_ex else f"0x{i:02X}"
                print(f"    [{fmt}] {nm}")
        print(f"  Total: {len(opcodes)} opcodes")
        return opcodes
    except Exception as e:
        print(f"  ERR: {e}")
        return {}

main_opcodes = dump_table("S2C Main Opcodes", RVA["GL2UserPacketTableName"], RVA["GL2UserPacketTableSize"])
ex_opcodes = dump_table("S2C Ex Opcodes", RVA["GL2UserExPacketTableName"], RVA["GL2UserExPacketTableSize"], True)

result["s2c_main_opcodes"] = {f"0x{k:02X}": v for k, v in sorted(main_opcodes.items())}
result["s2c_main_count"] = len(main_opcodes)
result["s2c_ex_opcodes"] = {f"0x{k:04X}": v for k, v in sorted(ex_opcodes.items())}
result["s2c_ex_count"] = len(ex_opcodes)

# === C2S opcode monitoring: read GL2LastSendPacketNum repeatedly ===
print(f"\n{'='*60}")
print("C2S Opcode Monitor (reading GL2LastSendPacketNum every 100ms for 10s)")
print("Move in game / chat / do actions to capture C2S opcodes!")
print(f"{'='*60}")

send_samples = []
last_val = None
for i in range(100):
    try:
        v = r32(base + RVA["GL2LastSendPacketNum"])
        v_ex = r32(base + RVA["GL2LastSendPacketNumEX"])
        ts = time.time()
        if v != last_val:
            print(f"  [{i*0.1:.1f}s] LastSend=0x{v:04X} LastSendEX=0x{v_ex:04X}")
            send_samples.append({"t": round(ts, 3), "send": v, "send_ex": v_ex})
            last_val = v
    except:
        pass
    time.sleep(0.1)

result["c2s_send_samples"] = send_samples

kernel32.CloseHandle(hp)

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(f"\nSaved to: {OUT}")
input("\nDone. Press Enter to close...")
