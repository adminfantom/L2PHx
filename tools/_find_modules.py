"""List all modules in L2.exe to find Core.dll base address.
Auto-elevates for admin rights.
"""
import ctypes, sys, os, subprocess, json, struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "l2_modules.json")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
    sys.exit(0)

import ctypes.wintypes as wt
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

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
    input("L2.exe not found"); sys.exit(1)

print(f"L2.exe PID: {pid}")
print(f"Python: {struct.calcsize('P')*8}-bit")

# List modules via Toolhelp
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong),
        ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]

TH32CS_SNAPMODULE = 0x08
TH32CS_SNAPMODULE32 = 0x10

snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
err = ctypes.get_last_error()
print(f"Snapshot handle: {snap}, last error: {err}")

if snap in (-1, 0xFFFFFFFF, None):
    # Try without SNAPMODULE32
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    err = ctypes.get_last_error()
    print(f"Retry without 32-bit flag: handle={snap}, err={err}")

modules = []
me = MODULEENTRY32W()
me.dwSize = ctypes.sizeof(me)

if kernel32.Module32FirstW(snap, ctypes.byref(me)):
    while True:
        m = {
            "name": me.szModule,
            "base": f"0x{me.modBaseAddr:08X}" if me.modBaseAddr else "NULL",
            "size": f"0x{me.modBaseSize:08X}" if me.modBaseSize else "0",
            "path": me.szExePath[:200]
        }
        modules.append(m)
        print(f"  {m['name']:30s} base={m['base']} size={m['size']}")
        if not kernel32.Module32NextW(snap, ctypes.byref(me)):
            break
else:
    err = ctypes.get_last_error()
    print(f"Module32FirstW failed: error {err}")

kernel32.CloseHandle(snap)

# Also try OpenProcess + ReadProcessMemory on the found Core.dll base
hp = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
print(f"\nOpenProcess: handle={hp}, err={ctypes.get_last_error()}")

rpm_tests = {}
if hp:
    for m in modules:
        if "core" in m["name"].lower() or "engine" in m["name"].lower() or "nwindow" in m["name"].lower():
            addr = int(m["base"], 16) if m["base"] != "NULL" else 0
            if addr:
                buf = ctypes.create_string_buffer(4)
                nr = ctypes.c_size_t(0)
                ok = kernel32.ReadProcessMemory(hp, ctypes.c_void_p(addr), buf, 2, ctypes.byref(nr))
                sig = buf.raw[:nr.value].hex() if ok else "FAIL"
                rpm_tests[m["name"]] = {"addr": m["base"], "sig": sig, "ok": bool(ok)}
                print(f"  RPM {m['name']} @{m['base']}: {sig} ({'OK' if ok else f'FAIL err={ctypes.get_last_error()}'})")
    kernel32.CloseHandle(hp)

result = {
    "pid": pid,
    "python_bits": struct.calcsize("P") * 8,
    "modules_count": len(modules),
    "modules": modules,
    "rpm_tests": rpm_tests,
}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(f"\nSaved {len(modules)} modules to: {OUT}")
input("Press Enter to close...")
