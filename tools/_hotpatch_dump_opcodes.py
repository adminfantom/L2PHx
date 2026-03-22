"""Hot-patch: dump L2 opcode tables from L2.exe memory.

Runs inside the proxy process (admin), reads L2.exe memory via ctypes.
Uses CreateToolhelp32Snapshot to find Core.dll in 32-bit L2.exe.
"""
import os
import ctypes
import ctypes.wintypes as wt
import struct
import json
import subprocess
from datetime import datetime

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\l2_opcodes_live.json"
os.makedirs(os.path.dirname(out), exist_ok=True)

def _run():
    result = {"timestamp": datetime.now().isoformat()}

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # Find L2.exe PID
        pid = None
        try:
            o = subprocess.check_output(["tasklist"], text=True, stderr=subprocess.DEVNULL)
            for line in o.split("\n"):
                if "L2.exe" in line:
                    parts = line.split()
                    for p in parts:
                        if p.isdigit():
                            pid = int(p)
                            break
                    if pid:
                        break
        except:
            pass

        if not pid:
            result["error"] = "L2.exe not found"
            with open(out, "w") as f:
                json.dump(result, f, indent=2)
            return

        result["pid"] = pid

        # Enable SeDebugPrivilege
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            class LUID(ctypes.Structure):
                _fields_ = [("Lo", wt.DWORD), ("Hi", wt.LONG)]
            class TP(ctypes.Structure):
                _fields_ = [("Count", wt.DWORD), ("Luid", LUID), ("Attr", wt.DWORD)]
            ht = wt.HANDLE()
            advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0028, ctypes.byref(ht))
            luid = LUID()
            advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
            tp = TP(1, luid, 2)
            advapi32.AdjustTokenPrivileges(ht, False, ctypes.byref(tp), 0, None, None)
            kernel32.CloseHandle(ht)
            result["debug_priv"] = True
        except:
            result["debug_priv"] = False

        # Open L2.exe
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        hProc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not hProc:
            result["error"] = f"OpenProcess failed: {ctypes.get_last_error()}"
            with open(out, "w") as f:
                json.dump(result, f, indent=2)
            return

        def rpm(addr, size):
            buf = ctypes.create_string_buffer(size)
            n = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
            if not ok:
                raise OSError(f"RPM fail 0x{addr:08X}: err {ctypes.get_last_error()}")
            return buf.raw[:n.value]

        def read_u32(addr):
            return struct.unpack("<I", rpm(addr, 4))[0]

        def read_wstr(addr, mc=256):
            if addr == 0: return None
            try:
                d = rpm(addr, mc*2)
            except:
                return None
            for i in range(0, len(d)-1, 2):
                if d[i]==0 and d[i+1]==0:
                    return d[:i].decode("utf-16-le", errors="replace")
            return d.decode("utf-16-le", errors="replace")

        # Find Core.dll via toolhelp
        class ME32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260),
            ]

        TH32CS_SNAPMODULE = 0x08
        TH32CS_SNAPMODULE32 = 0x10
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)

        core_base = None
        core_size = None

        if snap != ctypes.c_void_p(-1).value and snap != -1:
            me = ME32()
            me.dwSize = ctypes.sizeof(me)
            if kernel32.Module32FirstW(snap, ctypes.byref(me)):
                while True:
                    modname = me.szModule.lower()
                    if modname == "core.dll":
                        core_base = me.modBaseAddr
                        core_size = me.modBaseSize
                        break
                    if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                        break
            kernel32.CloseHandle(snap)
        else:
            result["toolhelp_error"] = ctypes.get_last_error()

        # Fallback: try known base 0x15000000
        if core_base is None:
            try:
                test = rpm(0x15000000, 2)
                if test[:2] == b'MZ':
                    core_base = 0x15000000
                    core_size = 0x300000  # ~3MB estimate
                    result["core_base_source"] = "fallback_0x15000000"
            except:
                pass

        if core_base is None:
            result["error"] = "Core.dll not found"
            with open(out, "w") as f:
                json.dump(result, f, indent=2)
            kernel32.CloseHandle(hProc)
            return

        result["core_dll_base"] = f"0x{core_base:08X}"
        result["core_dll_size"] = f"0x{core_size:08X}" if core_size else "unknown"

        # RVAs from PE exports
        RVA_TABLE_SIZE = 0x001DD1D8
        RVA_TABLE_NAME = 0x001D7F98
        RVA_EX_SIZE = 0x001D56B4
        RVA_EX_NAME = 0x001DBEE0
        RVA_USE_KEY_CRYPT = 0x001D8254

        # Read values
        try:
            use_key_crypt = read_u32(core_base + RVA_USE_KEY_CRYPT)
            result["GL2UseKeyCrypt"] = use_key_crypt
        except:
            result["GL2UseKeyCrypt"] = "read_error"

        try:
            main_size = read_u32(core_base + RVA_TABLE_SIZE)
            result["main_table_size"] = main_size
        except Exception as e:
            result["main_table_error"] = str(e)
            main_size = 0

        try:
            main_ptr = read_u32(core_base + RVA_TABLE_NAME)
            result["main_table_ptr"] = f"0x{main_ptr:08X}"
        except:
            main_ptr = 0

        # Dump main opcodes
        main_opcodes = {}
        if main_ptr and 0 < main_size < 500:
            try:
                ptr_data = rpm(main_ptr, main_size * 4)
                for i in range(main_size):
                    sp = struct.unpack_from("<I", ptr_data, i*4)[0]
                    if sp:
                        name = read_wstr(sp, 128)
                        if name:
                            main_opcodes[f"0x{i:02X}"] = name
            except Exception as e:
                result["main_read_error"] = str(e)

        result["main_opcodes"] = main_opcodes
        result["main_count"] = len(main_opcodes)

        # Dump Ex opcodes
        try:
            ex_size = read_u32(core_base + RVA_EX_SIZE)
            result["ex_table_size"] = ex_size
        except:
            ex_size = 0

        try:
            ex_ptr = read_u32(core_base + RVA_EX_NAME)
            result["ex_table_ptr"] = f"0x{ex_ptr:08X}"
        except:
            ex_ptr = 0

        ex_opcodes = {}
        if ex_ptr and 0 < ex_size < 500:
            try:
                ptr_data = rpm(ex_ptr, ex_size * 4)
                for i in range(ex_size):
                    sp = struct.unpack_from("<I", ptr_data, i*4)[0]
                    if sp:
                        name = read_wstr(sp, 128)
                        if name:
                            ex_opcodes[f"0x{i:04X}"] = name
            except Exception as e:
                result["ex_read_error"] = str(e)

        result["ex_opcodes"] = ex_opcodes
        result["ex_count"] = len(ex_opcodes)

        kernel32.CloseHandle(hProc)

    except Exception as e:
        import traceback
        result["error"] = str(e)
        result["traceback"] = traceback.format_exc()

    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

_run()
