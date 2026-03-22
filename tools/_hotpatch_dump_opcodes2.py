"""Hot-patch v2: dump L2 opcode tables with verbose diagnostics."""
import os, ctypes, ctypes.wintypes as wt, struct, json, subprocess
from datetime import datetime

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\l2_opcodes_live.json"
os.makedirs(os.path.dirname(out), exist_ok=True)

def _run():
    r = {"ts": datetime.now().isoformat(), "steps": []}
    def log(s):
        r["steps"].append(s)

    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

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
                    break
        except: pass

        if not pid:
            r["error"] = "L2.exe not found"
            with open(out, "w") as f: json.dump(r, f, indent=2)
            return

        r["l2_pid"] = pid
        r["my_pid"] = os.getpid()
        log(f"L2.exe PID={pid}, my PID={os.getpid()}")

        # SeDebugPrivilege
        try:
            a32 = ctypes.WinDLL("advapi32", use_last_error=True)
            class LUID(ctypes.Structure):
                _fields_ = [("Lo", wt.DWORD), ("Hi", wt.LONG)]
            class TP(ctypes.Structure):
                _fields_ = [("Cnt", wt.DWORD), ("L", LUID), ("A", wt.DWORD)]
            ht = wt.HANDLE()
            a32.OpenProcessToken(k32.GetCurrentProcess(), 0x28, ctypes.byref(ht))
            lu = LUID()
            a32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(lu))
            tp = TP(1, lu, 2)
            a32.AdjustTokenPrivileges(ht, False, ctypes.byref(tp), 0, None, None)
            k32.CloseHandle(ht)
            log("SeDebugPrivilege OK")
        except Exception as e:
            log(f"SeDebugPrivilege FAIL: {e}")

        # Open with all possible access flags
        flags = 0x0010 | 0x0400  # VM_READ | QUERY_INFORMATION
        hP = k32.OpenProcess(flags, False, pid)
        log(f"OpenProcess(0x{flags:04X}, {pid}): handle=0x{hP:X}" if hP else f"OpenProcess FAIL: {ctypes.get_last_error()}")
        if not hP:
            r["error"] = f"OpenProcess fail: {ctypes.get_last_error()}"
            with open(out, "w") as f: json.dump(r, f, indent=2)
            return

        def rpm(addr, sz):
            buf = ctypes.create_string_buffer(sz)
            n = ctypes.c_size_t(0)
            ok = k32.ReadProcessMemory(hP, ctypes.c_void_p(addr), buf, sz, ctypes.byref(n))
            return (ok, buf.raw[:n.value], ctypes.get_last_error())

        # Try reading at multiple candidate addresses for Core.dll
        candidates = [0x15000000, 0x10000000, 0x14000000, 0x16000000, 0x0F000000, 0x20000000]

        core_base = None
        for addr in candidates:
            ok, data, err = rpm(addr, 2)
            if ok and len(data) >= 2:
                is_mz = data[:2] == b'MZ'
                log(f"  0x{addr:08X}: read OK, MZ={is_mz}, bytes={data[:2].hex()}")
                if is_mz:
                    core_base = addr
                    break
            else:
                log(f"  0x{addr:08X}: read FAIL err={err}")

        # Also try scanning PEB for module list
        if core_base is None:
            log("Trying NtQueryInformationProcess for PEB32...")
            try:
                ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
                # ProcessWow64Information = 26
                peb32_addr = ctypes.c_void_p(0)
                status = ntdll.NtQueryInformationProcess(
                    hP, 26, ctypes.byref(peb32_addr),
                    ctypes.sizeof(peb32_addr), None)
                log(f"NtQueryInformationProcess(26): status=0x{status & 0xFFFFFFFF:08X}, PEB32=0x{peb32_addr.value or 0:08X}")

                if peb32_addr.value:
                    # Read PEB32.Ldr (offset 0x0C in 32-bit PEB)
                    ok, peb_data, _ = rpm(peb32_addr.value, 0x40)
                    if ok and len(peb_data) >= 0x10:
                        ldr_ptr = struct.unpack_from("<I", peb_data, 0x0C)[0]
                        log(f"PEB32.Ldr = 0x{ldr_ptr:08X}")

                        # Read Ldr.InLoadOrderModuleList (offset 0x0C)
                        ok, ldr_data, _ = rpm(ldr_ptr, 0x30)
                        if ok and len(ldr_data) >= 0x10:
                            list_head = struct.unpack_from("<I", ldr_data, 0x0C)[0]
                            log(f"InLoadOrderModuleList head = 0x{list_head:08X}")

                            # Walk the list
                            entry = list_head
                            visited = set()
                            for _ in range(200):
                                if entry in visited or entry == 0:
                                    break
                                visited.add(entry)

                                ok, entry_data, _ = rpm(entry, 0x40)
                                if not ok or len(entry_data) < 0x30:
                                    break

                                # LDR_DATA_TABLE_ENTRY32:
                                # +0x00: InLoadOrderLinks (Flink, Blink)
                                # +0x18: DllBase
                                # +0x20: EntryPoint (skip)
                                # +0x24: SizeOfImage
                                # +0x28: FullDllName (UNICODE_STRING: Length, MaxLength, Buffer)
                                # +0x30: BaseDllName
                                dll_base = struct.unpack_from("<I", entry_data, 0x18)[0]
                                size_of_image = struct.unpack_from("<I", entry_data, 0x24)[0]
                                name_len = struct.unpack_from("<H", entry_data, 0x30)[0]
                                name_ptr = struct.unpack_from("<I", entry_data, 0x34)[0]

                                modname = ""
                                if name_ptr and name_len > 0:
                                    ok2, name_data, _ = rpm(name_ptr, min(name_len, 512))
                                    if ok2:
                                        modname = name_data.decode("utf-16-le", errors="replace")

                                if "core" in modname.lower():
                                    log(f"FOUND: {modname} at 0x{dll_base:08X} size=0x{size_of_image:08X}")
                                    core_base = dll_base
                                    break

                                # Next entry
                                entry = struct.unpack_from("<I", entry_data, 0x00)[0]
            except Exception as e:
                log(f"PEB walk error: {e}")

        if core_base is None:
            r["error"] = "Core.dll not found at any candidate address"
            with open(out, "w") as f: json.dump(r, f, indent=2)
            k32.CloseHandle(hP)
            return

        r["core_dll_base"] = f"0x{core_base:08X}"
        log(f"Core.dll at 0x{core_base:08X}")

        # RVAs
        def read_u32(addr):
            ok, d, e = rpm(addr, 4)
            if not ok: raise OSError(f"read fail 0x{addr:08X}: err {e}")
            return struct.unpack("<I", d)[0]

        def read_wstr(addr, mc=256):
            if not addr: return None
            ok, d, _ = rpm(addr, mc*2)
            if not ok: return None
            for i in range(0, len(d)-1, 2):
                if d[i]==0 and d[i+1]==0:
                    return d[:i].decode("utf-16-le", errors="replace")
            return d.decode("utf-16-le", errors="replace")

        # Read UseKeyCrypt
        try:
            r["GL2UseKeyCrypt"] = read_u32(core_base + 0x001D8254)
        except: r["GL2UseKeyCrypt"] = "err"

        # Main table
        try:
            main_size = read_u32(core_base + 0x001DD1D8)
            main_ptr = read_u32(core_base + 0x001D7F98)
            r["main_table_size"] = main_size
            r["main_table_ptr"] = f"0x{main_ptr:08X}"
            log(f"Main: size={main_size}, ptr=0x{main_ptr:08X}")

            main_ops = {}
            if main_ptr and 0 < main_size < 500:
                ok, pd, _ = rpm(main_ptr, main_size * 4)
                if ok:
                    for i in range(main_size):
                        sp = struct.unpack_from("<I", pd, i*4)[0]
                        if sp:
                            nm = read_wstr(sp, 128)
                            if nm:
                                main_ops[f"0x{i:02X}"] = nm
            r["main_opcodes"] = main_ops
            r["main_count"] = len(main_ops)
            log(f"Main opcodes: {len(main_ops)}")
        except Exception as e:
            log(f"Main table error: {e}")

        # Ex table
        try:
            ex_size = read_u32(core_base + 0x001D56B4)
            ex_ptr = read_u32(core_base + 0x001DBEE0)
            r["ex_table_size"] = ex_size
            r["ex_table_ptr"] = f"0x{ex_ptr:08X}"
            log(f"Ex: size={ex_size}, ptr=0x{ex_ptr:08X}")

            ex_ops = {}
            if ex_ptr and 0 < ex_size < 500:
                ok, pd, _ = rpm(ex_ptr, ex_size * 4)
                if ok:
                    for i in range(ex_size):
                        sp = struct.unpack_from("<I", pd, i*4)[0]
                        if sp:
                            nm = read_wstr(sp, 128)
                            if nm:
                                ex_ops[f"0x{i:04X}"] = nm
            r["ex_opcodes"] = ex_ops
            r["ex_count"] = len(ex_ops)
            log(f"Ex opcodes: {len(ex_ops)}")
        except Exception as e:
            log(f"Ex table error: {e}")

        k32.CloseHandle(hP)

    except Exception as e:
        import traceback
        r["error"] = str(e)
        r["tb"] = traceback.format_exc()

    with open(out, "w", encoding="utf-8") as f:
        json.dump(r, f, indent=2, ensure_ascii=False)

_run()
