"""Dump L2 opcode tables with admin privileges."""
import sys
import os
import ctypes

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    print("Elevating to admin...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{os.path.abspath(__file__)}"',
        os.path.dirname(os.path.abspath(__file__)), 1)
    sys.exit(0)

# Now running as admin
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dump_opcode_tables import *

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "l2_opcodes_live.json")
os.makedirs(os.path.dirname(out_path), exist_ok=True)

pid = find_pid("L2.exe")
if not pid:
    with open(out_path, "w") as f:
        json.dump({"error": "L2.exe not found"}, f)
    input("L2.exe not found! Press Enter...")
    sys.exit(1)

print(f"L2.exe PID: {pid}")

if enable_debug_privilege():
    print("SeDebugPrivilege: ENABLED")

find_module_base._current_pid = pid

# Try toolhelp first
toolhelp_base, toolhelp_size = _find_module_toolhelp(pid, "Core.dll")
if toolhelp_base:
    print(f"Core.dll via Toolhelp: base=0x{toolhelp_base:08X}, size=0x{toolhelp_size:08X}")

handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not handle:
    err = ctypes.get_last_error()
    with open(out_path, "w") as f:
        json.dump({"error": f"OpenProcess failed: error {err}"}, f)
    input(f"OpenProcess failed (error {err})! Press Enter...")
    sys.exit(1)

try:
    if toolhelp_base:
        core_base, core_size = toolhelp_base, toolhelp_size
    else:
        core_base, core_size = find_module_base(handle, "Core.dll")

    if not core_base:
        with open(out_path, "w") as f:
            json.dump({"error": "Core.dll not found in process"}, f)
        input("Core.dll not found! Press Enter...")
        sys.exit(1)

    print(f"Core.dll base: 0x{core_base:08X}, size: 0x{core_size:08X}")

    # Read diagnostic values
    for name in ["GL2PacketCheck", "GL2LastRecvPacketNum", "GL2LastSendPacketNum",
                  "GL2LastRecvPacketNumEX", "GL2LastSendPacketNumEX"]:
        rva = EXPORTS[name]
        try:
            val = read_u32(handle, core_base + rva)
            print(f"  {name} = {val} (0x{val:08X})")
        except OSError as e:
            print(f"  {name} = ERROR: {e}")

    # Dump main opcodes
    main_opcodes = dump_packet_table(
        handle, core_base,
        EXPORTS["GL2UserPacketTableName"],
        EXPORTS["GL2UserPacketTableSize"],
        "GL2UserPacketTable (main opcodes)"
    )

    # Dump Ex opcodes
    ex_opcodes = dump_packet_table(
        handle, core_base,
        EXPORTS["GL2UserExPacketTableName"],
        EXPORTS["GL2UserExPacketTableSize"],
        "GL2UserExPacketTable (extended opcodes)"
    )

    result = {
        "timestamp": datetime.now().isoformat(),
        "pid": pid,
        "core_dll_base": f"0x{core_base:08X}",
        "main_opcodes": {f"0x{k:02X}": v for k, v in sorted(main_opcodes.items())},
        "main_count": len(main_opcodes),
        "ex_opcodes": {f"0x{k:04X}": v for k, v in sorted(ex_opcodes.items())},
        "ex_count": len(ex_opcodes),
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\nSaved to: {out_path}")

    # Print full list
    if main_opcodes:
        print(f"\n{'='*60}")
        print(f"FULL MAIN OPCODES ({len(main_opcodes)}):")
        for i in sorted(main_opcodes.keys()):
            print(f"  0x{i:02X} = {main_opcodes[i]}")

    if ex_opcodes:
        print(f"\n{'='*60}")
        print(f"FULL EX OPCODES ({len(ex_opcodes)}):")
        for i in sorted(ex_opcodes.keys()):
            print(f"  0x{i:04X} = {ex_opcodes[i]}")

finally:
    CloseHandle(handle)

input("\nDone! Press Enter to close...")
