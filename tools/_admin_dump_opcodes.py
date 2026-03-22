"""Run dump_opcode_tables.py with admin privileges."""
import sys, os, ctypes

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    print("Elevating to admin...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{os.path.join(os.path.dirname(os.path.abspath(__file__)), "dump_opcode_tables.py")}"',
        os.path.dirname(os.path.abspath(__file__)), 1)
    sys.exit(0)
