"""Run sys.remote_exec with admin privileges to patch the proxy (PID 716464)."""
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

TARGET_PID = 1007304
PATCH_SCRIPT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\_hotpatch_bypass_fix.py"

print(f"Admin: {is_admin()}")
print(f"Targeting PID: {TARGET_PID}")
print(f"Script: {PATCH_SCRIPT}")

try:
    sys.remote_exec(TARGET_PID, PATCH_SCRIPT)
    print("remote_exec completed!")
except Exception as e:
    print(f"ERROR: {e}")

input("Press Enter to close...")
