"""Direct sys.remote_exec without UAC — same-user process, no admin needed."""
import sys, os

TARGET_PID = 1007304
PATCH_SCRIPT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\_hotpatch_bypass_fix.py"

print(f"sys.version: {sys.version}")
print(f"Target PID: {TARGET_PID}")
print(f"Script: {PATCH_SCRIPT}")
print(f"Script exists: {os.path.exists(PATCH_SCRIPT)}")

try:
    sys.remote_exec(TARGET_PID, PATCH_SCRIPT)
    print("remote_exec OK — check _bypass_fix.txt in logs/")
except Exception as e:
    print(f"remote_exec FAILED: {type(e).__name__}: {e}")

input("Press Enter...")
