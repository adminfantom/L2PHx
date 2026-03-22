"""Enable SeDebugPrivilege then sys.remote_exec."""
import sys, os, ctypes
from ctypes import wintypes

SE_DEBUG_NAME = "SeDebugPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

def enable_debug_privilege():
    hToken = wintypes.HANDLE()
    luid = wintypes.LARGE_INTEGER()

    if not ctypes.windll.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(hToken)):
        return False, f"OpenProcessToken failed: {ctypes.GetLastError()}"

    if not ctypes.windll.advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        return False, f"LookupPrivilegeValue failed: {ctypes.GetLastError()}"

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", wintypes.LARGE_INTEGER), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    if not ctypes.windll.advapi32.AdjustTokenPrivileges(
        hToken, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
        return False, f"AdjustTokenPrivileges failed: {ctypes.GetLastError()}"

    err = ctypes.GetLastError()
    if err == 1300:  # ERROR_NOT_ALL_ASSIGNED
        return False, "SeDebugPrivilege not available for this token (not admin?)"

    ctypes.windll.kernel32.CloseHandle(hToken)
    return True, "SeDebugPrivilege enabled"

ok, msg = enable_debug_privilege()
print(f"SeDebugPrivilege: {msg}")

TARGET_PID = 1007304
PATCH_SCRIPT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\_hotpatch_bypass_fix.py"

print(f"Target PID: {TARGET_PID}")
print(f"Script exists: {os.path.exists(PATCH_SCRIPT)}")

try:
    sys.remote_exec(TARGET_PID, PATCH_SCRIPT)
    print("remote_exec OK!")
except Exception as e:
    print(f"remote_exec FAILED: {type(e).__name__}: {e}")
