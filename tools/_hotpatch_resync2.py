"""Hot-patch: re-sync shadow_xor_c2s counter by remaining 509 bytes.

Total pre-patch plaintext injections = 526 bytes.
Already resynced +17 (first attempt).
Post-patch encrypted injections (9199, 9452) already rotated shadow correctly.
Need: +509 more to match server.
"""
import os
import sys
import gc
import struct

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_resync2.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)

def _run():
    import traceback
    lines = []
    def log(s):
        lines.append(s)
        with open(out, "w") as f:
            f.write("\n".join(lines) + "\n")

    try:
        proxy = None
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                    proxy = obj
                    break
            except:
                pass

        if not proxy:
            log("FATAL: proxy not found")
            return

        xor_c2s = proxy.crypto.shadow_xor_c2s

        counter_before = struct.unpack_from("<I", xor_c2s.key, 8)[0]
        log(f"Before: key = {bytes(xor_c2s.key).hex()}")
        log(f"Before: counter = 0x{counter_before:08X}")

        DESYNC = 509  # 526 total - 17 already resynced
        xor_c2s._rotate_key(DESYNC)

        counter_after = struct.unpack_from("<I", xor_c2s.key, 8)[0]
        log(f"After: key = {bytes(xor_c2s.key).hex()}")
        log(f"After: counter = 0x{counter_after:08X}")
        log(f"Delta: {counter_after - counter_before}")
        log("DONE")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
