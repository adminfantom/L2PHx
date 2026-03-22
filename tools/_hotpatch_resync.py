"""Hot-patch: advance shadow_xor_c2s counter by 17 to re-sync with game server.

The desync was caused by a 17-byte plaintext injection (Say2 "ping") that
the server processed (decrypted + rotated counter) but shadow cipher didn't.
"""
import os
import sys
import gc

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_resync.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)

def _run():
    import traceback
    lines = []
    def log(s):
        lines.append(s)
        with open(out, "w") as f:
            f.write("\n".join(lines) + "\n")

    try:
        log(f"PID: {os.getpid()}")

        # Find proxy
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

        crypto = getattr(proxy, 'crypto', None)
        if not crypto:
            log("FATAL: no crypto")
            return

        xor_c2s = getattr(crypto, 'shadow_xor_c2s', None)
        if not xor_c2s:
            log("FATAL: no shadow_xor_c2s")
            return

        # Show current state
        log(f"Before: key = {bytes(xor_c2s.key).hex()}")
        import struct
        counter_before = struct.unpack_from("<I", xor_c2s.key, 8)[0]
        log(f"Before: counter = 0x{counter_before:08X} ({counter_before})")

        # Advance counter by 17 bytes (the plaintext injection size)
        DESYNC = 17
        xor_c2s._rotate_key(DESYNC)
        log(f"Advanced counter by {DESYNC}")

        counter_after = struct.unpack_from("<I", xor_c2s.key, 8)[0]
        log(f"After: key = {bytes(xor_c2s.key).hex()}")
        log(f"After: counter = 0x{counter_after:08X} ({counter_after})")
        log(f"Delta: {counter_after - counter_before}")

        log("DONE — shadow cipher re-synced!")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
