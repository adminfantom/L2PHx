"""Hot-patch: REVERT XOR encryption on injections.

Game bodies in the relay are PLAINTEXT (no XOR cipher).
Our encryption was corrupting injected packets.
Restore original wrap_relay_0x06.
"""
import os
import gc

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_revert_xor.txt"
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

        # Find proxy via gc
        proxy = None
        engine_globals = None
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                    proxy = obj
                    if hasattr(obj, 'run') and hasattr(obj.run, '__func__'):
                        engine_globals = obj.run.__func__.__globals__
                    break
            except:
                pass

        if not proxy:
            log("FATAL: proxy not found")
            return
        log(f"Proxy: {proxy}")

        if not engine_globals:
            log("FATAL: cannot get engine_globals")
            return

        current_wrap = engine_globals.get('wrap_relay_0x06')
        log(f"Current wrap: {current_wrap}")

        original_wrap = engine_globals.get('_original_wrap_relay_0x06')
        log(f"Original wrap: {original_wrap}")

        if original_wrap is None:
            log("FATAL: _original_wrap_relay_0x06 not found — was patch applied?")
            return

        # Revert to original (no XOR encryption)
        engine_globals['wrap_relay_0x06'] = original_wrap
        log(f"REVERTED to original: {original_wrap}")

        # Verify
        verify = engine_globals.get('wrap_relay_0x06')
        log(f"Verify: {verify}")
        log(f"Is original: {verify is original_wrap}")

        log("DONE — injections will now be PLAINTEXT (no XOR)")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
