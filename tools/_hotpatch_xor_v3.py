"""Hot-patch v3: encrypt injected C2S via shadow XOR.

Patches wrap_relay_0x06 in the CORRECT module globals (l2_engine, not _engine).
"""
import os
import sys
import gc

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_xor_v3.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as _f:
    _f.write("START\n")

def _run():
    import traceback
    lines = ["START"]
    def log(s):
        lines.append(s)
        with open(out, "w") as f:
            f.write("\n".join(lines) + "\n")

    try:
        log(f"PID: {os.getpid()}")

        # Find proxy instance via gc
        proxy = None
        engine_globals = None
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                    proxy = obj
                    # Get the module globals from the proxy's run method
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
            log("FATAL: cannot get engine_globals from proxy.run")
            return
        log(f"engine_globals id: {id(engine_globals)}")

        # Get the current wrap_relay_0x06 from the CORRECT globals
        current_wrap = engine_globals.get('wrap_relay_0x06')
        log(f"Current wrap_relay_0x06: {current_wrap}")

        # Save original if not already saved
        if '_original_wrap_relay_0x06' in engine_globals:
            original_wrap = engine_globals['_original_wrap_relay_0x06']
            log("Using saved original")
        else:
            original_wrap = current_wrap
            engine_globals['_original_wrap_relay_0x06'] = original_wrap
            log("Saved original")

        # Check crypto state
        crypto = getattr(proxy, 'crypto', None)
        log(f"crypto: {crypto}")
        if crypto:
            log(f"shadow_enabled: {getattr(crypto, 'shadow_enabled', False)}")
            xor_c2s = getattr(crypto, 'shadow_xor_c2s', None)
            log(f"shadow_xor_c2s: {xor_c2s}")
            if xor_c2s:
                log(f"key: {bytes(xor_c2s.key).hex()}")

        # Create patched function
        def wrap_encrypted(game_body):
            encrypted = game_body
            try:
                c = getattr(proxy, 'crypto', None)
                if c and getattr(c, 'shadow_enabled', False):
                    xor = getattr(c, 'shadow_xor_c2s', None)
                    if xor:
                        encrypted = bytes(xor.encrypt(bytearray(game_body)))
            except Exception:
                pass
            return original_wrap(encrypted)

        # Patch in the CORRECT globals
        engine_globals['wrap_relay_0x06'] = wrap_encrypted
        log(f"PATCHED engine_globals['wrap_relay_0x06'] = {wrap_encrypted}")

        # Verify
        verify = engine_globals.get('wrap_relay_0x06')
        log(f"Verify: {verify}")
        log(f"Is patched: {verify is wrap_encrypted}")

        log("DONE — injections will now be XOR-encrypted!")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
