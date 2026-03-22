"""Hot-patch v2: encrypt injected C2S packets with shadow XOR cipher."""
import os
out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_xor_v2.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as _f:
    _f.write("START\n")

def _run():
    import sys
    import gc
    import traceback

    lines = ["START"]
    def log(s):
        lines.append(s)
        with open(out, "w") as f:
            f.write("\n".join(lines) + "\n")

    try:
        log(f"PID: {os.getpid()}")

        engine = sys.modules.get('_engine')
        if not engine:
            log("FATAL: _engine not in sys.modules")
            return
        log(f"_engine found")

        # Find proxy via gc
        proxy = None
        L2MitmProxy = getattr(engine, 'L2MitmProxy', None)
        log(f"L2MitmProxy: {L2MitmProxy}")

        if L2MitmProxy:
            for obj in gc.get_referrers(L2MitmProxy):
                if isinstance(obj, L2MitmProxy):
                    proxy = obj
                    log(f"FOUND proxy via gc.get_referrers")
                    break

        if not proxy:
            # Broader search
            log("Trying gc.get_objects scan...")
            count = 0
            for obj in gc.get_objects():
                count += 1
                try:
                    if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                        proxy = obj
                        log(f"FOUND proxy via gc scan (checked {count} objects)")
                        break
                except:
                    pass
            if not proxy:
                log(f"Proxy NOT found after scanning {count} objects")
                return

        # Check crypto
        crypto = getattr(proxy, 'crypto', None)
        log(f"crypto: {crypto}")
        if crypto:
            log(f"shadow_enabled: {getattr(crypto, 'shadow_enabled', False)}")
            xor_c2s = getattr(crypto, 'shadow_xor_c2s', None)
            log(f"shadow_xor_c2s: {xor_c2s}")
            if xor_c2s:
                log(f"key: {bytes(xor_c2s.key).hex()}")

        # Save original
        original_wrap = engine.wrap_relay_0x06
        if hasattr(engine, '_original_wrap_relay_0x06'):
            original_wrap = engine._original_wrap_relay_0x06
            log("Using saved original wrap_relay_0x06")
        else:
            engine._original_wrap_relay_0x06 = original_wrap
            log("Saved original wrap_relay_0x06")

        # Monkey-patch
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

        engine.wrap_relay_0x06 = wrap_encrypted
        log(f"PATCHED! engine.wrap_relay_0x06 = {engine.wrap_relay_0x06}")
        log("DONE — injections will now be XOR-encrypted")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
