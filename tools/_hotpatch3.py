"""Debug hot-patch v3 — direct _engine access with error handling."""
import sys
import os
import traceback

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch3.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)

lines = []
def log(s):
    lines.append(s)
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")

try:
    log(f"PID: {os.getpid()}")

    engine = sys.modules.get('_engine')
    log(f"_engine module: {engine}")
    log(f"_engine file: {getattr(engine, '__file__', '?')}")

    has_wrap = hasattr(engine, 'wrap_relay_0x06')
    log(f"has wrap_relay_0x06: {has_wrap}")

    if has_wrap:
        log(f"wrap_relay_0x06: {engine.wrap_relay_0x06}")

    # Check for L2XorCipher
    has_xor = hasattr(engine, 'L2XorCipher')
    log(f"has L2XorCipher: {has_xor}")

    # Find proxy instance via __main__
    main_mod = sys.modules.get('__main__')
    log(f"__main__: {main_mod}")
    log(f"__main__ file: {getattr(main_mod, '__file__', '?')}")

    # List __main__ non-private attrs
    if main_mod:
        attrs = [a for a in dir(main_mod) if not a.startswith('_')]
        log(f"__main__ attrs: {attrs}")

    # Look for L2ProxyApp or similar
    proxy = None
    for attr_name in dir(main_mod):
        try:
            obj = getattr(main_mod, attr_name, None)
            if obj is None:
                continue
            t = type(obj).__name__
            if 'proxy' in attr_name.lower() or 'app' in attr_name.lower():
                log(f"  {attr_name}: type={t}")
            if hasattr(obj, 'proxy') and hasattr(getattr(obj, 'proxy', None), 'crypto'):
                proxy = obj.proxy
                log(f"FOUND proxy via {attr_name}.proxy")
                break
            if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock'):
                proxy = obj
                log(f"FOUND proxy directly: {attr_name}")
                break
        except Exception as e:
            log(f"  ERR on {attr_name}: {e}")

    if not proxy:
        # Try l2phx module
        l2phx = sys.modules.get('l2phx')
        log(f"l2phx module: {l2phx}")
        if l2phx:
            for attr_name in dir(l2phx):
                try:
                    obj = getattr(l2phx, attr_name, None)
                    if hasattr(obj, 'proxy'):
                        p = getattr(obj, 'proxy', None)
                        if p and hasattr(p, 'crypto'):
                            proxy = p
                            log(f"FOUND proxy via l2phx.{attr_name}.proxy")
                            break
                except:
                    pass

    if proxy:
        log(f"Proxy: {proxy}")
        log(f"Proxy type: {type(proxy).__name__}")
        log(f"Has crypto: {hasattr(proxy, 'crypto')}")
        crypto = getattr(proxy, 'crypto', None)
        if crypto:
            log(f"Crypto type: {type(crypto).__name__}")
            log(f"shadow_enabled: {getattr(crypto, 'shadow_enabled', '?')}")
            xor_c2s = getattr(crypto, 'shadow_xor_c2s', None)
            log(f"shadow_xor_c2s: {xor_c2s}")
            if xor_c2s:
                log(f"shadow_xor_c2s type: {type(xor_c2s).__name__}")
                log(f"shadow_xor_c2s key: {bytes(xor_c2s.key).hex()}")
                log(f"shadow_xor_c2s has encrypt: {hasattr(xor_c2s, 'encrypt')}")
    else:
        log("Proxy NOT found")
        # List all modules with 'l2' or 'proxy' in name
        relevant = [k for k in sys.modules if any(x in k.lower() for x in ('l2', 'proxy', 'phx'))]
        log(f"Relevant modules: {relevant}")

    log("DONE")
except Exception as e:
    log(f"EXCEPTION: {e}")
    log(traceback.format_exc())
