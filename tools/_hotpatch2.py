"""Minimal hot-patch test — write debug info to a file."""
import sys
import os

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_debug.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)

with open(out, "w") as f:
    f.write(f"PID: {os.getpid()}\n")
    f.write(f"sys.executable: {sys.executable}\n")
    f.write(f"Modules with 'engine': {[k for k in sys.modules if 'engine' in k.lower()]}\n")

    # Find _engine
    engine = None
    for name, mod in sys.modules.items():
        if hasattr(mod, 'wrap_relay_0x06'):
            engine = mod
            f.write(f"Found engine in module: {name}\n")
            break

    if not engine:
        f.write("ERROR: No module with wrap_relay_0x06 found!\n")
        f.write(f"All modules: {sorted(sys.modules.keys())}\n")
    else:
        f.write(f"wrap_relay_0x06: {engine.wrap_relay_0x06}\n")

        # Find proxy instance
        proxy = None
        main_mod = sys.modules.get('__main__')
        if main_mod:
            f.write(f"__main__ attrs: {[a for a in dir(main_mod) if not a.startswith('_')]}\n")
            for a in dir(main_mod):
                obj = getattr(main_mod, a, None)
                if hasattr(obj, 'proxy'):
                    f.write(f"Found proxy holder: {a} -> {obj}\n")
                    proxy = getattr(obj, 'proxy', None)
                    break
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock'):
                    f.write(f"Found proxy directly: {a}\n")
                    proxy = obj
                    break

        if proxy:
            f.write(f"Proxy: {proxy}\n")
            f.write(f"Has crypto: {hasattr(proxy, 'crypto')}\n")
            if hasattr(proxy, 'crypto') and proxy.crypto:
                c = proxy.crypto
                f.write(f"shadow_enabled: {getattr(c, 'shadow_enabled', '?')}\n")
                f.write(f"shadow_xor_c2s: {c.shadow_xor_c2s}\n")
                if c.shadow_xor_c2s:
                    f.write(f"shadow key: {bytes(c.shadow_xor_c2s.key).hex()}\n")
        else:
            f.write("Proxy not found in __main__\n")
            # Search all modules
            for mname, mod in list(sys.modules.items())[:100]:
                for attr in dir(mod):
                    try:
                        obj = getattr(mod, attr, None)
                        if obj and hasattr(obj, 'server_sock') and hasattr(obj, 'crypto'):
                            f.write(f"FOUND proxy in {mname}.{attr}\n")
                            proxy = obj
                            break
                    except:
                        pass
                if proxy:
                    break

    f.write("DONE\n")
