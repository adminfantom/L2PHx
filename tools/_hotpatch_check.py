"""Check which module the relay handler actually uses."""
import os
import sys

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_check.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)

lines = []
def log(s):
    lines.append(s)
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")

try:
    # Check all engine-related modules
    for name in sorted(sys.modules.keys()):
        if 'engine' in name.lower():
            mod = sys.modules[name]
            log(f"Module '{name}': {mod}")
            log(f"  __name__: {getattr(mod, '__name__', '?')}")
            log(f"  has wrap_relay_0x06: {hasattr(mod, 'wrap_relay_0x06')}")
            if hasattr(mod, 'wrap_relay_0x06'):
                fn = mod.wrap_relay_0x06
                log(f"  wrap_relay_0x06: {fn}")
                log(f"  is patched: {'wrap_encrypted' in str(fn)}")

    # Check if _engine and l2_engine are the same object
    e1 = sys.modules.get('_engine')
    e2 = sys.modules.get('l2_engine')
    log(f"\n_engine: {id(e1)}")
    log(f"l2_engine: {id(e2) if e2 else 'NOT FOUND'}")
    log(f"Same object: {e1 is e2 if e2 else 'N/A'}")

    # Check the proxy's method globals
    import gc
    for obj in gc.get_objects():
        try:
            if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                log(f"\nProxy found: {obj}")
                log(f"Proxy type: {type(obj)}")
                log(f"Proxy module: {type(obj).__module__}")
                # Check what wrap_relay_0x06 the proxy's globals point to
                # The relay handler is a method, its __globals__ is the module dict
                if hasattr(obj, 'run'):
                    run_func = obj.run
                    if hasattr(run_func, '__func__'):
                        g = run_func.__func__.__globals__
                        wrap_fn = g.get('wrap_relay_0x06')
                        log(f"run.__globals__['wrap_relay_0x06']: {wrap_fn}")
                        log(f"Is patched: {'wrap_encrypted' in str(wrap_fn)}")
                        log(f"Module dict id: {id(g)}")
                        if e1:
                            log(f"_engine.__dict__ id: {id(vars(e1))}")
                        if e2:
                            log(f"l2_engine.__dict__ id: {id(vars(e2))}")
                break
        except:
            pass

    log("\nDONE")
except Exception as e:
    import traceback
    log(f"EXCEPTION: {e}")
    log(traceback.format_exc())
