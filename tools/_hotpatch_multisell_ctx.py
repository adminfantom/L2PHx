"""Hot-patch: check multisell context - what packets surrounded the MultiSellChoose."""
import os
import gc
import time
import json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_multisell_ctx.txt"
OUT_JSON = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_multisell_ctx.json"
os.makedirs(os.path.dirname(OUT), exist_ok=True)


def _run():
    import traceback
    lines = []

    def log(s):
        lines.append(s)
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    try:
        log(f"PID: {os.getpid()} Time: {time.strftime('%H:%M:%S')}")

        # Find proxy + store
        proxy = None
        store = None
        multisell_cap = None
        game_cap = None

        import sys
        import __main__

        # Try to get engine globals
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

        log(f"Proxy found: {type(proxy).__name__}")

        # Get _MULTISELL_CAP
        if engine_globals:
            multisell_cap = engine_globals.get('_MULTISELL_CAP')
            game_cap = engine_globals.get('_GAME_CAP')

        if multisell_cap:
            captured = multisell_cap.get('captured', [])
            log(f"\n_MULTISELL_CAP: {len(captured)} entries")
            for i, c in enumerate(captured):
                log(f"  [{i}] ts={c.get('ts','?')} game_hex={c.get('game_hex','')[:80]} len={c.get('game_len','?')}")
        else:
            log("\n_MULTISELL_CAP: not found in engine_globals")

        if game_cap:
            captured = game_cap.get('captured', [])
            log(f"\n_GAME_CAP: {len(captured)} entries")
            for i, c in enumerate(captured[-20:]):
                log(f"  [{i}] ts={c.get('ts','?')} first=0x{c.get('first_byte',0):02X} len={c.get('game_len','?')} hex={c.get('game_hex','')[:40]}")
        else:
            log("\n_GAME_CAP: not found")

        # Check proxy store around seq 6610
        store = getattr(proxy, 'store', None)
        if not store:
            # Look for store in engine globals
            if engine_globals:
                store = engine_globals.get('store')

        if not store:
            for obj in gc.get_objects():
                try:
                    if hasattr(obj, 'packets') and hasattr(obj, 'add') and hasattr(obj, 'get_recent'):
                        store = obj
                        break
                except:
                    pass

        if store:
            log(f"\nStore found: {type(store).__name__}")
            # Find packets around seq 6610
            all_pkts = []
            try:
                # Try get_recent with large count
                all_pkts = store.get_recent(500)
                log(f"  Recent 500 packets available")
            except:
                try:
                    all_pkts = list(store.packets)[-500:]
                    log(f"  Got {len(all_pkts)} from store.packets")
                except Exception as e:
                    log(f"  Cannot access store: {e}")

            # Filter around seq 6610
            target_seq = 6610
            nearby = [p for p in all_pkts if isinstance(p, dict) and abs(p.get('seq', 0) - target_seq) <= 30]
            log(f"\nPackets around seq {target_seq} (±30):")
            result = []
            for p in sorted(nearby, key=lambda x: x.get('seq', 0)):
                seq = p.get('seq', '?')
                t = p.get('time', p.get('ts', '?'))
                d = p.get('dir', p.get('direction', '?'))
                name = p.get('name', '?')
                op = p.get('opcode', p.get('opcode_hex', '?'))
                size = p.get('size', '?')
                dec = p.get('dec_hex', p.get('hex', ''))[:80]
                marker = ' <<< MULTISELL' if seq == target_seq else ''
                line = f"  [{seq}] {t} {d} {op} {name} sz={size}{marker}"
                log(line)
                result.append({
                    'seq': seq, 'time': str(t), 'dir': str(d),
                    'op': str(op), 'name': str(name), 'size': str(size),
                    'dec': dec[:80]
                })

            with open(OUT_JSON, "w", encoding="utf-8") as f:
                json.dump({'nearby': result, 'multisell_cap': str(multisell_cap)}, f, indent=2)
        else:
            log("\nStore: not found")

        log("\nDONE")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
