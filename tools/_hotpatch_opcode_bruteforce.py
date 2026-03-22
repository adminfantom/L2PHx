"""Hot-patch: brute-force C2S BypassToServer opcode.

Sends BypassToServer("multisell 81381") with each of 256 possible opcodes.
Monitors S2C for multisell response (opcode 0xFE:XX or any new large packet).
Game bodies are PLAINTEXT inside relay 0x06 frames.

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import struct
import time
import json

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_opcode_bruteforce.txt"
out_json = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_opcode_bruteforce.json"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    import threading
    lines = []
    results = {"tested": [], "responses": [], "s2c_before": 0, "s2c_after": {}}

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[-1000:]) + "\n")

    def save_json():
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("C2S OPCODE BRUTE FORCE - BypassToServer")
        log("=" * 60)

        # Find proxy
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

        if not proxy or not engine_globals:
            log("FATAL: proxy/engine_globals not found")
            return

        server_sock = getattr(proxy, 'server_sock', None)
        send_fn = engine_globals.get('send_l2_packet')
        wrap_fn = engine_globals.get('wrap_relay_0x06')

        if not all([server_sock, send_fn, wrap_fn]):
            log("FATAL: missing functions")
            return

        log(f"server_sock: {server_sock}")

        # Bypass string as UTF-16LE null-terminated
        bypass_str = "multisell 81381"
        bypass_body = bypass_str.encode('utf-16-le') + b'\x00\x00'

        # Also try shorter bypass
        bypass_str2 = "_mrsl 81381"
        bypass_body2 = bypass_str2.encode('utf-16-le') + b'\x00\x00'

        # S2C response monitor
        s2c_new = []
        original_send = send_fn

        def monitor_s2c(sock, body):
            """Temporary hook to catch any S2C-like responses."""
            # We only hook C2S send, but we can check the proxy store
            original_send(sock, body)

        # Count current S2C packets in store
        store = getattr(proxy, 'store', None)
        if store:
            with store.lock:
                s2c_count_before = sum(1 for p in store.packets if p.get("dir") == "S2C")
            results["s2c_before"] = s2c_count_before
            log(f"S2C packets in store before: {s2c_count_before}")

        # Skip known login opcodes
        skip_opcodes = {0x00, 0x0E, 0x11, 0x12, 0x2B, 0xCB}
        # Also skip 0x06 (relay header) to avoid confusion
        skip_opcodes.add(0x06)

        log(f"\nStarting brute force: 256 opcodes, skip {len(skip_opcodes)} known")
        log(f"Bypass string: '{bypass_str}'")
        log(f"Format: [opcode] [UTF-16LE string + null]")
        log("")

        tested = 0
        batch_size = 16
        batch_delay = 0.5  # seconds between batches

        for batch_start in range(0, 256, batch_size):
            batch_end = min(batch_start + batch_size, 256)
            batch_opcodes = []

            for op in range(batch_start, batch_end):
                if op in skip_opcodes:
                    continue

                # Build packet: [opcode] + bypass_body
                pkt = bytes([op]) + bypass_body
                wrapped = wrap_fn(pkt)

                try:
                    send_fn(server_sock, wrapped)
                    batch_opcodes.append(op)
                    tested += 1
                except Exception as e:
                    log(f"  ERROR sending op=0x{op:02X}: {e}")
                    # Connection might be dead
                    log(f"\nCONNECTION ERROR at opcode 0x{op:02X}!")
                    results["connection_error"] = f"0x{op:02X}"
                    save_json()
                    return

            if batch_opcodes:
                ops_str = " ".join(f"{o:02X}" for o in batch_opcodes)
                log(f"[{time.strftime('%H:%M:%S')}] Batch {batch_start:3d}-{batch_end-1:3d}: sent {ops_str}")
                results["tested"].extend([f"0x{o:02X}" for o in batch_opcodes])

            time.sleep(batch_delay)

        log(f"\n{'='*60}")
        log(f"BRUTE FORCE COMPLETE: {tested} opcodes tested")
        log(f"{'='*60}")

        # Wait a moment for any server responses
        time.sleep(2)

        # Count S2C packets after
        if store:
            with store.lock:
                s2c_count_after = sum(1 for p in store.packets if p.get("dir") == "S2C")
                # Get new S2C packets
                new_s2c = []
                for p in store.packets:
                    if p.get("dir") == "S2C" and p.get("seq", 0) > 0:
                        new_s2c.append(p)
                # Get last 20 S2C
                recent_s2c = new_s2c[-20:]
            results["s2c_after_count"] = s2c_count_after
            results["s2c_new"] = s2c_count_after - s2c_count_before
            log(f"\nS2C packets after: {s2c_count_after} (new: {s2c_count_after - s2c_count_before})")
            log(f"\nLast 20 S2C packets:")
            for p in recent_s2c:
                op = p.get("opcode", -1)
                nm = p.get("opname", "?")
                ts = p.get("ts", "?")
                sz = p.get("len", 0)
                dec_hex = p.get("dec_hex", "")[:60]
                log(f"  [{ts}] op=0x{op:04X}({nm}) len={sz} hex={dec_hex}")
                results["responses"].append({
                    "ts": ts, "op": f"0x{op:04X}", "name": nm,
                    "len": sz, "hex": dec_hex[:80]
                })

        # Now try ExMultiSellList with all 256 opcodes as main + sub 0x019E
        log(f"\n{'='*60}")
        log(f"PHASE 2: ExMultiSellList brute force (256 main opcodes)")
        log(f"Format: [opcode] [9E 01] [listId=81381 LE32]")
        log(f"{'='*60}")

        list_id = 81381
        sub_bytes = struct.pack('<H', 0x019E)
        list_bytes = struct.pack('<I', list_id)

        for batch_start in range(0, 256, batch_size):
            batch_end = min(batch_start + batch_size, 256)
            batch_opcodes = []

            for op in range(batch_start, batch_end):
                if op in skip_opcodes:
                    continue

                pkt = bytes([op]) + sub_bytes + list_bytes
                wrapped = wrap_fn(pkt)

                try:
                    send_fn(server_sock, wrapped)
                    batch_opcodes.append(op)
                except Exception as e:
                    log(f"  CONNECTION ERROR at 0x{op:02X}: {e}")
                    save_json()
                    return

            if batch_opcodes:
                ops_str = " ".join(f"{o:02X}" for o in batch_opcodes)
                log(f"[{time.strftime('%H:%M:%S')}] ExMS Batch {batch_start:3d}-{batch_end-1:3d}: sent {ops_str}")

            time.sleep(batch_delay)

        log(f"\nEXMULTISELL BRUTE FORCE COMPLETE")

        # Final check
        time.sleep(3)
        if store:
            with store.lock:
                s2c_final = sum(1 for p in store.packets if p.get("dir") == "S2C")
                recent = [p for p in store.packets if p.get("dir") == "S2C"][-10:]
            log(f"\nFINAL S2C count: {s2c_final} (total new: {s2c_final - s2c_count_before})")
            log(f"Last 10 S2C:")
            for p in recent:
                op = p.get("opcode", -1)
                nm = p.get("opname", "?")
                ts = p.get("ts", "?")
                sz = p.get("len", 0)
                log(f"  [{ts}] op=0x{op:04X}({nm}) len={sz}")

        save_json()
        log(f"\nDONE at {time.strftime('%H:%M:%S')}")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())
        save_json()


_run()
