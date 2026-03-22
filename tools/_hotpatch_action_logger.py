"""Hot-patch: log ALL C2S game opcodes with timestamps for action mapping.

Install on running proxy. Tracks every unique game opcode and logs
full hex when a NEW opcode appears. User performs actions to reveal opcode mapping.
"""
import os
import gc
import struct
import time
import threading
import json

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_action_logger.txt"
out_json = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_action_logger.json"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)

def _run():
    import traceback
    lines = []
    opcode_data = {}  # opcode -> {count, first_ts, first_hex, sizes, all_hex}

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def save_json():
        export = {}
        for op, info in sorted(opcode_data.items()):
            export[f"0x{op:02X}"] = {
                "count": info["count"],
                "first_ts": info["first_ts"],
                "first_hex": info["first_hex"],
                "sizes": sorted(info["sizes"]),
                "last_hex": info.get("last_hex", ""),
                "samples": info.get("samples", [])[:5]
            }
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)

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

        if not proxy or not engine_globals:
            log("FATAL: proxy/engine_globals not found")
            return

        server_sock = getattr(proxy, 'server_sock', None)
        client_sock = getattr(proxy, 'client_sock', None)
        send_fn = engine_globals.get('send_l2_packet')
        recv_fn = engine_globals.get('recv_l2_packet')
        wrap_fn = engine_globals.get('wrap_relay_0x06')

        if not send_fn:
            log("FATAL: no send_l2_packet")
            return

        log(f"server_sock: {server_sock}")
        log(f"client_sock: {client_sock}")
        log(f"wrap_relay_0x06: {'YES' if wrap_fn else 'NO'}")

        original_send = send_fn
        baseline_ts = time.time()

        # Track known opcodes from initial capture
        known_ops = set()

        def decode_relay_game_body(body):
            """Decode relay 0x06 → game body (same as proxy code)."""
            if len(body) < 3 or body[0] != 0x06:
                return None, {}
            inner = body[1:]
            mask1 = inner[0]
            deobf = bytearray(len(inner))
            for i in range(len(inner)):
                deobf[i] = inner[i] ^ mask1
            # Type A: deobf[1:8] all zeros
            if len(deobf) >= 9 and all(b == 0 for b in deobf[1:8]):
                layer1_data = bytes(deobf[8:])
                pkt_type = "A"
            else:
                layer1_data = bytes(deobf[1:])
                pkt_type = "B"
            if len(layer1_data) < 2:
                return None, {"type": pkt_type}
            mask2 = layer1_data[0]
            layer2 = bytes(b ^ mask2 for b in layer1_data)
            game_body = layer2[1:]  # skip zero prefix
            is_padding = len(set(layer1_data[:8])) <= 1
            return game_body, {"type": pkt_type, "mask1": mask1, "mask2": mask2, "padding": is_padding}

        def hooked_send(sock, body):
            nonlocal known_ops
            # Only intercept C2S relay to server
            if sock is server_sock and len(body) > 0:
                if body[0] == 0x06:
                    game_body, info = decode_relay_game_body(body)
                    if game_body and len(game_body) > 0 and not info.get("padding"):
                        op = game_body[0]
                        ts = time.strftime('%H:%M:%S')
                        elapsed = time.time() - baseline_ts

                        if op not in opcode_data:
                            opcode_data[op] = {
                                "count": 0,
                                "first_ts": ts,
                                "first_hex": game_body.hex(),
                                "first_len": len(game_body),
                                "sizes": set(),
                                "samples": [],
                            }
                            # NEW OPCODE - prominent log
                            log(f"")
                            log(f">>> NEW OPCODE 0x{op:02X} at {ts} (+{elapsed:.1f}s) <<<")
                            log(f"    len={len(game_body)} type={info.get('type')} mask1=0x{info.get('mask1',0):02X} mask2=0x{info.get('mask2',0):02X}")
                            log(f"    full_hex={game_body.hex()}")
                            log(f"    relay_hex={body.hex()}")
                            log(f"")
                            known_ops.add(op)

                        opcode_data[op]["count"] += 1
                        opcode_data[op]["sizes"].add(len(game_body))
                        opcode_data[op]["last_hex"] = game_body.hex()
                        if len(opcode_data[op]["samples"]) < 5:
                            opcode_data[op]["samples"].append({
                                "ts": ts, "len": len(game_body),
                                "hex": game_body[:64].hex()
                            })

                        # Periodic summary
                        if opcode_data[op]["count"] % 20 == 0:
                            log(f"[{ts}] 0x{op:02X} count={opcode_data[op]['count']} sizes={sorted(opcode_data[op]['sizes'])}")

                        save_json()

            original_send(sock, body)

        # Install hook
        engine_globals['send_l2_packet'] = hooked_send
        log("ACTION LOGGER HOOK INSTALLED!")
        log("Perform actions in game to discover opcodes:")
        log("  - USE an item from inventory")
        log("  - MOVE to a different position")
        log("  - TARGET an NPC")
        log("  - OPEN/CLOSE inventory")
        log("  - SIT/STAND")
        log("Each NEW opcode will be logged prominently.")
        log("")

        # Auto-remove after 300 seconds (5 min)
        def _auto_remove():
            time.sleep(300)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Hook auto-removed after 300s")
                log(f"SUMMARY: {len(opcode_data)} unique opcodes:")
                for op in sorted(opcode_data.keys()):
                    info = opcode_data[op]
                    log(f"  0x{op:02X}: count={info['count']} sizes={sorted(info['sizes'])} first={info['first_hex'][:60]}")
                save_json()

        t = threading.Thread(target=_auto_remove, daemon=True)
        t.start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
