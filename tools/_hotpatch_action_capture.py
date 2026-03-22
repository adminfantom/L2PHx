"""Hot-patch: capture ALL C2S game bodies with timestamps for opcode mapping.

Logs every unique opcode with hex dump. When user performs actions,
new opcodes appear = real C2S opcode discovery.

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import struct
import time
import json

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_action_capture.txt"
out_json = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_action_capture.json"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    lines = []
    opcode_db = {}
    all_packets = []
    baseline_ts = time.time()

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[-500:]) + "\n")

    def save_json():
        export = {"opcodes": {}, "timeline": all_packets[-100:]}
        for op, info in sorted(opcode_db.items()):
            export["opcodes"][f"0x{op:02X}"] = {
                "count": info["count"],
                "first_ts": info["first_ts"],
                "sizes": sorted(info["sizes"])[:20],
                "first_hex": info["first_hex"][:160],
                "last_hex": info.get("last_hex", "")[:160],
                "samples": info.get("samples", [])[:5],
            }
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("C2S ACTION CAPTURE - ALL GAME BODIES")
        log("DO SOMETHING IN GAME NOW!")
        log("=" * 60)

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
        original_send = send_fn

        if not send_fn:
            log("FATAL: no send_l2_packet")
            return

        log(f"server_sock: {server_sock}")

        def decode_relay_game_body(body):
            if len(body) < 3 or body[0] != 0x06:
                return None, {}
            inner = body[1:]
            mask1 = inner[0]
            deobf = bytearray(len(inner))
            for i in range(len(inner)):
                deobf[i] = inner[i] ^ mask1
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
            game_body = layer2[1:]
            is_padding = len(set(layer1_data[:8])) <= 1
            return game_body, {"type": pkt_type, "mask1": mask1, "mask2": mask2, "padding": is_padding}

        def hooked_send(sock, body):
            if sock is server_sock and len(body) > 0:
                if body[0] == 0x06 and len(body) > 2:
                    game_body, info = decode_relay_game_body(body)
                    if game_body and len(game_body) > 0 and not info.get("padding"):
                        op = game_body[0]
                        ts = time.strftime('%H:%M:%S')
                        elapsed = time.time() - baseline_ts

                        pkt_info = {
                            "ts": ts, "elapsed": round(elapsed, 1),
                            "op": f"0x{op:02X}", "len": len(game_body),
                            "hex": game_body[:80].hex()
                        }
                        all_packets.append(pkt_info)

                        if op not in opcode_db:
                            opcode_db[op] = {
                                "count": 0, "first_ts": ts,
                                "first_hex": game_body.hex(),
                                "sizes": set(), "samples": [],
                            }
                            log(f"")
                            log(f">>> NEW OPCODE 0x{op:02X} at {ts} (+{elapsed:.1f}s) <<<")
                            log(f"    len={len(game_body)} type={info.get('type')}")
                            log(f"    hex={game_body[:80].hex()}")
                            if len(game_body) > 80:
                                log(f"    hex2={game_body[80:160].hex()}")

                        opcode_db[op]["count"] += 1
                        opcode_db[op]["sizes"].add(len(game_body))
                        opcode_db[op]["last_hex"] = game_body[:80].hex()

                        if len(opcode_db[op]["samples"]) < 5:
                            opcode_db[op]["samples"].append({
                                "ts": ts, "len": len(game_body),
                                "hex": game_body[:120].hex()
                            })

                        # Summary every 20 packets
                        total = sum(i["count"] for i in opcode_db.values())
                        if total % 20 == 0:
                            save_json()
                            log(f"\n[{ts}] total={total} unique_ops={len(opcode_db)}")
                            for o in sorted(opcode_db.keys()):
                                log(f"    0x{o:02X}: count={opcode_db[o]['count']} sizes={sorted(opcode_db[o]['sizes'])[:10]}")

            original_send(sock, body)

        engine_globals['send_l2_packet'] = hooked_send
        log("ACTION CAPTURE HOOK INSTALLED!")
        log("Perform actions NOW - each new opcode = new packet type!")
        log("")

        # Auto-remove after 300 seconds (5 min)
        import threading
        def _auto_remove():
            time.sleep(300)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Hook removed after 5min")
                log(f"FINAL: {len(opcode_db)} unique opcodes")
                for o in sorted(opcode_db.keys()):
                    i = opcode_db[o]
                    log(f"  0x{o:02X}: count={i['count']} sizes={sorted(i['sizes'])[:15]} first_hex={i['first_hex'][:80]}")
                save_json()

        t = threading.Thread(target=_auto_remove, daemon=True)
        t.start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
