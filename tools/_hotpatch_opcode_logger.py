"""Hot-patch: log ALL unique C2S game opcodes seen in real-time.

Hooks send_l2_packet to decode relay and log every unique game opcode.
Goal: discover real Samurai Crow opcodes by watching user actions.
"""
import os
import gc
import struct
import time
import threading

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_opcode_logger.txt"
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
        log(f"Time: {time.strftime('%H:%M:%S')}")

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
        recv_fn = engine_globals.get('recv_l2_packet')
        send_fn = engine_globals.get('send_l2_packet')

        if not send_fn:
            log("FATAL: no send_l2_packet")
            return

        # Track unique opcodes
        seen_opcodes = {}  # opcode -> {count, first_body_hex, sizes}
        original_send = send_fn

        def decode_relay_game_body(body):
            """Decode relay 0x06 to get game_body."""
            if len(body) < 3 or body[0] != 0x06:
                return None
            inner = body[1:]
            mask1 = inner[0]
            deobf = bytearray(len(inner))
            for i in range(len(inner)):
                deobf[i] = inner[i] ^ mask1
            # Type A: deobf[1:8] all zeros
            if len(deobf) >= 9 and all(b == 0 for b in deobf[1:8]):
                layer1_data = bytes(deobf[8:])
            else:
                layer1_data = bytes(deobf[1:])
            if len(layer1_data) < 2:
                return None
            mask2 = layer1_data[0]
            layer2 = bytes(b ^ mask2 for b in layer1_data)
            return layer2[1:]  # skip zero prefix

        def hooked_send(sock, body):
            # Decode if it's a relay packet to server
            if sock is server_sock and len(body) > 2 and body[0] == 0x06:
                game_body = decode_relay_game_body(body)
                if game_body and len(game_body) > 0:
                    op = game_body[0]
                    ts = time.strftime('%H:%M:%S')
                    if op not in seen_opcodes:
                        seen_opcodes[op] = {
                            "count": 0,
                            "first_hex": game_body[:40].hex(),
                            "first_len": len(game_body),
                            "sizes": set(),
                        }
                        log(f"[{ts}] NEW OPCODE 0x{op:02X}: len={len(game_body)} hex={game_body[:40].hex()}")
                    seen_opcodes[op]["count"] += 1
                    seen_opcodes[op]["sizes"].add(len(game_body))

                    # Every 10th packet of each type, update
                    if seen_opcodes[op]["count"] % 10 == 0:
                        log(f"[{ts}] 0x{op:02X} count={seen_opcodes[op]['count']} sizes={sorted(seen_opcodes[op]['sizes'])}")

            original_send(sock, body)

        # Install hook
        engine_globals['send_l2_packet'] = hooked_send
        log("Opcode logger hook installed!")
        log("Perform actions in game: type in chat, use items, open shops...")
        log("Each NEW opcode will be logged here.")
        log("")

        # Auto-remove after 120 seconds
        def _auto_remove():
            time.sleep(120)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Hook auto-removed after 120s")
                log(f"SUMMARY: {len(seen_opcodes)} unique opcodes seen:")
                for op in sorted(seen_opcodes.keys()):
                    info = seen_opcodes[op]
                    log(f"  0x{op:02X}: count={info['count']} sizes={sorted(info['sizes'])} first={info['first_hex'][:30]}")

        t = threading.Thread(target=_auto_remove, daemon=True)
        t.start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
