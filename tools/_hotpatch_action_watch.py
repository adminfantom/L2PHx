"""Hot-patch v3: watch ALL send_l2_packet calls for C2S game bodies.

No socket comparison - captures everything.
When new opcode appears, auto-injects bypass.
"""
import os
import gc
import time

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_action_watch.txt"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    import threading
    lines = []
    seen_ops = {}
    baseline_ops = set()
    new_ops_list = []
    injected = [False]
    baseline_phase = [True]
    pkt_count = [0]

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[-500:]) + "\n")

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("ACTION WATCH v3 - no socket filter")
        log("=" * 60)

        proxy = None
        engine_globals = None
        for obj in gc.get_objects():
            try:
                if (hasattr(obj, 'crypto') and hasattr(obj, 'server_sock')
                        and hasattr(obj, 'inject_c2s')):
                    proxy = obj
                    if hasattr(obj, 'run') and hasattr(obj.run, '__func__'):
                        engine_globals = obj.run.__func__.__globals__
                    # Don't break - keep looking for one with live socket
                    sock = obj.server_sock
                    if sock and hasattr(sock, 'fileno'):
                        try:
                            if sock.fileno() != -1:
                                break  # Found live one
                        except:
                            pass
            except:
                pass

        if not engine_globals:
            log("FATAL: engine_globals not found")
            return

        send_fn = engine_globals.get('send_l2_packet')
        original_send = send_fn
        queue = proxy.inject_c2s if proxy else None

        log(f"proxy found: {proxy is not None}")
        log(f"queue: {type(queue).__name__ if queue is not None else 'None'}")

        def decode_game_body(body):
            if len(body) < 3 or body[0] != 0x06:
                return None
            inner = body[1:]
            m1 = inner[0]
            d = bytearray(len(inner))
            for i in range(len(inner)):
                d[i] = inner[i] ^ m1
            if len(d) >= 9 and all(b == 0 for b in d[1:8]):
                l1 = bytes(d[8:])
            else:
                l1 = bytes(d[1:])
            if len(l1) < 2:
                return None
            m2 = l1[0]
            l2 = bytes(b ^ m2 for b in l1)
            return l2[1:]

        def do_inject():
            if injected[0] or queue is None:
                return
            injected[0] = True
            log(f"\n[{time.strftime('%H:%M:%S')}] AUTO-INJECT triggered!")
            if len(queue) > 0:
                queue.clear()

            bypass = "multisell 81381".encode('utf-16-le') + b'\x00\x00'
            skip = {0x06, 0x0E, 0x11, 0x12, 0x2B, 0xCB}
            skip.update(baseline_ops)

            cnt = 0
            for op in range(256):
                if op in skip:
                    continue
                queue.append(bytes([op]) + bypass)
                cnt += 1
            log(f"Queued {cnt} BypassToServer packets")

        def hooked_send(sock_arg, body):
            """Intercept ALL send_l2_packet calls."""
            # Check if this is a relay 0x06 frame (C2S to server)
            if len(body) > 2 and body[0] == 0x06:
                gb = decode_game_body(body)
                if gb and len(gb) > 0:
                    op = gb[0]
                    pkt_count[0] += 1
                    seen_ops[op] = seen_ops.get(op, 0) + 1

                    if baseline_phase[0]:
                        baseline_ops.add(op)
                    elif op not in baseline_ops:
                        ts = time.strftime('%H:%M:%S')
                        log(f"\n*** NEW OPCODE 0x{op:02X} at {ts} ***")
                        log(f"    body ({len(gb)}b): {gb[:40].hex()}")
                        new_ops_list.append(op)
                        threading.Thread(target=do_inject, daemon=True).start()

                    if pkt_count[0] % 20 == 0:
                        ops = " ".join(f"{o:02X}({c})" for o, c in sorted(seen_ops.items()))
                        log(f"[{time.strftime('%H:%M:%S')}] #{pkt_count[0]} ops: {ops}")

            original_send(sock_arg, body)

        engine_globals['send_l2_packet'] = hooked_send
        log("Hook on send_l2_packet installed!")
        log("Baseline collection (5s)...")

        time.sleep(5)
        baseline_phase[0] = False
        log(f"Baseline: {' '.join(f'0x{o:02X}' for o in sorted(baseline_ops))}")
        log(f"Packets in baseline: {pkt_count[0]}")
        log(f"\n>>> CLICK ON NPC IN GAME! <<<")
        log(f"Hook will auto-inject BypassToServer when new opcode detected.\n")

        def _cleanup():
            time.sleep(180)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Cleanup.")
                log(f"Total pkts: {pkt_count[0]}, ops: {sorted(seen_ops.keys())}")
                log(f"New: {[f'0x{o:02X}' for o in new_ops_list]}, injected: {injected[0]}")

        threading.Thread(target=_cleanup, daemon=True).start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
