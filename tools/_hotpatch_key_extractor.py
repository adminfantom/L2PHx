"""Hot-patch: extract per-opcode XOR keys from game traffic.

Monitors ALL C2S game bodies. For each opcode, extracts the 2-byte
XOR key (key_even, key_odd) from zero-plaintext positions at the tail
of packets. Tracks key rotation between phases.

Provides encrypt/decrypt for arbitrary packets using extracted keys.
When new opcodes appear (user actions), logs them with full detail.

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import struct
import time
import threading
import json

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_key_extractor.txt"
out_json = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_key_extractor.json"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    lines = []
    # Per-opcode tracking: {enc_op: {count, key_even, key_odd, samples, sizes, ...}}
    opcode_db = {}
    phase_history = []  # [{ts, periodic_op, key_even, key_odd}]
    current_periodic_op = None
    periodic_count = 0

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def save_json():
        export = {
            "phase_history": phase_history[-20:],
            "opcodes": {},
            "current_periodic": hex(current_periodic_op) if current_periodic_op is not None else None,
        }
        for op, info in sorted(opcode_db.items()):
            export["opcodes"][f"0x{op:02X}"] = {
                "count": info["count"],
                "key_even": f"0x{info['key_even']:02X}" if info["key_even"] is not None else None,
                "key_odd": f"0x{info['key_odd']:02X}" if info["key_odd"] is not None else None,
                "key_confidence": info.get("key_confidence", 0),
                "sizes": sorted(info["sizes"])[:20],
                "first_hex": info["first_hex"][:120],
                "last_hex": info.get("last_hex", "")[:120],
                "is_periodic": info.get("is_periodic", False),
                "samples": info.get("samples", [])[:3],
            }
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, ensure_ascii=False)

    def extract_key(game_body):
        """Extract 2-byte XOR key from a game body using tail-zero detection.

        Strategy: scan from the end of the packet for positions where
        the byte value repeats consistently at even/odd positions.
        The repeating value at zero-plaintext positions = key byte.
        """
        if len(game_body) < 10:
            return None, None, 0

        data = game_body
        n = len(data)

        # Collect even and odd position bytes from the tail
        even_tail = []  # (pos, byte) from end
        odd_tail = []
        for i in range(n - 1, max(n - 30, 0), -1):
            if i % 2 == 0:
                even_tail.append(data[i])
            else:
                odd_tail.append(data[i])

        key_even = None
        key_odd = None
        confidence = 0

        # For even positions: find most common byte in tail
        if len(even_tail) >= 3:
            from collections import Counter
            ec = Counter(even_tail)
            most_common_byte, count = ec.most_common(1)[0]
            if count >= 3 and count >= len(even_tail) * 0.5:
                key_even = most_common_byte
                confidence += count

        # For odd positions
        if len(odd_tail) >= 3:
            from collections import Counter
            oc = Counter(odd_tail)
            most_common_byte, count = oc.most_common(1)[0]
            if count >= 3 and count >= len(odd_tail) * 0.5:
                key_odd = most_common_byte
                confidence += count

        return key_even, key_odd, confidence

    def extract_key_multi(samples):
        """Extract key from multiple samples of the same opcode.

        Uses cross-sample analysis: at zero-plaintext positions,
        the encrypted byte should be identical across all samples
        (same key, same plaintext=0).
        """
        if len(samples) < 2:
            return None, None, 0

        # Find minimum common length
        min_len = min(len(s) for s in samples)
        if min_len < 4:
            return None, None, 0

        key_even = None
        key_odd = None
        confidence = 0

        # For each position, check if all samples have the same byte
        even_candidates = {}  # byte -> count of positions where all match
        odd_candidates = {}

        for pos in range(min(min_len, 60)):
            vals = [s[pos] for s in samples if pos < len(s)]
            if len(vals) >= 2 and len(set(vals)) == 1:
                # All samples agree at this position
                b = vals[0]
                if pos % 2 == 0:
                    even_candidates[b] = even_candidates.get(b, 0) + 1
                else:
                    odd_candidates[b] = odd_candidates.get(b, 0) + 1

        # The key byte is the value that appears at most positions
        if even_candidates:
            best = max(even_candidates.items(), key=lambda x: x[1])
            if best[1] >= 3:
                key_even = best[0]
                confidence += best[1]

        if odd_candidates:
            best = max(odd_candidates.items(), key=lambda x: x[1])
            if best[1] >= 3:
                key_odd = best[0]
                confidence += best[1]

        return key_even, key_odd, confidence

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("XOR KEY EXTRACTOR + ACTION MONITOR")
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
        client_sock = getattr(proxy, 'client_sock', None)
        send_fn = engine_globals.get('send_l2_packet')
        wrap_fn = engine_globals.get('wrap_relay_0x06')

        if not send_fn:
            log("FATAL: no send_l2_packet")
            return

        log(f"server_sock: {server_sock}")
        log(f"wrap_relay_0x06: {'YES' if wrap_fn else 'NO'}")

        original_send = send_fn
        baseline_ts = time.time()
        known_ops = set()
        raw_samples = {}  # op -> [bytes, bytes, ...]

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
            nonlocal current_periodic_op, periodic_count
            if sock is server_sock and len(body) > 0:
                if body[0] == 0x06 and len(body) > 2:
                    game_body, info = decode_relay_game_body(body)
                    if game_body and len(game_body) > 0 and not info.get("padding"):
                        op = game_body[0]
                        ts = time.strftime('%H:%M:%S')
                        elapsed = time.time() - baseline_ts

                        # Track samples
                        if op not in raw_samples:
                            raw_samples[op] = []
                        if len(raw_samples[op]) < 10:
                            raw_samples[op].append(bytes(game_body))

                        if op not in opcode_db:
                            opcode_db[op] = {
                                "count": 0,
                                "key_even": None,
                                "key_odd": None,
                                "key_confidence": 0,
                                "first_ts": ts,
                                "first_hex": game_body.hex(),
                                "sizes": set(),
                                "samples": [],
                                "is_periodic": False,
                            }
                            # NEW OPCODE
                            log(f"")
                            log(f">>> NEW OPCODE 0x{op:02X} at {ts} (+{elapsed:.1f}s) <<<")
                            log(f"    len={len(game_body)} type={info.get('type')}")
                            log(f"    hex={game_body[:64].hex()}")
                            log(f"    relay={body[:64].hex()}")

                            # Check if this is periodic or action
                            if op not in known_ops:
                                log(f"    ** POSSIBLE USER ACTION! New opcode 0x{op:02X} **")
                            known_ops.add(op)

                        opcode_db[op]["count"] += 1
                        opcode_db[op]["sizes"].add(len(game_body))
                        opcode_db[op]["last_hex"] = game_body[:64].hex()

                        if len(opcode_db[op]["samples"]) < 5:
                            opcode_db[op]["samples"].append({
                                "ts": ts, "len": len(game_body),
                                "hex": game_body[:80].hex()
                            })

                        # Try to extract key from this single packet
                        ke, ko, conf = extract_key(game_body)
                        if conf > opcode_db[op].get("key_confidence", 0):
                            opcode_db[op]["key_even"] = ke
                            opcode_db[op]["key_odd"] = ko
                            opcode_db[op]["key_confidence"] = conf
                            if ke is not None or ko is not None:
                                real_op = (op ^ ke) if ke is not None else None
                                log(f"    KEY for 0x{op:02X}: even=0x{ke:02X if ke is not None else '??'} odd=0x{ko:02X if ko is not None else '??'} conf={conf} real_op={f'0x{real_op:02X}' if real_op is not None else '?'}")

                        # Multi-sample key extraction
                        if len(raw_samples.get(op, [])) >= 3:
                            ke2, ko2, conf2 = extract_key_multi(raw_samples[op])
                            if conf2 > opcode_db[op].get("key_confidence", 0):
                                opcode_db[op]["key_even"] = ke2
                                opcode_db[op]["key_odd"] = ko2
                                opcode_db[op]["key_confidence"] = conf2
                                real_op = (op ^ ke2) if ke2 is not None else None
                                log(f"    MULTI-KEY 0x{op:02X}: even=0x{ke2:02X if ke2 is not None else '??'} odd=0x{ko2:02X if ko2 is not None else '??'} conf={conf2} real_op={f'0x{real_op:02X}' if real_op is not None else '?'}")

                        # Detect periodic opcode changes
                        if current_periodic_op is None or current_periodic_op == op:
                            current_periodic_op = op
                            periodic_count += 1
                        elif opcode_db[op]["count"] > 3:
                            # This opcode has taken over as periodic
                            old_op = current_periodic_op
                            old_ke = opcode_db.get(old_op, {}).get("key_even")
                            new_ke = opcode_db[op].get("key_even")
                            log(f"\n[{ts}] PHASE CHANGE: 0x{old_op:02X} -> 0x{op:02X}")
                            if old_ke is not None and new_ke is not None:
                                log(f"    key_even rotation: 0x{old_ke:02X} -> 0x{new_ke:02X} (delta 0x{old_ke ^ new_ke:02X})")
                            phase_history.append({
                                "ts": ts, "old_op": f"0x{old_op:02X}",
                                "new_op": f"0x{op:02X}",
                                "old_key_even": f"0x{old_ke:02X}" if old_ke is not None else None,
                                "new_key_even": f"0x{new_ke:02X}" if new_ke is not None else None,
                            })
                            current_periodic_op = op
                            periodic_count = opcode_db[op]["count"]
                            opcode_db[op]["is_periodic"] = True

                        # Periodic summary
                        total = sum(info2["count"] for info2 in opcode_db.values())
                        if total % 50 == 0:
                            save_json()
                            op_summary = ", ".join(
                                f"0x{o:02X}({opcode_db[o]['count']})"
                                for o in sorted(opcode_db.keys())
                            )
                            log(f"[{ts}] total={total} opcodes: {op_summary}")
                            # Log all extracted keys
                            for o in sorted(opcode_db.keys()):
                                ke = opcode_db[o].get("key_even")
                                ko = opcode_db[o].get("key_odd")
                                if ke is not None or ko is not None:
                                    real = (o ^ ke) if ke is not None else None
                                    log(f"    0x{o:02X}: ke={f'0x{ke:02X}' if ke is not None else '?'} ko={f'0x{ko:02X}' if ko is not None else '?'} -> real={f'0x{real:02X}' if real is not None else '?'}")

            original_send(sock, body)

        # Install hook
        engine_globals['send_l2_packet'] = hooked_send
        log("KEY EXTRACTOR HOOK INSTALLED!")
        log("Monitors ALL traffic and extracts per-opcode XOR keys.")
        log("Perform actions in game to discover new opcodes:")
        log("  - USE an item from inventory")
        log("  - TARGET an NPC or monster")
        log("  - SIT/STAND (Alt+X)")
        log("  - OPEN inventory (Alt+I) or skill list")
        log("  - TRY TO MOVE (click on ground)")
        log("Each NEW opcode = new packet type discovered!")
        log("")

        # Auto-remove after 3600 seconds (60 min)
        def _auto_remove():
            time.sleep(3600)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Hook auto-removed after 60min")
                log(f"SUMMARY: {len(opcode_db)} unique opcodes:")
                for op in sorted(opcode_db.keys()):
                    info2 = opcode_db[op]
                    ke = info2.get("key_even")
                    ko = info2.get("key_odd")
                    real = (op ^ ke) if ke is not None else None
                    log(f"  0x{op:02X}: count={info2['count']} ke={f'0x{ke:02X}' if ke is not None else '?'} ko={f'0x{ko:02X}' if ko is not None else '?'} real={f'0x{real:02X}' if real is not None else '?'} sizes={sorted(info2['sizes'])[:15]}")
                log(f"\nPhase history ({len(phase_history)} transitions):")
                for ph in phase_history:
                    log(f"  {ph['ts']}: {ph['old_op']} -> {ph['new_op']} (ke: {ph.get('old_key_even')} -> {ph.get('new_key_even')})")
                save_json()

        t = threading.Thread(target=_auto_remove, daemon=True)
        t.start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
