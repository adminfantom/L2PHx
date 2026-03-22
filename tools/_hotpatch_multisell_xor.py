"""Hot-patch: auto-detect XOR key from keepalive, then inject multisell packets.

Strategy:
1. Hook send_l2_packet to capture C2S game bodies
2. Track the most frequent opcode = keepalive (assumed real opcode 0x00)
3. Extract key_even and key_odd from keepalive packets (null-byte positions)
4. Encrypt BypassToServer("multisell 81381") and ExMultiSellList(81381) with current key
5. Send directly

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import struct
import time
import json

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_multisell_xor.txt"
out_json = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_multisell_xor.json"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    import threading
    lines = []
    state = {
        "phase_opcode": None,     # current keepalive encrypted opcode
        "phase_count": {},        # count per encrypted opcode
        "phase_samples": {},      # samples per encrypted opcode
        "key_even": None,
        "key_odd": None,
        "injected": False,
        "packets_seen": 0,
        "phase_history": [],
    }

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[-500:]) + "\n")

    def save_json():
        export = dict(state)
        export["phase_count"] = {f"0x{k:02X}": v for k, v in state["phase_count"].items()}
        export["phase_samples"] = {f"0x{k:02X}": [s.hex() for s in v[:3]] for k, v in state["phase_samples"].items()}
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=2, default=str)

    def xor_encrypt(plaintext, ke, ko):
        """Apply 2-byte XOR cipher: even positions use ke, odd use ko."""
        result = bytearray(len(plaintext))
        for i in range(len(plaintext)):
            if i % 2 == 0:
                result[i] = plaintext[i] ^ ke
            else:
                result[i] = plaintext[i] ^ ko
        return bytes(result)

    def extract_key_from_keepalive(samples):
        """Extract key_even and key_odd from keepalive samples.

        Keepalive (real opcode 0x00): first byte XOR key_even = encrypted_opcode.
        So key_even = encrypted_opcode (since real = 0x00, 0x00 XOR key = key).

        key_odd: look at odd positions that should be zero (padding).
        Multiple samples - byte[1] should be consistent = key_odd.
        """
        if not samples:
            return None, None

        # key_even = opcode byte (since real opcode 0x00 XOR key_even = encrypted)
        ke = samples[0][0]

        # key_odd from position 1 (should be 0x00 in plaintext for keepalive)
        # Use majority vote across samples
        odd_bytes = {}
        for s in samples:
            if len(s) > 1:
                b = s[1]
                odd_bytes[b] = odd_bytes.get(b, 0) + 1

        if odd_bytes:
            ko = max(odd_bytes, key=odd_bytes.get)
        else:
            ko = 0

        return ke, ko

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("MULTISELL XOR AUTO-INJECT")
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
        original_send = send_fn

        if not all([server_sock, send_fn, wrap_fn]):
            log(f"FATAL: missing: sock={bool(server_sock)} send={bool(send_fn)} wrap={bool(wrap_fn)}")
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
            return game_body, {"type": pkt_type, "mask1": mask1, "mask2": mask2}

        def do_inject(ke, ko):
            """Inject multisell packets with current XOR key."""
            if state["injected"]:
                return
            state["injected"] = True

            ts = time.strftime('%H:%M:%S')
            log(f"\n{'='*60}")
            log(f"[{ts}] INJECTING with key_even=0x{ke:02X} key_odd=0x{ko:02X}")
            log(f"{'='*60}")

            # === Packet 1: BypassToServer (real opcode 0x23) ===
            # Format: [23] [len_as_uint16] [UTF-16LE string + null]
            # But in modern L2, BypassToServer format is: [23] [UTF-16LE null-terminated string]
            bypass_str = "multisell 81381"
            bypass_utf16 = bypass_str.encode('utf-16-le') + b'\x00\x00'
            # Packet body: opcode + string
            pkt1_plain = b'\x23' + bypass_utf16
            pkt1_enc = xor_encrypt(pkt1_plain, ke, ko)
            log(f"\nPkt1: BypassToServer('multisell 81381')")
            log(f"  plain: {pkt1_plain.hex()}")
            log(f"  encrypted: {pkt1_enc.hex()}")
            log(f"  len: {len(pkt1_enc)}")

            wrapped1 = wrap_fn(pkt1_enc)
            try:
                send_fn(server_sock, wrapped1)
                log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
            except Exception as e:
                log(f"  SEND ERROR: {e}")

            time.sleep(0.3)

            # === Packet 2: ExMultiSellList (real opcode 0xD0, sub 0x019E) ===
            # Format: [D0] [9E 01] [listId LE32]
            list_id = 81381
            pkt2_plain = b'\xD0' + struct.pack('<H', 0x019E) + struct.pack('<I', list_id)
            pkt2_enc = xor_encrypt(pkt2_plain, ke, ko)
            log(f"\nPkt2: ExMultiSellList({list_id})")
            log(f"  plain: {pkt2_plain.hex()}")
            log(f"  encrypted: {pkt2_enc.hex()}")

            wrapped2 = wrap_fn(pkt2_enc)
            try:
                send_fn(server_sock, wrapped2)
                log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
            except Exception as e:
                log(f"  SEND ERROR: {e}")

            time.sleep(0.3)

            # === Packet 3: BypassToServer with _mrsl format ===
            bypass_str2 = "_mrsl 81381"
            bypass_utf16_2 = bypass_str2.encode('utf-16-le') + b'\x00\x00'
            pkt3_plain = b'\x23' + bypass_utf16_2
            pkt3_enc = xor_encrypt(pkt3_plain, ke, ko)
            log(f"\nPkt3: BypassToServer('_mrsl 81381')")
            log(f"  encrypted: {pkt3_enc.hex()}")

            wrapped3 = wrap_fn(pkt3_enc)
            try:
                send_fn(server_sock, wrapped3)
                log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
            except Exception as e:
                log(f"  SEND ERROR: {e}")

            time.sleep(0.3)

            # === Packet 4: Try with key assumption that keepalive = 0x48 (ValidatePosition) ===
            # If our keepalive assumption is wrong, try alternative
            alt_ke = ke ^ 0x48  # if real opcode was 0x48 instead of 0x00
            alt_ko = ko  # odd key doesn't depend on opcode assumption the same way

            pkt4_plain = b'\x23' + bypass_utf16
            pkt4_enc = xor_encrypt(pkt4_plain, alt_ke, alt_ko)
            log(f"\nPkt4: BypassToServer (alt key, assuming keepalive=0x48)")
            log(f"  alt_ke=0x{alt_ke:02X} alt_ko=0x{alt_ko:02X}")
            log(f"  encrypted: {pkt4_enc.hex()}")

            wrapped4 = wrap_fn(pkt4_enc)
            try:
                send_fn(server_sock, wrapped4)
                log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
            except Exception as e:
                log(f"  SEND ERROR: {e}")

            # === Packet 5: Try UNENCRYPTED (maybe game body IS plaintext) ===
            pkt5_plain = b'\x23' + bypass_utf16
            log(f"\nPkt5: BypassToServer (UNENCRYPTED, raw plaintext)")
            log(f"  hex: {pkt5_plain.hex()}")

            wrapped5 = wrap_fn(pkt5_plain)
            try:
                send_fn(server_sock, wrapped5)
                log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
            except Exception as e:
                log(f"  SEND ERROR: {e}")

            time.sleep(0.3)

            # === Packet 6: ExMultiSellList UNENCRYPTED ===
            pkt6_plain = b'\xD0' + struct.pack('<H', 0x019E) + struct.pack('<I', list_id)
            log(f"\nPkt6: ExMultiSellList (UNENCRYPTED)")
            log(f"  hex: {pkt6_plain.hex()}")

            wrapped6 = wrap_fn(pkt6_plain)
            try:
                send_fn(server_sock, wrapped6)
                log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
            except Exception as e:
                log(f"  SEND ERROR: {e}")

            log(f"\n{'='*60}")
            log(f"ALL 6 PACKETS SENT at {time.strftime('%H:%M:%S')}")
            log(f"{'='*60}")
            save_json()

        def hooked_send(sock, body):
            if sock is server_sock and len(body) > 0 and body[0] == 0x06 and len(body) > 2:
                game_body, info = decode_relay_game_body(body)
                if game_body and len(game_body) > 0:
                    op = game_body[0]
                    state["packets_seen"] += 1

                    # Track opcode frequency
                    state["phase_count"][op] = state["phase_count"].get(op, 0) + 1
                    if op not in state["phase_samples"]:
                        state["phase_samples"][op] = []
                    if len(state["phase_samples"][op]) < 10:
                        state["phase_samples"][op].append(bytes(game_body))

                    # Detect most frequent = keepalive
                    if state["packets_seen"] >= 5 and not state["injected"]:
                        # Find the opcode with highest count
                        most_freq = max(state["phase_count"], key=state["phase_count"].get)
                        freq_count = state["phase_count"][most_freq]

                        if freq_count >= 4:
                            # Extract key from keepalive
                            ke, ko = extract_key_from_keepalive(
                                state["phase_samples"].get(most_freq, [])
                            )

                            if ke is not None:
                                state["key_even"] = ke
                                state["key_odd"] = ko
                                state["phase_opcode"] = most_freq

                                log(f"\n[{time.strftime('%H:%M:%S')}] Keepalive detected: 0x{most_freq:02X} (count={freq_count})")
                                log(f"  key_even=0x{ke:02X} key_odd=0x{ko:02X}")
                                log(f"  Samples seen: {state['packets_seen']}")

                                # Show all captured opcodes
                                for opc in sorted(state["phase_count"].keys()):
                                    cnt = state["phase_count"][opc]
                                    smpls = state["phase_samples"].get(opc, [])
                                    hex_preview = smpls[0].hex()[:60] if smpls else "?"
                                    log(f"  opcode 0x{opc:02X}: count={cnt} hex={hex_preview}")

                                # INJECT!
                                do_inject(ke, ko)

            original_send(sock, body)

        engine_globals['send_l2_packet'] = hooked_send
        log("XOR AUTO-INJECT HOOK INSTALLED!")
        log("Waiting for 5+ keepalive packets to extract key...")
        log("Then auto-injecting multisell packets.")
        log("")

        # Auto-remove after 120 seconds
        def _auto_remove():
            time.sleep(120)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Hook removed after 2min")
                log(f"Total packets: {state['packets_seen']}")
                log(f"Injected: {state['injected']}")
                save_json()

        t = threading.Thread(target=_auto_remove, daemon=True)
        t.start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
