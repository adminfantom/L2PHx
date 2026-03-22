"""Hot-patch: capture next real client relay packet and replay it 1s later.

If the replay works (game server processes it), the transport is fine and
the issue is in our packet format.
If replay doesn't work, the intermediate filters extra packets.

Also: captures the raw encrypted game_body to check if XOR is applied.
"""
import os
import gc
import struct
import time
import threading

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_replay_test.txt"
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

        if not proxy:
            log("FATAL: proxy not found")
            return

        server_sock = getattr(proxy, 'server_sock', None)
        log(f"server_sock: {server_sock}")

        # Hook into the relay handler to capture next packet
        # Monkey-patch send_l2_packet to intercept the next real C2S relay forward
        send_fn = engine_globals.get('send_l2_packet') if engine_globals else None
        if not send_fn:
            log("FATAL: no send_l2_packet")
            return

        # State
        state = {
            "captured": False,
            "raw_frame": None,
            "replay_sent": False,
        }

        original_send = send_fn

        def hooked_send(sock, body):
            # Call original first
            original_send(sock, body)

            # Only intercept C2S to server_sock (not S2C)
            if sock is server_sock and not state["captured"] and len(body) > 10 and body[0] == 0x06:
                # This is a real client relay packet being forwarded
                l2_frame = struct.pack("<H", len(body) + 2) + body
                state["captured"] = True
                state["raw_frame"] = l2_frame
                log(f"CAPTURED relay forward: {len(body)} bytes, body[:40]={body[:40].hex()}")

                # Restore original send to avoid recursion
                engine_globals['send_l2_packet'] = original_send

                # Replay after delay in separate thread
                def _replay():
                    time.sleep(1.0)
                    try:
                        sock.sendall(l2_frame)
                        state["replay_sent"] = True
                        log(f"REPLAY SENT: {len(l2_frame)} bytes (1s delay)")
                    except Exception as e:
                        log(f"REPLAY ERROR: {e}")

                    # Also send a custom Say2 2s later
                    time.sleep(1.0)
                    try:
                        # Build Say2 "replay_ok" plaintext
                        text = "replay_ok".encode("utf-16-le") + b'\x00\x00'
                        say2 = b'\x49' + text + struct.pack("<I", 0) + b'\x00\x00'
                        log(f"Say2 plaintext ({len(say2)} bytes): {say2.hex()}")

                        # Wrap in relay
                        wrap_fn = engine_globals.get('wrap_relay_0x06')
                        if wrap_fn:
                            wrapped = wrap_fn(say2)
                            frame = struct.pack("<H", len(wrapped) + 2) + wrapped
                            sock.sendall(frame)
                            log(f"CUSTOM Say2 SENT: {len(frame)} bytes (2s delay)")
                        else:
                            log("No wrap_relay_0x06!")
                    except Exception as e:
                        log(f"CUSTOM Say2 ERROR: {e}")

                    # Dump XOR key analysis
                    try:
                        crypto = getattr(proxy, 'crypto', None)
                        if crypto:
                            xor_c2s = getattr(crypto, 'shadow_xor_c2s', None)
                            if xor_c2s:
                                log(f"shadow_xor_c2s key: {bytes(xor_c2s.key).hex()}")
                                counter = struct.unpack_from("<I", xor_c2s.key, 8)[0]
                                log(f"shadow counter: 0x{counter:08X} ({counter})")
                    except:
                        pass

                t = threading.Thread(target=_replay, daemon=True)
                t.start()

        # Install hook
        engine_globals['send_l2_packet'] = hooked_send
        log("Hook installed — waiting for next C2S relay packet...")
        log("(hook auto-removes after first capture)")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
