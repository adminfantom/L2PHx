"""Hot-patch: send Say2 DIRECTLY via server_sock, bypassing injection queue.

Tests whether the intermediate processes standalone relay packets
sent as separate TCP segments.
"""
import os
import gc
import struct
import time
import threading

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_direct_send.txt"
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
        server_lock = getattr(proxy, 'server_lock', None)
        if not server_sock:
            log("FATAL: no server_sock")
            return
        log(f"server_sock: {server_sock}")
        log(f"server_lock: {server_lock}")

        # Get wrap_relay_0x06 from engine globals
        wrap_fn = engine_globals.get('wrap_relay_0x06') if engine_globals else None
        if not wrap_fn:
            log("FATAL: no wrap_relay_0x06")
            return
        log(f"wrap_relay_0x06: {wrap_fn}")

        # Build Say2 "hello" plaintext
        def _encode_str(s):
            return s.encode("utf-16-le") + b'\x00\x00'

        say2_body = b'\x49' + _encode_str("hello") + struct.pack("<I", 0) + _encode_str("")
        log(f"Say2 body ({len(say2_body)} bytes): {say2_body.hex()}")

        # Wrap in relay
        relay_pkt = wrap_fn(say2_body)
        log(f"Relay packet ({len(relay_pkt)} bytes): {relay_pkt.hex()}")

        # L2 frame: [2B LE length] + body
        l2_frame = struct.pack("<H", len(relay_pkt) + 2) + relay_pkt
        log(f"L2 frame ({len(l2_frame)} bytes): {l2_frame.hex()}")

        # Send directly with a delay (separate TCP segment)
        def _delayed_send():
            try:
                time.sleep(0.5)  # 500ms delay to ensure separate TCP segment
                if server_lock:
                    with server_lock:
                        server_sock.sendall(l2_frame)
                else:
                    server_sock.sendall(l2_frame)
                log("SENT directly via server_sock (delayed 500ms)")
            except Exception as e:
                log(f"SEND ERROR: {e}")

        t = threading.Thread(target=_delayed_send, daemon=True)
        t.start()
        log("Delayed send thread started (500ms)")

        # Also try a second send after 2 seconds
        def _delayed_send2():
            try:
                time.sleep(2.0)
                # Build Say2 "test123"
                say2_body2 = b'\x49' + _encode_str("test123") + struct.pack("<I", 0) + _encode_str("")
                relay_pkt2 = wrap_fn(say2_body2)
                l2_frame2 = struct.pack("<H", len(relay_pkt2) + 2) + relay_pkt2
                if server_lock:
                    with server_lock:
                        server_sock.sendall(l2_frame2)
                else:
                    server_sock.sendall(l2_frame2)
                log(f"SENT Say2 'test123' directly (delayed 2s)")
            except Exception as e:
                log(f"SEND2 ERROR: {e}")

        t2 = threading.Thread(target=_delayed_send2, daemon=True)
        t2.start()
        log("Second delayed send thread started (2s)")

        log("DONE — check game chat for 'hello' and 'test123'")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
