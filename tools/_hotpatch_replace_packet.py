"""Hot-patch: REPLACE next real C2S relay packet with Say2 "test_replace".

Instead of injecting extra packets (which intermediate drops),
we replace a real client packet so packet count stays the same.
"""
import os
import gc
import struct
import threading

out = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_hotpatch_replace_packet.txt"
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

        if not proxy:
            log("FATAL: proxy not found")
            return

        if not engine_globals:
            log("FATAL: cannot get engine_globals")
            return

        server_sock = getattr(proxy, 'server_sock', None)
        log(f"server_sock: {server_sock}")

        send_fn = engine_globals.get('send_l2_packet')
        wrap_fn = engine_globals.get('wrap_relay_0x06')
        if not send_fn or not wrap_fn:
            log(f"FATAL: send={send_fn}, wrap={wrap_fn}")
            return

        # Build Say2 "test_replace" plaintext game body
        def _encode_str(s):
            return s.encode("utf-16-le") + b'\x00\x00'

        say2_body = b'\x49' + _encode_str("test_replace") + struct.pack("<I", 0) + _encode_str("")
        say2_wrapped = wrap_fn(say2_body)
        log(f"Say2 body ({len(say2_body)} bytes): {say2_body.hex()}")
        log(f"Say2 wrapped ({len(say2_wrapped)} bytes): {say2_wrapped.hex()}")

        # State: replace the NEXT real C2S relay packet
        state = {"replaced": False, "count": 0}
        original_send = send_fn

        def hooked_send(sock, body):
            # Only intercept C2S relay to server_sock, skip first 2 packets (give game time)
            if sock is server_sock and not state["replaced"] and len(body) > 1 and body[0] == 0x06:
                state["count"] += 1
                if state["count"] >= 3:  # skip first 2 real packets, replace 3rd
                    # REPLACE: send our Say2 wrapped relay instead of real packet
                    state["replaced"] = True
                    engine_globals['send_l2_packet'] = original_send  # restore
                    log(f"REPLACING packet #{state['count']}: original {len(body)}B -> say2 {len(say2_wrapped)}B")
                    log(f"Original: {body[:40].hex()}")
                    log(f"Replacement: {say2_wrapped[:40].hex()}")
                    original_send(sock, say2_wrapped)
                    return
                else:
                    log(f"Skipping packet #{state['count']} ({len(body)}B): {body[:20].hex()}")

            # Default: pass through
            original_send(sock, body)

        # Install hook
        engine_globals['send_l2_packet'] = hooked_send
        log("Hook installed — will REPLACE 3rd C2S relay packet with Say2")
        log("Move your character to generate packets...")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())

_run()
