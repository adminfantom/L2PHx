"""Hot-patch: test if port 17453 stream is XOR-encrypted.

Captures raw C2S bodies and tests shadow XOR decryption.
If shadow-decrypted body starts with 0x06 (relay), stream IS encrypted.

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import time

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_stream_test.txt"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    lines = []

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[-500:]) + "\n")

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("STREAM ENCRYPTION TEST")
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

        crypto = proxy.crypto
        log(f"crypto.passthrough: {crypto.passthrough}")
        log(f"crypto.xor_only: {getattr(crypto, 'xor_only', 'N/A')}")
        log(f"crypto.xor_key: {crypto.xor_key.hex() if crypto.xor_key else None}")
        log(f"crypto.shadow_enabled: {crypto.shadow_enabled}")

        shadow_c2s = getattr(crypto, 'shadow_xor_c2s', None)
        shadow_s2c = getattr(crypto, 'shadow_xor_s2c', None)
        log(f"shadow_xor_c2s: {shadow_c2s}")
        log(f"shadow_xor_s2c: {shadow_s2c}")

        # Check shadow cipher state
        if shadow_c2s:
            log(f"shadow_c2s.key: {shadow_c2s.key.hex() if hasattr(shadow_c2s, 'key') else '?'}")
            for attr in ['_pos', '_counter', '_key', 'key', 'pos']:
                val = getattr(shadow_c2s, attr, 'N/A')
                if val != 'N/A':
                    if isinstance(val, bytes):
                        log(f"  shadow_c2s.{attr}: {val.hex()}")
                    else:
                        log(f"  shadow_c2s.{attr}: {val}")

        server_sock = getattr(proxy, 'server_sock', None)
        send_fn = engine_globals.get('send_l2_packet')
        original_send = send_fn

        # Capture next 10 C2S packets and test shadow decryption
        captured = []

        def hooked_send(sock, body):
            if sock is server_sock and len(body) > 1 and len(captured) < 10:
                # Try shadow decryption
                # Create a FRESH copy of shadow cipher for testing (don't advance real state)
                shadow_test = None
                try:
                    from copy import deepcopy
                    if shadow_c2s:
                        shadow_test = deepcopy(shadow_c2s)
                except:
                    pass

                info = {
                    "raw_hex": body[:32].hex(),
                    "raw_first": f"0x{body[0]:02X}",
                    "len": len(body),
                }

                if shadow_test:
                    try:
                        dec = shadow_test.decrypt(bytearray(body))
                        info["shadow_hex"] = bytes(dec[:32]).hex()
                        info["shadow_first"] = f"0x{dec[0]:02X}"
                        info["shadow_starts_06"] = dec[0] == 0x06
                    except Exception as e:
                        info["shadow_err"] = str(e)

                captured.append(info)
                ts = time.strftime('%H:%M:%S')
                log(f"\n[{ts}] C2S pkt #{len(captured)}: len={info['len']} raw_first={info['raw_first']}")
                log(f"  raw: {info['raw_hex']}")
                if 'shadow_hex' in info:
                    log(f"  shadow: {info['shadow_hex']}")
                    log(f"  shadow_starts_06: {info.get('shadow_starts_06')}")
                if 'shadow_err' in info:
                    log(f"  shadow_err: {info['shadow_err']}")

                if len(captured) >= 10:
                    # Unhook
                    engine_globals['send_l2_packet'] = original_send
                    # Summary
                    starts_06 = sum(1 for c in captured if c.get('shadow_starts_06'))
                    log(f"\n{'='*60}")
                    log(f"SUMMARY: {len(captured)} packets captured")
                    log(f"Shadow decrypt starts with 0x06: {starts_06}/{len(captured)}")
                    if starts_06 > 5:
                        log("CONCLUSION: Stream IS XOR-encrypted! Injections need encryption!")
                    else:
                        log("CONCLUSION: Stream is NOT XOR-encrypted. Issue is elsewhere.")
                    log(f"{'='*60}")

            original_send(sock, body)

        engine_globals['send_l2_packet'] = hooked_send
        log("STREAM TEST HOOK INSTALLED - capturing 10 C2S packets...")

        # Auto-remove after 60 seconds
        import threading
        def _auto_remove():
            time.sleep(60)
            if engine_globals.get('send_l2_packet') is hooked_send:
                engine_globals['send_l2_packet'] = original_send
                log(f"\n[{time.strftime('%H:%M:%S')}] Hook removed (timeout)")
                starts_06 = sum(1 for c in captured if c.get('shadow_starts_06'))
                log(f"Captured: {len(captured)}, shadow_06: {starts_06}")

        t = threading.Thread(target=_auto_remove, daemon=True)
        t.start()

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
