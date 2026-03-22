"""Hot-patch: inject ExMultiSellList(81381) + RequestBypassToServer(multisell 81381) directly.

Bypasses the queue mechanism by sending directly via server socket.
Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import struct
import time

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_multisell_inject.txt"
os.makedirs(os.path.dirname(out_txt), exist_ok=True)


def _run():
    import traceback
    lines = []

    def log(s):
        lines.append(s)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    try:
        log(f"PID: {os.getpid()}")
        log(f"Time: {time.strftime('%H:%M:%S')}")
        log("=" * 60)
        log("MULTISELL INJECTION - DIRECT SOCKET SEND")
        log("=" * 60)

        # Find proxy object
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

        if not server_sock:
            log("FATAL: no server_sock")
            return
        if not send_fn:
            log("FATAL: no send_l2_packet")
            return
        if not wrap_fn:
            log("FATAL: no wrap_relay_0x06")
            return

        log(f"server_sock: {server_sock}")
        log(f"target_port: {getattr(proxy, '_target_port', 'NOT SET')}")
        log(f"inject_c2s queue: {len(proxy.inject_c2s)} items pending")

        # ══════════════════════════════════════════════════════════
        # Packet 1: ExMultiSellList (D0:019E) with listId=81381
        # Format: [D0] [9E 01] [listId as LE uint32]
        # ══════════════════════════════════════════════════════════
        list_id = 81381
        pkt1 = b'\xD0' + struct.pack('<H', 0x019E) + struct.pack('<I', list_id)
        log(f"\nPacket 1: ExMultiSellList({list_id})")
        log(f"  hex: {pkt1.hex()}")
        log(f"  len: {len(pkt1)}")

        # Wrap in relay 0x06 and send
        wrapped1 = wrap_fn(pkt1)
        log(f"  relay hex: {wrapped1.hex()}")
        log(f"  relay len: {len(wrapped1)}")

        try:
            send_fn(server_sock, wrapped1)
            log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
        except Exception as e:
            log(f"  SEND ERROR: {e}")

        time.sleep(0.5)

        # ══════════════════════════════════════════════════════════
        # Packet 2: RequestBypassToServer (0x23) with "multisell 81381"
        # Format: [23] [UTF-16LE null-terminated string]
        # ══════════════════════════════════════════════════════════
        bypass_str = "multisell 81381"
        bypass_encoded = bypass_str.encode('utf-16-le') + b'\x00\x00'
        pkt2 = b'\x23' + bypass_encoded
        log(f"\nPacket 2: RequestBypassToServer(\"{bypass_str}\")")
        log(f"  hex: {pkt2.hex()}")
        log(f"  len: {len(pkt2)}")

        wrapped2 = wrap_fn(pkt2)
        log(f"  relay hex: {wrapped2.hex()}")
        log(f"  relay len: {len(wrapped2)}")

        try:
            send_fn(server_sock, wrapped2)
            log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
        except Exception as e:
            log(f"  SEND ERROR: {e}")

        time.sleep(0.5)

        # ══════════════════════════════════════════════════════════
        # Packet 3: RequestBypassToServer with "_mrsl 81381" (alt format)
        # ══════════════════════════════════════════════════════════
        bypass_str2 = "_mrsl 81381"
        bypass_encoded2 = bypass_str2.encode('utf-16-le') + b'\x00\x00'
        pkt3 = b'\x23' + bypass_encoded2
        log(f"\nPacket 3: RequestBypassToServer(\"{bypass_str2}\")")
        log(f"  hex: {pkt3.hex()}")
        log(f"  len: {len(pkt3)}")

        wrapped3 = wrap_fn(pkt3)
        try:
            send_fn(server_sock, wrapped3)
            log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
        except Exception as e:
            log(f"  SEND ERROR: {e}")

        time.sleep(0.5)

        # ══════════════════════════════════════════════════════════
        # Packet 4: ExMultiSellList with byte variation (just listId, no extra)
        # Some servers expect: [D0] [9E 01] [listId LE32] [0x01 byte]
        # ══════════════════════════════════════════════════════════
        pkt4 = b'\xD0' + struct.pack('<H', 0x019E) + struct.pack('<I', list_id) + b'\x01'
        log(f"\nPacket 4: ExMultiSellList({list_id}) + byte(1)")
        log(f"  hex: {pkt4.hex()}")

        wrapped4 = wrap_fn(pkt4)
        try:
            send_fn(server_sock, wrapped4)
            log(f"  SENT OK at {time.strftime('%H:%M:%S')}")
        except Exception as e:
            log(f"  SEND ERROR: {e}")

        log(f"\n{'=' * 60}")
        log(f"ALL 4 PACKETS SENT at {time.strftime('%H:%M:%S')}")
        log(f"Check S2C packets for multisell list response (opcode 0xD0 or 0xFE:0185)")
        log(f"{'=' * 60}")

        # Drain any pending queued injections too
        pending = len(proxy.inject_c2s)
        if pending > 0:
            log(f"\nDraining {pending} queued injections...")
            while proxy.inject_c2s:
                queued_pkt = proxy.inject_c2s.popleft()
                wrapped_q = wrap_fn(queued_pkt)
                try:
                    send_fn(server_sock, wrapped_q)
                    log(f"  Queued pkt sent: op=0x{queued_pkt[0]:02X} len={len(queued_pkt)}")
                except Exception as e:
                    log(f"  Queued pkt error: {e}")
            log(f"Queue drained.")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
