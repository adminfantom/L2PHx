"""Hot-patch: inject BypassToServer via inject_c2s queue (thread-safe).

Previous attempts failed due to:
1. Race condition: direct socket writes without server_lock
2. Socket was already closed when script ran

FIX: use proxy.inject_c2s queue. The relay loop processes it WITH server_lock.
Also: verify socket is alive, clear stale queue items first.

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import struct
import time

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_bypass_queue.txt"
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
        log("BYPASS QUEUE INJECTION v2 (THREAD-SAFE)")
        log("=" * 60)

        proxy = None
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                    proxy = obj
                    break
            except:
                pass

        if not proxy:
            log("FATAL: proxy not found")
            return

        queue = proxy.inject_c2s

        # Clear stale items from previous failed attempts
        stale = len(queue)
        if stale > 0:
            queue.clear()
            log(f"Cleared {stale} stale items from queue")

        sock = proxy.server_sock
        log(f"server_sock: {sock}")
        log(f"server_sock fileno: {sock.fileno() if sock else 'None'}")
        log(f"target_port: {getattr(proxy, '_target_port', 'N/A')}")

        # Verify socket is alive
        if not sock or sock.fileno() == -1:
            log("FATAL: server_sock is closed! Cannot inject.")
            return

        log(f"Socket is ALIVE (fd={sock.fileno()})")

        # BypassToServer format: [opcode] [UTF-16LE null-terminated string]
        bypass_str = "multisell 81381"
        bypass_body = bypass_str.encode('utf-16-le') + b'\x00\x00'

        # Skip known login/system opcodes
        skip = {0x00, 0x06, 0x0E, 0x11, 0x12, 0x2B, 0xCB}

        # Phase 1: BypassToServer with all opcodes
        log(f"\n--- PHASE 1: BypassToServer('multisell 81381') ---")
        log(f"Format: [opcode] + UTF-16LE null-terminated string ({len(bypass_body)} bytes)")

        count = 0
        for op in range(256):
            if op in skip:
                continue
            pkt = bytes([op]) + bypass_body
            queue.append(pkt)
            count += 1

        log(f"Queued {count} packets")

        # Wait for relay loop to process - check every second
        for i in range(10):
            time.sleep(1)
            remaining = len(queue)
            if remaining == 0:
                log(f"  All sent after {i+1}s")
                break
            if i % 3 == 2:
                log(f"  After {i+1}s: {remaining} remaining")

        remaining = len(queue)
        if remaining > 0:
            log(f"  WARNING: {remaining} items still in queue after 10s!")
        else:
            log(f"  Phase 1 complete - all {count} packets sent")

        # Phase 2: ExMultiSellList format
        log(f"\n--- PHASE 2: ExMultiSellList(81381) ---")
        log(f"Format: [opcode] + [9E 01] + [listId LE32]")

        list_id = 81381
        sub_bytes = struct.pack('<H', 0x019E)
        list_bytes = struct.pack('<I', list_id)

        count2 = 0
        for op in range(256):
            if op in skip:
                continue
            pkt = bytes([op]) + sub_bytes + list_bytes
            queue.append(pkt)
            count2 += 1

        log(f"Queued {count2} packets")

        for i in range(10):
            time.sleep(1)
            remaining = len(queue)
            if remaining == 0:
                log(f"  All sent after {i+1}s")
                break
            if i % 3 == 2:
                log(f"  After {i+1}s: {remaining} remaining")

        remaining = len(queue)
        if remaining > 0:
            log(f"  WARNING: {remaining} items still in queue after 10s!")
        else:
            log(f"  Phase 2 complete - all {count2} packets sent")

        # Phase 3: BypassToServer with length-prefix format
        log(f"\n--- PHASE 3: BypassToServer (length-prefixed) ---")
        log(f"Format: [opcode] + [strlen uint16] + [UTF-16LE + null]")

        strlen = len(bypass_str) + 1
        bypass_body_with_len = struct.pack('<H', strlen) + bypass_str.encode('utf-16-le') + b'\x00\x00'

        count3 = 0
        for op in range(256):
            if op in skip:
                continue
            pkt = bytes([op]) + bypass_body_with_len
            queue.append(pkt)
            count3 += 1

        log(f"Queued {count3} packets")

        for i in range(15):
            time.sleep(1)
            remaining = len(queue)
            if remaining == 0:
                log(f"  All sent after {i+1}s")
                break
            if i % 3 == 2:
                log(f"  After {i+1}s: {remaining} remaining")

        log(f"\n{'='*60}")
        log(f"TOTAL QUEUED: {count + count2 + count3}")
        log(f"Queue remaining: {len(queue)}")
        log(f"Done at {time.strftime('%H:%M:%S')}")
        log(f"{'='*60}")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
