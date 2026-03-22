"""Hot-patch: inject BypassToServer('multisell 81381') while NPC context is active.

User has warehouse NPC dialog open. Inject bypass with all possible opcodes.
Skip known auto-opcodes to minimize packet count.

Install via sys.remote_exec on running proxy PID.
"""
import os
import gc
import time

out_txt = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_bypass_npc.txt"
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
        log("BYPASS NPC INJECT - multisell 81381")
        log("=" * 60)

        proxy = None
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                    proxy = obj
                    sock = obj.server_sock
                    if sock and hasattr(sock, 'fileno'):
                        try:
                            if sock.fileno() != -1:
                                break
                        except:
                            pass
            except:
                pass

        if not proxy:
            log("FATAL: proxy not found")
            return

        queue = proxy.inject_c2s
        sock = proxy.server_sock

        if not sock or sock.fileno() == -1:
            log("FATAL: server_sock closed")
            return

        log(f"Socket alive (fd={sock.fileno()})")

        # Clear stale
        stale = len(queue)
        if stale > 0:
            queue.clear()
            log(f"Cleared {stale} stale items")

        # Known auto-opcodes to skip (this session + login + system)
        skip = {
            0x00, 0x02, 0x06, 0x09, 0x0A, 0x0B, 0x0C, 0x0E,
            0x11, 0x12, 0x14, 0x1C, 0x2B, 0x38, 0x3B, 0x3E,
            0x8E, 0xC0, 0xCB, 0xE0, 0xE2, 0xE4
        }

        bypass_str = "multisell 81381"

        # Format 1: [opcode] + UTF-16LE null-terminated (no length prefix)
        bypass_body1 = bypass_str.encode('utf-16-le') + b'\x00\x00'

        # Format 2: [opcode] + [uint16 strlen] + UTF-16LE null-terminated
        import struct
        strlen = len(bypass_str) + 1
        bypass_body2 = struct.pack('<H', strlen) + bypass_str.encode('utf-16-le') + b'\x00\x00'

        # Phase 1: Format 1 (simpler, most common in L2)
        log(f"\n--- PHASE 1: BypassToServer (no length prefix) ---")
        log(f"Payload: [op] + UTF16LE({bypass_str}) + null ({len(bypass_body1)}b)")

        count1 = 0
        for op in range(256):
            if op in skip:
                continue
            queue.append(bytes([op]) + bypass_body1)
            count1 += 1

        log(f"Queued {count1} packets")

        # Wait for relay loop to process
        for i in range(15):
            time.sleep(1)
            remaining = len(queue)
            if remaining == 0:
                log(f"  All sent after {i+1}s")
                break
            if i % 3 == 2:
                log(f"  After {i+1}s: {remaining} remaining")

        remaining = len(queue)
        if remaining > 0:
            log(f"  WARNING: {remaining} still in queue after 15s")
        else:
            log(f"  Phase 1 complete - all {count1} packets sent")

        # Small pause between phases
        time.sleep(2)

        # Phase 2: Format 2 (with length prefix)
        log(f"\n--- PHASE 2: BypassToServer (with length prefix) ---")
        log(f"Payload: [op] + uint16({strlen}) + UTF16LE + null ({len(bypass_body2)}b)")

        count2 = 0
        for op in range(256):
            if op in skip:
                continue
            queue.append(bytes([op]) + bypass_body2)
            count2 += 1

        log(f"Queued {count2} packets")

        for i in range(15):
            time.sleep(1)
            remaining = len(queue)
            if remaining == 0:
                log(f"  All sent after {i+1}s")
                break
            if i % 3 == 2:
                log(f"  After {i+1}s: {remaining} remaining")

        remaining = len(queue)
        if remaining > 0:
            log(f"  WARNING: {remaining} still in queue after 15s")
        else:
            log(f"  Phase 2 complete - all {count2} packets sent")

        log(f"\n{'='*60}")
        log(f"TOTAL: {count1 + count2} packets ({count1} + {count2})")
        log(f"Queue remaining: {len(queue)}")
        log(f"Done at {time.strftime('%H:%M:%S')}")
        log(f"CHECK GAME: multisell window should open if successful!")
        log(f"{'='*60}")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        log(traceback.format_exc())


_run()
