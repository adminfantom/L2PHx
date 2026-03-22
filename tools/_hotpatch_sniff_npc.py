"""
Hot-patch: real-time S2C sniff monitor for NPC interaction on port 7777.
Installs a background thread that watches for NPC HTML, dialog open, and
multisell-related S2C packets. Extracts NPC objectId automatically.

When NPC objectId found:
  1. Injects C2S Action (0x1F) with objectId
  2. Waits 500ms
  3. Injects bypass "multisell 81381"
  4. Waits 1s
  5. Injects MultiSellChoose entries 1,3,5,7
"""
import os
import gc
import time
import struct
import threading
import json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_sniff_npc.txt"
OUT_JSON = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_sniff_npc.json"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

LOG_LINES = []
DATA = {'npc_objects': {}, 'multisell_seen': False}


def log(s):
    ts = time.strftime('%H:%M:%S')
    msg = f"[{ts}] {s}"
    LOG_LINES.append(msg)
    try:
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(LOG_LINES[-500:]) + "\n")
    except:
        pass
    print(msg)


def save_json():
    try:
        with open(OUT_JSON, "w", encoding="utf-8") as f:
            json.dump(DATA, f, indent=2)
    except:
        pass


def build_action(object_id, shift=0):
    return struct.pack("<BIIIIb", 0x1F, object_id, 0, 0, 0, shift)


def build_bypass(command):
    encoded = command.encode('utf-16-le') + b'\x00\x00'
    return b'\x23' + struct.pack('<H', len(command) + 1) + encoded


def build_multisell_choose(list_id, entry_id, amount=1):
    return struct.pack("<BIIq", 0xB0, list_id, entry_id, amount) + b'\x00' * 24


def try_inject_multisell(proxy, npc_object_id, list_id=81381):
    """Full injection sequence: Action -> bypass -> MultiSellChoose x4"""
    entries = [1, 3, 5, 7]

    log(f"=== FULL INJECTION SEQUENCE ===")
    log(f"NPC objectId: {npc_object_id} (0x{npc_object_id:08X})")

    # 1. Click NPC (Action)
    action_pkt = build_action(npc_object_id, 0)
    proxy.inject_c2s.append(action_pkt)
    log(f"  [1] Injected Action(objectId={npc_object_id}) sz={len(action_pkt)}")
    time.sleep(0.8)

    # 2. Send bypass
    bypass_pkt = build_bypass(f"multisell {list_id}")
    proxy.inject_c2s.append(bypass_pkt)
    log(f"  [2] Injected bypass 'multisell {list_id}' sz={len(bypass_pkt)}")
    time.sleep(1.2)

    # 3. MultiSellChoose x4
    for entry_id in entries:
        pkt = build_multisell_choose(list_id, entry_id, 1)
        proxy.inject_c2s.append(pkt)
        log(f"  [3] Injected MultiSellChoose list={list_id} entry={entry_id}")
        time.sleep(0.1)

    log(f"=== INJECTION SEQUENCE DONE ===")


def decode_npc_html(data, opcode):
    """Try to decode NpcHtmlMessage from raw packet body."""
    results = {}

    # Common NpcHtmlMessage formats:
    # Format A (old): opcode(1) + objectId(4) + html(utf16le null-term)
    # Format B (new): opcode(1) + objectId(4) + html_len(2) + html(utf16le)

    if len(data) < 5:
        return results

    try:
        obj_id = struct.unpack_from('<I', data, 0)[0]
        results['object_id_raw'] = obj_id

        # Validate objectId (must be in typical L2 range)
        # L2 server object IDs: 0x40000000 - 0x50000000 or similar
        if 0x10000000 <= obj_id <= 0x80000000:
            results['object_id_valid'] = obj_id

        # Try to decode html text
        html_data = data[4:]
        if len(html_data) > 4:
            # Try without length prefix
            html_txt = html_data.decode('utf-16-le', errors='replace')[:500]
            if '<html>' in html_txt.lower() or '<br>' in html_txt.lower() or 'bypass' in html_txt.lower():
                results['html'] = html_txt
                results['has_html'] = True

                # Check for multisell bypass
                if 'multisell' in html_txt.lower() or '81381' in html_txt:
                    results['has_multisell_81381'] = True
    except:
        pass

    return results


def monitor_thread():
    log("=== SNIFF NPC MONITOR STARTED ===")

    # Find proxy
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

    log(f"Proxy: {type(proxy).__name__}")

    # Find store
    store = getattr(proxy, 'store', None)
    if not store:
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'packets') and hasattr(obj, 'add') and hasattr(obj, 'get_recent'):
                    store = obj
                    break
            except:
                pass

    log(f"Store: {type(store).__name__ if store else 'NOT FOUND'}")

    if not store:
        log("FATAL: store not found")
        return

    # Track processed packets
    last_seq = 0
    processed_npc_ids = set()
    inject_cooldown = 0

    # S2C opcodes that might contain NPC interaction
    # In L2 Ertheia, common NPC-related S2C opcodes:
    NPC_LIKELY_OPCODES = {
        0x1B,  # NpcHtmlMessage
        0x0D,  # Die (can have target)
        0x16,  # StatusUpdate
        0x22,  # CreatureSay
        0x2E,  # ExShowScreenMessage or KeyInit
        0x3E,  # NpcHtmlMessage variant
        0x7B,  # ShowBoard
        0x81,  # SellList (or similar)
        0x8D,  # ShopPreviewList
        0xA1,  # ExShowList or similar
        0xFE,  # ExPacket (2-byte opcode follows)
    }

    iteration = 0

    while True:
        try:
            time.sleep(0.15)
            iteration += 1

            now_ts = time.time()

            # Get recent packets
            try:
                pkts = store.get_recent(100)
            except:
                continue

            new_npc_found = None

            for p in pkts:
                if not isinstance(p, dict):
                    continue
                seq = p.get('seq', 0)
                if seq <= last_seq:
                    continue

                d = str(p.get('dir', p.get('direction', ''))).upper()
                if 'S2C' not in d:
                    continue

                op = p.get('opcode', 0)
                if isinstance(op, str):
                    try:
                        op = int(op, 16) if op.startswith('0x') else int(op)
                    except:
                        op = 0

                name = str(p.get('name', ''))
                dec = p.get('dec_hex', p.get('hex', ''))

                # Log any new large S2C packet
                if seq > last_seq and len(dec) > 20:
                    if 'sniff' in name.lower() or op in NPC_LIKELY_OPCODES:
                        log(f"[seq={seq}] S2C op=0x{op:02X} name={name} len={len(dec)//2}")

                # Try to parse NPC HTML from any S2C packet
                if dec and len(dec) > 10:
                    try:
                        raw = bytes.fromhex(dec)

                        # Skip opcode byte (index 0), parse from index 1
                        # (opcode is separate in dec_hex vs raw)
                        payload = raw[1:] if len(raw) > 1 else raw

                        npc_info = decode_npc_html(payload, op)

                        if npc_info.get('has_html') and npc_info.get('object_id_valid'):
                            obj_id = npc_info['object_id_valid']
                            html = npc_info.get('html', '')
                            log(f"\n*** NPC HTML DETECTED! ***")
                            log(f"  seq={seq} op=0x{op:02X} objectId={obj_id} (0x{obj_id:08X})")
                            log(f"  HTML snippet: {html[:200]}")

                            DATA['npc_objects'][hex(obj_id)] = {
                                'object_id': obj_id,
                                'seq': seq,
                                'op': hex(op),
                                'html_snippet': html[:300],
                                'has_multisell': npc_info.get('has_multisell_81381', False)
                            }
                            save_json()

                            if npc_info.get('has_multisell_81381'):
                                log(f"  *** MULTISELL 81381 NPC! objectId={obj_id} ***")
                                if now_ts > inject_cooldown and obj_id not in processed_npc_ids:
                                    processed_npc_ids.add(obj_id)
                                    inject_cooldown = now_ts + 10.0
                                    new_npc_found = obj_id

                        # Also: look for objectId in any sniff packet
                        # by checking if objectId at various offsets is valid
                        if op in NPC_LIKELY_OPCODES and len(raw) >= 5:
                            for offset in [0, 1]:
                                if offset + 4 <= len(raw):
                                    candidate = struct.unpack_from('<I', raw, offset)[0]
                                    if 0x20000000 <= candidate <= 0x70000000:
                                        log(f"  Possible objectId at offset {offset}: {candidate} (0x{candidate:08X})")

                        # Search for "multisell" string in decoded bytes
                        if len(raw) > 8:
                            txt = raw.decode('utf-16-le', errors='replace')
                            if 'multisell' in txt.lower() or '81381' in txt:
                                log(f"\n*** MULTISELL TEXT in S2C seq={seq} op=0x{op:02X}! ***")
                                log(f"  text: {txt[:200]}")
                                DATA['multisell_seen'] = True
                                save_json()

                    except Exception as e:
                        pass

                if seq > last_seq:
                    last_seq = seq

            # If we found a multisell NPC, inject
            if new_npc_found and now_ts > inject_cooldown:
                inject_cooldown = now_ts + 15.0
                log(f"\nAUTO-INJECT triggered for NPC objectId={new_npc_found}")
                try_inject_multisell(proxy, new_npc_found)

            # Periodic status
            if iteration % 200 == 0:
                log(f"[STATUS] iter={iteration} last_seq={last_seq} npc_count={len(DATA['npc_objects'])}")

        except Exception as e:
            log(f"Thread error: {e}")
            import traceback
            log(traceback.format_exc())
            time.sleep(1)


def _run():
    log(f"=== SNIFF NPC HOTPATCH ===")
    log(f"PID: {os.getpid()} Time: {time.strftime('%H:%M:%S')}")

    # Check if already running
    for t in threading.enumerate():
        if t.name == 'sniff_npc_monitor':
            log("Thread already running, starting fresh one anyway")
            break

    t = threading.Thread(target=monitor_thread, name='sniff_npc_monitor', daemon=True)
    t.start()
    log(f"Thread started: {t.name} id={t.ident}")


_run()
