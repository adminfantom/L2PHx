"""Hot-patch: scan store for S2C NPC HTML packets to find multisell NPC objectId."""
import os
import gc
import time
import json
import struct

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_npc_scan.txt"
OUT_JSON = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_npc_scan.json"
os.makedirs(os.path.dirname(OUT), exist_ok=True)


def _run():
    import traceback
    lines = []

    def log(s):
        lines.append(s)
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    try:
        log(f"PID: {os.getpid()} Time: {time.strftime('%H:%M:%S')}")

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

        store = getattr(proxy, 'store', None)
        if not store:
            for obj in gc.get_objects():
                try:
                    if hasattr(obj, 'packets') and hasattr(obj, 'add') and hasattr(obj, 'get_recent'):
                        store = obj
                        break
                except:
                    pass

        if not store:
            log("Store not found")
            return

        log(f"Store: {type(store).__name__}")

        # Get last 500 packets
        all_pkts = []
        try:
            all_pkts = store.get_recent(500)
            log(f"Got {len(all_pkts)} packets from store")
        except:
            try:
                all_pkts = list(store.packets)[-500:]
                log(f"Got {len(all_pkts)} from store.packets")
            except Exception as e:
                log(f"Cannot get packets: {e}")
                return

        # Scan for S2C NPC-related opcodes
        # NpcHtmlMessage = 0x1B, ShowBoard = 0x7B, ExShowList = 0xFE 0x1F
        NPC_OPCODES = {0x1B, 0x7B, 0xA1, 0x3E, 0x11, 0xD6}
        npc_pkts = []
        multisell_pkts = []

        log("\n--- S2C packet opcode distribution (recent 500) ---")
        opcode_counts = {}
        for p in all_pkts:
            if not isinstance(p, dict):
                continue
            d = p.get('dir', p.get('direction', ''))
            if 'S2C' not in str(d) and 'server' not in str(d).lower() and 's2c' not in str(d).lower():
                continue
            op = p.get('opcode', 0)
            if isinstance(op, str):
                try:
                    op = int(op, 16) if op.startswith('0x') else int(op)
                except:
                    op = 0
            opcode_counts[op] = opcode_counts.get(op, 0) + 1

            dec = p.get('dec_hex', p.get('hex', ''))
            if op in NPC_OPCODES:
                npc_pkts.append((p.get('seq', 0), p.get('time', '?'), op, dec))

            # Check dec_hex for "multisell" text pattern (UTF-16LE)
            if dec and len(dec) > 10:
                try:
                    raw = bytes.fromhex(dec)
                    # Try UTF-16LE decode
                    if len(raw) > 4:
                        txt = raw.decode('utf-16-le', errors='replace')
                        if 'multisell' in txt.lower() or '81381' in txt:
                            multisell_pkts.append({
                                'seq': p.get('seq', 0),
                                'time': str(p.get('time', '?')),
                                'op': hex(op),
                                'text': txt[:300],
                                'hex': dec[:80]
                            })
                            log(f"\n*** MULTISELL FOUND in S2C op=0x{op:02X} seq={p.get('seq','?')} ***")
                            log(f"    text: {txt[:200]}")
                except:
                    pass

        log("\nTop S2C opcodes:")
        for op_val, cnt in sorted(opcode_counts.items(), key=lambda x: -x[1])[:20]:
            log(f"  0x{op_val:02X} = {cnt}")

        log(f"\nNPC-related packets ({len(npc_pkts)}):")
        for seq, ts, op, dec in npc_pkts[-20:]:
            log(f"  [{seq}] {ts} op=0x{op:02X} hex={dec[:60]}")
            # Try to decode as NpcHtmlMessage
            if op == 0x1B and dec:
                try:
                    raw = bytes.fromhex(dec)
                    if len(raw) > 5:
                        # NpcHtmlMessage: opcode(1) + objectId(4) + string(utf16le null-term)
                        obj_id = struct.unpack_from('<I', raw, 1)[0] if len(raw) >= 5 else 0
                        html_raw = raw[5:]
                        html_txt = html_raw.decode('utf-16-le', errors='replace').rstrip('\x00')[:300]
                        log(f"    NPC objectId: {obj_id} (0x{obj_id:08X})")
                        log(f"    HTML: {html_txt[:200]}")
                        if 'multisell' in html_txt.lower() or '81381' in html_txt:
                            log(f"    *** MULTISELL 81381 NPC! objectId={obj_id} ***")
                except Exception as e:
                    log(f"    decode err: {e}")

        log(f"\nMultisell text found in S2C: {len(multisell_pkts)}")

        # Also check ALL S2C packets for opcode 0x1B in raw hex
        log("\n--- Scanning all packets for op 0x1B (NpcHtmlMessage) ---")
        html_count = 0
        for p in all_pkts:
            d = str(p.get('dir', p.get('direction', '')))
            if 'S2C' not in d and 's2c' not in d.lower() and 'server' not in d.lower():
                continue
            dec = p.get('dec_hex', p.get('hex', ''))
            if dec and dec.startswith('1b'):
                html_count += 1
                seq = p.get('seq', '?')
                try:
                    raw = bytes.fromhex(dec)
                    obj_id = struct.unpack_from('<I', raw, 1)[0] if len(raw) >= 5 else 0
                    html_raw = raw[5:]
                    html_txt = html_raw.decode('utf-16-le', errors='replace').rstrip('\x00')[:400]
                    log(f"\n[{seq}] NpcHtml objectId={obj_id} (0x{obj_id:08X})")
                    log(f"  {html_txt[:200]}")
                    if 'multisell' in html_txt.lower() or '81381' in html_txt:
                        log(f"  *** MULTISELL MATCH! ***")
                        multisell_pkts.append({'seq': seq, 'obj_id': obj_id, 'html': html_txt[:400]})
                except Exception as e:
                    log(f"[{seq}] decode err: {e}")

        log(f"\nTotal NpcHtmlMessage packets: {html_count}")

        # Also look for any packet with 'multisell' keyword in name field
        log("\n--- Scanning name field for multisell ---")
        for p in all_pkts:
            name = str(p.get('name', '')).lower()
            if 'multisell' in name or 'multilist' in name:
                log(f"  seq={p.get('seq','?')} op=0x{p.get('opcode',0):02X} name={p.get('name','?')} dir={p.get('dir','?')}")

        with open(OUT_JSON, "w", encoding="utf-8") as f:
            json.dump({
                'opcode_counts': {hex(k): v for k, v in opcode_counts.items()},
                'npc_packets': [{'seq': s, 'time': str(t), 'op': hex(o), 'hex': d[:40]} for s, t, o, d in npc_pkts],
                'multisell_packets': multisell_pkts
            }, f, indent=2)

        log("\nDONE")

    except Exception as e:
        log(f"EXCEPTION: {e}")
        import traceback
        log(traceback.format_exc())


_run()
