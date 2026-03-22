"""Check S2C packets after our injections (seq 7550+) for multisell list response."""
import os
import gc
import time
import struct
import json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_s2c_monitor.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    lines.append(s)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

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
    exit()

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
    exit()

log(f"Store: {type(store).__name__}")

# Get all recent packets
pkts = store.get_recent(500)
log(f"Total packets: {len(pkts)}")

# Find max seq
max_seq = max((p.get('seq', 0) for p in pkts if isinstance(p, dict)), default=0)
log(f"Max seq in store: {max_seq}")

# Look at S2C packets with seq > 7540 (after our injections)
inject_seq = 7540
log(f"\n--- S2C packets after seq {inject_seq} ---")
s2c_after = []
for p in pkts:
    if not isinstance(p, dict):
        continue
    seq = p.get('seq', 0)
    if seq < inject_seq:
        continue
    d = str(p.get('dir', p.get('direction', ''))).upper()
    if 'S2C' not in d:
        continue
    s2c_after.append(p)

log(f"S2C packets after seq {inject_seq}: {len(s2c_after)}")
for p in sorted(s2c_after, key=lambda x: x.get('seq', 0)):
    seq = p.get('seq', '?')
    op = p.get('opcode', 0)
    if isinstance(op, str):
        try:
            op = int(op, 16) if op.startswith('0x') else int(op)
        except:
            op = 0
    name = p.get('name', '?')
    dec = p.get('dec_hex', p.get('hex', ''))
    ts = p.get('time', '?')
    log(f"  [{seq}] {ts} op=0x{op:02X} name={name} hex={dec[:60]}")

    # Try to decode as multisell list (ExMultiSellInfo or similar)
    if dec and len(dec) > 10:
        try:
            raw = bytes.fromhex(dec)
            # Try UTF-16LE decode
            if len(raw) > 4:
                txt = raw.decode('utf-16-le', errors='replace')
                if 'multisell' in txt.lower() or '81381' in txt:
                    log(f"    *** MULTISELL in S2C! text: {txt[:200]}")
        except:
            pass

# Also show ALL recent packets (both directions) with seq > inject_seq
log(f"\n--- ALL packets after seq {inject_seq} ---")
all_after = [p for p in pkts if isinstance(p, dict) and p.get('seq', 0) >= inject_seq]
for p in sorted(all_after, key=lambda x: x.get('seq', 0))[:60]:
    seq = p.get('seq', '?')
    op = p.get('opcode', 0)
    if isinstance(op, str):
        try:
            op = int(op, 16) if op.startswith('0x') else int(op)
        except:
            op = 0
    name = p.get('name', '?')
    d = str(p.get('dir', p.get('direction', ''))).upper()
    marker = ''
    if 'inject' in name.lower() or 'INJECT' in name:
        marker = ' <<INJECT>>'
    log(f"  [{seq}] {d} op=0x{op:02X} {name}{marker}")

log("\nDONE")
