"""IMMEDIATE: inject bypass + multisell while grocery NPC dialog is active."""
import os, gc, time, struct

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_immediate_buy.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    lines.append(f"[{time.strftime('%H:%M:%S.%f')[:-3]}] {s}")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])

log("=== IMMEDIATE MULTISELL BUY ===")
log(f"PID: {os.getpid()}")

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

log(f"Proxy: {type(proxy).__name__}")
log(f"Queue before: {len(proxy.inject_c2s)}")

TARGET_LIST = 81381
ENTRIES = [1, 3, 5, 7]

# Bypass format: 0x23 + len(u16) + UTF16LE + null
def build_bypass(cmd):
    enc = cmd.encode('utf-16-le') + b'\x00\x00'
    return b'\x23' + struct.pack('<H', len(cmd) + 1) + enc

# MultiSellChoose: 0xB0 + list_id(4) + entry_id(4) + amount(8) + pad(24)
def build_choose(list_id, entry_id, amount=1):
    return struct.pack("<BIIq", 0xB0, list_id, entry_id, amount) + b'\x00' * 24

# === FIRE IMMEDIATELY ===
log(f"\nStep 1: inject bypass 'multisell {TARGET_LIST}'")
bp = build_bypass(f"multisell {TARGET_LIST}")
proxy.inject_c2s.append(bp)
log(f"  bypass queued, len={len(bp)}")

# Small delay, then MultiSellChoose
time.sleep(0.5)

log(f"\nStep 2: inject MultiSellChoose for entries {ENTRIES}")
for entry_id in ENTRIES:
    pkt = build_choose(TARGET_LIST, entry_id, 1)
    proxy.inject_c2s.append(pkt)
    log(f"  queued entry={entry_id} sz={len(pkt)}")
    time.sleep(0.05)

log(f"\nQueue after: {len(proxy.inject_c2s)}")
log(f"\n=== DONE - check game for items! ===")
