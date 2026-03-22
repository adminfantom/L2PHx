"""BYPASS FIX + INJECT v1.
Исправляет ошибку build_bypass (лишний length prefix \x10\x00).
Правильный формат C2S 0x23: opcode(1) + null-terminated UTF-16LE (NO length prefix).

1. Читає live xor_key з proxy.crypto для декодування npcObjectId
2. Інжектує правильний bypass: 'multisell 81381' (без length prefix)
3. Очікує S_MULTI_SELL_LIST (через _MULTISELL_CAP або shadow decrypt)
4. Якщо отримано npcObjectId → повторює з 'npc_OID_multisell 81381'
5. Інжектує MultiSellChoose для entries 1,3,5,7
"""
import gc, sys, struct, os, time, json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_bypass_fix.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    lines.append(f"[{time.strftime('%H:%M:%S')}] {s}")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])

log("=== BYPASS FIX + INJECT v1 ===")
log(f"PID: {os.getpid()}")

# Find proxy
proxy = None
for obj in gc.get_objects():
    try:
        if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
            proxy = obj
            break
    except: pass

if not proxy:
    log("FATAL: proxy not found")
    raise SystemExit(1)

log(f"Proxy: {type(proxy).__name__}")
crypto = proxy.crypto

# === Read live XOR key ===
xor_key = getattr(crypto, 'xor_key', None) if crypto else None
if xor_key:
    log(f"Live xor_key: {bytes(xor_key).hex()}")
    # Verify key[0..4] match known values from stored S_MULTI_SELL_LIST analysis
    known_k = {0: 0x00, 1: 0x5f, 2: 0x95, 3: 0xa8, 4: 0x47}
    matches = all(xor_key[i] == v for i, v in known_k.items())
    log(f"key[0..4] match known values: {matches}")
else:
    log("WARNING: xor_key not available")

# === DECODE NPC OID FROM STORED S_MULTI_SELL_LIST ===
# Known S2C 0xD0 body (344 bytes) from 22:27 session
# Confirmed: listId=81381, XOR key[0..4]={00,5f,95,a8,47}
# Zero-padding region at bytes 136+ gives: key[8..11]={4b,0e,18,5e}
STORED_BODY_HEX = (
    "d06ac26b2ceac095063ef977ce145a577e77c317732ad1eb3b444436f86c1c30f"
    "90ef85d9cc678b20f3a7d35e69026961491d21f454f112c16a6ded880ec39530"
    "54b4a1391f80505c761828e6c46d3cd2d9f6dd1e7b61534122ecd34590d2742d"
    "6e48cbc159d673750d1db5af9d7586b411f970e3ed22ebe86eee6f24296673ba"
    "482c27b19efd38ac1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc"
    "1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc"
    "1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc"
    "1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc"
    "1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afdc1cfd789d0196afd"
    "df17b3ec1f0480ef89da7a89e947717f8f247b3edb68427885afb8ea3d70a763"
    "c1cfd789d0196afd9e31f0483fa96388374f06baa01eefaf"
)
try:
    stored = bytes.fromhex(STORED_BODY_HEX.replace(" ", ""))
    log(f"Stored body: {len(stored)} bytes OK")
except Exception as e:
    log(f"Stored body hex error: {e}")
    stored = None

npc_oid = None
log("\n=== NPC OID DECODING ===")

if stored and xor_key:
    enc = stored
    # key[5..7] from live xor_key
    k5, k6, k7 = xor_key[5], xor_key[6], xor_key[7]
    log(f"key[5..7] from live: 0x{k5:02x} 0x{k6:02x} 0x{k7:02x}")

    # Decode bytes 5-7 (npcObjectId bytes 0-2)
    p5 = enc[5] ^ k5 ^ enc[4]
    p6 = enc[6] ^ k6 ^ enc[5]
    p7 = enc[7] ^ k7 ^ enc[6]
    log(f"plain[5..7] = 0x{p5:02x} 0x{p6:02x} 0x{p7:02x}")

    # For byte 8 (MSB of npcObjectId), try plain=0 first
    for msb in [0, 1, 2]:
        k8 = enc[8] ^ msb ^ enc[7]
        candidate = struct.unpack("<I", bytes([p5, p6, p7, msb]))[0]
        log(f"  plain[8]=0x{msb:02x} → key[8]=0x{k8:02x} → npcObjectId={candidate} (0x{candidate:08x})")

    # Most likely (MSB=0):
    npc_oid = struct.unpack("<I", bytes([p5, p6, p7, 0x00]))[0]
    log(f"\nMost likely npcObjectId = {npc_oid} (0x{npc_oid:08x})")
else:
    log("Cannot decode: missing stored body or xor_key")
    # Fall back to zero-padding derived key[8..11] = {0x4b, 0x0e, 0x18, 0x5e}
    # combined with known key[0..4] = {00, 5f, 95, a8, 47}
    # key[5..7] still unknown
    log("Fallback: trying without key[5..7] (will use current cipher state)")

# === Also check live cipher for xor_key ===
for cname in ['client_c2s', 'server_c2s']:
    c = getattr(crypto, cname, None) if crypto else None
    if c and hasattr(c, 'key') and len(c.key) >= 8:
        kb = bytes(c.key)[:8]
        log(f"{cname}.key[0..7] = {kb.hex()}")
        if kb[0] == 0x00 and list(kb[1:5]) == [0x5f, 0x95, 0xa8, 0x47]:
            log(f"  CONFIRMED same base_key as stored session!")
            k5_alt = kb[5]
            k6_alt = kb[6]
            k7_alt = kb[7]
            log(f"  key[5..7] = 0x{k5_alt:02x} 0x{k6_alt:02x} 0x{k7_alt:02x}")
            if stored:
                p5a = stored[5] ^ k5_alt ^ stored[4]
                p6a = stored[6] ^ k6_alt ^ stored[5]
                p7a = stored[7] ^ k7_alt ^ stored[6]
                oid_alt = struct.unpack("<I", bytes([p5a, p6a, p7a, 0x00]))[0]
                log(f"  → npcObjectId = {oid_alt} (0x{oid_alt:08x})")
                if not npc_oid:
                    npc_oid = oid_alt

# === FIXED build_bypass: NO length prefix ===
def build_bypass_fixed(cmd: str) -> bytes:
    """Correct L2 RequestBypassToServer: opcode(1) + null-terminated UTF-16LE."""
    return b'\x23' + cmd.encode('utf-16-le') + b'\x00\x00'

def build_multisell_choose(list_id, entry_id, amount=1):
    return struct.pack("<BIIq", 0xB0, list_id, entry_id, amount) + b'\x00' * 24

LIST_ID = 81381
ENTRIES = [1, 3, 5, 7]

# === INJECT: try 'multisell 81381' first (no NPC objectId required on some servers) ===
log("\n=== INJECTION ===")
log("Checking inject_c2s queue...")

# Strategy 1: multisell without NPC objectId
bypass_cmd_1 = f"multisell {LIST_ID}"
bypass_pkt_1 = build_bypass_fixed(bypass_cmd_1)
log(f"Bypass1 hex: {bypass_pkt_1.hex()}")
log(f"Bypass1 decoded: opcode=0x{bypass_pkt_1[0]:02x} cmd='{bypass_cmd_1}'")

# Verify: decode the packet back to check
check_cmd = bypass_pkt_1[1:].decode('utf-16-le', errors='ignore').rstrip('\x00')
log(f"Verification: decoded cmd = '{check_cmd}' (should be '{bypass_cmd_1}')")

proxy.inject_c2s.append(bypass_pkt_1)
log(f"Injected bypass: '{bypass_cmd_1}' ({len(bypass_pkt_1)} bytes)")
time.sleep(0.5)

# Check if MULTISELL_CAP got something
engine = None
for name, mod in list(sys.modules.items()):
    try:
        if hasattr(mod, '_MULTISELL_CAP') and hasattr(mod, 'wrap_relay_0x06'):
            engine = mod
            break
    except: pass

cap = engine._MULTISELL_CAP.get('captured', []) if engine else []
log(f"MULTISELL_CAP after bypass1: {len(cap)} captures")

# Inject MultiSellChoose for all entries
for entry_id in ENTRIES:
    pkt = build_multisell_choose(LIST_ID, entry_id, 1)
    proxy.inject_c2s.append(pkt)
    log(f"Injected MultiSellChoose entry={entry_id} ({len(pkt)} bytes)")
    time.sleep(0.05)

log(f"\nWaiting 1s for server response...")
time.sleep(1.0)

# Check again
cap_after = engine._MULTISELL_CAP.get('captured', []) if engine else []
log(f"MULTISELL_CAP after injection: {len(cap_after)} captures")

# === Strategy 2: if we have npcObjectId, also try with NPC prefix ===
if npc_oid:
    bypass_cmd_2 = f"npc_{npc_oid}_multisell {LIST_ID}"
    bypass_pkt_2 = build_bypass_fixed(bypass_cmd_2)
    log(f"\nStrategy 2: inject bypass with NPC objectId")
    log(f"  cmd: '{bypass_cmd_2}'")
    log(f"  hex: {bypass_pkt_2.hex()}")
    proxy.inject_c2s.append(bypass_pkt_2)
    time.sleep(0.5)
    for entry_id in ENTRIES:
        pkt = build_multisell_choose(LIST_ID, entry_id, 1)
        proxy.inject_c2s.append(pkt)
        log(f"  Injected MultiSellChoose entry={entry_id}")
        time.sleep(0.05)
else:
    log("\nStrategy 2 skipped: npcObjectId unknown (xor_key mismatch or unavailable)")
    log("To get npcObjectId: have player walk to NPC and click it naturally")
    log("Then check pkt_dump for C2S_0023_game_RequestBypassToServer with 'multisell'")

log("\n=== DONE ===")
