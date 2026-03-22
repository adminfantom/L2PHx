"""GET KEY + DECODE NPC OID v1.
Читає xor_key з живого proxy.crypto, декодує npcObjectId із збереженого тіла
S_MULTI_SELL_LIST (listId=81381).
Потім шукає NPC HTML повідомлення у PacketStore.
"""
import gc, sys, struct, os, time, json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_get_key.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    lines.append(f"[{time.strftime('%H:%M:%S')}] {s}")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])

log("=== GET KEY + DECODE NPC OID v1 ===")
log(f"PID: {os.getpid()}")

# === Find proxy ===
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
if not crypto:
    log("FATAL: proxy.crypto is None")
    raise SystemExit(1)

# === Read xor_key from live session ===
xor_key = getattr(crypto, 'xor_key', None)
if not xor_key:
    log("FATAL: proxy.crypto.xor_key is None (not initialized?)")
    raise SystemExit(1)

log(f"proxy.crypto.xor_key ({len(xor_key)} bytes): {bytes(xor_key).hex()}")
log(f"  key[0]=0x{xor_key[0]:02x} key[1]=0x{xor_key[1]:02x} key[2]=0x{xor_key[2]:02x} "
    f"key[3]=0x{xor_key[3]:02x} key[4]=0x{xor_key[4]:02x}")
log(f"  key[5]=0x{xor_key[5]:02x} key[6]=0x{xor_key[6]:02x} key[7]=0x{xor_key[7]:02x}")

# === Verify against known key[0..4] ===
KNOWN_KEY = {0: 0x00, 1: 0x5f, 2: 0x95, 3: 0xa8, 4: 0x47}
matches = all(xor_key[i] == v for i, v in KNOWN_KEY.items())
log(f"Key[0..4] match confirmed values: {matches}")
if not matches:
    log("WARNING: key differs from known - different game session! Proceeding anyway...")
    for i, v in KNOWN_KEY.items():
        got = xor_key[i]
        log(f"  expected key[{i}]=0x{v:02x}, got=0x{got:02x} {'OK' if got==v else 'MISMATCH'}")

# Also dump live cipher key states
for cname in ('client_c2s', 'server_c2s', 'server_s2c', 'client_s2c', 'shadow_xor_s2c', 'shadow_xor_c2s'):
    c = getattr(crypto, cname, None)
    if c and hasattr(c, 'key'):
        k = bytes(c.key)
        log(f"  {cname}.key[0..15]: {k.hex()}")
        log(f"    base[0..7]={k[:8].hex()} counter_le={k[8:12].hex()} suffix[4..7]={k[12:16].hex()}")

# === Stored S_MULTI_SELL_LIST body (22:27 session, 344 bytes) ===
# Body từ pkt_dump/00008_S2C_00D0_S_MULTI_SELL_LIST.bin
PKT_DUMP = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\logs\pkt_dump\00008_S2C_00D0_S_MULTI_SELL_LIST.bin"
if os.path.exists(PKT_DUMP):
    stored_body = open(PKT_DUMP, 'rb').read()
    log(f"\nStored body: {len(stored_body)} bytes from {PKT_DUMP}")
    log(f"  first 32 bytes: {stored_body[:32].hex()}")
else:
    log(f"WARNING: pkt_dump file not found: {PKT_DUMP}")
    # fallback: hardcoded 22:27 session body (48 bytes)
    stored_body = bytes.fromhex(
        "d06ac26b2ceac095063ef977ce145a577e77c317732ad1eb3b444436f86c1c30f90ef85d9cc678b20f3a7d35e690269614"
    )
    log(f"  Using hardcoded 48-byte fallback")

enc = stored_body

# === Verify listId assumption ===
# key[1..4] from known listId=81381: e5 3d 01 00
# enc[i] = plain[i] ^ key[i&15] ^ enc[i-1]  (Interlude mode, kl=15)
# Assume plain[1..4] = e5 3d 01 00
log("\n=== VERIFY KNOWN PLAINTEXT ===")
LIST_ID = 81381
plain_listid = [0xe5, 0x3d, 0x01, 0x00]
key_derived = [None] * 16
key_derived[0] = 0x00  # enc[0] = plain[0] ^ key[0], and enc[0]=0xD0=opcode=plain[0] => key[0]=0

for i in range(1, 5):
    k = enc[i] ^ plain_listid[i-1] ^ enc[i-1]
    key_derived[i] = k
    log(f"  Derived key[{i}]=0x{k:02x}, xor_key[{i}]=0x{xor_key[i]:02x}, "
        f"match={'YES' if k == xor_key[i] else 'NO'}")

key_match_listid = all(key_derived[i] == xor_key[i] for i in range(1, 5))
log(f"listId-derived key[1..4] matches live xor_key: {key_match_listid}")

if not key_match_listid:
    log("CRITICAL: stored body key[1..4] != live xor_key[1..4]")
    log("=> Stored body is from a DIFFERENT session than current live key")
    log("=> Cannot use live xor_key[5..7] to decode stored body directly")
    # But we can still try - might reveal which bytes differ
else:
    log("CONFIRMED: stored body uses same base_key as live session")

# === Decode npcObjectId from stored body ===
log("\n=== DECODE NPC OBJECT ID ===")
# We need key[5..7] which = xor_key[5..7]
k5 = xor_key[5]
k6 = xor_key[6]
k7 = xor_key[7]
log(f"Using key[5]=0x{k5:02x} key[6]=0x{k6:02x} key[7]=0x{k7:02x}")

# Cipher: enc[i] = plain[i] ^ key[i&15] ^ enc[i-1]
# => plain[i] = enc[i] ^ key[i&15] ^ enc[i-1]
plain5 = enc[5] ^ k5 ^ enc[4]
plain6 = enc[6] ^ k6 ^ enc[5]
plain7 = enc[7] ^ k7 ^ enc[6]
log(f"enc[4..7]: {enc[4]:02x} {enc[5]:02x} {enc[6]:02x} {enc[7]:02x}")
log(f"plain[5..7]: {plain5:02x} {plain6:02x} {plain7:02x}")

# For byte 8 (npcObjectId MSB), we need key[8] = counter at time of packet
# Assumption: npcObjectId < 0x01000000 => plain[8] = 0
# => key[8]_at_time = enc[8] ^ 0 ^ enc[7] = enc[8] ^ enc[7]
plain8_if_zero = 0
key8_if_plain8_zero = enc[8] ^ 0 ^ enc[7]
log(f"If plain[8]=0: key[8]_at_time=0x{key8_if_plain8_zero:02x}")

# Also try plain[8] = likely small values
for plain8_try in [0x00, 0x01, 0x02]:
    key8 = enc[8] ^ plain8_try ^ enc[7]
    npc_oid_bytes = bytes([plain5, plain6, plain7, plain8_try])
    npc_oid = struct.unpack("<I", npc_oid_bytes)[0]
    log(f"  If plain[8]=0x{plain8_try:02x}: npcObjectId={npc_oid} (0x{npc_oid:08x}), "
        f"key[8]_at_time=0x{key8:02x}")
    log(f"    Bypass cmd: npc_{npc_oid}_multisell 81381")

# The most likely npcObjectId (assuming MSB=0):
npc_oid_likely = struct.unpack("<I", bytes([plain5, plain6, plain7, 0x00]))[0]
log(f"\n=== MOST LIKELY npcObjectId = {npc_oid_likely} (0x{npc_oid_likely:08x}) ===")
log(f"=== Bypass cmd: npc_{npc_oid_likely}_multisell 81381 ===")

# === Also check if CURRENT session's live cipher has seen multisell ===
log("\n=== SCAN PACKETSTORE for NPC data ===")
store = proxy.store
with store.lock:
    packets_snap = list(store.packets)

log(f"PacketStore: {len(packets_snap)} packets")

LIST_ID_BYTES = struct.pack("<I", LIST_ID)
npc_html_count = 0
npc_info_count = 0

for pkt in packets_snap:
    direction = pkt.get('dir', '')
    body = pkt.get('_body', b'')
    opcode = pkt.get('opcode', -1)
    seq = pkt.get('seq', 0)
    ts = pkt.get('ts', '')
    opname = pkt.get('opname', '')

    if direction != 'S2C' or len(body) < 5:
        continue

    # S_NPC_HTML_MESSAGE (opcode 0x0F or 0x19 depending on version)
    # In Interlude/Ertheia: 0x0F = S_EX_SHOW_SCREEN_MSG, 0x19 = S_NPC_HTML_MESSAGE
    if opcode in (0x000F, 0x0019, 0x0010, 0x0011, 0x00A9):
        # Look for multisell text in NPC HTML
        try:
            text = body.decode('utf-16-le', errors='ignore').lower()
            if 'multisell' in text or '81381' in text or 'npc_' in text:
                npc_html_count += 1
                log(f"  NPC_HTML seq={seq} ts={ts} op=0x{opcode:04X}: contains 'multisell'/'npc_'")
                log(f"    text[:200]: {text[:200]}")
        except:
            pass

        # Also raw bytes search
        if b'multisell' in body.lower() or LIST_ID_BYTES in body:
            npc_html_count += 1
            log(f"  NPC_HTML raw bytes seq={seq} ts={ts} op=0x{opcode:04X}")

    # S_NPC_INFO (opcode 0x16)
    if opcode == 0x0016 and 'sniff' in opname:
        npc_info_count += 1
        if len(body) >= 9:
            oid = struct.unpack_from("<I", body, 1)[0]
            tmpl = struct.unpack_from("<I", body, 5)[0] if len(body) >= 9 else 0
            log(f"  NPC_INFO seq={seq} ts={ts}: oid={oid} tmpl={tmpl}")

    # S_MULTI_SELL_LIST (opcode 0xD0) plaintext
    if opcode == 0x00D0 and not pkt.get('extra', {}).get('passthrough'):
        if len(body) >= 9:
            listid = struct.unpack_from("<I", body, 1)[0]
            if listid == LIST_ID:
                npcoid = struct.unpack_from("<I", body, 5)[0]
                log(f"  *** MULTI_SELL_LIST PLAINTEXT seq={seq} ts={ts}: listId={listid} npcOid={npcoid}")

    # Search for listId bytes in any plaintext S2C
    if LIST_ID_BYTES in body:
        pos = body.find(LIST_ID_BYTES)
        log(f"  S2C listId-bytes found seq={seq} ts={ts} op=0x{opcode:04X}({opname}) pos={pos}")
        ctx = body[max(0, pos-8):pos+16]
        log(f"    context: {ctx.hex()}")

log(f"\nNPC HTML messages with multisell: {npc_html_count}")
log(f"NPC INFO packets: {npc_info_count}")

# === ALSO: look at pkt_dump sniff path for NPC_INFO that might have npcOid ===
log("\n=== SCAN pkt_dump directory for NPC_INFO ===")
PKT_DIR = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\logs\pkt_dump"
npc_info_files = []
if os.path.isdir(PKT_DIR):
    for fn in os.listdir(PKT_DIR):
        if 'NPC_INFO' in fn.upper() or 'NPC_HTML' in fn.upper():
            npc_info_files.append(fn)
    log(f"pkt_dump NPC files: {len(npc_info_files)}")
    for fn in sorted(npc_info_files)[:20]:
        fpath = os.path.join(PKT_DIR, fn)
        try:
            fdata = open(fpath, 'rb').read()
            log(f"  {fn}: {len(fdata)} bytes, first16={fdata[:16].hex()}")
            # Check for listId in NPC_HTML
            if LIST_ID_BYTES in fdata:
                pos = fdata.find(LIST_ID_BYTES)
                log(f"    *** CONTAINS LIST_ID at pos={pos}!")
                ctx = fdata[max(0, pos-8):pos+16]
                log(f"    context: {ctx.hex()}")
        except Exception as e:
            log(f"  {fn}: error={e}")

log("\n=== DONE ===")
