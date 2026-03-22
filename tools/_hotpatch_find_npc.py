"""Find NPC objectId from S_MULTI_SELL_LIST packets in PacketStore.

Searches for:
1. S2C packets with opcode 0xD0 (S_MULTI_SELL_LIST) that are TRUE PLAINTEXT
2. S2C packets where body contains list_id=81381 (e5 3d 01 00)
3. Recent S2C NPC_INFO packets for NPC identification

Also attempts known-plaintext attack on field-XOR encoded S_MULTI_SELL_LIST.
"""
import gc, sys, struct, os, time, json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_find_npc.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    lines.append(f"[{time.strftime('%H:%M:%S')}] {s}")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])

log("=== FIND NPC objectId ===")

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

log(f"Proxy found: {type(proxy).__name__}")
store = proxy.store
log(f"PacketStore: {len(store.packets)} packets")

LIST_ID = 81381
list_id_bytes = struct.pack("<I", LIST_ID)  # e5 3d 01 00

found_multisell = []
found_versions = []
found_npc_info = []

with store.lock:
    packets_snap = list(store.packets)

log(f"Scanning {len(packets_snap)} packets...")

for pkt in packets_snap:
    body = pkt.get('_body', b'')
    direction = pkt.get('dir', '')
    opname = pkt.get('opname', '')
    opcode = pkt.get('opcode', -1)
    seq = pkt.get('seq', 0)
    ts = pkt.get('ts', '')

    # Track VERSION_CHECK packets to know when crypto was established
    if direction == 'S2C' and opcode == 0x002E:
        found_versions.append((seq, ts, body.hex()[:64]))
        log(f"  VERSION_CHECK at seq={seq} ts={ts} body={body[:16].hex()}")

    # Look for S2C D0 packets (S_MULTI_SELL_LIST)
    if direction == 'S2C' and len(body) >= 9:
        first_byte = body[0] if body else 0

        # Opcode 0xD0 = S_MULTI_SELL_LIST
        if first_byte == 0xD0:
            log(f"  S2C 0xD0 at seq={seq} ts={ts} opname={opname} len={len(body)}")
            log(f"    body[:16]={body[:16].hex()}")

            # Check if list_id is in plaintext
            if len(body) >= 5:
                candidate_listid = struct.unpack_from("<I", body, 1)[0]
                log(f"    candidate listId (bytes 1-4) = {candidate_listid}")
                if candidate_listid == LIST_ID:
                    log(f"    *** MATCH! listId=81381 in PLAINTEXT!")
                    if len(body) >= 9:
                        npc_oid = struct.unpack_from("<I", body, 5)[0]
                        log(f"    *** npcObjectId = {npc_oid} (0x{npc_oid:08x})")
                        found_multisell.append({
                            'seq': seq, 'ts': ts, 'npc_oid': npc_oid,
                            'body_hex': body[:32].hex()
                        })

            # Also do known-plaintext attack
            # enc[k] = plain[k] ^ key[k%16] ^ enc[k-1], key[0]=0
            # Assume plain[1..4] = e5 3d 01 00 (list_id=81381)
            if len(body) >= 9:
                enc = body
                # Derive key[1..4] from known listId
                key = [None] * 16
                key[0] = 0  # always
                plain_listid = [0xe5, 0x3d, 0x01, 0x00]
                for i in range(1, 5):
                    k = enc[i] ^ plain_listid[i-1] ^ enc[i-1]
                    key[i] = k
                    log(f"    derived key[{i}] = 0x{k:02x}")

                # Try to decode npcObjectId (bytes 5-8) using what we know
                # We don't know key[5..8] yet, but we can check:
                # If this IS the 81381 list, encode back to verify
                log(f"    To decode npcOid, need key[5..8]")

    # Look for list_id in plaintext anywhere in S2C body
    if direction == 'S2C' and list_id_bytes in body:
        pos = body.find(list_id_bytes)
        log(f"  S2C listId 81381 found at seq={seq} ts={ts} op=0x{opcode:04X}({opname}) pos={pos}")
        log(f"    body around match: {body[max(0,pos-4):pos+16].hex()}")
        if pos >= 4:
            npc_oid = struct.unpack_from("<I", body, pos-4)[0]
            log(f"    Possible npcObjectId BEFORE listId: {npc_oid}")
        if pos + 8 <= len(body):
            after = struct.unpack_from("<I", body, pos+4)[0]
            log(f"    4 bytes AFTER listId: {after}")

    # Look for S_NPC_INFO packets (opcode 0x16 or 0x0C)
    if direction == 'S2C' and opcode in (0x0016, 0x000C):
        if len(body) >= 5:
            if 'sniff' in opname:
                # True plaintext from sniff path
                npc_oid = struct.unpack_from("<I", body, 1)[0] if len(body) >= 5 else 0
                found_npc_info.append((seq, ts, npc_oid, body[:32].hex()))

log(f"\nFound {len(found_multisell)} S_MULTI_SELL_LIST matches with listId=81381")
for m in found_multisell:
    log(f"  seq={m['seq']} ts={m['ts']} npcOid={m['npc_oid']}")

log(f"\nFound {len(found_versions)} VERSION_CHECK packets")

# Known-plaintext attack using BOTH 18:17 and 22:27 captures
log("\n=== KNOWN-PLAINTEXT ATTACK on stored S_MULTI_SELL_LIST ===")
# From mcp.log:
# 18:17 body: d06ac26b2ceac0959a8353f6e5ba34b27e77c317732ad1eb3b444436f86c1c30f...
# 22:27 body: d06ac26b2ceac095063ef977ce145a577e77c317732ad1eb3b444436f86c1c30f...

body_1817 = bytes.fromhex("d06ac26b2ceac0959a8353f6e5ba34b27e77c317732ad1eb3b444436f86c1c30f90ef85d9cc678b20f3a7d35e690269614")
body_2227 = bytes.fromhex("d06ac26b2ceac095063ef977ce145a577e77c317732ad1eb3b444436f86c1c30f90ef85d9cc678b20f3a7d35e690269614")

# Assuming plain[1..4] = LIST_ID = 81381 = e5 3d 01 00
enc_a = body_1817  # enc_a and enc_b have SAME key[0..7] (base_key, same session)
enc_b = body_2227  # but DIFFERENT key[8..11] (counter, different packet positions)

def derive_key_from_known(enc_bytes, known_plain, start_plain_byte=1):
    """Derive key bytes from known plaintext."""
    key = {}
    key[0] = 0
    for i in range(start_plain_byte, start_plain_byte + len(known_plain)):
        plain_byte = known_plain[i - start_plain_byte]
        k = enc_bytes[i] ^ plain_byte ^ enc_bytes[i-1]
        key[i % 16] = k
    return key

# Derive key[1..4] from listId=81381
known = [0xe5, 0x3d, 0x01, 0x00]
key_from_a = derive_key_from_known(body_1817, known, 1)
key_from_b = derive_key_from_known(body_2227, known, 1)

log(f"Key from 18:17: {key_from_a}")
log(f"Key from 22:27: {key_from_b}")

# key[1..4] should match between sessions (same base_key bytes)
match = all(key_from_a.get(i) == key_from_b.get(i) for i in range(1, 5))
log(f"Key[1..4] matches between sessions: {match}")

if match:
    log("Confirmed: listId=81381 assumption is CORRECT (key[1..4] same in both sessions)")
    partial_key = key_from_a
    log(f"Partial key: {partial_key}")

    # Now try to recover more key bytes from known structure
    # At byte 9: isPackaged (bool: 0 or 1)
    # At bytes 10-12: padding/upper bytes (likely 0)
    # Try: plain[9] = 0, plain[10..12] = 0
    # Then key[9] = enc[9] ^ 0 ^ enc[8]
    # BUT key[9] is COUNTER byte (different per session), so this gives counter for each session

    # What WE WANT: key[5..8] (base_key bytes 5-8) to decode npcObjectId

    # Strategy: look at the DIVERGENCE point (byte 8)
    # enc_a[8] = 0x9a, enc_b[8] = 0x06
    # plain[8] = npcObjectId_MSB (same in both)
    # key[8]_a = enc_a[8] ^ plain[8] ^ enc_a[7]
    # key[8]_b = enc_b[8] ^ plain[8] ^ enc_b[7]
    # enc_a[7] = enc_b[7] = 0x95 (same up to byte 7)
    # So: key[8]_a - key[8]_b = enc_a[8] - enc_b[8] (XOR)
    # = 0x9a ^ 0x06 = 0x9c
    # This tells us the DIFFERENCE between the two counter values, not the actual value
    diff_k8 = enc_a[8] ^ enc_b[8]
    log(f"Counter[0] difference between sessions: 0x{diff_k8:02x}")

    # To recover key[5..7] (base_key bytes 5-7), we need plain[5..7] = npcObjectId bytes 0-2
    # If npcObjectId is small (< 16M), then plain[8] = 0 (MSB is 0)
    # If plain[8] = 0:
    #   key[8]_a = enc_a[8] ^ 0 ^ enc_a[7] = 0x9a ^ 0x95 = 0x0f
    #   key[8]_b = enc_b[8] ^ 0 ^ enc_b[7] = 0x06 ^ 0x95 = 0x93
    if True:  # try plain[8] = 0
        k8_a = enc_a[8] ^ 0 ^ enc_a[7]
        k8_b = enc_b[8] ^ 0 ^ enc_b[7]
        log(f"If npcObjectId MSB=0: key[8]_a=0x{k8_a:02x} key[8]_b=0x{k8_b:02x}")

    # For key[5..7], we need different known plaintext
    # The COUNTER increments by packet SIZE
    # Between session 18:17 and 22:27, many packets were sent
    # The counter difference = sum of (packet_sizes mod ...) = complex

    # Let's try: looking at bytes 16+ in the bodies where they RECONVERGE
    # Body 18:17: ...9a 83 53 f6 e5 ba 34 b2 7e 77 c3 17 73 2a d1 eb 3b 44 44 36 f8 6c 1c 30 f9...
    # Body 22:27: ...06 3e f9 77 ce 14 5a 57 7e 77 c3 17 73 2a d1 eb 3b 44 44 36 f8 6c 1c 30 f9...
    # Bytes 16+: 7e 77 c3 17 73 2a d1 eb 3b 44 44 36... - SAME in both!
    log("\nComparing bytes 16+ between sessions:")
    for i in range(16, min(len(enc_a), len(enc_b), 48)):
        match = "==" if enc_a[i] == enc_b[i] else "!="
        if enc_a[i] != enc_b[i]:
            log(f"  byte[{i}]: 0x{enc_a[i]:02x} {match} 0x{enc_b[i]:02x}")

    # Bytes 16+ are SAME again!
    # This means the XOR encoding "reset" at byte 16 (key position 0 mod 16 = 0)
    # Key[0]=0 always, so at byte 16 (index 16, key[16%16]=key[0]=0):
    # enc[16] = plain[16] ^ 0 ^ enc[15]
    # Since key[0]=0 and both sessions have same enc[15]:

    # Find where bytes converge again
    log("\nFinding convergence point:")
    for i in range(8, min(len(enc_a), len(enc_b))):
        if enc_a[i] == enc_b[i]:
            log(f"  Bytes converge at index {i}: 0x{enc_a[i]:02x}")
            break

    # KEY INSIGHT: The bodies RECONVERGE at byte 16!
    # This means key[0] = 0, so at position 16 (key[16 mod 16] = key[0] = 0):
    # enc[16] = plain[16] ^ 0 ^ enc[15]
    # For session A: enc_a[16] = plain[16] ^ 0 ^ enc_a[15]
    # For session B: enc_b[16] = plain[16] ^ 0 ^ enc_b[15]
    # Since enc_a[16] == enc_b[16], we need enc_a[15] == enc_b[15]
    # Let's check:
    log(f"\nenc_a[14]={enc_a[14]:02x} enc_b[14]={enc_b[14]:02x}")
    log(f"enc_a[15]={enc_a[15]:02x} enc_b[15]={enc_b[15]:02x}")

    # If enc_a[15] != enc_b[15] but enc_a[16] == enc_b[16], then:
    # plain_a[16] ^ enc_a[15] = plain_b[16] ^ enc_b[15]
    # But plain[16] should be the SAME in both sessions (same packet content at that position)
    # So enc_a[15] must == enc_b[15]
    # This implies key[15] is the SAME in both sessions!
    # So key[15] is NOT a counter byte but a base_key or constant byte.

    # Actually this tells us: key[8..15] cycle = key[8] is counter but by byte 15 they reconverge
    # The counter WRAPS AROUND within 16 bytes?
    # Or the plaintext at byte 15 cancels out the counter difference

    # Let me check: if BOTH sessions' counter resets to the same value at byte 16...
    # Counter[k] advances by packet_size. The counter in the KEY is at positions 8-11.
    # After 16 bytes of cipher, key cycles back to key[0]=0.
    # The counter at key[8] is DIFFERENT, but at key[8 mod 16] = key[8] for i=8.
    # At i=24 (8+16), key[24 mod 16] = key[8] again = counter (DIFFERENT).

    # So the pattern should be: bytes 0-7 same, bytes 8-15 different, bytes 16-23 same again
    # (because key[0..7] same, key[8..15] different due to counter, key[16..23] = key[0..7] same)
    log("\nChecking divergence/convergence pattern:")
    for i in range(min(len(enc_a), len(enc_b), 48)):
        same = enc_a[i] == enc_b[i]
        if not same or (i > 0 and (enc_a[i-1] == enc_b[i-1]) != same):
            log(f"  i={i}: {'SAME' if same else 'DIFF'} a=0x{enc_a[i]:02x} b=0x{enc_b[i]:02x}")

    # KEY FINDING: bytes 0-7 SAME (key[0..7] same), bytes 8-15 DIFF (key[8..15] counter),
    # bytes 16+ SAME (back to key[0..7])
    # This means: plain[i] at i=8..15 is SAME in both sessions (same NPC objectId, same fields)
    # And from byte 16 onward: plain is the same and key is the same (key[0..7] cycle)
    # So bytes 16+ being same is consistent

    # CRITICALLY: From bytes 16 onward (same in both), I can derive key[0..7] values
    # that we couldn't get from bytes 0-7 (since key[0]=0 forces opcode unchanged).
    # At i=16: key[16%16]=key[0]=0, so enc[16] = plain[16] ^ 0 ^ enc[15]
    # At i=17: key[17%16]=key[1]=0x7f (already derived), so enc[17] = plain[17] ^ 0x7f ^ enc[16]

    # But I need to know plain[16] to get anything useful. Hmm.

    # Actually, the DIVERGENCE at bytes 8-15 gives information about COUNTER VALUES
    # and therefore about packet sizes before this packet.

    # But for NPC objectId: it's in bytes 5-8 (key[5..7,8]).
    # key[5..7] = base_key bytes 5-7 = SAME in both sessions.
    # key[8] = counter[0] = DIFFERENT.
    # I can compute key[5..7] IF I know plain[5..7] = npcObjectId bytes 0-2.

    # APPROACH: Brute force npcObjectId
    # NPC objectIds in L2 are typically in range 10000000-10999999 or similar.
    # Since I know key[1..4], I can verify any candidate by checking enc[5..7].
    # For each candidate npcObjectId value:
    #   - compute what enc[5..7] should be
    #   - check against actual enc[5..7] from both sessions (must match)

    # enc[5] = plain[5] ^ key[5] ^ enc[4] = npc_byte0 ^ key[5] ^ enc[4]
    # enc[6] = plain[6] ^ key[6] ^ enc[5] = npc_byte1 ^ key[6] ^ enc[5]
    # enc[7] = plain[7] ^ key[7] ^ enc[6] = npc_byte2 ^ key[7] ^ enc[6]

    # Since enc[0..7] is the SAME in both sessions, enc[5..7] from BOTH sessions
    # gives the SAME constraints: key[5..7] are uniquely determined by npc_byte[0..2].

    # But since we don't know key[5..7], we have ONE cipher equation per byte:
    # key[5] = enc[5] ^ plain[5] ^ enc[4]
    # No constraint to narrow it down unless we assume something.

    # HOWEVER: From bytes 16+ we know enc[i] = enc[i-1] ^ plain[i] ^ key[i%16]
    # And key[5%16] = key[5] = base_key[5] (same for both sessions).
    # So enc_a[21] = plain[21] ^ key[5] ^ enc_a[20]  (since 21%16=5)
    # = enc_b[21] (since both are the same at i=16+)
    # This tells us key[5] = enc_a[21] ^ plain[21] ^ enc_a[20]
    # But I still need plain[21] to compute key[5].

    # STUCK - cannot derive key[5..7] without more known plaintext.

    log("\n=== TRYING ALTERNATIVE: look at byte 5 in SNIFF path S2C ===")
    log("Need to find any S2C 0xD0 packet AFTER VERSION_CHECK (TRUE PLAINTEXT)")

log("\n=== ALSO: search for NPC objectIds in recent S2C packets ===")
# Look for the multisell NPC objectId in S_NPC_INFO
# The NPC template ID for the multisell NPC might be 81381
# (but template ID != objectId)

# Try sys.remote_exec is not needed - we're already inside the proxy process!
# Let's directly access the proxy's state

# Search for any S2C packets with list_id 81381
log("\n=== Scanning full PacketStore for list_id=81381 in any S2C ===")
for pkt in packets_snap:
    if pkt.get('dir') != 'S2C':
        continue
    body = pkt.get('_body', b'')
    # Direct scan for e5 3d 01 00
    pos = body.find(list_id_bytes)
    if pos >= 0:
        seq = pkt.get('seq', 0)
        opname = pkt.get('opname', '')
        opcode = pkt.get('opcode', -1)
        log(f"  FOUND list_id in S2C seq={seq} op=0x{opcode:04X}({opname}) pos={pos}")
        log(f"    Context: {body[max(0,pos-8):pos+16].hex()}")
        if pos >= 4:
            npc_candidate = struct.unpack_from("<I", body, pos-4)[0]
            log(f"    4 bytes before: {npc_candidate} (0x{npc_candidate:08x})")

log("\n=== RESULT ===")
if found_multisell:
    log(f"SUCCESS: Found NPC objectId in PacketStore!")
    for m in found_multisell:
        log(f"  npcObjectId = {m['npc_oid']}")
else:
    log("No TRUE PLAINTEXT S_MULTI_SELL_LIST with listId=81381 found in PacketStore")
    log("The S_MULTI_SELL_LIST is always received in passthrough mode (before VERSION_CHECK)")
    log("Need alternative approach to find NPC objectId")

log("\n=== DONE ===")
