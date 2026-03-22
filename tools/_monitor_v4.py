"""Monitor v4 — XOR-encrypted injection. No inject_bypass. No queue flooding.

Root causes fixed vs v3:
  v3 used inject_bypass → queued in inject_c2s → drained ALL-AT-ONCE on first real C2S → flood → kick
  v3 used inject_raw with PLAINTEXT → backend XOR-decrypts as garbage → silently ignored

v4 strategy:
  1. XOR-encrypt ALL injected packets (bypass + 0xB0) before sending
  2. inject_raw only (direct send to relay, no queue)
  3. Relay forwards XOR-encrypted bytes to backend → backend decrypts correctly
  4. Track relay C2S XOR state from reconnect (not 7777, only 17453 relay)
  5. Probe entry IDs 1-20 for list 8658 (valid IDs buy items, invalid silently fail)
  6. Send bypass to OPEN multisell before sending 0xB0

XOR cipher (Interlude L2):
  key = key[0..7](session) + C8279301(c2s initial rotation) + A16C3197(fixed suffix)
  enc[i] = plain[i] ^ key[i%16] ^ enc[i-1]   (enc[-1]=0 at start)
  After packet: key[8..11] += len(game_body) mod 2^32
"""
import urllib.request, json, time, struct, os, glob, sys

API         = 'http://127.0.0.1:8877/api'
LIST_ID     = 8658
ENTRY_PROBE = list(range(1, 21))   # Try IDs 1-20; valid ones buy, invalid silently fail
DUMP_DIR    = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'pkt_dump')

PACKET_DELAY    = 0.7    # seconds between individual packet sends (anti-flood)
BYPASS_WAIT     = 2.5    # wait after bypass before sending 0xB0
CYCLE_INTERVAL  = 30.0   # seconds between inject cycles
LOGIN_THRESH    = 40     # store_count must exceed this before player is "in game"
BYPASS_INTERVAL = 8.0    # seconds between bypass re-opens

C2S_INIT_ROTATION = bytes([0xC8, 0x27, 0x93, 0x01])  # key[8..11] initial value (C2S only)
S2C_INIT_ROTATION = bytes([0x00, 0x00, 0x00, 0x00])  # key[8..11] initial value (S2C)
KEY_SUFFIX        = bytes([0xA1, 0x6C, 0x31, 0x97])   # key[12..15] fixed

OUT = os.path.join(os.path.dirname(__file__), 'logs', '_monitor_v4.txt')
os.makedirs(os.path.dirname(OUT), exist_ok=True)
_lines = []
def log(s):
    msg = f"[{time.strftime('%H:%M:%S')}] {s}"
    _lines.append(msg)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(_lines[-3000:]) + '\n')
    print(msg)


# ═══ API helpers ════════════════════════════════════════════════════════════

def api(data, timeout=5):
    body = json.dumps(data).encode()
    req = urllib.request.Request(API, data=body,
                                 headers={'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read())
    except Exception as e:
        return {'error': str(e)}

def get_status():
    return api({'action': 'get_status'})

def get_crypto():
    return api({'action': 'get_crypto'})

def inject_raw_hex(hex_str):
    """Send hex bytes directly (wraps in relay 0x06 frame, direct send, no queue)."""
    return api({'action': 'inject_raw', 'hex_data': hex_str})


# ═══ XOR cipher state ═══════════════════════════════════════════════════════

class XorState:
    """Track L2 Interlude XOR cipher state for one direction (C2S or S2C)."""
    def __init__(self, key_base_hex: str, init_rotation: bytes = C2S_INIT_ROTATION):
        """key_base_hex: 16 hex chars (8 bytes) from get_crypto()['xor_key']"""
        base = bytes.fromhex(key_base_hex)[:8]
        self.key = bytearray(base + init_rotation + KEY_SUFFIX)  # 16 bytes
        self.enc_prev = 0
        self.total_rotation = 0

    def advance_by_body(self, game_body: bytes):
        """Update state as if game_body was just sent/received."""
        if game_body:
            self.enc_prev = game_body[-1]
            n = len(game_body)
            k8 = struct.unpack_from('<I', self.key, 8)[0]
            k8 = (k8 + n) & 0xFFFFFFFF
            struct.pack_into('<I', self.key, 8, k8)
            self.total_rotation += n

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext bytes and advance state."""
        encrypted = bytearray(len(plaintext))
        ep = self.enc_prev
        key = bytes(self.key)
        for i, b in enumerate(plaintext):
            enc_byte = b ^ key[i % 16] ^ ep
            encrypted[i] = enc_byte
            ep = enc_byte
        enc_bytes = bytes(encrypted)
        self.advance_by_body(enc_bytes)
        return enc_bytes

    def state_str(self):
        k8 = struct.unpack_from('<I', self.key, 8)[0]
        return (f"key={self.key[:8].hex()} rot={self.total_rotation} "
                f"enc_prev=0x{self.enc_prev:02x} k8={k8}")


# ═══ Packet builders ════════════════════════════════════════════════════════

def build_bypass_pkt(command: str) -> bytes:
    """C2S bypass: 0x23 + UTF-16LE(command) + null-terminator."""
    return bytes([0x23]) + command.encode('utf-16-le') + b'\x00\x00'

def build_multisell_pkt(list_id: int, entry_id: int, qty: int = 1) -> bytes:
    """C2S MultiSellChoose (0xB0): IDA MCP format from NWindow.dll."""
    # GroupID(I) + InfoID(I) + ItemCount(I) + Enchant(I) + AttrDefHoly(I)
    # + IsBlessedItem(I) + n_ensoul_slots(I=3) + EnsoulOptionNum_i(I)*3
    return struct.pack('<BIIIIIII', 0xB0, list_id, entry_id, qty, 0, 0, 0, 3) + b'\x00' * 12


# ═══ Relay C2S file tracker ═════════════════════════════════════════════════

class RelayC2STracker:
    """
    Tracks relay C2S game body files from pkt_dump that appeared after session_start_time.
    Used to advance C2S XOR state.
    Includes both real player keepalives AND our own inject packets.
    """
    def __init__(self, session_start_time: float):
        self.session_start = session_start_time
        self._seen = set()

    def get_new_bodies(self) -> list:
        """Return new relay C2S game body bytes (sorted by mtime), not yet seen.
        Skips INJECT_ files (our own packets — already advanced via encrypt())."""
        candidates = []
        for f in glob.glob(os.path.join(DUMP_DIR, '*_C2S_*')):
            bn = os.path.basename(f)
            if '_RAW' in bn or 'sniff' in bn.lower() or 'INJECT' in bn or f in self._seen:
                continue
            try:
                mtime = os.path.getmtime(f)
            except OSError:
                continue
            if mtime >= self.session_start:
                candidates.append((mtime, f))
        candidates.sort()
        result = []
        for mtime, f in candidates:
            self._seen.add(f)
            try:
                with open(f, 'rb') as fp:
                    data = fp.read()
                if data:
                    result.append(data)
            except OSError:
                pass
        return result


# ═══ Relay S2C trade-start detector ═════════════════════════════════════════

class S2CTradeStartDetector:
    """Watch for new S_TRADE_START (0x14) relay files after session_start_time."""
    def __init__(self, session_start_time: float):
        self.session_start = session_start_time
        self._seen = set()

    def get_new_trade_starts(self) -> list:
        """Return (filename, data) for new S2C 0x14 files."""
        result = []
        for f in glob.glob(os.path.join(DUMP_DIR, '*_S2C_0014_*')):
            bn = os.path.basename(f)
            if '_RAW' in bn or 'sniff' in bn.lower() or 'INJECT' in bn or f in self._seen:
                continue
            try:
                mtime = os.path.getmtime(f)
            except OSError:
                continue
            if mtime >= self.session_start and os.path.getsize(f) > 100:
                self._seen.add(f)
                try:
                    with open(f, 'rb') as fp:
                        data = fp.read()
                    result.append((f, data))
                except OSError:
                    pass
        return result


# ═══ S2C decryption (to extract entry IDs) ══════════════════════════════════

class RelayS2CTracker:
    """Track relay S2C for XOR state (to decode S_TRADE_START)."""
    def __init__(self, session_start_time: float, xor: XorState):
        self.session_start = session_start_time
        self.xor = xor
        self._seen = set()
        self._pending = []  # (mtime, f)

    def poll(self):
        """Collect new relay S2C files and update XOR state. Skips INJECT_ files."""
        for f in glob.glob(os.path.join(DUMP_DIR, '*_S2C_*')):
            bn = os.path.basename(f)
            if '_RAW' in bn or 'sniff' in bn.lower() or 'INJECT' in bn or f in self._seen:
                continue
            try:
                mtime = os.path.getmtime(f)
                sz = os.path.getsize(f)
            except OSError:
                continue
            if mtime >= self.session_start and sz > 1:
                self._pending.append((mtime, f))
                self._seen.add(f)

        # Process in time order
        self._pending.sort()
        for mtime, f in self._pending:
            try:
                with open(f, 'rb') as fp:
                    data = fp.read()
                self.xor.advance_by_body(data)
            except OSError:
                pass
        self._pending.clear()

    def try_decrypt(self, enc_data: bytes) -> bytes:
        """Try to decrypt enc_data using CURRENT S2C state (non-destructive snapshot)."""
        key = bytes(self.xor.key)
        ep = self.xor.enc_prev
        plain = bytearray()
        for i, enc_byte in enumerate(enc_data):
            plain_byte = enc_byte ^ key[i % 16] ^ ep
            plain.append(plain_byte)
            ep = enc_byte
        return bytes(plain)


def try_decode_trade_start(raw_bytes: bytes, s2c_xor: RelayS2CTracker) -> list:
    """
    Try to decode S_TRADE_START packet to find entry IDs.
    Returns list of entry IDs if successful, empty list if not.
    """
    if len(raw_bytes) < 20:
        return []

    # Attempt decrypt
    dec = s2c_xor.try_decrypt(raw_bytes)

    # Check: dec[0] should be 0x14 (S_TRADE_START opcode)
    if dec[0] != 0x14:
        log(f"[DECODE] S_TRADE_START opcode mismatch: got 0x{dec[0]:02x}, expected 0x14")
        return []

    # Check: dec[1..4] should be list_id = LIST_ID
    got_list_id = struct.unpack_from('<I', dec, 1)[0]
    if got_list_id != LIST_ID:
        log(f"[DECODE] list_id mismatch: got {got_list_id}, expected {LIST_ID}")
        log(f"[DECODE] dec[:12]={dec[:12].hex()} — XOR state might be off")
        return []

    log(f"[DECODE] S_TRADE_START decoded! list_id={got_list_id} ✓")

    # Try to extract entry count and entry IDs
    # Format: opcode(1) + list_id(4) + is_package(1) + entry_count(4) + entries...
    # But format may vary by version. Try different offsets.
    try:
        # Variant A: opcode + list_id + is_package(1) + count(4)
        offset = 1 + 4 + 1
        count = struct.unpack_from('<I', dec, offset)[0]
        offset += 4
        if 0 < count < 200:
            log(f"[DECODE] Variant A: entry_count={count} at offset 6")
            entry_ids = []
            for _ in range(min(count, 50)):
                if offset + 4 > len(dec):
                    break
                eid = struct.unpack_from('<I', dec, offset)[0]
                entry_ids.append(eid)
                # Skip entry struct (size unknown, try 24 bytes per entry)
                offset += 24
            if entry_ids:
                log(f"[DECODE] Entry IDs found: {entry_ids[:10]}")
                return entry_ids
    except Exception as e:
        log(f"[DECODE] Parse error: {e}")

    # If we can't parse structure, just return IDs 1-10 as fallback
    log("[DECODE] Couldn't parse entry structure, using probe IDs 1-20")
    return []


# ═══ Main loop ═══════════════════════════════════════════════════════════════

log("=== MONITOR v4 (XOR-encrypted injection, no inject_bypass) ===")
log(f"LIST_ID={LIST_ID} PROBE_ENTRIES={ENTRY_PROBE}")
log(f"PACKET_DELAY={PACKET_DELAY}s BYPASS_WAIT={BYPASS_WAIT}s CYCLE_INTERVAL={CYCLE_INTERVAL}s")

last_connected    = False
login_complete    = False
last_inject_time  = 0.0
last_bypass_time  = 0.0
session_start     = 0.0
c2s_tracker       = None
s2c_tracker       = None
trade_detector    = None
c2s_xor           = None
s2c_xor           = None
entry_ids         = []     # Discovered valid entry IDs (if decoded)
known_good_ids    = set()  # Entry IDs confirmed to produce items

while True:
    try:
        status = get_status()
        if 'error' in status:
            log(f"API error: {status['error']}")
            time.sleep(5)
            continue

        connected   = status.get('connected', False)
        store_count = status.get('store_count', 0)
        now         = time.time()

        # ── Reconnect detection ───────────────────────────────────────────
        if connected and not last_connected:
            log("*** RECONNECTED — initializing XOR state ***")
            login_complete   = False
            last_inject_time = now + 15.0   # Suppress for 15s after connect
            last_bypass_time = 0.0
            session_start    = now - 0.5    # Files modified from ~now

            # Get fresh key
            crypto = get_crypto()
            xkey = crypto.get('xor_key', '')
            if not xkey or len(xkey) < 16:
                log(f"[WARN] No XOR key yet: {crypto}")
                last_connected = connected
                time.sleep(1)
                continue

            log(f"[XOR] Session key: {xkey}")
            c2s_xor        = XorState(xkey, C2S_INIT_ROTATION)
            s2c_xor        = XorState(xkey, S2C_INIT_ROTATION)
            c2s_tracker    = RelayC2STracker(session_start)
            s2c_tracker    = RelayS2CTracker(session_start, s2c_xor)
            trade_detector = S2CTradeStartDetector(session_start)
            entry_ids      = []

        last_connected = connected

        if not connected:
            if int(now) % 30 == 0:
                log(f"[WAIT] disconnected. store={store_count}")
            time.sleep(0.5)
            continue

        # ── Track new relay C2S (advance XOR state) ───────────────────────
        if c2s_tracker and c2s_xor:
            new_bodies = c2s_tracker.get_new_bodies()
            for body in new_bodies:
                c2s_xor.advance_by_body(body)
            if new_bodies:
                log(f"[XOR_TRACK] Processed {len(new_bodies)} new relay C2S. "
                    f"State: {c2s_xor.state_str()}")

        # ── Track new relay S2C (for decoding S_TRADE_START) ──────────────
        if s2c_tracker:
            s2c_tracker.poll()

        # ── Detect S_TRADE_START (decode entry IDs if XOR state good) ─────
        if trade_detector and s2c_tracker and not entry_ids:
            new_trade = trade_detector.get_new_trade_starts()
            for fname, data in new_trade:
                log(f"[TRADE_START] New S_TRADE_START: {os.path.basename(fname)} {len(data)}B")
                ids = try_decode_trade_start(data, s2c_tracker)
                if ids:
                    entry_ids = ids
                    log(f"[ENTRY_IDS] Decoded: {entry_ids}")
                    break

        # ── Login completion ───────────────────────────────────────────────
        if not login_complete and store_count > LOGIN_THRESH:
            login_complete = True
            log(f"*** LOGIN COMPLETE (store_count={store_count}) ***")
            last_inject_time = now + 5.0   # Grace period

        if not login_complete:
            time.sleep(0.5)
            continue

        # ── Main inject cycle ──────────────────────────────────────────────
        if now - last_inject_time < CYCLE_INTERVAL:
            time.sleep(0.5)
            continue

        # Check XOR ready
        if not c2s_xor:
            log("[SKIP] XOR state not initialized")
            time.sleep(2)
            continue

        log(f"[CYCLE] store={store_count} c2s_state=({c2s_xor.state_str()})")

        # ── Step 1: Send XOR-encrypted bypass "multisell LIST_ID" ─────────
        if now - last_bypass_time >= BYPASS_INTERVAL:
            bypass_plain = build_bypass_pkt(f"multisell {LIST_ID}")
            bypass_enc   = c2s_xor.encrypt(bypass_plain)
            r = inject_raw_hex(bypass_enc.hex())
            log(f"[BYPASS] multisell {LIST_ID} (XOR-enc {len(bypass_enc)}B): {r}")
            last_bypass_time = now
            time.sleep(BYPASS_WAIT)

        # ── Step 2: Send XOR-encrypted 0xB0 for each entry ID ─────────────
        ids_to_try = entry_ids if entry_ids else ENTRY_PROBE
        sent = 0
        for eid in ids_to_try:
            pkt_plain = build_multisell_pkt(LIST_ID, eid, 1)
            pkt_enc   = c2s_xor.encrypt(pkt_plain)
            r = inject_raw_hex(pkt_enc.hex())
            status_str = r.get('status', r.get('error', '?'))
            log(f"  [0xB0] entry={eid}: {status_str}")
            sent += 1
            time.sleep(PACKET_DELAY)

        log(f"[CYCLE DONE] Sent {sent} 0xB0 packets.")
        last_inject_time = now

    except KeyboardInterrupt:
        log("Stopped by user.")
        break
    except Exception as e:
        log(f"Loop error: {e}")
        import traceback
        log(traceback.format_exc()[:500])
        time.sleep(3)
