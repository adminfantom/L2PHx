"""Monitor v3 — rate-limited multisell injection. Fixes anti-flood disconnect from v2.

Root cause of v2 failure:
  inject_c2s queue accumulates 24-30 packets during the 9s login phase.
  All fire at once on the first real C2S → server anti-flood disconnect.

v3 strategy:
  1. Wait until login sequence is complete (store_count rises above LOGIN_COMPLETE threshold)
  2. Use multisell_cap/replay (direct server_sock send, no queue) for already-captured packets
  3. For queue-based injection: only add 1 packet per cycle, verify queue would be near-empty first
  4. All individual packet sends separated by PACKET_DELAY seconds
  5. On reconnect: do NOT inject during login phase
"""
import urllib.request, json, time, struct, os

API = 'http://127.0.0.1:8877/api'
LIST_ID  = 8658
ENTRIES  = [1, 3, 5, 7]

# Timing constants — tuned to avoid L2 anti-flood
PACKET_DELAY     = 0.25   # minimum seconds between any two packets to server
BYPASS_DELAY     = 1.5    # wait after bypass before sending MultiSellChoose
CYCLE_INTERVAL   = 10.0   # seconds between full inject cycles
LOGIN_SC_THRESH  = 40     # store_count must exceed this before we consider player "in game"
                           # (login sequence typically produces 30-50 S2C packets)
REPLAY_PER_ENTRY = 3      # how many replays per entry (keep low to avoid flood)

OUT = os.path.join(os.path.dirname(__file__), 'logs', '_monitor_v3.txt')
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    msg = f"[{time.strftime('%H:%M:%S')}] {s}"
    lines.append(msg)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines[-2000:]) + '\n')
    print(msg)


def api(data, timeout=5):
    body = json.dumps(data).encode()
    req = urllib.request.Request(API, data=body,
                                  headers={'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read())
    except Exception as e:
        return {'error': str(e)}


def send_one_bypass(cmd):
    """Queue a single bypass string. Returns API response."""
    return api({'action': 'inject_bypass', 'command': cmd})


def send_one_raw(hex_data):
    """Queue a single raw packet. Returns API response."""
    return api({'action': 'inject_raw', 'hex_data': hex_data})


def replay_one(entry_id, count=1):
    """Send directly via multisell_cap/replay (bypasses inject_c2s queue).
    count=1 sends exactly one packet. Call multiple times for more."""
    return api({'action': 'multisell_cap', 'sub': 'replay',
                'idx': -1, 'entry_id': entry_id, 'count': count})


def get_status():
    return api({'action': 'get_status'})


def get_cap_status():
    return api({'action': 'multisell_cap', 'sub': 'status'})


def get_crypto():
    return api({'action': 'get_crypto'})


def safe_inject_bypass_sequence():
    """Open multisell and send ONE MultiSellChoose per entry — rate-limited.
    Uses the inject_c2s queue but sends packets one by one with delays.
    Only call when you're confident the queue is empty and login is complete."""

    log("[SAFE_INJ] Sending bypass 'multisell {}'".format(LIST_ID))
    r = send_one_bypass(f"multisell {LIST_ID}")
    log(f"  bypass: {r}")
    time.sleep(BYPASS_DELAY)   # wait for server to send S_MULTI_SELL_LIST back

    for eid in ENTRIES:
        # IDA MCP confirmed format (NWindow.dll execRequestMultiSellChoose, slot 0x640):
        # opcode(B) + GroupID(I) + InfoID(I) + ItemCount(I) + Enchant(I) +
        # AttrDefHoly(I) + IsBlessedItem(I) + n_ensoul_slots(I=3) + EnsoulOptionNum_i(I)*3
        # Total: 41 bytes, all LE32
        pkt = struct.pack('<BIIIIIII', 0xB0, LIST_ID, eid, 1, 0, 0, 0, 3) + b'\x00' * 12
        r = send_one_raw(pkt.hex())
        log(f"  MultiSellChoose entry={eid}: {r}")
        time.sleep(PACKET_DELAY)   # rate limit between packets


def safe_replay_all(cap_count):
    """Replay captured packet for all entries — one packet at a time with delay."""
    log(f"[REPLAY] cap_count={cap_count}, replaying {REPLAY_PER_ENTRY}x each entry {ENTRIES}")
    for _ in range(REPLAY_PER_ENTRY):
        for eid in ENTRIES:
            r = replay_one(eid, count=1)   # send exactly 1 packet
            status = r.get('ok', r.get('error', 'err'))
            log(f"  replay entry={eid}: {status}")
            time.sleep(PACKET_DELAY)


log("=== MONITOR v3 (rate-limited) ===")
log(f"LIST_ID={LIST_ID} ENTRIES={ENTRIES}")
log(f"PACKET_DELAY={PACKET_DELAY}s BYPASS_DELAY={BYPASS_DELAY}s CYCLE_INTERVAL={CYCLE_INTERVAL}s")
log(f"LOGIN_SC_THRESH={LOGIN_SC_THRESH} REPLAY_PER_ENTRY={REPLAY_PER_ENTRY}")

last_connected   = False
last_cap_count   = 0
last_inject_time = 0
login_complete   = False    # True once store_count exceeds LOGIN_SC_THRESH after connect

while True:
    try:
        status = get_status()
        if 'error' in status:
            log(f"API error: {status['error']}")
            time.sleep(5)
            continue

        connected   = status.get('connected', False)
        store_count = status.get('store_count', 0)

        cap_resp  = get_cap_status()
        cap_count = cap_resp.get('count', 0)
        now       = time.time()

        # ── Detect new capture ─────────────────────────────────────────────
        if cap_count > last_cap_count:
            log(f"*** NEW C2S 0xB0 CAPTURE! {last_cap_count}→{cap_count} ***")
            last_cap_count = cap_count
            if connected and login_complete:
                safe_replay_all(cap_count)
                last_inject_time = now   # update cooldown

        # ── Detect reconnect ───────────────────────────────────────────────
        if connected and not last_connected:
            log("*** RECONNECTED — waiting for login to complete ***")
            login_complete   = False
            last_inject_time = now + 15.0   # suppress injections for 15s after connect
        last_connected = connected

        # ── Detect login completion ────────────────────────────────────────
        if connected and not login_complete and store_count > LOGIN_SC_THRESH:
            login_complete = True
            log(f"*** LOGIN COMPLETE (store_count={store_count}) — ready to inject ***")
            # Give an extra grace period before first inject
            last_inject_time = now + 3.0

        # ── Main inject cycle ──────────────────────────────────────────────
        elapsed = now - last_inject_time
        if connected and login_complete and elapsed >= CYCLE_INTERVAL:
            crypto = get_crypto()
            # В PLAINTEXT_INTERMEDIATE режиме KeyInit не приходит → initialized=False всегда.
            # Но passthrough=True устанавливается сразу после первого S2C — это признак готовности.
            crypto_ready = crypto.get('initialized', False) or crypto.get('passthrough', False)
            if not crypto_ready:
                log("[SKIP] Crypto not ready (initialized=False, passthrough=False)")
                time.sleep(2)
                continue

            log(f"[CYCLE] store={store_count} cap={cap_count} xor={str(crypto.get('xor_key','?'))[:8]}")

            if cap_count > 0:
                # Prefer replay (direct-send, no queue) when we have a capture
                safe_replay_all(cap_count)
            else:
                # No capture yet — inject via queue (only if safe to do so)
                safe_inject_bypass_sequence()

            last_inject_time = now

        elif not connected:
            if int(now) % 30 == 0:
                log(f"[WAIT] disconnected. cap={cap_count} sc={store_count}")

        time.sleep(0.5)

    except KeyboardInterrupt:
        log("Stopped by user")
        break
    except Exception as e:
        log(f"Loop error: {e}")
        time.sleep(3)
