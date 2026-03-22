"""Monitor v2 — aggressive multisell injection + capture replay.

Improvements over v1:
- Injects IMMEDIATELY on reconnect (0s delay first time, then every 3s)
- Monitors multisell_cap: when count increases → replay all 4 entries 30x
- Monitors store_count: rapid jump = large S2C arrived → multisell may be open → inject NOW
- Also replays via multisell_cap API (uses captured player's own packet with correct encryption)
"""
import urllib.request, json, time, struct, os, sys

API = 'http://127.0.0.1:8877/api'
LIST_ID = 81381
ENTRIES = [1, 3, 5, 7]
INJECT_INTERVAL = 3.0      # seconds between inject attempts
REPLAY_COUNT    = 30       # how many times to replay each captured entry
OUT = os.path.join(os.path.dirname(__file__), 'logs', '_monitor_v2.txt')
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    msg = f"[{time.strftime('%H:%M:%S')}] {s}"
    lines.append(msg)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines[-1000:]) + '\n')
    print(msg)

def api(data, timeout=5):
    body = json.dumps(data).encode()
    req = urllib.request.Request(API, data=body, headers={'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read())
    except Exception as e:
        return {'error': str(e)}

def inject_bypass(cmd):
    return api({'action': 'inject_bypass', 'command': cmd})

def inject_raw(hex_data):
    return api({'action': 'inject_raw', 'hex_data': hex_data})

def multisell_choose_raw(list_id, entry_id, amount=1):
    pkt = struct.pack('<BIIq', 0xB0, list_id, entry_id, amount) + b'\x00' * 24
    return inject_raw(pkt.hex())

def replay_captured(entry_id, count=REPLAY_COUNT):
    """Replay last captured player C2S 0xB0 with modified entry_id."""
    return api({'action': 'multisell_cap', 'sub': 'replay',
                'idx': -1, 'entry_id': entry_id, 'count': count})

def do_full_inject(label=""):
    """Send bypass + ExMultiSellList + captured FED0 + MultiSellChoose for all entries."""
    # Strategy 1: standard bypass 'multisell LIST_ID'
    r_bp = inject_bypass(f"multisell {LIST_ID}")
    # Strategy 2: custom bypass '_mrsl LIST_ID' (server shortcut found in logs)
    inject_bypass(f"_mrsl {LIST_ID}")
    # Strategy 3: C2S ExPacket 0xD0 sub=0x019E with listId (ExMultiSellList, 7 bytes)
    ex_pkt = struct.pack('<BHI', 0xD0, 0x019E, LIST_ID)
    inject_raw(ex_pkt.hex())
    # Strategy 4: C2S ExPacket 0xD0 sub=0x6ED0 (NPC click captured from 22:32 session, 32 bytes)
    # Relay protocol sends game bodies as plaintext; npcObjectId may still be valid
    fed0_hex = 'd0d06e985951cce37ea720221da072faf8b9364a87d2b57493ea597ce18d1f49'
    inject_raw(fed0_hex)
    time.sleep(0.15)
    results = []
    for eid in ENTRIES:
        r = multisell_choose_raw(LIST_ID, eid, 1)
        results.append(r.get('status', r.get('error', 'err'))[:6])
        time.sleep(0.04)
    log(f"[INJ{label}] bypass={r_bp.get('size','err')}B ex_pkt={ex_pkt.hex()} choose={results}")
    return results

def do_replay_all(cap_count):
    """Replay captured player packet for all 4 entries."""
    log(f"[REPLAY] cap_count={cap_count} → replaying {REPLAY_COUNT}x each entry {ENTRIES}")
    for eid in ENTRIES:
        r = replay_captured(eid, REPLAY_COUNT)
        log(f"  replay entry={eid}: {r}")
        time.sleep(0.1)

log("=== MONITOR v2 ===")
log(f"LIST_ID={LIST_ID} ENTRIES={ENTRIES} interval={INJECT_INTERVAL}s replay={REPLAY_COUNT}x")

last_inject_time    = 0
last_cap_count      = 0
last_store_count    = 0
last_connected      = False
inject_count        = 0
was_disconnected    = True   # start assuming disconnected

while True:
    try:
        status = api({'action': 'get_status'})
        if 'error' in status:
            log(f"API error: {status['error']}")
            time.sleep(5)
            continue

        running   = status.get('running', False)
        connected = status.get('connected', False)
        store_count = status.get('store_count', 0)

        cap_resp  = api({'action': 'multisell_cap', 'sub': 'status'})
        cap_count = cap_resp.get('count', 0)

        now = time.time()

        # ── Detect new capture (player bought naturally) ──────────────
        if cap_count > last_cap_count:
            log(f"*** NEW CAPTURE! cap_count {last_cap_count}→{cap_count} ***")
            log(f"    data: {json.dumps(cap_resp.get('captured', [])[:2])}")
            last_cap_count = cap_count
            if connected:
                do_replay_all(cap_count)

        # ── Detect reconnect ──────────────────────────────────────────
        if connected and not last_connected:
            log(f"*** RECONNECTED! Injecting immediately ***")
            was_disconnected = False
            last_inject_time = 0   # force inject NOW
            # small grace period for crypto init
            time.sleep(0.5)

        last_connected = connected

        # ── Detect large S2C burst (store_count spike = potential MultiSellList) ──
        sc_delta = store_count - last_store_count
        if sc_delta >= 5 and connected:
            # Check if any recent large S2C arrived
            pkts = api({'action': 'get_packets', 'count': 10, 'direction': 's2c'})
            large = [p for p in pkts.get('packets', [])
                     if (p.get('len') or p.get('size') or 0) > 200]
            if large:
                log(f"[SC_SPIKE] store_count+{sc_delta}, large S2C: {[(p.get('opcode_hex'),p.get('len') or p.get('size')) for p in large]}")
                # Multisell might be open — inject immediately
                last_inject_time = 0

        last_store_count = store_count

        # ── Main inject loop ──────────────────────────────────────────
        elapsed = now - last_inject_time
        if running and connected and elapsed >= INJECT_INTERVAL:
            crypto  = api({'action': 'get_crypto'})
            initialized = crypto.get('initialized', False)
            xor_key = crypto.get('xor_key')

            inject_count += 1
            do_full_inject(f"#{inject_count}")
            last_inject_time = now

            # If we have a capture, also replay it each cycle
            if cap_count > 0:
                log(f"  [ALSO REPLAY] cap available, replaying all entries")
                for eid in ENTRIES:
                    r = replay_captured(eid, 5)
                    log(f"    replay entry={eid}: {r.get('status', r.get('error','err'))}")
                    time.sleep(0.05)

            # Check recent D0 / large packets
            pkts = api({'action': 'get_packets', 'count': 15})
            large_s2c = [p for p in pkts.get('packets', [])
                         if (p.get('len') or p.get('size') or 0) > 100
                         and p.get('direction') in ('s2c', None)]
            if large_s2c:
                for p in large_s2c[:3]:
                    log(f"  S2C sz={p.get('len') or p.get('size')} op={p.get('opcode_hex') or hex(p.get('opcode',0))} inj={p.get('injected')}")

            log(f"  status: cap={cap_count} sc={store_count} init={initialized} xor={xor_key[:8] if xor_key else None}")

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
