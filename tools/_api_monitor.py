"""Monitor via web API (port 8877) and inject correct multisell bypass.

Runs as standalone script (no admin needed).
Injects 'multisell 81381' + MultiSellChoose for entries 1,3,5,7 every 15s when player is in game.
"""
import urllib.request, json, time, struct, os, sys

API = 'http://127.0.0.1:8877/api'
LIST_ID = 81381
ENTRIES = [1, 3, 5, 7]
OUT = os.path.join(os.path.dirname(__file__), 'logs', '_api_monitor.txt')
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    msg = f"[{time.strftime('%H:%M:%S')}] {s}"
    lines.append(msg)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines[-500:]) + '\n')
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

def multisell_choose(list_id, entry_id, amount=1):
    pkt = struct.pack('<BIIq', 0xB0, list_id, entry_id, amount) + b'\x00' * 24
    return inject_raw(pkt.hex())

log("=== API MONITOR v1 ===")
log(f"Target multisell: {LIST_ID}, entries: {ENTRIES}")

last_inject_time = 0
last_seq = 0
inject_count = 0
success_count = 0

while True:
    try:
        # 1. Check status
        status = api({'action': 'get_status'})
        if 'error' in status:
            log(f"API error: {status['error']}")
            time.sleep(5)
            continue

        running = status.get('running', False)
        connected = status.get('connected', False)
        store_count = status.get('store_count', 0)

        # 2. Check crypto (is player in game?)
        crypto = api({'action': 'get_crypto'})
        initialized = crypto.get('initialized', False)
        xor_key = crypto.get('xor_key')

        # 3. Check multisell captures
        cap_resp = api({'action': 'multisell_cap', 'sub': 'status'})
        cap_count = cap_resp.get('count', 0)

        if cap_count > success_count:
            success_count = cap_count
            log(f"*** SUCCESS! multisell_cap count={cap_count} ***")
            log(f"Cap data: {json.dumps(cap_resp.get('captured', [])[:2])}")

        now = time.time()
        elapsed = now - last_inject_time

        # 4. Only inject if connected and 15s cooldown
        if running and connected and elapsed >= 15.0:
            # Try both with and without NPC OID
            # Strategy 1: simple multisell (works if near NPC on some servers)
            cmd1 = f"multisell {LIST_ID}"
            r1 = inject_bypass(cmd1)

            # Strategy 2: also try with estimated NPC OID (byte3=0xd8, try range)
            # npcObjectId candidates based on our cross-session analysis: MSB=0xd8
            # Try a few candidates based on common NPC template IDs
            # We'll try the bypass first and see

            time.sleep(0.3)

            # Inject MultiSellChoose for all entries
            choose_results = []
            for entry_id in ENTRIES:
                r = multisell_choose(LIST_ID, entry_id, 1)
                choose_results.append(r.get('status', 'err'))
                time.sleep(0.05)

            inject_count += 1
            last_inject_time = now

            # Also check recent packets to see if server responded
            pkts = api({'action': 'get_packets', 'count': 20})
            recent_d0 = [p for p in pkts.get('packets', [])
                         if p.get('opcode') == 0xD0 or p.get('opcode_hex') == '0xD0']

            log(f"[{inject_count}] bypass={r1.get('size', 'err')}B choose={choose_results} "
                f"cap={cap_count} d0={len(recent_d0)} "
                f"init={initialized} xor={xor_key[:8] if xor_key else None}")

            if recent_d0:
                for p in recent_d0:
                    log(f"  D0 FOUND! seq={p.get('seq')} sz={p.get('len') or p.get('size')} "
                        f"ts={p.get('ts') or p.get('time')} inj={p.get('injected')}")
        else:
            # Just status line every 30s
            if int(now) % 30 == 0:
                log(f"[WAIT] running={running} connected={connected} init={initialized} "
                    f"cap={cap_count} xor={xor_key[:8] if xor_key else None} next={max(0,int(15-elapsed))}s")

        time.sleep(1.0)

    except KeyboardInterrupt:
        log("Stopped by user")
        break
    except Exception as e:
        log(f"Loop error: {e}")
        time.sleep(5)
