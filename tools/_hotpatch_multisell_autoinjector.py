"""
Hot-patch: background thread that watches for player's multisell activity
and auto-injects MultiSellChoose for scrolls (entries 1,3,5,7).

Flow:
  1. Player walks to NPC, opens dialog (NPC has multisell 81381)
  2. Player clicks multisell button → C2S bypass "multisell 81381" (opcode 0x23)
  3. Server responds with multisell list
  4. Player sends MultiSellChoose (opcode 0xB0, list_id=81381)
  5. THIS HOOK: detects 0xB0 in _MULTISELL_CAP or detects 0x23 bypass →
     auto-injects MultiSellChoose for entries 1,3,5,7

Also: immediately tries injecting via WebSocket (list might still be open).
"""
import os
import gc
import time
import struct
import threading
import json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_autoinjector.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

LOG_LINES = []

def log(s):
    ts = time.strftime('%H:%M:%S')
    msg = f"[{ts}] {s}"
    LOG_LINES.append(msg)
    try:
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(LOG_LINES) + "\n")
    except:
        pass
    print(msg)


def build_multisell_choose(list_id, entry_id, amount=1):
    return struct.pack("<BIIq", 0xB0, list_id, entry_id, amount) + b'\x00' * 24


def build_bypass(command):
    encoded = command.encode('utf-16-le') + b'\x00\x00'
    return b'\x23' + struct.pack('<H', len(command) + 1) + encoded


def inject_multisell_sequence(proxy, list_id=81381):
    """Inject MultiSellChoose for entries 1,3,5,7."""
    entries = [1, 3, 5, 7]
    for entry_id in entries:
        pkt = build_multisell_choose(list_id, entry_id, 1)
        proxy.inject_c2s.append(pkt)
        log(f"  INJECTED MultiSellChoose list={list_id} entry={entry_id} size={len(pkt)}")
        time.sleep(0.05)


def get_proxy_and_globals():
    proxy = None
    engine_globals = None
    for obj in gc.get_objects():
        try:
            if hasattr(obj, 'crypto') and hasattr(obj, 'server_sock') and hasattr(obj, 'inject_c2s'):
                proxy = obj
                if hasattr(obj, 'run') and hasattr(obj.run, '__func__'):
                    engine_globals = obj.run.__func__.__globals__
                break
        except:
            pass
    return proxy, engine_globals


def monitor_thread():
    log("=== AUTOINJECTOR THREAD STARTED ===")
    log("Waiting for proxy...")

    proxy, eng_globs = get_proxy_and_globals()
    if not proxy:
        log("FATAL: proxy not found")
        return

    log(f"Proxy: {type(proxy).__name__}")

    multisell_cap = None
    game_cap = None
    if eng_globs:
        multisell_cap = eng_globs.get('_MULTISELL_CAP')
        game_cap = eng_globs.get('_GAME_CAP')

    log(f"_MULTISELL_CAP available: {multisell_cap is not None}")
    log(f"_GAME_CAP available: {game_cap is not None}")

    # Enable capture if not already
    if multisell_cap:
        multisell_cap['enabled'] = True
        multisell_cap['max_captures'] = 50

    # Get store
    store = getattr(proxy, 'store', None)
    if not store and eng_globs:
        store = eng_globs.get('store')
    if not store:
        for obj in gc.get_objects():
            try:
                if hasattr(obj, 'packets') and hasattr(obj, 'add') and hasattr(obj, 'get_recent'):
                    store = obj
                    break
            except:
                pass

    log(f"Store: {type(store).__name__ if store else 'NOT FOUND'}")

    last_multisell_count = 0
    last_processed_seq = 0
    already_injected_seqs = set()
    inject_cooldown = 0

    TARGET_LIST = 81381
    ENTRIES = [1, 3, 5, 7]

    log(f"Monitoring for multisell {TARGET_LIST}, entries {ENTRIES}")
    log("=" * 50)

    # --- Immediate attempt: try inject right now ---
    # (might work if multisell list is still open from previous interaction)
    log("IMMEDIATE ATTEMPT: injecting multisell sequence now...")
    # First inject bypass to (re)open list
    bypass_pkt = build_bypass(f"multisell {TARGET_LIST}")
    proxy.inject_c2s.append(bypass_pkt)
    log(f"  Injected bypass 'multisell {TARGET_LIST}' size={len(bypass_pkt)}")
    time.sleep(0.8)
    inject_multisell_sequence(proxy, TARGET_LIST)
    log("  Immediate attempt done")

    iteration = 0
    while True:
        try:
            time.sleep(0.2)
            iteration += 1

            now_ts = time.time()

            # === WATCH _MULTISELL_CAP ===
            if multisell_cap:
                caps = multisell_cap.get('captured', [])
                if len(caps) > last_multisell_count:
                    # New MultiSellChoose captured!
                    new_caps = caps[last_multisell_count:]
                    last_multisell_count = len(caps)
                    for cap in new_caps:
                        ts = cap.get('ts', '?')
                        game_hex = cap.get('game_hex', '')
                        game_len = cap.get('game_len', 0)
                        log(f"\n*** NEW MultiSellChoose captured at {ts} len={game_len} ***")
                        log(f"    hex: {game_hex[:40]}")

                        # Decode list_id from raw game_body
                        try:
                            raw = bytes.fromhex(game_hex)
                            # game_body: opcode(1) + list_id(4) + entry_id(4) + amount(8) + pad(24)
                            if len(raw) >= 9:
                                list_id = struct.unpack_from('<I', raw, 1)[0]
                                entry_id = struct.unpack_from('<I', raw, 5)[0]
                                log(f"    list_id={list_id} entry_id={entry_id}")
                                if list_id == TARGET_LIST:
                                    log(f"    TARGET LIST DETECTED! Injecting entries {ENTRIES}...")
                                    time.sleep(0.3)
                                    inject_multisell_sequence(proxy, TARGET_LIST)
                        except Exception as e:
                            log(f"    decode err: {e}")

            # === WATCH STORE FOR C2S 0x23 (bypass) ===
            if store and now_ts > inject_cooldown:
                try:
                    recent = store.get_recent(50)
                    for p in recent:
                        if not isinstance(p, dict):
                            continue
                        seq = p.get('seq', 0)
                        if seq in already_injected_seqs or seq <= last_processed_seq:
                            continue
                        d = str(p.get('dir', p.get('direction', ''))).upper()
                        if 'C2S' not in d:
                            continue
                        op = p.get('opcode', 0)
                        if isinstance(op, str):
                            try:
                                op = int(op, 16) if op.startswith('0x') else int(op)
                            except:
                                op = 0
                        name = str(p.get('name', ''))

                        # Detect bypass (0x23 or name contains RequestBypassToServer)
                        is_bypass = (op == 0x23) or ('bypass' in name.lower() and 'c2s' in d)
                        if is_bypass:
                            dec = p.get('dec_hex', p.get('hex', ''))
                            already_injected_seqs.add(seq)
                            if seq > last_processed_seq:
                                last_processed_seq = seq

                            # Decode bypass command
                            cmd = ''
                            if dec:
                                try:
                                    raw = bytes.fromhex(dec)
                                    # bypass: opcode(1) + string(utf16le null-term)
                                    # Or opcode + len_u16 + utf16le string
                                    if len(raw) >= 3:
                                        # Try with length prefix
                                        str_len = struct.unpack_from('<H', raw, 1)[0] if len(raw) >= 3 else 0
                                        str_bytes = raw[3:3 + str_len * 2] if str_len else raw[1:]
                                        cmd = str_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
                                except:
                                    pass

                            log(f"\n[seq={seq}] C2S BYPASS detected! cmd='{cmd[:60]}'")

                            if str(TARGET_LIST) in cmd or 'multisell' in cmd.lower():
                                log(f"  TARGET MULTISELL! Injecting sequence in 400ms...")
                                inject_cooldown = now_ts + 5.0
                                time.sleep(0.4)
                                inject_multisell_sequence(proxy, TARGET_LIST)
                            else:
                                log(f"  Not our multisell, skipping")

                        # Also track new MultiSellChoose from relay (game: prefix)
                        if 'b0' in name.lower() or 'multisell' in name.lower():
                            if seq not in already_injected_seqs:
                                already_injected_seqs.add(seq)
                                log(f"\n[seq={seq}] C2S MULTISELLCHOOSE detected in store! name={name}")
                                dec = p.get('dec_hex', p.get('hex', ''))
                                if dec:
                                    try:
                                        raw = bytes.fromhex(dec)
                                        if len(raw) >= 9:
                                            list_id = struct.unpack_from('<I', raw, 1)[0]
                                            entry_id = struct.unpack_from('<I', raw, 5)[0]
                                            log(f"  list_id={list_id} entry_id={entry_id}")
                                            if list_id == TARGET_LIST and now_ts > inject_cooldown:
                                                inject_cooldown = now_ts + 5.0
                                                time.sleep(0.3)
                                                inject_multisell_sequence(proxy, TARGET_LIST)
                                    except:
                                        pass

                except Exception as e:
                    if iteration % 50 == 0:
                        log(f"Store check error: {e}")

            # Periodic status
            if iteration % 150 == 0:
                mc = len(multisell_cap.get('captured', [])) if multisell_cap else '?'
                log(f"[STATUS] iter={iteration} multisell_cap={mc} cooldown={max(0,inject_cooldown-now_ts):.1f}s")

        except Exception as e:
            log(f"Thread error: {e}")
            import traceback
            log(traceback.format_exc())
            time.sleep(1)


def _run():
    log("=== HOTPATCH MULTISELL AUTOINJECTOR ===")
    log(f"PID: {os.getpid()} Time: {time.strftime('%H:%M:%S')}")

    # Check if thread already running
    for t in threading.enumerate():
        if t.name == 'multisell_autoinjector':
            log("Thread already running! Stopping old one...")
            # Can't easily stop it, just start a new one with same name
            break

    t = threading.Thread(target=monitor_thread, name='multisell_autoinjector', daemon=True)
    t.start()
    log(f"Thread started: {t.name} id={t.ident}")
    log("Thread will run in background. Check logs at:")
    log(f"  {OUT}")


_run()
