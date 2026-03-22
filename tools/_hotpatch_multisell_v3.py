"""MULTISELL INJECT v3 — полное исправление.

Ключевые исправления:
1. Правильная длина MultiSellChoose = 42 байта (padding=25, не 24)
2. Инжект в 3 форматах: field-XOR из сессии 11:28, field-XOR из сессии 04:25 (частичный),
   plaintext 42-байт (на случай если сервер не декодирует field-XOR)
3. Множественные форматы bypass: B3/23/74/B0
4. Фоновый монитор: при появлении РЕАЛЬНОГО захвата 0xB0 — немедленный replay
5. Инжект ExMultiSellList перед MultiSellChoose
"""
import gc, time, struct, threading, os, json, sys

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_multisell_v3.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

LINES = []
def log(s):
    ts = time.strftime('%H:%M:%S')
    msg = f"[{ts}] {s}"
    LINES.append(msg)
    try:
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(LINES[-500:]) + "\n")
    except: pass
    print(msg)

log("=== MULTISELL INJECT v3 STARTED ===")
log(f"PID: {os.getpid()}")

# === Найти proxy ===
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
log(f"inject_c2s len before: {len(proxy.inject_c2s)}")

# === Найти _engine модуль ===
engine = None
for name, mod in list(sys.modules.items()):
    if hasattr(mod, '_MULTISELL_CAP') and hasattr(mod, 'multisell_replay_modify'):
        engine = mod
        break

if not engine:
    log("FATAL: _engine module not found")
    raise SystemExit(1)

log(f"Engine: {engine.__name__}")
log(f"_MULTISELL_CAP captured: {len(engine._MULTISELL_CAP.get('captured', []))}")

# ====================================================
# КОНСТАНТЫ
# ====================================================

LIST_ID = 81381
ENTRIES = [1, 3, 5, 7]  # все нужные позиции мультисела

# Реальный захват игрока из сессии 11:28 (19 марта):
# list_id=81381, entry_id=1, amount=1, 42 байта
CAPTURE_1128 = "b0f0816db0f097a5b0f093d094a9a7eb4eb956a9d9f10e83ebfed7cf5cdec294b8d5abaa03fd6004d6b4"

# ====================================================
# ФУНКЦИИ ПОСТРОЕНИЯ ПАКЕТОВ
# ====================================================

def build_bypass_b3(cmd):
    """0xB3 = BypassUserCmd"""
    enc = cmd.encode('utf-16-le') + b'\x00\x00'
    return bytes([0xB3]) + struct.pack('<H', len(cmd) + 1) + enc

def build_bypass_23(cmd):
    """0x23 = RequestBypassToServer (стандартный)"""
    enc = cmd.encode('utf-16-le') + b'\x00\x00'
    return bytes([0x23]) + struct.pack('<H', len(cmd) + 1) + enc

def build_bypass_74(cmd):
    """0x74 = SendBypassBuildCmd"""
    enc = cmd.encode('utf-16-le') + b'\x00\x00'
    return bytes([0x74]) + struct.pack('<H', len(cmd) + 1) + enc

def build_bypass_b0(cmd):
    """0xB0 + UTF-16LE (формат из INJECT файлов)"""
    enc = cmd.encode('utf-16-le') + b'\x00\x00'
    return bytes([0xB0]) + enc

def build_multisell_plain(list_id, entry_id, amount=1):
    """Plaintext MultiSellChoose, 42 байта (ИСПРАВЛЕНО: padding=25)"""
    return struct.pack("<BIIq", 0xB0, list_id, entry_id, amount) + b'\x00' * 25

def build_ex_multisell_list(list_id):
    """ExMultiSellList request — C2S opcode 0xD0"""
    # Формат: opcode(1) + unk(2) + list_id(4) = 7 байт
    # Из _multisell_xor.txt: plain = d09e01e53d0100
    # Но: 0x9E01 неясно, попробуем несколько форматов
    return struct.pack("<BBHI", 0xD0, 0x9E, 0x0001, list_id)

def multisell_replay_modify_local(captured_hex, new_entry_id, old_entry_id=1, new_amount=1, old_amount=1):
    """XOR-арифметика без знания ключа. ТОЛЬКО для пакетов из той же сессии!"""
    data = bytearray.fromhex(captured_hex)
    if len(data) < 17:
        raise ValueError(f"Too short: {len(data)}")
    # Изменить entryId (bytes 5-8)
    old_eid = struct.pack("<I", old_entry_id)
    new_eid = struct.pack("<I", new_entry_id)
    for i in range(4):
        data[5 + i] ^= old_eid[i] ^ new_eid[i]
    # Изменить amount (bytes 9-16) если нужно
    if new_amount != old_amount:
        old_amt = struct.pack("<q", old_amount)
        new_amt = struct.pack("<q", new_amount)
        for i in range(8):
            data[9 + i] ^= old_amt[i] ^ new_amt[i]
    return bytes(data)

# ====================================================
# ИНЖЕКТ BYPASS (все форматы)
# ====================================================
cmd = f"multisell {LIST_ID}"

log(f"\n=== ШАГ 1: BYPASS в 4 форматах ===")
log(f"Команда: '{cmd}'")

for name, pkt in [
    ("0xB3 BypassUserCmd", build_bypass_b3(cmd)),
    ("0x23 RequestBypass", build_bypass_23(cmd)),
    ("0x74 SendBypass", build_bypass_74(cmd)),
    ("0xB0 UTF16LE", build_bypass_b0(cmd)),
]:
    proxy.inject_c2s.append(pkt)
    log(f"  Queued {name} sz={len(pkt)} hex={pkt[:8].hex()}")

time.sleep(2.0)

# ====================================================
# ИНЖЕКТ ExMultiSellList
# ====================================================
log(f"\n=== ШАГ 2: ExMultiSellList ===")
eml = build_ex_multisell_list(LIST_ID)
proxy.inject_c2s.append(eml)
log(f"  Queued ExMultiSellList sz={len(eml)} hex={eml.hex()}")

time.sleep(1.5)

# ====================================================
# ИНЖЕКТ MultiSellChoose — PLAINTEXT 42-байт
# ====================================================
log(f"\n=== ШАГ 3: MultiSellChoose PLAINTEXT (42 байт) ===")
for entry_id in ENTRIES:
    pkt = build_multisell_plain(LIST_ID, entry_id, 1)
    proxy.inject_c2s.append(pkt)
    log(f"  Plain entry={entry_id} sz={len(pkt)} hex={pkt[:10].hex()}")
    time.sleep(0.2)

time.sleep(2.0)

# ====================================================
# ИНЖЕКТ MultiSellChoose — FIELD-XOR из сессии 11:28
# ====================================================
log(f"\n=== ШАГ 4: MultiSellChoose FIELD-XOR (сессия 11:28) ===")
for entry_id in ENTRIES:
    pkt_hex = multisell_replay_modify_local(CAPTURE_1128, entry_id, 1)
    proxy.inject_c2s.append(pkt_hex)
    log(f"  XOR-1128 entry={entry_id} sz={len(pkt_hex)} hex={pkt_hex[:10].hex()}")
    time.sleep(0.2)

time.sleep(3.0)

# ====================================================
# ЕЩЁ РАЗ bypass + plaintext (retry)
# ====================================================
log(f"\n=== ШАГ 5: RETRY bypass + plain ===")
proxy.inject_c2s.append(build_bypass_b3(cmd))
proxy.inject_c2s.append(build_bypass_23(cmd))
time.sleep(1.5)
for entry_id in ENTRIES:
    pkt = build_multisell_plain(LIST_ID, entry_id, 1)
    proxy.inject_c2s.append(pkt)
    time.sleep(0.15)
log("  Retry complete")

# ====================================================
# ФОНОВЫЙ МОНИТОР: ждём реального захвата и replay
# ====================================================
log(f"\n=== ШАГ 6: ЗАПУСК МОНИТОРА ===")

_monitor_done = False

def _monitor():
    global _monitor_done
    cap_list = engine._MULTISELL_CAP.get('captured', [])
    last_len = len(cap_list)
    seen_entries = set()
    injection_count = [0]

    log(f"[Monitor] started, current cap count={last_len}")

    for iteration in range(0, 1800):  # 30 минут максимум
        time.sleep(1.0)

        cap_list = engine._MULTISELL_CAP.get('captured', [])
        if len(cap_list) > last_len:
            # Новый захват!
            new_caps = cap_list[last_len:]
            last_len = len(cap_list)

            for cap in new_caps:
                if isinstance(cap, (bytes, bytearray)):
                    cap_hex = cap.hex()
                elif isinstance(cap, str):
                    cap_hex = cap
                elif isinstance(cap, dict):
                    cap_hex = cap.get('hex', '') or cap.get('game_body', '')
                    if isinstance(cap_hex, (bytes, bytearray)):
                        cap_hex = cap_hex.hex()
                else:
                    log(f"[Monitor] Unknown capture type: {type(cap)}")
                    continue

                if not cap_hex or len(cap_hex) < 20:
                    log(f"[Monitor] Capture too short: {cap_hex}")
                    continue

                log(f"\n[Monitor] *** НОВЫЙ ЗАХВАТ 0xB0! len={len(cap_hex)//2} hex={cap_hex[:20]}...")

                # Определяем entry_id из захвата (используем факт что первый захват = entry_id=1)
                # и используем XOR-арифметику для остальных
                captured_entry = 1  # предполагаем что первый захват = entry_id=1

                log(f"[Monitor] Replay entries {ENTRIES} из захваченного entry={captured_entry}")
                proxy.inject_c2s.append(build_bypass_b3(cmd))
                proxy.inject_c2s.append(build_bypass_23(cmd))
                time.sleep(1.5)

                for e_id in ENTRIES:
                    try:
                        modified = multisell_replay_modify_local(
                            cap_hex, e_id, old_entry_id=captured_entry)
                        proxy.inject_c2s.append(modified)
                        log(f"[Monitor]   Queued SAME-SESSION entry={e_id} sz={len(modified)}")
                        injection_count[0] += 1
                        time.sleep(0.2)
                    except Exception as ex:
                        log(f"[Monitor]   ERROR entry={e_id}: {ex}")

                log(f"[Monitor] Total injected: {injection_count[0]}")

        if iteration % 60 == 0:
            log(f"[Monitor] iter={iteration} cap={len(cap_list)} injected={injection_count[0]}")

    log("[Monitor] Done (30min timeout)")
    _monitor_done = True

t = threading.Thread(target=_monitor, name='multisell_v3_monitor', daemon=True)
t.start()
log(f"Monitor thread started: {t.name} id={t.ident}")

log(f"\n=== DONE: все пакеты отправлены, монитор активен ===")
log(f"inject_c2s len after: {len(proxy.inject_c2s)}")
