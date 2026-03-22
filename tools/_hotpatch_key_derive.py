"""KEY DERIVE + FIELD-XOR INJECT v1.
Вилучення session XOR ключа з PacketStore та інжект правильно закодованих 0xB0 пакетів.

Алгоритм:
1. Сканує PacketStore на C2S game_bodies (field-XOR encoded)
2. Attack (0x01): plain[5:13]=0 → key[5:13]=enc[5:13]
3. Say (0x1B): plain[2:5]=0 (type is small int) → key[2:5]=enc[2:5]
4. Будь-який пакет >= N байт де plain[i]=0 → key[i]=enc[i]
5. Будує field-XOR encoded 0xB0 та інжектить
"""
import gc, sys, struct, os, time, json

OUT = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_key_derive.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines = []
def log(s):
    lines.append(f"[{time.strftime('%H:%M:%S.%f')[:-3]}] {s}")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])

log("=== KEY DERIVE + FIELD-XOR INJECT v1 ===")
log(f"PID: {os.getpid()}")

# === Знайти proxy та engine ===
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

engine = None
for name, mod in list(sys.modules.items()):
    try:
        if hasattr(mod, '_MULTISELL_CAP') and hasattr(mod, 'wrap_relay_0x06'):
            engine = mod
            break
    except: pass

if not engine:
    log("FATAL: engine module not found")
    raise SystemExit(1)

log(f"Proxy: {type(proxy).__name__}")
store = getattr(proxy, 'store', None)
if not store:
    log("FATAL: proxy.store not found")
    raise SystemExit(1)

log(f"PacketStore: {len(store.packets)} packets")

# === КОНСТАНТИ ===
LIST_ID = 81381
ENTRIES = [1, 3, 5, 7]
list_id_bytes = struct.pack("<I", LIST_ID)  # e5 3d 01 00

# === ВИЛУЧЕННЯ КЛЮЧА ===
# key[i] = enc[i] XOR plain[i]. Ключ 42 байти для 0xB0 пакету.
key = [None] * 64  # з запасом
key[0] = 0x00     # завжди 0 (opcode проходить без змін)

def update_key(pos, enc_byte, plain_byte):
    """Оновлює key[pos] якщо значення узгоджене."""
    k = enc_byte ^ plain_byte
    if key[pos] is None:
        key[pos] = k
        return True
    elif key[pos] != k:
        log(f"  KEY CONFLICT at pos={pos}: existing=0x{key[pos]:02x}, new=0x{k:02x} (enc=0x{enc_byte:02x} plain=0x{plain_byte:02x})")
        return False
    return True  # узгоджено

attack_count = 0
say_count = 0
other_count = 0

with store.lock:
    packets_snap = list(store.packets)

log(f"Scanning {len(packets_snap)} packets...")

for pkt in packets_snap:
    if pkt.get('dir') != 'C2S':
        continue
    extra = pkt.get('extra', {})
    if not extra.get('inner'):
        continue  # тільки game-layer пакети (inner relay)

    body = pkt.get('_body')
    if not body or len(body) < 2:
        continue

    opcode = body[0]

    # === Attack (0x01): plain[0]=0x01, plain[5:13]=[0]*8 ===
    # Формат: opcode(1) + objectId(4) + unk1(4) + unk2(4) = 13 bytes
    # unk1/unk2 зазвичай 0 для звичайної атаки
    if opcode == 0x01 and len(body) >= 13:
        # key[5:13] = body[5:13] (якщо plain[5:13]=0)
        for i in range(5, 13):
            update_key(i, body[i], 0x00)
        attack_count += 1

    # === RequestSay2 (0x1B): plain[2:5]=[0]*3 (type < 256) ===
    # Формат: opcode(1) + type(int32=4) + text(utf16le)
    # type is small (0-15), so plain[2:4] = upper bytes = 0
    elif opcode == 0x1B and len(body) >= 5:
        # plain[2:5] = 0 (type is at most 4 bytes but small value)
        for i in range(2, 5):
            update_key(i, body[i], 0x00)
        say_count += 1
        # Також: в UTF16LE тексті кожен 2-й байт від позиції 5 = 0x00 (для ASCII)
        # Позиція 5 = перший char byte, позиція 6 = 0x00, позиція 8 = 0x00 ...
        for i in range(6, min(len(body), 50), 2):
            update_key(i, body[i], 0x00)

    # === RequestMoveToLocation (0x43): позиції з координатами ===
    # Формат: opcode(1) + targetX(4) + targetY(4) + targetZ(4) [+ origX + origY + origZ]
    # targetZ (позиція 9:13) часто = невелике число або 0 для рівного рельєфу
    # НЕ використовуємо - занадто ненадійно

    # === RequestBypassToServer (0x23) inject ===
    # Якщо пакет лейбловий як INJECT - це plaintext, пропускаємо
    opname = pkt.get('opname', '')
    if 'INJECT' in opname or 'inject' in opname:
        continue

    other_count += 1

log(f"Attack packets: {attack_count}, SAY packets: {say_count}, Other: {other_count}")

# === ВИВОДИМО ВІДОМІ КЛЮЧОВІ БАЙТИ ===
known = [(i, k) for i, k in enumerate(key[:50]) if k is not None]
log(f"Known key bytes: {len(known)}")
for pos, k in known:
    log(f"  key[{pos}] = 0x{k:02x}")

# === ПЕРЕВІРЯЄМО ЧИ ДОСТАТНЬО ДЛЯ 0xB0 (позиції 5:9 = entry_id) ===
# Мінімальний набір: key[5:9] для entry_id
can_inject_entry = all(key[i] is not None for i in range(5, 9))
can_inject_list = all(key[i] is not None for i in range(1, 5))
can_inject_amount_low = all(key[i] is not None for i in range(9, 13))

log(f"Can encode list_id: {can_inject_list}")
log(f"Can encode entry_id: {can_inject_entry}")
log(f"Can encode amount_low: {can_inject_amount_low}")

# === ЯКЩО МАЄМО ДОСТАТНЬО КЛЮЧОВИХ БАЙТ - ІНЖЕКТИМО ===
if can_inject_entry and can_inject_list:
    log("\n=== BUILDING FIELD-XOR ENCODED 0xB0 PACKETS ===")

    for entry_id in ENTRIES:
        # Будуємо plaintext 0xB0
        plain = struct.pack("<BIIq", 0xB0, LIST_ID, entry_id, 1) + b'\x00' * 25  # 42 bytes

        # field-XOR encode
        enc = bytearray(len(plain))
        for i in range(len(plain)):
            if key[i] is not None:
                enc[i] = plain[i] ^ key[i]
            else:
                # Невідомі позиції: для plain=0 enc=key[i]; оскільки key[i] невідомий,
                # ставимо 0 (якщо plain=0, то enc=key[i], але ми не знаємо key[i])
                # Краще: для padding (позиції 17:42) де plain=0, якщо ключ невідомий,
                # використовуємо 0 і сподіваємось що server проігнорує padding
                enc[i] = 0x00 if plain[i] == 0 else plain[i]  # fallback

        enc_bytes = bytes(enc)
        proxy.inject_c2s.append(enc_bytes)
        log(f"  Injected entry={entry_id} enc_hex={enc_bytes[:16].hex()}...")
        time.sleep(0.1)

    log("=== INJECTION COMPLETE ===")

elif can_inject_entry:
    log("\nHave key[5:9] but NOT key[1:5] (list_id positions)")
    log("Cannot encode list_id correctly - skipping injection")
    log("NEED: SAY channel type=0 packet to get key[1:5]")
else:
    log("\nInsufficient key bytes for injection")
    log("Need attack packets and/or SAY packets")

# === ТАКОЖ ПЕРЕВІРЯЄМО _MULTISELL_CAP ===
cap_list = engine._MULTISELL_CAP.get('captured', [])
log(f"\n_MULTISELL_CAP count: {len(cap_list)}")
if cap_list:
    for i, cap in enumerate(cap_list):
        gh = cap.get('game_hex', '')
        log(f"  Cap[{i}]: ts={cap.get('ts')} len={cap.get('game_len')} hex={gh[:20]}")

    # Якщо є захоплений 0xB0 - використовуємо XOR arithmetic
    log("\n=== REPLAY FROM CAPTURED 0xB0 ===")
    cap0 = cap_list[-1]
    cap_hex = cap0.get('game_hex', '')
    if len(cap_hex) >= 18:
        data = bytearray.fromhex(cap_hex)
        # entry_id в байтах 5:9
        base_entry = struct.unpack_from("<I", data, 5)[0]
        log(f"  Captured entry_id={base_entry}")

        for entry_id in ENTRIES:
            modified = bytearray(data)
            old_eid = struct.pack("<I", base_entry)
            new_eid = struct.pack("<I", entry_id)
            for i in range(4):
                modified[5 + i] ^= old_eid[i] ^ new_eid[i]
            proxy.inject_c2s.append(bytes(modified))
            log(f"  Replay entry={entry_id} hex={bytes(modified)[:16].hex()}")
            time.sleep(0.1)

# === ВИВОДИМО KEY JSON ===
key_out = {"session_key_partial": [k if k is not None else None for k in key[:50]]}
key_path = r"D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\_key_derived.json"
with open(key_path, "w") as f:
    json.dump(key_out, f, indent=2)
log(f"Key saved to {key_path}")

log("=== KEY DERIVE DONE ===")
