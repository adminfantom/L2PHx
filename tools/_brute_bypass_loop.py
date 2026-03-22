"""Цикличный brute-force BypassToServer("multisell 81381").

Отправляет ВСЕ 224 опкода каждые 5 секунд в течение 30 секунд.
Открой NPC диалог В ЛЮБОЙ МОМЕНТ пока скрипт работает.

Использование:
  python _brute_bypass_loop.py
"""
import urllib.request
import json
import time
import sys
import concurrent.futures

API = "http://127.0.0.1:8877/api/inject_raw"

# "multisell 81381" в UTF-16LE + null
BODY_HEX = "6d0075006c0074006900730065006c006c002000380031003300380031000000"

# Авто-опкоды (пропускаем)
SKIP = {
    0x00, 0x02, 0x06, 0x09, 0x13, 0x1B, 0x22, 0x2D, 0x2E, 0x30,
    0x3F, 0x51, 0x59, 0x70, 0x75, 0x80, 0x85, 0x8C, 0x8E, 0x90,
    0x99, 0xAF, 0xC0, 0xCB, 0xDA, 0xDC, 0xE0, 0xE2, 0xF0, 0xF9,
    0xFD, 0xFF
}

OPCODES = [op for op in range(256) if op not in SKIP]


def inject(hex_data: str):
    data = json.dumps({"hex_data": hex_data}).encode()
    req = urllib.request.Request(API, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=1) as resp:
            resp.read()
    except Exception:
        pass


def send_batch(label: str):
    """Отправить все 224 опкода параллельно."""
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futures = []
        for op in OPCODES:
            hex_data = f"{op:02x}{BODY_HEX}"
            futures.append(pool.submit(inject, hex_data))
        concurrent.futures.wait(futures)
    elapsed = time.time() - t0
    print(f"  [{label}] {len(OPCODES)} пакетов за {elapsed:.2f}с")


def main():
    print("=" * 60)
    print("BRUTE-FORCE BypassToServer('multisell 81381') — LOOP")
    print("=" * 60)
    print(f"Опкодов: {len(OPCODES)} (пропуск {len(SKIP)} авто)")
    print(f"API: {API}")
    print()

    # Тест связи
    try:
        data = json.dumps({"hex_data": f"23{BODY_HEX}"}).encode()
        req = urllib.request.Request(API, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            print(f"Тест: {json.loads(resp.read())}")
    except Exception as e:
        print(f"ОШИБКА: {e}")
        sys.exit(1)

    print()
    print(">>> СКРИПТ СТАРТУЕТ ЧЕРЕЗ 3 СЕКУНДЫ <<<")
    print(">>> ОТКРОЙ NPC ДИАЛОГ В ИГРЕ И ДЕРЖИ ОТКРЫТЫМ <<<")
    print()
    time.sleep(3)

    rounds = 6  # 6 раундов x 5 секунд = 30 секунд
    for i in range(rounds):
        send_batch(f"Раунд {i+1}/{rounds}")
        if i < rounds - 1:
            print(f"  Ожидание 5с... (открой NPC если не открыт)")
            time.sleep(5)

    print()
    print("=" * 60)
    print(f"Готово! {rounds} раундов x {len(OPCODES)} = {rounds * len(OPCODES)} пакетов")
    print("Проверь игру — окно мультиселла должно появиться!")
    print("=" * 60)


if __name__ == "__main__":
    main()
