"""Быстрый brute-force BypassToServer("multisell 81381") — все 256 опкодов.

Отправляет напрямую через REST API прокси (http://127.0.0.1:8877).
Запускай ПОКА ДИАЛОГ NPC ОТКРЫТ!

Использование:
  python _brute_bypass_fast.py
"""
import urllib.request
import json
import time
import sys

API = "http://127.0.0.1:8877/api/inject_raw"

# "multisell 81381" в UTF-16LE + null terminator
BODY_HEX = "6d0075006c0074006900730065006c006c002000380031003300380031000000"

# Авто-опкоды из статистики (пропускаем чтобы не мусорить)
SKIP = {
    0x00, 0x02, 0x06, 0x09, 0x13, 0x1B, 0x22, 0x2D, 0x2E, 0x30,
    0x3F, 0x51, 0x59, 0x70, 0x75, 0x80, 0x85, 0x8C, 0x8E, 0x90,
    0x99, 0xAF, 0xC0, 0xCB, 0xDA, 0xDC, 0xE0, 0xE2, 0xF0, 0xF9,
    0xFD, 0xFF
}


def inject(hex_data: str) -> dict:
    data = json.dumps({"hex_data": hex_data}).encode()
    req = urllib.request.Request(API, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=2) as resp:
        return json.loads(resp.read())


def main():
    print("=== BRUTE-FORCE BypassToServer('multisell 81381') ===")
    print(f"API: {API}")
    print(f"Пропуск {len(SKIP)} авто-опкодов")
    print()

    # Проверка связи
    try:
        r = inject(f"23{BODY_HEX}")
        print(f"Тест: opcode 0x23 -> {r}")
    except Exception as e:
        print(f"ОШИБКА: не могу подключиться к прокси: {e}")
        sys.exit(1)

    input("\n>>> ОТКРОЙ ДИАЛОГ NPC И НАЖМИ ENTER <<<\n")

    t0 = time.time()
    sent = 0
    errors = 0

    for op in range(256):
        if op in SKIP:
            continue
        hex_data = f"{op:02x}{BODY_HEX}"
        try:
            inject(hex_data)
            sent += 1
        except Exception:
            errors += 1

    elapsed = time.time() - t0
    print(f"\nГотово: {sent} пакетов за {elapsed:.1f}с (ошибок: {errors})")
    print(f"Скорость: {sent/elapsed:.0f} пакетов/с")
    print("\nПроверь игру — должно появиться окно мультиселла!")


if __name__ == "__main__":
    main()
