"""start_divert.py — запуск WinDivert redirect отдельно от l2phx.py.

Запускать от АДМИНИСТРАТОРА в отдельном окне:
    python tools/start_divert.py

Перехватывает новые TCP SYN на GAME_PORTS → редиректит на PROXY_PORT 17777.
Текущие ESTABLISHED соединения не затрагивает — они будут перехвачены
при следующем реконнекте (дроп сервера, зон, краш).

l2phx.py должен быть запущен БЕЗ --divert (иначе конфликт WinDivert handle).
"""
import sys, os, time

# Добавляем родительский каталог в path чтобы импортировать _engine
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _engine import WinDivertRedirector, GAME_PORTS, PROXY_PORT

print(f"[DIVERT] GAME_PORTS = {sorted(GAME_PORTS)}")
print(f"[DIVERT] PROXY_PORT = {PROXY_PORT}")
print(f"[DIVERT] Запуск WinDivert редиректора...")
print(f"[DIVERT] Следующий реконнект игры на порты {sorted(GAME_PORTS)} будет перехвачен.")
print(f"[DIVERT] Ctrl+C для остановки.")
print()

divert = WinDivertRedirector(PROXY_PORT)
t = threading.Thread(target=divert.run, daemon=True, name="divert")
t.start()

try:
    while t.is_alive():
        time.sleep(5)
        if divert._pkt_count > 0:
            print(f"[DIVERT] пакетов перехвачено: {divert._pkt_count}")
except KeyboardInterrupt:
    print("[DIVERT] Остановка...")
    divert.running = False
    t.join(timeout=3)
    print("[DIVERT] Остановлен.")
