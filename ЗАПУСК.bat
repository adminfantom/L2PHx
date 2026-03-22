@echo off
title L2 PHX — ЗАПУСК
echo ========================================
echo  L2 PHX: Proxy + WinDivert + Monitor
echo ========================================
echo.

:: Убиваем старые инстансы
taskkill /F /FI "WINDOWTITLE eq l2phx*" >nul 2>&1

cd /d "%~dp0"

:: Запускаем прокси + WinDivert в отдельном окне
start "l2phx-proxy" cmd /k "python l2phx.py --divert 2>&1"

echo [OK] Прокси запущен с WinDivert.
echo.
echo Теперь:
echo  1. Войди в игру через очередь
echo  2. Когда зайдешь - монитор запустится автоматически
echo.

:: Ждём пока прокси поднимется (5 сек)
timeout /t 5 /nobreak >nul

:: Запускаем монитор в этом окне — он сам ждёт connected=True
echo [OK] Запускаю монитор v4 (XOR-шифрование, без inject_bypass, без flood)...
python tools\_monitor_v4.py

pause
