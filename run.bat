@echo off
title inScanLan - Network Scanner
color 0A

echo.
echo ========================================
echo   inScanLan - Network Scanner
echo ========================================
echo.
echo Avvio applicazione...
echo.

python main.py

if errorlevel 1 (
    echo.
    echo ERRORE: Impossibile avviare l'applicazione
    echo Verifica che Python sia installato correttamente
    echo.
    pause
)
