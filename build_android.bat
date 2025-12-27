@echo off
echo ========================================
echo   Build Android APK con WSL2
echo ========================================
echo.
echo Questo script richiede WSL2 installato.
echo.
echo 1. Installa WSL2 se non presente:
echo    wsl --install
echo.
echo 2. Avvia Ubuntu e installa dipendenze:
echo    sudo apt update
echo    sudo apt install -y python3-pip git zip unzip openjdk-17-jdk
echo    pip3 install buildozer cython
echo.
echo 3. Build APK:
echo    cd /mnt/c/Users/info/inScanLan
echo    buildozer android debug
echo.
pause

REM Avvia WSL se disponibile
wsl --list >nul 2>&1
if errorlevel 1 (
    echo WSL2 non installato!
    echo Installa con: wsl --install
    pause
    exit /b 1
)

echo Avvio WSL2...
wsl -d Ubuntu bash -c "cd /mnt/c/Users/info/inScanLan && bash build_android_wsl.sh"
