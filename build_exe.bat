@echo off
title Build inScanLan.exe
color 0B

echo ========================================
echo   Compilazione inScanLan in EXE
echo ========================================
echo.

REM Verifica se PyInstaller è installato
python -c "import PyInstaller" 2>NUL
if errorlevel 1 (
    echo [1/3] Installazione PyInstaller...
    pip install pyinstaller
    if errorlevel 1 (
        echo ERRORE: Impossibile installare PyInstaller
        pause
        exit /b 1
    )
) else (
    echo [1/3] PyInstaller già installato
)

echo.
echo [2/3] Compilazione in corso...
echo.

REM Compila l'applicazione in un singolo file EXE
python -m PyInstaller --onefile --windowed --icon=logo_inscanlan.ico --add-data "logo_inscanlan.jpg;." --add-data "logo_inscanlan.ico;." --name inScanLan main.py

if errorlevel 1 (
    echo.
    echo ERRORE durante la compilazione!
    echo.
    pause
    exit /b 1
)

echo.
echo [3/3] Compilazione completata!
echo.
echo ========================================
echo   EXE creato in: dist\inScanLan.exe
echo ========================================
echo.
echo Il file inScanLan.exe è PORTATILE e può essere
echo copiato su qualsiasi PC Windows senza installazioni.
echo.
echo File di output:
dir /b dist\inScanLan.exe 2>NUL
echo.
pause
