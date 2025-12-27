#!/bin/bash

echo "========================================="
echo "  inScanLan - Build Android APK"
echo "========================================="
echo ""

# Verifica Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 non trovato. Installazione..."
    sudo apt update
    sudo apt install -y python3 python3-pip
fi

# Verifica dipendenze
echo "📦 Installazione dipendenze..."
sudo apt install -y git zip unzip openjdk-17-jdk autoconf libtool pkg-config \
    zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo5 cmake libffi-dev \
    libssl-dev

# Installa Buildozer
if ! command -v buildozer &> /dev/null; then
    echo "📦 Installazione Buildozer..."
    pip3 install --user buildozer cython==0.29.33
    export PATH=$PATH:~/.local/bin
fi

# Verifica buildozer.spec
if [ ! -f "buildozer.spec" ]; then
    echo "🔧 Creazione buildozer.spec..."
    buildozer init
    
    # Configura buildozer.spec
    cat > buildozer.spec << 'EOF'
[app]
title = inScanLan
package.name = inscanlan
package.domain = org.inscanlan

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,db

version = 1.0

requirements = python3,kivy==2.1.0,kivymd,sqlite3

permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,ACCESS_FINE_LOCATION

orientation = portrait
fullscreen = 0

android.api = 33
android.minapi = 21
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a,armeabi-v7a

[buildozer]
log_level = 2
warn_on_root = 1
EOF
fi

# Build APK
echo "🔨 Build APK in corso..."
buildozer android debug

if [ -f "bin/inscanlan-1.0-armeabi-v7a-debug.apk" ]; then
    echo ""
    echo "✅ APK creato con successo!"
    echo "📦 File: bin/inscanlan-1.0-armeabi-v7a-debug.apk"
    echo ""
    echo "📱 Per installare:"
    echo "   adb install bin/inscanlan-1.0-armeabi-v7a-debug.apk"
    echo ""
else
    echo "❌ Errore durante la build"
    exit 1
fi
