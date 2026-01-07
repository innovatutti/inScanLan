# 📱 Build inScanLan per Android

Questa guida spiega come convertire inScanLan in un'app Android (.apk).

## ⚠️ Nota Importante

L'app Windows usa Tkinter che **NON funziona su Android**. Per Android serve una versione con **Kivy**.

## 🔧 Opzione 1: Kivy + Buildozer (Consigliato)

### Prerequisiti
```bash
# Su Windows, installa:
- Python 3.8+
- WSL2 (Windows Subsystem for Linux)
- Ubuntu da Microsoft Store

# Su Ubuntu/WSL:
sudo apt update
sudo apt install -y python3-pip git zip unzip openjdk-8-jdk autoconf libtool
pip3 install buildozer cython
```

### Crea versione Kivy
Crea un nuovo file `main_android.py` con interfaccia Kivy:

```python
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
import subprocess

class NetworkScannerApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Header
        layout.add_widget(Label(
            text='inScanLan Network Scanner',
            size_hint=(1, 0.1),
            font_size='20sp'
        ))
        
        # IP Input
        self.ip_input = TextInput(
            text='192.168.1.0/24',
            hint_text='Range IP',
            size_hint=(1, 0.1),
            multiline=False
        )
        layout.add_widget(self.ip_input)
        
        # Scan Button
        scan_btn = Button(
            text='Avvia Scansione',
            size_hint=(1, 0.1),
            on_press=self.start_scan
        )
        layout.add_widget(scan_btn)
        
        # Results
        self.results = Label(
            text='Risultati scansione...',
            size_hint=(1, 0.7)
        )
        scroll = ScrollView(size_hint=(1, 0.7))
        scroll.add_widget(self.results)
        layout.add_widget(scroll)
        
        return layout
    
    def start_scan(self, instance):
        # Implementa logica scansione Android
        self.results.text = 'Scansione avviata...'

if __name__ == '__main__':
    NetworkScannerApp().run()
```

### Configura buildozer.spec

```bash
buildozer init
```

Modifica `buildozer.spec`:
```ini
[app]
title = inScanLan
package.name = inscanlan
package.domain = org.inscanlan
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy
permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE
orientation = portrait
fullscreen = 0

android.api = 34
android.minapi = 21
android.ndk = 25c
android.accept_sdk_license = True
```

### Build APK
```bash
# Su WSL/Linux
buildozer android debug

# Il file APK sarà in: bin/inscanlan-1.0-debug.apk
```

## 🔧 Opzione 2: BeeWare (Cross-platform più semplice)

```bash
pip install briefcase

briefcase new
# Segui wizard
# Nome app: inScanLan
# Package: com.inscanlan.app

cd inscanlan
briefcase create android
briefcase build android
briefcase package android

# APK in: build/inscanlan/android/gradle/app/build/outputs/apk/
```

## 🔧 Opzione 3: Hybrid (Python + WebView)

Usa **Chaquopy** per eseguire Python in app Android nativa:

1. Crea progetto Android Studio
2. Aggiungi Chaquopy in `build.gradle`
3. Includi codice Python
4. WebView per UI HTML/CSS/JS

## 📦 Features Android da Implementare

```python
# Scanner WiFi Android
from android import mActivity
from android.permissions import request_permissions, Permission
from jnius import autoclass

# Permessi necessari
request_permissions([
    Permission.ACCESS_FINE_LOCATION,
    Permission.ACCESS_WIFI_STATE,
    Permission.CHANGE_WIFI_STATE
])

WifiManager = autoclass('android.net.wifi.WifiManager')
wifi = mActivity.getSystemService(Context.WIFI_SERVICE)

# Scansione WiFi
wifi.startScan()
results = wifi.getScanResults()

for network in results:
    ssid = network.SSID
    signal = network.level  # dBm
    frequency = network.frequency  # MHz
```

## 🚀 Installazione APK

1. **Abilita "Origini Sconosciute"** su Android
2. Copia APK sul dispositivo via:
   - ADB: `adb install inscanlan.apk`
   - USB: Copia file e installa da File Manager
   - Email/Cloud: Invia APK e scarica

## ⚡ Quick Start (Solo Test)

Per test rapido senza build completo:

```bash
# Installa Termux su Android
# In Termux:
pkg install python
pip install flask

# Crea web server
python -m http.server 8080

# Accedi da browser Android: localhost:8080
```

## 🔐 Note Sicurezza

- **MAI** pubblicare su Play Store con password hardcoded
- Cripta database credenziali
- Usa Android Keystore per password
- Richiedi permessi runtime

## 📚 Risorse

- Kivy: https://kivy.org/doc/stable/guide/android.html
- Buildozer: https://buildozer.readthedocs.io/
- BeeWare: https://beeware.org/
- Chaquopy: https://chaquo.com/chaquopy/

## 💡 Raccomandazione

Per uso personale, consiglio **Kivy + Buildozer** perché:
- ✅ Accesso completo API Android
- ✅ Performance native
- ✅ Controllo totale UI
- ✅ No dipendenze WebView
