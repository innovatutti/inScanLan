# Guida Build Locale - inScanLan

## 🚀 Build APK Android in Locale (Consigliato)

La build su GitHub Actions ha problemi di rete. È molto più affidabile compilare in locale.

### Opzione 1: Build su Windows con WSL2 (Raccomandato)

#### Prerequisiti:
1. **WSL2 installato** (Ubuntu)
2. **Python 3.8+**
3. **JDK 17**

#### Installazione WSL2:
```powershell
# PowerShell come Amministratore
wsl --install -d Ubuntu
# Riavvia il PC
```

#### Setup Build Environment:
```bash
# In WSL2 (Ubuntu)
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    git \
    zip unzip \
    openjdk-17-jdk \
    autoconf libtool \
    pkg-config \
    zlib1g-dev \
    libncurses5-dev \
    libffi-dev \
    libssl-dev \
    build-essential

# Installa Buildozer
pip3 install --upgrade pip
pip3 install buildozer cython==0.29.33
```

#### Build APK:
```bash
# Naviga al progetto
cd /mnt/c/Users/info/inScanLan

# Prima build (ci vorrà tempo, scarica tutto)
buildozer android debug

# Build successive (molto più veloci)
buildozer android debug
```

L'APK sarà in: `bin/inscanlan-1.0-arm64-v8a_armeabi-v7a-debug.apk`

---

### Opzione 2: Build su Linux nativo

Se hai una macchina Linux:

```bash
# Clone repository
git clone https://github.com/innovatutti/inScanLan.git
cd inScanLan

# Installa dipendenze
sudo apt-get update
sudo apt-get install -y \
    python3-pip git zip unzip openjdk-17-jdk \
    autoconf libtool pkg-config zlib1g-dev \
    libncurses5-dev libffi-dev libssl-dev \
    build-essential

# Installa Buildozer
pip3 install buildozer cython==0.29.33

# Build
buildozer android debug
```

---

### Opzione 3: Usare Termux su Android

Compila direttamente sul tuo telefono Android!

#### Setup Termux:
1. Installa Termux da F-Droid (non da Play Store)
2. Apri Termux:

```bash
# Update packages
pkg update && pkg upgrade

# Installa dipendenze
pkg install python git openjdk-17 clang make

# Installa Buildozer
pip install buildozer cython

# Clone repository
git clone https://github.com/innovatutti/inScanLan.git
cd inScanLan

# Build
buildozer android debug
```

---

### Opzione 4: Docker (Cross-platform)

Usa un container Docker pre-configurato:

#### Crea Dockerfile:
```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 python3-pip git zip unzip \
    openjdk-17-jdk wget curl \
    autoconf libtool pkg-config \
    zlib1g-dev libncurses5-dev \
    libffi-dev libssl-dev \
    build-essential ccache

RUN pip3 install buildozer cython==0.29.33

WORKDIR /app

CMD ["buildozer", "android", "debug"]
```

#### Build con Docker:
```bash
# Costruisci immagine
docker build -t inscanlan-builder .

# Compila APK
docker run -v ${PWD}:/app inscanlan-builder
```

---

### 🎯 Troubleshooting

**"buildozer: command not found"**
```bash
export PATH=$PATH:$HOME/.local/bin
```

**"SDK not found"**
Buildozer scarica automaticamente Android SDK alla prima build. Serve connessione internet e pazienza (10-20 minuti).

**"NDK compilation failed"**
```bash
buildozer android clean
buildozer android debug
```

**"Permission denied"**
```bash
chmod +x buildozer.spec
```

---

### ⚡ Build Veloce dopo la prima volta

Dopo la prima build (che scarica tutto), le successive sono veloci:

```bash
# Pulisci vecchi build
buildozer android clean

# Build veloce
buildozer android debug

# Build release (signed)
buildozer android release
```

---

### 📦 Installazione APK

#### Su Android:
1. Trasferisci APK dal PC al telefono
2. Apri con File Manager
3. Abilita "Installa app sconosciute"
4. Installa

#### Via ADB:
```bash
adb install -r bin/*.apk
```

---

### 🔄 GitHub Actions (Solo Manuale)

Se vuoi provare comunque GitHub Actions:

1. Vai su repository GitHub
2. Tab "Actions"
3. "Build Android APK"
4. Click "Run workflow"
5. Attendi (può fallire per problemi di rete)

**Nota**: Build in locale è 10x più affidabile!

---

### 📊 Confronto Metodi

| Metodo | Velocità | Difficoltà | Affidabilità |
|--------|----------|----------|--------------|
| WSL2 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Linux nativo | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Termux | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Docker | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| GitHub Actions | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |

---

### 💡 Consigli

1. **Prima build**: Falla su WiFi veloce, scarica ~2-3 GB
2. **Cache**: `.buildozer/` contiene cache, non cancellare
3. **Build incrementali**: Buildozer ricompila solo quello che cambia
4. **Release**: Per app ufficiale, usa `buildozer android release` e firma l'APK

---

### 🆘 Supporto

Se hai problemi:
1. Controlla log di buildozer: `.buildozer/logs/`
2. Pulisci e riprova: `buildozer android clean`
3. Verifica requisiti: `buildozer android debug -v`

Buona compilazione! 🚀
