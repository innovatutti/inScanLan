# inScanLan - Aggiornamento per Android

## ✅ Funzionalità Aggiunte (Versione Windows)

### 🔑 Database Integrato (SQLite)
- **Auto-creato** al primo avvio: `inscanlan.db`
- **3 Tabelle:**
  1. `scans` - Storico scansioni di rete
  2. `smb_credentials` - Credenziali SMB/CIFS salvate
  3. `wifi_passwords` - Password WiFi estratte

### 📂 Nuovi Pulsanti Toolbar:
- **💾 Salva Scan** - Salva scansione corrente nel DB
- **📂 Carica Scan** - Ricarica scansioni precedenti
- **📄 PDF** - Esporta PDF professionale
- **🔐 WiFi Passwords** - Estrai e salva password WiFi Windows

### 🖱️ Menu Contestuale (Tasto Destro):
Clicca con **tasto destro** su un dispositivo per:
- 📡 **Ping** - Ping continuo
- ⚡ **Test Velocità** - Misura throughput
- 🌐 **Apri nel Browser** - http://IP
- 🔌 **SSH** - Connessione SSH
- 📂 **Mapping SMB/CIFS** - Crea unità di rete Windows
- 🔑 **Gestisci Credenziali** - Salva/modifica credenziali SMB
- 📋 **Copia IP** - Copia negli appunti

### 🗄️ Mapping SMB con Credenziali:
1. Tasto destro su dispositivo → **📂 Mapping SMB**
2. Inserisci:
   - Percorso condivisione (es: `\\\\192.168.1.100\\share`)
   - Lettera unità (E:, F:, Z:, etc.)
   - Username e Password
3. ✅ Opzione "Salva credenziali" → Memorizza nel DB
4. Credenziali auto-caricate ai prossimi mapping

### 🔐 Estrazione Password WiFi:
- Clicca **🔐 WiFi Passwords**
- Estrae TUTTE le password WiFi salvate in Windows
- Mostra: SSID, Password, Tipo sicurezza
- Salva automaticamente nel database
- Accessibile offline anche senza WiFi attivo

## 📱 Versione Android

### Prerequisiti
```bash
# Installa su Windows con WSL2
sudo apt install python3-pip buildozer
pip install kivy kivymd
```

### Build APK
```bash
# Nella cartella del progetto
buildozer android debug

# APK generato in: bin/inscanlan-1.0-debug.apk
```

### Permessi Android Richiesti
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_STATE" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

### Limitazioni Android vs Windows:
| Funzione | Windows | Android |
|----------|---------|---------|
| Ping Scan | ✅ Pieno | ⚠️ Limitato (no root) |
| Port Scan | ✅ Completo | ✅ Sì |
| NetBIOS | ✅ Sì | ❌ No |
| ARP Scan | ✅ Sì | ⚠️ Solo root |
| WiFi Scan | ✅ Tutte bande | ✅ Sì (con permessi) |
| SMB Mapping | ✅ Nativo Windows | ❌ No (serve app esterna) |
| SSH | ✅ Integrato | ✅ Sì (Termux/lib) |
| Database | ✅ SQLite | ✅ SQLite |

## 🚀 Come Usare (Windows)

1. **Prima scansione:**
   - Inserisci subnet (auto-rilevata)
   - Clicca "▶ Avvia Scansione"
   
2. **Salva risultati:**
   - Clicca "💾 Salva Scan"
   - I dati vanno in `inscanlan.db`

3. **Mapping SMB:**
   - Tasto destro su IP → "📂 Mapping SMB"
   - Inserisci credenziali
   - Windows crea unità di rete (es: Z:)

4. **Password WiFi:**
   - Clicca "🔐 WiFi Passwords"
   - Vedi tutte le password salvate
   - Esporta se necessario

## 🔒 Sicurezza

- ⚠️ Database **NON criptato** per default
- 🔐 Per produzione, cripta con:
  ```python
  from cryptography.fernet import Fernet
  # Cripta password prima di salvare
  ```
- 📝 File `.gitignore` già configurato per escludere `*.db`

## 📦 File Creati

```
inScanLan/
├── inscanlan.db          # Database scansioni/credenziali
├── scans/                # Esportazioni JSON (se usate)
└── exports/              # PDF generati
```

## 💡 Tips

- **Backup DB**: Copia `inscanlan.db` periodicamente
- **Portable**: L'app funziona da USB senza installazione
- **Multi-rete**: Salva scan di reti diverse
- **Password WiFi**: Richiede esecuzione come **Amministratore**

## 🐛 Troubleshooting

**"Errore creazione database"**
→ Verifica permessi cartella

**"Nessuna password WiFi trovata"**
→ Esegui come Amministratore

**"Mapping SMB fallito"**
→ Verifica che il percorso UNC sia corretto (`\\\\IP\\share`)

---

📚 Guida completa Android: Vedi `ANDROID_BUILD.md`
