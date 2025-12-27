# 📊 Gestione Database e Credenziali - inScanLan

## 🗄️ Dove si salvano i dati

### Percorso Database
```
C:\Users\info\inScanLan\inscanlan.db
```

Puoi aprire il file con qualsiasi client SQLite (es: [DB Browser for SQLite](https://sqlitebrowser.org/))

## 📋 Struttura Database

### 1. Tabella `scans` - Storico Scansioni
Memorizza tutte le scansioni di rete effettuate:

```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,           -- Data/ora scansione
    subnet TEXT,              -- Subnet scansionata (es: 192.168.1.0/24)
    devices_count INTEGER,    -- Numero dispositivi trovati
    scan_data TEXT            -- JSON con tutti i dispositivi
)
```

**Esempio scan_data JSON:**
```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "netbios": "ROUTER",
    "mac": "AA:BB:CC:DD:EE:FF",
    "vendor": "TP-Link",
    "ports": "80,443,8080",
    "status": "Online"
  }
]
```

### 2. Tabella `smb_credentials` - Credenziali SMB/CIFS
Salva username e password per connessioni di rete SMB:

```sql
CREATE TABLE smb_credentials (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,   -- IP del server SMB
    username TEXT,            -- Username per accesso
    password TEXT,            -- Password (salvata in CHIARO!)
    share_path TEXT,          -- Percorso condivisione (es: \\192.168.1.10\documenti)
    notes TEXT                -- Note aggiuntive
)
```

**⚠️ ATTENZIONE SICUREZZA:**
- Le password SMB sono salvate in **chiaro** nel database
- Il file `inscanlan.db` non è crittografato
- Usa solo su PC personali protetti

### 3. Tabella `wifi_passwords` - Password WiFi Estratte
Memorizza password WiFi trovate su Windows:

```sql
CREATE TABLE wifi_passwords (
    id INTEGER PRIMARY KEY,
    ssid TEXT UNIQUE,         -- Nome rete WiFi
    password TEXT,            -- Password WiFi
    security_type TEXT,       -- Tipo sicurezza (WPA2, WPA3, etc.)
    timestamp TEXT            -- Data estrazione
)
```

## 🔌 Come si stabiliscono connessioni SMB

### Metodo 1: Menu Contestuale (tasto destro)
1. **Scansiona la rete** (pulsante "Scan")
2. **Clicca destro su un IP** nella tabella dispositivi
3. Scegli **"Mappa SMB"**
4. Compila il form:
   - **Percorso condivisione**: `\\192.168.1.10\documenti`
   - **Lettera unità**: `Z:`
   - **Username**: `admin`
   - **Password**: `password123`
   - ☑️ **Salva credenziali** (checkbox)
5. Clicca **"✅ Crea Mapping"**

### Cosa succede:
```powershell
# Comando eseguito:
net use Z: \\192.168.1.10\documenti /user:admin password123 /persistent:yes

# Salvataggio nel database:
INSERT INTO smb_credentials VALUES (
  '192.168.1.10', 
  'admin', 
  'password123', 
  '\\192.168.1.10\documenti', 
  NULL
)
```

### Metodo 2: Gestione Credenziali
1. **Clicca destro su un IP**
2. Scegli **"Gestisci Credenziali SMB"**
3. Vedi le credenziali salvate per quell'IP
4. Puoi modificare o eliminare

## 🔐 Come si memorizzano le password

### Password SMB
**Quando vengono salvate:**
- Durante la creazione del mapping SMB (se checkbox attiva)
- Manualmente tramite "Gestisci Credenziali SMB"

**Dove vengono usate:**
- Al prossimo mapping dello stesso IP, credenziali pre-compilate
- Non vengono usate automaticamente (devi fare mapping manuale)

### Password WiFi
**Quando vengono estratte:**
1. Vai su tab **"Scanner WiFi"**
2. Clicca **"Estrai Password WiFi Salvate"**
3. L'app esegue:
```powershell
# Per ogni rete WiFi salvata:
netsh wlan show profile name="NOME_RETE" key=clear
```

**Risultato:**
```
SSID: MiaReteWiFi
Password: SuperSecret123
Tipo: WPA2-Personal
```

Salvate in `wifi_passwords` table.

## 📂 Come accedere ai dati salvati

### Opzione 1: Interfaccia App
- **Storico Scansioni**: Menu "Database" > "Carica Scansioni Salvate"
- **Credenziali SMB**: Tasto destro su IP > "Gestisci Credenziali SMB"
- **Password WiFi**: Tab "Scanner WiFi" > vedi lista password estratte

### Opzione 2: Database Diretto
```powershell
# Apri con SQLite
sqlite3 inscanlan.db

# Query utili:
SELECT * FROM scans ORDER BY timestamp DESC LIMIT 10;
SELECT ip_address, username FROM smb_credentials;
SELECT ssid, password FROM wifi_passwords;
```

### Opzione 3: Export
- **PDF**: Pulsante "Export PDF" (include statistiche)
- **HTML**: Esportazione web-friendly
- **Backup Database**: Copia `inscanlan.db` su altra cartella

## 🔒 Raccomandazioni Sicurezza

1. **Proteggi il file database**:
   ```powershell
   # Rendi inscanlan.db accessibile solo a te
   icacls inscanlan.db /inheritance:r /grant:r "%USERNAME%:F"
   ```

2. **Non condividere inscanlan.db** (contiene password in chiaro!)

3. **Backup criptato**:
   ```powershell
   # Comprimilo con password
   Compress-Archive -Path inscanlan.db -DestinationPath backup.zip
   # Poi cripta con 7-Zip o VeraCrypt
   ```

4. **Elimina dati sensibili periodicamente**:
   ```sql
   DELETE FROM smb_credentials WHERE timestamp < '2025-01-01';
   DELETE FROM wifi_passwords;
   VACUUM;
   ```

## 🗺️ Flusso Completo Esempio

```
1. Utente: Clicca "Scan" 
   ↓
2. App: Trova 10 dispositivi
   ↓
3. App: Salva in database:
   INSERT INTO scans VALUES (..., 'subnet: 192.168.1.0/24', 10, '[...]')
   ↓
4. Utente: Clicca destro su 192.168.1.50 > "Mappa SMB"
   ↓
5. App: Cerca credenziali salvate:
   SELECT * FROM smb_credentials WHERE ip_address='192.168.1.50'
   ↓
6. App: Pre-compila form se trovate
   ↓
7. Utente: Inserisce username/password, clicca "Crea Mapping"
   ↓
8. App: Esegue `net use Z: \\192.168.1.50\share /user:admin pass /persistent:yes`
   ↓
9. App: Se checkbox attiva, salva:
   INSERT INTO smb_credentials VALUES ('192.168.1.50', 'admin', 'pass', ...)
   ↓
10. Windows: Z: ora punta a \\192.168.1.50\share
```

## 📍 Posizione File Chiave

```
C:\Users\info\inScanLan\
├── inscanlan.db          ← DATABASE PRINCIPALE (contiene tutto!)
├── main.py               ← Applicazione Windows
├── network_scanner.py    ← Motore scansione
├── logo_inscanlan.ico    ← Icona app
└── exports/              ← PDF/HTML esportati (se salvati)
```

---

**💡 Tip**: Per visualizzare il database in modo facile, installa [DB Browser for SQLite](https://sqlitebrowser.org/dl/) e apri `inscanlan.db`
