# 📖 Guida Rapida - inScanLan

## 🔴 Menu Contestuale (Tasto Destro)

### Come usare il menu SMB:
1. **Fai una scansione** (pulsante "▶ Avvia Scansione")
2. **Aspetta che appaiano dispositivi** nella tabella
3. **Clicca con TASTO DESTRO su un IP** nella tabella
4. Vedrai questo menu:
   ```
   📡 Ping [IP]
   ⚡ Test Velocità
   ─────────────
   🌐 Apri nel Browser
   🔌 SSH a [IP]
   ─────────────
   📂 Mapping SMB/CIFS    ← QUESTO!
   🔑 Gestisci Credenziali SMB
   ─────────────
   📋 Copia IP
   ```

5. **Clicca su "📂 Mapping SMB/CIFS"**
6. Si apre finestra con:
   - **Percorso Condivisione**: `\\192.168.1.10\share`
   - **Lettera Unità**: `Z:`
   - **Username**: tuo username
   - **Password**: tua password
   - ☑️ **Salva credenziali** (spunta questo!)
7. Clicca **"✅ Crea Mapping"**

### Risultato:
- Windows monta `Z:` che punta a `\\IP\share`
- Username e password salvati in database
- Prossima volta, credenziali già compilate

---

## 🔐 Estrazione Password WiFi

### Passo 1: Vai al tab Scanner WiFi
1. Clicca **"📶 WiFi Scan"** (pulsante in alto)
2. Si apre finestra Scanner WiFi

### Passo 2: Estrai le password
1. Clicca **"🔑 Estrai Password WiFi Salvate"** (pulsante in alto)
2. L'app esegue:
   ```cmd
   netsh wlan show profiles
   netsh wlan show profile "NOME_RETE" key=clear
   ```
3. Se trova password, mostra finestra con tabella
4. Password salvate automaticamente nel database

### Perché dice "Nessuna password trovata"?

**Possibili cause:**
- ✗ Non sei connesso via WiFi (sei via Ethernet)
- ✗ Non hai mai salvato password WiFi su Windows
- ✗ Windows protegge le password (serve admin)

**Soluzione:**
1. **Esegui come Amministratore**:
   ```
   Tasto destro su inScanLan.exe → Esegui come amministratore
   ```
2. **Verifica profili WiFi manualmente**:
   ```powershell
   netsh wlan show profiles
   ```
3. Se vedi profili ma nessuna password:
   ```powershell
   netsh wlan show profile "NOME_TUA_RETE" key=clear
   ```
   Cerca la riga: `Contenuto chiave : PASSWORD_QUI`

---

## 💾 Salvataggio e Caricamento Scansioni

### METODO 1: Salvataggio Automatico
1. Fai una scansione
2. Al termine, è **automaticamente salvata** nel database
3. Trova in: Database → scans table

### METODO 2: Salvataggio con Nome (NUOVO!)
1. **Fai una scansione**
2. Clicca **"💾 Salva"** (pulsante in alto)
3. Inserisci nome (es: "Rete Ufficio", "Casa 27dic2025")
4. Clicca **"✅ Salva"**
5. **Salvato nel database** con nome personalizzato!

### Come Caricare Scansioni Salvate:
1. Clicca **"📂 Carica"** (pulsante in alto)
2. Vedi lista di tutte le scansioni:
   ```
   ID | Nome             | Data/Ora          | Subnet        | Dispositivi
   ───┼──────────────────┼───────────────────┼───────────────┼────────────
   5  | Rete Ufficio     | 2025-12-27 14:30  | 192.168.1.0/24| 15
   4  | Casa Sera        | 2025-12-27 10:15  | 192.168.0.0/24| 8
   3  | Scan_20251226    | 2025-12-26 22:00  | 10.0.0.0/24   | 23
   ```
3. **Clicca su una scansione**
4. Clicca **"✅ Carica"**
5. Dispositivi appaiono nella tabella!

### Eliminare Scansioni:
1. Clicca **"📂 Carica"**
2. Seleziona scansione da eliminare
3. Clicca **"🗑️ Elimina"**
4. Conferma
5. Scansione rimossa dal database

---

## 🗃️ Dove Sono i Dati?

### File Database:
```
C:\Users\info\inScanLan\inscanlan.db
```

### Tabelle nel Database:
1. **scans** - Tutte le scansioni
   - Ogni scansione ha: ID, Nome, Data, Subnet, Dispositivi (JSON)
   
2. **smb_credentials** - Credenziali SMB salvate
   - IP, Username, Password, Percorso share
   
3. **wifi_passwords** - Password WiFi estratte
   - SSID, Password, Tipo sicurezza

### Visualizzare i Dati:

#### Opzione A: Dall'app
- Scansioni: Pulsante **"📂 Carica"**
- WiFi: Tab Scanner WiFi → **"🔑 Estrai Password"**
- SMB: Tasto destro su IP → **"🔑 Gestisci Credenziali"**

#### Opzione B: SQLite Browser
1. Scarica [DB Browser for SQLite](https://sqlitebrowser.org/)
2. Apri `inscanlan.db`
3. Tab "Sfoglia dati"
4. Scegli tabella da vedere

#### Opzione C: PowerShell
```powershell
# Installa modulo SQLite
Install-Module -Name PSSQLite

# Leggi scansioni
Invoke-SqliteQuery -DataSource "C:\Users\info\inScanLan\inscanlan.db" -Query "SELECT * FROM scans"

# Leggi password WiFi
Invoke-SqliteQuery -DataSource "C:\Users\info\inScanLan\inscanlan.db" -Query "SELECT * FROM wifi_passwords"
```

---

## 🎯 Esempio Workflow Completo

### Scenario: Mappare condivisione NAS

1. **Scansione Rete**
   - Clicca "▶ Avvia Scansione"
   - Aspetta risultati

2. **Trova il NAS**
   - Vedi IP: 192.168.1.100
   - Hostname: "NAS-SYNOLOGY"

3. **Tasto Destro su IP**
   - Clicca IP 192.168.1.100 con **tasto destro**
   - Scegli **"📂 Mapping SMB/CIFS"**

4. **Configura Mapping**
   - Percorso: `\\192.168.1.100\documenti`
   - Lettera: `Z:`
   - Username: `admin`
   - Password: `miaSuperPassword`
   - ☑️ Salva credenziali: **SPUNTATO**

5. **Salva**
   - Clicca **"✅ Crea Mapping"**
   - Windows monta Z: → NAS
   - Credenziali salvate in database

6. **Salva Scansione**
   - Clicca **"💾 Salva"**
   - Nome: "Rete Casa con NAS"
   - Clicca **"✅ Salva"**

7. **Prossima Volta**
   - Clicca **"📂 Carica"**
   - Seleziona "Rete Casa con NAS"
   - Tutti i dispositivi ricaricati!

---

## ❗ Problemi Comuni

### "Nessuna password WiFi trovata"
**Soluzione**: Esegui come amministratore
```
Tasto destro su inScanLan.exe → Esegui come amministratore
```

### "Non vedo menu SMB con tasto destro"
**Problema**: Stai cliccando nel posto sbagliato
**Soluzione**: 
1. **PRIMA** fai una scansione
2. **POI** clicca tasto destro SU UN IP NELLA TABELLA (non fuori)
3. Il menu appare dove c'è il mouse

### "Mapping SMB fallisce"
**Cause**:
- Percorso errato (es: `\\IP\share` non `\\IP\`)
- Credenziali sbagliate
- Firewall blocca porta 445
- Condivisione non esistente

**Test manuale**:
```cmd
net use Z: \\192.168.1.100\share /user:admin password
```

### "Database vuoto dopo riavvio"
**Controlla**: Il database è in `C:\Users\info\inScanLan\inscanlan.db`
Se hai spostato l'EXE, il database è nella cartella dell'EXE

---

## 📊 Statistiche Database

### Vedere quante scansioni hai salvato:
1. Clicca **"📂 Carica"**
2. Conta le righe nella tabella

### Vedere tutte le password WiFi:
```sql
SELECT ssid, password FROM wifi_passwords;
```

### Vedere tutte le credenziali SMB:
1. Tasto destro su qualsiasi IP
2. Clicca **"🔑 Gestisci Credenziali SMB"**
3. Vedi tutte le credenziali salvate per quell'IP

---

**💡 Suggerimento**: Fai backup periodici di `inscanlan.db` per non perdere dati!
