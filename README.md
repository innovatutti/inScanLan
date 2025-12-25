# 🔍 inScanLan - Network Scanner

Scanner di rete completo per Windows con interfaccia grafica moderna.

## 🌟 Caratteristiche

- ✅ **Ping Scan** - Rileva host attivi in rete
- 🔌 **Port Scanning** - Scansione porte TCP personalizzabile
- 💻 **NetBIOS Discovery** - Recupera nomi computer Windows
- 📡 **ARP Scan** - Ottiene indirizzi MAC e produttori
- 📊 **Log Real-Time** - Visualizzazione in tempo reale delle operazioni
- 📈 **Statistiche Dettagliate** - Analisi completa dei risultati
- 🎨 **Interfaccia Moderna** - GUI intuitiva e professionale

## 📋 Requisiti

- Windows 10/11
- Python 3.7 o superiore
- Privilegi di amministratore (consigliati per alcune funzionalità)

## 🚀 Installazione

1. Clona o scarica il repository:
```bash
cd C:\Users\info\inScanLan
```

2. Verifica che Python sia installato:
```bash
python --version
```

3. Installa le dipendenze (opzionale):
```bash
pip install -r requirements.txt
```

## 💻 Utilizzo

### Avvio Rapido

Esegui l'applicazione con:
```bash
python main.py
```

### Funzionalità

1. **Configurazione Scansione**
   - Inserisci il range IP (es: `192.168.1.0/24` o `10.0.0.1-10.0.0.254`)
   - Specifica le porte da scansionare (es: `21,22,80,443,3389`)
   - Seleziona le opzioni di scansione desiderate

2. **Opzioni Disponibili**
   - **Ping Scan**: Verifica host raggiungibili
   - **NetBIOS**: Recupera nomi NetBIOS Windows
   - **ARP**: Ottiene MAC address e produttori
   - **Port Scan**: Scansiona le porte specificate

3. **Visualizzazione Risultati**
   - **Tab Log**: Visualizza operazioni in tempo reale
   - **Tab Dispositivi**: Tabella con tutti i dispositivi trovati
   - **Tab Statistiche**: Analisi e grafici dei risultati

## 📊 Porte Comuni

| Porta | Servizio | Descrizione |
|-------|----------|-------------|
| 21    | FTP      | File Transfer Protocol |
| 22    | SSH      | Secure Shell |
| 23    | Telnet   | Telnet |
| 80    | HTTP     | Web Server |
| 443   | HTTPS    | Web Server Sicuro |
| 445   | SMB      | Condivisioni Windows |
| 3389  | RDP      | Remote Desktop |
| 8080  | HTTP-ALT | Server Web Alternativo |

## ⚙️ Configurazione Avanzata

### Range IP Supportati

- **CIDR Notation**: `192.168.1.0/24`
- **Classe C**: `192.168.1.0/24` (256 indirizzi)
- **Classe B**: `172.16.0.0/16` (65536 indirizzi)
- **Custom Range**: Modifica il codice per range personalizzati

### Timeout e Performance

Modifica i timeout in `network_scanner.py`:
- `ping_host(timeout=1)` - Timeout ping (secondi)
- `check_port(timeout=0.5)` - Timeout port scan (secondi)
- `ThreadPoolExecutor(max_workers=50)` - Thread paralleli

## 🛡️ Privilegi Amministratore

Alcune funzionalità richiedono privilegi elevati:
- Accesso completo ARP cache
- Alcune operazioni di rete raw
- NetBIOS queries

Per eseguire come amministratore:
1. Click destro su `main.py`
2. Seleziona "Esegui come amministratore"

## 🔧 Risoluzione Problemi

### Python non trovato
Installa Python da [python.org](https://www.python.org/downloads/) e assicurati di selezionare "Add Python to PATH"

### Errori di permessi
Esegui il programma come amministratore

### Firewall blocca la scansione
Configura Windows Firewall per permettere l'applicazione

### NetBIOS non funziona
Verifica che il servizio NetBIOS sia attivo su Windows:
```bash
services.msc
```
Cerca "TCP/IP NetBIOS Helper"

## 📝 Note Legali

⚠️ **IMPORTANTE**: Usa questo strumento solo su reti di tua proprietà o con esplicita autorizzazione.
La scansione non autorizzata di reti può essere illegale.

## 🔄 Aggiornamenti Futuri

- [ ] Export risultati (CSV, JSON, HTML)
- [ ] Integrazione con Nmap
- [ ] Scansione OS fingerprinting
- [ ] Monitoraggio continuo
- [ ] Alert e notifiche
- [ ] Database storico scansioni
- [ ] Grafici interattivi

## 📧 Supporto

Per bug report o richieste di funzionalità, apri una issue sul repository.

## 📄 Licenza

Questo progetto è distribuito sotto licenza MIT.

---

**inScanLan** - Network Scanner Professionale per Windows
Versione 1.0.0 - 2025
