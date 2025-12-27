# Guida alla Scansione Layer 2 - inScanLan

## 🔍 Nuova Funzionalità: Rilevamento Dispositivi Fisici Multi-Subnet

### Cosa fa?
Questa funzionalità rileva **TUTTI i dispositivi fisici** presenti sulla rete, anche se:
- Hanno un IP configurato su una subnet diversa
- Hanno un IP "sbagliato" o non compatibile con la tua rete
- Sono configurati male e non rispondono al ping
- Sono su VLAN diverse ma fisicamente connessi allo stesso switch

### Perché è utile?
**Caso d'uso tipico: Stampanti con IP errato**
- Una stampante di rete è configurata con IP `10.0.0.50`
- Il tuo PC è sulla rete `192.168.1.0/24`
- Normalmente NON potresti vederla né comunicare con lei
- Con questa scansione Layer 2, la rilevi comunque tramite il suo **MAC address**

Una volta rilevata, puoi:
1. Vedere il suo MAC address
2. Identificare il vendor (es: HP, Canon, Epson)
3. Configurarla correttamente collegandoti direttamente

### Come funziona?

La scansione Layer 2 usa multiple tecniche:

#### 1. **Scansione Tabella ARP** 
   - Legge la cache ARP di sistema
   - Mostra tutti i dispositivi già comunicati in passato

#### 2. **ARP Broadcast Scanning**
   - Invia richieste ARP su range comuni (192.168.x.x, 10.0.x.x, 172.16.x.x)
   - Riceve risposte anche da dispositivi con IP "sbagliato"
   - Funziona a livello Layer 2 (datalink), quindi **ignora la configurazione IP**

#### 3. **mDNS/Bonjour Discovery**
   - Rileva stampanti di rete
   - Dispositivi Apple (Mac, iPhone, iPad)
   - Dispositivi IoT compatibili
   - Smart devices

#### 4. **SSDP/UPnP Discovery**
   - Router e gateway
   - NAS e storage di rete
   - Stampanti con UPnP
   - Smart TV e media devices
   - Telecamere IP

### Come usarla?

#### Via Web Interface:
1. Avvia il server: `python web_server.py`
2. Apri browser: `http://localhost:8080`
3. Clicca su **"🔍 Scan Dispositivi Fisici (Tutte le subnet)"**
4. Attendi qualche secondo (2-5 secondi)

#### Via Codice Python:
```python
from network_scanner import NetworkScanner

scanner = NetworkScanner()
devices = scanner.scan_all_physical_devices(
    log_callback=lambda msg, level: print(f"[{level}] {msg}")
)

for device in devices:
    print(f"IP: {device['ip']}")
    print(f"MAC: {device['mac']}")
    print(f"Vendor: {device['vendor']}")
    print(f"Raggiungibile: {device.get('reachable', 'Unknown')}")
    print(f"Fonte rilevamento: {device['source']}")
    print("---")
```

### Interpretazione Risultati

Per ogni dispositivo rilevato vedrai:

- **IP**: L'indirizzo IP configurato sul dispositivo
- **MAC**: L'indirizzo fisico MAC (univoco)
- **Vendor**: Produttore identificato dal MAC
- **Status**: 
  - `Online` - IP raggiungibile, dispositivo configurato correttamente
  - `Detected but unreachable (wrong subnet?)` - Rilevato ma IP non raggiungibile (subnet errata)
  - `Physical Device Detected` - Rilevato fisicamente ma non verificato
- **Rilevato via**: Tecnica usata per rilevarlo (ARP, mDNS, SSDP, etc.)
- **Tipo dispositivo**: Se identificato (Printer, Router, NAS, etc.)

### Esempio Pratico: Configurare Stampante con IP Errato

**Scenario:**
Stampante HP con IP `10.0.0.100` sulla tua rete `192.168.1.0/24`

**Procedura:**

1. **Esegui scansione Layer 2**
   ```
   Trovata stampante:
   IP: 10.0.0.100
   MAC: 00:1B:D5:12:34:56
   Vendor: Hewlett Packard
   Status: Detected but unreachable (wrong subnet?)
   ```

2. **Configurazione temporanea del tuo PC**
   - Aggiungi IP secondario sulla stessa subnet della stampante
   - Windows: `netsh interface ip add address "Ethernet" 10.0.0.99 255.255.255.0`
   - Ora puoi accedere a `http://10.0.0.100`

3. **Riconfigura la stampante**
   - Accedi all'interfaccia web: `http://10.0.0.100`
   - Cambia IP in `192.168.1.100`
   - Subnet mask: `255.255.255.0`
   - Gateway: `192.168.1.1`

4. **Rimuovi IP temporaneo**
   - `netsh interface ip delete address "Ethernet" 10.0.0.99`

5. **Verifica**
   - Ora la stampante è raggiungibile su `192.168.1.100`

### Limitazioni

- **Stesso segmento fisico**: Funziona solo per dispositivi collegati allo stesso switch/router fisico
- **Non attraversa router**: Non rileva dispositivi oltre un router (diverse reti Layer 3)
- **Permessi amministratore**: Su alcuni sistemi potrebbe richiedere privilegi elevati
- **Firewall**: Alcuni firewall potrebbero bloccare pacchetti mDNS/SSDP

### Protocolli Usati

| Protocollo | Porta | Tipo | Cosa Rileva |
|------------|-------|------|-------------|
| ARP | - | Layer 2 | Tutti i dispositivi fisici |
| mDNS | 5353 UDP | Multicast | Stampanti, Apple devices, IoT |
| SSDP | 1900 UDP | Multicast | Router, NAS, Smart TV, UPnP devices |

### Vantaggi vs Scansione IP Tradizionale

| Scansione IP (Layer 3) | Scansione Layer 2 |
|------------------------|-------------------|
| Solo subnet configurata | Tutte le subnet fisicamente connesse |
| Richiede IP raggiungibile | Funziona anche con IP errato |
| Veloce ma limitata | Più lenta ma completa |
| Non rileva dispositivi mal configurati | Rileva TUTTO ciò che è fisicamente connesso |

### Sicurezza

⚠️ **Nota di Sicurezza:**
- Questa scansione è passiva e non invasiva
- Non modifica configurazioni di rete
- Non tenta di accedere ai dispositivi
- È visibile solo sulla tua rete locale
- Utile per amministrazione di rete, non per scopi malevoli

### Troubleshooting

**"Nessun dispositivo trovato"**
- Verifica di essere connesso alla rete
- Controlla che il firewall non blocchi la scansione
- Prova a eseguire come amministratore

**"Dispositivi rilevati ma non raggiungibili"**
- Normale! Significa che hanno IP su subnet diversa
- Usa la procedura sopra per riconfigurarli

**"Scansione lenta"**
- Normale, la scansione Layer 2 richiede 2-5 secondi
- Usa timeout più brevi se necessario

## 🎯 Conclusione

Questa funzionalità è perfetta per:
- Amministratori di rete
- Tecnici IT
- Configurazione iniziale di dispositivi
- Troubleshooting problemi di rete
- Inventario hardware di rete

Buona scansione! 🔍
