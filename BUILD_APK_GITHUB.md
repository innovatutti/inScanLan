# Istruzioni per compilare APK con GitHub Actions

## Setup iniziale

1. **Crea repository GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit - inScanLan Android"
   git branch -M main
   git remote add origin https://github.com/TUO-USERNAME/inScanLan.git
   git push -u origin main
   ```

2. **Abilita GitHub Actions**:
   - Vai su repository Settings > Actions > General
   - Seleziona "Allow all actions"
   - Salva

## Come compilare l'APK

### Build manuale (metodo consigliato)
1. Vai su: `https://github.com/TUO-USERNAME/inScanLan/actions`
2. Clicca su "Build Android APK" nel menu laterale
3. Clicca "Run workflow" > "Run workflow"
4. Attendi 20-40 minuti
5. Scarica l'APK da "Artifacts"

**Nota**: Il workflow è configurato solo per avvio manuale per evitare build automatiche non necessarie.

## Scaricare l'APK compilato

1. Vai su **Actions** tab del repository
2. Clicca sulla build completata (✅ verde)
3. Scorri in basso fino a **Artifacts**
4. Clicca su **inscanlan-apk** per scaricare
5. Estrai il file ZIP
6. Trasferisci l'APK su Android e installa

## Creare una Release ufficiale

Per creare una release con APK scaricabile direttamente:

```bash
git tag v1.0
git push origin v1.0
```

L'APK sarà disponibile in: `Releases` > `v1.0` > Assets

## Tempi di compilazione

- **Prima build**: ~30-40 minuti (scarica SDK, NDK, etc.)
- **Build successive**: ~20-30 minuti (con cache)

## Minuti gratuiti disponibili

- **Repository pubblico**: ♾️ illimitati
- **Repository privato**: 2000 minuti/mese (~40 build)

## Miglioramenti recenti

- **Android API 34**: Aggiornato per compatibilità con le ultime versioni di Android
- **NDK 25c**: Utilizzata versione più stabile del NDK
- **Cache intelligente**: Le dipendenze buildozer vengono salvate tra le build
- **Licenze automatiche**: SDK license viene accettato automaticamente

## Troubleshooting

**Se la build fallisce**:
1. Controlla i log in Actions
2. Verifica che `buildozer.spec` sia configurato correttamente
3. Assicurati che `main.py` sia la versione Kivy (non Tkinter)
4. Controlla che tutte le dipendenze in requirements siano compatibili con Android

**Per debug locale** (solo su Linux x86_64):
```bash
buildozer -v android debug
```

