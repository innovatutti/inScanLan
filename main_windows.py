"""
inScanLan - Network Scanner
Applicazione Windows per la scansione completa della rete locale
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import threading
import queue
import os
import sys
import subprocess
import re
import json
import webbrowser
import socket
import sqlite3
from datetime import datetime
from network_scanner import NetworkScanner

class InScanLanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("inScanLan - Network Scanner")
        self.root.geometry("1200x800")
        self.root.configure(bg="#2b2b2b")
        
        # Imposta l'icona dell'applicazione
        self.set_app_icon()
        
        # Inizializza database
        self.init_database()
        
        self.scanner = NetworkScanner()
        self.log_queue = queue.Queue()
        self.is_scanning = False
        
        self.setup_ui()
        self.update_log()
        
    def set_app_icon(self):
        """
        Imposta l'icona dell'applicazione dal file logo_inscanlan.jpg
        """
        try:
            # Percorso del logo (gestisce sia esecuzione da script che da exe)
            if getattr(sys, 'frozen', False):
                # Se è un exe compilato con PyInstaller
                base_path = sys._MEIPASS
            else:
                # Se è uno script Python
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            logo_path = os.path.join(base_path, 'logo_inscanlan.jpg')
            
            if os.path.exists(logo_path):
                # Tkinter supporta solo .ico per iconwindow, usiamo PhotoImage per la finestra
                logo_img = tk.PhotoImage(file=logo_path)
                self.root.iconphoto(True, logo_img)
            else:
                # Fallback: prova anche con .ico se esiste
                ico_path = os.path.join(base_path, 'logo_inscanlan.ico')
                if os.path.exists(ico_path):
                    self.root.iconbitmap(ico_path)
        except Exception as e:
            # Se fallisce, continua senza icona personalizzata
            pass
        
    def setup_ui(self):
        # Stile
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", padding=6, font=('Segoe UI', 10))
        style.configure("TLabel", background="#2b2b2b", foreground="white", font=('Segoe UI', 10))
        style.configure("TFrame", background="#2b2b2b")
        
        # Frame principale
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurazione grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Header con toolbar file
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=10)
        header_frame.columnconfigure(1, weight=1)
        
        # Toolbar File (sinistra)
        file_toolbar = tk.Frame(header_frame, bg="#2b2b2b")
        file_toolbar.grid(row=0, column=0, sticky=tk.W, padx=5)
        
        tk.Button(file_toolbar, text="💾 Salva", command=self.save_network_map,
                 bg="#004400", fg="white", font=('Segoe UI', 9, 'bold'), padx=10, pady=3).pack(side=tk.LEFT, padx=2)
        tk.Button(file_toolbar, text="📂 Apri", command=self.load_network_map,
                 bg="#004466", fg="white", font=('Segoe UI', 9, 'bold'), padx=10, pady=3).pack(side=tk.LEFT, padx=2)
        tk.Button(file_toolbar, text="📄 PDF", command=self.export_to_pdf,
                 bg="#aa5500", fg="white", font=('Segoe UI', 9, 'bold'), padx=10, pady=3).pack(side=tk.LEFT, padx=2)
        
        # Titolo (centro)
        header_label = tk.Label(header_frame, text="🔍 inScanLan - Network Scanner", 
                               font=('Segoe UI', 20, 'bold'), bg="#2b2b2b", fg="#00ff00")
        header_label.grid(row=0, column=1)
        
        # Frame controlli
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, pady=10, sticky=(tk.W, tk.E))
        control_frame.columnconfigure(1, weight=1)
        
        # Range IP
        ttk.Label(control_frame, text="Range IP:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.ip_entry = ttk.Entry(control_frame, width=30, font=('Consolas', 10))
        
        # Rileva automaticamente la subnet locale
        local_ip, local_subnet = self.scanner.get_local_network()
        self.ip_entry.insert(0, local_subnet)
        self.ip_entry.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # Pulsante per rilevare subnet
        self.detect_btn = tk.Button(control_frame, text="🔄", command=self.detect_subnet,
                                    bg="#0066cc", fg="white", font=('Segoe UI', 9), padx=5)
        self.detect_btn.grid(row=0, column=2, padx=2)
        
        # Range porte
        ttk.Label(control_frame, text="Porte:").grid(row=0, column=3, padx=5, sticky=tk.W)
        self.port_entry = ttk.Entry(control_frame, width=20, font=('Consolas', 10))
        self.port_entry.insert(0, "21,22,23,80,443,445,3389,8080")
        self.port_entry.grid(row=0, column=4, padx=5, sticky=tk.W)
        
        # Mostra IP locale
        ttk.Label(control_frame, text=f"IP Locale: {local_ip}", 
                 foreground="#00aaff").grid(row=1, column=0, columnspan=3, padx=5, sticky=tk.W)
        
        # Opzioni
        options_frame = ttk.Frame(main_frame)
        options_frame.grid(row=2, column=0, pady=5, sticky=(tk.W, tk.E))
        
        self.ping_var = tk.BooleanVar(value=True)
        self.netbios_var = tk.BooleanVar(value=True)
        self.arp_var = tk.BooleanVar(value=True)
        self.port_scan_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Ping Scan", variable=self.ping_var).grid(row=0, column=0, padx=10)
        ttk.Checkbutton(options_frame, text="NetBIOS", variable=self.netbios_var).grid(row=0, column=1, padx=10)
        ttk.Checkbutton(options_frame, text="ARP", variable=self.arp_var).grid(row=0, column=2, padx=10)
        ttk.Checkbutton(options_frame, text="Port Scan", variable=self.port_scan_var).grid(row=0, column=3, padx=10)
        
        # Pulsanti
        self.scan_button = tk.Button(options_frame, text="▶ Avvia Scansione", 
                                     command=self.start_scan, bg="#00aa00", fg="white",
                                     font=('Segoe UI', 11, 'bold'), padx=20)
        self.scan_button.grid(row=0, column=4, padx=20)
        
        self.stop_button = tk.Button(options_frame, text="⬛ Stop", 
                                     command=self.stop_scan, bg="#aa0000", fg="white",
                                     font=('Segoe UI', 11, 'bold'), padx=20, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=5)
        
        # Sezione Ping Continuo
        ttk.Label(options_frame, text="Ping -t:", foreground="#00aaff").grid(row=0, column=6, padx=10)
        self.ping_ip_entry = ttk.Entry(options_frame, width=15, font=('Consolas', 10))
        self.ping_ip_entry.grid(row=0, column=7, padx=5)
        
        self.ping_button = tk.Button(options_frame, text="📡 Ping", 
                                     command=self.start_continuous_ping, bg="#0066cc", fg="white",
                                     font=('Segoe UI', 10, 'bold'), padx=15)
        self.ping_button.grid(row=0, column=8, padx=5)
        
        # Pulsante Scansione WiFi
        self.wifi_button = tk.Button(options_frame, text="📶 WiFi Scan", 
                                     command=self.open_wifi_scanner, bg="#9900cc", fg="white",
                                     font=('Segoe UI', 10, 'bold'), padx=15)
        self.wifi_button.grid(row=0, column=9, padx=5)
        
        # Pulsante Salva Scansione con Nome
        self.save_scan_button = tk.Button(options_frame, text="💾 Salva", 
                                         command=self.save_scan_with_name, bg="#006699", fg="white",
                                         font=('Segoe UI', 10, 'bold'), padx=15)
        self.save_scan_button.grid(row=0, column=10, padx=5)
        
        # Pulsante Carica Scansioni
        self.load_scan_button = tk.Button(options_frame, text="📂 Carica", 
                                          command=self.load_saved_scans, bg="#669900", fg="white",
                                          font=('Segoe UI', 10, 'bold'), padx=15)
        self.load_scan_button.grid(row=0, column=11, padx=5)
        
        # Notebook per tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=3, column=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Tab Risultati (PRIMA TAB)
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text="📊 Dispositivi Trovati")
        
        # Treeview per risultati
        columns = ('IP', 'Hostname', 'NetBIOS', 'MAC', 'Produttore', 'Porte Aperte', 'Status')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.tree.heading(col, text=col)
            if col == 'Porte Aperte':
                self.tree.column(col, width=200)
            elif col == 'Produttore':
                self.tree.column(col, width=150)
            else:
                self.tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Bind doppio click su IP per aprire finestra ping
        self.tree.bind('<Double-Button-1>', self.on_device_double_click)
        
        # Bind tasto destro per menu contestuale
        self.tree.bind('<Button-3>', self.show_context_menu)
        
        # Tab Log
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="📋 Log Real-Time")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=100, height=25, 
                                                  bg="#1e1e1e", fg="#00ff00",
                                                  font=('Consolas', 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab Statistiche
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📈 Statistiche")
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, width=100, height=25,
                                                    bg="#1e1e1e", fg="#00aaff",
                                                    font=('Consolas', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="Pronto", bd=1, relief=tk.SUNKEN, 
                                   anchor=tk.W, bg="#1e1e1e", fg="#00ff00", 
                                   font=('Segoe UI', 9))
        self.status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "#00ff00",
            "WARNING": "#ffaa00",
            "ERROR": "#ff0000",
            "SUCCESS": "#00ffaa"
        }
        self.log_queue.put((timestamp, message, level, color_map.get(level, "#00ff00")))
        
    def update_log(self):
        try:
            while True:
                timestamp, message, level, color = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, f"[{timestamp}] [{level}] {message}\n")
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.update_log)
        
    def start_scan(self):
        if self.is_scanning:
            return
            
        # Valida input
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            messagebox.showerror("Errore", "Inserisci un range IP valido")
            return
            
        # Parse porte
        port_input = self.port_entry.get().strip()
        try:
            ports = [int(p.strip()) for p in port_input.split(',') if p.strip()]
        except:
            messagebox.showerror("Errore", "Formato porte non valido")
            return
            
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Pulisci risultati precedenti
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.log_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        self.log("=== AVVIO SCANSIONE RETE ===", "SUCCESS")
        self.log(f"Range IP: {ip_range}", "INFO")
        self.log(f"Porte da scansionare: {ports}", "INFO")
        self.status_bar.config(text="Scansione in corso...")
        
        # Opzioni scansione
        options = {
            'ping': self.ping_var.get(),
            'netbios': self.netbios_var.get(),
            'arp': self.arp_var.get(),
            'port_scan': self.port_scan_var.get()
        }
        
        # Avvia scansione in thread separato
        scan_thread = threading.Thread(target=self.run_scan, 
                                       args=(ip_range, ports, options),
                                       daemon=True)
        scan_thread.start()
        
    def run_scan(self, ip_range, ports, options):
        try:
            results = self.scanner.scan_network(ip_range, ports, options, self.log)
            
            # Aggiorna treeview con risultati
            self.root.after(0, self.update_results, results)
            
            self.log("=== SCANSIONE COMPLETATA ===", "SUCCESS")
            self.status_bar.config(text=f"Scansione completata - {len(results)} dispositivi trovati")
            
        except Exception as e:
            self.log(f"Errore durante la scansione: {str(e)}", "ERROR")
            self.status_bar.config(text="Errore durante la scansione")
        finally:
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
    def update_results(self, results):
        for device in results:
            ports_str = ', '.join(map(str, device.get('open_ports', [])))
            self.tree.insert('', tk.END, values=(
                device.get('ip', 'N/A'),
                device.get('hostname', 'N/A'),
                device.get('netbios', 'N/A'),
                device.get('mac', 'N/A'),
                device.get('vendor', 'N/A'),
                ports_str if ports_str else 'Nessuna',
                device.get('status', 'N/A')
            ))
            
        # Aggiorna statistiche
        self.update_statistics(results)
        
    def update_statistics(self, results):
        self.stats_text.delete(1.0, tk.END)
        
        total = len(results)
        alive = sum(1 for d in results if d.get('status') == 'Online')
        
        stats = f"""
╔════════════════════════════════════════════════════════════╗
║             STATISTICHE SCANSIONE RETE                     ║
╚════════════════════════════════════════════════════════════╝

📊 Dispositivi Totali:        {total}
✅ Dispositivi Online:        {alive}
❌ Dispositivi Offline:       {total - alive}

🔌 PORTE APERTE PIÙ COMUNI:
"""
        
        # Conta porte aperte
        port_count = {}
        for device in results:
            for port in device.get('open_ports', []):
                port_count[port] = port_count.get(port, 0) + 1
                
        for port, count in sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            port_name = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP', 
                443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 8080: 'HTTP-ALT'
            }.get(port, 'Unknown')
            stats += f"   Porta {port:5d} ({port_name:10s}): {count} dispositivi\n"
            
        stats += f"\n🖥️  TIPI DI DISPOSITIVI:\n"
        netbios_names = [d.get('netbios', '') for d in results if d.get('netbios')]
        stats += f"   Con nome NetBIOS: {len(netbios_names)}\n"
        
        mac_vendors = {}
        for device in results:
            vendor = device.get('vendor', 'Unknown')
            if vendor != 'N/A' and vendor != 'Unknown':
                mac_vendors[vendor] = mac_vendors.get(vendor, 0) + 1
                
        stats += f"\n📡 PRODUTTORI:\n"
        for vendor, count in sorted(mac_vendors.items(), key=lambda x: x[1], reverse=True)[:5]:
            stats += f"   {vendor}: {count} dispositivi\n"
            
        self.stats_text.insert(1.0, stats)
        
    def detect_subnet(self):
        """
        Rileva nuovamente la subnet locale e aggiorna il campo IP
        """
        try:
            local_ip, local_subnet = self.scanner.get_local_network()
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, local_subnet)
            
            # Aggiorna label IP locale
            for widget in self.root.winfo_children():
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Frame):
                        for subchild in child.winfo_children():
                            if isinstance(subchild, ttk.Label) and "IP Locale:" in str(subchild.cget('text')):
                                subchild.config(text=f"IP Locale: {local_ip}")
                                
            self.log(f"Subnet rilevata: {local_subnet} (IP: {local_ip})", "SUCCESS")
            messagebox.showinfo("Subnet Rilevata", 
                              f"IP Locale: {local_ip}\nSubnet: {local_subnet}\n\nPuoi modificare manualmente se necessario.")
        except Exception as e:
            self.log(f"Errore rilevamento subnet: {str(e)}", "ERROR")
            messagebox.showerror("Errore", "Impossibile rilevare la subnet automaticamente")
    
    def init_database(self):
        """Inizializza il database SQLite per memorizzare scansioni e credenziali"""
        try:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'inscanlan.db')
            self.conn = sqlite3.connect(db_path)
            self.cursor = self.conn.cursor()
            
            # Tabella scansioni
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    subnet TEXT,
                    devices_count INTEGER,
                    scan_data TEXT
                )
            ''')
            
            # Tabella credenziali SMB
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS smb_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    username TEXT,
                    password TEXT,
                    share_path TEXT,
                    notes TEXT
                )
            ''')
            
            # Tabella password WiFi
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS wifi_passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT UNIQUE,
                    password TEXT,
                    security_type TEXT,
                    timestamp TEXT
                )
            ''')
            
            self.conn.commit()
        except Exception as e:
            print(f"Errore inizializzazione database: {e}")
    
    def save_current_scan(self):
        """Salva la scansione corrente nel database"""
        try:
            devices = []
            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                devices.append({
                    'ip': values[0],
                    'hostname': values[1],
                    'netbios': values[2],
                    'mac': values[3],
                    'vendor': values[4],
                    'ports': values[5],
                    'status': values[6]
                })
            
            scan_data = json.dumps(devices)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            subnet = self.ip_entry.get()
            
            self.cursor.execute('''
                INSERT INTO scans (timestamp, subnet, devices_count, scan_data)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, subnet, len(devices), scan_data))
            
            self.conn.commit()
            self.log(f"Scansione salvata: {len(devices)} dispositivi", "SUCCESS")
            messagebox.showinfo("Salvato", f"Scansione salvata nel database\n{len(devices)} dispositivi")
        except Exception as e:
            self.log(f"Errore salvataggio: {str(e)}", "ERROR")
    
    def load_scan_from_db(self):
        """Carica una scansione salvata dal database"""
        try:
            # Finestra selezione scansione
            select_win = tk.Toplevel(self.root)
            select_win.title("Carica Scansione")
            select_win.geometry("800x400")
            select_win.configure(bg="#2b2b2b")
            
            tk.Label(select_win, text="Scansioni Salvate", font=('Segoe UI', 16, 'bold'),
                    bg="#2b2b2b", fg="#00ff00").pack(pady=10)
            
            # Treeview per scansioni
            cols = ('ID', 'Data/Ora', 'Subnet', 'Dispositivi')
            scan_tree = ttk.Treeview(select_win, columns=cols, show='headings', height=15)
            
            for col in cols:
                scan_tree.heading(col, text=col)
            
            scan_tree.column('ID', width=50)
            scan_tree.column('Data/Ora', width=200)
            scan_tree.column('Subnet', width=200)
            scan_tree.column('Dispositivi', width=100)
            
            # Carica scansioni dal DB
            self.cursor.execute('SELECT id, timestamp, subnet, devices_count FROM scans ORDER BY id DESC')
            scans = self.cursor.fetchall()
            
            for scan in scans:
                scan_tree.insert('', tk.END, values=scan)
            
            scan_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            def load_selected():
                selection = scan_tree.selection()
                if not selection:
                    messagebox.showwarning("Attenzione", "Seleziona una scansione")
                    return
                
                scan_id = scan_tree.item(selection[0])['values'][0]
                self.cursor.execute('SELECT scan_data FROM scans WHERE id = ?', (scan_id,))
                result = self.cursor.fetchone()
                
                if result:
                    devices = json.loads(result[0])
                    
                    # Pulisci treeview
                    for item in self.tree.get_children():
                        self.tree.delete(item)
                    
                    # Carica dispositivi
                    for device in devices:
                        self.tree.insert('', tk.END, values=(
                            device['ip'],
                            device['hostname'],
                            device['netbios'],
                            device['mac'],
                            device['vendor'],
                            device['ports'],
                            device['status']
                        ))
                    
                    self.log(f"Scansione caricata: {len(devices)} dispositivi", "SUCCESS")
                    select_win.destroy()
            
            btn_frame = tk.Frame(select_win, bg="#2b2b2b")
            btn_frame.pack(pady=10)
            
            tk.Button(btn_frame, text="Carica", command=load_selected,
                     bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="Annulla", command=select_win.destroy,
                     bg="#aa0000", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
        
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile caricare scansioni:\n{str(e)}")
    
    def save_scan_with_name(self):
        """Salva la scansione corrente con un nome personalizzato"""
        if not self.tree.get_children():
            messagebox.showwarning("Attenzione", "Nessuna scansione da salvare")
            return
        
        # Finestra per inserire il nome
        save_win = tk.Toplevel(self.root)
        save_win.title("Salva Scansione")
        save_win.geometry("500x250")
        save_win.configure(bg="#2b2b2b")
        
        tk.Label(save_win, text="💾 Salva Scansione", font=('Segoe UI', 16, 'bold'),
                bg="#2b2b2b", fg="#00ff00").pack(pady=20)
        
        tk.Label(save_win, text="Nome scansione:", bg="#2b2b2b", fg="white",
                font=('Segoe UI', 11)).pack(pady=5)
        
        # Nome predefinito con data/ora
        default_name = f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        name_entry = ttk.Entry(save_win, width=40, font=('Segoe UI', 11))
        name_entry.insert(0, default_name)
        name_entry.pack(pady=10)
        name_entry.focus()
        
        def do_save():
            scan_name = name_entry.get().strip()
            if not scan_name:
                messagebox.showwarning("Attenzione", "Inserisci un nome per la scansione")
                return
            
            try:
                # Raccogli dati dispositivi
                devices = []
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    devices.append({
                        'ip': values[0],
                        'hostname': values[1],
                        'netbios': values[2],
                        'mac': values[3],
                        'vendor': values[4],
                        'ports': values[5],
                        'status': values[6]
                    })
                
                scan_data = json.dumps(devices)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                subnet = self.ip_entry.get()
                
                # Modifica tabella per includere nome scansione
                self.cursor.execute('''
                    INSERT INTO scans (timestamp, subnet, devices_count, scan_data, scan_name)
                    VALUES (?, ?, ?, ?, ?)
                ''', (timestamp, subnet, len(devices), scan_data, scan_name))
                
                self.conn.commit()
                self.log(f"Scansione '{scan_name}' salvata: {len(devices)} dispositivi", "SUCCESS")
                messagebox.showinfo("Salvato", f"Scansione '{scan_name}' salvata!\n{len(devices)} dispositivi")
                save_win.destroy()
            except sqlite3.IntegrityError:
                # Se la colonna scan_name non esiste ancora, aggiungila
                try:
                    self.cursor.execute('ALTER TABLE scans ADD COLUMN scan_name TEXT')
                    self.conn.commit()
                    # Riprova il salvataggio
                    do_save()
                except Exception as e:
                    messagebox.showerror("Errore", f"Errore salvataggio:\n{str(e)}")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore salvataggio:\n{str(e)}")
        
        btn_frame = tk.Frame(save_win, bg="#2b2b2b")
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="✅ Salva", command=do_save,
                 bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=30).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="❌ Annulla", command=save_win.destroy,
                 bg="#aa0000", fg="white", font=('Segoe UI', 11, 'bold'), padx=30).pack(side=tk.LEFT, padx=5)
        
        # Enter per salvare
        name_entry.bind('<Return>', lambda e: do_save())
    
    def load_saved_scans(self):
        """Finestra per caricare scansioni salvate con nome"""
        try:
            # Aggiungi colonna scan_name se non esiste
            try:
                self.cursor.execute('ALTER TABLE scans ADD COLUMN scan_name TEXT')
                self.conn.commit()
            except:
                pass  # Colonna già esistente
            
            # Finestra selezione scansione
            select_win = tk.Toplevel(self.root)
            select_win.title("Carica Scansione Salvata")
            select_win.geometry("900x500")
            select_win.configure(bg="#2b2b2b")
            
            tk.Label(select_win, text="📂 Scansioni Salvate", font=('Segoe UI', 16, 'bold'),
                    bg="#2b2b2b", fg="#00ff00").pack(pady=10)
            
            # Treeview per scansioni
            cols = ('ID', 'Nome', 'Data/Ora', 'Subnet', 'Dispositivi')
            scan_tree = ttk.Treeview(select_win, columns=cols, show='headings', height=18)
            
            for col in cols:
                scan_tree.heading(col, text=col)
            
            scan_tree.column('ID', width=50)
            scan_tree.column('Nome', width=250)
            scan_tree.column('Data/Ora', width=180)
            scan_tree.column('Subnet', width=180)
            scan_tree.column('Dispositivi', width=100)
            
            scrollbar = ttk.Scrollbar(select_win, orient=tk.VERTICAL, command=scan_tree.yview)
            scan_tree.configure(yscroll=scrollbar.set)
            
            # Carica scansioni dal DB
            self.cursor.execute('SELECT id, scan_name, timestamp, subnet, devices_count FROM scans ORDER BY id DESC')
            scans = self.cursor.fetchall()
            
            for scan in scans:
                scan_id, scan_name, timestamp, subnet, count = scan
                display_name = scan_name if scan_name else "(senza nome)"
                scan_tree.insert('', tk.END, values=(scan_id, display_name, timestamp, subnet, count))
            
            scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
            scrollbar.pack(side=tk.LEFT, fill=tk.Y, pady=10)
            
            def load_selected():
                selection = scan_tree.selection()
                if not selection:
                    messagebox.showwarning("Attenzione", "Seleziona una scansione")
                    return
                
                scan_id = scan_tree.item(selection[0])['values'][0]
                scan_name = scan_tree.item(selection[0])['values'][1]
                
                self.cursor.execute('SELECT scan_data, subnet FROM scans WHERE id = ?', (scan_id,))
                result = self.cursor.fetchone()
                
                if result:
                    devices = json.loads(result[0])
                    subnet = result[1]
                    
                    # Pulisci treeview
                    for item in self.tree.get_children():
                        self.tree.delete(item)
                    
                    # Aggiorna subnet nel campo
                    self.ip_entry.delete(0, tk.END)
                    self.ip_entry.insert(0, subnet)
                    
                    # Carica dispositivi
                    for device in devices:
                        self.tree.insert('', tk.END, values=(
                            device['ip'],
                            device['hostname'],
                            device['netbios'],
                            device['mac'],
                            device['vendor'],
                            device['ports'],
                            device['status']
                        ))
                    
                    self.log(f"Scansione '{scan_name}' caricata: {len(devices)} dispositivi", "SUCCESS")
                    messagebox.showinfo("Caricato", f"Scansione '{scan_name}' caricata\n{len(devices)} dispositivi")
                    select_win.destroy()
            
            def delete_selected():
                selection = scan_tree.selection()
                if not selection:
                    messagebox.showwarning("Attenzione", "Seleziona una scansione da eliminare")
                    return
                
                scan_id = scan_tree.item(selection[0])['values'][0]
                scan_name = scan_tree.item(selection[0])['values'][1]
                
                if messagebox.askyesno("Conferma", f"Eliminare la scansione '{scan_name}'?"):
                    self.cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
                    self.conn.commit()
                    scan_tree.delete(selection[0])
                    self.log(f"Scansione '{scan_name}' eliminata", "INFO")
            
            btn_frame = tk.Frame(select_win, bg="#2b2b2b")
            btn_frame.pack(pady=10)
            
            tk.Button(btn_frame, text="✅ Carica", command=load_selected,
                     bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="🗑️ Elimina", command=delete_selected,
                     bg="#cc6600", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="❌ Chiudi", command=select_win.destroy,
                     bg="#aa0000", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
        
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile caricare scansioni:\n{str(e)}")
            btn_frame.pack(pady=10)
            
            tk.Button(btn_frame, text="Carica", command=load_selected,
                     bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="Annulla", command=select_win.destroy,
                     bg="#aa0000", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
            
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile caricare scansioni:\n{str(e)}")
    
    def show_context_menu(self, event):
        """Mostra menu contestuale con tasto destro"""
        # Seleziona item sotto il mouse
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            values = self.tree.item(item)['values']
            ip_address = values[0]
            hostname = values[1]
            
            # Crea menu
            context_menu = tk.Menu(self.root, tearoff=0, bg="#2b2b2b", fg="white",
                                  activebackground="#00aa00", activeforeground="white")
            
            context_menu.add_command(label=f"📡 Ping {ip_address}", 
                                    command=lambda: self.open_ping_window(ip_address, hostname))
            context_menu.add_command(label=f"⚡ Test Velocità", 
                                    command=lambda: self.test_speed(ip_address))
            context_menu.add_separator()
            context_menu.add_command(label=f"🌐 Apri nel Browser (http://{ip_address})", 
                                    command=lambda: self.open_in_browser(ip_address))
            context_menu.add_command(label=f"🔌 SSH a {ip_address}", 
                                    command=lambda: self.open_ssh_window(ip_address))
            context_menu.add_separator()
            context_menu.add_command(label=f"📂 Mapping SMB/CIFS", 
                                    command=lambda: self.create_smb_mapping(ip_address))
            context_menu.add_command(label=f"🔑 Gestisci Credenziali SMB", 
                                    command=lambda: self.manage_smb_credentials(ip_address))
            context_menu.add_separator()
            context_menu.add_command(label=f"📋 Copia IP", 
                                    command=lambda: self.copy_to_clipboard(ip_address))
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
    
    def copy_to_clipboard(self, text):
        """Copia testo negli appunti"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log(f"Copiato: {text}", "INFO")
    
    def create_smb_mapping(self, ip_address):
        """Crea mapping di rete SMB/CIFS con credenziali"""
        map_win = tk.Toplevel(self.root)
        map_win.title(f"Mapping SMB - {ip_address}")
        map_win.geometry("500x400")
        map_win.configure(bg="#2b2b2b")
        
        tk.Label(map_win, text=f"🔌 Mapping Rete SMB", font=('Segoe UI', 16, 'bold'),
                bg="#2b2b2b", fg="#00ff00").pack(pady=10)
        
        tk.Label(map_win, text=f"Server: {ip_address}", font=('Segoe UI', 12),
                bg="#2b2b2b", fg="#00aaff").pack(pady=5)
        
        # Form
        form_frame = tk.Frame(map_win, bg="#2b2b2b")
        form_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        # Percorso condivisione
        tk.Label(form_frame, text="Percorso Condivisione:", bg="#2b2b2b", fg="white").grid(row=0, column=0, sticky=tk.W, pady=5)
        share_entry = ttk.Entry(form_frame, width=30)
        share_entry.insert(0, f"\\\\{ip_address}\\")
        share_entry.grid(row=0, column=1, pady=5, padx=5)
        
        # Lettera unità
        tk.Label(form_frame, text="Lettera Unità:", bg="#2b2b2b", fg="white").grid(row=1, column=0, sticky=tk.W, pady=5)
        drive_var = tk.StringVar(value="Z:")
        drive_combo = ttk.Combobox(form_frame, textvariable=drive_var, width=10,
                                   values=[f"{chr(i)}:" for i in range(ord('E'), ord('Z')+1)])
        drive_combo.grid(row=1, column=1, pady=5, padx=5, sticky=tk.W)
        
        # Username
        tk.Label(form_frame, text="Username:", bg="#2b2b2b", fg="white").grid(row=2, column=0, sticky=tk.W, pady=5)
        user_entry = ttk.Entry(form_frame, width=30)
        user_entry.grid(row=2, column=1, pady=5, padx=5)
        
        # Password
        tk.Label(form_frame, text="Password:", bg="#2b2b2b", fg="white").grid(row=3, column=0, sticky=tk.W, pady=5)
        pass_entry = ttk.Entry(form_frame, width=30, show="*")
        pass_entry.grid(row=3, column=1, pady=5, padx=5)
        
        # Salva credenziali
        save_cred_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(form_frame, text="Salva credenziali nel database", 
                       variable=save_cred_var).grid(row=4, column=0, columnspan=2, pady=10)
        
        # Carica credenziali salvate
        self.cursor.execute('SELECT username, password, share_path FROM smb_credentials WHERE ip_address = ?', (ip_address,))
        saved = self.cursor.fetchone()
        if saved:
            user_entry.insert(0, saved[0])
            pass_entry.insert(0, saved[1])
            if saved[2]:
                share_entry.delete(0, tk.END)
                share_entry.insert(0, saved[2])
        
        def do_mapping():
            share_path = share_entry.get().strip()
            drive = drive_var.get()
            username = user_entry.get().strip()
            password = pass_entry.get()
            
            if not share_path:
                messagebox.showwarning("Attenzione", "Inserisci il percorso di condivisione")
                return
            
            try:
                # Disconnetti se già mappato
                subprocess.run(['net', 'use', drive, '/delete'], 
                             capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                
                # Crea mapping
                cmd = ['net', 'use', drive, share_path]
                if username:
                    cmd.extend([f'/user:{username}', password])
                cmd.append('/persistent:yes')
                
                result = subprocess.run(cmd, capture_output=True, text=True,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
                
                if result.returncode == 0:
                    # Salva credenziali se richiesto
                    if save_cred_var.get() and username:
                        self.cursor.execute('''
                            INSERT OR REPLACE INTO smb_credentials (ip_address, username, password, share_path)
                            VALUES (?, ?, ?, ?)
                        ''', (ip_address, username, password, share_path))
                        self.conn.commit()
                    
                    self.log(f"Mapping creato: {drive} -> {share_path}", "SUCCESS")
                    messagebox.showinfo("Successo", f"Mapping creato con successo!\n\n{drive} -> {share_path}")
                    map_win.destroy()
                else:
                    messagebox.showerror("Errore", f"Impossibile creare mapping:\n{result.stderr}")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore creazione mapping:\n{str(e)}")
        
        btn_frame = tk.Frame(map_win, bg="#2b2b2b")
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="✅ Crea Mapping", command=do_mapping,
                 bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="❌ Annulla", command=map_win.destroy,
                 bg="#aa0000", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
    
    def manage_smb_credentials(self, ip_address):
        """Gestisci credenziali SMB salvate"""
        cred_win = tk.Toplevel(self.root)
        cred_win.title("Gestione Credenziali SMB")
        cred_win.geometry("700x500")
        cred_win.configure(bg="#2b2b2b")
        
        tk.Label(cred_win, text="🔑 Credenziali SMB Salvate", font=('Segoe UI', 16, 'bold'),
                bg="#2b2b2b", fg="#00ff00").pack(pady=10)
        
        # Treeview
        cols = ('IP', 'Username', 'Share', 'Note')
        cred_tree = ttk.Treeview(cred_win, columns=cols, show='headings', height=15)
        
        for col in cols:
            cred_tree.heading(col, text=col)
        
        cred_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def refresh_list():
            for item in cred_tree.get_children():
                cred_tree.delete(item)
            
            self.cursor.execute('SELECT ip_address, username, share_path, notes FROM smb_credentials')
            for row in self.cursor.fetchall():
                cred_tree.insert('', tk.END, values=row)
        
        refresh_list()
        
        def delete_cred():
            selection = cred_tree.selection()
            if selection:
                ip = cred_tree.item(selection[0])['values'][0]
                if messagebox.askyesno("Conferma", f"Eliminare credenziali per {ip}?"):
                    self.cursor.execute('DELETE FROM smb_credentials WHERE ip_address = ?', (ip,))
                    self.conn.commit()
                    refresh_list()
        
        tk.Button(cred_win, text="🗑️ Elimina Selezionato", command=delete_cred,
                 bg="#aa0000", fg="white", font=('Segoe UI', 10), padx=15).pack(pady=10)
    
    def extract_wifi_passwords(self):
        """Estrae e salva password WiFi di Windows"""
        try:
            # Ottieni profili WiFi
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                  capture_output=True, text=True, encoding='cp437',
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            
            profiles = re.findall(r'Profilo.*: (.+)', result.stdout)
            
            wifi_data = []
            for profile in profiles:
                profile = profile.strip()
                # Ottieni password
                key_result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'],
                                          capture_output=True, text=True, encoding='cp437',
                                          creationflags=subprocess.CREATE_NO_WINDOW)
                
                password_match = re.search(r'Contenuto chiave.*: (.+)', key_result.stdout)
                password = password_match.group(1).strip() if password_match else None
                
                security_match = re.search(r'Autenticazione.*: (.+)', key_result.stdout)
                security = security_match.group(1).strip() if security_match else 'Unknown'
                
                if password:
                    wifi_data.append((profile, password, security))
                    
                    # Salva nel database
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.cursor.execute('''
                        INSERT OR REPLACE INTO wifi_passwords (ssid, password, security_type, timestamp)
                        VALUES (?, ?, ?, ?)
                    ''', (profile, password, security, timestamp))
            
            self.conn.commit()
            
            # Mostra risultati
            if wifi_data:
                wifi_win = tk.Toplevel(self.root)
                wifi_win.title("Password WiFi Salvate")
                wifi_win.geometry("700x400")
                wifi_win.configure(bg="#2b2b2b")
                
                tk.Label(wifi_win, text=f"🔐 Password WiFi Trovate ({len(wifi_data)})", font=('Segoe UI', 16, 'bold'),
                        bg="#2b2b2b", fg="#00ff00").pack(pady=10)
                
                cols = ('SSID', 'Password', 'Sicurezza')
                wifi_tree = ttk.Treeview(wifi_win, columns=cols, show='headings', height=15)
                
                for col in cols:
                    wifi_tree.heading(col, text=col)
                
                wifi_tree.column('SSID', width=250)
                wifi_tree.column('Password', width=250)
                wifi_tree.column('Sicurezza', width=180)
                
                for ssid, pwd, sec in wifi_data:
                    wifi_tree.insert('', tk.END, values=(ssid, pwd, sec))
                
                scrollbar = ttk.Scrollbar(wifi_win, orient=tk.VERTICAL, command=wifi_tree.yview)
                wifi_tree.configure(yscroll=scrollbar.set)
                wifi_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10, padx=(0, 10))
                
                # Pulsante Esporta
                btn_frame = tk.Frame(wifi_win, bg="#2b2b2b")
                btn_frame.pack(pady=10)
                
                def export_to_txt():
                    try:
                        filename = f"WiFi_Passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write("Password WiFi Estratte\n")
                            f.write("=" * 60 + "\n\n")
                            for ssid, pwd, sec in wifi_data:
                                f.write(f"SSID: {ssid}\n")
                                f.write(f"Password: {pwd}\n")
                                f.write(f"Sicurezza: {sec}\n")
                                f.write("-" * 60 + "\n")
                        messagebox.showinfo("Salvato", f"Esportato in: {filename}")
                    except Exception as e:
                        messagebox.showerror("Errore", f"Errore esportazione: {str(e)}")
                
                tk.Button(btn_frame, text="📄 Esporta TXT", command=export_to_txt,
                         bg="#0066cc", fg="white", font=('Segoe UI', 10, 'bold'), padx=20).pack(side=tk.LEFT, padx=5)
                
                self.log(f"Estratte {len(wifi_data)} password WiFi", "SUCCESS")
                messagebox.showinfo("Successo", f"Trovate {len(wifi_data)} password WiFi!\nSalvate nel database.")
            else:
                messagebox.showinfo("Info", f"Nessuna password WiFi trovata.\n\nProfili trovati: {len(profiles)}\n\nAssicurati di:\n- Essere connesso con WiFi\n- Avere profili salvati in Windows\n- Eseguire come amministratore se necessario")
                
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile estrarre password WiFi:\n{str(e)}")
    
    def on_device_double_click(self, event):
        """
        Gestisce il doppio click su un dispositivo nella treeview
        """
        selection = self.tree.selection()
        if not selection:
            return
            
        item = self.tree.item(selection[0])
        values = item['values']
        if values:
            ip_address = values[0]  # Prima colonna è l'IP
            hostname = values[1] if len(values) > 1 else 'N/A'
            self.open_ping_window(ip_address, hostname)
    
    def start_continuous_ping(self):
        """
        Avvia ping continuo dall'IP inserito nella textbox
        """
        ip = self.ping_ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Attenzione", "Inserisci un indirizzo IP")
            return
        self.open_ping_window(ip, ip)
    
    def open_ping_window(self, ip_address, hostname):
        """
        Apre una nuova finestra per il ping continuo con statistiche
        """
        ping_win = tk.Toplevel(self.root)
        ping_win.title(f"Ping Continuo - {ip_address}")
        ping_win.geometry("700x600")
        ping_win.configure(bg="#2b2b2b")
        
        # Header
        header_frame = tk.Frame(ping_win, bg="#1e1e1e", height=80)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text=f"🌐 {ip_address}", 
                font=('Segoe UI', 16, 'bold'), bg="#1e1e1e", fg="#00ff00").pack(pady=5)
        tk.Label(header_frame, text=f"Hostname: {hostname}", 
                font=('Segoe UI', 10), bg="#1e1e1e", fg="#00aaff").pack()
        
        # Frame statistiche
        stats_frame = tk.Frame(ping_win, bg="#1e1e1e")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Labels per statistiche
        stats_labels = {}
        stats_data = ['Pacchetti Inviati', 'Ricevuti', 'Persi', 'Tempo Medio (ms)', 'Min (ms)', 'Max (ms)', 'Ultima Risposta']
        
        for i, stat in enumerate(stats_data):
            row = i // 4
            col = i % 4
            
            frame = tk.Frame(stats_frame, bg="#2b2b2b", relief=tk.RIDGE, borderwidth=1)
            frame.grid(row=row, column=col, padx=5, pady=5, sticky=(tk.W, tk.E))
            
            tk.Label(frame, text=stat, font=('Segoe UI', 8), bg="#2b2b2b", fg="#888888").pack()
            label = tk.Label(frame, text="0", font=('Segoe UI', 14, 'bold'), bg="#2b2b2b", fg="#00ff00")
            label.pack()
            stats_labels[stat] = label
        
        # Area log ping
        tk.Label(ping_win, text="Log Ping:", font=('Segoe UI', 10, 'bold'), 
                bg="#2b2b2b", fg="white").pack(anchor=tk.W, padx=10)
        
        ping_text = scrolledtext.ScrolledText(ping_win, width=80, height=20,
                                             bg="#1e1e1e", fg="#00ff00",
                                             font=('Consolas', 9))
        ping_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Pulsanti controllo
        control_frame = tk.Frame(ping_win, bg="#2b2b2b")
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ping_active = {'running': False, 'thread': None}
        
        def start_ping():
            if ping_active['running']:
                return
            ping_active['running'] = True
            start_btn.config(state=tk.DISABLED)
            stop_btn.config(state=tk.NORMAL)
            
            def run_ping():
                sent = 0
                received = 0
                lost = 0
                times = []
                
                try:
                    process = subprocess.Popen(
                        ['ping', '-t', ip_address],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        encoding='cp437',
                        bufsize=1
                    )
                    
                    ping_active['process'] = process
                    
                    for line in iter(process.stdout.readline, ''):
                        if not ping_active['running']:
                            process.terminate()
                            break
                        
                        line = line.strip()
                        if line:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            ping_text.insert(tk.END, f"[{timestamp}] {line}\n")
                            ping_text.see(tk.END)
                            
                            # Analizza risposta
                            if 'Reply from' in line or 'Risposta da' in line:
                                sent += 1
                                received += 1
                                
                                # Estrai tempo di risposta
                                time_match = re.search(r'time[=<]?(\d+)ms', line, re.IGNORECASE)
                                if time_match:
                                    response_time = int(time_match.group(1))
                                    times.append(response_time)
                                    
                                    # Aggiorna statistiche usando after per thread safety
                                    def update_stats():
                                        stats_labels['Pacchetti Inviati'].config(text=str(sent))
                                        stats_labels['Ricevuti'].config(text=str(received))
                                        stats_labels['Persi'].config(text=str(lost), fg="#00ff00" if lost == 0 else "#ff0000")
                                        stats_labels['Ultima Risposta'].config(text=f"{response_time} ms", fg="#00ff00")
                                        
                                        if times:
                                            avg_time = sum(times) / len(times)
                                            stats_labels['Tempo Medio (ms)'].config(text=f"{avg_time:.1f}")
                                            stats_labels['Min (ms)'].config(text=str(min(times)))
                                            stats_labels['Max (ms)'].config(text=str(max(times)))
                                    
                                    ping_win.after(0, update_stats)
                                        
                            elif 'Request timed out' in line or 'Richiesta scaduta' in line or 'unreachable' in line:
                                sent += 1
                                lost += 1
                                
                                def update_timeout():
                                    stats_labels['Pacchetti Inviati'].config(text=str(sent))
                                    stats_labels['Persi'].config(text=str(lost), fg="#ff0000")
                                    stats_labels['Ultima Risposta'].config(text="TIMEOUT", fg="#ff0000")
                                
                                ping_win.after(0, update_timeout)
                                
                except Exception as e:
                    ping_text.insert(tk.END, f"\nErrore: {str(e)}\n")
                finally:
                    ping_active['running'] = False
                    start_btn.config(state=tk.NORMAL)
                    stop_btn.config(state=tk.DISABLED)
            
            ping_thread = threading.Thread(target=run_ping, daemon=True)
            ping_thread.start()
            ping_active['thread'] = ping_thread
        
        def stop_ping():
            ping_active['running'] = False
            if 'process' in ping_active:
                ping_active['process'].terminate()
            start_btn.config(state=tk.NORMAL)
            stop_btn.config(state=tk.DISABLED)
        
        start_btn = tk.Button(control_frame, text="▶ Avvia Ping", command=start_ping,
                             bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=20)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = tk.Button(control_frame, text="⬛ Stop", command=stop_ping,
                            bg="#aa0000", fg="white", font=('Segoe UI', 11, 'bold'), padx=20, state=tk.DISABLED)
        stop_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="🗑️ Pulisci Log", command=lambda: ping_text.delete(1.0, tk.END),
                 bg="#555555", fg="white", font=('Segoe UI', 10), padx=15).pack(side=tk.LEFT, padx=5)
        
        # Avvia automaticamente il ping
        ping_win.after(500, start_ping)
    
    def show_context_menu(self, event):
        """
        Mostra menu contestuale con tasto destro
        """
        # Seleziona l'elemento sotto il mouse
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            values = self.tree.item(item)['values']
            if values:
                ip_address = values[0]
                
                # Crea menu contestuale
                context_menu = Menu(self.root, tearoff=0, bg="#2b2b2b", fg="white",
                                   activebackground="#0066cc", activeforeground="white")
                context_menu.add_command(label=f"📡 Ping Continuo - {ip_address}", 
                                        command=lambda: self.open_ping_window(ip_address, values[1]))
                context_menu.add_separator()
                context_menu.add_command(label="⚡ Test Velocità", 
                                        command=lambda: self.test_speed(ip_address))
                context_menu.add_command(label="🌐 Apri in Browser (Configura)", 
                                        command=lambda: self.open_in_browser(ip_address))
                context_menu.add_command(label="🔐 Connetti via SSH", 
                                        command=lambda: self.open_ssh_window(ip_address))
                
                # Mostra menu
                context_menu.post(event.x_root, event.y_root)
    
    def test_speed(self, ip_address):
        """
        Testa la velocità di trasferimento dati verso un IP (MB/s o GB/s)
        """
        speed_win = tk.Toplevel(self.root)
        speed_win.title(f"Test Velocità - {ip_address}")
        speed_win.geometry("650x550")
        speed_win.configure(bg="#2b2b2b")
        
        # Header
        tk.Label(speed_win, text=f"📊 Test Velocità di Rete", 
                font=('Segoe UI', 16, 'bold'), bg="#2b2b2b", fg="#00ff00").pack(pady=10)
        tk.Label(speed_win, text=f"Destinazione: {ip_address}", 
                font=('Segoe UI', 10), bg="#2b2b2b", fg="#00aaff").pack()
        
        # Progress e risultati
        progress_label = tk.Label(speed_win, text="Inizializzazione...", 
                                 font=('Segoe UI', 10), bg="#2b2b2b", fg="white")
        progress_label.pack(pady=15)
        
        result_frame = tk.Frame(speed_win, bg="#1e1e1e", relief=tk.RIDGE, borderwidth=2)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        result_text = scrolledtext.ScrolledText(result_frame, width=70, height=20,
                                               bg="#1e1e1e", fg="#00ff00",
                                               font=('Consolas', 9))
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        def run_speed_test():
            import time
            
            result_text.insert(tk.END, f"{'='*60}\n")
            result_text.insert(tk.END, f"  TEST VELOCITÀ DI RETE\n")
            result_text.insert(tk.END, f"  Destinazione: {ip_address}\n")
            result_text.insert(tk.END, f"{'='*60}\n\n")
            
            # Test 1: Verifica connettività
            progress_label.config(text="1/3 Verifica connettività...")
            result_text.insert(tk.END, "[1/3] Test Connettività\n")
            result_text.insert(tk.END, "-" * 60 + "\n")
            
            # Trova porta aperta
            test_ports = [80, 443, 22, 21, 8080, 3389, 445]
            open_port = None
            
            for port in test_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))
                    sock.close()
                    if result == 0:
                        open_port = port
                        result_text.insert(tk.END, f"  ✅ Porta {port} APERTA\n")
                        break
                    else:
                        result_text.insert(tk.END, f"  ❌ Porta {port} chiusa\n")
                except:
                    result_text.insert(tk.END, f"  ⚠️  Porta {port} timeout\n")
            
            # Test 2: Latenza
            progress_label.config(text="2/3 Test latenza (50 ping)...")
            result_text.insert(tk.END, f"\n[2/3] Test Latenza\n")
            result_text.insert(tk.END, "-" * 60 + "\n")
            
            times = []
            for i in range(50):
                try:
                    start = time.time()
                    output = subprocess.run(
                        ['ping', '-n', '1', '-w', '1000', ip_address],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=2,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        encoding='cp437'
                    )
                    end = time.time()
                    if output.returncode == 0:
                        times.append((end - start) * 1000)
                    
                    if (i + 1) % 10 == 0:
                        progress_label.config(text=f"2/3 Test latenza... {i+1}/50")
                except:
                    pass
            
            if times:
                avg_latency = sum(times) / len(times)
                min_latency = min(times)
                max_latency = max(times)
                jitter = max_latency - min_latency
                
                result_text.insert(tk.END, f"  Latenza Media:  {avg_latency:7.2f} ms\n")
                result_text.insert(tk.END, f"  Latenza Min:    {min_latency:7.2f} ms\n")
                result_text.insert(tk.END, f"  Latenza Max:    {max_latency:7.2f} ms\n")
                result_text.insert(tk.END, f"  Jitter:         {jitter:7.2f} ms\n")
                result_text.insert(tk.END, f"  Pacchetti OK:   {len(times)}/50 ({len(times)*2}%)\n")
            else:
                result_text.insert(tk.END, "  ❌ Test latenza fallito\n")
            
            # Test 3: Throughput
            progress_label.config(text="3/3 Test throughput...")
            result_text.insert(tk.END, f"\n[3/3] Test Throughput (Velocità Trasferimento)\n")
            result_text.insert(tk.END, "-" * 60 + "\n")
            
            if open_port:
                result_text.insert(tk.END, f"  Usando porta {open_port} per il test...\n\n")
                
                speeds = []
                for i in range(10):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3)
                        
                        start = time.time()
                        sock.connect((ip_address, open_port))
                        
                        # Invia richiesta HTTP se porta web
                        if open_port in [80, 443, 8080]:
                            request = f"GET / HTTP/1.1\r\nHost: {ip_address}\r\nConnection: close\r\n\r\n"
                            sock.send(request.encode())
                            
                            # Ricevi risposta
                            data = b""
                            while True:
                                chunk = sock.recv(8192)
                                if not chunk:
                                    break
                                data += chunk
                            
                            end = time.time()
                            elapsed = end - start
                            
                            if len(data) > 0 and elapsed > 0:
                                speed_mbps = (len(data) * 8) / elapsed / 1000000  # Mbps
                                speed_mbs = len(data) / elapsed / 1024 / 1024  # MB/s
                                speeds.append((speed_mbps, speed_mbs, len(data)))
                        else:
                            # Per altre porte, solo tempo di connessione
                            end = time.time()
                            elapsed = end - start
                            # Stima conservativa
                            est_speed = 10 / elapsed  # Mbps stimato
                            speeds.append((est_speed, est_speed / 8, 1500))
                        
                        sock.close()
                        progress_label.config(text=f"3/3 Test throughput... {i+1}/10")
                    except Exception as e:
                        pass
                
                if speeds:
                    avg_mbps = sum(s[0] for s in speeds) / len(speeds)
                    avg_mbs = sum(s[1] for s in speeds) / len(speeds)
                    total_data = sum(s[2] for s in speeds)
                    max_mbps = max(s[0] for s in speeds)
                    
                    result_text.insert(tk.END, f"  Test completati: {len(speeds)}/10\n")
                    result_text.insert(tk.END, f"  Dati trasferiti: {total_data / 1024:.2f} KB\n\n")
                    result_text.insert(tk.END, f"  RISULTATI:\n")
                    result_text.insert(tk.END, f"  {'─'*56}\n")
                    result_text.insert(tk.END, f"  Velocità Media:  {avg_mbs:10.2f} MB/s  ({avg_mbps:8.2f} Mbps)\n")
                    result_text.insert(tk.END, f"  Velocità Max:    {max(s[1] for s in speeds):10.2f} MB/s  ({max_mbps:8.2f} Mbps)\n")
                    
                    if avg_mbs > 100:
                        result_text.insert(tk.END, f"  In Gigabit:      {avg_mbs / 125:10.2f} Gbps\n")
                else:
                    result_text.insert(tk.END, "  ⚠️  Impossibile misurare throughput\n")
            else:
                result_text.insert(tk.END, "  ⚠️  Nessuna porta aperta - Uso stima da latenza\n\n")
                
                if times:
                    # Stima bandwidth teorico dalla latenza
                    mtu = 1500  # bytes
                    avg_lat_sec = avg_latency / 1000
                    est_bandwidth_mbps = (mtu * 8) / avg_lat_sec / 1000000
                    est_bandwidth_mbs = est_bandwidth_mbps / 8
                    
                    result_text.insert(tk.END, f"  Bandwidth Stimato: {est_bandwidth_mbs:.2f} MB/s ({est_bandwidth_mbps:.2f} Mbps)\n")
                    result_text.insert(tk.END, f"  (Stima basata su latenza e MTU standard)\n")
            
            result_text.insert(tk.END, f"\n{'='*60}\n")
            result_text.insert(tk.END, "✅ TEST COMPLETATO\n")
            result_text.insert(tk.END, f"{'='*60}\n")
            progress_label.config(text="Test completato!", fg="#00ff00")
        
        # Avvia test in thread
        test_thread = threading.Thread(target=run_speed_test, daemon=True)
        test_thread.start()
    
    def open_in_browser(self, ip_address):
        """
        Apre l'IP nel browser (interfaccia web del dispositivo)
        """
        try:
            # Prova prima HTTPS poi HTTP
            urls = [f"http://{ip_address}", f"https://{ip_address}"]
            
            choice = messagebox.askquestion("Apri in Browser", 
                                           f"Aprire {ip_address} in:\\n\\nHTTP (No) o HTTPS (Sì)?")
            
            if choice == 'yes':
                webbrowser.open(urls[1])
            else:
                webbrowser.open(urls[0])
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile aprire il browser:\\n{str(e)}")
    
    def open_ssh_window(self, ip_address):
        """
        Apre finestra per connessione SSH
        """
        ssh_win = tk.Toplevel(self.root)
        ssh_win.title(f"SSH - {ip_address}")
        ssh_win.geometry("700x500")
        ssh_win.configure(bg="#2b2b2b")
        
        tk.Label(ssh_win, text=f"🔐 Connessione SSH", 
                font=('Segoe UI', 16, 'bold'), bg="#2b2b2b", fg="#00ff00").pack(pady=10)
        
        # Frame configurazione
        config_frame = tk.Frame(ssh_win, bg="#1e1e1e")
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(config_frame, text="IP:", bg="#1e1e1e", fg="white", font=('Segoe UI', 10)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ip_entry = ttk.Entry(config_frame, width=30, font=('Consolas', 10))
        ip_entry.insert(0, ip_address)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(config_frame, text="Porta:", bg="#1e1e1e", fg="white", font=('Segoe UI', 10)).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        port_entry = ttk.Entry(config_frame, width=10, font=('Consolas', 10))
        port_entry.insert(0, "22")
        port_entry.grid(row=0, column=3, padx=5, pady=5)
        
        tk.Label(config_frame, text="Username:", bg="#1e1e1e", fg="white", font=('Segoe UI', 10)).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        user_entry = ttk.Entry(config_frame, width=30, font=('Consolas', 10))
        user_entry.insert(0, "root")
        user_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(config_frame, text="Password:", bg="#1e1e1e", fg="white", font=('Segoe UI', 10)).grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        pass_entry = ttk.Entry(config_frame, width=30, show="*", font=('Consolas', 10))
        pass_entry.grid(row=1, column=3, padx=5, pady=5)
        
        # Terminal output
        terminal_text = scrolledtext.ScrolledText(ssh_win, width=80, height=20,
                                                 bg="#000000", fg="#00ff00",
                                                 font=('Consolas', 9))
        terminal_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def connect_ssh():
            ip = ip_entry.get()
            port = port_entry.get()
            username = user_entry.get()
            password = pass_entry.get()
            
            terminal_text.insert(tk.END, f"Connessione a {username}@{ip}:{port}...\\n")
            terminal_text.insert(tk.END, "\\n⚠️  NOTA: Per funzionalità SSH complete, installare: pip install paramiko\\n\\n")
            
            try:
                # Tenta connessione usando client SSH di sistema
                if sys.platform == "win32":
                    # Su Windows, usa ssh.exe se disponibile o PuTTY
                    terminal_text.insert(tk.END, "Apertura client SSH esterno...\\n")
                    subprocess.Popen(f'start cmd /k ssh {username}@{ip} -p {port}', shell=True)
                else:
                    subprocess.Popen(['xterm', '-e', f'ssh {username}@{ip} -p {port}'])
            except Exception as e:
                terminal_text.insert(tk.END, f"\\nErrore: {str(e)}\\n")
                terminal_text.insert(tk.END, "\\nAlternativa: Usa PuTTY o un altro client SSH\\n")
        
        tk.Button(ssh_win, text="🔌 Connetti", command=connect_ssh,
                 bg="#00aa00", fg="white", font=('Segoe UI', 11, 'bold'), padx=20).pack(pady=10)
    
    def save_network_map(self):
        """
        Salva la mappatura di rete in un file JSON
        """
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],
                title="Salva Mappatura di Rete"
            )
            
            if filename:
                # Estrai dati dalla treeview
                devices = []
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    devices.append({
                        'ip': values[0],
                        'hostname': values[1],
                        'netbios': values[2],
                        'mac': values[3],
                        'vendor': values[4],
                        'ports': values[5],
                        'status': values[6]
                    })
                
                # Salva in JSON
                data = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'subnet': self.ip_entry.get(),
                    'total_devices': len(devices),
                    'devices': devices
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                
                self.log(f"Mappatura salvata: {filename}", "SUCCESS")
                messagebox.showinfo("Successo", f"Mappatura di rete salvata in:\\n{filename}")
        except Exception as e:
            self.log(f"Errore salvataggio: {str(e)}", "ERROR")
            messagebox.showerror("Errore", f"Impossibile salvare il file:\\n{str(e)}")
    
    def load_network_map(self):
        """
        Carica una mappatura di rete da file JSON
        """
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],
                title="Carica Mappatura di Rete"
            )
            
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Pulisci treeview
                for item in self.tree.get_children():
                    self.tree.delete(item)
                
                # Carica dispositivi
                for device in data.get('devices', []):
                    self.tree.insert('', tk.END, values=(
                        device.get('ip', 'N/A'),
                        device.get('hostname', 'N/A'),
                        device.get('netbios', 'N/A'),
                        device.get('mac', 'N/A'),
                        device.get('vendor', 'N/A'),
                        device.get('ports', 'N/A'),
                        device.get('status', 'N/A')
                    ))
                
                timestamp = data.get('timestamp', 'N/A')
                subnet = data.get('subnet', 'N/A')
                
                self.log(f"Mappatura caricata: {filename}", "SUCCESS")
                messagebox.showinfo("Successo", 
                                   f"Mappatura caricata:\\n\\nData: {timestamp}\\nSubnet: {subnet}\\nDispositivi: {len(data.get('devices', []))}")
        except Exception as e:
            self.log(f"Errore caricamento: {str(e)}", "ERROR")
            messagebox.showerror("Errore", f"Impossibile caricare il file:\\n{str(e)}")
    
    def export_to_pdf(self):
        """
        Esporta la mappatura di rete in PDF professionale
        """
        try:
            # Verifica se ci sono dispositivi da esportare
            if not self.tree.get_children():
                messagebox.showwarning("Attenzione", "Nessun dispositivo da esportare.\nEsegui prima una scansione.")
                return
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                title="Esporta Mappatura di Rete in PDF"
            )
            
            if not filename:
                return
            
            try:
                from reportlab.lib.pagesizes import A4, landscape
                from reportlab.lib import colors
                from reportlab.lib.units import inch
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib.enums import TA_CENTER, TA_LEFT
                
                # Crea PDF
                doc = SimpleDocTemplate(filename, pagesize=landscape(A4))
                elements = []
                styles = getSampleStyleSheet()
                
                # Stile titolo personalizzato
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=24,
                    textColor=colors.HexColor('#00aa00'),
                    spaceAfter=30,
                    alignment=TA_CENTER
                )
                
                subtitle_style = ParagraphStyle(
                    'CustomSubtitle',
                    parent=styles['Normal'],
                    fontSize=12,
                    textColor=colors.HexColor('#666666'),
                    spaceAfter=20,
                    alignment=TA_CENTER
                )
                
                # Titolo
                elements.append(Paragraph("🔍 MAPPATURA DI RETE - inScanLan", title_style))
                
                # Informazioni scansione
                scan_info = f"""
                Data e Ora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
                Subnet Scansionata: {self.ip_entry.get()}<br/>
                Dispositivi Trovati: {len(self.tree.get_children())}
                """
                elements.append(Paragraph(scan_info, subtitle_style))
                elements.append(Spacer(1, 0.3*inch))
                
                # Prepara dati tabella
                data = [['IP Address', 'Hostname', 'NetBIOS', 'MAC Address', 'Produttore', 'Porte Aperte', 'Status']]
                
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    # Formatta porte aperte per andare a capo se troppo lunghe
                    ports = str(values[5]) if values[5] else 'N/A'
                    if len(ports) > 30:
                        # Spezza ogni 30 caratteri
                        ports = '<br/>'.join([ports[i:i+30] for i in range(0, len(ports), 30)])
                    
                    row = [
                        str(values[0]),  # IP
                        str(values[1])[:20],  # Hostname (max 20 char)
                        str(values[2])[:15],  # NetBIOS
                        str(values[3]),  # MAC
                        str(values[4])[:20],  # Vendor
                        Paragraph(ports, styles['Normal']),  # Porte
                        str(values[6])  # Status
                    ]
                    data.append(row)
                
                # Crea tabella
                table = Table(data, colWidths=[1.2*inch, 1.3*inch, 1*inch, 1.2*inch, 1.3*inch, 1.5*inch, 0.8*inch])
                
                # Stile tabella
                table.setStyle(TableStyle([
                    # Header
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00aa00')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    
                    # Dati
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    
                    # Griglia
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    
                    # Alternare colori righe
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ]))
                
                elements.append(table)
                
                # Aggiungi statistiche
                elements.append(Spacer(1, 0.5*inch))
                
                # Calcola statistiche
                online_count = sum(1 for item in self.tree.get_children() 
                                  if self.tree.item(item)['values'][6] == 'Online')
                
                # Conta porte più comuni
                port_count = {}
                for item in self.tree.get_children():
                    ports_str = str(self.tree.item(item)['values'][5])
                    if ports_str and ports_str != 'N/A' and ports_str != 'Nessuna':
                        ports = ports_str.split(', ')
                        for port in ports:
                            port_count[port] = port_count.get(port, 0) + 1
                
                top_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:5]
                
                stats_text = f"""
                <b>STATISTICHE SCANSIONE</b><br/>
                <br/>
                Dispositivi Online: {online_count}<br/>
                Dispositivi Offline: {len(self.tree.get_children()) - online_count}<br/>
                <br/>
                """
                
                if top_ports:
                    stats_text += "<b>Porte più comuni:</b><br/>"
                    for port, count in top_ports:
                        port_name = {
                            '21': 'FTP', '22': 'SSH', '23': 'Telnet', '80': 'HTTP',
                            '443': 'HTTPS', '445': 'SMB', '3389': 'RDP', '8080': 'HTTP-ALT'
                        }.get(port, 'Unknown')
                        stats_text += f"  • Porta {port} ({port_name}): {count} dispositivi<br/>"
                
                elements.append(Paragraph(stats_text, styles['Normal']))
                
                # Footer
                elements.append(Spacer(1, 0.3*inch))
                footer_style = ParagraphStyle(
                    'Footer',
                    parent=styles['Normal'],
                    fontSize=8,
                    textColor=colors.grey,
                    alignment=TA_CENTER
                )
                elements.append(Paragraph(
                    f"Generato da inScanLan Network Scanner - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
                    footer_style
                ))
                
                # Genera PDF
                doc.build(elements)
                
                self.log(f"PDF esportato: {filename}", "SUCCESS")
                messagebox.showinfo("Successo", 
                    f"✅ PDF generato con successo!\n\nFile: {filename}\n\nDispositivi: {len(self.tree.get_children())}")
                
            except ImportError:
                # Se reportlab non è installato, usa fallback HTML->PDF o testo
                self.log("ReportLab non installato, uso fallback", "WARNING")
                self.export_to_pdf_fallback(filename)
                
        except Exception as e:
            self.log(f"Errore esportazione PDF: {str(e)}", "ERROR")
            messagebox.showerror("Errore", f"Impossibile esportare PDF:\n{str(e)}")
    
    def export_to_pdf_fallback(self, filename):
        """
        Fallback per PDF senza reportlab - genera HTML stampabile
        """
        try:
            html_file = filename.replace('.pdf', '.html')
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Mappatura di Rete - inScanLan</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #00aa00; text-align: center; }
        .info { text-align: center; color: #666; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #00aa00; color: white; padding: 12px; text-align: left; }
        td { padding: 8px; border: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .stats { margin-top: 30px; padding: 15px; background: #f9f9f9; border-left: 4px solid #00aa00; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 30px; }
        @media print {
            body { margin: 0; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <h1>🔍 MAPPATURA DI RETE - inScanLan</h1>
    <div class="info">
        <p><strong>Data e Ora:</strong> """ + datetime.now().strftime('%d/%m/%Y %H:%M:%S') + """</p>
        <p><strong>Subnet Scansionata:</strong> """ + self.ip_entry.get() + """</p>
        <p><strong>Dispositivi Trovati:</strong> """ + str(len(self.tree.get_children())) + """</p>
    </div>
    
    <button class="no-print" onclick="window.print()" style="padding: 10px 20px; background: #00aa00; color: white; border: none; cursor: pointer; font-size: 16px;">🖨️ Stampa PDF</button>
    
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>NetBIOS</th>
                <th>MAC Address</th>
                <th>Produttore</th>
                <th>Porte Aperte</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
""")
                
                for item in self.tree.get_children():
                    values = self.tree.item(item)['values']
                    f.write(f"""            <tr>
                <td>{values[0]}</td>
                <td>{values[1]}</td>
                <td>{values[2]}</td>
                <td>{values[3]}</td>
                <td>{values[4]}</td>
                <td>{values[5]}</td>
                <td>{values[6]}</td>
            </tr>
""")
                
                f.write("""        </tbody>
    </table>
    
    <div class="stats">
        <h3>Statistiche</h3>
        <p>Per generare PDF professionali, installa ReportLab:</p>
        <code>pip install reportlab</code>
    </div>
    
    <div class="footer">
        Generato da inScanLan Network Scanner - """ + datetime.now().strftime('%d/%m/%Y %H:%M:%S') + """
    </div>
</body>
</html>""")
            
            # Apri HTML nel browser
            import webbrowser
            webbrowser.open('file://' + os.path.abspath(html_file))
            
            messagebox.showinfo("HTML Generato", 
                f"File HTML creato: {html_file}\n\n"
                "Usa 'Stampa > Salva come PDF' dal browser.\n\n"
                "Per PDF automatici installa:\npip install reportlab")
            
        except Exception as e:
            self.log(f"Errore fallback: {str(e)}", "ERROR")
        
    def stop_scan(self):
        self.scanner.stop_scan()
        self.log("Interruzione scansione richiesta...", "WARNING")
        self.status_bar.config(text="Scansione interrotta")
    
    def open_wifi_scanner(self):
        """
        Apre finestra per scansione reti WiFi
        """
        wifi_win = tk.Toplevel(self.root)
        wifi_win.title("Scanner Reti WiFi")
        wifi_win.geometry("1100x750")
        wifi_win.configure(bg="#2b2b2b")
        
        # Header
        header_frame = tk.Frame(wifi_win, bg="#1e1e1e", height=60)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text="📶 Scanner Reti WiFi - Analisi Bande Frequenza", 
                font=('Segoe UI', 18, 'bold'), bg="#1e1e1e", fg="#9900cc").pack(pady=10)
        
        # Toolbar
        toolbar = tk.Frame(wifi_win, bg="#2b2b2b")
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        scan_active = {'running': False}
        
        def get_frequency_band(channel):
            """Determina la banda di frequenza dal numero di canale"""
            try:
                ch = int(channel)
                if 1 <= ch <= 14:
                    return "2.4 GHz", "#00aaff"
                elif 32 <= ch <= 68:
                    return "5 GHz (Low)", "#ff8800"
                elif 96 <= ch <= 144:
                    return "5 GHz (Mid)", "#ff6600"
                elif 149 <= ch <= 177:
                    return "5 GHz (High)", "#ff4400"
                elif ch > 200:  # WiFi 6E
                    return "6 GHz", "#aa00ff"
                else:
                    return "Unknown", "#888888"
            except:
                return "N/A", "#888888"
        
        def scan_wifi_networks():
            """Scansiona le reti WiFi disponibili"""
            if scan_active['running']:
                return
                
            scan_active['running'] = True
            scan_btn.config(state=tk.DISABLED)
            status_label.config(text="🔄 Scansione in corso...")
            
            # Pulisci treeview
            for item in tree.get_children():
                tree.delete(item)
            
            def run_scan():
                try:
                    # Usa netsh per Windows
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                        capture_output=True,
                        text=True,
                        encoding='cp437',
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=10
                    )
                    
                    if result.returncode != 0:
                        wifi_win.after(0, lambda: messagebox.showerror("Errore", 
                            "Impossibile scansionare reti WiFi.\nVerifica che l'adattatore WiFi sia attivo."))
                        return
                    
                    # Parse output
                    networks = []
                    current_network = {}
                    
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        
                        if line.startswith('SSID'):
                            if current_network and 'ssid' in current_network:
                                networks.append(current_network)
                            # Estrai SSID
                            ssid_match = re.search(r'SSID \d+ : (.+)', line)
                            if ssid_match:
                                current_network = {'ssid': ssid_match.group(1).strip()}
                        
                        elif 'Network type' in line or 'Tipo di rete' in line:
                            match = re.search(r': (.+)', line)
                            if match:
                                current_network['type'] = match.group(1).strip()
                        
                        elif 'Authentication' in line or 'Autenticazione' in line:
                            match = re.search(r': (.+)', line)
                            if match:
                                current_network['auth'] = match.group(1).strip()
                        
                        elif 'Encryption' in line or 'Crittografia' in line:
                            match = re.search(r': (.+)', line)
                            if match:
                                current_network['encryption'] = match.group(1).strip()
                        
                        elif 'BSSID' in line:
                            match = re.search(r'BSSID \d+ +: (.+)', line)
                            if match:
                                current_network['bssid'] = match.group(1).strip()
                        
                        elif 'Signal' in line or 'Segnale' in line:
                            match = re.search(r': (\d+)%', line)
                            if match:
                                signal_percent = int(match.group(1))
                                current_network['signal_percent'] = signal_percent
                                # Converti percentuale in dBm approssimativo
                                # Formula: dBm = (Signal% / 2) - 100
                                dbm = (signal_percent / 2) - 100
                                current_network['signal_dbm'] = int(dbm)
                        
                        elif 'Channel' in line or 'Canale' in line:
                            match = re.search(r': (\d+)', line)
                            if match:
                                current_network['channel'] = match.group(1).strip()
                    
                    # Aggiungi ultima rete
                    if current_network and 'ssid' in current_network:
                        networks.append(current_network)
                    
                    # Raggruppa per SSID e prendi il segnale più forte
                    unique_networks = {}
                    for net in networks:
                        ssid = net.get('ssid', '')
                        if ssid and ssid != '':
                            signal = net.get('signal_percent', 0)
                            if ssid not in unique_networks or signal > unique_networks[ssid].get('signal_percent', 0):
                                unique_networks[ssid] = net
                    
                    # Ordina per potenza segnale
                    sorted_networks = sorted(unique_networks.values(), 
                                            key=lambda x: x.get('signal_percent', 0), 
                                            reverse=True)
                    
                    # Conta reti per banda
                    band_counts = {'2.4 GHz': 0, '5 GHz (Low)': 0, '5 GHz (Mid)': 0, '5 GHz (High)': 0, '6 GHz': 0}
                    
                    # Aggiorna UI
                    def update_ui():
                        for net in sorted_networks:
                            ssid = net.get('ssid', 'N/A')
                            signal_percent = net.get('signal_percent', 0)
                            signal_dbm = net.get('signal_dbm', -100)
                            channel = net.get('channel', 'N/A')
                            auth = net.get('auth', 'N/A')
                            encryption = net.get('encryption', 'N/A')
                            bssid = net.get('bssid', 'N/A')
                            
                            # Determina banda frequenza
                            band, band_color = get_frequency_band(channel)
                            if band in band_counts:
                                band_counts[band] += 1
                            
                            # Determina qualità segnale
                            if signal_percent >= 80:
                                quality = "Eccellente"
                                quality_color = "#00ff00"
                            elif signal_percent >= 60:
                                quality = "Buono"
                                quality_color = "#88ff00"
                            elif signal_percent >= 40:
                                quality = "Discreto"
                                quality_color = "#ffaa00"
                            else:
                                quality = "Debole"
                                quality_color = "#ff6666"
                                color = "#ff0000"
                            
                            # Barra segnale
                            bars = "█" * (signal_percent // 10)
                            
                            security = f"{auth}/{encryption}" if auth != 'N/A' else 'N/A'
                            
                            # Filtra per banda se selezionato
                            filter_band = band_filter.get()
                            if filter_band != "Tutte" and band != filter_band:
                                continue
                            
                            item = tree.insert('', tk.END, values=(
                                ssid,
                                band,
                                channel,
                                f"{signal_percent}%",
                                f"{signal_dbm} dBm",
                                bars,
                                quality,
                                security,
                                bssid
                            ))
                            
                            # Colora la riga in base alla banda e qualità
                            tree.item(item, tags=(quality, band))
                        
                        # Configura colori tag per qualità
                        tree.tag_configure("Eccellente", foreground="#00ff00")
                        tree.tag_configure("Buono", foreground="#88ff00")
                        tree.tag_configure("Discreto", foreground="#ffaa00")
                        tree.tag_configure("Debole", foreground="#ff6666")
                        
                        # Aggiorna statistiche bande
                        total_networks = len(sorted_networks)
                        stats_text = f"✅ Trovate {total_networks} reti | "
                        stats_text += f"2.4GHz: {band_counts['2.4 GHz']} | "
                        total_5ghz = band_counts['5 GHz (Low)'] + band_counts['5 GHz (Mid)'] + band_counts['5 GHz (High)']
                        stats_text += f"5GHz: {total_5ghz} | "
                        stats_text += f"6GHz: {band_counts['6 GHz']}"
                        
                        status_label.config(text=stats_text)
                        scan_btn.config(state=tk.NORMAL)
                        scan_active['running'] = False
                    
                    wifi_win.after(0, update_ui)
                    
                except subprocess.TimeoutExpired:
                    wifi_win.after(0, lambda: status_label.config(text="❌ Timeout scansione"))
                    wifi_win.after(0, lambda: scan_btn.config(state=tk.NORMAL))
                    scan_active['running'] = False
                except Exception as e:
                    wifi_win.after(0, lambda: status_label.config(text=f"❌ Errore: {str(e)}"))
                    wifi_win.after(0, lambda: scan_btn.config(state=tk.NORMAL))
                    scan_active['running'] = False
            
            # Esegui scan in thread
            threading.Thread(target=run_scan, daemon=True).start()
        
        scan_btn = tk.Button(toolbar, text="🔄 Scansiona", command=scan_wifi_networks,
                            bg="#9900cc", fg="white", font=('Segoe UI', 11, 'bold'), padx=20)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Filtro banda
        tk.Label(toolbar, text="Filtra:", bg="#2b2b2b", fg="white").pack(side=tk.LEFT, padx=(20, 5))
        band_filter = ttk.Combobox(toolbar, width=12, state='readonly',
                                   values=["Tutte", "2.4 GHz", "5 GHz (Low)", "5 GHz (Mid)", "5 GHz (High)", "6 GHz"])
        band_filter.set("Tutte")
        band_filter.pack(side=tk.LEFT, padx=5)
        band_filter.bind('<<ComboboxSelected>>', lambda e: scan_wifi_networks())
        
        # Pulsante Estrai Password WiFi
        extract_pwd_btn = tk.Button(toolbar, text="🔑 Estrai Password WiFi Salvate",
                                   command=self.extract_wifi_passwords,
                                   bg="#cc6600", fg="white", font=('Segoe UI', 11, 'bold'), padx=20)
        extract_pwd_btn.pack(side=tk.LEFT, padx=20)
        
        auto_refresh_var = tk.BooleanVar(value=False)
        
        def toggle_auto_refresh():
            if auto_refresh_var.get():
                auto_scan()
        
        def auto_scan():
            if auto_refresh_var.get():
                scan_wifi_networks()
                wifi_win.after(10000, auto_scan)  # Ogni 10 secondi
        
        ttk.Checkbutton(toolbar, text="Auto-refresh (10s)", variable=auto_refresh_var,
                       command=toggle_auto_refresh).pack(side=tk.LEFT, padx=20)
        
        status_label = tk.Label(toolbar, text="Pronto", bg="#2b2b2b", fg="#00aaff",
                               font=('Segoe UI', 10))
        status_label.pack(side=tk.LEFT, padx=20)
        
        # Treeview per reti WiFi
        columns = ('SSID', 'Banda', 'Canale', 'Segnale %', 'Segnale dBm', 'Barre', 'Qualità', 'Sicurezza', 'BSSID')
        tree = ttk.Treeview(wifi_win, columns=columns, show='headings', height=20)
        
        # Configura colonne
        tree.heading('SSID', text='Nome Rete (SSID)')
        tree.heading('Banda', text='Banda Frequenza')
        tree.heading('Canale', text='Ch')
        tree.heading('Segnale %', text='%')
        tree.heading('Segnale dBm', text='dBm')
        tree.heading('Barre', text='Segnale')
        tree.heading('Qualità', text='Qualità')
        tree.heading('Sicurezza', text='Sicurezza')
        tree.heading('BSSID', text='MAC Access Point')
        
        tree.column('SSID', width=180)
        tree.column('Banda', width=110)
        tree.column('Canale', width=40)
        tree.column('Segnale %', width=50)
        tree.column('Segnale dBm', width=70)
        tree.column('Barre', width=100)
        tree.column('Qualità', width=90)
        tree.column('Sicurezza', width=130)
        tree.column('BSSID', width=130)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(wifi_win, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10, padx=(0, 10))
        
        # Info box
        info_frame = tk.Frame(wifi_win, bg="#1e1e1e", relief=tk.RIDGE, borderwidth=2)
        info_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        info_text = """
📊 Legenda Bande Frequenza e Potenza Segnale:
  🔵 2.4 GHz (Canali 1-14): Maggiore copertura, velocità inferiore, più interferenze
  🟠 5 GHz (Canali 36-177): Velocità superiore, copertura ridotta, meno interferenze
  🟣 6 GHz (WiFi 6E): Nuova banda ad alte prestazioni (richiede dispositivi compatibili)
  
  Potenza Segnale: -30 a -50 dBm (Eccellente) | -50 a -70 dBm (Buono) | -70 a -90 dBm (Discreto/Debole)
        """
        
        tk.Label(info_frame, text=info_text, bg="#1e1e1e", fg="#00aaff",
                font=('Consolas', 8), justify=tk.LEFT).pack(padx=10, pady=5)
        
        # Avvia prima scansione automaticamente
        wifi_win.after(500, scan_wifi_networks)

def main():
    root = tk.Tk()
    app = InScanLanApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
