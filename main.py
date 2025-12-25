"""
inScanLan - Network Scanner
Applicazione Windows per la scansione completa della rete locale
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import os
import sys
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
        
        # Header
        header_label = tk.Label(main_frame, text="🔍 inScanLan - Network Scanner", 
                               font=('Segoe UI', 20, 'bold'), bg="#2b2b2b", fg="#00ff00")
        header_label.grid(row=0, column=0, pady=10)
        
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
        
        # Notebook per tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=3, column=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Tab Log
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="📋 Log Real-Time")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=100, height=25, 
                                                  bg="#1e1e1e", fg="#00ff00",
                                                  font=('Consolas', 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tab Risultati
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
        
    def stop_scan(self):
        self.scanner.stop_scan()
        self.log("Interruzione scansione richiesta...", "WARNING")
        self.status_bar.config(text="Scansione interrotta")

def main():
    root = tk.Tk()
    app = InScanLanApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
