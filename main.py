"""
inScanLan - Android Version
Network Scanner per dispositivi mobili
"""
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock
from kivy.core.window import Window
import socket
import subprocess
import threading
import ipaddress
import re

Window.clearcolor = (0.17, 0.17, 0.17, 1)


class NetworkScannerApp(App):
    def build(self):
        self.title = 'inScanLan'
        
        # Layout principale
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Header
        header = Label(
            text='[b]inScanLan[/b]\nNetwork Scanner',
            markup=True,
            size_hint=(1, 0.15),
            font_size='24sp',
            color=(0, 1, 0, 1)
        )
        layout.add_widget(header)
        
        # Input subnet
        input_layout = BoxLayout(size_hint=(1, 0.1), spacing=5)
        input_layout.add_widget(Label(text='Subnet:', size_hint=(0.3, 1)))
        self.subnet_input = TextInput(
            text='192.168.1.0/24',
            size_hint=(0.5, 1),
            multiline=False
        )
        input_layout.add_widget(self.subnet_input)
        
        self.scan_btn = Button(
            text='Scan',
            size_hint=(0.2, 1),
            background_color=(0, 0.6, 0, 1)
        )
        self.scan_btn.bind(on_press=self.start_scan)
        input_layout.add_widget(self.scan_btn)
        layout.add_widget(input_layout)
        
        # Risultati
        self.results_label = Label(
            text='Premi Scan per iniziare...',
            size_hint=(1, None),
            height=50
        )
        layout.add_widget(self.results_label)
        
        # ScrollView per output
        scroll = ScrollView(size_hint=(1, 0.65))
        self.output_text = Label(
            text='',
            size_hint_y=None,
            markup=True,
            color=(0, 1, 0, 1)
        )
        self.output_text.bind(texture_size=self.output_text.setter('size'))
        scroll.add_widget(self.output_text)
        layout.add_widget(scroll)
        
        # Auto-detect subnet
        Clock.schedule_once(self.auto_detect_subnet, 0.5)
        
        return layout
    
    def auto_detect_subnet(self, dt):
        """Rileva automaticamente la subnet locale"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Estrai subnet (es: 192.168.1.50 -> 192.168.1.0/24)
            parts = local_ip.split('.')
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            self.subnet_input.text = subnet
            
            self.add_output(f"[color=00ffff]IP locale rilevato: {local_ip}[/color]")
            self.add_output(f"[color=00ffff]Subnet: {subnet}[/color]")
        except Exception as e:
            self.add_output(f"[color=ff0000]Errore rilevamento IP: {str(e)}[/color]")
    
    def start_scan(self, instance):
        """Avvia la scansione in un thread separato"""
        subnet = self.subnet_input.text.strip()
        
        if not subnet:
            self.add_output("[color=ff0000]Inserisci una subnet valida![/color]")
            return
        
        self.scan_btn.disabled = True
        self.scan_btn.text = 'Scanning...'
        self.output_text.text = ''
        self.results_label.text = 'Scansione in corso...'
        
        thread = threading.Thread(target=self.run_scan, args=(subnet,))
        thread.daemon = True
        thread.start()
    
    def run_scan(self, subnet):
        """Esegue la scansione di rete"""
        devices_found = 0
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_hosts = sum(1 for _ in network.hosts())
            
            self.add_output(f"[b]Scansione di {subnet}[/b]")
            self.add_output(f"Host da scansionare: {total_hosts}\n")
            
            for ip in network.hosts():
                ip_str = str(ip)
                
                # Ping veloce
                if self.ping_host(ip_str):
                    devices_found += 1
                    hostname = self.get_hostname(ip_str)
                    mac = self.get_mac_address(ip_str)
                    
                    output = f"[color=00ff00]✓[/color] {ip_str}"
                    if hostname:
                        output += f" - {hostname}"
                    if mac:
                        output += f" [{mac}]"
                    
                    self.add_output(output)
            
            self.add_output(f"\n[b][color=00ffff]Scansione completata![/color][/b]")
            self.add_output(f"[color=00ffff]Dispositivi trovati: {devices_found}[/color]")
            
            Clock.schedule_once(lambda dt: self.scan_complete(devices_found), 0)
            
        except Exception as e:
            self.add_output(f"[color=ff0000]Errore: {str(e)}[/color]")
            Clock.schedule_once(lambda dt: self.scan_complete(0), 0)
    
    def scan_complete(self, count):
        """Callback al termine della scansione"""
        self.scan_btn.disabled = False
        self.scan_btn.text = 'Scan'
        self.results_label.text = f'Dispositivi trovati: {count}'
    
    def ping_host(self, ip):
        """Esegue ping verso un host"""
        try:
            # Android usa ping Unix-like
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Ottiene il nome host"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def get_mac_address(self, ip):
        """Ottiene il MAC address (limitato su Android)"""
        try:
            # Su Android questo potrebbe non funzionare senza root
            result = subprocess.run(
                ['ip', 'neigh', 'show', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=1,
                text=True
            )
            
            if result.returncode == 0:
                match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result.stdout)
                if match:
                    return match.group(0)
        except:
            pass
        
        return None
    
    def add_output(self, text):
        """Aggiunge testo all'output"""
        def update(dt):
            current = self.output_text.text
            self.output_text.text = current + text + '\n'
        
        Clock.schedule_once(update, 0)


if __name__ == '__main__':
    NetworkScannerApp().run()
