"""
Network Scanner Module
Modulo per la scansione di rete con supporto per ping, port scan, NetBIOS, ARP
"""

import socket
import subprocess
import ipaddress
import threading
import time
import re
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self):
        self.stop_flag = False
        
    def stop_scan(self):
        self.stop_flag = True
        
    @staticmethod
    def get_local_network():
        """
        Rileva automaticamente la rete locale del PC
        Ritorna una tupla (ip_locale, subnet_cidr)
        """
        try:
            # Ottiene l'IP locale connettendosi a un server esterno (senza inviare dati)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            try:
                # Non invia dati, usa solo per ottenere l'interfaccia di rete locale
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
                
            # Ottiene la subnet mask via ipconfig (Windows)
            if platform.system() == 'Windows':
                output = subprocess.run(
                    ['ipconfig'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    encoding='cp437',
                    timeout=5
                )
                
                if output.returncode == 0:
                    lines = output.stdout.split('\n')
                    found_ip = False
                    
                    for i, line in enumerate(lines):
                        # Cerca la riga con l'IP locale
                        if local_ip in line:
                            found_ip = True
                        # Cerca la subnet mask nelle righe successive
                        if found_ip and 'Subnet Mask' in line or 'Maschera subnet' in line:
                            mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if mask_match:
                                subnet_mask = mask_match.group(1)
                                # Converte subnet mask in CIDR
                                cidr = NetworkScanner._mask_to_cidr(subnet_mask)
                                network = ipaddress.ip_network(f'{local_ip}/{cidr}', strict=False)
                                return local_ip, str(network)
                    
            # Fallback: assume /24 (classe C) come default
            network = ipaddress.ip_network(f'{local_ip}/24', strict=False)
            return local_ip, str(network)
            
        except Exception as e:
            # Fallback in caso di errore
            return '192.168.1.1', '192.168.1.0/24'
            
    @staticmethod
    def _mask_to_cidr(subnet_mask):
        """
        Converte subnet mask in notazione CIDR
        Es: 255.255.255.0 -> 24
        """
        try:
            return sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
        except:
            return 24  # Default
        
    def scan_network(self, ip_range, ports, options, log_callback):
        """
        Scansione completa della rete
        """
        self.stop_flag = False
        results = []
        
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_hosts = network.num_addresses
            log_callback(f"Scansione di {total_hosts} indirizzi IP...", "INFO")
            
            # Scansione parallela degli host
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {}
                
                for ip in network.hosts():
                    if self.stop_flag:
                        break
                    future = executor.submit(self.scan_host, str(ip), ports, options, log_callback)
                    futures[future] = str(ip)
                    
                for future in as_completed(futures):
                    if self.stop_flag:
                        break
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            status = "✅" if result['status'] == 'Online' else "❌"
                            log_callback(f"{status} {ip} - {result.get('hostname', 'N/A')}", "SUCCESS")
                    except Exception as e:
                        log_callback(f"Errore scansione {ip}: {str(e)}", "ERROR")
                        
        except ValueError as e:
            log_callback(f"Range IP non valido: {str(e)}", "ERROR")
            
        return results
        
    def scan_host(self, ip, ports, options, log_callback):
        """
        Scansione di un singolo host
        """
        result = {
            'ip': ip,
            'hostname': 'N/A',
            'netbios': 'N/A',
            'mac': 'N/A',
            'vendor': 'N/A',
            'open_ports': [],
            'status': 'Offline'
        }
        
        # Ping scan
        if options.get('ping', True):
            if not self.ping_host(ip):
                return None  # Host non raggiungibile
            result['status'] = 'Online'
            
        # Risoluzione hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result['hostname'] = hostname
        except:
            pass
            
        # NetBIOS scan
        if options.get('netbios', True):
            netbios_name = self.get_netbios_name(ip)
            if netbios_name:
                result['netbios'] = netbios_name
                
        # ARP scan
        if options.get('arp', True):
            mac, vendor = self.get_mac_address(ip)
            if mac:
                result['mac'] = mac
                result['vendor'] = vendor
                
        # Port scan
        if options.get('port_scan', True) and ports:
            open_ports = self.scan_ports(ip, ports)
            result['open_ports'] = open_ports
            
        return result
        
    def ping_host(self, ip, timeout=1):
        """
        Ping di un host
        """
        try:
            # Windows usa -n per count, -w per timeout in ms
            output = subprocess.run(
                ['ping', '-n', '1', '-w', str(timeout * 1000), ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return output.returncode == 0
        except:
            return False
            
    def scan_ports(self, ip, ports, timeout=0.5):
        """
        Scansione delle porte
        """
        open_ports = []
        
        for port in ports:
            if self.stop_flag:
                break
            if self.check_port(ip, port, timeout):
                open_ports.append(port)
                
        return open_ports
        
    def check_port(self, ip, port, timeout=0.5):
        """
        Verifica se una porta è aperta
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
            
    def get_netbios_name(self, ip):
        """
        Ottiene il nome NetBIOS di un host
        """
        try:
            output = subprocess.run(
                ['nbtstat', '-A', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
                encoding='cp437'  # Encoding Windows
            )
            
            if output.returncode == 0:
                lines = output.stdout.split('\n')
                for line in lines:
                    # Cerca il nome NetBIOS (primo nome nella tabella)
                    if '<00>' in line and 'UNIQUE' in line:
                        match = re.search(r'(\S+)\s+<00>\s+UNIQUE', line)
                        if match:
                            return match.group(1).strip()
        except:
            pass
        return None
        
    def get_mac_address(self, ip):
        """
        Ottiene indirizzo MAC e produttore via ARP
        """
        try:
            # Prima fa ping per popolare la cache ARP
            self.ping_host(ip, timeout=1)
            time.sleep(0.1)
            
            output = subprocess.run(
                ['arp', '-a', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW,
                encoding='cp437'
            )
            
            if output.returncode == 0:
                # Cerca pattern MAC address
                mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})'
                match = re.search(mac_pattern, output.stdout)
                if match:
                    mac = match.group(0).replace('-', ':').upper()
                    vendor = self.get_vendor_from_mac(mac)
                    return mac, vendor
        except:
            pass
        return None, None
        
    def get_vendor_from_mac(self, mac):
        """
        Identifica il produttore dal MAC address (primi 3 ottetti)
        Database semplificato dei vendor più comuni
        """
        mac_prefix = mac[:8].upper()
        
        vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
            '00:1C:42': 'Parallels',
            '08:00:27': 'VirtualBox',
            '00:15:5D': 'Microsoft Hyper-V',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:1B:63': 'Apple',
            'AC:DE:48': 'Apple',
            '00:03:93': 'Apple',
            '00:50:F2': 'Microsoft',
            '00:0D:3A': 'Microsoft',
            '28:18:78': 'Dell',
            '00:14:22': 'Dell',
            'D4:BE:D9': 'Dell',
            '00:1E:C9': 'Cisco',
            '00:0A:41': 'Cisco',
            '00:23:04': 'Cisco',
            '00:1B:D5': 'Hewlett Packard',
            '00:1F:29': 'Hewlett Packard',
            '00:25:B3': 'Hewlett Packard',
            '00:50:BA': 'D-Link',
            '00:17:9A': 'D-Link',
            '00:1C:F0': 'D-Link',
            '00:E0:4C': 'Realtek',
            '00:19:DB': 'Realtek',
            '52:54:00': 'QEMU/KVM',
            '00:16:3E': 'Xen',
            '00:21:5D': 'Samsung',
            '00:1D:25': 'Samsung',
            'C8:3A:35': 'Tenda',
            'E8:94:F6': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            '00:27:22': 'TP-Link',
            '00:1F:3F': 'Netgear',
            'A0:63:91': 'Netgear',
            '00:26:F2': 'Netgear',
            '00:24:01': 'Xiaomi',
            '34:CE:00': 'Xiaomi',
            '64:09:80': 'Xiaomi',
        }
        
        return vendors.get(mac_prefix, 'Unknown')
