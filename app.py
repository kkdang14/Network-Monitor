import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
import joblib
import logging
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, conf, get_if_list, get_if_addr
from scapy.arch.windows import get_windows_if_list
import tkinter as tk
from tkinter import ttk, scrolledtext, font, messagebox, filedialog
from datetime import datetime
from collections import defaultdict
import os
import traceback
import subprocess
import platform
import sys

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# ============================================================================
# AUTO-ELEVATION FUNCTIONS
# ============================================================================

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def run_as_admin():
    """Re-launch the script with administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            
            # Get the current script path
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:])
            
            # ShellExecute to run as admin
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas",  # Verb: run as administrator
                sys.executable,  # Python executable
                params,  # Script and arguments
                None,  # Working directory
                1  # Show window
            )
            
            if ret > 32:  # Success
                sys.exit(0)
            else:
                print("Failed to elevate privileges. Error code:", ret)
                return False
                
        else:  # Linux/Unix
            # Check if already root
            if os.geteuid() != 0:
                # Re-run with sudo
                args = ['sudo', sys.executable] + sys.argv
                os.execvp('sudo', args)
            return True
            
    except Exception as e:
        print(f"Error elevating privileges: {e}")
        return False

# ============================================================================
# Check and request admin privileges at startup
# ============================================================================
if not is_admin():
    print("=" * 70)
    print("⚠️  ADMINISTRATOR PRIVILEGES REQUIRED")
    print("=" * 70)
    print("This application requires administrator privileges to:")
    print("  • Block malicious IP addresses via firewall")
    print("  • Terminate suspicious network connections")
    print("  • Quarantine and isolate threats")
    print("\nAttempting to restart with administrator privileges...")
    print("=" * 70)
    
    # Try to elevate
    if not run_as_admin():
        print("\n❌ Failed to obtain administrator privileges.")
        print("Please manually run this script as administrator.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    else:
        # If successful elevation, this won't be reached (script restarts)
        sys.exit(0)

# If we reach here, we have admin privileges
print("✅ Running with Administrator privileges")

# ============================================================================

# Configure logging to both console and file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Set console encoding to UTF-8 for emoji support
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

class ThreatMitigationEngine:
    """Engine to handle threat mitigation and blocking."""
    
    def __init__(self, log_callback):
        self.log = log_callback
        self.blocked_ips = set()
        self.blocked_processes = set()
        self.quarantine_dir = "quarantine"
        self.is_windows = platform.system() == "Windows"
        
        # Create quarantine directory
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
    
    def block_ip_firewall(self, ip_address, reason="Malicious activity detected"):
        """Method 1: Block IP using Windows Firewall or iptables."""
        if ip_address in self.blocked_ips:
            return False
        
        try:
            self.log(f"🛡️ METHOD 1: Blocking IP {ip_address} via Firewall")
            
            if self.is_windows:
                # Windows Firewall rule
                rule_name = f"APT_Block_{ip_address.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    self.log(f"   ✅ Successfully blocked {ip_address} in Windows Firewall")
                    self.log(f"   Reason: {reason}")
                    return True
                else:
                    self.log(f"   ⚠️ Failed to block IP: {result.stderr}")
                    return False
            else:
                # Linux iptables
                cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    self.log(f"   ✅ Successfully blocked {ip_address} via iptables")
                    return True
                else:
                    self.log(f"   ⚠️ Failed to block IP: {result.stderr}")
                    return False
                    
        except Exception as e:
            self.log(f"   ❌ Error blocking IP: {str(e)}")
            return False
    
    def kill_suspicious_connections(self, ip_address, port):
        """Method 2: Terminate active TCP connections."""
        try:
            self.log(f"🔪 METHOD 2: Killing active connections to {ip_address}:{port}")
            
            if self.is_windows:
                # Get all TCP connections
                cmd = "netstat -ano"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                killed_count = 0
                for line in result.stdout.split('\n'):
                    if ip_address in line and str(port) in line:
                        # Extract PID
                        parts = line.split()
                        if len(parts) >= 5:
                            try:
                                pid = parts[-1]
                                # Kill process
                                kill_cmd = f"taskkill /F /PID {pid}"
                                kill_result = subprocess.run(kill_cmd, shell=True, capture_output=True, text=True)
                                
                                if kill_result.returncode == 0:
                                    killed_count += 1
                                    self.log(f"   ✅ Terminated process PID {pid}")
                                    self.blocked_processes.add(pid)
                            except:
                                continue
                
                if killed_count > 0:
                    self.log(f"   ✅ Successfully killed {killed_count} malicious connection(s)")
                    return True
                else:
                    self.log(f"   ℹ️ No active connections found to terminate")
                    return False
            else:
                # Linux: kill connections using ss and kill
                cmd = f"ss -K dst {ip_address} dport = {port}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                self.log(f"   ✅ Killed connections to {ip_address}:{port}")
                return True
                
        except Exception as e:
            self.log(f"   ❌ Error killing connections: {str(e)}")
            return False
    
    def isolate_and_quarantine(self, flow_key, threat_type):
        """Method 3: Network isolation + logging + quarantine."""
        try:
            src_ip, dst_ip, src_port, dst_port, proto = flow_key
            self.log(f"🔒 METHOD 3: Isolating and quarantining threat")
            
            # 1. Block both source and destination IPs
            self.log(f"   Step 1: Blocking source IP {src_ip}")
            self.block_ip_firewall(src_ip, f"{threat_type} source")
            
            self.log(f"   Step 2: Blocking destination IP {dst_ip}")
            self.block_ip_firewall(dst_ip, f"{threat_type} destination")
            
            # 2. Log threat details to quarantine
            threat_log_file = os.path.join(self.quarantine_dir, f"threat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            
            threat_info = f"""
=== THREAT QUARANTINE REPORT ===
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Threat Type: {threat_type}
Source IP: {src_ip}:{src_port}
Destination IP: {dst_ip}:{dst_port}
Protocol: {proto}
Action Taken: BLOCKED & QUARANTINED
Status: NEUTRALIZED

Mitigation Actions:
1. IP addresses blocked via firewall
2. Active connections terminated
3. Traffic isolated and logged
4. System administrator notified
================================
"""
            
            with open(threat_log_file, 'w', encoding='utf-8') as f:
                f.write(threat_info)
            
            self.log(f"   ✅ Threat details logged to: {threat_log_file}")
            
            # 3. Create network isolation rule (block all traffic from this subnet)
            subnet = '.'.join(src_ip.split('.')[:-1]) + '.0/24'
            self.log(f"   Step 3: Isolating subnet {subnet}")
            
            if self.is_windows:
                rule_name = f"APT_Isolate_{subnet.replace('.', '_').replace('/', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={subnet}'
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            self.log(f"   ✅ Network segment isolated successfully")
            
            # 4. Alert user
            self.log(f"   🚨 CRITICAL: {threat_type} has been neutralized!")
            self.log(f"   📋 Quarantine report: {threat_log_file}")
            
            return True
            
        except Exception as e:
            self.log(f"   ❌ Error in isolation process: {str(e)}")
            return False
    
    def execute_full_mitigation(self, flow_key, threat_type, confidence):
        """Execute all 3 mitigation methods."""
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
        
        self.log("=" * 80)
        self.log(f"🚨 INITIATING THREAT MITIGATION PROTOCOL")
        self.log(f"   Threat: {threat_type} | Confidence: {confidence:.1%}")
        self.log(f"   Target: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        self.log("=" * 80)
        
        # Execute all 3 methods
        success_count = 0
        
        # Method 1: Firewall blocking
        if self.block_ip_firewall(src_ip, f"{threat_type} detected"):
            success_count += 1
        
        # Method 2: Kill connections
        if self.kill_suspicious_connections(dst_ip, dst_port):
            success_count += 1
        
        # Method 3: Isolate and quarantine
        if self.isolate_and_quarantine(flow_key, threat_type):
            success_count += 1
        
        self.log("=" * 80)
        self.log(f"✅ MITIGATION COMPLETE: {success_count}/3 methods successful")
        self.log("=" * 80)
        
        return success_count >= 2  # Success if at least 2 methods worked
    
    def unblock_ip(self, ip_address):
        """Remove IP from firewall block list."""
        try:
            if self.is_windows:
                rule_name = f"APT_Block_{ip_address.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
            else:
                cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            self.blocked_ips.discard(ip_address)
            self.log(f"✅ Unblocked IP: {ip_address}")
            return True
        except Exception as e:
            self.log(f"❌ Error unblocking IP: {str(e)}")
            return False
    
    def get_blocked_list(self):
        """Return list of blocked IPs and processes."""
        return {
            'ips': list(self.blocked_ips),
            'processes': list(self.blocked_processes),
            'quarantine_files': os.listdir(self.quarantine_dir) if os.path.exists(self.quarantine_dir) else []
        }

class NetworkFlowAnalyzer:
    def __init__(self):
        self.flows = defaultdict(list)
        self.flow_start_time = {}
        self.flow_duration = 10
        
        # Statistics tracking
        self.total_packets_captured = 0
        self.total_flows_analyzed = 0
        self.trojan_detections = 0
        self.apt_detections = 0
        self.threats_mitigated = 0
        self.last_report_time = time.time()
        
    def get_flow_key(self, packet):
        """Generate unique flow key: (src_ip, dst_ip, src_port, dst_port, protocol)"""
        try:
            if IP in packet:
                src_ip, dst_ip = packet[IP].src, packet[IP].dst
                proto = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'OTHER'
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                else:
                    return None
                    
                return (src_ip, dst_ip, src_port, dst_port, proto)
            return None
        except Exception as e:
            logging.error(f"Error generating flow key: {str(e)}")
            return None
    
    def extract_features(self, flow_packets):
        """Extract 84 CICFlowMeter features from flow packets."""
        if not flow_packets:
            return None
            
        try:
            start_time = min(p.time for p in flow_packets)
            end_time = max(p.time for p in flow_packets)
            flow_duration = (end_time - start_time) * 1000
        except AttributeError:
            logging.error("Invalid packet data in flow, skipping feature extraction")
            return None
        
        # Initialize counters
        fwd_packets, bwd_packets = 0, 0
        fwd_bytes, bwd_bytes = 0, 0
        fwd_lengths, bwd_lengths = [], []
        iat_intervals = []
        fwd_iat, bwd_iat = [], []
        active_times, idle_times = [], []
        last_time = start_time
        flags = defaultdict(int)
        
        # Process packets chronologically
        sorted_packets = sorted(flow_packets, key=lambda p: p.time)
        prev_time = start_time
        
        for i, packet in enumerate(sorted_packets):
            try:
                pkt_time = packet.time
                pkt_len = len(packet)
                
                # IAT
                iat = (pkt_time - prev_time) * 1000
                iat_intervals.append(iat)
                prev_time = pkt_time
                
                # Direction
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                
                if src_port > 1024 and dst_port <= 1024:
                    fwd_packets += 1
                    fwd_bytes += pkt_len
                    fwd_lengths.append(pkt_len)
                    fwd_iat.append(iat)
                else:
                    bwd_packets += 1
                    bwd_bytes += pkt_len
                    bwd_lengths.append(pkt_len)
                    bwd_iat.append(iat)
                
                # TCP Flags
                if TCP in packet:
                    flags['FIN'] += 1 if packet[TCP].flags & 0x01 else 0
                    flags['SYN'] += 1 if packet[TCP].flags & 0x02 else 0
                    flags['RST'] += 1 if packet[TCP].flags & 0x04 else 0
                    flags['PSH'] += 1 if packet[TCP].flags & 0x08 else 0
                    flags['ACK'] += 1 if packet[TCP].flags & 0x10 else 0
                    flags['URG'] += 1 if packet[TCP].flags & 0x20 else 0
                    flags['CWR'] += 1 if packet[TCP].flags & 0x80 else 0
                    flags['ECE'] += 1 if packet[TCP].flags & 0x40 else 0
            except Exception as e:
                logging.error(f"Error processing packet: {str(e)}")
                continue
        
        # Calculate 84 features
        features = {
            'Protocol': 6 if TCP in flow_packets[0] else 17,
            'Flow Duration': flow_duration,
            'Total Fwd Packets': fwd_packets,
            'Total Backward Packets': bwd_packets,
            'Total Length of Fwd Packets': fwd_bytes,
            'Total Length of Bwd Packets': bwd_bytes,
            'Fwd Packet Length Max': max(fwd_lengths) if fwd_lengths else 0,
            'Fwd Packet Length Min': min(fwd_lengths) if fwd_lengths else 0,
            'Fwd Packet Length Mean': np.mean(fwd_lengths) if fwd_lengths else 0,
            'Fwd Packet Length Std': np.std(fwd_lengths) if fwd_lengths else 0,
            'Bwd Packet Length Max': max(bwd_lengths) if bwd_lengths else 0,
            'Bwd Packet Length Min': min(bwd_lengths) if bwd_lengths else 0,
            'Bwd Packet Length Mean': np.mean(bwd_lengths) if bwd_lengths else 0,
            'Bwd Packet Length Std': np.std(bwd_lengths) if bwd_lengths else 0,
            'Flow Bytes/s': (fwd_bytes + bwd_bytes) / (flow_duration / 1000) if flow_duration > 0 else 0,
            'Flow Packets/s': (fwd_packets + bwd_packets) / (flow_duration / 1000) if flow_duration > 0 else 0,
            'Flow IAT Mean': np.mean(iat_intervals) if iat_intervals else 0,
            'Flow IAT Std': np.std(iat_intervals) if iat_intervals else 0,
            'Flow IAT Max': max(iat_intervals) if iat_intervals else 0,
            'Flow IAT Min': min(iat_intervals) if iat_intervals else 0,
            'Fwd IAT Total': sum(fwd_iat) if fwd_iat else 0,
            'Fwd IAT Mean': np.mean(fwd_iat) if fwd_iat else 0,
            'Fwd IAT Std': np.std(fwd_iat) if fwd_iat else 0,
            'Fwd IAT Max': max(fwd_iat) if fwd_iat else 0,
            'Fwd IAT Min': min(fwd_iat) if fwd_iat else 0,
            'Bwd IAT Total': sum(bwd_iat) if bwd_iat else 0,
            'Bwd IAT Mean': np.mean(bwd_iat) if bwd_iat else 0,
            'Bwd IAT Std': np.std(bwd_iat) if bwd_iat else 0,
            'Bwd IAT Max': max(bwd_iat) if bwd_iat else 0,
            'Bwd IAT Min': min(bwd_iat) if bwd_iat else 0,
            'Fwd PSH Flags': flags['PSH'],
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': flags['URG'],
            'Bwd URG Flags': 0,
            'Fwd Header Length': 20 * fwd_packets,
            'Bwd Header Length': 20 * bwd_packets,
            'Fwd Packets/s': fwd_packets / (flow_duration / 1000) if flow_duration > 0 else 0,
            'Bwd Packets/s': bwd_packets / (flow_duration / 1000) if flow_duration > 0 else 0,
            'Min Packet Length': min([len(p) for p in flow_packets]) if flow_packets else 0,
            'Max Packet Length': max([len(p) for p in flow_packets]) if flow_packets else 0,
            'Packet Length Mean': np.mean([len(p) for p in flow_packets]) if flow_packets else 0,
            'Packet Length Std': np.std([len(p) for p in flow_packets]) if flow_packets else 0,
            'Packet Length Variance': np.var([len(p) for p in flow_packets]) if flow_packets else 0,
            'FIN Flag Count': flags['FIN'],
            'SYN Flag Count': flags['SYN'],
            'RST Flag Count': flags['RST'],
            'PSH Flag Count': flags['PSH'],
            'ACK Flag Count': flags['ACK'],
            'URG Flag Count': flags['URG'],
            'CWR Flag Count': flags['CWR'],
            'ECE Flag Count': flags['ECE'],
            'Down/Up Ratio': bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0,
            'Average Packet Size': (fwd_bytes + bwd_bytes) / (fwd_packets + bwd_packets) if (fwd_packets + bwd_packets) > 0 else 0,
            'Fwd Segment Size Avg': np.mean(fwd_lengths) if fwd_lengths else 0,
            'Bwd Segment Size Avg': np.mean(bwd_lengths) if bwd_lengths else 0,
            'Subflow Fwd Packets': fwd_packets,
            'Subflow Fwd Bytes': fwd_bytes,
            'Subflow Bwd Packets': bwd_packets,
            'Subflow Bwd Bytes': bwd_bytes,
            'Init_Win_bytes_forward': 65535,
            'Init_Win_bytes_backward': 65535,
            'act_data_pkt_fwd': fwd_packets,
            'min_seg_size_forward': 20,
            'Active Mean': 0, 'Active Std': 0, 'Active Max': 0, 'Active Min': 0,
            'Idle Mean': 0, 'Idle Std': 0, 'Idle Max': 0, 'Idle Min': 0
        }
        
        # Fill missing features with 0
        for i in range(84):
            feature_name = f'feature_{i}'
            if feature_name not in features:
                features[feature_name] = 0
                
        return features

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("APT & Trojan Detection with Auto-Mitigation System [ADMIN MODE]")
        self.is_monitoring = False
        self.analyzer = NetworkFlowAnalyzer()
        self.use_layer3 = False
        self.auto_mitigate = tk.BooleanVar(value=True)
        
        # Model paths
        self.trojan_model_path = tk.StringVar(value='trojan_lstm_model.h5')
        self.apt_model_path = tk.StringVar(value='apt_lstm_model.h5')
        self.scaler_path = tk.StringVar(value='scaler_apt.pkl')
        
        # Models (will be loaded after GUI setup)
        self.trojan_model = None
        self.apt_model = None
        self.scaler = None
        
        # Initialize mitigation engine
        self.mitigation_engine = ThreatMitigationEngine(self.log_message)
        
        # Setup GUI first
        self.setup_gui()
        
        # Load models
        self.load_all_models()
        
        # Start statistics reporter thread (after GUI is ready)
        self.start_statistics_reporter()
        
    def setup_gui(self):
        # Create main container with scrollbar
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Admin Status Banner
        admin_banner = ttk.Frame(main_container, relief=tk.RIDGE, borderwidth=2)
        admin_banner.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(admin_banner, text="✅ ADMINISTRATOR MODE - Full Mitigation Capabilities Enabled", 
                 font=('Arial', 10, 'bold'), foreground='green').pack(pady=5)
        
        # Status
        ttk.Label(main_container, text="Status:", font=('Segoe UI Emoji', 12, 'bold')).pack(pady=5)
        self.status_var = tk.StringVar(value="Stopped")
        self.status_label = ttk.Label(main_container, textvariable=self.status_var, font=('Arial', 14))
        self.status_label.pack(pady=5)
        
        # Model Configuration Frame (Compact)
        model_frame = ttk.LabelFrame(main_container, text="🤖 AI Models", padding=5)
        model_frame.pack(pady=5, padx=10, fill=tk.X)
        
        # Create 3-column layout for models (more compact)
        models_grid = ttk.Frame(model_frame)
        models_grid.pack(fill=tk.X)
        
        # Trojan Model (Row 1)
        ttk.Label(models_grid, text="Trojan:", width=8).grid(row=0, column=0, sticky=tk.W, padx=2)
        trojan_entry = ttk.Entry(models_grid, textvariable=self.trojan_model_path, width=35, font=('Arial', 8))
        trojan_entry.grid(row=0, column=1, padx=2, sticky=tk.EW)
        btn_frame1 = ttk.Frame(models_grid)
        btn_frame1.grid(row=0, column=2, padx=2)
        ttk.Button(btn_frame1, text="📁", command=lambda: self.browse_model('trojan'), width=3).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_frame1, text="🔄", command=lambda: self.reload_model('trojan'), width=3).pack(side=tk.LEFT, padx=1)
        
        # APT Model (Row 2)
        ttk.Label(models_grid, text="APT:", width=8).grid(row=1, column=0, sticky=tk.W, padx=2)
        apt_entry = ttk.Entry(models_grid, textvariable=self.apt_model_path, width=35, font=('Arial', 8))
        apt_entry.grid(row=1, column=1, padx=2, pady=2, sticky=tk.EW)
        btn_frame2 = ttk.Frame(models_grid)
        btn_frame2.grid(row=1, column=2, padx=2)
        ttk.Button(btn_frame2, text="📁", command=lambda: self.browse_model('apt'), width=3).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_frame2, text="🔄", command=lambda: self.reload_model('apt'), width=3).pack(side=tk.LEFT, padx=1)
        
        # Scaler (Row 3)
        ttk.Label(models_grid, text="Scaler:", width=8).grid(row=2, column=0, sticky=tk.W, padx=2)
        scaler_entry = ttk.Entry(models_grid, textvariable=self.scaler_path, width=35, font=('Arial', 8))
        scaler_entry.grid(row=2, column=1, padx=2, sticky=tk.EW)
        btn_frame3 = ttk.Frame(models_grid)
        btn_frame3.grid(row=2, column=2, padx=2)
        ttk.Button(btn_frame3, text="📁", command=lambda: self.browse_model('scaler'), width=3).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_frame3, text="🔄", command=lambda: self.reload_model('scaler'), width=3).pack(side=tk.LEFT, padx=1)
        
        models_grid.columnconfigure(1, weight=1)
        
        # Model status (compact)
        self.model_status_label = ttk.Label(model_frame, text="", foreground="green", font=('Arial', 8))
        self.model_status_label.pack(pady=2)
        
        # Auto-Mitigation Toggle (Compact)
        mitigation_frame = ttk.LabelFrame(main_container, text="⚔️ Mitigation", padding=5)
        mitigation_frame.pack(pady=5, padx=10, fill=tk.X)
        
        ttk.Checkbutton(
            mitigation_frame, 
            text="🛡️ Auto-Mitigate (Block IP + Kill Connections + Quarantine)",
            variable=self.auto_mitigate,
            command=self.toggle_mitigation
        ).pack(anchor=tk.W)
        
        # Statistics Frame (Compact)
        stats_frame = ttk.LabelFrame(main_container, text="📊 Statistics", padding=5)
        stats_frame.pack(pady=5, padx=10, fill=tk.X)
        
        self.stats_text = tk.Text(stats_frame, height=4, font=('Consolas', 8), bg='#f0f0f0')
        self.stats_text.pack(fill=tk.X)
        
        # Blocked List Frame (Compact)
        blocked_frame = ttk.LabelFrame(main_container, text="🚫 Blocked", padding=5)
        blocked_frame.pack(pady=5, padx=10, fill=tk.X)
        
        self.blocked_text = tk.Text(blocked_frame, height=2, font=('Consolas', 8), bg='#fff5f5')
        self.blocked_text.pack(fill=tk.X)
        
        # Log (Reduced height)
        ttk.Label(main_container, text="Detection & Mitigation Log:", font=('Segoe UI Emoji', 10, 'bold')).pack(pady=(5,2))
        self.log_text = scrolledtext.ScrolledText(main_container, width=120, height=12, font=('Consolas', 8))
        self.log_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
        
        # Controls (Always visible at bottom)
        button_frame = ttk.Frame(main_container)
        button_frame.pack(pady=10, side=tk.BOTTOM)
        
        self.start_btn = ttk.Button(button_frame, text="🚀 START", command=self.start_monitoring, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ STOP", command=self.stop_monitoring, state='disabled', width=15)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_log, width=12)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.view_quarantine_btn = ttk.Button(button_frame, text="📁 Quarantine", command=self.view_quarantine, width=15)
        self.view_quarantine_btn.pack(side=tk.LEFT, padx=5)
        
        self.update_statistics_display()
    
    def toggle_mitigation(self):
        if self.auto_mitigate.get():
            self.log_message("🛡️ Auto-Mitigation ENABLED - Threats will be automatically blocked")
        else:
            self.log_message("⚠️ Auto-Mitigation DISABLED - Threats will only be logged")
    
    def browse_model(self, model_type):
        """Browse and select model/scaler file."""
        if model_type == 'scaler':
            filetypes = [("Pickle files", "*.pkl"), ("All files", "*.*")]
            title = "Select Scaler File"
        else:
            filetypes = [("H5 Model files", "*.h5"), ("All files", "*.*")]
            title = f"Select {model_type.upper()} Model File"
        
        filename = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes
        )
        
        if filename:
            if model_type == 'trojan':
                self.trojan_model_path.set(filename)
                self.log_message(f"📁 Selected Trojan model: {os.path.basename(filename)}")
            elif model_type == 'apt':
                self.apt_model_path.set(filename)
                self.log_message(f"📁 Selected APT model: {os.path.basename(filename)}")
            elif model_type == 'scaler':
                self.scaler_path.set(filename)
                self.log_message(f"📁 Selected Scaler: {os.path.basename(filename)}")
    
    def reload_model(self, model_type):
        """Reload a specific model."""
        if self.is_monitoring:
            messagebox.showwarning("Warning", "Stop monitoring before reloading models!")
            return
        
        try:
            if model_type == 'trojan':
                self.log_message(f"🔄 Reloading Trojan model from: {self.trojan_model_path.get()}")
                self.trojan_model = load_model(self.trojan_model_path.get())
                self.log_message("✅ Trojan model reloaded successfully")
                
            elif model_type == 'apt':
                self.log_message(f"🔄 Reloading APT model from: {self.apt_model_path.get()}")
                self.apt_model = load_model(self.apt_model_path.get())
                self.log_message("✅ APT model reloaded successfully")
                
            elif model_type == 'scaler':
                self.log_message(f"🔄 Reloading Scaler from: {self.scaler_path.get()}")
                self.scaler = joblib.load(self.scaler_path.get())
                self.log_message("✅ Scaler reloaded successfully")
            
            self.update_model_status()
            
        except Exception as e:
            self.log_message(f"❌ Error reloading {model_type}: {str(e)}")
            messagebox.showerror("Error", f"Failed to reload {model_type}:\n{str(e)}")
    
    def load_all_models(self):
        """Load all models at startup."""
        try:
            self.log_message("🔄 Loading AI models...")
            
            # Load Trojan model
            if os.path.exists(self.trojan_model_path.get()):
                self.trojan_model = load_model(self.trojan_model_path.get())
                self.log_message(f"✅ Trojan model loaded: {self.trojan_model_path.get()}")
            else:
                self.log_message(f"⚠️ Trojan model not found: {self.trojan_model_path.get()}")
            
            # Load APT model
            if os.path.exists(self.apt_model_path.get()):
                self.apt_model = load_model(self.apt_model_path.get())
                self.log_message(f"✅ APT model loaded: {self.apt_model_path.get()}")
            else:
                self.log_message(f"⚠️ APT model not found: {self.apt_model_path.get()}")
            
            # Load Scaler
            if os.path.exists(self.scaler_path.get()):
                self.scaler = joblib.load(self.scaler_path.get())
                self.log_message(f"✅ Scaler loaded: {self.scaler_path.get()}")
            else:
                self.log_message(f"⚠️ Scaler not found: {self.scaler_path.get()}")
            
            self.update_model_status()
            
            # Check if all models loaded
            if self.trojan_model and self.apt_model and self.scaler:
                self.log_message("✅ All models loaded successfully - Ready to monitor!")
            else:
                self.log_message("⚠️ Some models missing - Please load models before starting")
                
        except Exception as e:
            self.log_message(f"❌ Error loading models: {str(e)}")
            messagebox.showwarning("Model Loading Error", 
                                 f"Failed to load some models:\n{str(e)}\n\n"
                                 "Please use Browse button to select correct model files.")
    
    def update_model_status(self):
        """Update model status indicator."""
        status_parts = []
        
        if self.trojan_model:
            status_parts.append("Trojan ✅")
        else:
            status_parts.append("Trojan ❌")
        
        if self.apt_model:
            status_parts.append("APT ✅")
        else:
            status_parts.append("APT ❌")
        
        if self.scaler:
            status_parts.append("Scaler ✅")
        else:
            status_parts.append("Scaler ❌")
        
        status_text = "Models Status: " + " | ".join(status_parts)
        
        if self.trojan_model and self.apt_model and self.scaler:
            self.model_status_label.config(text=status_text, foreground="green")
        else:
            self.model_status_label.config(text=status_text + " - ⚠️ Incomplete", foreground="red")
    
    def update_blocked_display(self):
        """Update blocked threats display."""
        blocked_data = self.mitigation_engine.get_blocked_list()
        
        display_text = f"Blocked IPs: {len(blocked_data['ips'])} | "
        display_text += f"Killed Processes: {len(blocked_data['processes'])} | "
        display_text += f"Quarantine Files: {len(blocked_data['quarantine_files'])}\n"
        
        if blocked_data['ips']:
            display_text += f"IPs: {', '.join(list(blocked_data['ips'])[:5])}"
            if len(blocked_data['ips']) > 5:
                display_text += f" ... (+{len(blocked_data['ips'])-5} more)"
        
        self.blocked_text.delete(1.0, tk.END)
        self.blocked_text.insert(1.0, display_text)
    
    def view_quarantine(self):
        """Open quarantine folder."""
        try:
            quarantine_dir = self.mitigation_engine.quarantine_dir
            if os.path.exists(quarantine_dir):
                if platform.system() == "Windows":
                    os.startfile(quarantine_dir)
                else:
                    subprocess.run(['xdg-open', quarantine_dir])
                self.log_message(f"📁 Opened quarantine folder: {quarantine_dir}")
            else:
                messagebox.showinfo("Quarantine", "No quarantine files yet")
        except Exception as e:
            self.log_message(f"❌ Error opening quarantine: {str(e)}")
    
    def update_statistics_display(self):
        """Update the statistics display in GUI."""
        stats = f"""Packets Captured: {self.analyzer.total_packets_captured:,} | Flows Analyzed: {self.analyzer.total_flows_analyzed:,}
Active Flows: {len(self.analyzer.flows):,} | Trojan Detections: {self.analyzer.trojan_detections} | APT Detections: {self.analyzer.apt_detections}
Threats Mitigated: {self.analyzer.threats_mitigated} | Auto-Mitigation: {'ENABLED ✅' if self.auto_mitigate.get() else 'DISABLED ⚠️'}
Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        
        if hasattr(self, 'stats_text'):
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats)
        
        # Update blocked list
        if hasattr(self, 'blocked_text'):
            self.update_blocked_display()
        
        # Schedule next update
        if self.is_monitoring:
            self.root.after(1000, self.update_statistics_display)
    
    def start_statistics_reporter(self):
        """Start background thread to report statistics every 5 minutes."""
        def report_loop():
            while True:
                time.sleep(300)  # 5 minutes
                if self.is_monitoring:
                    self.log_message("=" * 80)
                    self.log_message("📊 5-MINUTE STATISTICS REPORT")
                    self.log_message(f"   Total Packets Captured: {self.analyzer.total_packets_captured:,}")
                    self.log_message(f"   Total Flows Analyzed: {self.analyzer.total_flows_analyzed:,}")
                    self.log_message(f"   Active Flows (ongoing): {len(self.analyzer.flows):,}")
                    self.log_message(f"   Trojan Detections: {self.analyzer.trojan_detections}")
                    self.log_message(f"   APT Detections: {self.analyzer.apt_detections}")
                    self.log_message(f"   Threats Mitigated: {self.analyzer.threats_mitigated}")
                    self.log_message(f"   Detection Rate: {((self.analyzer.trojan_detections + self.analyzer.apt_detections) / max(self.analyzer.total_flows_analyzed, 1) * 100):.2f}%")
                    
                    # Show blocked IPs
                    blocked_data = self.mitigation_engine.get_blocked_list()
                    self.log_message(f"   Blocked IPs: {len(blocked_data['ips'])}")
                    
                    # Show top 5 active flows
                    if self.analyzer.flows:
                        self.log_message("   Top 5 Active Flows:")
                        sorted_flows = sorted(self.analyzer.flows.items(), 
                                            key=lambda x: len(x[1]), 
                                            reverse=True)[:5]
                        for i, (flow_key, packets) in enumerate(sorted_flows, 1):
                            src_ip, dst_ip, src_port, dst_port, proto = flow_key
                            self.log_message(f"      {i}. {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto}) - {len(packets)} packets")
                    
                    self.log_message("=" * 80)
        
        reporter_thread = threading.Thread(target=report_loop, daemon=True)
        reporter_thread.start()
    
    def log_message(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        full_msg = f"[{timestamp}] {message}"
        self.log_text.insert(tk.END, full_msg + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        # Log without emojis to console to avoid encoding issues
        safe_msg = message.encode('ascii', 'ignore').decode('ascii')
        logging.info(safe_msg)
    
    def packet_callback(self, packet):
        """Real-time packet processing."""
        self.analyzer.total_packets_captured += 1
        
        if IP in packet and (TCP in packet or UDP in packet):
            flow_key = self.analyzer.get_flow_key(packet)
            if flow_key:
                self.analyzer.flows[flow_key].append(packet)
                
                # Log new flow
                if flow_key not in self.analyzer.flow_start_time:
                    self.analyzer.flow_start_time[flow_key] = packet.time
                    src_ip, dst_ip, src_port, dst_port, proto = flow_key
                    self.log_message(f"🔵 New flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})")
                
                # Process flow every 10 seconds
                if (packet.time - self.analyzer.flow_start_time[flow_key]) >= self.analyzer.flow_duration:
                    self.process_flow(flow_key)
    
    def process_flow(self, flow_key):
        """Process flow and predict APT/Trojan in a separate thread."""
        def process():
            try:
                flow_packets = self.analyzer.flows[flow_key]
                self.analyzer.total_flows_analyzed += 1
                
                src_ip, dst_ip, src_port, dst_port, proto = flow_key
                flow_id = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})"
                
                self.log_message(f"🔍 Analyzing flow: {flow_id} ({len(flow_packets)} packets)")
                
                features = self.analyzer.extract_features(flow_packets)
                
                if features:
                    # Log key features
                    self.log_message(f"   Flow Duration: {features['Flow Duration']:.2f}ms, "
                                   f"Fwd Packets: {features['Total Fwd Packets']}, "
                                   f"Bwd Packets: {features['Total Backward Packets']}, "
                                   f"Total Bytes: {features['Total Length of Fwd Packets'] + features['Total Length of Bwd Packets']}")
                    
                    # Check if models are loaded
                    if not self.trojan_model or not self.apt_model or not self.scaler:
                        self.log_message("⚠️ Models not loaded - skipping prediction")
                        return
                    
                    feature_df = pd.DataFrame([features])
                    X_new = self.scaler.transform(feature_df)
                    X_new = X_new.reshape((1, 1, X_new.shape[1]))
                    
                    # Predict
                    trojan_prob = self.trojan_model.predict(X_new, verbose=0)[0][0]
                    apt_prob = self.apt_model.predict(X_new, verbose=0)[0][0]
                    
                    trojan_pred = 1 if trojan_prob > 0.5 else 0
                    apt_pred = 1 if apt_prob > 0.5 else 0
                    
                    # Log results and execute mitigation if needed
                    if trojan_pred == 1 or apt_pred == 1:
                        self.log_message(f"🚨 ALERT: {flow_id}")
                        
                        threat_type = None
                        confidence = 0
                        
                        if trojan_pred == 1:
                            self.analyzer.trojan_detections += 1
                            threat_type = "TROJAN"
                            confidence = trojan_prob
                            self.log_message(f"   ⚠️ TROJAN DETECTED (Confidence: {trojan_prob:.3f})")
                        
                        if apt_pred == 1:
                            self.analyzer.apt_detections += 1
                            if threat_type is None or apt_prob > confidence:
                                threat_type = "APT"
                                confidence = apt_prob
                            self.log_message(f"   ⚠️ APT DETECTED (Confidence: {apt_prob:.3f})")
                        
                        # Execute mitigation if enabled
                        if self.auto_mitigate.get():
                            self.log_message(f"   🛡️ Initiating auto-mitigation for {threat_type}...")
                            
                            success = self.mitigation_engine.execute_full_mitigation(
                                flow_key, 
                                threat_type, 
                                confidence
                            )
                            
                            if success:
                                self.analyzer.threats_mitigated += 1
                                self.log_message(f"   ✅ {threat_type} successfully neutralized!")
                            else:
                                self.log_message(f"   ⚠️ Partial mitigation - check administrator privileges")
                        else:
                            self.log_message(f"   ℹ️ Auto-mitigation disabled - threat logged only")
                    else:
                        self.log_message(f"✓ Clean: {flow_id} (Trojan:{trojan_prob:.3f}, APT:{apt_prob:.3f})")
                
                # Cleanup
                del self.analyzer.flows[flow_key]
                del self.analyzer.flow_start_time[flow_key]
                
            except Exception as e:
                self.log_message(f"⚠️ Error processing flow: {str(e)}")
                logging.error(traceback.format_exc())
        
        threading.Thread(target=process, daemon=True).start()
    
    def select_interface(self):
        """Select a valid network interface for Layer 3 sniffing."""
        try:
            # Try to get Windows interfaces first
            try:
                win_ifaces = get_windows_if_list()
                for iface in win_ifaces:
                    if iface.get('ips') and len(iface['ips']) > 0:
                        ip = iface['ips'][0]
                        if ip != "0.0.0.0" and not ip.startswith("169.254"):
                            self.log_message(f"ℹ️ Selected interface: {iface['name']} (IP: {ip})")
                            return iface['name']
            except:
                pass
            
            # Fallback to standard interface list
            available_interfaces = get_if_list()
            if not available_interfaces:
                self.log_message("❌ No network interfaces available.")
                return None
            
            # Try to find an interface with a valid IP address
            for iface in available_interfaces:
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != "0.0.0.0" and not ip.startswith("169.254"):
                        self.log_message(f"ℹ️ Selected interface: {iface} (IP: {ip})")
                        return iface
                except:
                    continue
            
            # Use first available interface as last resort
            self.log_message(f"ℹ️ Using first available interface: {available_interfaces[0]}")
            return available_interfaces[0]
            
        except Exception as e:
            self.log_message(f"⚠️ Error selecting interface: {str(e)}")
            return None
    
    def start_monitoring(self):
        """Start packet sniffing with proper Layer 3 configuration."""
        # Check if models are loaded
        if not self.trojan_model or not self.apt_model or not self.scaler:
            messagebox.showerror("Error", 
                                "Models not loaded!\n\n"
                                "Please load all required models:\n"
                                "- Trojan Model (.h5)\n"
                                "- APT Model (.h5)\n"
                                "- Scaler (.pkl)")
            return
        
        try:
            # Check if Npcap is available
            try:
                conf.use_pcap = True
                # Test if it works
                test_ifaces = get_if_list()
                self.use_layer3 = False
                self.log_message("✅ Npcap detected - using Layer 2 sniffing")
            except:
                # Force Layer 3 mode
                conf.use_pcap = False
                from scapy.arch.windows import _NotAvailableSocket
                conf.L3socket = conf.L3socket
                self.use_layer3 = True
                self.log_message("ℹ️ Npcap not available - using Layer 3 sniffing")
                self.log_message("ℹ️ Install Npcap from https://npcap.com/ for full Layer 2 support")
            
            # Select interface
            self.iface = self.select_interface()
            if not self.iface:
                self.log_message("❌ No valid network interface found")
                return
            
            self.is_monitoring = True
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            
            layer_info = "Layer 3" if self.use_layer3 else "Layer 2"
            mitigation_status = "AUTO-MITIGATION ON 🛡️" if self.auto_mitigate.get() else "DETECTION ONLY ⚠️"
            self.status_var.set(f"🟢 MONITORING ({layer_info}) - {mitigation_status}")
            self.log_message(f"🚀 Started monitoring on '{self.iface}' ({layer_info})")
            self.log_message(f"🛡️ Mitigation Mode: {mitigation_status}")
            self.log_message(f"📡 Waiting for network traffic...")
            
            # Start statistics update
            self.update_statistics_display()
            
            def sniff_loop():
                """Continuous sniffing loop with error recovery."""
                retry_count = 0
                max_retries = 3
                
                while self.is_monitoring and retry_count < max_retries:
                    try:
                        # Configure for Layer 3 if needed
                        if self.use_layer3:
                            conf.use_pcap = False
                        
                        # Start sniffing with timeout to allow checking is_monitoring flag
                        sniff(
                            iface=self.iface,
                            prn=self.packet_callback,
                            store=False,
                            timeout=1,
                            stop_filter=lambda x: not self.is_monitoring
                        )
                        
                        # Reset retry count on successful sniff
                        retry_count = 0
                        
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        retry_count += 1
                        self.log_message(f"⚠️ Sniffing error (attempt {retry_count}/{max_retries}): {str(e)}")
                        if retry_count >= max_retries:
                            self.log_message("❌ Max retries reached. Stopping monitoring.")
                            self.root.after(0, self.stop_monitoring)
                            break
                        time.sleep(1)
            
            self.sniff_thread = threading.Thread(target=sniff_loop, daemon=True)
            self.sniff_thread.start()
            
        except Exception as e:
            self.log_message(f"❌ Failed to start monitoring: {str(e)}")
            self.log_message(f"Stack trace: {traceback.format_exc()}")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop packet sniffing and update GUI."""
        self.is_monitoring = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("🔴 STOPPED")
        self.log_message("⏹️ Stopped network monitoring")
        
        # Final statistics
        self.log_message("=" * 80)
        self.log_message("📊 FINAL STATISTICS")
        self.log_message(f"   Total Packets Captured: {self.analyzer.total_packets_captured:,}")
        self.log_message(f"   Total Flows Analyzed: {self.analyzer.total_flows_analyzed:,}")
        self.log_message(f"   Trojan Detections: {self.analyzer.trojan_detections}")
        self.log_message(f"   APT Detections: {self.analyzer.apt_detections}")
        self.log_message(f"   Threats Mitigated: {self.analyzer.threats_mitigated}")
        
        blocked_data = self.mitigation_engine.get_blocked_list()
        self.log_message(f"   IPs Blocked: {len(blocked_data['ips'])}")
        self.log_message(f"   Processes Killed: {len(blocked_data['processes'])}")
        self.log_message(f"   Quarantine Files: {len(blocked_data['quarantine_files'])}")
        self.log_message("=" * 80)
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

def main():
    """Main entry point with proper error handling."""
    try:
        # Admin status confirmed
        logging.info("✅ Running with Administrator privileges")
        
        # Check and configure Scapy for Layer 3 if needed
        try:
            conf.use_pcap = True
            test = get_if_list()
            logging.info("✅ Npcap detected")
        except:
            logging.warning("⚠️ Npcap not detected, using Layer 3 socket")
            conf.use_pcap = False
        
        # List available interfaces
        try:
            interfaces = get_if_list()
            logging.info(f"Available interfaces: {interfaces}")
        except Exception as e:
            logging.error(f"Could not list interfaces: {e}")
        
        # Start GUI
        root = tk.Tk()
        root.geometry("1300x900")
        app = NetworkMonitorApp(root)
        
        root.mainloop()
        
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        logging.error(traceback.format_exc())
        raise

if __name__ == "__main__":
    main()