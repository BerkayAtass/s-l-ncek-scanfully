from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Union, Set, Dict, Any
from enum import Enum
import subprocess
import os
import json
import fcntl
from datetime import datetime
import ipaddress
import re
import xml.etree.ElementTree as ET
import csv
import pandas as pd
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uuid
import threading
import time
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import shutil
import traceback
import queue
import concurrent.futures
from fastapi.encoders import jsonable_encoder

app = FastAPI()

# CORS ayarları düzeltildi - Frontend adreslerini ekledik
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Geliştirme için tüm kaynaklara izin ver (Üretim için değiştirin!)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Genişletilmiş Enum sınıfları
class ScanType(str, Enum):
    TCP_CONNECT = "sT"        # TCP Connect tarama (standart)
    TCP_SYN = "sS"            # TCP SYN tarama (hızlı, yarı-gizli)
    TCP_ACK = "sA"            # TCP ACK tarama (firewall keşfi)
    TCP_WINDOW = "sW"         # TCP Window tarama
    TCP_MAIMON = "sM"         # TCP Maimon tarama
    UDP_SCAN = "sU"           # UDP portları tarama
    PING_SCAN = "sP"          # Sadece ping taraması
    SKIP_PING = "Pn"          # Keşfi yoksay - tüm hostları çevrimiçi varsay
    FIN_SCAN = "sF"           # FIN tarama
    XMAS_SCAN = "sX"          # Xmas tarama
    NULL_SCAN = "sN"          # Null tarama
    IP_PROTOCOL = "sO"        # IP protokol taraması
    IDLE_SCAN = "sI"          # Idle tarama (ileri seviye)

class PortOption(str, Enum):
    SINGLE = "single"     # Tek port tarama
    RANGE = "range"       # Port aralığı tarama
    FAST = "fast"         # Yaygın 100 port (hızlı)
    ALL = "all"           # Tüm portlar (65535)
    TOP_1000 = "top1000"  # En yaygın 1000 port
    TOP_10 = "top10"      # En yaygın 10 port

class ServiceDetection(str, Enum):
    NONE = "none"             # Servis algılama yok
    STANDARD = "standard"     # Standart servis algılama
    LIGHT = "light"           # Hafif banner yakalama
    AGGRESSIVE = "aggressive" # Agresif servis algılama
    OS_DETECT = "os"          # İşletim sistemi tespiti

class TimingTemplate(str, Enum):
    PARANOID = "T0"       # Çok yavaş, IDS kaçınma
    SNEAKY = "T1"         # Yavaş, IDS kaçınma
    POLITE = "T2"         # Normal hızdan yavaş, daha az bant genişliği
    NORMAL = "T3"         # Varsayılan, normal hız
    AGGRESSIVE = "T4"     # Daha hızlı, güçlü sistemlerde
    INSANE = "T5"         # Çok hızlı, doğruluğu feda eder

class ScriptCategory(str, Enum):
    NONE = "none"             # Script kullanma
    DEFAULT = "default"       # Varsayılan scriptler
    DISCOVERY = "discovery"   # Keşif scriptleri
    SAFE = "safe"             # Güvenli scriptler
    AUTH = "auth"             # Kimlik doğrulama scriptleri
    BROADCAST = "broadcast"   # Yayın scriptleri
    BRUTE = "brute"           # Kaba kuvvet scriptleri
    VULN = "vuln"             # Güvenlik açığı scriptleri
    EXPLOIT = "exploit"       # Exploit scriptleri
    INTRUSIVE = "intrusive"   # İzinsiz giriş scriptleri
    MALWARE = "malware"       # Zararlı yazılım scriptleri
    DOS = "dos"               # DoS scriptleri
    ALL = "all"               # Tüm scriptler
    VULNERS = "vulners"       # Vulners.com veritabanı taraması
    VULSCAN = "vulscan"       # Offline veritabanı taraması
    
class OutputFormat(str, Enum):
    NORMAL = "normal"         # Normal çıktı
    XML = "xml"               # XML çıktı
    JSON = "json"             # JSON çıktı
    GREPABLE = "grepable"     # Grepable çıktı
    ALL = "all"               # Tüm formatlar

class ScanStatus(str, Enum):
    QUEUED = "queued"          # Sırada bekliyor
    RUNNING = "running"        # Çalışıyor
    COMPLETED = "completed"    # Tamamlandı
    FAILED = "failed"          # Hata oluştu

class ScanRequest(BaseModel):
    # Target specification
    target: str
    target_type: str  # ip, host, range, subnet, file
    
    # Scan name (optional)
    scan_name: Optional[str] = None

    # Port selection
    port_option: PortOption
    port_value: Optional[str] = None  # For single or range options

    # Scan type
    scan_type: ScanType

    # Service detection
    service_detection: ServiceDetection = ServiceDetection.NONE
    version_intensity: Optional[int] = None  # 0-9 arasında değer

    # Script selection
    script_category: ScriptCategory = ScriptCategory.NONE
    custom_scripts: Optional[str] = None  # Custom script isimleri

    # Timing template
    timing_template: Optional[TimingTemplate] = None

    # Output format
    output_format: OutputFormat = OutputFormat.XML

# Dinamik olarak CPU çekirdek sayısına göre thread sayısını belirle
max_workers = max(4, multiprocessing.cpu_count() * 2)  # En az 4, en fazla CPU*2 kadar thread

# Thread-safe sözlük ve kilit mekanizmaları
active_scans_lock = threading.Lock()
active_scans: Dict[str, Dict[str, Any]] = {}

# Dosya kilitleme/kilit açma fonksiyonları
def lock_file(f):
    """Dosyayı kilitler"""
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (IOError, BlockingIOError):
        return False

def unlock_file(f):
    """Dosya kilidini kaldırır"""
    try:
        fcntl.flock(f, fcntl.LOCK_UN)
        return True
    except IOError:
        return False

# Veri seri hale getirme hatası düzeltici fonksiyon (JSON serialization)
def safe_serialize(obj):
    """Güvenli bir şekilde JSON'a dönüştürülebilir veriyi döndürür"""
    if isinstance(obj, dict):
        return {k: safe_serialize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [safe_serialize(x) for x in obj]
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        # Diğer veri tiplerini güvenli string'e çevir
        return str(obj)

# Öncelikli iş kuyrukları
high_priority_queue = queue.PriorityQueue()
normal_priority_queue = queue.PriorityQueue()
low_priority_queue = queue.PriorityQueue()

# Tarama zamanlaycısı
class ScanScheduler:
    def __init__(self, max_workers):
        self.queue = queue.PriorityQueue()
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.scheduler_thread.start()
    
    def add_scan(self, priority, scan_id, request):
        """Yeni tarama ekle, önceliğe göre sırala"""
        self.queue.put((priority, (scan_id, request)))
    
    def _scheduler_loop(self):
        """Arka planda sürekli çalışan iş yöneticisi"""
        while self.running:
            try:
                if not self.queue.empty():
                    # Kuyruktaki bir sonraki işi al
                    priority, (scan_id, request) = self.queue.get(block=False)
                    
                    # Thread havuzuna işi gönder
                    self.executor.submit(run_scan_in_background, scan_id, request)
                    self.queue.task_done()
                else:
                    # Kuyruk boşsa biraz bekle
                    time.sleep(0.5)
            except Exception as e:
                print(f"Scheduler error: {e}")
                time.sleep(1)
    
    def shutdown(self):
        """Scheduler'ı düzgün şekilde kapat"""
        self.running = False
        self.scheduler_thread.join(timeout=5)
        self.executor.shutdown(wait=False)

# Thread-safe tarama durumu güncelleme
def update_scan_status(scan_id, status_update):
    with active_scans_lock:
        if scan_id in active_scans:
            active_scans[scan_id].update(status_update)

def get_scan_status(scan_id):
    with active_scans_lock:
        if scan_id in active_scans:
            return active_scans[scan_id].copy()
        return None

# Outputs klasörünü oluştur
os.makedirs("outputs", exist_ok=True)

# Scheduler'ı başlat
scan_scheduler = ScanScheduler(max_workers)

@app.on_event("startup")
async def startup_event():
    print(f"FastAPI başlatılıyor, tarama zamanlaycısı {max_workers} thread ile başlatıldı")

@app.on_event("shutdown")
async def shutdown_event():
    print("FastAPI kapatılıyor, kaynaklar serbest bırakılıyor")
    scan_scheduler.shutdown()

def parse_xml_file(xml_file):
    """
    XML dosyasını parse eder ve ElementTree root elementini döndürür.
    """
    max_retries = 3
    retry_delay = 1  # saniye
    
    for attempt in range(max_retries):
        try:
            # Dosya varsa ve okunabiliyorsa
            if not os.path.exists(xml_file):
                print(f"Hata: {xml_file} dosyası bulunamadı. ({attempt+1}/{max_retries})")
                time.sleep(retry_delay)
                continue
                
            # Dosya boyutunu kontrol et - 0 boyutlu dosyalar problemli olabilir
            if os.path.getsize(xml_file) == 0:
                print(f"Hata: {xml_file} dosyası boş. ({attempt+1}/{max_retries})")
                time.sleep(retry_delay)
                continue
                
            # Dosyayı açmayı dene
            with open(xml_file, 'r', encoding='utf-8') as f:
                # Dosyayı kilitler
                if not lock_file(f):
                    print(f"Dosya kilitli, okuma ertelemesi: {xml_file} ({attempt+1}/{max_retries})")
                    time.sleep(retry_delay)
                    continue
                    
                try:
                    tree = ET.parse(f)
                    return tree.getroot()
                except ET.ParseError as e:
                    print(f"Hata: XML dosyası parse edilemedi: {e} ({attempt+1}/{max_retries})")
                    time.sleep(retry_delay)
                finally:
                    unlock_file(f)
                    
        except Exception as e:
            print(f"XML dosyası işlenirken beklenmeyen hata: {e} ({attempt+1}/{max_retries})")
            traceback.print_exc()
            time.sleep(retry_delay)
    
    return None

def get_scan_info(root):
    """
    Nmap tarama bilgilerini çıkarır.
    """
    scan_info = {}
    
    # Eğer root None ise, varsayılan bir bilgi döndür
    if root is None:
        return {
            'start_time': 'Bilinmiyor',
            'scanner_name': 'Nmap',
            'scanner_version': 'Bilinmiyor',
            'command': 'Bilinmiyor'
        }
    
    # Tarama zamanı bilgileri
    if root.attrib.get('start'):
        start_time = int(root.attrib.get('start', 0))
        scan_info['start_time'] = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
    else:
        scan_info['start_time'] = 'Bilinmiyor'
    
    # Nmap versiyonu ve komut
    scanner = root.find('.//scanner')
    if scanner is not None:
        scan_info['scanner_name'] = scanner.attrib.get('name', 'Nmap')
        scan_info['scanner_version'] = scanner.attrib.get('version', 'Bilinmiyor')
    else:
        scan_info['scanner_name'] = 'Nmap'
        scan_info['scanner_version'] = 'Bilinmiyor'
    
    # Çalıştırılan Nmap komutu
    command = root.find('.//nmaprun')
    if command is not None:
        scan_info['command'] = command.attrib.get('args', 'Bilinmiyor')
    else:
        scan_info['command'] = 'Bilinmiyor'
    
    return scan_info

def extract_host_data(host):
    """
    Bir host elementi için tüm verileri çıkarır.
    """
    host_data = {}
    
    # IP adresi
    address_elem = host.find('./address[@addrtype="ipv4"]')
    if address_elem is not None:
        host_data['ip'] = address_elem.attrib.get('addr', 'Bilinmiyor')
    else:
        # IPv6 veya diğer adres tipleri için kontrol et
        address_elem = host.find('./address')
        if address_elem is not None:
            host_data['ip'] = address_elem.attrib.get('addr', 'Bilinmiyor')
        else:
            host_data['ip'] = 'Bilinmiyor'
    
    # MAC adresi
    mac_elem = host.find('./address[@addrtype="mac"]')
    if mac_elem is not None:
        host_data['mac'] = mac_elem.attrib.get('addr', '')
        host_data['vendor'] = mac_elem.attrib.get('vendor', '')
    else:
        host_data['mac'] = ''
        host_data['vendor'] = ''
    
    # Hostname
    hostname_elem = host.find('./hostnames/hostname[@type="PTR"]')
    if hostname_elem is not None:
        host_data['hostname'] = hostname_elem.attrib.get('name', '')
    else:
        host_data['hostname'] = ''
    
    # Host durumu
    status_elem = host.find('./status')
    if status_elem is not None:
        host_data['status'] = status_elem.attrib.get('state', 'Bilinmiyor')
        host_data['reason'] = status_elem.attrib.get('reason', '')
    else:
        host_data['status'] = 'Bilinmiyor'
        host_data['reason'] = ''
    
    # OS bilgisi
    os_elem = host.find('./os/osmatch')
    if os_elem is not None:
        host_data['os_name'] = os_elem.attrib.get('name', '')
        host_data['os_accuracy'] = os_elem.attrib.get('accuracy', '')
    else:
        host_data['os_name'] = ''
        host_data['os_accuracy'] = ''
    
    return host_data

def extract_port_data(host, host_data):
    """
    Bir host için tüm port verilerini çıkarır ve her port için bir liste öğesi döndürür.
    """
    port_data_list = []
    
    ports = host.findall('./ports/port')
    if not ports:
        # Port bulunamadıysa bile, bir satır döndür
        base_data = host_data.copy()
        base_data.update({
            'protocol': '',
            'port': '',
            'state': '',
            'reason': '',
            'service': '',
            'product': '',
            'version': '',
            'extrainfo': '',
            'cpe': '',
            'scripts': ''
        })
        port_data_list.append(base_data)
        return port_data_list
    
    for port in ports:
        port_data = host_data.copy()
        
        # Port numarası ve protokol
        port_data['protocol'] = port.attrib.get('protocol', '')
        port_data['port'] = port.attrib.get('portid', '')
        
        # Port durumu
        state_elem = port.find('./state')
        if state_elem is not None:
            port_data['state'] = state_elem.attrib.get('state', '')
            port_data['reason'] = state_elem.attrib.get('reason', '')
        else:
            port_data['state'] = ''
            port_data['reason'] = ''
        
        # Servis bilgisi
        service_elem = port.find('./service')
        if service_elem is not None:
            port_data['service'] = service_elem.attrib.get('name', '')
            port_data['product'] = service_elem.attrib.get('product', '')
            port_data['version'] = service_elem.attrib.get('version', '')
            port_data['extrainfo'] = service_elem.attrib.get('extrainfo', '')
            
            # CPE bilgisi
            cpe_elem = service_elem.find('./cpe')
            if cpe_elem is not None and cpe_elem.text:
                port_data['cpe'] = cpe_elem.text
            else:
                port_data['cpe'] = ''
        else:
            port_data['service'] = ''
            port_data['product'] = ''
            port_data['version'] = ''
            port_data['extrainfo'] = ''
            port_data['cpe'] = ''
        
        # Script sonuçları
        scripts = port.findall('./script')
        if scripts:
            script_results = []
            for script in scripts:
                script_id = script.attrib.get('id', '')
                script_output = script.attrib.get('output', '').replace('\n', ' ').replace('"', "'")
                script_results.append(f"{script_id}: {script_output}")
            port_data['scripts'] = '; '.join(script_results)
        else:
            port_data['scripts'] = ''
        
        port_data_list.append(port_data)
    
    return port_data_list

def parse_nmap_xml(xml_file):
    """
    Nmap XML dosyasını parse edip, host ve port verilerini çıkarır.
    """
    root = parse_xml_file(xml_file)
    if root is None:
        return {}, []
    
    scan_info = get_scan_info(root)
    
    all_data = []
    
    # Her host için veri çıkar
    for host in root.findall('.//host'):
        host_data = extract_host_data(host)
        port_data_list = extract_port_data(host, host_data)
        all_data.extend(port_data_list)
    
    return scan_info, all_data

def write_to_csv(scan_info, all_data, output_file):
    """
    Çıkarılan verileri CSV dosyasına yazar.
    """
    if not all_data:
        print("Uyarı: Yazılacak veri yok.")
        return False
    
    # Tüm alanları belirle
    fieldnames = [
        'ip', 'hostname', 'mac', 'vendor', 'status', 'reason', 
        'os_name', 'os_accuracy', 'protocol', 'port', 'state', 
        'reason', 'service', 'product', 'version', 'extrainfo', 
        'cpe', 'scripts'
    ]
    
    # Geçici dosya kullan
    temp_file = f"{output_file}.tmp"
    
    try:
        with open(temp_file, 'w', newline='', encoding='utf-8') as csvfile:
            # Üst bilgi satırını ekle
            csvfile.write("# Nmap Scan Results\n")
            csvfile.write(f"# Scanner: {scan_info['scanner_name']} {scan_info['scanner_version']}\n")
            csvfile.write(f"# Command: {scan_info['command']}\n")
            csvfile.write(f"# Start Time: {scan_info['start_time']}\n")
            csvfile.write(f"# Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n#\n")
            
            # CSV verisini yaz
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_data)
        
        # Taşımayı atomik olarak yap (dosya bozulmasını önler)
        shutil.move(temp_file, output_file)
        
        print(f"CSV dosyası başarıyla oluşturuldu: {output_file}")
        return True
    
    except IOError as e:
        print(f"Hata: CSV dosyası yazılamadı: {e}")
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        return False
    
    except Exception as e:
        print(f"Beklenmeyen hata: CSV dosyası yazılamadı: {e}")
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        return False

def get_incompatible_scan_types(scan_type: ScanType) -> Set[ScanType]:
    """
    Seçilen tarama tipi ile uyumsuz olan diğer tarama tiplerini döndürür.
    """
    # TCP, UDP ve belirli tarama tipleri arasındaki uyumsuzluklar
    tcp_types = {ScanType.TCP_CONNECT, ScanType.TCP_SYN, ScanType.TCP_ACK, 
                 ScanType.TCP_WINDOW, ScanType.TCP_MAIMON}
    
    udp_types = {ScanType.UDP_SCAN}
    
    special_types = {ScanType.FIN_SCAN, ScanType.XMAS_SCAN, ScanType.NULL_SCAN, 
                    ScanType.IP_PROTOCOL, ScanType.IDLE_SCAN}
    
    discovery_types = {ScanType.PING_SCAN, ScanType.SKIP_PING}
    
    if scan_type in tcp_types:
        return udp_types | special_types | discovery_types
    elif scan_type in udp_types:
        return tcp_types | special_types | discovery_types
    elif scan_type in special_types:
        return tcp_types | udp_types | discovery_types
    elif scan_type in discovery_types:
        return tcp_types | udp_types | special_types
    
    return set()

def estimate_scan_duration(request: ScanRequest) -> dict:
    """
    Tarama süresini tahmin eder ve tahmini dakika cinsinden döndürür
    """
    # Temel süre
    base_duration = 5  # dakika
    
    # Hedef tipine göre çarpan
    target_multiplier = {
        "ip": 1,
        "host": 1.2,
        "range": 5,
        "subnet": 10,
        "file": 5  # Dosya içeriğine bağlı, ortalama bir değer
    }.get(request.target_type, 1)
    
    # Port seçeneğine göre çarpan
    port_multiplier = {
        "single": 0.1,
        "range": lambda val: max(1, int(val.split("-")[1]) / 1000) if val and "-" in val else 3,
        "fast": 1,
        "top10": 0.5,
        "top1000": 3,
        "all": 10
    }
    
    if request.port_option == "range" and request.port_value:
        try:
            port_mult = port_multiplier["range"](request.port_value)
        except (ValueError, IndexError):
            port_mult = 3  # Hatalı değer durumunda varsayılan
    else:
        port_mult = port_multiplier.get(request.port_option, 1)
    
    # Tarama tipine göre çarpan
    scan_multiplier = {
        "sT": 2,
        "sS": 1.5,
        "sA": 2,
        "sW": 2.5,
        "sM": 3,
        "sU": 4,
        "sP": 0.5,
        "Pn": 1.5,
        "sF": 2.5,
        "sX": 2.5,
        "sN": 2.5,
        "sO": 3,
        "sI": 4
    }.get(request.scan_type, 1)
    
    # Servis algılama çarpanı
    service_multiplier = {
        "none": 1,
        "light": 1.5,
        "standard": 2,
        "aggressive": 4,
        "os": 3
    }.get(request.service_detection, 1)
    
    # Script çarpanı
    script_multiplier = {
        "none": 1,
        "default": 2,
        "discovery": 2,
        "safe": 1.5,
        "auth": 2,
        "broadcast": 1.5,
        "brute": 5,
        "vuln": 4,
        "exploit": 4,
        "intrusive": 3,
        "malware": 3,
        "dos": 4,
        "all": 10,
        "vulners": 3,
        "vulscan": 3
    }.get(request.script_category, 1)
    
    # Timing çarpanı
    timing_multiplier = {
        "T0": 10,
        "T1": 5,
        "T2": 3,
        "T3": 1,
        "T4": 0.7,
        "T5": 0.5
    }.get(request.timing_template, 1) if request.timing_template else 1
    
    # Toplam süre hesaplama
    estimated_duration = base_duration * target_multiplier * port_mult * scan_multiplier * service_multiplier * script_multiplier * timing_multiplier
    
    # Eğer çok uzun sürüyorsa saatlere dönüştür
    if estimated_duration > 60:
        hours = estimated_duration / 60
        return {
            "duration": round(hours, 1),
            "unit": "saat"
        }
    else:
        return {
            "duration": round(estimated_duration, 1),
            "unit": "dakika"
        }

def validate_target(target, target_type):
    """Validate target based on target_type"""
    if target_type == "ip":
        # Validate single IP
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    elif target_type == "host":
        # Validate hostname or just accept any non-empty string for host
        return bool(target)
    elif target_type == "range":
        # Validate IP range like 192.168.1.1-20
        range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$'
        return bool(re.match(range_pattern, target))
    elif target_type == "subnet":
        # Validate subnet like 192.168.1.0/24
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False
    elif target_type == "file":
        # Validate file exists
        return os.path.isfile(target)
    else:
        return False

# İlerleme izleyici fonksiyon
def update_progress_periodically(scan_id, start_time, est_duration_seconds):
    """Tarama ilerlemesini periyodik olarak güncelleyen thread fonksiyonu"""
    while True:
        try:
            # Tarama durumunu kontrol et
            scan_status = get_scan_status(scan_id)
            if not scan_status or scan_status.get("stop_updater", False):
                break
                
            # İlerlemeyi hesapla
            elapsed = time.time() - start_time
            progress_percent = min(80, int(30 + (elapsed / est_duration_seconds) * 50))
            
            # Durumu güncelle
            update_scan_status(scan_id, {
                "progress": progress_percent,
                "message": f"Nmap taraması devam ediyor... ({progress_percent}%)",
                "elapsed_seconds": round(elapsed)
            })
            
            # 2 saniye bekle
            time.sleep(2)
        except Exception as e:
            print(f"Progress updater error for scan {scan_id}: {e}")
            time.sleep(5)  # Hata durumunda daha uzun bekle

def run_scan_in_background(scan_id: str, request: ScanRequest):
    """Tarama işlemini arka planda çalıştırır"""
    lock_file_path = None
    progress_thread = None
    
    try:
        # Tarama durumunu güncelle
        update_scan_status(scan_id, {
            "status": ScanStatus.RUNNING,
            "progress": 5,
            "message": "Tarama başlatılıyor..."
        })
        
        # Validate target based on target_type
        if not validate_target(request.target, request.target_type):
            raise ValueError(f"Invalid target for type: {request.target_type}")

        # Use custom name if provided, otherwise use timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir_name = request.scan_name if request.scan_name else timestamp
        
        # Check if the directory already exists
        output_dir = os.path.join("outputs", output_dir_name)
        if os.path.exists(output_dir) and request.scan_name:
            raise ValueError(f"Scan name '{output_dir_name}' already exists")

        # Progress update
        update_scan_status(scan_id, {
            "progress": 10,
            "message": "Nmap komutu hazırlanıyor..."
        })

        # Build nmap command
        command = ["nmap"]
        
        # Add target
        if request.target_type == "file":
            command.extend(["-iL", request.target])
        else:
            command.append(request.target)
        
        # Add port options
        if request.port_option == PortOption.SINGLE and request.port_value:
            command.extend(["-p", request.port_value])
        elif request.port_option == PortOption.RANGE and request.port_value:
            command.extend(["-p", request.port_value])
        elif request.port_option == PortOption.FAST:
            command.append("-F")
        elif request.port_option == PortOption.ALL:
            command.append("-p-")
        elif request.port_option == PortOption.TOP_1000:
            command.extend(["-p", "1-1000"])
        elif request.port_option == PortOption.TOP_10:
            command.extend(["-p", "21,22,23,25,80,110,139,443,445,3389"])
        
        # Add scan type
        command.append(f"-{request.scan_type.value}")
        
        # Add service detection
        if request.service_detection == ServiceDetection.STANDARD:
            command.append("-sV")
        elif request.service_detection == ServiceDetection.LIGHT:
            command.extend(["-sV", "--version-intensity", "0"])
        elif request.service_detection == ServiceDetection.AGGRESSIVE:
            command.extend(["-sV", "--version-intensity", "9"])
        elif request.service_detection == ServiceDetection.OS_DETECT:
            command.append("-O")
        
        # Add version intensity if specified
        if request.version_intensity is not None and request.service_detection in [ServiceDetection.STANDARD, ServiceDetection.LIGHT, ServiceDetection.AGGRESSIVE]:
            command.extend(["--version-intensity", str(request.version_intensity)])
        
        # Add script options
        if request.script_category != ScriptCategory.NONE:
            if request.script_category == ScriptCategory.VULNERS:
                command.extend(["--script", "vulners"])
            elif request.script_category == ScriptCategory.VULSCAN:
                command.extend(["--script", "vulscan"])
            else:
                command.extend(["--script", request.script_category.value])
        
        # Add custom scripts if specified
        if request.custom_scripts:
            command.extend(["--script", request.custom_scripts])
        
        # Add timing template if specified
        if request.timing_template:
            command.append(f"-{request.timing_template.value}")
        
        # Progress update
        update_scan_status(scan_id, {
            "progress": 20,
            "message": "Nmap taraması başlatılıyor..."
        })
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Kilit dosyası oluştur
        lock_file_path = os.path.join(output_dir, ".lock")
        with open(lock_file_path, 'w') as lock_file:
            lock_file.write(f"PID: {os.getpid()}, Time: {datetime.now().isoformat()}")
        
        # Always create XML output for our parsing
        output_file = os.path.join(output_dir, "output.xml")
        command.extend(["-oX", output_file])
        
        # Add other output formats if requested
        if request.output_format == OutputFormat.NORMAL or request.output_format == OutputFormat.ALL:
            command.extend(["-oN", os.path.join(output_dir, "output.txt")])
        
        if request.output_format == OutputFormat.JSON or request.output_format == OutputFormat.ALL:
            command.extend(["-oJ", os.path.join(output_dir, "output.json")])
        
        if request.output_format == OutputFormat.GREPABLE or request.output_format == OutputFormat.ALL:
            command.extend(["-oG", os.path.join(output_dir, "output.gnmap")])
        
        # Estimate scan duration
        estimated_duration = estimate_scan_duration(request)
        
        try:
            # Log the command for debugging
            command_str = " ".join(command)
            print(f"Executing command: {command_str}")
            
            # Progress update
            update_scan_status(scan_id, {
                "progress": 30,
                "message": "Nmap taraması çalışıyor...",
                "command": command_str,
                "estimated_duration": estimated_duration
            })
            
            # Run nmap scan (non-blocking with Popen)
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Tahmini süreyi saniyeye çevir
            est_duration_seconds = estimated_duration["duration"] * 60  # dakikayı saniyeye çevir
            if estimated_duration["unit"] == "saat":
                est_duration_seconds *= 60  # saati dakikaya, dakikayı saniyeye çevir
            
            # İlerleme guncelleme thread'ini başlat
            start_time = time.time()
            progress_thread = threading.Thread(
                target=update_progress_periodically,
                args=(scan_id, start_time, est_duration_seconds),
                daemon=True
            )
            progress_thread.start()
            
            # Wait for process to complete
            stdout, stderr = process.communicate()
            
            # İlerleme thread'ini durdur
            update_scan_status(scan_id, {"stop_updater": True})
            if progress_thread and progress_thread.is_alive():
                progress_thread.join(timeout=5)
            
            # Check if process completed successfully
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command, stderr)
            
            # Progress update
            update_scan_status(scan_id, {
                "progress": 85,
                "message": "Tarama tamamlandı, sonuçlar işleniyor..."
            })
            
        except subprocess.CalledProcessError as e:
            error_message = f"Nmap execution error: {e}\nCommand: {' '.join(command)}\nStderr: {e.stderr}"
            print(error_message)
            update_scan_status(scan_id, {
                "status": ScanStatus.FAILED,
                "error": error_message
            })
            return
        
        # Progress update
        update_scan_status(scan_id, {
            "progress": 90,
            "message": "Sonuçlar kaydediliyor..."
        })
        
        # Create info.json file
        info_data = {
            "scan_name": output_dir_name,
            "date": datetime.now().strftime('%Y-%m-%d'),
            "time": datetime.now().strftime('%H:%M:%S'),
            "target": request.target,
            "target_type": request.target_type,
            "port_option": request.port_option,
            "port_value": request.port_value,
            "scan_type": request.scan_type,
            "service_detection": request.service_detection,
            "version_intensity": request.version_intensity,
            "script_category": request.script_category,
            "custom_scripts": request.custom_scripts,
            "timing_template": request.timing_template,
            "output_format": request.output_format,
            "estimated_duration": estimated_duration,
            "command": command_str,
            "scan_id": scan_id
        }
        
        # info.json dosyasını geçici dosyaya yaz
        info_temp = os.path.join(output_dir, "info.json.tmp")
        with open(info_temp, "w") as info_file:
            json.dump(info_data, info_file, indent=4)
        # Atomik taşıma
        shutil.move(info_temp, os.path.join(output_dir, "info.json"))
        
        # Parse XML and create CSV output - Parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            # XML'i parse et
            xml_future = executor.submit(parse_nmap_xml, output_file)
            
            # XML'i parse et ve sonuçları al
            scan_info, all_data = xml_future.result()
            
            # CSV'yi yaz
            csv_output_path = os.path.join(output_dir, "output.csv")
            csv_future = executor.submit(write_to_csv, scan_info, all_data, csv_output_path)
            csv_result = csv_future.result()
        
        # Paralel olarak zafiyet analizi başlat (background olarak)
        scan_for_vulnerabilities_background(output_dir_name, output_file)
        
        # Taramayı tamamlandı olarak işaretle
        update_scan_status(scan_id, {
            "status": ScanStatus.COMPLETED,
            "progress": 100,
            "message": "Tarama tamamlandı!",
            "output_dir": output_dir,
            "output_path": output_file,
            "csv_path": csv_output_path,
            "scan_name": output_dir_name
        })
        
        # Kilit dosyasını kaldır
        if lock_file_path and os.path.exists(lock_file_path):
            os.remove(lock_file_path)
        
    except Exception as e:
        # Hata durumunu kaydet
        update_scan_status(scan_id, {
            "status": ScanStatus.FAILED,
            "error": str(e),
            "message": f"Hata oluştu: {str(e)}"
        })
        print(f"Error in scan {scan_id}: {str(e)}")
        traceback.print_exc()
        
        # İlerleme thread'ini durdur
        if progress_thread and progress_thread.is_alive():
            update_scan_status(scan_id, {"stop_updater": True})
            progress_thread.join(timeout=2)
        
        # Kilit dosyasını kaldır
        if lock_file_path and os.path.exists(lock_file_path):
            try:
                os.remove(lock_file_path)
            except:
                pass

@app.post("/scan")
async def scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Yeni bir tarama başlatır ve arka planda çalıştırır"""
    try:
        # Benzersiz bir tarama ID'si oluştur
        scan_id = str(uuid.uuid4())
        
        # Tarama durumunu başlangıçta 'sırada' olarak ayarla
        with active_scans_lock:
            active_scans[scan_id] = {
                "status": ScanStatus.QUEUED,
                "created_at": datetime.now().isoformat(),
                "request": request.dict(),
                "progress": 0,
                "message": "Tarama sıraya alındı",
                "scan_name": request.scan_name,
                "target": request.target
            }
        
        # Tarama önceliğini belirle
        priority = 1  # Normal öncelik
        
        # Zafiyet taramaları ve özel scriptlere yüksek öncelik ver
        if request.script_category in [ScriptCategory.VULN, ScriptCategory.VULNERS, ScriptCategory.EXPLOIT]:
            priority = 0  # Yüksek öncelik (0 en yüksek)
        # Tüm port taraması gibi uzun süren işlemlere düşük öncelik ver
        elif request.port_option == PortOption.ALL or request.timing_template in [TimingTemplate.PARANOID, TimingTemplate.SNEAKY]:
            priority = 2  # Düşük öncelik
        
        # İş zamanlaycıya ekle
        scan_scheduler.add_scan(priority, scan_id, request)
        
        # Tahmini süreyi hesapla
        estimated_duration = estimate_scan_duration(request)
        
        return {
            "scan_id": scan_id,
            "status": ScanStatus.QUEUED,
            "message": "Tarama başlatıldı",
            "scan_name": request.scan_name,
            "estimated_duration": estimated_duration,
            "priority": priority
        }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Tarama başlatılırken hata: {str(e)}")

@app.get("/scan/{scan_id}/status")
async def get_scan_status_api(scan_id: str):
    """Belirli bir taramanın güncel durumunu döndürür"""
    try:
        with active_scans_lock:
            if scan_id not in active_scans:
                raise HTTPException(status_code=404, detail=f"Scan ID {scan_id} not found")
            
            return active_scans[scan_id]
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Tarama durumu alınırken hata: {str(e)}")

@app.get("/scans/active")
async def get_active_scans():
    """Aktif ve tamamlanmış taramaların listesini döndürür"""
    try:
        with active_scans_lock:
            active_scans_list = [
                {
                    "scan_id": scan_id,
                    "status": info["status"],
                    "created_at": info["created_at"],
                    "progress": info.get("progress", 0),
                    "message": info.get("message", ""),
                    "scan_name": info.get("scan_name", ""),
                    "target": info.get("target", "")
                }
                for scan_id, info in active_scans.items()
            ]
            
            return {
                "active_scans": active_scans_list
            }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Aktif taramalar alınırken hata: {str(e)}")

@app.get("/scan/check_name/{scan_name}")
async def check_scan_name(scan_name: str):
    """Bir tarama adının daha önce kullanılıp kullanılmadığını kontrol eder"""
    try:
        scan_path = os.path.join("outputs", scan_name)
        exists = os.path.exists(scan_path)
        return {"exists": exists}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Tarama adı kontrolünde hata: {str(e)}")

@app.get("/scans")
async def list_scans():
    """Tüm mevcut taramaların listesini ve meta verilerini döndürür"""
    try:
        output_dir = "outputs"
        if not os.path.exists(output_dir):
            return {"scans": []}
        
        scans = []
        
        # Çok sayıda tarama varsa, çoklu thread kullan
        scan_dirs = [d for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d))]
        
        with ThreadPoolExecutor(max_workers=min(10, len(scan_dirs) if len(scan_dirs) > 0 else 1)) as executor:
            # Her bir dizin için işleme fonksiyonu
            futures = {executor.submit(process_scan_dir, os.path.join(output_dir, scan_dir), scan_dir): scan_dir for scan_dir in scan_dirs}
            
            # Tamamlanan işleri topla
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    scans.append(result)
        
        return {"scans": scans}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Tarama listesi alınırken hata: {str(e)}")

def process_scan_dir(scan_path, scan_dir):
    """
    Tek bir tarama dizinini işleyip bilgilerini döndürür.
    Çoklu thread için kullanılır.
    """
    try:
        info_path = os.path.join(scan_path, "info.json")
        
        # Dizinde .lock dosyası varsa atla
        if os.path.exists(os.path.join(scan_path, ".lock")):
            return None
            
        # info.json dosyası yoksa basit bilgilerle dahil et
        if not os.path.exists(info_path):
            # Dosya oluşturma zamanını al
            creation_time = datetime.fromtimestamp(os.path.getctime(scan_path))
            return {
                "name": scan_dir,
                "info": {
                    "date": creation_time.strftime('%Y-%m-%d'),
                    "time": creation_time.strftime('%H:%M:%S'),
                    "target": "Bilinmiyor",
                    "target_type": "Bilinmiyor"
                }
            }
            
        try:
            with open(info_path, "r") as info_file:
                scan_info = json.load(info_file)
                return {
                    "name": scan_dir,
                    "info": scan_info
                }
        except json.JSONDecodeError:
            # JSON bozuksa, basit bilgilerle dahil et
            creation_time = datetime.fromtimestamp(os.path.getctime(scan_path))
            return {
                "name": scan_dir,
                "info": {
                    "date": creation_time.strftime('%Y-%m-%d'),
                    "time": creation_time.strftime('%H:%M:%S'),
                    "target": "Bilinmiyor (Bozuk bilgi dosyası)",
                    "target_type": "Bilinmiyor"
                }
            }
        
    except Exception as e:
        print(f"Error processing scan directory {scan_dir}: {e}")
        return None

@app.get("/scan/{scan_name}/details")
async def get_scan_details(scan_name: str):
    """Belirli bir tarama hakkında basit bilgileri döndürür"""
    try:
        # Minimum veri döndür
        return {
            "name": scan_name,
            "info": {
                "scan_name": scan_name,
                "date": datetime.now().strftime('%Y-%m-%d'),
                "time": datetime.now().strftime('%H:%M:%S'),
                "target": "Test hedef",
                "target_type": "ip"
            },
            "files": {},
            "data": [],
            "columns": []
        }
    except Exception as e:
        print(f"Hata oluştu: {str(e)}")
        traceback.print_exc()
        # Hatanın detaylarını döndür
        return JSONResponse(
            status_code=200,  # 500 yerine 200 döndür ama hata bilgisini içerde ver
            content={
                "name": scan_name,
                "info": {
                    "scan_name": scan_name,
                    "error": str(e)
                },
                "error_details": traceback.format_exc(),
                "files": {},
                "data": [],
                "columns": []
            }
        )

@app.get("/scan/{scan_name}/table")
async def get_scan_table(scan_name: str):
    """Get tabular data for a scan as JSON"""
    try:
        scan_path = os.path.join("outputs", scan_name)
        
        # Tarama hala çalışıyorsa uygun mesaj döndür
        if os.path.exists(os.path.join(scan_path, ".lock")):
            return {
                "columns": ["Bilgi"],
                "data": [["Tarama devam ediyor, sonuçlar henüz hazır değil."]]
            }
        
        csv_path = os.path.join(scan_path, "output.csv")
        
        if not os.path.exists(csv_path):
            # CSV yoksa XML'den veriler çıkartılabilir
            xml_path = os.path.join(scan_path, "output.xml")
            if os.path.exists(xml_path):
                scan_info, all_data = parse_nmap_xml(xml_path)
                if all_data:
                    # Verileri CSV'ye yaz
                    write_to_csv(scan_info, all_data, csv_path)
                else:
                    return {
                        "columns": ["Bilgi"],
                        "data": [["Henüz tarama verisi mevcut değil."]]
                    }
            else:
                return {
                    "columns": ["Bilgi"],
                    "data": [["Tarama veri dosyaları bulunamadı."]]
                }
        
        try:
            # Dosya boyutunu kontrol et
            if os.path.getsize(csv_path) == 0:
                return {
                    "columns": ["Bilgi"],
                    "data": [["CSV dosyası boş, tarama tamamlanmamış olabilir."]]
                }
            
            # Dinamik yorum satırı tespiti
            with open(csv_path, 'r', encoding='utf-8') as f:
                comment_lines = 0
                for line in f:
                    if line.startswith('#'):
                        comment_lines += 1
                    else:
                        break
            
            # CSV verisini oku, yorum satırlarını atla
            df = pd.read_csv(csv_path, skiprows=comment_lines)
            
            # NaN değerlerini boş string ile değiştir (JSON uyumlu olması için)
            df = df.fillna("")
            
            # DataFrame'i JSON formatına dönüştür
            table_data = {
                "columns": df.columns.tolist(),
                "data": df.values.tolist()
            }
            
            # Güvenli serileştirme
            return JSONResponse(content=jsonable_encoder(table_data))
        except pd.errors.EmptyDataError:
            return {
                "columns": ["Bilgi"],
                "data": [["CSV dosyası boş veya hatalı format."]]
            }
        except Exception as e:
            traceback.print_exc()
            return {
                "columns": ["Hata"],
                "data": [[f"CSV okuma hatası: {str(e)}"]]
            }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Tablo verileri alınırken hata oluştu: {str(e)}")

# YENİ ENDPOINT: Dosya içeriğini alma
@app.get("/scan/{scan_name}/file/{file_name}")
async def get_file_content(scan_name: str, file_name: str):
    """Belirli bir tarama için dosya içeriğini döndürür"""
    try:
        scan_path = os.path.join("outputs", scan_name)
        file_path = os.path.join(scan_path, file_name)
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail=f"Dosya bulunamadı: {file_name}")
        
        # Dosya boyutunu kontrol et
        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB limit
            return {"content": "Dosya çok büyük, web arayüzünden görüntülenemiyor"}
        
        # Dosya içeriğini oku
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        return {"content": content}
    
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Dosya içeriği alınırken hata oluştu: {str(e)}")

# Zafiyet taraması fonksiyonları (multi-threaded)
def scan_for_vulnerabilities_background(scan_name: str, xml_path: str):
    """Zafiyet taramasını arka planda başlatan yardımcı fonksiyon"""
    thread = threading.Thread(
        target=scan_for_vulnerabilities_thread,
        args=(scan_name, xml_path),
        daemon=True
    )
    thread.start()
    return True

def scan_for_vulnerabilities_thread(scan_name: str, xml_path: str):
    """Zafiyet taramasını arka planda yapan thread fonksiyonu"""
    try:
        exploit_path = os.path.join("outputs", scan_name, "exploits.json")
        
        if not os.path.exists(xml_path):
            print(f"XML dosyası bulunamadı: {xml_path}")
            return
        
        # Eğer zafiyet dosyası yoksa, zafiyetleri ara
        if not os.path.exists(exploit_path):
            vulnerabilities = scan_for_vulnerabilities(scan_name, xml_path)
            
            # Exploits dosyasını kaydet
            os.makedirs(os.path.dirname(exploit_path), exist_ok=True)
            with open(exploit_path, 'w', encoding='utf-8') as f:
                json.dump(vulnerabilities, f, indent=4, ensure_ascii=False)
                
            print(f"Zafiyet taraması tamamlandı: {scan_name}")
            
    except Exception as e:
        print(f"Zafiyet taraması sırasında hata oluştu: {e}")
        traceback.print_exc()

def scan_for_vulnerabilities(scan_name: str, xml_path: str) -> Dict[str, Any]:
    """Birden fazla araç kullanarak zafiyetleri tarar ve sonuçları döndürür"""
    try:
        services = extract_services_from_xml(xml_path)
        
        # Sonuçları saklamak için yapı
        results = {
            "timestamp": scan_name,
            "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "services": []
        }
        
        # Her servis için paralel olarak zafiyet taraması yap
        if not services:
            return results
            
        # Çok fazla servis için threadpool büyüklüğünü sınırla
        max_parallel = min(len(services), 5)
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            # Her servis için zafiyet taraması yap
            future_to_service = {executor.submit(scan_service_vulnerabilities, service): service for service in services}
            
            # Sonuçları topla
            for future in concurrent.futures.as_completed(future_to_service):
                service = future_to_service[future]
                try:
                    service_results = future.result()
                    if service_results and service_results.get("vulnerabilities"):
                        results["services"].append(service_results)
                except Exception as e:
                    print(f"Servis zafiyet taraması sırasında hata: {e} - {service['ip']}:{service['port']}")
        
        return results
    
    except Exception as e:
        print(f"Zafiyet taraması sırasında hata: {e}")
        traceback.print_exc()
        # Hata durumunda boş sonuç yapısı oluştur
        return {
            "timestamp": scan_name,
            "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "error": str(e),
            "services": []
        }

def scan_service_vulnerabilities(service):
    """Tek bir servis için tüm zafiyet taramalarını yapar"""
    try:
        service_results = {
            "ip": service["ip"],
            "port": service["port"],
            "protocol": service["protocol"],
            "service": service["service"],
            "product": service["product"],
            "version": service["version"],
            "vulnerabilities": []
        }
        
        # Farklı tarama araçlarını paralel olarak çalıştır
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            # 1. Searchsploit ile ara
            if service["product"]:
                futures.append(executor.submit(search_with_searchsploit, service["product"], service["version"]))
            
            # 2. Vulners NSE script ile ara (eğer ip ve port bilgisi varsa)
            if service["ip"] and service["port"]:
                futures.append(executor.submit(scan_with_vulners_nse, service["ip"], service["port"]))
            
            # 3. CVE veritabanı (simüle edilmiş)
            if service["product"]:
                futures.append(executor.submit(search_cve_database, service["product"], service["version"]))
            
            # 4. Eğer HTTP/HTTPS servisi ise Nikto ile tara
            is_web = service["service"].lower() in ["http", "https"]
            if is_web and service["ip"] and service["port"]:
                nikto_future = executor.submit(scan_with_nikto, service["ip"], service["port"])
                futures.append(nikto_future)
            
            # 5. Eğer önemli servisler ise vulscan ile tara
            if service["service"].lower() in ["ssh", "ftp", "telnet", "smtp", "mysql", "mssql"]:
                futures.append(executor.submit(scan_with_vulscan_nse, service["ip"], service["port"]))
            
            # Tüm sonuçları topla
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        service_results["vulnerabilities"].extend(result)
                except Exception as e:
                    print(f"Zafiyet tarama aracı hatası: {e}")
                    
        return service_results
    except Exception as e:
        print(f"Servis zafiyet taraması hatası: {e}")
        return None

def extract_services_from_xml(xml_path: str) -> List[Dict[str, str]]:
    """Nmap XML çıktısından servis ve versiyon bilgilerini çıkarır"""
    services = []
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        for host in root.findall(".//host"):
            ip = ""
            # IP adresini al
            address = host.find("./address[@addrtype='ipv4']")
            if address is not None:
                ip = address.get("addr", "")
            
            # Portları ve servisleri işle
            for port in host.findall(".//ports/port"):
                port_id = port.get("portid", "")
                protocol = port.get("protocol", "")
                
                # Port durumunu kontrol et - sadece açık portları al
                state = port.find("./state")
                if state is not None and state.get("state") != "open":
                    continue
                
                service_elem = port.find("./service")
                if service_elem is not None:
                    service = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    
                    if service:
                        services.append({
                            "ip": ip,
                            "port": port_id,
                            "protocol": protocol,
                            "service": service,
                            "product": product,
                            "version": version
                        })
        
        return services
    
    except Exception as e:
        print(f"XML'den servis çıkarma hatası: {e}")
        traceback.print_exc()
        return []

# Zafiyet tarama araçları için fonksiyonlar
def search_with_searchsploit(product: str, version: str) -> List[Dict[str, str]]:
    """Searchsploit kullanarak exploit ara"""
    vulnerabilities = []
    
    if not product:
        return vulnerabilities
    
    # Arama terimi oluştur
    search_term = product
    if version:
        search_term += f" {version}"
    
    try:
        # Searchsploit'i çalıştır
        cmd = ["searchsploit", "--json", search_term]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
        
        # JSON çıktısını işle
        try:
            if result.stdout:
                data = json.loads(result.stdout)
                if "RESULTS_EXPLOIT" in data and data["RESULTS_EXPLOIT"]:
                    for exploit in data["RESULTS_EXPLOIT"]:
                        vulnerabilities.append({
                            "tool": "searchsploit",
                            "title": exploit.get("Title", "Bilinmeyen Exploit"),
                            "id": exploit.get("EDB-ID", ""),
                            "risk": "Exploit Mevcut",
                            "description": exploit.get("Description", exploit.get("Title", "")),
                            "reference": f"https://www.exploit-db.com/exploits/{exploit.get('EDB-ID', '')}"
                        })
        except json.JSONDecodeError:
            # JSON analiz edilemezse, düz metin sonuçları işle
            lines = result.stdout.split('\n')
            for line in lines:
                if search_term.lower() in line.lower() and "|" in line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        title = parts[1].strip()
                        vulnerabilities.append({
                            "tool": "searchsploit",
                            "title": title,
                            "id": "Bilinmeyen",
                            "risk": "Exploit Mevcut",
                            "description": title,
                            "reference": "https://www.exploit-db.com/"
                        })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"Searchsploit çalıştırma hatası: {e}")
        return vulnerabilities

def scan_with_vulners_nse(ip: str, port: str) -> List[Dict[str, str]]:
    """Nmap Vulners script kullanarak zafiyet tara"""
    vulnerabilities = []
    
    if not ip or not port:
        return vulnerabilities
    
    try:
        # Nmap vulners scriptini çalıştır
        cmd = ["nmap", "--script", "vulners", "-p", port, ip]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        
        # Çıktıyı işle - regex ile CVE ID'leri ve CVSS skorlarını çıkar
        output = result.stdout
        vulnerabilities_found = False
        
        # CVE ve CVSS değerlerini çıkar
        cve_pattern = r'(CVE-\d{4}-\d{4,})\s+(\d+\.\d+)'
        matches = re.findall(cve_pattern, output)
        
        for match in matches:
            cve_id, cvss = match
            vulnerabilities_found = True
            
            # CVSS skora göre risk seviyesini belirle
            risk = "Düşük"
            try:
                cvss_float = float(cvss)
                if cvss_float >= 9.0:
                    risk = "Kritik"
                elif cvss_float >= 7.0:
                    risk = "Yüksek"
                elif cvss_float >= 4.0:
                    risk = "Orta"
                else:
                    risk = "Düşük"
            except ValueError:
                risk = "Bilinmeyen"
            
            vulnerabilities.append({
                "tool": "vulners",
                "title": f"Port {port}'deki serviste güvenlik açığı",
                "id": cve_id,
                "risk": risk,
                "description": f"CVSS Skoru: {cvss}",
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"Vulners script çalıştırma hatası: {e}")
        return vulnerabilities

def scan_with_vulscan_nse(ip: str, port: str) -> List[Dict[str, str]]:
    """Nmap Vulscan script kullanarak zafiyet tara"""
    vulnerabilities = []
    
    if not ip or not port:
        return vulnerabilities
    
    try:
        # Nmap vulscan scriptini çalıştır
        cmd = ["nmap", "--script", "vulscan", "-p", port, ip]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        
        # Çıktıyı işle
        output = result.stdout
        vulscan_pattern = r'((?:CVE|BID|OSVDB|SECUNIA|EDB-ID|MSFT)[-:]\d+)\s+(.+?)(?=\n|$)'
        matches = re.findall(vulscan_pattern, output)
        
        for match in matches:
            vuln_id, description = match
            vuln_type = vuln_id.split('-')[0] if '-' in vuln_id else vuln_id.split(':')[0]
            
            # Referans URL oluştur
            reference = ""
            if vuln_type == "CVE":
                reference = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
            elif vuln_type == "EDB-ID":
                reference = f"https://www.exploit-db.com/exploits/{vuln_id.split('-')[2]}"
            
            vulnerabilities.append({
                "tool": "vulscan",
                "title": description,
                "id": vuln_id,
                "risk": "Bilinmeyen",  # Vulscan risk seviyesi sağlamıyor
                "description": description,
                "reference": reference
            })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"Vulscan script çalıştırma hatası: {e}")
        return vulnerabilities

def scan_with_nikto(ip: str, port: str) -> List[Dict[str, str]]:
    """Nikto kullanarak web sunucusu güvenlik açıklarını tara"""
    vulnerabilities = []
    
    if not ip or not port:
        return vulnerabilities
    
    try:
        # Nikto'yu çalıştır
        protocol = "https" if port == "443" else "http"
        cmd = ["nikto", "-h", f"{protocol}://{ip}:{port}", "-Format", "txt"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        
        # Çıktıyı işle - Nikto OSVDB ve CVE formatlarını bul
        output = result.stdout
        
        # OSVDB referanslarını bul
        osvdb_pattern = r'OSVDB-(\d+).*?:\s+(.*?)(?=\n|$)'
        osvdb_matches = re.findall(osvdb_pattern, output)
        
        for match in osvdb_matches:
            osvdb_id, description = match
            vulnerabilities.append({
                "tool": "nikto",
                "title": description,
                "id": f"OSVDB-{osvdb_id}",
                "risk": "Orta",
                "description": description,
                "reference": f"https://vulndb.cyberriskanalytics.com/vulnerabilities/{osvdb_id}"
            })
        
        # CVE referanslarını bul
        cve_pattern = r'(CVE-\d{4}-\d{4,}).*?:\s+(.*?)(?=\n|$)'
        cve_matches = re.findall(cve_pattern, output)
        
        for match in cve_matches:
            cve_id, description = match
            vulnerabilities.append({
                "tool": "nikto",
                "title": description,
                "id": cve_id,
                "risk": "Orta",
                "description": description,
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        
        return vulnerabilities
    
    except Exception as e:
        print(f"Nikto çalıştırma hatası: {e}")
        return vulnerabilities

def search_cve_database(product: str, version: str) -> List[Dict[str, str]]:
    """CVE veritabanında zafiyet ara (simülasyon)"""
    vulnerabilities = []
    
    if not product:
        return vulnerabilities
    
    # Yaygın yazılımlar için bazı ortak CVE'ler
    common_vulns = {
        "apache": [
            {"id": "CVE-2021-44790", "title": "Apache HTTP Server buffer overflow", "risk": "Kritik", 
             "description": "Apache HTTP Server'da mod_lua script işleme sırasında meydana gelen bellek ile ilgili bir güvenlik açığı.", 
             "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44790"}
        ],
        "nginx": [
            {"id": "CVE-2022-41741", "title": "Nginx Bellek Sızıntısı", "risk": "Orta", 
             "description": "Nginx HTTP/3 uygulamasında bellek sızıntısı sorunu.", 
             "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-41741"}
        ],
        "mysql": [
            {"id": "CVE-2022-21417", "title": "MySQL Yetki Yükseltme", "risk": "Yüksek", 
             "description": "MySQL Server'da yetki yükseltme açığı.", 
             "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-21417"}
        ],
        "openssh": [
            {"id": "CVE-2021-28041", "title": "OpenSSH scp açığı", "risk": "Orta", 
             "description": "OpenSSH scp istemcisinde güvenlik açığı.", 
             "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-28041"}
        ],
        "vsftpd": [
            {"id": "CVE-2011-2523", "title": "VSFTPD Backdoor", "risk": "Kritik", 
             "description": "VSFTPD 2.3.4 backdoor güvenlik açığı.", 
             "reference": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"}
        ]
    }
    
    # Ürün adını normalize et
    product_lower = product.lower()
    
    # Her bir ürün için kontrol et
    for prod, vulns in common_vulns.items():
        if prod in product_lower:
            # Versiyon kontrolü ekle (gerçekte daha karmaşık olmalı)
            for vuln in vulns:
                vuln["tool"] = "cvedetails"
                vulnerabilities.append(vuln)
    
    return vulnerabilities

@app.get("/scan/{scan_name}/vulnerabilities")
async def get_scan_vulnerabilities(scan_name: str):
    """Bir tarama için zafiyet bilgilerini döndürür"""
    try:
        xml_path = os.path.join("outputs", scan_name, "output.xml")
        exploit_path = os.path.join("outputs", scan_name, "exploits.json")
        
        if not os.path.exists(xml_path):
            return JSONResponse(content={
                "timestamp": scan_name,
                "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "error": "XML dosyası bulunamadı",
                "services": []
            })
        
        # Eğer zafiyet dosyası yoksa, zafiyetleri ara
        if not os.path.exists(exploit_path):
            # Eğer henüz yoksa başlat ve bekliyor mesajı döndür
            scan_for_vulnerabilities_background(scan_name, xml_path)
            return JSONResponse(content={
                "timestamp": scan_name,
                "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "message": "Zafiyet taraması başlatıldı, sonuçlar hazırlanıyor...",
                "status": "processing",
                "services": []
            })
        else:
            # Zafiyet dosyasını oku
            with open(exploit_path, 'r', encoding='utf-8') as f:
                vulnerabilities = json.load(f)
            
            return JSONResponse(content=vulnerabilities)
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(content={
            "timestamp": scan_name,
            "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "error": f"Zafiyet verileri işlenirken hata: {str(e)}",
            "services": []
        })

@app.get("/scan/incompatible/{scan_type}")
async def get_incompatible_scans(scan_type: ScanType):
    """
    Belirli bir tarama tipi ile uyumsuz olan tarama tiplerini döndürür
    """
    try:
        incompatible = get_incompatible_scan_types(scan_type)
        return {"incompatible_types": list(incompatible)}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Uyumsuz tarama tipleri alınırken hata: {str(e)}")

@app.get("/scan/estimate")
async def estimate_scan(
    target_type: str,
    port_option: PortOption,
    port_value: Optional[str] = None,
    scan_type: ScanType = ScanType.TCP_CONNECT,
    service_detection: ServiceDetection = ServiceDetection.NONE,
    version_intensity: Optional[int] = None,
    script_category: ScriptCategory = ScriptCategory.NONE,
    custom_scripts: Optional[str] = None,
    timing_template: Optional[TimingTemplate] = None,
):
    """
    Tarama süresini tahmin eder ve tahmini dakika cinsinden döndürür
    """
    try:
        request = ScanRequest(
            target="dummy",  # Bu endpoint için hedef önemli değil
            target_type=target_type,
            port_option=port_option,
            port_value=port_value,
            scan_type=scan_type,
            service_detection=service_detection,
            version_intensity=version_intensity,
            script_category=script_category,
            custom_scripts=custom_scripts,
            timing_template=timing_template
        )
        
        estimated_duration = estimate_scan_duration(request)
        return {"estimated_duration": estimated_duration}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Tarama süresi tahmin edilirken hata: {str(e)}")