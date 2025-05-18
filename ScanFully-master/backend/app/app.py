import streamlit as st
import requests
import json
import os
import xml.dom.minidom
import pandas as pd
from enum import Enum
import time
import threading
import uuid
import traceback

# Enum sınıfları
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

# Tarama süresi tahminleri (dakika)
SCAN_DURATION_ESTIMATES = {
    "single": {
        "description": "1 port için tarama yapar, 10-30 saniye",
        "duration": 0.5,
        "unit": "dakika"
    },
    "range": {
        "description": "Belirtilen port aralığını tarar",
        "duration": 3,
        "unit": "dakika"
    },
    "fast": {
        "description": "Yaygın 100 portu tarar",
        "duration": 1,
        "unit": "dakika"
    },
    "top10": {
        "description": "En yaygın 10 portu tarar",
        "duration": 0.5,
        "unit": "dakika"
    },
    "top1000": {
        "description": "En yaygın 1000 portu tarar",
        "duration": 3,
        "unit": "dakika" 
    },
    "all": {
        "description": "Tüm portları (65535) tarar, çok uzun sürer",
        "duration": 10,
        "unit": "dakika"
    }
}

# Tarama tipi açıklamaları ve süreleri
SCAN_TYPE_INFO = {
    "sT": {
        "name": "TCP Connect tarama (standart)",
        "description": "Standart TCP bağlantı taraması, en güvenilir",
        "duration_factor": 2.0,
        "requires_root": False,
        "stealth": "Düşük (IDS'ler kolayca tespit eder)"
    },
    "sS": {
        "name": "TCP SYN tarama (hızlı, yarı-gizli)",
        "description": "Yarım bağlantı kurar, hızlı ve biraz daha gizli",
        "duration_factor": 1.5,
        "requires_root": True,
        "stealth": "Orta (IDS'ler yine de tespit edebilir)"
    },
    "sA": {
        "name": "TCP ACK tarama (firewall keşfi)",
        "description": "Firewall kurallarını tespit etmek için",
        "duration_factor": 2.0,
        "requires_root": True,
        "stealth": "Orta"
    },
    "sW": {
        "name": "TCP Window tarama",
        "description": "Windows size değerlerini kullanarak kapalı/açık port tespiti",
        "duration_factor": 2.5,
        "requires_root": True,
        "stealth": "Orta-Yüksek"
    },
    "sM": {
        "name": "TCP Maimon tarama",
        "description": "Özel bir FIN/ACK taraması",
        "duration_factor": 3.0,
        "requires_root": True,
        "stealth": "Yüksek"
    },
    "sU": {
        "name": "UDP portları tarama",
        "description": "UDP portlarını tarar, yavaştır",
        "duration_factor": 4.0,
        "requires_root": True,
        "stealth": "Düşük-Orta"
    },
    "sP": {
        "name": "Sadece ping taraması",
        "description": "Çalışan sistemleri bulmak için sadece ping taraması",
        "duration_factor": 0.5,
        "requires_root": False,
        "stealth": "Düşük"
    },
    "Pn": {
        "name": "Ping taramasını atla - tüm hostları çevrimiçi varsay",
        "description": "Ping atlamadan direkt port taraması yapar",
        "duration_factor": 1.5,
        "requires_root": False,
        "stealth": "Düşük"
    },
    "sF": {
        "name": "FIN tarama",
        "description": "Sadece FIN flag'i gönderir, gizli bir tarama",
        "duration_factor": 2.5,
        "requires_root": True,
        "stealth": "Yüksek"
    },
    "sX": {
        "name": "Xmas tarama",
        "description": "FIN, PSH ve URG flag'lerini gönderir, gizli bir tarama",
        "duration_factor": 2.5,
        "requires_root": True,
        "stealth": "Yüksek"
    },
    "sN": {
        "name": "Null tarama",
        "description": "Hiçbir flag göndermeyen gizli bir tarama",
        "duration_factor": 2.5,
        "requires_root": True,
        "stealth": "Yüksek"
    },
    "sO": {
        "name": "IP protokol taraması",
        "description": "Hangi IP protokollerinin desteklendiğini bulur",
        "duration_factor": 3.0,
        "requires_root": True,
        "stealth": "Orta"
    },
    "sI": {
        "name": "Idle tarama (ileri seviye)",
        "description": "Zombi makine kullanarak kimliğinizi gizleyen tarama",
        "duration_factor": 4.0,
        "requires_root": True,
        "stealth": "Çok Yüksek"
    }
}

# Servis tespit açıklamaları ve süreleri
SERVICE_DETECTION_INFO = {
    "none": {
        "name": "Yok",
        "description": "Servis tespiti yapma, sadece port açık/kapalı bilgisi",
        "duration_factor": 1.0
    },
    "light": {
        "name": "Hafif banner yakalama",
        "description": "Sadece temel banner bilgilerini alır, hızlı",
        "duration_factor": 1.5
    },
    "standard": {
        "name": "Standart servis algılama",
        "description": "Açık portlardaki servisleri tespit eder",
        "duration_factor": 2.0
    },
    "aggressive": {
        "name": "Agresif servis algılama",
        "description": "Daha detaylı servis ve versiyon bilgisi, yavaş",
        "duration_factor": 4.0
    },
    "os": {
        "name": "İşletim sistemi tespiti",
        "description": "İşletim sistemi parmak izi tespiti yapar",
        "duration_factor": 3.0,
        "requires_root": True
    }
}

# Script kategorileri açıklamaları ve süreleri
SCRIPT_CATEGORY_INFO = {
    "none": {
        "name": "Yok",
        "description": "NSE scriptleri kullanma",
        "duration_factor": 1.0
    },
    "default": {
        "name": "Varsayılan scriptler",
        "description": "Güvenli ve hızlı NSE scriptlerini çalıştırır",
        "duration_factor": 2.0
    },
    "discovery": {
        "name": "Keşif scriptleri",
        "description": "Sistemler hakkında ek bilgi toplar",
        "duration_factor": 2.0
    },
    "safe": {
        "name": "Güvenli scriptler",
        "description": "Hedef sistemlere zarar vermeyen scriptler",
        "duration_factor": 1.5
    },
    "auth": {
        "name": "Kimlik doğrulama scriptleri",
        "description": "Kimlik doğrulama mekanizmalarını test eder",
        "duration_factor": 2.0
    },
    "broadcast": {
        "name": "Yayın scriptleri",
        "description": "Yerel ağ keşfi için yayın scriptleri",
        "duration_factor": 1.5
    },
    "brute": {
        "name": "Kaba kuvvet scriptleri",
        "description": "Şifre kırma ve kaba kuvvet saldırı scriptleri",
        "duration_factor": 5.0
    },
    "vuln": {
        "name": "Güvenlik açığı scriptleri",
        "description": "Güvenlik açıklarını tespit eder",
        "duration_factor": 4.0
    },
    "exploit": {
        "name": "Exploit scriptleri",
        "description": "Güvenlik açıklarını istismar eden scriptler",
        "duration_factor": 4.0
    },
    "intrusive": {
        "name": "İzinsiz giriş scriptleri",
        "description": "Agresif ve izinsiz giriş deneyen scriptler",
        "duration_factor": 3.0
    },
    "malware": {
        "name": "Zararlı yazılım scriptleri",
        "description": "Zararlı yazılım tespit scriptleri",
        "duration_factor": 3.0
    },
    "dos": {
        "name": "DoS scriptleri",
        "description": "Servis dışı bırakma saldırısı scriptleri",
        "duration_factor": 4.0
    },
    "all": {
        "name": "Tüm scriptler",
        "description": "Tüm NSE scriptlerini çalıştırır, çok uzun sürer",
        "duration_factor": 10.0
    },
    "vulners": {
        "name": "Vulners.com veritabanı taraması",
        "description": "Vulners.com'daki güvenlik açıklarını kontrol eder",
        "duration_factor": 3.0
    },
    "vulscan": {
        "name": "Offline veritabanı taraması",
        "description": "Offline güvenlik açığı veritabanını kullanır",
        "duration_factor": 3.0
    }
}

# Timing şablonları açıklamaları
TIMING_TEMPLATE_INFO = {
    "T0": {
        "name": "Paranoid (T0)",
        "description": "Çok yavaş, IDS sistemlerinden kaçınmak için",
        "duration_factor": 10.0
    },
    "T1": {
        "name": "Sneaky (T1)",
        "description": "Yavaş, IDS sistemlerine yakalanma riski az",
        "duration_factor": 5.0
    },
    "T2": {
        "name": "Polite (T2)",
        "description": "Normal hızdan yavaş, bant genişliğini az kullanır",
        "duration_factor": 3.0
    },
    "T3": {
        "name": "Normal (T3)",
        "description": "Varsayılan ayar, normal hız",
        "duration_factor": 1.0
    },
    "T4": {
        "name": "Aggressive (T4)",
        "description": "Daha hızlı tarama, iyi bağlantılar için",
        "duration_factor": 0.7
    },
    "T5": {
        "name": "Insane (T5)",
        "description": "Çok hızlı, doğruluktan ödün verir",
        "duration_factor": 0.5
    }
}

# Hedef türleri açıklamaları
TARGET_TYPE_INFO = {
    "ip": {
        "name": "Tek IP Adresi",
        "description": "Tek bir IP adresini tarar",
        "example": "192.168.1.1",
        "duration_factor": 1.0
    },
    "host": {
        "name": "Hostname",
        "description": "Belirli bir hostname/domain adresini tarar",
        "example": "www.example.com",
        "duration_factor": 1.2
    },
    "range": {
        "name": "IP Aralığı",
        "description": "Belirli bir IP aralığını tarar",
        "example": "192.168.1.1-20",
        "duration_factor": 5.0
    },
    "subnet": {
        "name": "Alt Ağ",
        "description": "Belirli bir alt ağı tarar",
        "example": "192.168.1.0/24",
        "duration_factor": 10.0
    },
    "file": {
        "name": "IP Listesi Dosyası",
        "description": "Dosyadan IP adreslerini okuyarak tarar",
        "example": "list-of-ips.txt",
        "duration_factor": 5.0
    }
}

# Çıktı formatları açıklamaları
OUTPUT_FORMAT_INFO = {
    "normal": {
        "name": "Normal",
        "description": "Standart Nmap çıktısı"
    },
    "xml": {
        "name": "XML",
        "description": "XML formatında çıktı"
    },
    "json": {
        "name": "JSON",
        "description": "JSON formatında çıktı"
    },
    "grepable": {
        "name": "Grepable",
        "description": "Grep ile işlenebilir çıktı formatı"
    },
    "all": {
        "name": "Tüm Formatlar",
        "description": "Tüm çıktı formatlarını kaydeder"
    }
}

# Session state değişkenleri
if 'scan_name' not in st.session_state:
    st.session_state.scan_name = None
if 'show_scan_form' not in st.session_state:
    st.session_state.show_scan_form = False
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False
if 'scan_result' not in st.session_state:
    st.session_state.scan_result = None
if 'scan_error' not in st.session_state:
    st.session_state.scan_error = None
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 0
if 'active_scans' not in st.session_state:
    st.session_state.active_scans = {}
if 'monitoring_scans' not in st.session_state:
    st.session_state.monitoring_scans = set()
if 'last_api_check' not in st.session_state:
    st.session_state.last_api_check = 0
if 'api_available' not in st.session_state:
    st.session_state.api_available = True

# API URL 
API_URL = "http://127.0.0.1:8000"

# Yardımcı fonksiyonlar
def is_api_available():
    """API servisinin çalışıp çalışmadığını kontrol eder"""
    # Son kontrolden 5 saniye geçtiyse tekrar kontrol et
    current_time = time.time()
    if current_time - st.session_state.last_api_check > 5:
        try:
            response = requests.get(f"{API_URL}/scans/active", timeout=2)
            is_available = response.status_code == 200
            st.session_state.api_available = is_available
            st.session_state.last_api_check = current_time
            return is_available
        except:
            st.session_state.api_available = False
            st.session_state.last_api_check = current_time
            return False
    return st.session_state.api_available

def safe_api_call(endpoint, method="get", data=None, params=None, error_message="API hatası", default_return=None):
    """API çağrılarını hata kontrolü ile yap"""
    if not is_api_available():
        st.error("API servisi çalışmıyor. Lütfen backend servisini kontrol edin.")
        return default_return
    
    try:
        if method.lower() == "get":
            response = requests.get(f"{API_URL}{endpoint}", params=params, timeout=10)
        elif method.lower() == "post":
            response = requests.post(f"{API_URL}{endpoint}", json=data, timeout=10)
        else:
            return default_return
        
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"{error_message}: {response.status_code} - {response.text}")
            return default_return
    except requests.exceptions.RequestException as e:
        st.error(f"{error_message}: {str(e)}")
        return default_return
    except json.JSONDecodeError:
        st.error(f"{error_message}: Geçersiz JSON yanıtı")
        return default_return
    except Exception as e:
        st.error(f"{error_message}: {str(e)}")
        traceback.print_exc()
        return default_return

def check_scan_name(name):
    """Tarama adının daha önce kullanılıp kullanılmadığını kontrol eder"""
    result = safe_api_call(f"/scan/check_name/{name}", 
                          error_message=f"'{name}' adı kontrol edilirken hata oluştu", 
                          default_return={"exists": False})
    
    return result.get("exists", False) if result else False

def start_scan_in_background(scan_request):
    """Tarama başlatır ve bir scan_id döndürür"""
    try:
        # Debug için API isteğinin içeriğini loglayalım
        print(f"API isteği gönderiliyor: {json.dumps(scan_request, indent=2)}")
        
        result = safe_api_call("/scan", 
                              method="post", 
                              data=scan_request, 
                              error_message="Tarama başlatılamadı", 
                              default_return=None)
        
        print(f"API yanıtı: {result}")
        
        if result:
            scan_id = result.get("scan_id")
            if scan_id:
                st.session_state.active_scans[scan_id] = result
                st.session_state.monitoring_scans.add(scan_id)
                return scan_id
        
        return None
    except Exception as e:
        print(f"Tarama başlatma hatası: {str(e)}")
        traceback.print_exc()
        return None

def update_scan_status():
    """Aktif taramaların durumunu periyodik olarak günceller"""
    if not st.session_state.monitoring_scans:
        return
    
    if not is_api_available():
        return
    
    active_scans_to_monitor = list(st.session_state.monitoring_scans)
    for scan_id in active_scans_to_monitor:
        result = safe_api_call(f"/scan/{scan_id}/status", 
                              error_message=f"Tarama durumu güncellenirken hata ({scan_id})", 
                              default_return=None)
        
        if result:
            st.session_state.active_scans[scan_id] = result
            
            # Tamamlanan taramaları izleme listesinden çıkar
            status = result.get("status")
            if status in ["completed", "failed"]:
                st.session_state.monitoring_scans.remove(scan_id)

def get_all_active_scans():
    """Tüm aktif taramaları API'den alır"""
    result = safe_api_call("/scans/active", 
                          error_message="Aktif taramalar alınamadı", 
                          default_return={"active_scans": []})
    
    active_scans = result.get("active_scans", [])
    
    # Session state'i güncelle
    for scan in active_scans:
        scan_id = scan.get("scan_id")
        if scan_id:
            st.session_state.active_scans[scan_id] = scan
            
            # Tamamlanmamış taramaları izleme listesine ekle
            if scan.get("status") not in ["completed", "failed"]:
                st.session_state.monitoring_scans.add(scan_id)
    
    return active_scans

def run_background_scan(scan_request):
    """Arka planda tarama çalıştırır"""
    try:
        scan_id = start_scan_in_background(scan_request)
        if scan_id:
            st.session_state.scan_running = True
            st.toast(f"'{scan_request['scan_name']}' taraması başlatıldı (ID: {scan_id})", icon="🔍")
            # Sayfayı yenile
            st.rerun()
        else:
            st.session_state.scan_error = "Tarama başlatılamadı"
    except Exception as e:
        st.session_state.scan_error = str(e)
        traceback.print_exc()
    finally:
        st.session_state.scan_running = False

def get_all_scans():
    """Mevcut tüm taramaların listesini alır"""
    return safe_api_call("/scans", 
                        error_message="Tarama listesi alınamadı", 
                        default_return={"scans": []}).get("scans", [])

def get_incompatible_scan_types(scan_type):
    """API'den seçilen tarama tipi ile uyumsuz olan tarama tiplerini alır"""
    result = safe_api_call(f"/scan/incompatible/{scan_type}", 
                          error_message="Uyumsuz tarama tipleri alınamadı", 
                          default_return={"incompatible_types": []})
    
    return result.get("incompatible_types", [])

def get_scan_estimate(options):
    """API'den tarama süresi tahmini alır"""
    result = safe_api_call("/scan/estimate", 
                          params=options, 
                          error_message="Tarama süresi tahmini alınamadı", 
                          default_return={"estimated_duration": {"duration": 5, "unit": "dakika"}})
    
    return result.get("estimated_duration", {"duration": 5, "unit": "dakika"})

def show_scan_duration_estimate():
    """Mevcut seçimlere göre tarama süresi tahmini hesaplar ve gösterir"""
    # Streamlit'in session_state kullanarak değişkenleri alın
    try:
        # Mevcut session state değerlerini al, yoksa varsayılan değerler kullan
        target_type_val = st.session_state.get('target_type', 'ip')
        port_option_val = st.session_state.get('port_option', 'fast')
        scan_type_val = st.session_state.get('scan_type', 'sT')
        service_detection_val = st.session_state.get('service_detection', 'none')
        script_category_val = st.session_state.get('script_category', 'none')
        port_value_val = st.session_state.get('port_value', None)
        version_intensity_val = st.session_state.get('version_intensity', None)
        timing_template_val = st.session_state.get('timing_template', None)
        
        # API bağlantısı varsa API'den tahmin al
        if is_api_available():
            options = {
                "target_type": target_type_val,
                "port_option": port_option_val,
                "scan_type": scan_type_val,
                "service_detection": service_detection_val,
                "script_category": script_category_val,
                "port_value": port_value_val,
                "version_intensity": version_intensity_val,
                "timing_template": timing_template_val
            }
            
            estimate = get_scan_estimate(options)
            duration_value = estimate.get("duration", 5)
            duration_unit = estimate.get("unit", "dakika")
        else:
            # API bağlantısı yoksa yerel tahmin yap
            duration_value = 5  # dakika
            duration_unit = "dakika"
            
            # Sabit tahmin yerine basit bir hesaplama yapalım
            if port_option_val == 'all':
                duration_value = 15
            elif port_option_val == 'range':
                duration_value = 8
            elif port_option_val == 'top1000':
                duration_value = 7
            elif port_option_val == 'fast':
                duration_value = 3
            elif port_option_val == 'single':
                duration_value = 1
            
            # Tarama türü etkisi
            if scan_type_val in ['sU', 'sI']:
                duration_value *= 2
            elif scan_type_val in ['sS', 'sT']:
                duration_value *= 1.2
            
            # Servis algılama etkisi
            if service_detection_val == 'aggressive':
                duration_value *= 2.5
            elif service_detection_val == 'standard':
                duration_value *= 1.8
            elif service_detection_val == 'light':
                duration_value *= 1.3
            
            # Script kategori etkisi
            if script_category_val in ['vuln', 'exploit', 'all']:
                duration_value *= 3
            elif script_category_val in ['brute', 'intrusive']:
                duration_value *= 2.5
            elif script_category_val != 'none':
                duration_value *= 1.5
            
            # Saatlere dönüştür eğer 60 dakikadan fazlaysa
            if duration_value > 60:
                duration_value = duration_value / 60
                duration_unit = "saat"
                duration_value = round(duration_value, 1)
            else:
                duration_value = round(duration_value, 1)
        
        # Renk belirle
        if duration_unit == "dakika":
            if duration_value < 2:
                duration_color = "green"
            elif duration_value < 10:
                duration_color = "orange"
            else:
                duration_color = "red"
        else:  # saat
            duration_color = "red"
        
        return f"<span style='color:{duration_color}; font-weight:bold'>~{duration_value} {duration_unit}</span>"
    
    except Exception as e:
        # Hata durumunda genel bir tahmin dön
        traceback.print_exc()
        return "<span style='color:orange; font-weight:bold'>~5 dakika</span>"

# Periyodik güncelleme işlevi
def autorefresh_status():
    if st.session_state.monitoring_scans and is_api_available():
        update_scan_status()
        time.sleep(2)
        st.rerun()

# Streamlit arayüzünü oluştur
st.set_page_config(
    page_title="Gelişmiş Nmap Tarama Aracı",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API kontrolü
if not is_api_available():
    st.error("""
    ⚠️ API servisine bağlanılamıyor! 
    
    Lütfen backend servisinin çalıştığından emin olun:
    ```
    uvicorn main:app --reload
    ```
    
    veya
    
    ```
    python -m uvicorn main:app --reload
    ```
    """)

# Ana başlık - her zaman gösterilir
st.title("🔍 Gelişmiş Nmap Tarama Aracı")

# Ana çerçeveyi oluştur - her zaman erişilebilir olsun
main_tabs = st.tabs(["Tarama Parametreleri", "Tarama Sonuçları"])

# Önceki taramaları görüntüleme - önceden çalıştır ki tab seçimini etkileyebilsin
st.sidebar.header("Önceki Taramalar")

# API kullanılabilirliğini kontrol et
if is_api_available():
    scans = get_all_scans()
    
    if scans:
        scan_options = ["Seçiniz"]
        scan_names = {}
        
        for scan in scans:
            scan_name = scan["name"]
            scan_info = scan["info"]
            
            # İsim ve tarih formatı
            date = scan_info.get("date", "Bilinmiyor")
            scan_time = scan_info.get("time", "Bilinmiyor")
            
            display_name = f"{scan_name} - {date} {scan_time}"
            scan_options.append(display_name)
            scan_names[display_name] = scan_name
        
        selected_scan_display = st.sidebar.selectbox("Kaydedilmiş Tarama Sonuçları", scan_options)
        
        if selected_scan_display != "Seçiniz":
            selected_scan = scan_names[selected_scan_display]
            # Session state güncelleme
            st.session_state['selected_scan'] = selected_scan
            # Sonuçlar sekmesine geç
            st.session_state.active_tab = 1
    else:
        st.sidebar.info("Henüz tarama bulunmuyor")
else:
    st.sidebar.warning("API servisi bağlantısı yok - Taramalar listelenemedi")

# Aktif taramaları görüntüleme
st.sidebar.markdown("---")
st.sidebar.header("Aktif Taramalar")

# API kullanılabilirliğini kontrol et
if is_api_available():
    # Aktif taramaları API'den al
    active_scans = get_all_active_scans()
    
    if active_scans:
        # Aktif taramaları listele
        for scan in active_scans:
            scan_id = scan.get("scan_id")
            scan_name = scan.get("scan_name", "İsimsiz Tarama")
            status = scan.get("status")
            progress = scan.get("progress", 0)
            message = scan.get("message", "")
            
            # Durum göstergeleri ve renkler
            status_color = {
                "queued": "blue",
                "running": "orange",
                "completed": "green",
                "failed": "red"
            }.get(status, "gray")
            
            st.sidebar.markdown(f"### {scan_name}")
            st.sidebar.progress(progress / 100)
            st.sidebar.markdown(f"<span style='color:{status_color}'>{status.upper()}: {message}</span>", unsafe_allow_html=True)
            
            # Tamamlandıysa detay görüntüleme butonu
            if status == "completed":
                if st.sidebar.button(f"Sonuçları Görüntüle", key=f"view_{scan_id}"):
                    # Sonuçlar sekmesine geç ve seçili taramayı ayarla
                    st.session_state['selected_scan'] = scan.get("scan_name")
                    st.session_state.active_tab = 1
                    st.rerun()
            
            st.sidebar.markdown("---")
    else:
        st.sidebar.info("Aktif tarama bulunmuyor")
else:
    st.sidebar.warning("API servisi bağlantısı yok - Aktif taramalar listelenemedi")

# Tarama durumu bildirimi
if st.session_state.scan_running:
    # Sağ alt köşede bildirim göster
    st.sidebar.info("⏳ Tarama arka planda çalışıyor...")
elif st.session_state.scan_result:
    # Tarama tamamlandı bildirimi
    st.sidebar.success(f"✅ Tarama tamamlandı: {st.session_state.scan_result.get('scan_name')}")
    if st.sidebar.button("Temizle"):
        st.session_state.scan_result = None
        st.rerun()
elif st.session_state.scan_error:
    # Tarama hatası bildirimi
    st.sidebar.error(f"❌ Tarama hatası: {st.session_state.scan_error}")
    if st.sidebar.button("Temizle"):
        st.session_state.scan_error = None
        st.rerun()

# Aktif sekmeyi ayarla
if st.session_state.active_tab == 1:
    main_tabs[1].selectbox = True

# Periyodik güncellemeler için
if st.session_state.monitoring_scans:
    autorefresh_status()

# Before showing the main app, check if we need to get a scan name
if not st.session_state.show_scan_form:
    with main_tabs[0]:
        st.header("Tarama için bir isim girin")
        
        scan_name = st.text_input("Tarama Adı", placeholder="örn: home-network-scan")
        
        if st.button("Devam Et", use_container_width=True):
            if not scan_name:
                st.error("Lütfen bir tarama adı girin!")
            elif not is_api_available():
                st.error("API servisi çalışmıyor. Lütfen backend servisini kontrol edin.")
            elif check_scan_name(scan_name):
                st.error(f"'{scan_name}' adında bir tarama zaten mevcut.")
            else:
                st.session_state.scan_name = scan_name
                st.session_state.show_scan_form = True
                st.rerun()
else:
    # Show scan form
    with main_tabs[0]:
        # Tarama parametreleri sekmesi
        st.subheader("1️⃣ Hedef Belirtme")
        target_type_col, target_col = st.columns([1, 3])
        
        with target_type_col:
            target_type = st.radio(
                "Hedef Türü",
                list(TARGET_TYPE_INFO.keys()),
                format_func=lambda x: TARGET_TYPE_INFO[x]["name"]
            )
            # Session state güncelleme
            st.session_state['target_type'] = target_type
            st.info(TARGET_TYPE_INFO[target_type]["description"])
        
        with target_col:
            target = st.text_input(
                "Hedef",
                placeholder=TARGET_TYPE_INFO[target_type]["example"],
                help=f"Örnek: {TARGET_TYPE_INFO[target_type]['example']}"
            )
            # Session state güncelleme
            st.session_state['target'] = target
        
        # Port tarama seçenekleri
        st.subheader("2️⃣ Port Tarama Seçenekleri")
        port_option_col, port_value_col = st.columns([1, 3])
        
        with port_option_col:
            port_option = st.radio(
                "Port Seçeneği",
                list(SCAN_DURATION_ESTIMATES.keys()),
                format_func=lambda x: {
                    "single": "Tek port",
                    "range": "Port aralığı",
                    "fast": "Yaygın 100 port (Hızlı)",
                    "top10": "En yaygın 10 port",
                    "top1000": "En yaygın 1000 port",
                    "all": "Tüm portlar (65535)"
                }[x]
            )
            # Session state güncelleme
            st.session_state['port_option'] = port_option
            st.info(SCAN_DURATION_ESTIMATES[port_option]["description"])
        
        port_value = None
        with port_value_col:
            if port_option == "single":
                port_value = st.text_input("Port numarası:", "80", help="Örn: 80, 443, 22")
                # Session state güncelleme
                st.session_state['port_value'] = port_value
            elif port_option == "range":
                port_value = st.text_input("Port aralığı:", "1-1000", help="Örn: 1-1000, 20-25, 80,443,8080")
                # Session state güncelleme
                st.session_state['port_value'] = port_value
            else:
                # Session state güncelleme
                st.session_state['port_value'] = None
        
        # Tarama türü seçimi
        st.subheader("3️⃣ Tarama Türü")
        scan_type_containers = st.columns(3)
        
        # Önce TCP tabanlı taramalar
        tcp_scan_types = [s for s in SCAN_TYPE_INFO.keys() if s.startswith('s') and 'TCP' in SCAN_TYPE_INFO[s]['name']]
        # Sonra UDP ve diğer taramalar
        udp_scan_types = [s for s in SCAN_TYPE_INFO.keys() if s.startswith('s') and 'UDP' in SCAN_TYPE_INFO[s]['name']]
        # Diğer özel taramalar
        special_scan_types = [s for s in SCAN_TYPE_INFO.keys() if s not in tcp_scan_types and s not in udp_scan_types]
        
        # Tarama türlerini sütunlara dağıt
        scan_type_groups = [tcp_scan_types, udp_scan_types, special_scan_types]
        scan_type_options = {}
        
        for i, group in enumerate(scan_type_groups):
            with scan_type_containers[i]:
                for scan in group:
                    info = SCAN_TYPE_INFO[scan]
                    
                    # Root gerektiren taramalar için uyarı
                    disabled = False
                    help_text = f"{info['description']}"
                    
                    if info.get('requires_root', False):
                        try:
                            if not os.geteuid() == 0:  # Root kontrolü
                                disabled = True
                                help_text += " (⚠️ Root yetkisi gerektirir. Docker kullanarak çalıştırabilirsiniz.)"
                        except:
                            # Windows sistemlerde geteuid() mevcut değil, bu durumda varsayılan olarak Docker içinde çalıştığımızı varsayabiliriz
                            pass
                    
                    scan_type_options[scan] = {
                        "disabled": disabled,
                        "help_text": help_text,
                        "duration_factor": info['duration_factor'],
                        "name": info['name']
                    }
        
        # Tarama türü seçimi
        scan_type_cols = st.columns([3, 1])
        with scan_type_cols[0]:
            # Tarama türü seçenekleri
            scan_types_list = list(scan_type_options.keys())
            scan_type_names = [scan_type_options[s]["name"] for s in scan_types_list]
            scan_type_index = scan_types_list.index("sT") if "sT" in scan_types_list else 0  # Varsayılan olarak TCP Connect
            
            scan_type = st.radio(
                "Tarama Türü",
                scan_types_list,
                index=scan_type_index,
                format_func=lambda x: scan_type_options[x]["name"],
                horizontal=True
            )
            # Session state güncelleme
            st.session_state['scan_type'] = scan_type

            # Seçilen tarama türü root gerektiriyor ve root değilsek uyarı göster
            if scan_type_options[scan_type].get("disabled", False):
                root_warning = SCAN_TYPE_INFO[scan_type].get('requires_root', False)
                if root_warning:
                    st.warning("⚠️ Bu tarama türü root yetkisi gerektirir. Docker içinde çalıştırdığınız için sorun olmayacaktır, ancak normal bir sistemde bu tarama türü çalışmayabilir.")
                
        with scan_type_cols[1]:
            # Seçilen tarama türü hakkında bilgi
            st.info(scan_type_options[scan_type]["help_text"])
            
            if 'stealth' in SCAN_TYPE_INFO[scan_type]:
                st.markdown(f"**Gizlilik:** {SCAN_TYPE_INFO[scan_type]['stealth']}")
            
            # Tarama süresi tahmini
            st.markdown(f"**Tahmini Süre:** {show_scan_duration_estimate()}", unsafe_allow_html=True)
        
        # Servis Algılama
        st.subheader("4️⃣ Servis Algılama (Opsiyonel)")
        service_detection_cols = st.columns([3, 1])
        
        with service_detection_cols[0]:
            service_detection = st.radio(
                "Servis Algılama",
                list(SERVICE_DETECTION_INFO.keys()),
                format_func=lambda x: SERVICE_DETECTION_INFO[x]["name"],
                horizontal=True
            )
            # Session state güncelleme
            st.session_state['service_detection'] = service_detection
        
        with service_detection_cols[1]:
            st.info(SERVICE_DETECTION_INFO[service_detection]["description"])
            
            # OS tespiti için root kontrolü
            if service_detection == "os" and SERVICE_DETECTION_INFO[service_detection].get('requires_root', False):
                try:
                    if not os.geteuid() == 0:
                        st.warning("⚠️ OS tespiti için root yetkisi gerekir. Docker kullanarak çalıştırabilirsiniz.")
                except:
                    # Windows sistemlerde geteuid() mevcut değil
                    pass
        
        # Version Intensity
        version_intensity = None
        if service_detection in ["standard", "light", "aggressive"]:
            version_intensity = st.slider(
                "Version Intensity (Versiyon Tespiti Derinliği)",
                min_value=0,
                max_value=9,
                value=7 if service_detection == "aggressive" else (0 if service_detection == "light" else 5),
                help="0: En hızlı fakat az bilgi, 9: En yavaş fakat en detaylı bilgi"
            )
            # Session state güncelleme
            st.session_state['version_intensity'] = version_intensity
        else:
            # Session state güncelleme
            st.session_state['version_intensity'] = None
        
        # NSE Script Kategorileri
        st.subheader("5️⃣ NSE Script Seçenekleri (Opsiyonel)")
        script_cols = st.columns([3, 1])
        
        with script_cols[0]:
            script_category = st.radio(
                "Script Kategorisi",
                list(SCRIPT_CATEGORY_INFO.keys()),
                format_func=lambda x: SCRIPT_CATEGORY_INFO[x]["name"],
                horizontal=True
            )
            # Session state güncelleme
            st.session_state['script_category'] = script_category
        
        with script_cols[1]:
            st.info(SCRIPT_CATEGORY_INFO[script_category]["description"])
        
        # Özel script girişi
        custom_scripts = None
        if script_category != "none":
            custom_scripts = st.text_input(
                "Özel Script İsimleri (İsteğe Bağlı)",
                placeholder="http-title,banner,ssl-cert",
                help="Virgülle ayrılmış özel script isimleri (opsiyonel)"
            )
            # Session state güncelleme
            st.session_state['custom_scripts'] = custom_scripts
        else:
            # Session state güncelleme
            st.session_state['custom_scripts'] = None
        
        # Timing Template
        st.subheader("6️⃣ Zamanlama Şablonu (Opsiyonel)")
        timing_cols = st.columns([3, 1])
        
        with timing_cols[0]:
            timing_options = list(TIMING_TEMPLATE_INFO.keys())
            timing_template_index = timing_options.index("T3") if "T3" in timing_options else 0  # Varsayılan olarak Normal
            
            timing_template = st.radio(
                "Zamanlama Şablonu",
                [None] + timing_options,
                index=timing_template_index + 1,  # +1 çünkü None eklendi başa
                format_func=lambda x: "Varsayılan (Normal)" if x is None else TIMING_TEMPLATE_INFO[x]["name"],
                horizontal=True
            )
            # Session state güncelleme
            st.session_state['timing_template'] = timing_template
        
        with timing_cols[1]:
            if timing_template:
                st.info(TIMING_TEMPLATE_INFO[timing_template]["description"])
            else:
                st.info("Varsayılan T3 (Normal) ayarı kullanılır")
        
        # Çıktı Formatı
        st.subheader("7️⃣ Çıktı Formatı (Opsiyonel)")
        output_cols = st.columns([3, 1])
        
        with output_cols[0]:
            output_format = st.radio(
                "Çıktı Formatı",
                list(OUTPUT_FORMAT_INFO.keys()),
                format_func=lambda x: OUTPUT_FORMAT_INFO[x]["name"],
                horizontal=True
            )
            # Session state güncelleme
            st.session_state['output_format'] = output_format
        
        with output_cols[1]:
            st.info(OUTPUT_FORMAT_INFO[output_format]["description"])
        
        # Tarama özeti
        st.subheader("🔍 Tarama Özeti")
        
        # Özet bilgileri görüntüle
        summary_col1, summary_col2 = st.columns(2)
        
        with summary_col1:
            st.markdown(f"**Tarama Adı:** `{st.session_state.scan_name}`")
            st.markdown(f"**Hedef:** `{target if target else 'Henüz belirtilmedi'}`")
            st.markdown(f"**Hedef Türü:** {TARGET_TYPE_INFO[target_type]['name']}")
            st.markdown(f"**Port Seçeneği:** {SCAN_DURATION_ESTIMATES[port_option]['description']}")
            if port_value:
                st.markdown(f"**Port Değeri:** `{port_value}`")
            st.markdown(f"**Tarama Türü:** {SCAN_TYPE_INFO[scan_type]['name']}")
        
        with summary_col2:
            st.markdown(f"**Servis Algılama:** {SERVICE_DETECTION_INFO[service_detection]['name']}")
            if version_intensity is not None:
                st.markdown(f"**Versiyon Tespiti Derinliği:** {version_intensity}")
            st.markdown(f"**Script Kategorisi:** {SCRIPT_CATEGORY_INFO[script_category]['name']}")
            if custom_scripts:
                st.markdown(f"**Özel Scriptler:** `{custom_scripts}`")
            st.markdown(f"**Zamanlama Şablonu:** {TIMING_TEMPLATE_INFO[timing_template]['name'] if timing_template else 'Varsayılan'}")
            st.markdown(f"**Tahmini Süre:** {show_scan_duration_estimate()}", unsafe_allow_html=True)
        
        # Tarama Başlat Butonu
        start_scan_button = st.button("🚀 Tarama Başlat", type="primary", use_container_width=True)
        
        if start_scan_button:
            if not target:
                st.error("Lütfen bir hedef girin!")
            elif not is_api_available():
                st.error("API servisi çalışmıyor. Lütfen backend servisini kontrol edin.")
            else:
                try:
                    # API'ye direkt istek atalım
                    scan_request = {
                        "scan_name": st.session_state.scan_name,
                        "target": target,
                        "target_type": target_type,
                        "port_option": port_option,
                        "port_value": port_value,
                        "scan_type": scan_type,
                        "service_detection": service_detection,
                        "version_intensity": version_intensity,
                        "script_category": script_category,
                        "custom_scripts": custom_scripts,
                        "timing_template": timing_template,
                        "output_format": output_format
                    }
                    
                    st.info("API'ye doğrudan istek gönderiliyor...")
                    print(f"Gönderilen istek: {json.dumps(scan_request, indent=2)}")
                    
                    response = requests.post(
                        f"{API_URL}/scan", 
                        json=scan_request, 
                        timeout=10
                    )
                    
                    st.write(f"API yanıt kodu: {response.status_code}")
                    st.write(f"API yanıtı: {response.text}")
                    
                    if response.status_code == 200:
                        result = response.json()
                        st.success(f"Tarama başarıyla başlatıldı! Tarama ID: {result.get('scan_id')}")
                        time.sleep(3)  # Mesajın görünmesi için bekle
                        st.session_state.show_scan_form = False
                        st.session_state.scan_name = None
                        st.rerun()
                    else:
                        st.error(f"Tarama başlatılamadı: {response.text}")
                except Exception as e:
                    st.error(f"Tarama başlatılırken hata oluştu: {str(e)}")
                    traceback.print_exc()

# Tarama sonuçları sekmesi
with main_tabs[1]:
    if 'selected_scan' in st.session_state and st.session_state['selected_scan']:
        selected_scan = st.session_state['selected_scan']
        
        # Geri butonu ekle
        if st.button("← Tarama Listesine Dön"):
            st.session_state.pop('selected_scan', None)
            st.session_state.active_tab = 0
            st.rerun()
        
        # API kullanılabilirliğini kontrol et
        if is_api_available():
            try:
                # API'den tarama detaylarını al
                scan_details = safe_api_call(f"/scan/{selected_scan}/details", 
                                          error_message=f"Tarama detayları alınamadı: {selected_scan}",
                                          default_return={"name": selected_scan, "info": {}, "files": {}, "results": None})
                
                if scan_details:
                    scan_info = scan_details.get("info", {})
                    
                    # Çalıştırılan komut ve diğer bilgileri göster
                    st.subheader("Tarama Bilgileri")
                    st.code(scan_info.get("command", "Komut bilgisi bulunamadı"), language="bash")
                    
                    info_cols = st.columns(4)
                    with info_cols[0]:
                        st.markdown(f"**Tarih:** {scan_info.get('date', 'Bilinmiyor')}")
                        st.markdown(f"**Saat:** {scan_info.get('time', 'Bilinmiyor')}")
                    
                    with info_cols[1]:
                        st.markdown(f"**Hedef:** {scan_info.get('target', 'Bilinmiyor')}")
                        st.markdown(f"**Hedef Türü:** {scan_info.get('target_type', 'Bilinmiyor')}")
                    
                    with info_cols[2]:
                        st.markdown(f"**Port Seçeneği:** {scan_info.get('port_option', 'Bilinmiyor')}")
                        if scan_info.get('port_value'):
                            st.markdown(f"**Port Değeri:** {scan_info.get('port_value')}")
                    
                    with info_cols[3]:
                        st.markdown(f"**Tarama Türü:** {scan_info.get('scan_type', 'Bilinmiyor')}")
                        st.markdown(f"**Servis Algılama:** {scan_info.get('service_detection', 'Bilinmiyor')}")
                    
                    # Tahmini süre
                    if "estimated_duration" in scan_info:
                        est_duration = scan_info["estimated_duration"]
                        st.info(f"Tahmini Süre: {est_duration['duration']} {est_duration['unit']}")
                    
                    # Tablo görünümü
                    st.markdown("### Tarama Sonuçları")
                    result_tabs = st.tabs(["Tablo Görünümü", "XML Görünümü", "Zafiyetler", "Ham Çıktılar"])
                    
                    with result_tabs[0]:
                        try:
                            # API'den tablo verilerini al
                            table_data = safe_api_call(f"/scan/{selected_scan}/table", 
                                                    error_message=f"Tablo verisi alınamadı: {selected_scan}",
                                                    default_return=None)
                            
                            if table_data:
                                columns = table_data["columns"]
                                data = table_data["data"]
                                
                                # Filtreleme opsiyonları ekle
                                st.markdown("#### Tablo Filtreleme")
                                filter_col1, filter_col2 = st.columns(2)
                                
                                with filter_col1:
                                    # Sadece açık portları göster
                                    show_only_open = st.checkbox("Sadece açık portları göster", value=True)
                                    # Session state güncelleme
                                    st.session_state['show_only_open'] = show_only_open
                                
                                with filter_col2:
                                    # Gösterilecek IP filtresi
                                    # Boş veya None değerleri filtrele, unique_ips listesini oluştur
                                    ip_index = columns.index('ip') if 'ip' in columns else -1
                                    if ip_index >= 0:
                                        unique_ips = sorted(list(set([row[ip_index] for row in data 
                                                        if row[ip_index] and str(row[ip_index]).lower() != 'bilinmiyor'])))
                                        selected_ips = st.multiselect("IP Filtresi", unique_ips, default=unique_ips)
                                        # Session state güncelleme
                                        st.session_state['selected_ips'] = selected_ips
                                    else:
                                        selected_ips = []
                                
                                # Sütun seçimi
                                default_columns = ['ip', 'hostname', 'port', 'protocol', 'state', 'service', 'product', 'version']
                                available_columns = [col for col in columns if col != '']
                                selected_columns = st.multiselect(
                                    "Görüntülenecek sütunlar seçin",
                                    available_columns,
                                    default=[col for col in default_columns if col in available_columns]
                                )
                                # Session state güncelleme
                                st.session_state['selected_columns'] = selected_columns
                                
                                # Filtreleme ve sütun seçme işlemlerini uygula
                                if selected_columns:
                                    # Filtreleme
                                    filtered_data = []
                                    ip_index = columns.index('ip') if 'ip' in columns else -1
                                    state_index = columns.index('state') if 'state' in columns else -1
                                    
                                    for row in data:
                                        # IP filtresi kontrolü
                                        if ip_index >= 0 and selected_ips and row[ip_index] not in selected_ips:
                                            continue
                                        
                                        # Açık port filtresi kontrolü
                                        if show_only_open and state_index >= 0 and row[state_index] != 'open':
                                            continue
                                        
                                        # Seçilen sütunları ekle
                                        filtered_row = [row[columns.index(col)] if columns.index(col) < len(row) else "" for col in selected_columns]
                                        filtered_data.append(filtered_row)
                                    
                                    # Veri varsa göster
                                    if filtered_data:
                                        # DataFrame oluştur ve göster
                                        df = pd.DataFrame(filtered_data, columns=selected_columns)
                                        st.dataframe(df, use_container_width=True)
                                        
                                        # Özet bilgileri göster
                                        st.markdown("#### Özet Bilgi")
                                        col1, col2, col3 = st.columns(3)
                                        with col1:
                                            st.metric("Toplam Kayıt", len(filtered_data))
                                        if 'state' in selected_columns:
                                            with col2:
                                                open_count = sum(1 for row in filtered_data if row[selected_columns.index('state')] == 'open')
                                                st.metric("Açık Port Sayısı", open_count)
                                        if 'service' in selected_columns:
                                            with col3:
                                                unique_services = len(set(row[selected_columns.index('service')] for row in filtered_data 
                                                                if row[selected_columns.index('service')]))
                                                st.metric("Farklı Servis Sayısı", unique_services)
                                        
                                        # CSV olarak indirme butonu
                                        csv_download = df.to_csv(index=False).encode('utf-8')
                                        st.download_button(
                                            label="Filtrelenmiş tabloyu CSV olarak indir",
                                            data=csv_download,
                                            file_name=f"nmap_filtered_{selected_scan}.csv",
                                            mime="text/csv",
                                        )
                                    else:
                                        st.warning("Seçilen filtrelere uygun sonuç bulunamadı")
                                else:
                                    st.warning("Lütfen en az bir sütun seçin")
                            else:
                                st.error("Tarama verileri yüklenemedi. API servisini kontrol edin.")
                                
                                # CSV dosyasının doğrudan okunması için yedek yöntem
                                csv_path = os.path.join("outputs", selected_scan, "output.csv")
                                if os.path.exists(csv_path):
                                    try:
                                        # Yorum satırlarını dinamik olarak tespit et
                                        with open(csv_path, 'r', encoding='utf-8') as f:
                                            comment_lines = 0
                                            for line in f:
                                                if line.startswith('#'):
                                                    comment_lines += 1
                                                else:
                                                    break
                                        
                                        # CSV dosyasını oku, yorum satırlarını atla
                                        df = pd.read_csv(csv_path, skiprows=comment_lines)
                                        # NaN değerlerini boş string ile değiştir
                                        df = df.fillna("")
                                        st.dataframe(df, use_container_width=True)
                                        
                                        csv_download = df.to_csv(index=False).encode('utf-8')
                                        st.download_button(
                                            label="CSV dosyasını indir",
                                            data=csv_download,
                                            file_name=f"nmap_scan_{selected_scan}.csv",
                                            mime="text/csv"
                                        )
                                    except Exception as csv_error:
                                        st.error(f"CSV dosyası okunamadı: {csv_error}")
                        except Exception as e:
                            st.error(f"Tablo veri hatası: {str(e)}")
                            traceback.print_exc()
                    
                    with result_tabs[1]:
                        output_path = os.path.join("outputs", selected_scan, "output.xml")
                        if os.path.exists(output_path):
                            try:
                                # XML dosyasını oku ve güzel formatla
                                dom = xml.dom.minidom.parse(output_path)
                                pretty_xml = dom.toprettyxml()
                                
                                with st.expander("XML Çıktısı", expanded=False):
                                    st.code(pretty_xml, language="xml")
                                
                                # XML içeriğini daha okunabilir hale getir
                                hosts = dom.getElementsByTagName("host")
                                if hosts:
                                    st.markdown("#### Tarama Özeti")
                                    for host in hosts:
                                        addresses = host.getElementsByTagName("address")
                                        hostname_elements = host.getElementsByTagName("hostname")
                                        ports = host.getElementsByTagName("port")
                                        
                                        # IP adresi
                                        for address in addresses:
                                            if address.getAttribute("addrtype") == "ipv4":
                                                st.markdown(f"#### Host: {address.getAttribute('addr')}")
                                        
                                        # Hostname
                                        hostnames = []
                                        for hostname in hostname_elements:
                                            hostnames.append(hostname.getAttribute("name"))
                                        if hostnames:
                                            st.markdown(f"**Hostname(s):** {', '.join(hostnames)}")
                                        
                                        # Portlar
                                        if ports:
                                            st.markdown("**Açık Portlar:**")
                                            port_data = []
                                            for port in ports:
                                                port_id = port.getAttribute("portid")
                                                protocol = port.getAttribute("protocol")
                                                state_elem = port.getElementsByTagName("state")[0]
                                                state = state_elem.getAttribute("state")
                                                
                                                if state == "open":
                                                    service_info = "?"
                                                    service_elems = port.getElementsByTagName("service")
                                                    if service_elems:
                                                        service = service_elems[0]
                                                        service_info = service.getAttribute("name")
                                                        product = service.getAttribute("product")
                                                        version = service.getAttribute("version")
                                                        if product:
                                                            service_info += f" ({product}"
                                                            if version:
                                                                service_info += f" {version}"
                                                            service_info += ")"
                                                    
                                                    port_data.append(f"- **{port_id}/{protocol}**: {service_info}")
                                            
                                            for pd in port_data:
                                                st.markdown(pd)
                            except Exception as e:
                                st.error(f"XML dosyası işlenirken hata oluştu: {e}")
                                traceback.print_exc()
                                
                                # Hataya rağmen XML içeriğini görüntülemeye çalış
                                try:
                                    with open(output_path, "r") as f:
                                        st.code(f.read(), language="xml")
                                except:
                                    st.error("XML dosyası okunamadı.")
                        else:
                            st.info("XML dosyası henüz oluşturulmamış veya erişilemiyor.")
                    
                    with result_tabs[2]:  # Zafiyetler sekmesi
                        try:
                            # API'den zafiyet verilerini al
                            vuln_data = safe_api_call(f"/scan/{selected_scan}/vulnerabilities", 
                                                   error_message="Zafiyet verileri alınamadı",
                                                   default_return={"error": "Zafiyet verileri alınamadı", "services": []})
                            
                            if "error" in vuln_data:
                                st.error(f"Zafiyet tarama sırasında hata oluştu: {vuln_data['error']}")
                            
                            # Servis bilgilerini kontrol et
                            services = vuln_data.get("services", [])
                            
                            if not services:
                                st.info("Taramada hiçbir zafiyet bulunamadı veya tarama henüz tamamlanmadı.")
                                
                                # Zafiyet taramasını başlatmak için buton
                                if st.button("Zafiyet Taramasını Başlat"):
                                    with st.spinner("Zafiyet taraması yapılıyor... Bu işlem birkaç dakika sürebilir..."):
                                        retry_response = safe_api_call(f"/scan/{selected_scan}/vulnerabilities", 
                                                                   error_message="Zafiyet taraması başlatılamadı",
                                                                   default_return=None)
                                        
                                        if retry_response:
                                            st.success("Zafiyet taraması tamamlandı! Sayfayı yenileyerek sonuçları görebilirsiniz.")
                                            st.rerun()
                                        else:
                                            st.error("Zafiyet taraması başlatılamadı.")
                            else:
                                st.success(f"Toplam {len(services)} hizmette zafiyet bulundu.")
                                
                                # Servis filtreleme
                                all_services = [f"{s['ip']}:{s['port']} - {s['service']}" for s in services]
                                selected_services = st.multiselect(
                                    "Gösterilecek hizmetleri seçin",
                                    all_services,
                                    default=all_services
                                )
                                
                                # Risk seviyesi filtreleme
                                all_risks = ["Kritik", "Yüksek", "Orta", "Düşük", "Bilinmeyen", "Exploit Mevcut"]
                                selected_risks = st.multiselect(
                                    "Gösterilecek risk seviyelerini seçin",
                                    all_risks,
                                    default=all_risks
                                )
                                
                                # Her servis için zafiyetleri listele
                                for i, service in enumerate(services):
                                    service_key = f"{service['ip']}:{service['port']} - {service['service']}"
                                    
                                    if service_key in selected_services:
                                        with st.expander(f"{service_key} - {service['product']} {service['version']}"):
                                            vulns = service.get("vulnerabilities", [])
                                            
                                            # Zafiyet tablosunu oluştur
                                            vuln_data = []
                                            for vuln in vulns:
                                                if vuln.get("risk", "Bilinmeyen") in selected_risks:
                                                    vuln_data.append([
                                                        vuln.get("tool", ""),
                                                        vuln.get("id", ""),
                                                        vuln.get("title", ""),
                                                        vuln.get("risk", "Bilinmeyen"),
                                                        vuln.get("description", "")
                                                    ])
                                            
                                            if vuln_data:
                                                df = pd.DataFrame(
                                                    vuln_data,
                                                    columns=["Araç", "ID", "Başlık", "Risk", "Açıklama"]
                                                )
                                                
                                                # Risk renklerini tanımla - Streamlit arayüzüne uygun yapıldı
                                                def highlight_risk(s):
                                                    risk_colors = {
                                                        "Kritik": "background-color: red; color: white",
                                                        "Yüksek": "background-color: orange; color: black",
                                                        "Orta": "background-color: yellow; color: black",
                                                        "Düşük": "background-color: green; color: white",
                                                        "Exploit Mevcut": "background-color: purple; color: white",
                                                        "Bilinmeyen": "background-color: gray; color: white"
                                                    }
                                                    return [risk_colors.get(s.iloc[i]) if column == "Risk" else "" 
                                                            for i, column in enumerate(s.index)]
                                                
                                                # Streamlit'in styled_df yaklaşımı
                                                st.dataframe(df.style.apply(highlight_risk, axis=1))
                                                
                                                # Zafiyet özet bilgisi
                                                risk_counts = {}
                                                for vuln in vulns:
                                                    risk = vuln.get("risk", "Bilinmeyen")
                                                    if risk in selected_risks:
                                                        risk_counts[risk] = risk_counts.get(risk, 0) + 1
                                                
                                                st.write("**Özet:**")
                                                summary_cols = st.columns(len(risk_counts))
                                                
                                                for i, (risk, count) in enumerate(risk_counts.items()):
                                                    with summary_cols[i]:
                                                        st.metric(f"{risk} Zafiyetler", count)
                                            else:
                                                st.info("Seçilen filtrelerle eşleşen zafiyet bulunamadı.")
                                
                                # Tüm zafiyetleri CSV olarak dışa aktarma butonu
                                all_vuln_data = []
                                
                                for service in services:
                                    service_key = f"{service['ip']}:{service['port']} - {service['service']}"
                                    if service_key in selected_services:
                                        for vuln in service.get("vulnerabilities", []):
                                            if vuln.get("risk", "Bilinmeyen") in selected_risks:
                                                all_vuln_data.append({
                                                    "IP": service["ip"],
                                                    "Port": service["port"],
                                                    "Servis": service["service"],
                                                    "Ürün": service["product"],
                                                    "Versiyon": service["version"],
                                                    "Araç": vuln.get("tool", ""),
                                                    "Zafiyet ID": vuln.get("id", ""),
                                                    "Başlık": vuln.get("title", ""),
                                                    "Risk": vuln.get("risk", "Bilinmeyen"),
                                                    "Açıklama": vuln.get("description", ""),
                                                    "Referans": vuln.get("reference", "")
                                                })
                                
                                if all_vuln_data:
                                    df_all = pd.DataFrame(all_vuln_data)
                                    csv_vuln = df_all.to_csv(index=False).encode('utf-8')
                                    
                                    st.download_button(
                                        label="Zafiyet raporunu CSV olarak indir",
                                        data=csv_vuln,
                                        file_name=f"vulnerabilities_{selected_scan}.csv",
                                        mime="text/csv",
                                    )
                        
                        except Exception as e:
                            st.error(f"Zafiyet verileri işlenirken hata oluştu: {e}")
                            traceback.print_exc()
                            st.info("API servisinin çalıştığından emin olun.")
                    
                    with result_tabs[3]:
                        # Diğer çıktı formatlarını göster
                        txt_path = os.path.join("outputs", selected_scan, "output.txt")
                        if os.path.exists(txt_path):
                            with st.expander("Normal Çıktı (TXT)", expanded=False):
                                with open(txt_path, "r") as f:
                                    st.code(f.read(), language="bash")
                        
                        json_path = os.path.join("outputs", selected_scan, "output.json")
                        if os.path.exists(json_path):
                            with st.expander("JSON Çıktı", expanded=False):
                                with open(json_path, "r") as f:
                                    st.code(f.read(), language="json")
                        
                        gnmap_path = os.path.join("outputs", selected_scan, "output.gnmap")
                        if os.path.exists(gnmap_path):
                            with st.expander("Grepable Çıktı", expanded=False):
                                with open(gnmap_path, "r") as f:
                                    st.code(f.read(), language="bash")
                else:
                    st.error("Tarama bilgileri alınamadı. API servisinin çalıştığından emin olun.")
            
            except Exception as e:
                st.error(f"Tarama detayları alınırken hata oluştu: {e}")
                traceback.print_exc()
                st.info("API servisinin çalıştığından emin olun.")
        else:
            st.error("""
            ⚠️ API servisine bağlanılamıyor. Tarama sonuçları görüntülenemiyor.
            
            Backend API servisini çalıştırdığınızdan emin olun:
            ```
            uvicorn main:app --reload
            ```
            """)
    else:
        st.info("Görüntülenecek tarama sonucu seçilmedi. Lütfen soldaki menüden bir tarama seçin.")

# Arkaplanı ve stilleri özelleştir
st.markdown("""
<style>
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f0f2f6;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #e6f0ff;
        color: #0366d6;
        font-weight: bold;
    }
    .stButton > button {
        font-weight: bold;
    }
    .stRadio > div {
        flex-direction: row;
        gap: 10px;
    }
    .stRadio [data-testid="stMarkdownContainer"] > p {
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown("### 📋 Hakkında")
st.sidebar.info(
    """
    Bu araç, Nmap tarama aracının yeteneklerini kullanarak ağ keşfi ve güvenlik analizleri yapmanıza yardımcı olur.
    
    ⚠️ **Güvenlik Uyarısı:** Bu aracı yalnızca izin verilen sistemlerde ve yasal amaçlar için kullanın.
    İzinsiz ağ taraması yasalara aykırı olabilir.
    """
)

# API durum bilgisi
if not is_api_available():
    st.sidebar.markdown("---")
    st.sidebar.error("⚠️ API Servisi Çalışmıyor")
else:
    st.sidebar.markdown("---")
    st.sidebar.success("✅ API Servisi Aktif")

# Periyodik güncellemeler için arka plan işlemi
if st.session_state.monitoring_scans:
    autorefresh_status()