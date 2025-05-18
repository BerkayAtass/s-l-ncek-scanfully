// services/scanType.js
export const ScanType = {
  TCP_CONNECT: "sT",    // TCP Connect tarama (standart)
  TCP_SYN: "sS",        // TCP SYN tarama (hızlı, yarı-gizli)
  TCP_ACK: "sA",        // TCP ACK tarama (firewall keşfi)
  TCP_WINDOW: "sW",     // TCP Window tarama
  TCP_MAIMON: "sM",     // TCP Maimon tarama
  UDP_SCAN: "sU",       // UDP portları tarama
  PING_SCAN: "sP",      // Sadece ping taraması
  SKIP_PING: "Pn",      // Keşfi yoksay - tüm hostları çevrimiçi varsay
  FIN_SCAN: "sF",       // FIN tarama
  XMAS_SCAN: "sX",      // Xmas tarama
  NULL_SCAN: "sN",      // Null tarama
  IP_PROTOCOL: "sO",    // IP protokol taraması
  IDLE_SCAN: "sI"       // Idle tarama (ileri seviye)
};

export const PortOption = {
  SINGLE: "single",     // Tek port tarama
  RANGE: "range",       // Port aralığı tarama
  FAST: "fast",         // Yaygın 100 port (hızlı)
  ALL: "all",           // Tüm portlar (65535)
  TOP_1000: "top1000",  // En yaygın 1000 port
  TOP_10: "top10"       // En yaygın 10 port
};

export const ServiceDetection = {
  NONE: "none",             // Servis algılama yok
  STANDARD: "standard",     // Standart servis algılama
  LIGHT: "light",           // Hafif banner yakalama
  AGGRESSIVE: "aggressive", // Agresif servis algılama
  OS_DETECT: "os"           // İşletim sistemi tespiti
};

export const TimingTemplate = {
  PARANOID: "T0",       // Çok yavaş, IDS kaçınma
  SNEAKY: "T1",         // Yavaş, IDS kaçınma
  POLITE: "T2",         // Normal hızdan yavaş, daha az bant genişliği
  NORMAL: "T3",         // Varsayılan, normal hız
  AGGRESSIVE: "T4",     // Daha hızlı, güçlü sistemlerde
  INSANE: "T5"          // Çok hızlı, doğruluğu feda eder
};

export const ScriptCategory = {
  NONE: "none",             // Script kullanma
  DEFAULT: "default",       // Varsayılan scriptler
  DISCOVERY: "discovery",   // Keşif scriptleri
  SAFE: "safe",             // Güvenli scriptler
  AUTH: "auth",             // Kimlik doğrulama scriptleri
  BROADCAST: "broadcast",   // Yayın scriptleri
  BRUTE: "brute",           // Kaba kuvvet scriptleri
  VULN: "vuln",             // Güvenlik açığı scriptleri
  EXPLOIT: "exploit",       // Exploit scriptleri
  INTRUSIVE: "intrusive",   // İzinsiz giriş scriptleri
  MALWARE: "malware",       // Zararlı yazılım scriptleri
  DOS: "dos",               // DoS scriptleri
  ALL: "all",               // Tüm scriptler
  VULNERS: "vulners",       // Vulners.com veritabanı taraması
  VULSCAN: "vulscan"        // Offline veritabanı taraması
};

export const OutputFormat = {
  NORMAL: "normal",         // Normal çıktı
  XML: "xml",               // XML çıktı
  JSON: "json",             // JSON çıktı
  GREPABLE: "grepable",     // Grepable çıktı
  ALL: "all"                // Tüm formatlar
};