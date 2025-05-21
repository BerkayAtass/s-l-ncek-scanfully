ScanClass Network Tarama Projesi Teknik Dökümantasyonu
Bu dökümantasyon, ağ tarama ve zafiyet analizi gerçekleştiren backend projesinin temel bileşenlerini açıklamaktadır. Proje, çeşitli tarama türlerini destekleyen, bulguları işleyen ve web UI aracılığıyla kullanıcıya sunan kapsamlı bir sistemdir.
Modül ve Dosya Yapısı Özeti
ScanClass.py
Bu dosya, tarama işlemlerinin temel sınıflarını ve veri modellerini içerir. Enum sınıfları kullanılarak tarama tiplerini, port seçeneklerini ve çıktı formatlarını tanımlar.
Önemli Sınıflar ve Enumlar:

ScanType: TCP_CONNECT, TCP_SYN, UDP_SCAN gibi farklı tarama tiplerini tanımlar
PortOption: SINGLE, RANGE, FAST, TOP_1000 gibi port tarama stratejilerini belirler
ServiceDetection: Servis tespit düzeylerini (NONE, STANDARD, AGGRESSIVE vb.) tanımlar
ScriptCategory: Tarama sırasında kullanılacak script kategorilerini (VULN, DISCOVERY vb.) tanımlar
ScanRequest: Tarama parametrelerini barındıran Pydantic modeli

functions.py
Projenin merkezinde yer alan bu dosya, temel işlevleri ve yardımcı fonksiyonları içerir.
Önemli Fonksiyonlar:

run_scan_in_background: Tarama işlemini arka planda çalıştırır
estimate_scan_duration: Tarama süresini tahmin eder
parse_nmap_xml ve extract_services_from_xml: Tarama sonuçlarını analiz eder
get_incompatible_scan_types: Belirli bir tarama tipiyle uyumsuz olan diğer tipleri belirler

vuln.py
Zafiyet tarama işlemlerini gerçekleştiren bu modül, çeşitli harici araçları kullanarak servisler üzerinde güvenlik açıklarını tespit eder.
Önemli Fonksiyonlar:

scan_for_vulnerabilities_background: Zafiyet taramasını arka planda başlatır
scan_for_vulnerabilities: Ana zafiyet tarama işlevini yürütür
scan_service_vulnerabilities: Tek bir servis için zafiyet taraması yapar
search_cve_database: Ürün ve versiyon bilgilerine göre CVE veritabanında arama yapar

Kullanılan Zafiyet Tarama Araçları:

Nmap Vulners Script: Nmap aracının vulnerability tarama script'i. Servis ve versiyonlara göre CVE eşleşmelerini bulur.
Searchsploit: ExploitDB veritabanını sorgulayan bir araç. Belirli yazılım ve versiyonlar için bilinen exploitleri arar.
Vulscan NSE: Nmap için bir script kütüphanesi olup, çeşitli güvenlik veritabanlarını (CVE, ExploitDB vb.) kullanarak zafiyet taraması yapar.
Nikto: Web sunucularına özel zafiyet tarama aracı. HTTP/HTTPS servislerindeki yaygın güvenlik açıklarını tespit eder.

io.py
Dosya işlemleri ve veri dönüşümlerini gerçekleştiren yardımcı fonksiyonları içerir.
Önemli Fonksiyonlar:

parse_xml_file: XML dosyalarını güvenli bir şekilde ayrıştırır
write_to_csv: Tarama sonuçlarını CSV formatına dönüştürür
extract_services_from_xml: XML çıktılarından servis bilgilerini çıkarır

main.py
FastAPI tabanlı backend API'yi oluşturan ana dosya. Endpoint'leri tanımlar ve HTTP isteklerini işler.
Önemli Endpoint'ler:

/scan: Yeni bir tarama başlatır
/scan/{scan_id}/status: Belirli bir taramanın durumunu sorgular
/scan/{scan_name}/vulnerabilities: Zafiyet tarama sonuçlarını döndürür

Detaylı Fonksiyon Açıklamaları
ScanClass.py
ScanType Enum
Nmap tarafından desteklenen tarama tiplerini tanımlar:

TCP_CONNECT (sT): Tam TCP bağlantı taraması, en güvenilir ancak daha yavaş tarama yöntemi
TCP_SYN (sS): Yarı-açık tarama, tamamlanmamış TCP bağlantıları kullanır, daha hızlı ve gizlidir
UDP_SCAN (sU): UDP portları için tarama yapar
PING_SCAN (sP): Sadece ping taraması yaparak sistemlerin aktif olup olmadığını kontrol eder
SKIP_PING (Pn): Ping sorgusu yapmadan tüm hedefleri tarar

ScanRequest Sınıfı
Kullanıcının tanımladığı tarama parametrelerini içeren Pydantic modeli:

target: Taranacak hedef (IP, alan adı, IP aralığı)
target_type: Hedefin türü (tek IP, host adı, IP aralığı vb.)
port_option: Port tarama stratejisi
scan_type: Kullanılacak tarama yöntemi
service_detection: Servis tespit seviyesi
script_category: Çalıştırılacak script kategorisi

vuln.py
scan_for_vulnerabilities_background(scan_name, xml_path)
Zafiyet taramasını arka planda başlatan fonksiyon.

Ayrı bir thread oluşturarak zafiyet taramasını asenkron bir şekilde çalıştırır
Ana uygulamayı bloke etmeden uzun süren zafiyet taramalarını gerçekleştirir

scan_for_vulnerabilities(scan_name, xml_path)
Ana zafiyet tarama işlevini yürüten fonksiyon.

XML çıktısından servis bilgilerini çıkarır
Her servis için scan_service_vulnerabilities fonksiyonunu çağırır
Sonuçları bir JSON veri yapısında toplar

scan_service_vulnerabilities(service)
Belirli bir servis için zafiyet taramalarını gerçekleştirir.

CVE veritabanında ürün ve sürüm bilgilerine göre arama yapar
Searchsploit ile exploit taraması yapar
Nmap Vulners script'i ile canlı zafiyet taraması gerçekleştirir

search_with_searchsploit(product, version)
Searchsploit aracını kullanarak exploit veritabanında arama yapar.

Ürün ve sürüm bilgilerine göre exploitleri sorgular
Bulunan exploitleri bir liste halinde döndürür
ExploitDB'den elde edilen sonuçları işler

scan_with_vulners_nse(ip, port)
Nmap Vulners NSE script'i kullanarak zafiyet taraması yapar.

Belirli bir IP:Port kombinasyonu için canlı zafiyet taraması gerçekleştirir
CVSS skorlarına göre risk seviyelerini belirler
CVE numaralarını ve açıklamalarını toplar

scan_with_vulscan_nse(ip, port)
Nmap Vulscan script kütüphanesini kullanarak zafiyet taraması yapar.

Çeşitli güvenlik veritabanlarını (CVE, ExploitDB, OSVDB vb.) kullanır
Bulunan zafiyetleri ID ve açıklamalarıyla birlikte kaydeder

scan_with_nikto(ip, port)
Nikto web tarama aracını kullanarak web sunucularında zafiyet taraması yapar.

HTTP/HTTPS hizmetleri için özelleştirilmiş güvenlik kontrollerini gerçekleştirir
OSVDB ve CVE referanslarını içeren zafiyet raporları üretir

search_cve_database(product, version)
Yerel CVE veritabanında ürün ve sürüm bilgilerine göre arama yapar.

Yaygın servislere (Apache, MySQL, SSH vb.) ait bilinen zafiyetleri içerir
Ürün adına göre eşleşen zafiyetleri döndürür
Sürüm bilgisine göre filtreleme uygular

functions.py
run_scan_in_background(scan_id, request)
Tarama işlemini arka planda çalıştıran ana fonksiyon.

Hedefi ve tarama parametrelerini doğrular
Nmap komutunu oluşturur ve çalıştırır
Tarama durumunu periyodik olarak günceller
Sonuçları XML, CSV ve diğer formatlarda kaydeder
Tamamlandığında zafiyet taramasını başlatır

estimate_scan_duration(request)
Tarama parametrelerine göre tahmini süreyi hesaplar.

Hedef tipi, port stratejisi, tarama tipi gibi faktörleri değerlendirir
Dakika veya saat cinsinden tahmini süreyi döndürür

extract_host_data(host) ve extract_port_data(host, host_data)
Nmap XML çıktısından host ve port verilerini çıkaran fonksiyonlar.

IP adresi, hostname, MAC adresi, OS bilgisi gibi verileri toplar
Açık portlar, servisler, sürümler ve script çıktılarını ayrıştırır

get_incompatible_scan_types(scan_type)
Belirli bir tarama tipiyle birlikte kullanılamayacak diğer tarama tiplerini belirler.

TCP, UDP ve özel tarama tipleri arasındaki uyumsuzlukları yönetir

io.py
parse_nmap_xml(xml_file)
Nmap XML çıktısını ayrıştırarak yapılandırılmış veriye dönüştürür.

Tarama bilgilerini, host detaylarını ve port verilerini çıkarır
Elde edilen verileri işlenmiş bir veri yapısında döndürür

write_to_csv(scan_info, all_data, output_file)
Tarama sonuçlarını CSV formatına dönüştürür.

Sonuçları okuması ve işlemesi kolay bir tabloya çevirir
Tarama bilgilerini üstveri olarak CSV dosyasına ekler

extract_services_from_xml(xml_path)
XML çıktısından servis ve sürüm bilgilerini çıkarır.

Zafiyet taraması için gerekli temel servis bilgilerini toplar
IP, port, protokol, servis adı, ürün adı ve sürüm bilgilerini içerir

main.py
ScanScheduler Sınıfı
Tarama işlerini öncelik sırasına göre yöneten zamanlaycı sınıfı.

Taramaları öncelik kuyruklarına ekler
Arka planda sürekli çalışan bir thread ile taramaları sıraya göre çalıştırır
Sistem kaynaklarını verimli kullanmak için iş parçacığı havuzu (thread pool) yönetir

/scan Endpoint
Yeni bir tarama başlatmak için kullanılan API endpoint'i.

ScanRequest nesnesini alır ve doğrular
Benzersiz bir scan_id oluşturur
Tarama önceliğini belirler
Taramayı zamanlaycıya ekler

/scan/{scan_id}/status Endpoint
Belirli bir taramanın durumunu sorgulamak için kullanılan API endpoint'i.

Taramanın geçerli durumunu, ilerleme yüzdesini ve mesajlarını döndürür

/scan/{scan_name}/vulnerabilities Endpoint
Zafiyet tarama sonuçlarını sorgulamak için kullanılan API endpoint'i.

Belirli bir tarama için zafiyet verilerini döndürür
Zafiyet taraması tamamlanmamışsa, taramayı başlatır
Zafiyet dosyası bozuk veya eksikse, yeniden tarama başlatır

Proje Mimarisi ve İş Akışı

Kullanıcı, web UI üzerinden tarama parametrelerini belirler
FastAPI endpoint'i üzerinden tarama isteği alınır ve önceliklendirilir
Tarama zamanlaycısı, tarama işlemini arka planda çalıştırır
Nmap ile hedef sistemler taranır ve sonuçlar XML formatında kaydedilir
XML çıktısı işlenerek servis ve portlar tespit edilir
Tespit edilen her servis için zafiyet taraması gerçekleştirilir:

CVE veritabanında arama yapılır
Searchsploit ile exploit taraması yapılır
Vulners/Vulscan scriptleri çalıştırılır
Web servisler için Nikto ile özel tarama yapılır


Tüm sonuçlar işlenerek kullanıcıya sunulur

Bu proje, modern bir ağ güvenliği tarama aracı olarak tasarlanmış olup, çeşitli harici araçları (Nmap, Searchsploit, Vulners, Nikto) tek bir arayüz altında birleştirmektedir. Docker konteynerizasyonu sayesinde tüm bağımlılıklar entegre edilmiş ve dağıtım kolaylaştırılmıştır