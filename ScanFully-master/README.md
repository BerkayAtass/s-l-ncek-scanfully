## API Kullanımı

front/services/api.jsx içinde 3 farklı fonksiyon bulunuyor.

- crateScan ---> tarama başlatma
- getScans  ---> bütün taramaları alma
- getScanDetails ---> tarama detaylarını alma


Tarama yapma işlemi front/src/pages/scan.jsx dosyasında 95.satırda submitScan fonksiyonuyla yapılıyor.

PrepareScanRequestte kullanıcının girmiş olduğu işlemler doğrultusunda veri formatı hazırlanıyor. 

console.log ile ekrana yazdırılıyor. 99.satırda API Post işlemi gerçekleşiyor.

------------------------------------------

front/src/pages/oldScan.jsx dosyasında 19.satırda sayfa yüklenir yüklenmez. getScans fonksiyonu ile veri çekilip "scans" state değerine atanır. 32. satırda map ile ekrana yazdırılır.


------------------------------------------


getScanDetails ---> front/src/pages/scanDetail.jsx altında 18.satırda veri çekme işlemleri gerçekleşiyor.



--------------------------------------

Aynı anda tarama işlemi hala gerçekleşmiyor gibi gözüküyor.

docker üzerinden ping atma işlemi denenecek

Zafiyetli makineler kurularak test gerçekleştirilecek.