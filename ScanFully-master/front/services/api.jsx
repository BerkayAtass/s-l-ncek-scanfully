// services/api.js
import axios from 'axios';

const API_URL = 'http://127.0.0.1:8001';

// Tarama adı kontrolü
export const checkName = async (name) => {
  try {
    const response = await axios.get(`${API_URL}/scan/check_name/${name}`);
    return response.data.exists;
  } catch (error) {
    console.error('İsim kontrol hatası:', error);
    throw error;
  }
};

// Tarama oluşturma
export const createScan = async (scanData) => {
  try {
    const response = await axios.post(`${API_URL}/scan`, scanData);
    return response.data;
  } catch (error) {
    console.error('Tarama hatası:', error);
    throw error;
  }
};

// Tüm taramaları getir
export const getScans = async () => {
  try {
    const response = await axios.get(`${API_URL}/scans`);
    return response.data;
  } catch (error) {
    console.error('Tarama listesi hatası:', error);
    throw error;
  }
};

export const getScanDetails = async (scanName) => {
  try {
    const response = await axios.get(`${API_URL}/scan/${scanName}/details`);
    return response.data;
  } catch (error) {
    console.error('Tarama detayları hatası:', error);

    // Backend'den 500 hatası geldiğinde daha anlamlı bir hata nesnesi döndür
    if (error.response && error.response.status === 500) {
      return {
        error: true,
        message: "Tarama detayları alınırken sunucu hatası oluştu. Tarama sonuçları çok büyük veya uyumsuz veri içeriyor olabilir.",
        name: scanName
      };
    }

    // 404 hatası için ayrı mesaj
    if (error.response && error.response.status === 404) {
      return {
        error: true,
        message: "Tarama bulunamadı. Silinmiş veya adı değişmiş olabilir.",
        name: scanName
      };
    }

    // Diğer hatalar için genel mesaj
    return {
      error: true,
      message: `Tarama detayları alınırken hata: ${error.message}`,
      name: scanName
    };
  }
};

// Zafiyet tarama sonuçlarını getir
export const getScanVulnerabilities = async (scanName) => {
  try {
    const response = await axios.get(`${API_URL}/scan/${scanName}/vulnerabilities`);
    return response.data;
  } catch (error) {
    console.error('Zafiyet verileri hatası:', error);
    throw error;
  }
};

// Tarama süresi tahmini al
export const getScanEstimate = async (params) => {
  try {
    const response = await axios.get(`${API_URL}/scan/estimate`, { params });
    return response.data;
  } catch (error) {
    console.error('Süre tahmini hatası:', error);
    throw error;
  }
};

// Aktif taramaları getir (son 30 dakikada başlatılan taramalar)
export const getActiveScans = async (minutes = 30, retryCount = 2) => {
  let attempts = 0;

  const fetchData = async () => {
    try {
      console.log('Aktif tarama verileri alınıyor...');
      const response = await axios.get(`${API_URL}/scans/active`, {
        timeout: 10000 // 10 saniye timeout
      });

      // API yanıtı kontrol
      if (!response || !response.data) {
        console.warn('API yanıtı boş veya geçersiz format');
        return { activeScans: [] };
      }

      // Tarama verisi kontrol
      const scans = response.data.active_scans || [];
      if (scans.length === 0) {
        console.log('Aktif tarama bulunamadı');
        return { activeScans: [] };
      }

      // Aktif tarama verilerini doğrudan kullan
      const activeScans = scans.map(scan => ({
        scan_id: scan.scan_id || '',
        scan_name: scan.scan_name || 'İsimsiz Tarama',
        target: scan.target || '',
        progress: scan.progress || 0,
        message: scan.message || '',
        status: scan.status || 'running',
        created_at: scan.created_at || ''
      }));

      console.log(`${activeScans.length} aktif tarama bulundu`);
      return { activeScans };

    } catch (error) {
      console.error('Aktif taramalar alınırken hata:', error.message);

      // Sunucu hatası veya ağ problemi ise tekrar dene
      if (axios.isAxiosError(error) && (error.response?.status >= 500 || !error.response) && attempts < retryCount) {
        attempts++;
        console.log(`Aktif tarama verileri ${attempts}. kez tekrar deneniyor...`);

        // Üstel gecikme ile tekrar dene (0.5s, 1.5s, 3.5s, ...)
        const delay = Math.pow(2, attempts) * 500 + Math.random() * 500;
        await new Promise(resolve => setTimeout(resolve, delay));

        return fetchData();
      }

      // API hatası daha ayrıntılı loglanabilir
      if (error.response) {
        console.error('API Hata Detayı:', {
          status: error.response.status,
          data: error.response.data
        });
      }

      // Beklenmeyen hatalarda boş liste dön ama hatayı fırlat
      throw error;
    }
  };

  try {
    return await fetchData();
  } catch (error) {
    console.error('Tüm aktif tarama alma denemeleri başarısız oldu');
    // Uygulama çalışmaya devam etsin diye hata yerine boş dizi dön
    return { activeScans: [] };
  }
};

// Dosya içeriğini al
export const getFileContent = async (scanName, fileName) => {
  try {
    const response = await axios.get(`${API_URL}/scan/${scanName}/file/${fileName}`);
    return response.data;
  } catch (error) {
    console.error("Dosya içeriği alınırken hata:", error);
    // Hata durumunda boş içerik döndür
    return { content: null, error: error.message };
  }
};

export const getScanTable = async (scanName) => {
  try {
    const response = await axios.get(`${API_URL}/scan/${scanName}/table`);
    return response.data;
  } catch (error) {
    console.error('Tarama tablo verileri hatası:', error);
    throw error;
  }
};