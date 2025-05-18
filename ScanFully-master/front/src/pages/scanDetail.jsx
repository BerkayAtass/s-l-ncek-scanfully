import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Box, Typography, Paper, CircularProgress, Alert,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  FormControlLabel, Checkbox, FormGroup, Button, TextField,
  IconButton, Chip, Tabs, Tab
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import FilterListIcon from '@mui/icons-material/FilterList';
import CloudDownloadIcon from '@mui/icons-material/CloudDownload';
import BugReportIcon from '@mui/icons-material/BugReport';
import { useParams } from 'react-router-dom';
import { useSelector } from 'react-redux';
import Appbar from '../components/header';

// API_URL sabit değişkeni
const API_URL = 'http://127.0.0.1:8001';

// Tarama tablosu verilerini al
const getScanTable = async (scanName) => {
  try {
    const response = await axios.get(`${API_URL}/scan/${scanName}/table`);
    return response.data;
  } catch (error) {
    console.error('Tarama tablo verileri hatası:', error);
    throw error;
  }
};

// Zafiyet verilerini al
const getScanVulnerabilities = async (scanName) => {
  try {
    console.log(`Zafiyet verileri isteniyor: ${scanName}`);
    const response = await axios.get(`${API_URL}/scan/${scanName}/vulnerabilities`, {
      headers: {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache'
      },
      timeout: 10000 // 10 saniye timeout
    });
    
    console.log('Zafiyet yanıtı alındı:', response.data);
    return response.data;
  } catch (error) {
    console.error('Zafiyet verileri hatası:', error);
    throw error;
  }
};

function ScanResultsTable() {
  const { id } = useParams();
  const { theme, colors } = useSelector((store) => store.constant);
  
  const [tableData, setTableData] = useState({ columns: [], data: [] });
  const [filteredData, setFilteredData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Filtre durumları
  const [onlyOpenPorts, setOnlyOpenPorts] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  
  // İstatistikler
  const [stats, setStats] = useState({
    totalRows: 0,
    openPorts: 0,
    uniqueServices: 0,
    ipAddresses: 0
  });

  // Zafiyet sekmesi için state'ler
  const [activeTab, setActiveTab] = useState('results');
  const [vulnerabilityData, setVulnerabilityData] = useState(null);
  const [vulnerabilityLoading, setVulnerabilityLoading] = useState(false);
  const [vulnerabilityError, setVulnerabilityError] = useState(null);
  
  useEffect(() => {
    fetchTableData();
  }, [id]);
  
  useEffect(() => {
    if (tableData.data.length > 0) {
      applyFilters();
    }
  }, [tableData, onlyOpenPorts, searchTerm]);
  
  // Zafiyet verilerini almak için useEffect
  useEffect(() => {
    if (activeTab === 'vulnerabilities') {
      fetchVulnerabilityData();
    }
  }, [activeTab, id]);
  
  // Tablo verilerini API'den çek
  const fetchTableData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      console.log(`Tarama tablo verileri alınıyor: ${id}`);
      const response = await getScanTable(id);
      
      if (!response || !response.data || !Array.isArray(response.data)) {
        setTableData({ columns: ['Bilgi'], data: [['Veri bulunamadı']] });
        setFilteredData([['Veri bulunamadı']]);
        setLoading(false);
        return;
      }
      
      setTableData(response);
      console.log('Tarama tablo verileri alındı:', response);
      
      setLoading(false);
    } catch (err) {
      console.error('Tarama tablo verileri alınırken hata:', err);
      setError('Veriler alınırken bir hata oluştu: ' + (err.message || 'Bilinmeyen hata'));
      setLoading(false);
    }
  };
  
  // Zafiyet verilerini getir fonksiyonu
  const fetchVulnerabilityData = async () => {
    try {
      setVulnerabilityLoading(true);
      setVulnerabilityError(null);
      
      console.log(`Zafiyet verileri alınıyor: ${id}`);
      const data = await getScanVulnerabilities(id);
      console.log('Zafiyet verileri:', data);
      setVulnerabilityData(data);
      
      setVulnerabilityLoading(false);
    } catch (err) {
      console.error('Zafiyet verileri alınırken hata:', err);
      setVulnerabilityError('Zafiyet verileri alınamadı: ' + (err.message || 'Bilinmeyen hata'));
      setVulnerabilityLoading(false);
    }
  };
  
  // Filtreleri uygula
  const applyFilters = () => {
    if (!tableData.data || !Array.isArray(tableData.data) || tableData.data.length === 0) {
      setFilteredData([]);
      updateStats([]);
      return;
    }
    
    let data = [...tableData.data];
    
    // Sütun indekslerini bul
    const stateIndex = tableData.columns.findIndex(col => col.toLowerCase() === 'state' || col.toLowerCase() === 'durum');
    const serviceIndex = tableData.columns.findIndex(col => col.toLowerCase() === 'service' || col.toLowerCase() === 'servis');
    const ipIndex = tableData.columns.findIndex(col => col.toLowerCase() === 'ip');
    
    // Sadece açık portlar filtresi
    if (onlyOpenPorts && stateIndex !== -1) {
      data = data.filter(row => row[stateIndex] === 'open');
    }
    
    // Arama filtresi
    if (searchTerm.trim()) {
      const term = searchTerm.toLowerCase();
      data = data.filter(row => 
        row.some(cell => 
          cell && cell.toString().toLowerCase().includes(term)
        )
      );
    }
    
    setFilteredData(data);
    updateStats(data, { stateIndex, serviceIndex, ipIndex });
  };
  
  // İstatistikleri güncelle
  const updateStats = (data, indexes = {}) => {
    if (!data || !Array.isArray(data)) return;
    
    const { stateIndex = -1, serviceIndex = -1, ipIndex = -1 } = indexes;
    
    // Açık portları say
    const openPorts = stateIndex !== -1 
      ? data.filter(row => row[stateIndex] === 'open').length 
      : 0;
    
    // Benzersiz servisleri say
    const uniqueServices = serviceIndex !== -1 
      ? new Set(data.filter(row => row[serviceIndex]).map(row => row[serviceIndex])).size 
      : 0;
    
    // Benzersiz IP'leri say
    const ipAddresses = ipIndex !== -1 
      ? new Set(data.filter(row => row[ipIndex]).map(row => row[ipIndex])).size 
      : 0;
    
    setStats({
      totalRows: data.length,
      openPorts,
      uniqueServices,
      ipAddresses
    });
  };
  
  // CSV olarak dışa aktar
  const exportAsCSV = () => {
    if (!filteredData.length || !tableData.columns.length) return;
    
    // Başlık satırı
    const headers = tableData.columns.join(',');
    
    // Veri satırları
    const rows = filteredData.map(row => 
      row.map(cell => {
        const value = cell || '';
        return value.toString().includes(',') ? `"${value}"` : value;
      }).join(',')
    ).join('\n');
    
    const csvContent = `${headers}\n${rows}`;
    
    // CSV dosyasını indir
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `${id}_scan_results.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };
  
  // Port durumuna göre hücre renklendirme
  const getStatusStyle = (status) => {
    if (!status) return {};
    
    switch(status.toLowerCase()) {
      case 'open':
        return { 
          backgroundColor:  'rgba(76, 175, 80, 0.1)', 
          fontWeight: 'bold' 
        };
      case 'closed':
        return { 
          backgroundColor: 'rgba(244, 67, 54, 0.1)'
        };
      case 'filtered':
        return { 
          backgroundColor: 'rgba(255, 152, 0, 0.1)'
        };
      default:
        return {};
    }
  };

  // Risk seviyesine göre renk döndürür
  const getRiskColor = (risk) => {
    switch(risk) {
      case 'Kritik': return { bg: '#d32f2f', text: 'white' };
      case 'Yüksek': return { bg: '#f57c00', text: 'black' };
      case 'Orta': return { bg: '#fbc02d', text: 'black' };
      case 'Düşük': return { bg: '#388e3c', text: 'white' };
      default: return { bg: '#9e9e9e', text: 'white' };
    }
  };
  
  return (
    <div>
      <Appbar/>
      <div style={{ backgroundColor: colors.bodyLightColor, minHeight: '100vh' }}>
        <Box sx={{ p: 3 }}>
          <Paper 
            elevation={3} 
            sx={{ 
              p: 2, 
              mb: 3, 
              backgroundColor: colors.scanLightColor,
              color: colors.lightText 
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap' }}>
              <Typography variant="h5" component="h1" sx={{ mb: { xs: 2, md: 0 } }}>
                Tarama Sonuçları: {id}
              </Typography>
              
              {/* Tab Bar */}
              <Tabs 
                value={activeTab} 
                onChange={(e, newValue) => setActiveTab(newValue)}
                aria-label="scan detail tabs"
              >
                <Tab label="Tarama Sonuçları" value="results" />
                <Tab label="Zafiyetler" value="vulnerabilities" icon={<BugReportIcon />} />
              </Tabs>
            </Box>
            
            {/* Sonuçlar sekmesi */}
            {activeTab === 'results' && (
              <>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Box>
                    {!loading && filteredData.length > 0 && stats.totalRows > 0 && (
                      <Box sx={{ mb: 2, display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                        <Chip 
                          label={`Toplam Satır: ${stats.totalRows}`} 
                          size="small"
                          sx={{ 
                            backgroundColor: theme ? 'rgba(74, 71, 71, 0.73)' : 'rgba(0,0,0,0.1)',
                            color: theme ? colors.darkText : colors.lightText
                          }}
                        />
                        {stats.openPorts > 0 && (
                          <Chip 
                            label={`Açık Port: ${stats.openPorts}`} 
                            size="small"
                            sx={{ 
                              backgroundColor: theme ? 'rgba(46, 125, 50, 0.6)' : 'rgba(76, 175, 80, 0.2)',
                              color: theme ? colors.darkText : colors.lightText
                            }}
                          />
                        )}
                        {stats.uniqueServices > 0 && (
                          <Chip 
                            label={`Farklı Servis: ${stats.uniqueServices}`} 
                            size="small"
                            sx={{ 
                              backgroundColor: theme ? 'rgba(2, 136, 209, 0.6)' : 'rgba(255, 118, 20, 0.2)',
                              color: theme ? colors.darkText : colors.lightText
                            }}
                          />
                        )}
                        {stats.ipAddresses > 0 && (
                          <Chip 
                            label={`IP Sayısı: ${stats.ipAddresses}`} 
                            size="small"
                            sx={{ 
                              backgroundColor: theme ? 'rgba(217, 0, 255, 0.96)' : 'rgba(186, 104, 200, 0.2)',
                              color: theme ? colors.darkText : colors.lightText
                            }}
                          />
                        )}
                      </Box>
                    )}
                  </Box>
                  
                  <Box>
                    <IconButton 
                      sx={{ color: theme ? colors.darkText : colors.lightText }}
                      onClick={() => setShowFilters(!showFilters)}
                      title="Filtreleri göster/gizle"
                    >
                      <FilterListIcon />
                    </IconButton>
                    
                    <Button 
                      variant="contained" 
                      color="primary" 
                      startIcon={<CloudDownloadIcon />} 
                      disabled={!filteredData.length}
                      onClick={exportAsCSV}
                      size="small"
                      sx={{ ml: 1 }}
                    >
                      CSV İndir
                    </Button>
                  </Box>
                </Box>
                
                {/* Filtreleme bölümü */}
                {showFilters && (
                  <Paper 
                    elevation={2} 
                    sx={{ 
                      mb: 2, 
                      p: 2, 
                      backgroundColor: theme ? colors.cardDarkColor : '#f5f5f5',
                      color: theme ? colors.darkText : colors.lightText  
                    }}
                  >
                    <Typography variant="subtitle1" gutterBottom>Filtreleme Seçenekleri</Typography>
                    
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center' }}>
                      <FormGroup>
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={onlyOpenPorts}
                              onChange={(e) => setOnlyOpenPorts(e.target.checked)}
                              color="primary"
                            />
                          }
                          label="Sadece açık portları göster"
                        />
                      </FormGroup>
                      
                      <TextField
                        label="Arama"
                        variant="outlined"
                        size="small"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        placeholder="Herhangi bir alana göre ara..."
                        InputProps={{
                          startAdornment: <SearchIcon fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />
                        }}
                        sx={{ 
                          minWidth: 220,
                          '& .MuiOutlinedInput-root': {
                            '& fieldset': {
                              borderColor: theme ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.2)'
                            },
                            '&:hover fieldset': {
                              borderColor: theme ? 'rgba(255,255,255,0.3)' : 'rgba(0,0,0,0.3)'
                            }
                          },
                          '& .MuiInputLabel-root': {
                            color: theme ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.7)'
                          },
                          '& .MuiInputBase-input': {
                            color: theme ? colors.darkText : colors.lightText
                          }
                        }}
                      />
                    </Box>
                  </Paper>
                )}
                
                {/* Yükleniyor ve hata durumları */}
                {loading ? (
                  <Box sx={{ display: 'flex', justifyContent: 'center', my: 5 }}>
                    <CircularProgress />
                  </Box>
                ) : error ? (
                  <Alert severity="error" sx={{ my: 2 }}>{error}</Alert>
                ) : filteredData.length === 0 ? (
                  <Alert severity="info" sx={{ my: 2 }}>
                    Gösterilecek sonuç bulunamadı. Filtreleri değiştirmeyi deneyin.
                  </Alert>
                ) : (
                  // Tablo
                  <Paper 
                    elevation={3} 
                    sx={{ 
                      mb: 3, 
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor,
                      color: theme ? colors.darkText : colors.lightText
                    }}
                  >
                    <TableContainer sx={{ overflow: 'auto' }}>
                      <Table sx={{ minWidth: 650 }} size="small" aria-label="scan results table">
                        <TableHead>
                          <TableRow sx={{ backgroundColor: theme ? 'rgba(234, 1, 1, 0.05)' : 'rgba(255, 0, 0, 0.03)' }}>
                            {tableData.columns.map((column, index) => (
                              <TableCell 
                                key={index} 
                                sx={{ 
                                  color: theme ? colors.darkText : colors.lightText, 
                                  fontWeight: 'bold' 
                                }}
                              >
                                {column}
                              </TableCell>
                            ))}
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {filteredData.map((row, rowIndex) => {
                            // "state" sütunu varsa, renklendirme kullan
                            const stateIndex = tableData.columns.findIndex(col => 
                              col.toLowerCase() === 'state' || col.toLowerCase() === 'durum'
                            );
                            
                            return (
                              <TableRow 
                                key={rowIndex}
                                sx={{ 
                                  '&:nth-of-type(odd)': { 
                                    backgroundColor: theme ? 'rgba(105, 104, 104, 0.91)' : 'rgba(190, 213, 234, 0.97)' 
                                  },
                                  '&:hover': { 
                                    backgroundColor: theme ? 'rgba(57, 108, 65, 0.94)' : 'rgb(195, 189, 159)' 
                                  }
                                }}
                              >
                                {row.map((cell, cellIndex) => {
                                  // "state" sütunu için özel stil
                                  if (cellIndex === stateIndex) {
                                    let statusColor = { bg: '#9e9e9e', text: 'white' };
                                    
                                    if (cell === 'open') {
                                      statusColor = { bg: '#4caf50', text: 'white' };
                                    } else if (cell === 'closed') {
                                      statusColor = { bg: '#f44336', text: 'white' };
                                    } else if (cell === 'filtered') {
                                      statusColor = { bg: '#ff9800', text: 'black' };
                                    }
                                    
                                    return (
                                      <TableCell key={cellIndex}>
                                        <Chip 
                                          label={cell || 'unknown'} 
                                          size="small"
                                          sx={{ 
                                            backgroundColor: statusColor.bg,
                                            color: statusColor.text,
                                            fontSize: '0.7rem',
                                            height: 20
                                          }}
                                        />
                                      </TableCell>
                                    );
                                  }
                                  
                                  // Normal hücreler
                                  return (
                                    <TableCell 
                                      key={cellIndex}
                                      sx={{ color: theme ? colors.darkText : colors.lightText }}
                                    >
                                      {cell}
                                    </TableCell>
                                  );
                                })}
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Paper>
                )}
              </>
            )}
            
            {/* Zafiyetler sekmesi */}
            {activeTab === 'vulnerabilities' && (
              <>
                {vulnerabilityLoading ? (
                  <Box sx={{ display: 'flex', justifyContent: 'center', my: 5 }}>
                    <CircularProgress />
                  </Box>
                ) : vulnerabilityError ? (
                  <Alert severity="error" sx={{ my: 2 }}>{vulnerabilityError}</Alert>
                ) : !vulnerabilityData ? (
                  <Alert severity="info" sx={{ my: 2 }}>
                    Zafiyet verileri yüklenemedi.
                  </Alert>
                ) : vulnerabilityData.status === 'processing' ? (
                  <Box sx={{ textAlign: 'center', my: 3 }}>
                    <CircularProgress sx={{ mb: 2 }} />
                    <Typography variant="body1">
                      {vulnerabilityData.message || "Zafiyet taraması devam ediyor, lütfen bekleyin..."}
                    </Typography>
                  </Box>
                ) : vulnerabilityData.services && vulnerabilityData.services.length === 0 ? (
                  <Alert severity="info" sx={{ my: 2 }}>
                    Bu taramada herhangi bir zafiyet tespit edilmedi.
                  </Alert>
                ) : (
                  <Box>
                    {vulnerabilityData.services.map((service, serviceIndex) => (
                      <Paper 
                        key={serviceIndex}
                        elevation={3} 
                        sx={{ 
                          mb: 3, 
                          backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor,
                          color: theme ? colors.darkText : colors.lightText,
                          overflow: 'hidden'
                        }}
                      >
                        <Box sx={{ 
                          p: 2, 
                          bgcolor: theme ? 'rgba(255, 0, 0, 0.1)' : 'rgba(255, 0, 0, 0.05)', 
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}>
                          <Box>
                            <Typography variant="h6">
                              {service.service} {service.product} {service.version}
                            </Typography>
                            <Typography variant="body2">
                              {service.ip}:{service.port} ({service.protocol})
                            </Typography>
                          </Box>
                          <Chip 
                            label={`${service.vulnerabilities.length} Zafiyet`}
                            color="error"
                            variant="outlined"
                          />
                        </Box>
                        
                        <TableContainer>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell sx={{ fontWeight: 'bold', color: theme ? colors.darkText : colors.lightText }}>
                                  Zafiyet ID
                                </TableCell>
                                <TableCell sx={{ fontWeight: 'bold', color: theme ? colors.darkText : colors.lightText }}>
                                  Başlık
                                </TableCell>
                                <TableCell sx={{ fontWeight: 'bold', color: theme ? colors.darkText : colors.lightText }}>
                                  Risk
                                </TableCell>
                                <TableCell sx={{ fontWeight: 'bold', color: theme ? colors.darkText : colors.lightText }}>
                                  Araç
                                </TableCell>
                                <TableCell sx={{ fontWeight: 'bold', color: theme ? colors.darkText : colors.lightText }}>
                                  Referans
                                </TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {service.vulnerabilities.map((vuln, vulnIndex) => {
                                const riskColor = getRiskColor(vuln.risk);
                                return (
                                  <TableRow key={vulnIndex}>
                                    <TableCell sx={{ color: theme ? colors.darkText : colors.lightText }}>
                                      {vuln.id}
                                    </TableCell>
                                    <TableCell sx={{ color: theme ? colors.darkText : colors.lightText }}>
                                      {vuln.title}
                                    </TableCell>
                                    <TableCell>
                                      <Chip 
                                        label={vuln.risk}
                                        size="small"
                                        sx={{ 
                                          backgroundColor: riskColor.bg,
                                          color: riskColor.text,
                                          fontWeight: 'bold',
                                          fontSize: '0.7rem'
                                        }}
                                      />
                                    </TableCell>
                                    <TableCell sx={{ color: theme ? colors.darkText : colors.lightText }}>
                                      {vuln.tool}
                                    </TableCell>
                                    <TableCell>
                                      {vuln.reference ? (
                                        <Button 
                                          href={vuln.reference} 
                                          target="_blank" 
                                          size="small" 
                                          variant="outlined"
                                        >
                                          Detaylar
                                        </Button>
                                      ) : 'N/A'}
                                    </TableCell>
                                  </TableRow>
                                );
                              })}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Paper>
                    ))}
                  </Box>
                )}
              </>
            )}
          </Paper>
        </Box>
      </div>
    </div>
  );
}

export default ScanResultsTable;