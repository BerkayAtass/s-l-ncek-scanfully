import React, { useState, useEffect } from 'react';
import Appbar from '../components/header';
import { 
  Card, CardContent, CardActions, Button, Typography, Chip, Grid, Box, 
  CircularProgress, Alert, Divider, LinearProgress, Badge, Tab, Tabs,
  IconButton, Tooltip, MenuItem, Menu, TextField, InputAdornment,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import { getScans, getActiveScans, getScanTable } from '../../services/api';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import TargetIcon from '@mui/icons-material/GpsFixed';
import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import SortIcon from '@mui/icons-material/Sort';
import FilterListIcon from '@mui/icons-material/FilterList';
import SubjectIcon from '@mui/icons-material/Subject';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SecurityIcon from '@mui/icons-material/Security';
import ViewListIcon from '@mui/icons-material/ViewList';
import GridViewIcon from '@mui/icons-material/GridView';

function OldScan() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [activeScans, setActiveScans] = useState([]);
  const [combinedScans, setCombinedScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [tabValue, setTabValue] = useState(0);
  const [sortAnchorEl, setSortAnchorEl] = useState(null);
  const [filterAnchorEl, setFilterAnchorEl] = useState(null);
  const [sortOption, setSortOption] = useState('date-desc');
  const [filterOption, setFilterOption] = useState('all');
  const { theme, colors } = useSelector((store) => store.constant);
  
  // Yeni: Aktif taramalar için tablo verileri
  const [activeScanTables, setActiveScanTables] = useState({});
  const [loadingTables, setLoadingTables] = useState({});
  const [viewMode, setViewMode] = useState('cards'); // 'cards' veya 'table'
  const [tableDataLoaded, setTableDataLoaded] = useState(false);

  // Yeni: Tablo veri yükleme fonksiyonu
  const fetchActiveScanTables = async () => {
    // Önceki aktif taramalar için tablolar artık yüklenmekte değil
    setLoadingTables({});
    
    // Yeni yükleme durumlarını oluştur
    const newLoadingStates = {};
    activeScans.forEach(scan => {
      newLoadingStates[scan.scan_name] = true;
    });
    setLoadingTables(newLoadingStates);
    
    // Her aktif tarama için tablo verilerini çek
    const tables = {};
    const promises = activeScans.map(async (scan) => {
      try {
        if (!scan.scan_name) return;
        
        const tableData = await getScanTable(scan.scan_name);
        tables[scan.scan_name] = tableData;
      } catch (err) {
        console.error(`${scan.scan_name} tablosu alınırken hata:`, err);
        tables[scan.scan_name] = { error: true, message: err.message };
      } finally {
        setLoadingTables(prev => ({
          ...prev,
          [scan.scan_name]: false
        }));
      }
    });
    
    await Promise.all(promises);
    setActiveScanTables(tables);
    setTableDataLoaded(true);
  };

  // Data fetching
  const fetchData = async () => {
    setLoading(true);
    try {
      console.log("Tüm tarama verileri isteniyor...");
      
      // Parallel data fetching with Promise.all
      const [scansResponse, activeScansResponse] = await Promise.all([
        getScans(),
        getActiveScans()
      ]);
      
      console.log("Tamamlanan taramalar:", scansResponse);
      console.log("Aktif taramalar:", activeScansResponse);
      
      // Process completed scans
      if (scansResponse && scansResponse.scans && Array.isArray(scansResponse.scans)) {
        setScans(scansResponse.scans);
      } else {
        console.warn("Tamamlanan tarama verisi uygun formatta değil:", scansResponse);
        setScans([]);
      }
  
      // Process active scans - veri yapısı kontrollerini iyileştirme
      if (activeScansResponse) {
        // API yanıt formatı değişmiş olabilir, farklı olası yapıları kontrol et
        let activeScansList = [];
        
        if (activeScansResponse.active_scans && Array.isArray(activeScansResponse.active_scans)) {
          activeScansList = activeScansResponse.active_scans;
          console.log(`${activeScansList.length} aktif tarama bulundu (active_scans)`);
        } else if (activeScansResponse.activeScans && Array.isArray(activeScansResponse.activeScans)) {
          activeScansList = activeScansResponse.activeScans;
          console.log(`${activeScansList.length} aktif tarama bulundu (activeScans)`);
        } else if (Array.isArray(activeScansResponse)) {
          activeScansList = activeScansResponse;
          console.log(`${activeScansList.length} aktif tarama bulundu (doğrudan dizi)`);
        }
        
        // Aktif taramaları state'e kaydet
        setActiveScans(activeScansList);
        
        // Eğer aktif tarama sekmesindeyse ve tablo görünümündeyse, tablo verilerini getir
        if (tabValue === 1 && viewMode === 'table' && activeScansList.length > 0) {
          fetchActiveScanTables();
        }
      } else {
        console.warn("Aktif tarama verisi alınamadı:", activeScansResponse);
        setActiveScans([]);
      }
  
      setError(null);
    } catch (err) {
      console.error("Tarama verileri alınırken hata:", err);
      setError("Taramalar alınırken bir hata oluştu");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // Initial data load
  useEffect(() => {
    fetchData();
    
    // Set up interval to refresh active scans every 10 seconds
    const intervalId = setInterval(() => {
      console.log("Aktif taramalar periyodik kontrolü yapılıyor...");
      getActiveScans()
        .then(response => {
          console.log("Periyodik kontrol yanıtı:", response);
          
          // API yanıt formatı değişmiş olabilir, farklı olası yapıları kontrol et
          let activeScansList = [];
          
          if (response && response.active_scans && Array.isArray(response.active_scans)) {
            activeScansList = response.active_scans;
          } else if (response && response.activeScans && Array.isArray(response.activeScans)) {
            activeScansList = response.activeScans;
          } else if (Array.isArray(response)) {
            activeScansList = response;
          }
          
          if (activeScansList.length > 0) {
            console.log(`${activeScansList.length} aktif tarama güncellendi`);
            setActiveScans(activeScansList);
            
            // Eğer aktif tarama sekmesindeyse ve tablo görünümündeyse, tablo verilerini güncelle
            if (tabValue === 1 && viewMode === 'table') {
              fetchActiveScanTables();
            }
          } else {
            console.log("Aktif tarama bulunamadı veya tamamlandı");
          }
        })
        .catch(err => {
          console.error("Aktif tarama periyodik güncellemesi hatası:", err);
        });
    }, 10000);
    
    return () => clearInterval(intervalId);
  }, [tabValue, viewMode]);

  // Yeni: Tab değiştiğinde veya görünüm modu değiştiğinde
  useEffect(() => {
    // Eğer aktif taramalar sekmesine geçildiyse ve tablo modundaysa tablo verilerini yükle
    if (tabValue === 1 && viewMode === 'table' && !tableDataLoaded) {
      fetchActiveScanTables();
    }
  }, [tabValue, viewMode]);

  // Combine and sort scans whenever active scans or completed scans change
  useEffect(() => {
    // Create combined list of scans with type property
    const combined = [
      ...activeScans.map(scan => ({
        ...scan,
        type: 'active',
        info: {
          date: new Date(scan.created_at).toLocaleDateString(),
          time: new Date(scan.created_at).toLocaleTimeString(),
          target: scan.target || "Bilinmeyen hedef",
          target_type: scan.target_type || "Bilinmiyor",
          estimated_duration: scan.estimated_duration
        }
      })),
      ...scans.map(scan => ({
        ...scan,
        type: 'completed'
      }))
    ];
    
    // Apply search filter
    let filtered = combined;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = combined.filter(scan => {
        const scanName = scan.name || scan.scan_name || '';
        const target = (scan.info && scan.info.target) || scan.target || '';
        return scanName.toLowerCase().includes(term) || target.toLowerCase().includes(term);
      });
    }
    
    // Apply type filter
    if (filterOption !== 'all') {
      filtered = filtered.filter(scan => {
        if (filterOption === 'active') return scan.type === 'active';
        if (filterOption === 'completed') return scan.type === 'completed';
        if (filterOption === 'tcp') return scan.info && scan.info.scan_type && scan.info.scan_type.startsWith('s');
        if (filterOption === 'udp') return scan.info && scan.info.scan_type === 'sU';
        return true;
      });
    }
    
    // Apply sorting
    filtered.sort((a, b) => {
      const dateA = new Date(a.info?.date ? `${a.info.date} ${a.info.time || ''}` : a.created_at || 0);
      const dateB = new Date(b.info?.date ? `${b.info.date} ${b.info.time || ''}` : b.created_at || 0);
      
      switch(sortOption) {
        case 'date-asc':
          return dateA - dateB;
        case 'date-desc':
          return dateB - dateA;
        case 'name-asc':
          return (a.name || a.scan_name || '').localeCompare(b.name || b.scan_name || '');
        case 'name-desc':
          return (b.name || b.scan_name || '').localeCompare(a.name || a.scan_name || '');
        default:
          return dateB - dateA;
      }
    });
    
    setCombinedScans(filtered);
  }, [scans, activeScans, searchTerm, sortOption, filterOption]);

  // Handle manual refresh
  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    if (tabValue === 1 && viewMode === 'table') {
      setTableDataLoaded(false);
      fetchActiveScanTables();
    }
  };
  
  // Tab handling
  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
    setFilterOption(newValue === 0 ? 'all' : newValue === 1 ? 'active' : 'completed');
    
    // Eğer aktif taramalara geçilirse ve tablo modundaysa tablo verilerini yükle
    if (newValue === 1 && viewMode === 'table' && !tableDataLoaded) {
      fetchActiveScanTables();
    }
  };

  // Menu handling
  const handleSortClick = (event) => {
    setSortAnchorEl(event.currentTarget);
  };
  
  const handleFilterClick = (event) => {
    setFilterAnchorEl(event.currentTarget);
  };
  
  const handleSortClose = () => {
    setSortAnchorEl(null);
  };
  
  const handleFilterClose = () => {
    setFilterAnchorEl(null);
  };
  
  const handleSortSelect = (option) => {
    setSortOption(option);
    handleSortClose();
  };
  
  const handleFilterSelect = (option) => {
    setFilterOption(option);
    handleFilterClose();
  };
  
  // Görünüm modunu değiştir
  const toggleViewMode = () => {
    const newMode = viewMode === 'cards' ? 'table' : 'cards';
    setViewMode(newMode);
    
    // Eğer aktif taramalar sekmesindeyse ve tablo moduna geçildiyse ve henüz yüklenmemişse
    if (tabValue === 1 && newMode === 'table' && !tableDataLoaded) {
      fetchActiveScanTables();
    }
  };

  // Render loading state
  if (loading && !refreshing) {
    return (
      <div style={{ backgroundColor: colors.bodyLightColor, minHeight: '100vh' }}>
        <Appbar />
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh', flexDirection: 'column' }}>
          <CircularProgress sx={{ mb: 2 }} />
          <Typography variant="h6">Taramalar Yükleniyor...</Typography>
        </Box>
      </div>
    );
  }

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

  return (
    <div style={{ backgroundColor: colors.bodyLightColor, minHeight: '100vh' }}>
      <Appbar />
      <Box sx={{ padding: "30px" }}>
        {/* Header and controls */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', mb: 3 }}>
          <Typography variant="h4" sx={{ mb: { xs: 2, md: 0 } }}>
            Tarama Listesi
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 2 }}>
            <TextField
              placeholder="Tarama ara..."
              size="small"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
              sx={{ width: { xs: '100%', sm: '200px' } }}
            />
            
            <Tooltip title="Sırala">
              <IconButton onClick={handleSortClick}>
                <SortIcon />
              </IconButton>
            </Tooltip>
            
            <Tooltip title="Filtrele">
              <IconButton onClick={handleFilterClick}>
                <FilterListIcon />
              </IconButton>
            </Tooltip>
            
            <Tooltip title={viewMode === 'cards' ? 'Tablo Görünümü' : 'Kart Görünümü'}>
              <IconButton onClick={toggleViewMode}>
                {viewMode === 'cards' ? <ViewListIcon /> : <GridViewIcon />}
              </IconButton>
            </Tooltip>
            
            <Tooltip title="Yenile">
              <IconButton onClick={handleRefresh} disabled={refreshing}>
                {refreshing ? <CircularProgress size={24} /> : <RefreshIcon />}
              </IconButton>
            </Tooltip>
            
            <Button 
              variant="contained" 
              color="primary"
              startIcon={<PlayArrowIcon />}
              onClick={() => navigate('../scan')}
            >
              Yeni Tarama
            </Button>
          </Box>
        </Box>
        
        {/* Sorting menu */}
        <Menu
          anchorEl={sortAnchorEl}
          open={Boolean(sortAnchorEl)}
          onClose={handleSortClose}
        >
          <MenuItem onClick={() => handleSortSelect('date-desc')} selected={sortOption === 'date-desc'}>
            En yeni ilk
          </MenuItem>
          <MenuItem onClick={() => handleSortSelect('date-asc')} selected={sortOption === 'date-asc'}>
            En eski ilk
          </MenuItem>
          <MenuItem onClick={() => handleSortSelect('name-asc')} selected={sortOption === 'name-asc'}>
            İsim (A-Z)
          </MenuItem>
          <MenuItem onClick={() => handleSortSelect('name-desc')} selected={sortOption === 'name-desc'}>
            İsim (Z-A)
          </MenuItem>
        </Menu>
        
        {/* Filtering menu */}
        <Menu
          anchorEl={filterAnchorEl}
          open={Boolean(filterAnchorEl)}
          onClose={handleFilterClose}
        >
          <MenuItem onClick={() => handleFilterSelect('all')} selected={filterOption === 'all'}>
            Tümü
          </MenuItem>
          <MenuItem onClick={() => handleFilterSelect('active')} selected={filterOption === 'active'}>
            Aktif Taramalar
          </MenuItem>
          <MenuItem onClick={() => handleFilterSelect('completed')} selected={filterOption === 'completed'}>
            Tamamlanan Taramalar
          </MenuItem>
          <Divider />
          <MenuItem onClick={() => handleFilterSelect('tcp')} selected={filterOption === 'tcp'}>
            TCP Taramaları
          </MenuItem>
          <MenuItem onClick={() => handleFilterSelect('udp')} selected={filterOption === 'udp'}>
            UDP Taramaları
          </MenuItem>
        </Menu>
        
        {/* Error display */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}
        
        {/* Tabs for filtering */}
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs value={tabValue} onChange={handleTabChange} aria-label="scan tabs">
            <Tab label={`Tümü (${combinedScans.length})`} />
            <Tab 
              label={
                <Badge badgeContent={activeScans.length} color="error" max={99} showZero={false}>
                  Aktif Taramalar
                </Badge>
              } 
            />
            <Tab label={`Tamamlanan (${scans.length})`} />
          </Tabs>
        </Box>
        
        {/* Refresh progress */}
        {refreshing && (
          <LinearProgress sx={{ mb: 3 }} />
        )}
        
        {/* AKTIF TARAMALAR TABLO GÖRÜNÜMÜ */}
        {tabValue === 1 && viewMode === 'table' && (
          <Box>
            {activeScans.length === 0 ? (
              <Box sx={{ my: 4, textAlign: 'center' }}>
                <Typography variant="h6" sx={{ mb: 2, opacity: 0.7 }}>
                  Aktif tarama bulunamadı.
                </Typography>
                <Button 
                  variant="contained"
                  color="primary"
                  startIcon={<PlayArrowIcon />}
                  onClick={() => navigate('../scan')}
                >
                  Yeni Tarama Başlat
                </Button>
              </Box>
            ) : (
              // Her aktif tarama için ayrı tablo
              activeScans.map((scan, index) => {
                const scanTableData = activeScanTables[scan.scan_name];
                const isLoading = loadingTables[scan.scan_name];
                
                return (
                  <Paper 
                    key={index} 
                    elevation={3} 
                    sx={{ 
                      mb: 4, 
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor,
                      color: theme ? colors.darkText : colors.lightText,
                      overflow: 'hidden'
                    }}
                  >
                    <Box sx={{ 
                      p: 2, 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'center',
                      backgroundColor: theme ? 'rgba(255, 0, 0, 0.05)' : 'rgba(184, 0, 0, 0.03)'
                    }}>
                      <Box>
                        <Typography variant="h6">{scan.scan_name || "İsimsiz Tarama"}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          {scan.target} {scan.progress ? `(${scan.progress}%)` : ''}
                        </Typography>
                      </Box>
                      
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Chip 
                          label={`Durum: ${scan.status === 'running' ? 'Çalışıyor' : 
                                        scan.status === 'queued' ? 'Sırada' : 
                                        scan.status === 'completed' ? 'Tamamlandı' : 
                                        scan.status === 'failed' ? 'Hata' : 'Bilinmiyor'}`}
                          color={scan.status === 'running' ? 'warning' : 
                                scan.status === 'queued' ? 'info' : 
                                scan.status === 'completed' ? 'success' : 
                                scan.status === 'failed' ? 'error' : 'default'}
                          size="small"
                        />
                        
                        <Button 
                          variant="outlined" 
                          size="small"
                          onClick={() => navigate(`../scanDetails/${scan.scan_name}`)}
                        >
                          Detaylar
                        </Button>
                      </Box>
                    </Box>
                    
                    {/* İlerleme çubuğu */}
                    {scan.status === 'running' && (
                      <LinearProgress 
                        variant="determinate" 
                        value={scan.progress || 0} 
                        sx={{ height: 4 }}
                      />
                    )}
                    
                    {/* Tablo verileri */}
                    {isLoading ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        <CircularProgress size={30} />
                      </Box>
                    ) : scanTableData && scanTableData.columns && scanTableData.data ? (
                      <TableContainer sx={{ maxHeight: 400 }}>
                        <Table stickyHeader size="small">
                          <TableHead>
                            <TableRow>
                              {scanTableData.columns.map((column, colIndex) => (
                                <TableCell 
                                  key={colIndex}
                                  sx={{ 
                                    backgroundColor: theme ? 'rgb(255, 0, 0)' : 'rgb(0, 68, 255)',
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
                            {scanTableData.data.length > 0 ? (
                              scanTableData.data.map((row, rowIndex) => (
                                <TableRow 
                                  key={rowIndex}
                                  sx={{ 
                                    '&:nth-of-type(odd)': { 
                                      backgroundColor: theme ? 'rgb(255, 0, 0)' : 'rgba(255, 0, 0, 0.03)'
                                    }
                                  }}
                                >
                                  {row.map((cell, cellIndex) => {
                                    // Kolon ismi "state" veya "durum" ise ve değer "open" ise hücre stilini değiştir
                                    const columnName = scanTableData.columns[cellIndex]?.toLowerCase();
                                    const isStateColumn = columnName === 'state' || columnName === 'durum';
                                    
                                    return (
                                      <TableCell 
                                        key={cellIndex}
                                        sx={{ 
                                          color: theme ? colors.darkText : colors.lightText,
                                          ...(isStateColumn ? getStatusStyle(cell) : {})
                                        }}
                                      >
                                        {cell}
                                      </TableCell>
                                    );
                                  })}
                                </TableRow>
                              ))
                            ) : (
                              <TableRow>
                                <TableCell 
                                  colSpan={scanTableData.columns.length}
                                  sx={{ 
                                    textAlign: 'center',
                                    color: theme ? colors.darkText : colors.lightText,
                                    py: 3
                                  }}
                                >
                                  Henüz tarama sonucu bulunamadı.
                                </TableCell>
                              </TableRow>
                            )}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Box sx={{ p: 3, textAlign: 'center' }}>
                        <Typography variant="body1" color="text.secondary">
                          Tarama sonuçları henüz mevcut değil
                        </Typography>
                      </Box>
                    )}
                  </Paper>
                );
              })
            )}
          </Box>
        )}
        
        {/* Kartlar ve normal görünüm */}
        {(tabValue !== 1 || viewMode === 'cards') && (
          <Grid container spacing={3}>
            {combinedScans.length > 0 ? (
              combinedScans.map((scan, index) => {
                // Get proper values based on scan type
                const isActive = scan.type === 'active';
                const scanName = isActive ? scan.scan_name : scan.name || "Adsız Tarama";
                const scanInfo = scan.info || {};
                const scanDate = isActive 
                  ? new Date(scan.created_at).toLocaleString()
                  : scanInfo.date ? `${scanInfo.date} ${scanInfo.time || ''}` : "Tarih bilgisi yok";
                const target = isActive ? scan.target : scanInfo.target || "Bilinmeyen hedef";
                const targetType = scanInfo.target_type || "";
                const progress = isActive ? scan.progress : 100;
                const status = isActive ? scan.status : "completed";
                
                // Status chip color
                const getStatusColor = () => {
                  if (status === "running") return "warning";
                  if (status === "queued") return "info";
                  if (status === "completed") return "success";
                  if (status === "failed") return "error";
                  return "default";
                };
                
                // Status text
                const getStatusText = () => {
                  if (status === "running") return "Çalışıyor";
                  if (status === "queued") return "Sırada";
                  if (status === "completed") return "Tamamlandı";
                  if (status === "failed") return "Hata";
                  return "Bilinmiyor";
                };
                
                return (
                  <Grid item key={index} xs={12} sm={6} md={4} lg={3}>
                    <Card 
                      sx={{ 
                        backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor,
                        height: '100%',
                        display: 'flex',
                        flexDirection: 'column',
                        transition: 'transform 0.2s',
                        '&:hover': {
                          transform: 'translateY(-5px)',
                          boxShadow: '0 8px 16px rgba(0,0,0,0.2)'
                        },
                        ...(isActive && {
                          border: '2px solid',
                          borderColor: 'primary.main'
                        })
                      }}
                    >
                      <CardContent sx={{ flexGrow: 1 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                          <Typography gutterBottom variant="h6" component="div" sx={{ fontWeight: 'bold' }}>
                            {scanName}
                          </Typography>
                          
                          <Chip 
                            label={getStatusText()}
                            size="small"
                            color={getStatusColor()}
                          />
                        </Box>
                        
                        {isActive && (
                          <Box sx={{ width: '100%', mb: 2 }}>
                            <LinearProgress 
                              variant="determinate" 
                              value={progress} 
                              color={getStatusColor() !== "default" ? getStatusColor() : "primary"}
                            />
                            <Typography variant="body2" color="text.secondary" align="right">
                              {progress}%
                            </Typography>
                          </Box>
                        )}
                        
                        <Divider sx={{ my: 1 }} />
                        
                        <Box sx={{ display: 'flex', alignItems: 'center', mt: 1.5, mb: 0.5 }}>
                          <AccessTimeIcon fontSize="small" sx={{ mr: 1, opacity: 0.7 }} />
                          <Typography variant="body2" color="text.secondary">
                            {scanDate}
                          </Typography>
                        </Box>
                        
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                          <TargetIcon fontSize="small" sx={{ mr: 1, opacity: 0.7 }} />
                          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {target}
                          </Typography>
                        </Box>
                        
                        {scanInfo.port_option && (
                          <Typography variant="body2" color="text.secondary">
                            <strong>Port:</strong> {scanInfo.port_option} {scanInfo.port_value ? `(${scanInfo.port_value})` : ''}
                          </Typography>
                        )}
                        
                        {scanInfo.scan_type && (
                          <Typography variant="body2" color="text.secondary">
                            <strong>Tarama:</strong> {scanInfo.scan_type}
                          </Typography>
                        )}
                        
                        <Box sx={{ display: 'flex', mt: 1, gap: 0.5, flexWrap: 'wrap' }}>
                          {targetType && (
                            <Chip 
                              label={targetType}
                              size="small"
                              color="primary"
                              variant="outlined"
                            />
                          )}
                          
                          {scanInfo.service_detection && scanInfo.service_detection !== "none" && (
                            <Chip 
                              label={scanInfo.service_detection}
                              size="small"
                              color="secondary"
                              variant="outlined"
                            />
                          )}
                        </Box>
                      </CardContent>
                      
                      <CardActions>
                        <Button 
                          variant="outlined"
                          size="small" 
                          startIcon={<SubjectIcon />}
                          onClick={() => navigate(`../scanDetails/${scanName}?tab=info`)}
                          sx={{ flexGrow: 1 }}
                        >
                          Detaylar
                        </Button>
                        
                        <Button 
                          variant="outlined"
                          size="small" 
                          startIcon={<AssessmentIcon />}
                          onClick={() => navigate(`../scanDetails/${scanName}?tab=results`)}
                          sx={{ flexGrow: 1 }}
                        >
                          Sonuçlar
                        </Button>
                        
                        <Button 
                          variant="outlined"
                          size="small" 
                          color="error"
                          startIcon={<SecurityIcon />}
                          onClick={() => navigate(`../scanDetails/${scanName}?tab=vulnerabilities`)}
                          sx={{ flexGrow: 1 }}
                        >
                          Zafiyetler
                        </Button>
                      </CardActions>
                    </Card>
                  </Grid>
                );
              })
            ) : (
              <Grid item xs={12}>
                <Typography variant="h6" align="center" sx={{ my: 4, opacity: 0.7 }}>
                  {searchTerm ? "Arama kriterlerine uygun tarama bulunamadı." : "Henüz tarama bulunmuyor."}
                </Typography>
                <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                  <Button 
                    variant="contained" 
                    color="primary"
                    startIcon={<PlayArrowIcon />}
                    onClick={() => navigate('../scan')}
                  >
                    Yeni Tarama Başlat
                  </Button>
                </Box>
              </Grid>
            )}
          </Grid>
        )}
        
        {/* Aktif taramalar sekmesi için eklenen özel kart görünümü */}
        {tabValue === 1 && viewMode === 'cards' && (
          <Grid item xs={12}>
            {activeScans.length > 0 ? (
              <Grid container spacing={3}>
                {activeScans.map((scan, index) => (
                  <Grid item key={index} xs={12} sm={6} md={4} lg={3}>
                    <Card 
                      sx={{ 
                        backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor,
                        height: '100%',
                        display: 'flex',
                        flexDirection: 'column',
                        transition: 'transform 0.2s',
                        '&:hover': {
                          transform: 'translateY(-5px)',
                          boxShadow: '0 8px 16px rgba(0,0,0,0.2)'
                        },
                        border: '2px solid',
                        borderColor: 'primary.main'  // Aktif taramaları vurgulamak için
                      }}
                    >
                      <CardContent sx={{ flexGrow: 1 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
                          <Typography gutterBottom variant="h6" component="div" sx={{ fontWeight: 'bold' }}>
                            {scan.scan_name || "İsimsiz Tarama"}
                          </Typography>
                          
                          <Chip 
                            label={scan.status === "running" ? "Çalışıyor" : 
                                  scan.status === "queued" ? "Sırada" : 
                                  scan.status === "completed" ? "Tamamlandı" : 
                                  scan.status === "failed" ? "Hata" : "Bilinmiyor"}
                            size="small"
                            color={scan.status === "running" ? "warning" : 
                                  scan.status === "queued" ? "info" : 
                                  scan.status === "completed" ? "success" : 
                                  scan.status === "failed" ? "error" : "default"}
                          />
                        </Box>
                        
                        {/* Progress bar */}
                        <Box sx={{ width: '100%', mb: 2 }}>
                          <LinearProgress 
                            variant="determinate" 
                            value={scan.progress || 0} 
                            color={scan.status === "running" ? "warning" : "primary"}
                          />
                          <Typography variant="body2" color="text.secondary" align="right">
                            {scan.progress || 0}%
                          </Typography>
                        </Box>
                        
                        <Divider sx={{ my: 1 }} />
                        
                        <Box sx={{ display: 'flex', alignItems: 'center', mt: 1.5, mb: 0.5 }}>
                          <AccessTimeIcon fontSize="small" sx={{ mr: 1, opacity: 0.7 }} />
                          <Typography variant="body2" color="text.secondary">
                            {new Date(scan.created_at).toLocaleString()}
                          </Typography>
                        </Box>
                        
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                          <TargetIcon fontSize="small" sx={{ mr: 1, opacity: 0.7 }} />
                          <Typography variant="body2" color="text.secondary" sx={{ maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {scan.target || "Hedef bilgisi yok"}
                          </Typography>
                        </Box>
                      </CardContent>
                      
                      <CardActions>
                        <Button 
                          variant="contained"
                          size="small" 
                          onClick={() => navigate(`../scanDetails/${scan.scan_name}`)}
                          sx={{ flexGrow: 1 }}
                        >
                          Detaylar
                        </Button>
                      </CardActions>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            ) : (
              <Box sx={{ textAlign: 'center', my: 5 }}>
                <Typography variant="h6" sx={{ mb: 2, opacity: 0.7 }}>
                  Şu anda aktif tarama bulunmuyor.
                </Typography>
                <Button 
                  variant="contained" 
                  color="primary"
                  onClick={() => navigate('../scan')}
                >
                  Yeni Tarama Başlat
                </Button>
              </Box>
            )}
          </Grid>
        )}
      </Box>
    </div>
  );
}

export default OldScan;