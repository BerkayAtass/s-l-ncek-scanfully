import React, { useState, useEffect } from 'react';
import { 
  Box, Typography, Button, Paper, CircularProgress,
  IconButton, Collapse
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import { getActiveScans } from '../../services/api';

function ActiveScanNotifier() {
  const { theme, colors } = useSelector((store) => store.constant);
  const navigate = useNavigate();
  
  const [activeScans, setActiveScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(false);
  
  // Aktif taramaları almak için API isteği
  const fetchActiveScans = async () => {
    try {
      setLoading(true);
      const response = await getActiveScans();
      
      if (response && response.activeScans) {
        // "completed" durumundaki taramaları filtrele
        const filteredScans = response.activeScans.filter(scan => scan.status !== "completed");
        
        setActiveScans(filteredScans);
        // Eğer aktif tarama varsa ve panel kapalıysa, otomatik olarak aç
        if (filteredScans.length > 0 && !expanded) {
          setExpanded(true);
        }
      } else if (response && response.active_scans) {
        // JSON örneğindeki alan adına göre alternatif kontrol
        const filteredScans = response.active_scans.filter(scan => scan.status !== "completed");
        
        setActiveScans(filteredScans);
        if (filteredScans.length > 0 && !expanded) {
          setExpanded(true);
        }
      } else {
        setActiveScans([]);
      }
      
      setError(null);
    } catch (err) {
      console.error("Aktif taramalar alınırken hata:", err);
      setError("Tarama bilgileri alınamadı");
    } finally {
      setLoading(false);
    }
  };
  
  // Sayfa yüklendiğinde ve belirli aralıklarla aktif taramaları kontrol et
  useEffect(() => {
    // İlk yüklemede taramaları kontrol et
    fetchActiveScans();
    
    // Düzenli aralıklarla kontrol et (10 saniyede bir)
    const intervalId = setInterval(() => {
      fetchActiveScans();
    }, 10000);
    
    // Component kaldırıldığında interval'i temizle
    return () => clearInterval(intervalId);
  }, []);
  
  // Popup olmadığında görünecek sekme
  const renderTab = () => (
    <Paper
      elevation={3}
      sx={{
        position: 'fixed',
        left: expanded ? '-100px' : 0,
        top: '50%',
        transform: 'translateY(-50%)',
        zIndex: 1199,
        display: 'flex',
        alignItems: 'center',
        borderTopRightRadius: '8px',
        borderBottomRightRadius: '8px',
        overflow: 'hidden',
        cursor: 'pointer',
        transition: 'left 0.3s ease',
        backgroundColor:'rgba(137, 185, 244, 0.9)',
      }}
      onClick={() => setExpanded(true)}
    >
      <Box sx={{ p: 1.5, color: 'black', display: 'flex', alignItems: 'center' }}>
        {loading ? (
          <CircularProgress size={24} color="inherit" />
        ) : (
          <>
            <AccessTimeIcon sx={{ mr: 1 }} />
            <Typography variant="button">
              {activeScans.length > 0 ? `${activeScans.length} Aktif Tarama` : "Taramalar"}
            </Typography>
          </>
        )}
        <ChevronRightIcon />
      </Box>
    </Paper>
  );
  
  // Ana Popup içeriği 
  const popupStyle = {
    position: 'fixed',
    left: expanded ? 0 : '-300px',
    top: '50%',
    transform: 'translateY(-50%)',
    zIndex: 1200,
    width: '280px',
    boxShadow: '4px 4px 12px rgba(0,0,0,0.3)',
    transition: 'all 0.3s ease-in-out',
    borderTopRightRadius: '10px',
    borderBottomRightRadius: '10px',
    overflow: 'hidden'
  };
  
  // Taramalar varsa veya yükleniyor ise göster
  if (activeScans.length === 0 && !loading) {
    return renderTab();
  }
  
  return (
    <>
      {renderTab()}
      
      <Paper 
        elevation={6}
        style={{
          ...popupStyle,
          backgroundColor: colors.scanLightColor,
          color: colors.lightText
        }}
      >
        <Box sx={{ 
          bgcolor: 'primary.main', 
          py: 1, 
          px: 2, 
          display: 'flex', 
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <Typography variant="h6" sx={{ color: 'white', display: 'flex', alignItems: 'center' }}>
            <AccessTimeIcon sx={{ mr: 1 }} /> Aktif Taramalar
          </Typography>
          
          <IconButton 
            size="small" 
            onClick={() => setExpanded(false)}
            sx={{ color: 'white' }}
          >
            <ChevronLeftIcon />
          </IconButton>
        </Box>
        
        <Box sx={{ p: 2 }}>
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
              <CircularProgress size={30} />
            </Box>
          ) : error ? (
            <Typography color="error">{error}</Typography>
          ) : (
            <>
              {activeScans.length === 0 ? (
                <Typography variant="body2" sx={{ textAlign: 'center', p: 2 }}>
                  Şu anda aktif bir tarama bulunmuyor.
                </Typography>
              ) : (
                <>
                  <Typography variant="body1" gutterBottom sx={{ fontWeight: 'bold' }}>
                    {activeScans.length} tarama devam ediyor:
                  </Typography>
                  
                  <Box sx={{ maxHeight: '300px', overflowY: 'auto', mb: 2 }}>
                    {activeScans.map((scan, index) => (
                      <Paper
                        key={index}
                        elevation={2}
                        sx={{
                          p: 1.5,
                          mb: 1.5,
                          backgroundColor: 'rgba(137, 185, 244, 0.2)',
                          borderRadius: 1
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                          {scan.scan_name}
                        </Typography>
                        
                        <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                          <strong>Hedef:</strong> &nbsp;{scan.target}
                        </Typography>
                        
                        <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center' }}>
                          <AccessTimeIcon fontSize="small" sx={{ mr: 0.5 }} />
                          <strong>Tahmini:</strong> &nbsp;
                          {scan.estimated_duration?.duration} {scan.estimated_duration?.unit}
                        </Typography>
                      </Paper>
                    ))}
                  </Box>
                </>
              )}
              
              <Button 
                variant="contained" 
                color="primary" 
                fullWidth
                onClick={() => navigate('/oldScan')}
              >
                Tüm Taramaları Görüntüle
              </Button>
            </>
          )}
        </Box>
      </Paper>
    </>
  );
}

export default ActiveScanNotifier;