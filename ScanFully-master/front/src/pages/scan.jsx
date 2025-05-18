import React, { useState, useEffect } from 'react';
import "../css/scan.css";
import Appbar from '../components/header';
import ActiveScanNotifier from '../components/active-scan';
import { 
  TextField, Switch, FormControl, FormLabel, RadioGroup, 
  FormControlLabel, Radio, MenuItem, Select, InputLabel,
  Slider, Chip, Divider, Box, Typography, Button, 
  Paper, Accordion, AccordionSummary, AccordionDetails,
  CircularProgress, Alert, Snackbar, IconButton
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import { useSelector } from 'react-redux';
import { checkName, createScan, getScanEstimate } from '../../services/api';
import { 
  ScanType, PortOption, ServiceDetection, ScriptCategory, 
  TimingTemplate, OutputFormat 
} from "../../services/scanType";

function Scan() {
  const { theme, colors } = useSelector((store) => store.constant);
  
  // Temel Tarama Parametreleri
  const [scanName, setScanName] = useState("");
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState("ip");
  const [expanded, setExpanded] = useState(false);
  const [isNameExists, setIsNameExists] = useState(false);
  const [isScanStarted, setIsScanStarted] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [estimatedDuration, setEstimatedDuration] = useState({ duration: 5, unit: "dakika" });
  
  // Port Seçenekleri
  const [portOption, setPortOption] = useState("top1000");
  const [portValue, setPortValue] = useState("");
  
  // Tarama Türü
  const [scanType, setScanType] = useState("sT");
  
  // Servis Algılama
  const [serviceDetection, setServiceDetection] = useState("none");
  const [versionIntensity, setVersionIntensity] = useState(5);
  
  // NSE Script Kategorileri
  const [scriptCategory, setScriptCategory] = useState("none");
  const [customScripts, setCustomScripts] = useState("");
  
  // Zamanlama Şablonu
  const [timingTemplate, setTimingTemplate] = useState("T3");
  
  // Çıktı Formatı
  const [outputFormat, setOutputFormat] = useState("xml");
  
  // Form doğrulama
  const [formError, setFormError] = useState("");
  
  // İsim kontrolü
  useEffect(() => {
    if (scanName) {
      const timer = setTimeout(() => {
        checkNameExists(scanName);
      }, 500);
      
      return () => clearTimeout(timer);
    }
  }, [scanName]);
  
  // Tarama süresi tahmini
  useEffect(() => {
    if (target && targetType && portOption) {
      updateDurationEstimate();
    }
  }, [targetType, portOption, scanType, serviceDetection, scriptCategory, timingTemplate]);
  
  const checkNameExists = async (name) => {
    try {
      const exists = await checkName(name);
      setIsNameExists(exists);
    } catch (error) {
      console.error("İsim kontrolü hatası:", error);
    }
  };
  
  const updateDurationEstimate = async () => {
    try {
      const params = {
        target_type: targetType,
        port_option: portOption,
        port_value: portValue,
        scan_type: scanType,
        service_detection: serviceDetection,
        version_intensity: versionIntensity,
        script_category: scriptCategory,
        timing_template: timingTemplate
      };
      
      const estimate = await getScanEstimate(params);
      setEstimatedDuration(estimate.estimated_duration);
    } catch (error) {
      console.error("Süre tahmini hatası:", error);
    }
  };
  
  const handleSubmit = async () => {
    if (!scanName) {
      setFormError("Lütfen bir tarama adı girin");
      return;
    }
    
    if (!target) {
      setFormError("Lütfen bir hedef girin");
      return;
    }
    
    if (isNameExists) {
      setFormError("Bu tarama adı zaten kullanılıyor");
      return;
    }
    
    setFormError("");
    setLoading(true);
    
    try {
      // API isteğini daha güvenilir hale getirmek için değişiklikler
      const scanRequest = {
        scan_name: scanName.trim(),
        target: target.trim(),
        target_type: targetType,
        port_option: portOption,
        port_value: portValue ? portValue.trim() : null,
        scan_type: scanType,
        service_detection: serviceDetection,
        version_intensity: serviceDetection !== "none" ? parseInt(versionIntensity) : null,
        script_category: scriptCategory,
        custom_scripts: customScripts ? customScripts.trim() : null,
        timing_template: timingTemplate,
        output_format: outputFormat
      };
      
      console.log("Gönderilen tarama isteği:", scanRequest); // Debug için
      
      const response = await createScan(scanRequest);
      console.log("API yanıtı:", response); // Debug için
      
      setScanResult(response);
      setIsScanStarted(true);
    } catch (error) {
      console.error("Tarama başlatma hatası:", error);
      // Daha açıklayıcı hata mesajı
      if (error.response && error.response.data) {
        setFormError(`Hata: ${error.response.data.detail || 'Tarama başlatılamadı'}`);
      } else {
        setFormError("Tarama başlatılırken bir hata oluştu: " + (error.message || "Bilinmeyen hata"));
      }
    } finally {
      setLoading(false);
    }
  };
  
  // Hedef türü seçenekleri
  const targetTypes = [
    { value: "ip", label: "Tek IP Adresi", example: "192.168.1.1" },
    { value: "host", label: "Hostname", example: "www.example.com" },
    { value: "range", label: "IP Aralığı", example: "192.168.1.1-20" },
    { value: "subnet", label: "Alt Ağ", example: "192.168.1.0/24" },
    { value: "file", label: "IP Listesi Dosyası", example: "list-of-ips.txt" }
  ];
  
  // Port seçenekleri
  const portOptions = [
    { value: "single", label: "Tek port", desc: "1 port için tarama yapar, hızlı" },
    { value: "range", label: "Port aralığı", desc: "Belirtilen port aralığını tarar" },
    { value: "fast", label: "Yaygın 100 port (Hızlı)", desc: "Yaygın 100 portu tarar" },
    { value: "top10", label: "En yaygın 10 port", desc: "En yaygın 10 portu tarar" },
    { value: "top1000", label: "En yaygın 1000 port", desc: "En yaygın 1000 portu tarar" },
    { value: "all", label: "Tüm portlar (65535)", desc: "Tüm portları tarar, çok uzun sürer" }
  ];
  
  // Tarama türleri
  const scanTypes = [
    { value: "sT", label: "TCP Connect tarama (standart)", desc: "Standart TCP bağlantı taraması, en güvenilir" },
    { value: "sS", label: "TCP SYN tarama (hızlı, yarı-gizli)", desc: "Yarım bağlantı kurar, hızlı ve biraz daha gizli" },
    { value: "sA", label: "TCP ACK tarama (firewall keşfi)", desc: "Firewall kurallarını tespit etmek için" },
    { value: "sU", label: "UDP portları tarama", desc: "UDP portlarını tarar, yavaştır" },
    { value: "sP", label: "Sadece ping taraması", desc: "Çalışan sistemleri bulmak için sadece ping taraması" },
    { value: "Pn", label: "Keşfi yoksay", desc: "Ping atlamadan direkt port taraması yapar" }
  ];
  
  // Servis algılama seçenekleri
  const serviceOptions = [
    { value: "none", label: "Yok", desc: "Servis tespiti yapma, sadece port açık/kapalı bilgisi" },
    { value: "light", label: "Hafif banner yakalama", desc: "Sadece temel banner bilgilerini alır, hızlı" },
    { value: "standard", label: "Standart servis algılama", desc: "Açık portlardaki servisleri tespit eder" },
    { value: "aggressive", label: "Agresif servis algılama", desc: "Daha detaylı servis ve versiyon bilgisi, yavaş" },
    { value: "os", label: "İşletim sistemi tespiti", desc: "İşletim sistemi parmak izi tespiti yapar" }
  ];
  
  // Script kategorileri
  const scriptOptions = [
    { value: "none", label: "Yok", desc: "NSE scriptleri kullanma" },
    { value: "default", label: "Varsayılan scriptler", desc: "Güvenli ve hızlı NSE scriptlerini çalıştırır" },
    { value: "discovery", label: "Keşif scriptleri", desc: "Sistemler hakkında ek bilgi toplar" },
    { value: "safe", label: "Güvenli scriptler", desc: "Hedef sistemlere zarar vermeyen scriptler" },
    { value: "vuln", label: "Güvenlik açığı scriptleri", desc: "Güvenlik açıklarını tespit eder" },
    { value: "vulners", label: "Vulners.com veritabanı taraması", desc: "Vulners.com'daki güvenlik açıklarını kontrol eder" }
  ];
  
  // Zamanlama şablonları
  const timingOptions = [
    { value: "T0", label: "Paranoid (T0)", desc: "Çok yavaş, IDS sistemlerinden kaçınmak için" },
    { value: "T1", label: "Sneaky (T1)", desc: "Yavaş, IDS sistemlerine yakalanma riski az" },
    { value: "T2", label: "Polite (T2)", desc: "Normal hızdan yavaş, bant genişliğini az kullanır" },
    { value: "T3", label: "Normal (T3)", desc: "Varsayılan ayar, normal hız" },
    { value: "T4", label: "Aggressive (T4)", desc: "Daha hızlı tarama, iyi bağlantılar için" },
    { value: "T5", label: "Insane (T5)", desc: "Çok hızlı, doğruluktan ödün verir" }
  ];
  
  // Çıktı formatları
  const outputOptions = [
    { value: "normal", label: "Normal", desc: "Standart Nmap çıktısı" },
    { value: "xml", label: "XML", desc: "XML formatında çıktı" },
    { value: "json", label: "JSON", desc: "JSON formatında çıktı" },
    { value: "grepable", label: "Grepable", desc: "Grep ile işlenebilir çıktı formatı" },
    { value: "all", label: "Tüm Formatlar", desc: "Tüm çıktı formatlarını kaydeder" }
  ];
  
  const getDurationColor = () => {
    if (estimatedDuration.unit === "dakika") {
      if (estimatedDuration.duration < 2) return "green";
      if (estimatedDuration.duration < 10) return "orange";
      return "red";
    }
    return "red"; // saat birimi için
  };
  
  // Sol taraftaki popup için stil tanımları
  const popupStyle = {
    position: 'fixed',
    left: 0,
    top: '50%',
    transform: 'translateY(-50%)',
    zIndex: 1201,
    width: '280px',
    boxShadow: '4px 4px 12px rgba(0,0,0,0.3)',
    transition: 'all 0.3s ease-in-out',
    borderTopRightRadius: '10px',
    borderBottomRightRadius: '10px',
    overflow: 'hidden'
  };
  
  return (
    <div style={{ backgroundColor: colors.bodyLightColor, minHeight: '100vh' }}>
      <Appbar />
      <ActiveScanNotifier />
      
      {/* Tarama Başlatıldı Popup */}
      {isScanStarted && (
        <Paper 
          elevation={6}
          style={{
            ...popupStyle,
            backgroundColor: colors.scanLightColor,
            color: colors.lightText
          }}
        >
          <Box sx={{ bgcolor: 'primary.main', py: 1, px: 2 }}>
            <Typography variant="h6" sx={{ color: 'white', display: 'flex', alignItems: 'center' }}>
              <CheckCircleIcon sx={{ mr: 1 }} /> Tarama Başlatıldı
            </Typography>
          </Box>
          
          <Box sx={{ p: 2 }}>
            <Typography variant="body1" gutterBottom sx={{ fontWeight: 'bold' }}>
              Tarama Bilgileri:
            </Typography>
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <strong>Ad:</strong> &nbsp;{scanResult?.scan_name}
              </Typography>
              
              <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <strong>Hedef:</strong> &nbsp;{target}
              </Typography>
              
              <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center' }}>
                <AccessTimeIcon fontSize="small" sx={{ mr: 0.5 }} />
                <strong>Tahmini Süre:</strong> &nbsp;
                {scanResult?.estimated_duration?.duration} {scanResult?.estimated_duration?.unit}
              </Typography>
            </Box>
            
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontStyle: 'italic' }}>
              Tarama arka planda devam ediyor...
            </Typography>
            
            <Button 
              variant="contained" 
              color="primary" 
              fullWidth
              onClick={() => window.location.href = '/oldScan'}
            >
              Taramaları Görüntüle
            </Button>
          </Box>
        </Paper>
      )}
      
      <div className="scanPage">
        <div 
          className="scanTab" 
          style={{ 
            backgroundColor: theme ? colors.scanDarkColor : colors.scanLightColor,
            color: theme ? colors.darkText : colors.lightText,
            padding: '20px',
            maxWidth: '800px',
            margin: 'auto'
          }}
        >
          <Typography variant="h4" gutterBottom>
            Nmap Tarama Aracı
          </Typography>
          
          {isScanStarted ? (
            <Paper 
              elevation={3} 
              style={{ 
                padding: '20px', 
                marginTop: '20px',
                backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
              }}
            >
              <Typography variant="h5" gutterBottom color="primary">
                Tarama Başlatıldı
              </Typography>
              <Typography variant="body1" paragraph>
                <strong>Tarama Adı:</strong> {scanResult?.scan_name}
              </Typography>
              <Typography variant="body1" paragraph>
                <strong>Tahmini Süre:</strong> {scanResult?.estimated_duration?.duration} {scanResult?.estimated_duration?.unit}
              </Typography>
              <Button 
                variant="contained" 
                color="primary"
                onClick={() => window.location.href = '/oldScan'}
                sx={{ mt: 2 }}
              >
                Taramaları Görüntüle
              </Button>
            </Paper>
          ) : (
            <>
              {formError && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {formError}
                </Alert>
              )}
              
              <Paper 
                elevation={3} 
                style={{ 
                  padding: '20px', 
                  marginBottom: '20px',
                  backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                }}
              >
                <Typography variant="h6" gutterBottom>
                  1️⃣ Temel Bilgiler
                </Typography>
                
                <TextField
                  fullWidth
                  label="Tarama Adı"
                  variant="outlined"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  error={isNameExists}
                  helperText={isNameExists ? "Bu tarama adı zaten kullanılıyor" : ""}
                  margin="normal"
                />
                
                <FormControl fullWidth margin="normal">
                  <InputLabel>Hedef Türü</InputLabel>
                  <Select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    label="Hedef Türü"
                  >
                    {targetTypes.map((type) => (
                      <MenuItem key={type.value} value={type.value}>
                        {type.label}
                      </MenuItem>
                    ))}
                  </Select>
                  <Typography variant="caption" color="textSecondary">
                    Örnek: {targetTypes.find(t => t.value === targetType)?.example}
                  </Typography>
                </FormControl>
                
                <TextField
                  fullWidth
                  label="Hedef"
                  placeholder={targetTypes.find(t => t.value === targetType)?.example}
                  variant="outlined"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  margin="normal"
                />
              </Paper>
              
              <Accordion expanded={expanded} onChange={() => setExpanded(!expanded)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Gelişmiş Tarama Seçenekleri</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Paper 
                    elevation={2} 
                    style={{ 
                      padding: '15px', 
                      marginBottom: '15px',
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                    }}
                  >
                    <Typography variant="h6" gutterBottom>
                      2️⃣ Port Seçenekleri
                    </Typography>
                    
                    <FormControl component="fieldset">
                      <RadioGroup
                        value={portOption}
                        onChange={(e) => setPortOption(e.target.value)}
                      >
                        {portOptions.map((option) => (
                          <FormControlLabel 
                            key={option.value} 
                            value={option.value} 
                            control={<Radio />} 
                            label={
                              <Box>
                                <Typography variant="body1">{option.label}</Typography>
                                <Typography variant="caption" color="textSecondary">{option.desc}</Typography>
                              </Box>
                            } 
                          />
                        ))}
                      </RadioGroup>
                    </FormControl>
                    
                    {portOption === 'single' && (
                      <TextField
                        fullWidth
                        label="Port Numarası"
                        placeholder="80"
                        variant="outlined"
                        value={portValue}
                        onChange={(e) => setPortValue(e.target.value)}
                        margin="normal"
                        helperText="Örn: 80, 443, 22"
                      />
                    )}
                    
                    {portOption === 'range' && (
                      <TextField
                        fullWidth
                        label="Port Aralığı"
                        placeholder="1-1000"
                        variant="outlined"
                        value={portValue}
                        onChange={(e) => setPortValue(e.target.value)}
                        margin="normal"
                        helperText="Örn: 1-1000, 20-25, 80,443,8080"
                      />
                    )}
                  </Paper>
                  
                  <Paper 
                    elevation={2} 
                    style={{ 
                      padding: '15px', 
                      marginBottom: '15px',
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                    }}
                  >
                    <Typography variant="h6" gutterBottom>
                      3️⃣ Tarama Türü
                    </Typography>
                    
                    <FormControl component="fieldset">
                      <RadioGroup
                        value={scanType}
                        onChange={(e) => setScanType(e.target.value)}
                      >
                        {scanTypes.map((type) => (
                          <FormControlLabel 
                            key={type.value} 
                            value={type.value} 
                            control={<Radio />} 
                            label={
                              <Box>
                                <Typography variant="body1">{type.label}</Typography>
                                <Typography variant="caption" color="textSecondary">{type.desc}</Typography>
                              </Box>
                            } 
                          />
                        ))}
                      </RadioGroup>
                    </FormControl>
                  </Paper>
                  
                  <Paper 
                    elevation={2} 
                    style={{ 
                      padding: '15px', 
                      marginBottom: '15px',
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                    }}
                  >
                    <Typography variant="h6" gutterBottom>
                      4️⃣ Servis Algılama (Opsiyonel)
                    </Typography>
                    
                    <FormControl component="fieldset">
                      <RadioGroup
                        value={serviceDetection}
                        onChange={(e) => setServiceDetection(e.target.value)}
                      >
                        {serviceOptions.map((option) => (
                          <FormControlLabel 
                            key={option.value} 
                            value={option.value} 
                            control={<Radio />} 
                            label={
                              <Box>
                                <Typography variant="body1">{option.label}</Typography>
                                <Typography variant="caption" color="textSecondary">{option.desc}</Typography>
                              </Box>
                            } 
                          />
                        ))}
                      </RadioGroup>
                    </FormControl>
                    
                    {serviceDetection !== 'none' && serviceDetection !== 'os' && (
                      <Box mt={2}>
                        <Typography gutterBottom>
                          Versiyon Tespiti Derinliği: {versionIntensity}
                        </Typography>
                        <Slider
                          value={versionIntensity}
                          min={0}
                          max={9}
                          step={1}
                          marks
                          onChange={(e, value) => setVersionIntensity(value)}
                          valueLabelDisplay="auto"
                        />
                        <Typography variant="caption" color="textSecondary">
                          0: En hızlı fakat az bilgi, 9: En yavaş fakat en detaylı bilgi
                        </Typography>
                      </Box>
                    )}
                  </Paper>
                  
                  <Paper 
                    elevation={2} 
                    style={{ 
                      padding: '15px', 
                      marginBottom: '15px',
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                    }}
                  >
                    <Typography variant="h6" gutterBottom>
                      5️⃣ NSE Script Seçenekleri (Opsiyonel)
                    </Typography>
                    
                    <FormControl component="fieldset">
                      <RadioGroup
                        value={scriptCategory}
                        onChange={(e) => setScriptCategory(e.target.value)}
                      >
                        {scriptOptions.map((option) => (
                          <FormControlLabel 
                            key={option.value} 
                            value={option.value} 
                            control={<Radio />} 
                            label={
                              <Box>
                                <Typography variant="body1">{option.label}</Typography>
                                <Typography variant="caption" color="textSecondary">{option.desc}</Typography>
                              </Box>
                            } 
                          />
                        ))}
                      </RadioGroup>
                    </FormControl>
                    
                    {scriptCategory !== 'none' && (
                      <TextField
                        fullWidth
                        label="Özel Script İsimleri (İsteğe Bağlı)"
                        placeholder="http-title,banner,ssl-cert"
                        variant="outlined"
                        value={customScripts}
                        onChange={(e) => setCustomScripts(e.target.value)}
                        margin="normal"
                        helperText="Virgülle ayrılmış özel script isimleri"
                      />
                    )}
                  </Paper>
                  
                  <Paper 
                    elevation={2} 
                    style={{ 
                      padding: '15px', 
                      marginBottom: '15px',
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                    }}
                  >
                    <Typography variant="h6" gutterBottom>
                      6️⃣ Zamanlama Şablonu (Opsiyonel)
                    </Typography>
                    
                    <FormControl component="fieldset">
                      <RadioGroup
                        value={timingTemplate}
                        onChange={(e) => setTimingTemplate(e.target.value)}
                      >
                        {timingOptions.map((option) => (
                          <FormControlLabel 
                            key={option.value} 
                            value={option.value} 
                            control={<Radio />} 
                            label={
                              <Box>
                                <Typography variant="body1">{option.label}</Typography>
                                <Typography variant="caption" color="textSecondary">{option.desc}</Typography>
                              </Box>
                            } 
                          />
                        ))}
                      </RadioGroup>
                    </FormControl>
                  </Paper>
                  
                  <Paper 
                    elevation={2} 
                    style={{ 
                      padding: '15px', 
                      marginBottom: '15px',
                      backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                    }}
                  >
                    <Typography variant="h6" gutterBottom>
                      7️⃣ Çıktı Formatı (Opsiyonel)
                    </Typography>
                    
                    <FormControl component="fieldset">
                      <RadioGroup
                        value={outputFormat}
                        onChange={(e) => setOutputFormat(e.target.value)}
                      >
                        {outputOptions.map((option) => (
                          <FormControlLabel 
                            key={option.value} 
                            value={option.value} 
                            control={<Radio />} 
                            label={
                              <Box>
                                <Typography variant="body1">{option.label}</Typography>
                                <Typography variant="caption" color="textSecondary">{option.desc}</Typography>
                              </Box>
                            } 
                          />
                        ))}
                      </RadioGroup>
                    </FormControl>
                  </Paper>
                </AccordionDetails>
              </Accordion>
              
              <Paper 
                elevation={3} 
                style={{ 
                  padding: '20px', 
                  marginTop: '20px',
                  backgroundColor: theme ? colors.cardDarkColor : colors.cardLightColor
                }}
              >
                <Typography variant="h6" gutterBottom>
                  🔍 Tarama Özeti
                </Typography>
                
                <Box sx={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                  <Box sx={{ flex: '1 1 45%', minWidth: '250px' }}>
                    <Typography><strong>Tarama Adı:</strong> {scanName || "Belirtilmedi"}</Typography>
                    <Typography><strong>Hedef:</strong> {target || "Belirtilmedi"}</Typography>
                    <Typography><strong>Hedef Türü:</strong> {targetTypes.find(t => t.value === targetType)?.label}</Typography>
                    <Typography><strong>Port Seçeneği:</strong> {portOptions.find(p => p.value === portOption)?.label}</Typography>
                    {portValue && <Typography><strong>Port Değeri:</strong> {portValue}</Typography>}
                  </Box>
                  
                  <Box sx={{ flex: '1 1 45%', minWidth: '250px' }}>
                    <Typography><strong>Tarama Türü:</strong> {scanTypes.find(s => s.value === scanType)?.label}</Typography>
                    <Typography><strong>Servis Algılama:</strong> {serviceOptions.find(s => s.value === serviceDetection)?.label}</Typography>
                    {serviceDetection !== 'none' && serviceDetection !== 'os' && (
                      <Typography><strong>Versiyon Derinliği:</strong> {versionIntensity}</Typography>
                    )}
                    <Typography><strong>Script Kategorisi:</strong> {scriptOptions.find(s => s.value === scriptCategory)?.label}</Typography>
                    <Typography>
                      <strong>Tahmini Süre:</strong> 
                      <span style={{ color: getDurationColor(), fontWeight: 'bold' }}>
                        {" "}{estimatedDuration.duration} {estimatedDuration.unit}
                      </span>
                    </Typography>
                  </Box>
                </Box>
                
                <Box sx={{ mt: 3, textAlign: 'center' }}>
                  <Button
                    variant="contained"
                    color="primary"
                    size="large"
                    onClick={handleSubmit}
                    disabled={loading || !scanName || !target || isNameExists}
                    startIcon={loading && <CircularProgress size={20} color="inherit" />}
                    sx={{ minWidth: '200px' }}
                  >
                    {loading ? "Tarama Başlatılıyor..." : "🚀 Tarama Başlat"}
                  </Button>
                </Box>
              </Paper>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default Scan;