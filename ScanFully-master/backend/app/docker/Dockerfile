FROM ubuntu:22.04

# Zaman dilimini ayarla
ENV TZ=Europe/Istanbul
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Gerekli paketleri kur
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    git \
    curl \
    jq \
    libxml2-utils \
    && rm -rf /var/lib/apt/lists/*

# ExploitDB'yi (searchsploit) manuel olarak kur
RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
RUN ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
# Not: .searchsploit_rc konfigürasyon dosyası yeni sürümlerde farklı konumda bulunuyor veya gerekli değil

# Nmap script'lerini kur
WORKDIR /usr/share/nmap/scripts
RUN curl -sL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -o vulners.nse
RUN mkdir -p /usr/share/nmap/scripts/vulscan/
RUN cd /usr/share/nmap/scripts/vulscan/ && \
    curl -sL https://raw.githubusercontent.com/scipag/vulscan/master/vulscan.nse -o vulscan.nse && \
    curl -sL https://raw.githubusercontent.com/scipag/vulscan/master/vulscan/cve.csv -o cve.csv && \
    curl -sL https://raw.githubusercontent.com/scipag/vulscan/master/vulscan/exploitdb.csv -o exploitdb.csv && \
    curl -sL https://raw.githubusercontent.com/scipag/vulscan/master/vulscan/openvas.csv -o openvas.csv && \
    curl -sL https://raw.githubusercontent.com/scipag/vulscan/master/vulscan/osvdb.csv -o osvdb.csv && \
    curl -sL https://raw.githubusercontent.com/scipag/vulscan/master/vulscan/scipvuldb.csv -o scipvuldb.csv

# Nmap veritabanını güncelle
RUN nmap --script-updatedb

# Çalışma dizini oluştur
WORKDIR /app

# Python bağımlılıklarını kur
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Uygulamayı kopyala
COPY . .

# Portları aç
EXPOSE 8000 8501

# Start script'ini çalıştırılabilir yap
RUN chmod +x ./docker/start.sh