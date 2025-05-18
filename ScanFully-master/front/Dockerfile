FROM node:20-alpine

WORKDIR /app

# Package dosyalarını kopyala
COPY package*.json ./

# Bağımlılıkları yükle
RUN npm install

# Diğer tüm dosyaları kopyala
COPY . .

# Vite'ın geliştirme portunu dışarı aç
EXPOSE 5173

# Geliştirme sunucusunu başlat
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]