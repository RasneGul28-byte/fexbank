# FexBank - Bankacılık Destek Sistemi

Flask + PostgreSQL ile geliştirilmiş, katmanlı güvenlik mimarisine sahip bankacılık destek sistemi prototipi.

## Güvenlik Özellikleri

- **bcrypt** ile şifre hash'leme
- **AES-256** ile kart verisi şifreleme
- **CVV saklanmaz** (PCI-DSS uyumlu)
- **Kart maskesi** (sadece son 4 hane)
- **WAF**: SQL Injection, XSS, Path Traversal koruması
- **Rate Limiting** & DDoS koruması
- **Brute-force** koruması (5 deneme → IP ban)
- **Session güvenliği** (HTTPOnly, SameSite)
- **Security Headers** (CSP, HSTS, X-Frame-Options)
- **Audit Log** sistemi
- **Parametreli SQL** sorguları

## Kullanılan Katmanlar ve Teknolojiler

| Katman | Teknoloji |
|--------|-----------|
| Backend | Flask, Python 3.10+ |
| Veritabanı | PostgreSQL 14+ |
| Şifreleme | bcrypt, cryptography (Fernet) |
| Frontend | Vanilla JS, Modern CSS |

## Kurulum

### Gereksinimler

- Python 3.10+
- PostgreSQL 14+

### Adımlar

```bash
# 1. PostgreSQL veritabanı oluştur
sudo -u postgres psql <<EOF
CREATE DATABASE bank_support_db;
CREATE USER bankuser WITH PASSWORD 'bankpass123';
ALTER DATABASE bank_support_db OWNER TO bankuser;
GRANT ALL ON DATABASE bank_support_db TO bankuser;
EOF

sudo -u postgres psql -d bank_support_db <<EOF
GRANT ALL ON SCHEMA public TO bankuser;
EOF

# 2. Sanal ortam
python3 -m venv venv
source venv/bin/activate

# 3. Bağımlılıklar
pip install flask psycopg2-binary bcrypt cryptography

# 4. .env dosyası oluştur
cat > .env <<EOF
DB_HOST=localhost
DB_NAME=bank_support_db
DB_USER=bankuser
DB_PASSWORD=bankpass123
ADMIN_USERNAME=admin
ADMIN_PASSWORD=GucluSifreKULLAN!
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
EOF

# 5. Çalıştır
set -a; source .env; set +a
python3 app.py
```

Fexbank http uzantısı ile localhostta ve 5000 portunda çalışmaktadır "http://localhost:5000"

## Varsayılan Hesaplar

**Yönetici (Admin Panel):**
- **Kullanıcı adı:** `admin`
- **Şifre:** Kurulum adımlarında `.env` dosyasına yazdığınız 
  `ADMIN_PASSWORD` değeri (örnek: `GucluSifreKULLAN!`)

**Not:** Admin şifresini `.env` dosyasından değiştirebilirsiniz. 
Değişiklikten sonra sunucuyu yeniden başlatın.

**Müşteri:** Kayıt sayfasından oluşturulur
1. Ana sayfada **"Müşteri Kaydı"** sekmesine tıklayın
2. Formu doldurun (Ad Soyad, E-posta, Telefon, Kart bilgileri, Şifre)
3. **"Kayıt Ol"** butonuna basın
4. Ardından **"Müşteri Girişi"** sekmesinden giriş yapın

## Yol Haritası

- [ ] Redis ile kalıcı depolama (rate limiting, bloklar)
- [ ] 2FA (TOTP) entegrasyonu
- [ ] CSRF koruması (Flask-WTF)
- [ ] Docker + docker-compose
- [ ] pytest ile otomatik testler
- [ ] GitHub Actions CI/CD
- [ ] SIEM entegrasyonu (ELK)
- [ ] Şifre karmaşıklık politikası

## Uyarı

Bu bir **öğrenci prototipidir**. Production ortamında kullanılmadan önce yol haritasındaki maddelerin tamamlanması gerekir.

## Lisans

MIT License
