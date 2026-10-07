FexBank - Bankacılık Destek Sistemi

Flask + PostgreSQL ile geliştirdiğim, katmanlı güvenlik mimarisine 
sahip bir bankacılık destek sistemi prototipidir.

Güvenlik Özellikleri

- **bcrypt** ile şifre hash'leme
- **AES-256** ile kart verisi şifreleme
- **CVV saklamama** (PCI-DSS uyumlu)
- **Kart maskesi** (sadece son 4 hane)
- **WAF**: SQL Injection, XSS, Path Traversal koruması
- **Rate Limiting** & DDoS koruması
- **Brute-force** koruması (5 deneme sonrası → IP ban)
- **Session güvenliği** (HTTPOnly, SameSite)
- **Security Headers** (CSP, HSTS, X-Frame-Options)
- **Audit Log** sistemi
- **Parametreli SQL** sorguları

Teknolojiler

| Katman | Teknoloji |
|--------|-----------|
| Backend | Flask, Python 3.10+ |
| Veritabanı | PostgreSQL 14+ |
| Şifreleme | bcrypt, cryptography (Fernet) |
| Frontend | Vanilla JS, Modern CSS |

Kurulum

Gereksinimler

- Python 3.10+
- PostgreSQL 14+

Sırasıyla Adımlar

```bash
# 1. PostgreSQL veritabanı oluştur
sudo -u postgres psql <<EOF
CREATE DATABASE bank_support_db;
CREATE USER bankuser WITH PASSWORD 'ORNEKbankpass123';
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
DB_PASSWORD=ORNEKbankpass123
ADMIN_USERNAME=admin
ADMIN_PASSWORD=GucluSifreKullan!
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
EOF

# 5. Çalıştır
set -a; source .env; set +a
python3 app.py

# FexBank 5000 portunda çalışır.
