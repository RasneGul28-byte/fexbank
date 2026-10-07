from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import psycopg2
import os
import re
import time
import secrets
from functools import wraps
from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor
import bcrypt
from cryptography.fernet import Fernet
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
if not os.environ.get('SECRET_KEY'):
    logger.warning("SECRET_KEY ayarlanmadı! Geçici anahtar üretildi.")
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key().decode()
if not os.environ.get('ENCRYPTION_KEY'):
    logger.warning("ENCRYPTION_KEY ayarlanmadı! Geçici anahtar üretildi.")
cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

FAIL2BAN_ENABLED = True
DDoS_PROTECTION_ENABLED = True
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_MINUTE = 100
MAX_LOGIN_ATTEMPTS = 5
BCRYPT_ROUNDS = 12

request_history = {}
login_attempts = {}
customer_balances = {}
customer_card_limits = {}
blocked_cards = {}
blocked_users = {}


def is_ddos_attack(ip):
    if not DDoS_PROTECTION_ENABLED:
        return False
    now = time.time()
    request_history.setdefault(ip, [])
    request_history[ip] = [t for t in request_history[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(request_history[ip]) > MAX_REQUESTS_PER_MINUTE:
        if FAIL2BAN_ENABLED:
            ban_ip(ip)
        return True
    request_history[ip].append(now)
    return False


def ban_ip(ip):
    logger.warning(f"IP banlandı: {ip}")
    login_attempts[ip] = {'banned_until': time.time() + 3600}


def is_ip_banned(ip):
    if ip in login_attempts:
        return time.time() < login_attempts[ip].get('banned_until', 0)
    return False


def check_login_attempts(ip, email):
    key = f"{ip}_{email}"
    login_attempts.setdefault(key, {'attempts': 0, 'attempt_times': []})
    now = time.time()
    recent = [t for t in login_attempts[key]['attempt_times'] if now - t < 300]
    if len(recent) >= MAX_LOGIN_ATTEMPTS:
        ban_ip(ip)
        return True
    return False


def log_failed_login(ip, email):
    key = f"{ip}_{email}"
    login_attempts.setdefault(key, {'attempts': 0, 'attempt_times': []})
    login_attempts[key]['attempts'] += 1
    login_attempts[key]['attempt_times'].append(time.time())


def waf_check(req):
    sql_keywords = ['union', 'select', 'insert', 'delete', 'drop', 'update', 'or 1=1', ';', '--', '/*', '*/']
    user_input = str(req.json) if req.json else str(req.form) + str(req.args)
    for keyword in sql_keywords:
        if keyword in user_input.lower():
            logger.warning(f"WAF: SQL Injection denemesi - {keyword}")
            return False
    xss_patterns = ['<script>', 'javascript:', 'onload=', 'onerror=', '<iframe', 'eval(']
    for pattern in xss_patterns:
        if pattern in user_input.lower():
            logger.warning(f"WAF: XSS denemesi - {pattern}")
            return False
    if '../' in user_input or '..\\' in user_input:
        logger.warning("WAF: Path traversal denemesi")
        return False
    return True


def encrypt_card(card_number):
    return cipher.encrypt(card_number.encode()).decode()


def decrypt_card(encrypted_card):
    try:
        return cipher.decrypt(encrypted_card.encode()).decode()
    except Exception:
        return None


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode('utf-8')


def verify_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def audit_log(user_id, action, details, ip):
    try:
        conn = get_db_connection()
        if not conn:
            return
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (%s, %s, %s, %s)',
            (user_id, action, details, ip)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Audit log hatası: {e}")


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


@app.before_request
def security_checks():
    if request.method == 'OPTIONS':
        return
    client_ip = request.remote_addr
    if is_ip_banned(client_ip):
        return api_response(False, None, "IP adresi şüpheli aktivite nedeniyle engellendi", 403)
    if is_ddos_attack(client_ip):
        return api_response(False, None, "Çok fazla istek. Lütfen daha sonra tekrar deneyin.", 429)
    if request.method in ['POST', 'PUT', 'DELETE']:
        if request.content_length and request.content_length > 0:
            if not waf_check(request):
                return api_response(False, None, "İstek güvenlik sistemi tarafından engellendi", 403)
    if session.get('customer_name') and session.get('customer_name') in blocked_users:
        session.clear()
        return api_response(False, None, "Erişiminiz engellendi. Lütfen destek ile iletişime geçin.", 403)


def get_db_connection():
    try:
        return psycopg2.connect(
            host=os.environ.get('DB_HOST', 'localhost'),
            database=os.environ.get('DB_NAME', 'bank_support_db'),
            user=os.environ.get('DB_USER', 'postgres'),
            password=os.environ.get('DB_PASSWORD', ''),
            port=os.environ.get('DB_PORT', '5432')
        )
    except Exception as e:
        logger.error(f"Veritabanı bağlantı hatası: {e}")
        return None


def init_db():
    conn = get_db_connection()
    if not conn:
        logger.error("Veritabanına bağlanılamadı!")
        return
    cur = conn.cursor()
    try:
        for table in ['audit_logs', 'ticket_messages', 'chat_history', 'tickets', 'customers']:
            cur.execute(f'DROP TABLE IF EXISTS {table} CASCADE')

        cur.execute('''
            CREATE TABLE customers (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                card_number_encrypted TEXT NOT NULL,
                card_last_four TEXT NOT NULL,
                expiry_date_encrypted TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE tickets (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                customer_name TEXT,
                title TEXT NOT NULL,
                issue_type TEXT,
                description TEXT,
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'low',
                priority_score INTEGER DEFAULT 0,
                admin_assigned TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE ticket_messages (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES tickets(id),
                sender_type TEXT NOT NULL,
                sender_name TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE chat_history (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        logger.info("Veritabanı tabloları oluşturuldu!")
    except Exception as e:
        logger.error(f"Veritabanı başlatma hatası: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()


def api_response(success=True, data=None, message="", status_code=200):
    return jsonify({
        "success": success,
        "data": data or {},
        "message": message,
        "timestamp": datetime.now().isoformat()
    }), status_code


def handle_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"{f.__name__} hatası: {e}")
            return api_response(False, None, f"Sunucu hatası: {str(e)}", 500)
    return wrapper


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('customer_id'):
            return api_response(False, None, "Giriş yapmanız gerekiyor", 401)
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return api_response(False, None, "Yönetici yetkisi gerekiyor", 401)
        return f(*args, **kwargs)
    return wrapper


def validate_email(email):
    if not email or len(email) > 254:
        return False
    return re.match(r'^[\w\.\-+]+@[\w\.\-]+\.\w{2,}$', email, re.UNICODE) is not None


def validate_phone(phone):
    return re.match(r'^\+?[0-9\s\-\(\)]{10,20}$', phone) is not None


def validate_card_number(card_number):
    return re.match(r'^\d{16}$', card_number) is not None


def validate_expiry_date(expiry_date):
    return re.match(r'^(0[1-9]|1[0-2])\/([0-9]{2})$', expiry_date) is not None


def validate_cvv(cvv):
    return re.match(r'^\d{3}$', cvv) is not None


def analyze_ticket_priority(title, description, issue_type):
    text = f"{title} {description} {issue_type}".lower()

    critical = {
        'dolandırıcılık': 15, 'dolandırıldım': 15, 'hırsızlık': 15, 'çalıntı': 15, 'kayıp kart': 12,
        'yetkisiz işlem': 14, 'izinsiz transfer': 14, 'para kaybı': 13, 'hesap hack': 16,
        'şifre çalındı': 13, 'kart çalıntı': 14, 'kart kayıp': 12, 'hesabım hacklendi': 16,
        'kimlik hırsızlığı': 16, 'sahtecilik': 14, 'kart kopyalama': 13,
        'acil': 8, 'kritik': 10, 'acilen': 8, 'hemen': 7, 'derhal': 9, 'hızlıca': 7,
        'acil durum': 10, 'acil yardım': 9, 'acil bloke': 11, 'acil iptal': 11,
        'acil müdahale': 10, 'acil destek': 9,
        'tüm param gitti': 14, 'büyük miktar': 9, 'yüksek tutar': 8, 'param yok': 12,
        'yetkisiz ödeme': 12, 'izinsiz çekim': 12, 'büyük kayıp': 11, 'yüklü miktar': 9,
        'erişim yok': 8, 'hesaba giremiyorum': 7, 'bloke': 7, 'engellendi': 7, 'kilitlendi': 7,
        'hesap kapandı': 9, 'kartım bloke': 9, 'kartım iptal': 9, 'erişim engellendi': 8,
        'bugün': 6, 'yarın': 5, 'acil transfer': 10, 'acil ödeme': 9, 'son gün': 7
    }
    medium = {
        'sorun': 4, 'problem': 4, 'hatalı': 5, 'yanlış': 4, 'düzeltme': 3, 'onarım': 3,
        'yavaş': 3, 'gecikme': 4, 'beklemede': 3, 'cevap bekliyorum': 3,
        'işlem başarısız': 6, 'transfer olmadı': 6, 'ödeme yapılamadı': 6,
        'teknik sorun': 5, 'sistem hatası': 6, 'bağlantı sorunu': 5,
        'limit': 4, 'kart limiti': 4, 'bakiye': 3, 'hesap bakiyesi': 3,
        'internet bankacılığı': 2, 'mobil uygulama': 2
    }
    low = {
        'bilgi': 1, 'soru': 1, 'merak': 1, 'öğrenmek': 1, 'danışmak': 1,
        'genel': 1, 'normal': 1, 'rutin': 1, 'standart': 1,
        'kampanya': 1, 'teklif': 1, 'ürün': 1, 'hizmet': 1
    }
    type_weights = {
        'credit_card': 8, 'account': 6, 'internet_banking': 4,
        'mobile_app': 3, 'loan': 5, 'other': 0
    }

    score = 0
    for pattern, weight in critical.items():
        if pattern in text:
            score += weight * text.count(pattern)
    for pattern, weight in medium.items():
        if pattern in text:
            score += weight * text.count(pattern)
    for pattern, weight in low.items():
        if pattern in text:
            score -= weight * text.count(pattern)

    score += type_weights.get(issue_type, 0)

    word_count = len(description.split())
    if word_count > 100:
        score += 3
    elif word_count > 50:
        score += 2
    elif word_count > 20:
        score += 1
    elif word_count < 10:
        score -= 2

    if description:
        upper_ratio = sum(1 for c in description if c.isupper()) / len(description)
        if upper_ratio > 0.15:
            score += 4
        elif upper_ratio > 0.08:
            score += 2

    score += min(description.count('!') * 2, 8)
    score -= min(description.count('?'), 3)

    for word in ['hemen', 'acil', 'derhal', 'şimdi', 'bugün', 'yarın']:
        if word in text:
            score += 3

    for pattern in [r'\d{5,}', r'[0-9]+\.?[0-9]*\s*(tl|try|₺|usd|eur)']:
        if re.search(pattern, description, re.IGNORECASE):
            score += 4

    score = max(score, 0)

    if score >= 25:
        return 'critical', score
    elif score >= 15:
        return 'high', score
    elif score >= 8:
        return 'medium', score
    return 'low', score


def get_customer_balance(customer_id):
    if customer_id not in customer_balances:
        customer_balances[customer_id] = 45250
    return customer_balances[customer_id]


def update_customer_balance(customer_id, amount):
    current = get_customer_balance(customer_id)
    if current + amount < 0:
        return False, "Yetersiz bakiye"
    customer_balances[customer_id] = current + amount
    return True, customer_balances[customer_id]


def update_customer_password(customer_id, new_password):
    try:
        conn = get_db_connection()
        if not conn:
            return False, "Veritabanı hatası"
        cur = conn.cursor()
        cur.execute('UPDATE customers SET password_hash = %s WHERE id = %s',
                    (hash_password(new_password), customer_id))
        conn.commit()
        cur.close()
        conn.close()
        return True, "Şifre başarıyla güncellendi"
    except Exception as e:
        logger.error(f"Şifre güncelleme hatası: {e}")
        return False, "Şifre güncellenirken hata oluştu"


def get_customer_card_limits(customer_id):
    if customer_id not in customer_card_limits:
        customer_card_limits[customer_id] = {
            'daily_withdrawal': 150000,
            'daily_shopping': 300000,
            'daily_online': 100000,
            'monthly_total': 1500000
        }
    return customer_card_limits[customer_id]


def update_customer_card_limits(customer_id, new_limits):
    try:
        current = get_customer_card_limits(customer_id)
        for key, value in new_limits.items():
            if value is not None:
                current[key] = value
        customer_card_limits[customer_id] = current
        return True, "Kart limitleri başarıyla güncellendi"
    except Exception as e:
        logger.error(f"Kart limiti güncelleme hatası: {e}")
        return False, "Kart limitleri güncellenirken hata oluştu"


def block_card_func(card_number):
    try:
        card_number = card_number.replace(' ', '')
        if len(card_number) != 16:
            return False, "Geçersiz kart numarası"
        blocked_cards[card_number] = True
        return True, f"Kart {card_number[-4:]} başarıyla bloke edildi"
    except Exception as e:
        logger.error(f"Kart bloklama hatası: {e}")
        return False, "Kart bloklanırken hata oluştu"


def is_card_blocked(card_number):
    return blocked_cards.get(card_number.replace(' ', ''), False)


def block_user_access(username):
    try:
        blocked_users[username] = True
        return True, f"Kullanıcı {username} erişimi engellendi"
    except Exception as e:
        logger.error(f"Kullanıcı bloklama hatası: {e}")
        return False, "Erişim engellenirken hata oluştu"


def order_new_card(address):
    try:
        if not address or len(address) < 10:
            return False, "Lütfen tam adresi giriniz"
        return True, f"Yeni kartınız şu adrese gönderilecektir: {address}. Teslimat 5-7 iş günü sürecektir."
    except Exception as e:
        logger.error(f"Kart siparişi hatası: {e}")
        return False, "Kart sipariş edilirken hata oluştu"


def generate_smart_response(question, customer_name=""):
    q = question.lower()
    balance = get_customer_balance(session.get('customer_id', 0))
    limits = get_customer_card_limits(session.get('customer_id', 0))

    responses = {
        'balance': {
            'keywords': ['bakiye', 'hesap', 'para', 'bakiyem', 'hesap bakiyesi', 'balance'],
            'response': f'''Bakiye kontrolü için birkaç yöntem mevcuttur:

1. İnternet bankacılığı: web sitemizden kişisel hesabınıza giriş yapın
2. Mobil uygulama: FexBank uygulamasını App Store veya Google Play'den indirin
3. Otomatik bilgi: +90 962 708 10 34 numarasını arayın
4. ATM: kartınızı takın ve "Bakiye Sorgulama" seçeneğini seçin

Hesap limitleri:
- Günlük çekim limiti: 150.000 RUB
- Aylık işlem limiti: 1.500.000 RUB

Mevcut bakiye tutarı: {balance:,} RUB''',
            'options': []
        },
        'card': {
            'keywords': ['kart', 'kredi kartı', 'banka kartı', 'kart bloke', 'kartımı bloke et', 'card'],
            'response': '''Banka kartları hakkında:

Acil bloklama: +90 962 708 10 34 (7/24)
Yeni kart siparişi: internet bankacılığından yapılabilir
Kart limitleri:
- Nakit çekme: günlük 150.000 RUB'a kadar
- Alışveriş: günlük 300.000 RUB'a kadar
- İnternet ödemeleri: günlük 100.000 RUB'a kadar

Limit değişikliği için banka şubesine başvurun.''',
            'options': ['Kart Bloklama', 'Limit Değiştirme', 'Yeni Kart Siparişi']
        },
        'transfer': {
            'keywords': ['transfer', 'para transferi', 'para gönderme', 'havale', 'eft'],
            'response': f'''Para transferi hakkında:

Banka içi transferler:
- Komisyon: 0 RUB
- Limit: 500.000 RUB/gün
- Süre: Anında

Bankalar arası transferler:
- Komisyon: %1.5 (min. 50 RUB)
- Limit: 300.000 RUB/gün
- Süre: 1-3 iş günü

Uluslararası transferler:
- Komisyon: %2 (min. 100 RUB)
- Limit: 1.000.000 RUB/gün
- Süre: 3-5 iş günü

Mevcut bakiyeniz: {balance:,} RUB

Acil transferler ek ücret karşılığında yapılabilir.''',
            'options': ['Acil Transfer', 'Normal Transfer']
        },
        'password': {
            'keywords': ['şifre', 'parola', 'giriş', 'erişim', 'şifremi unuttum', 'şifre değiştirme', 'yeni şifre', 'password'],
            'response': 'Şifre değiştirmek için yeni şifrenizi giriniz. Yeni şifreniz en az 8 karakter içermelidir.',
            'options': ['Şifre Değiştirme', 'Erişim Bloklama']
        },
        'other': {
            'keywords': ['diğer', 'başka', 'diğer sorular', 'other'],
            'response': '''Diğer konular için:
1. Teknik destek talebi oluşturun
2. Çağrı merkezini arayın: +90 962 708 10 34
3. En yakın banka şubesine başvurun''',
            'options': []
        }
    }

    main_menu = ['Bakiye', 'Kartlar', 'Transferler', 'Şifreler ve Erişim', 'Diğer Sorular']

    if 'ana menü' in q or 'ana' in q:
        return {'answer': 'Merhaba! Size nasıl yardımcı olabilirim? Bir konu seçin veya soru sorun.',
                'options': main_menu, 'menu_type': 'main'}

    if 'erişim bloke' in q or 'erişim bloklama' in q:
        return {'answer': 'Erişim bloklama için kullanıcı adınızı giriniz:',
                'options': ['Erişimi Blokla', 'İptal'], 'menu_type': 'block_access_form'}

    if 'diğer sorular' in q:
        return {'answer': 'Lütfen sorunuzu ayrıntılı olarak yazınız. Size daha iyi yardımcı olabilmemiz için sorunuzu mümkün olduğunca ayrıntılı açıklayınız.',
                'options': ['Talep Oluştur', 'İletişim Bilgileri', 'Ana Menü'], 'menu_type': 'other_questions'}

    if 'acil transfer' in q:
        return {'answer': f'''Acil transfer için aşağıdaki bilgileri giriniz:

- Alıcı kart numarası
- Kart son kullanma tarihi (AA/YY)
- CVV
- Transfer tutarı (RUB)

Mevcut bakiyeniz: {balance:,} RUB''',
                'options': ['Transferi Tamamla', 'İptal'],
                'menu_type': 'urgent_transfer_form', 'transfer_type': 'acil'}

    if 'normal transfer' in q or 'sıradan transfer' in q:
        return {'answer': f'''Normal transfer için aşağıdaki bilgileri giriniz:

- Alıcı kart numarası
- Kart son kullanma tarihi (AA/YY)
- CVV
- Transfer tutarı (RUB)

Mevcut bakiyeniz: {balance:,} RUB''',
                'options': ['Transferi Tamamla', 'İptal'],
                'menu_type': 'normal_transfer_form', 'transfer_type': 'normal'}

    if 'şifre değiştirme' in q:
        return {'answer': 'Şifre değiştirmek için yeni şifrenizi giriniz. Yeni şifreniz en az 8 karakter içermelidir.',
                'options': ['Şifreyi Değiştir', 'İptal'], 'menu_type': 'password_change_form'}

    if 'limit değişikliği' in q or 'limit değiştirme' in q:
        return {'answer': f'''Kart limiti değişikliği:

Mevcut limitleriniz:
- Günlük nakit çekme: {limits['daily_withdrawal']:,} RUB
- Günlük alışveriş: {limits['daily_shopping']:,} RUB
- Günlük internet ödemeleri: {limits['daily_online']:,} RUB
- Aylık toplam işlem limiti: {limits['monthly_total']:,} RUB

Lütfen yeni limit değerlerini giriniz:''',
                'options': ['Limitleri Güncelle', 'İptal'],
                'menu_type': 'limit_change_form', 'current_limits': limits}

    if 'kart blok' in q or 'kartı blokla' in q:
        return {'answer': 'Kart bloklamak için kart numarasını giriniz (16 hane):',
                'options': ['Kartı Blokla', 'İptal'], 'menu_type': 'block_card_form'}

    if 'yeni kart' in q or 'kart siparişi' in q:
        return {'answer': 'Yeni kart siparişi için teslimat adresini giriniz:',
                'options': ['Kart Sipariş Et', 'İptal'], 'menu_type': 'order_card_form'}

    best_match, highest_score = None, 0
    for category, data in responses.items():
        score = sum(1 for kw in data['keywords'] if kw in q)
        if score > highest_score:
            highest_score = score
            best_match = data

    if best_match:
        return {'answer': best_match['response'], 'options': best_match['options'], 'menu_type': 'category'}

    specific = {
        'bakiyeyi kontrol et': {
            'answer': f'''Mevcut bakiyeniz: {balance:,} RUB

Detaylı bilgi için:
1. İşlem geçmişini kontrol edin
2. Hesap limitlerini öğrenin
3. Destek ile iletişime geçin''',
            'options': ['İşlem Geçmişi', 'Hesap Limitleri', 'Ana Menü']
        },
        'işlem geçmişi': {
            'answer': '''İşlem geçmişi aşağıdaki hizmetlerden görüntülenebilir:
1. İnternet bankacılığı: tüm işlemlerin tam geçmişi
2. Mobil uygulama: son 100 işlem
3. Banka şubesi ekstresi: herhangi bir dönem için

Detaylı bilgi için banka şubesine başvurun.''',
            'options': ['Ana Menü', 'İletişim Bilgileri']
        },
        'iletişim bilgileri': {
            'answer': '''FexBank İletişim Bilgileri:

Çağrı merkezi: +90 962 708 10 34 (7/24)
Acil kart bloklama: +90 962 708 10 34
E-posta: support@fexbank.com
Merkez ofis: İstanbul, Türkiye

Şube çalışma saatleri: Pzt-Cum 09:00-20:00, Cmt 10:00-17:00''',
            'options': ['Ana Menü', 'Bankanın Şubeleri']
        }
    }

    for option, data in specific.items():
        if option in q:
            return {'answer': data['answer'], 'options': data['options'], 'menu_type': 'specific'}

    return {'answer': '''Sorunuz için teşekkürler! Daha doğru bir yanıt için öneriler:

1. Teknik destek talebi oluşturun
2. Çağrı merkezini arayın: +90 962 708 10 34
3. En yakın banka şubesine başvurun

Uzmanlarımız durumunuzu detaylı inceleyip en iyi çözümü sunacaktır.''',
        'options': ['Talep Oluştur', 'İletişim Bilgileri', 'Ana Menü'],
        'menu_type': 'default'}


LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <title>FexBank - Modern Bankacılık</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root { --primary: #2563eb; --primary-dark: #1d4ed8; --secondary: #059669; --danger: #dc2626; --dark: #1e293b; --gray: #64748b; --border: #e2e8f0; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { background: white; border-radius: 20px; padding: 40px; box-shadow: 0 25px 50px rgba(0,0,0,0.15); width: 100%; max-width: 480px; }
        .logo { text-align: center; margin-bottom: 32px; }
        .logo h1 { font-size: 2.8rem; font-weight: 800; background: linear-gradient(135deg, #2563eb, #1d4ed8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
        .logo .tagline { color: var(--gray); font-size: 1.1rem; font-weight: 500; }
        .tabs { display: flex; background: #f8fafc; border-radius: 15px; padding: 6px; margin-bottom: 28px; border: 1px solid var(--border); }
        .tab { flex: 1; padding: 14px; text-align: center; background: transparent; border: none; border-radius: 12px; cursor: pointer; font-weight: 600; color: var(--gray); transition: all 0.3s; font-size: 14px; }
        .tab.active { background: white; color: var(--primary); box-shadow: 0 4px 15px rgba(37,99,235,0.2); }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 10px; font-weight: 600; color: var(--dark); font-size: 14px; }
        input, select { width: 100%; padding: 14px 16px; border: 2px solid var(--border); border-radius: 12px; font-size: 15px; background: white; color: var(--dark); }
        input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(37,99,235,0.1); }
        .btn { width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-top: 8px; }
        .btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; box-shadow: 0 8px 25px rgba(37,99,235,0.3); }
        .btn-primary:hover { transform: translateY(-2px); }
        .btn-secondary { background: linear-gradient(135deg, var(--secondary), #047857); color: white; }
        .btn-outline { background: transparent; color: var(--primary); border: 2px solid var(--primary); }
        .message { padding: 16px; border-radius: 12px; margin-bottom: 20px; text-align: center; font-weight: 600; font-size: 14px; border: 1px solid; }
        .success { background: #dcfce7; color: #166534; border-color: #bbf7d0; }
        .error { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
        .welcome-section { text-align: center; padding: 24px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>FexBank</h1>
            <div class="tagline">Akıllı Bankacılık Desteği</div>
        </div>

        {% if session.get('customer_id') %}
            <div class="welcome-section">
                <div class="message success">Hoş geldiniz, <strong>{{ session.get('customer_name', 'Müşteri') }}</strong>!</div>
                <button class="btn btn-primary" onclick="location.href='/dashboard'">Destek Paneli</button>
                <button class="btn btn-outline" style="margin-top:12px;" onclick="location.href='/logout'">Çıkış Yap</button>
            </div>
        {% elif session.get('admin_logged_in') %}
            <div class="welcome-section">
                <div class="message success">Hoş geldiniz, <strong>Yönetici</strong>!</div>
                <button class="btn btn-primary" onclick="location.href='/admin'">Yönetici Paneli</button>
                <button class="btn btn-outline" style="margin-top:12px;" onclick="location.href='/logout'">Çıkış Yap</button>
            </div>
        {% else %}
            <div class="tabs">
                <button class="tab active" onclick="showTab('login')">Müşteri Girişi</button>
                <button class="tab" onclick="showTab('register')">Müşteri Kaydı</button>
                <button class="tab" onclick="showTab('admin-login')">Yönetici Girişi</button>
            </div>

            <div id="login" class="tab-content">
                <form onsubmit="event.preventDefault(); login();">
                    <div class="form-group"><label>E-posta:</label><input type="email" id="login_email" placeholder="ornek@mail.com" required></div>
                    <div class="form-group"><label>Kart Numarası:</label><input type="text" id="login_card_number" placeholder="1234 5678 9012 3456" required maxlength="19"></div>
                    <div class="form-group"><label>Kart Son Kullanma:</label><input type="text" id="login_expiry_date" placeholder="AA/YY" required maxlength="5"></div>
                    <div class="form-group"><label>CVV:</label><input type="text" id="login_cvv" placeholder="123" required maxlength="3"></div>
                    <div class="form-group"><label>Şifre:</label><input type="password" id="login_password" placeholder="Şifreniz" required></div>
                    <button type="submit" class="btn btn-primary">Giriş Yap</button>
                </form>
            </div>

            <div id="register" class="tab-content" style="display:none;">
                <form onsubmit="event.preventDefault(); register();">
                    <div class="form-group"><label>Ad Soyad:</label><input type="text" id="reg_name" placeholder="Tam adınız" required></div>
                    <div class="form-group"><label>E-posta:</label><input type="email" id="reg_email" placeholder="ornek@mail.com" required></div>
                    <div class="form-group"><label>Telefon:</label><input type="tel" id="reg_phone" placeholder="+90 5XX XXX XX XX" required></div>
                    <div class="form-group"><label>Kart Numarası:</label><input type="text" id="reg_card_number" placeholder="1234567890123456" required maxlength="19"></div>
                    <div class="form-group"><label>Son Kullanma:</label><input type="text" id="reg_expiry_date" placeholder="AA/YY" required maxlength="5"></div>
                    <div class="form-group"><label>CVV:</label><input type="text" id="reg_cvv" placeholder="123" required maxlength="3"></div>
                    <div class="form-group"><label>Şifre (min. 8 karakter):</label><input type="password" id="reg_password" placeholder="En az 8 karakter" required minlength="8"></div>
                    <button type="submit" class="btn btn-primary">Kayıt Ol</button>
                </form>
            </div>

            <div id="admin-login" class="tab-content" style="display:none;">
                <form onsubmit="event.preventDefault(); adminLogin();">
                    <div class="form-group"><label>Yönetici Adı:</label><input type="text" id="admin_username" placeholder="Yönetici adı" required></div>
                    <div class="form-group"><label>Yönetici Şifresi:</label><input type="password" id="admin_password" placeholder="Yönetici şifresi" required></div>
                    <button type="submit" class="btn btn-secondary">Yönetici Girişi</button>
                </form>
            </div>

            <div id="message"></div>
        {% endif %}
    </div>

    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
            document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
            document.getElementById(tabName).style.display = 'block';
        }

        function formatCardNumber(input) {
            let value = input.value.replace(/\\s+/g, '').replace(/[^0-9]/gi, '');
            let formatted = '';
            for (let i = 0; i < value.length; i++) {
                if (i > 0 && i % 4 === 0) formatted += ' ';
                formatted += value[i];
            }
            input.value = formatted;
        }

        function formatExpiryDate(input) {
            let value = input.value.replace(/[^0-9]/g, '');
            if (value.length >= 2) value = value.substring(0, 2) + '/' + value.substring(2, 4);
            input.value = value;
        }

        document.getElementById('login_card_number')?.addEventListener('input', function() { formatCardNumber(this); });
        document.getElementById('login_expiry_date')?.addEventListener('input', function() { formatExpiryDate(this); });
        document.getElementById('reg_card_number')?.addEventListener('input', function() { this.value = this.value.replace(/[^0-9]/g, ''); });
        document.getElementById('reg_expiry_date')?.addEventListener('input', function() { formatExpiryDate(this); });

        async function login() {
            const data = {
                email: document.getElementById('login_email').value,
                card_number: document.getElementById('login_card_number').value.replace(/\\s+/g, ''),
                expiry_date: document.getElementById('login_expiry_date').value,
                cvv: document.getElementById('login_cvv').value,
                password: document.getElementById('login_password').value
            };
            if (!data.email || !data.card_number || !data.expiry_date || !data.cvv || !data.password) {
                showMessage('Tüm alanları doldurun', 'error'); return;
            }
            try {
                const res = await fetch('/api/v1/auth/login', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (result.success) {
                    showMessage('Giriş başarılı!', 'success');
                    setTimeout(() => window.location.href = '/dashboard', 1000);
                } else {
                    showMessage(result.message, 'error');
                }
            } catch (e) { showMessage('Giriş hatası', 'error'); }
        }

        async function register() {
            const data = {
                name: document.getElementById('reg_name').value,
                email: document.getElementById('reg_email').value,
                phone: document.getElementById('reg_phone').value,
                card_number: document.getElementById('reg_card_number').value.replace(/\\s+/g, ''),
                expiry_date: document.getElementById('reg_expiry_date').value,
                cvv: document.getElementById('reg_cvv').value,
                password: document.getElementById('reg_password').value
            };
            for (let k in data) { if (!data[k]) { showMessage('Tüm alanları doldurun', 'error'); return; } }
            if (data.password.length < 8) { showMessage('Şifre en az 8 karakter olmalı', 'error'); return; }
            try {
                const res = await fetch('/api/v1/auth/register', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (result.success) {
                    showMessage('Kayıt başarılı! Giriş yapabilirsiniz.', 'success');
                    setTimeout(() => showTab('login'), 1500);
                } else {
                    showMessage(result.message, 'error');
                }
            } catch (e) { showMessage('Kayıt hatası', 'error'); }
        }

        async function adminLogin() {
            const data = {
                username: document.getElementById('admin_username').value,
                password: document.getElementById('admin_password').value
            };
            if (!data.username || !data.password) { showMessage('Kullanıcı adı ve şifre gerekli', 'error'); return; }
            try {
                const res = await fetch('/api/v1/auth/admin-login', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (result.success) {
                    showMessage('Yönetici girişi başarılı!', 'success');
                    setTimeout(() => window.location.href = '/admin', 1000);
                } else {
                    showMessage(result.message, 'error');
                }
            } catch (e) { showMessage('Giriş hatası', 'error'); }
        }

        function showMessage(text, type) {
            const el = document.getElementById('message');
            el.innerHTML = `<div class="message ${type}">${text}</div>`;
            setTimeout(() => el.innerHTML = '', 5000);
        }
    </script>
</body>
</html>
'''


DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <title>FexBank - Destek Paneli</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root { --primary: #2563eb; --primary-dark: #1d4ed8; --secondary: #059669; --danger: #dc2626; --dark: #1e293b; --gray: #64748b; --border: #e2e8f0; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: #f1f5f9; min-height: 100vh; padding: 24px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 20px; padding: 32px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 2px solid var(--border); }
        .logo h1 { font-size: 2.4rem; font-weight: 800; background: linear-gradient(135deg, #2563eb, #1d4ed8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .user-info { text-align: right; color: var(--dark); font-size: 1.1rem; font-weight: 600; }
        .btn { padding: 12px 24px; border: none; border-radius: 12px; cursor: pointer; font-weight: 600; margin-left: 12px; font-size: 14px; }
        .btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; }
        .btn-primary:hover { transform: translateY(-2px); }
        .btn-outline { background: transparent; color: var(--primary); border: 2px solid var(--primary); }
        .section { background: white; margin: 24px 0; padding: 32px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 1px solid var(--border); }
        .section h2 { color: var(--dark); margin-bottom: 20px; font-size: 1.5rem; font-weight: 700; }
        .chat-box { height: 500px; border: 2px solid var(--border); border-radius: 16px; padding: 24px; margin-bottom: 20px; overflow-y: auto; background: #f8fafc; }
        .message { margin: 16px 0; padding: 18px 20px; border-radius: 16px; max-width: 80%; }
        .user { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; margin-left: auto; border-bottom-right-radius: 6px; }
        .ai { background: white; color: var(--dark); margin-right: auto; border-bottom-left-radius: 6px; border: 1px solid var(--border); }
        .input-group { display: flex; gap: 16px; align-items: center; }
        input, textarea, select { flex: 1; padding: 16px 20px; border: 2px solid var(--border); border-radius: 12px; font-size: 15px; background: white; color: var(--dark); }
        input:focus, textarea:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(37,99,235,0.1); }
        .quick-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 20px 0; }
        .quick-option { padding: 20px; background: white; color: var(--dark); border: 2px solid var(--border); border-radius: 12px; cursor: pointer; text-align: center; font-weight: 600; }
        .quick-option:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.15); }
        .quick-option.account { border-color: #10b981; background: linear-gradient(135deg, #f0fdf4, #dcfce7); }
        .quick-option.card { border-color: #ef4444; background: linear-gradient(135deg, #fef2f2, #fee2e2); }
        .quick-option.transfer { border-color: #3b82f6; background: linear-gradient(135deg, #eff6ff, #dbeafe); }
        .quick-option.password { border-color: #f59e0b; background: linear-gradient(135deg, #fffbeb, #fef3c7); }
        .quick-option.other { border-color: #6b7280; background: linear-gradient(135deg, #f9fafb, #f3f4f6); }
        .nav-btn { padding: 10px 20px; background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; border: none; border-radius: 10px; cursor: pointer; font-size: 13px; font-weight: 600; margin-right: 10px; }
        .nav-btn.secondary { background: linear-gradient(135deg, var(--secondary), #047857); }
        .nav-btn.outline { background: transparent; color: var(--primary); border: 2px solid var(--primary); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 32px; }
        .stat-card { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; padding: 28px; border-radius: 16px; text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: 800; margin-bottom: 8px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: var(--dark); font-size: 14px; }
        .ticket-item { background: #f8fafc; border: 1px solid var(--border); padding: 24px; margin: 16px 0; border-radius: 12px; }
        .status-badge { padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; margin-right: 8px; }
        .status-open { background: #dcfce7; color: #166534; }
        .status-closed { background: #e0e7ff; color: #3730a3; }
        .status-in-progress { background: #fef3c7; color: #92400e; }
        .status-critical { background: #fecaca; color: #991b1b; }
        .status-high { background: #fed7aa; color: #9a3412; }
        .status-medium { background: #fef3c7; color: #92400e; }
        .status-low { background: #e0e7ff; color: #3730a3; }
        .ticket-description { width: 100%; height: 150px; padding: 16px 20px; border: 2px solid var(--border); border-radius: 12px; font-size: 15px; resize: none; font-family: 'Inter', sans-serif; }
        .message-container { max-height: 400px; overflow-y: auto; border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 16px; background: #f8fafc; }
        .ticket-message { margin: 12px 0; padding: 12px 16px; border-radius: 12px; max-width: 80%; }
        .customer-message { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; margin-left: auto; border-bottom-right-radius: 6px; }
        .admin-message { background: white; color: var(--dark); margin-right: auto; border: 1px solid var(--border); border-bottom-left-radius: 6px; }
        .message-sender { font-size: 12px; font-weight: 600; margin-bottom: 4px; opacity: 0.8; }
        .message-content { font-size: 14px; }
        .message-time { font-size: 11px; text-align: right; margin-top: 4px; opacity: 0.6; }
        .balance-info { background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 15px; border-radius: 12px; margin: 15px 0; text-align: center; font-weight: 600; }
        .transfer-form, .password-form, .limit-form, .block-form, .order-form { background: #f8fafc; border: 2px solid var(--border); border-radius: 12px; padding: 20px; margin: 15px 0; }
        .transfer-form input, .password-form input, .limit-form input, .block-form input { margin-bottom: 12px; }
        .order-form textarea { margin-bottom: 12px; width: 100%; min-height: 80px; resize: vertical; padding: 16px; border: 2px solid var(--border); border-radius: 12px; }
        .limit-info { background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; padding: 15px; border-radius: 12px; margin: 15px 0; text-align: center; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo"><h1>FexBank</h1></div>
            <div class="user-info">
                Hoş geldiniz <strong>{{ session.get('customer_name', 'Müşteri') }}</strong>!
                <button class="btn btn-outline" onclick="location.href='/logout'">Çıkış</button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number" id="totalTickets">0</div><div>Toplam Talep</div></div>
            <div class="stat-card"><div class="stat-number" id="openTickets">0</div><div>Açık Talepler</div></div>
            <div class="stat-card"><div class="stat-number" id="currentBalance">45,250</div><div>Güncel Bakiye (₽)</div></div>
        </div>

        <div class="section">
            <h2>Destek</h2>
            <div class="chat-box" id="chatBox">
                <div class="message ai">
                    <strong>Asistan:</strong> Merhaba! Size nasıl yardımcı olabilirim? Bir konu seçin veya soru sorun.
                    <div class="quick-options">
                        <button class="quick-option account" onclick="selectOption('Bakiye')">Bakiye</button>
                        <button class="quick-option card" onclick="selectOption('Kartlar')">Kartlar</button>
                        <button class="quick-option transfer" onclick="selectOption('Transferler')">Transferler</button>
                        <button class="quick-option password" onclick="selectOption('Şifreler ve Erişim')">Şifreler ve Erişim</button>
                        <button class="quick-option other" onclick="selectOption('Diğer Sorular')">Diğer Sorular</button>
                    </div>
                </div>
            </div>
            <div class="input-group">
                <input type="text" id="questionInput" placeholder="Sorunuzu yazın..." onkeypress="if(event.key==='Enter') sendQuestion()">
                <button class="btn btn-primary" onclick="sendQuestion()">Gönder</button>
            </div>
        </div>

        <div class="section">
            <h2>Talep Oluştur</h2>
            <form id="ticketForm">
                <div class="form-group"><label>Başlık:</label><input type="text" id="ticketTitle" placeholder="Talep başlığı" required></div>
                <div class="form-group">
                    <label>Sorun Tipi:</label>
                    <select id="issueType" required>
                        <option value="">Seçin</option>
                        <option value="internet_banking">İnternet Bankacılığı</option>
                        <option value="password_change">Şifre Değiştirme</option>
                        <option value="credit_card">Kredi Kartı</option>
                        <option value="mobile_app">Mobil Uygulama</option>
                        <option value="account">Hesaplar</option>
                        <option value="loan">Krediler</option>
                        <option value="other">Diğer</option>
                    </select>
                </div>
                <div class="form-group"><label>Açıklama:</label><textarea class="ticket-description" id="description" placeholder="Sorununuzu açıklayın..." required></textarea></div>
                <button type="button" class="btn btn-primary" onclick="createTicket()">Talep Oluştur</button>
            </form>
            <div id="ticketResult"></div>
        </div>

        <div class="section">
            <h2>Taleplerim</h2>
            <div id="ticketHistory">Yükleniyor...</div>
        </div>

        <div id="ticketModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.5); z-index:1000; align-items:center; justify-content:center;">
            <div style="background:white; border-radius:16px; padding:32px; max-width:800px; width:90%; max-height:90vh; overflow-y:auto;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
                    <h2 id="modalTitle">Talep Detayı</h2>
                    <button onclick="closeTicketModal()" style="background:none; border:none; font-size:24px; cursor:pointer; color:var(--gray);">&times;</button>
                </div>
                <div id="modalContent"></div>
            </div>
        </div>
    </div>

    <script>
        let chatHistory = [];
        let currentTicketId = null;
        let currentTransferType = '';
        let currentBalance = 45250;

        function updateBalanceDisplay() {
            document.getElementById('currentBalance').textContent = currentBalance.toLocaleString();
        }

        function selectOption(option) {
            document.getElementById('questionInput').value = option;
            sendQuestion();
        }

        function showMainMenu() {
            const chatBox = document.getElementById('chatBox');
            const div = document.createElement('div');
            div.innerHTML = `
                <div class="message ai">
                    <strong>Asistan:</strong> Merhaba! Size nasıl yardımcı olabilirim? Bir konu seçin veya soru sorun.
                    <div class="quick-options">
                        <button class="quick-option account" onclick="selectOption('Bakiye')">Bakiye</button>
                        <button class="quick-option card" onclick="selectOption('Kartlar')">Kartlar</button>
                        <button class="quick-option transfer" onclick="selectOption('Transferler')">Transferler</button>
                        <button class="quick-option password" onclick="selectOption('Şifreler ve Erişim')">Şifreler ve Erişim</button>
                        <button class="quick-option other" onclick="selectOption('Diğer Sorular')">Diğer Sorular</button>
                    </div>
                </div>`;
            chatBox.appendChild(div);
            chatBox.scrollTop = chatBox.scrollHeight;
        }

        function goBack() {
            if (chatHistory.length > 1) {
                const chatBox = document.getElementById('chatBox');
                if (chatBox.lastChild) chatBox.removeChild(chatBox.lastChild);
                const prev = chatHistory[chatHistory.length - 2];
                if (prev && prev.menu_type === 'main') {
                    showMainMenu();
                } else if (prev) {
                    const aiMsg = document.createElement('div');
                    aiMsg.className = 'message ai';
                    aiMsg.innerHTML = `
                        <strong>Asistan:</strong> ${prev.content}
                        ${prev.options && prev.options.length > 0 ?
                            `<div class="quick-options" style="margin-top:15px;">
                                ${prev.options.map(o => `<button class="quick-option" onclick="selectOption('${o}')">${o}</button>`).join('')}
                            </div>` : ''}
                        <div style="margin-top:16px;">
                            <button class="nav-btn outline" onclick="showMainMenu()">Ana Menü</button>
                            ${chatHistory.length > 2 ? `<button class="nav-btn secondary" onclick="goBack()">Geri</button>` : ''}
                        </div>`;
                    chatBox.appendChild(aiMsg);
                    chatBox.scrollTop = chatBox.scrollHeight;
                }
                chatHistory.pop();
            } else {
                showMainMenu();
            }
        }

        async function sendQuestion() {
            const question = document.getElementById('questionInput').value.trim();
            if (!question) return;
            const chatBox = document.getElementById('chatBox');
            const userMsg = document.createElement('div');
            userMsg.className = 'message user';
            userMsg.innerHTML = `<strong>Siz:</strong> ${question}`;
            chatBox.appendChild(userMsg);
            document.getElementById('questionInput').value = '';

            try {
                const response = await fetch('/api/v1/chat', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question: question })
                });
                const data = await response.json();
                if (data.success) {
                    const aiMsg = document.createElement('div');
                    aiMsg.className = 'message ai';
                    let html = `<strong>Asistan:</strong> ${data.data.answer.replace(/\\n/g, '<br>')}`;

                    if (data.data.menu_type === 'urgent_transfer_form' || data.data.menu_type === 'normal_transfer_form') {
                        currentTransferType = data.data.transfer_type;
                        html += showTransferForm(data.data.transfer_type);
                    }
                    if (data.data.menu_type === 'password_change_form') html += showPasswordForm();
                    if (data.data.menu_type === 'limit_change_form') html += showLimitForm(data.data.current_limits);
                    if (data.data.menu_type === 'block_card_form') html += showBlockCardForm();
                    if (data.data.menu_type === 'order_card_form') html += showOrderCardForm();
                    if (data.data.menu_type === 'block_access_form') html += showBlockAccessForm();

                    if (data.data.options && data.data.options.length > 0) {
                        html += `<div class="quick-options" style="margin-top:15px;">`;
                        data.data.options.forEach(option => {
                            if (option === 'Transferi Tamamla') html += `<button class="quick-option" onclick="completeTransfer()">${option}</button>`;
                            else if (option === 'Şifreyi Değiştir') html += `<button class="quick-option" onclick="changePassword()">${option}</button>`;
                            else if (option === 'Limitleri Güncelle') html += `<button class="quick-option" onclick="updateCardLimits()">${option}</button>`;
                            else if (option === 'Kartı Blokla') html += `<button class="quick-option" onclick="blockCard()">${option}</button>`;
                            else if (option === 'Kart Sipariş Et') html += `<button class="quick-option" onclick="orderCard()">${option}</button>`;
                            else if (option === 'Erişimi Blokla') html += `<button class="quick-option" onclick="blockAccess()">${option}</button>`;
                            else if (option === 'İptal') html += `<button class="quick-option" onclick="cancelOperation()">${option}</button>`;
                            else html += `<button class="quick-option" onclick="selectOption('${option}')">${option}</button>`;
                        });
                        html += `</div>`;
                    }

                    html += `<div style="margin-top:16px;">
                        <button class="nav-btn outline" onclick="showMainMenu()">Ana Menü</button>
                        ${chatHistory.length > 0 ? `<button class="nav-btn secondary" onclick="goBack()">Geri</button>` : ''}
                    </div>`;

                    aiMsg.innerHTML = html;
                    chatBox.appendChild(aiMsg);
                    chatHistory.push({
                        type: 'ai',
                        content: data.data.answer,
                        options: data.data.options,
                        menu_type: data.data.menu_type
                    });
                } else {
                    const errMsg = document.createElement('div');
                    errMsg.className = 'message ai';
                    errMsg.innerHTML = `<strong>Asistan:</strong> Hata: ${data.message}`;
                    chatBox.appendChild(errMsg);
                }
                chatBox.scrollTop = chatBox.scrollHeight;
            } catch (error) {
                const errMsg = document.createElement('div');
                errMsg.className = 'message ai';
                errMsg.innerHTML = `<strong>Asistan:</strong> Bağlantı hatası. Lütfen tekrar deneyin.`;
                chatBox.appendChild(errMsg);
                chatBox.scrollTop = chatBox.scrollHeight;
            }
        }

        function showTransferForm(transferType) {
            return `
                <div class="transfer-form">
                    <div class="balance-info">Güncel bakiye: <span>${currentBalance.toLocaleString()}</span> RUB</div>
                    <input type="text" id="recipientCard" placeholder="Alıcı kart numarası (16 hane)" maxlength="19">
                    <input type="text" id="expiryDate" placeholder="Son kullanma (AA/YY)" maxlength="5">
                    <input type="text" id="cvv" placeholder="CVV (3 hane)" maxlength="3">
                    <input type="number" id="transferAmount" placeholder="Transfer tutarı (RUB)" min="1" max="${currentBalance}">
                    <div style="color:#666; font-size:12px; margin-top:10px;">
                        ${transferType === 'acil' ? 'Acil transfer: 1 dakikadan kısa sürede gönderilir' : 'Normal transfer: 3-5 dakika içinde gönderilir'}
                    </div>
                </div>`;
        }

        function showPasswordForm() {
            return `<div class="password-form">
                <input type="password" id="newPassword" placeholder="Yeni şifre (en az 8 karakter)" minlength="8">
                <input type="password" id="confirmPassword" placeholder="Yeni şifreyi onayla">
                <div style="color:#666; font-size:12px; margin-top:10px;">Yeni şifreniz en az 8 karakter içermelidir</div>
            </div>`;
        }

        function showLimitForm(currentLimits) {
            return `<div class="limit-form">
                <div class="limit-info">Güncel kart limitleriniz</div>
                <input type="number" id="dailyWithdrawal" placeholder="Günlük nakit çekme limiti (RUB)" value="${currentLimits.daily_withdrawal}" min="0" max="1000000">
                <input type="number" id="dailyShopping" placeholder="Günlük alışveriş limiti (RUB)" value="${currentLimits.daily_shopping}" min="0" max="1000000">
                <input type="number" id="dailyOnline" placeholder="Günlük internet ödeme limiti (RUB)" value="${currentLimits.daily_online}" min="0" max="1000000">
                <input type="number" id="monthlyTotal" placeholder="Aylık toplam işlem limiti (RUB)" value="${currentLimits.monthly_total}" min="0" max="5000000">
                <div style="color:#666; font-size:12px; margin-top:10px;">Not: Limit değişiklikleri banka onayına tabidir ve 1-2 iş günü içinde yürürlüğe girer.</div>
            </div>`;
        }

        function showBlockCardForm() {
            return `<div class="block-form">
                <input type="text" id="cardToBlock" placeholder="Bloklanacak kart numarası (16 hane)" maxlength="19">
                <div style="color:#666; font-size:12px; margin-top:10px;">Kart bloklandıktan sonra tüm işlemler durdurulacaktır</div>
            </div>`;
        }

        function showOrderCardForm() {
            return `<div class="order-form">
                <textarea id="deliveryAddress" placeholder="Tam teslimat adresini giriniz (sokak, bina, daire, şehir, posta kodu)"></textarea>
                <div style="color:#666; font-size:12px; margin-top:10px;">Yeni kart 5-7 iş günü içinde teslim edilecektir</div>
            </div>`;
        }

        function showBlockAccessForm() {
            return `<div class="block-form">
                <input type="text" id="usernameToBlock" placeholder="Kullanıcı adınızı girin">
                <div style="color:#666; font-size:12px; margin-top:10px;">Erişim bloklandıktan sonra oturumunuz kapatılacak ve tekrar giriş yapamayacaksınız</div>
            </div>`;
        }

        function completeTransfer() {
            const recipientCard = document.getElementById('recipientCard').value.replace(/\\s+/g, '');
            const expiryDate = document.getElementById('expiryDate').value;
            const cvv = document.getElementById('cvv').value;
            const amount = parseInt(document.getElementById('transferAmount').value);

            if (!recipientCard || !expiryDate || !cvv || !amount) { alert('Lütfen tüm alanları doldurun'); return; }
            if (recipientCard.length !== 16) { alert('Kart numarası 16 hane olmalıdır'); return; }
            if (!/^\\d{2}\\/\\d{2}$/.test(expiryDate)) { alert('Son kullanma AA/YY formatında olmalıdır'); return; }
            if (cvv.length !== 3) { alert('CVV 3 hane olmalıdır'); return; }
            if (amount <= 0) { alert('Geçerli bir tutar girin'); return; }
            if (amount > currentBalance) { alert('Yetersiz bakiye'); return; }

            fetch('/api/v1/transfer', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    recipient_card: recipientCard, expiry_date: expiryDate,
                    cvv: cvv, amount: amount, transfer_type: currentTransferType
                })
            }).then(r => r.json()).then(data => {
                const chatBox = document.getElementById('chatBox');
                const resultMsg = document.createElement('div');
                resultMsg.className = 'message ai';
                if (data.success) {
                    currentBalance = data.data.new_balance;
                    updateBalanceDisplay();
                    resultMsg.innerHTML = `<strong>Asistan:</strong> ${data.message}
                        <div class="balance-info" style="margin-top:10px;">Güncel bakiye: ${data.data.new_balance.toLocaleString()} RUB</div>`;
                } else {
                    resultMsg.innerHTML = `<strong>Asistan:</strong> ${data.message}`;
                }
                chatBox.appendChild(resultMsg);
                chatBox.scrollTop = chatBox.scrollHeight;
            }).catch(() => {
                const chatBox = document.getElementById('chatBox');
                const err = document.createElement('div');
                err.className = 'message ai';
                err.innerHTML = `<strong>Asistan:</strong> Transfer sırasında hata oluştu`;
                chatBox.appendChild(err);
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        function changePassword() {
            const np = document.getElementById('newPassword').value;
            const cp = document.getElementById('confirmPassword').value;
            if (!np || !cp) { alert('Lütfen tüm alanları doldurun'); return; }
            if (np.length < 8) { alert('Şifre en az 8 karakter olmalı'); return; }
            if (np !== cp) { alert('Şifreler eşleşmiyor'); return; }
            fetch('/api/v1/change-password', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ new_password: np })
            }).then(r => r.json()).then(data => {
                const chatBox = document.getElementById('chatBox');
                const msg = document.createElement('div');
                msg.className = 'message ai';
                msg.innerHTML = `<strong>Asistan:</strong> ${data.message}`;
                chatBox.appendChild(msg);
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        function updateCardLimits() {
            const dw = parseInt(document.getElementById('dailyWithdrawal').value);
            const ds = parseInt(document.getElementById('dailyShopping').value);
            const doo = parseInt(document.getElementById('dailyOnline').value);
            const mt = parseInt(document.getElementById('monthlyTotal').value);
            if (!dw || !ds || !doo || !mt) { alert('Lütfen tüm limit alanlarını doldurun'); return; }
            if (dw < 0 || ds < 0 || doo < 0 || mt < 0) { alert('Limit değerleri negatif olamaz'); return; }
            fetch('/api/v1/update-card-limits', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ daily_withdrawal: dw, daily_shopping: ds, daily_online: doo, monthly_total: mt })
            }).then(r => r.json()).then(data => {
                const chatBox = document.getElementById('chatBox');
                const msg = document.createElement('div');
                msg.className = 'message ai';
                if (data.success) {
                    msg.innerHTML = `<strong>Asistan:</strong> ${data.message}
                        <div class="limit-info" style="margin-top:10px;">
                            Yeni limitleriniz:<br>
                            Günlük nakit: ${dw.toLocaleString()} RUB<br>
                            Günlük alışveriş: ${ds.toLocaleString()} RUB<br>
                            Günlük internet: ${doo.toLocaleString()} RUB<br>
                            Aylık toplam: ${mt.toLocaleString()} RUB
                        </div>`;
                } else {
                    msg.innerHTML = `<strong>Asistan:</strong> ${data.message}`;
                }
                chatBox.appendChild(msg);
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        function blockCard() {
            const cn = document.getElementById('cardToBlock').value.replace(/\\s+/g, '');
            if (!cn) { alert('Lütfen kart numarasını girin'); return; }
            if (cn.length !== 16) { alert('Kart numarası 16 hane olmalıdır'); return; }
            fetch('/api/v1/block-card', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ card_number: cn })
            }).then(r => r.json()).then(data => {
                const chatBox = document.getElementById('chatBox');
                const msg = document.createElement('div');
                msg.className = 'message ai';
                msg.innerHTML = `<strong>Asistan:</strong> ${data.message}`;
                chatBox.appendChild(msg);
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        function orderCard() {
            const address = document.getElementById('deliveryAddress').value.trim();
            if (!address) { alert('Lütfen teslimat adresini girin'); return; }
            if (address.length < 10) { alert('Lütfen tam adresi girin'); return; }
            fetch('/api/v1/order-card', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ address: address })
            }).then(r => r.json()).then(data => {
                const chatBox = document.getElementById('chatBox');
                const msg = document.createElement('div');
                msg.className = 'message ai';
                msg.innerHTML = `<strong>Asistan:</strong> ${data.message}`;
                chatBox.appendChild(msg);
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        function blockAccess() {
            const username = document.getElementById('usernameToBlock').value.trim();
            if (!username) { alert('Lütfen kullanıcı adınızı girin'); return; }
            fetch('/api/v1/block-access', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username })
            }).then(r => r.json()).then(data => {
                const chatBox = document.getElementById('chatBox');
                const msg = document.createElement('div');
                msg.className = 'message ai';
                msg.innerHTML = `<strong>Asistan:</strong> ${data.message}`;
                chatBox.appendChild(msg);
                chatBox.scrollTop = chatBox.scrollHeight;
                if (data.success) setTimeout(() => window.location.href = '/logout', 2000);
            });
        }

        function cancelOperation() {
            const chatBox = document.getElementById('chatBox');
            const msg = document.createElement('div');
            msg.className = 'message ai';
            msg.innerHTML = `<strong>Asistan:</strong> İşlem iptal edildi`;
            chatBox.appendChild(msg);
            chatBox.scrollTop = chatBox.scrollHeight;
            showMainMenu();
        }

        document.addEventListener('input', function(e) {
            if (e.target.id === 'recipientCard' || e.target.id === 'cardToBlock') {
                let value = e.target.value.replace(/\\s+/g, '').replace(/[^0-9]/gi, '');
                let formatted = '';
                for (let i = 0; i < value.length; i++) {
                    if (i > 0 && i % 4 === 0) formatted += ' ';
                    formatted += value[i];
                }
                e.target.value = formatted;
            }
            if (e.target.id === 'expiryDate') {
                let value = e.target.value.replace(/[^0-9]/g, '');
                if (value.length >= 2) value = value.substring(0, 2) + '/' + value.substring(2, 4);
                e.target.value = value;
            }
        });

        async function createTicket() {
            const title = document.getElementById('ticketTitle').value.trim();
            const issueType = document.getElementById('issueType').value;
            const description = document.getElementById('description').value.trim();
            if (!title || !issueType || !description) { showTicketResult('Tüm alanları doldurun', 'error'); return; }
            try {
                const response = await fetch('/api/v1/tickets', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title, issue_type: issueType, description })
                });
                const data = await response.json();
                if (data.success) {
                    showTicketResult(`Talep #${data.data.ticket_id} başarıyla oluşturuldu!`, 'success');
                    document.getElementById('ticketForm').reset();
                    loadTicketHistory();
                    loadStats();
                } else {
                    showTicketResult(data.message, 'error');
                }
            } catch (error) {
                showTicketResult('Talep oluşturma hatası', 'error');
            }
        }

        function showTicketResult(message, type) {
            const el = document.getElementById('ticketResult');
            el.innerHTML = `<div class="message ${type}">${message}</div>`;
            setTimeout(() => el.innerHTML = '', 5000);
        }

        async function loadTicketHistory() {
            try {
                const response = await fetch('/api/v1/my-tickets');
                const data = await response.json();
                if (data.success) {
                    const html = data.data.tickets.map(t => {
                        let sb = '', pb = '';
                        if (t.status === 'open') sb = `<span class="status-badge status-open">Açık</span>`;
                        else if (t.status === 'closed') sb = `<span class="status-badge status-closed">Kapalı</span>`;
                        else if (t.status === 'in_progress') sb = `<span class="status-badge status-in-progress">İşlemde</span>`;
                        if (t.priority === 'critical') pb = `<span class="status-badge status-critical">Kritik</span>`;
                        else if (t.priority === 'high') pb = `<span class="status-badge status-high">Yüksek</span>`;
                        else if (t.priority === 'medium') pb = `<span class="status-badge status-medium">Orta</span>`;
                        else pb = `<span class="status-badge status-low">Düşük</span>`;
                        return `<div class="ticket-item">
                            <strong>#${t.id} - ${t.title}</strong><br>
                            Tip: ${getIssueTypeText(t.issue_type)}<br>
                            Durum: ${sb}<br>
                            Öncelik: ${pb}<br>
                            Oluşturma: ${new Date(t.created_at).toLocaleString('tr-TR')}<br>
                            <strong>Açıklama:</strong><br>
                            <div style="margin-top:8px; padding:12px; background:white; border-radius:8px; border:1px solid var(--border);">${t.description}</div>
                            <div style="margin-top:12px;">
                                <button class="nav-btn" onclick="viewTicketDetails(${t.id})">Detayları Görüntüle</button>
                            </div>
                        </div>`;
                    }).join('');
                    document.getElementById('ticketHistory').innerHTML = html || 'Talep yok';
                }
            } catch (error) {
                document.getElementById('ticketHistory').innerHTML = 'Talep yükleme hatası';
            }
        }

        async function viewTicketDetails(ticketId) {
            currentTicketId = ticketId;
            try {
                const response = await fetch(`/api/v1/tickets/${ticketId}/messages`);
                const data = await response.json();
                if (data.success) {
                    const t = data.data.ticket;
                    const messages = data.data.messages;
                    let mh = '';
                    messages.forEach(m => {
                        const cls = m.sender_type === 'customer' ? 'customer-message' : 'admin-message';
                        mh += `<div class="ticket-message ${cls}">
                            <div class="message-sender">${m.sender_name}</div>
                            <div class="message-content">${m.message}</div>
                            <div class="message-time">${new Date(m.created_at).toLocaleString('tr-TR')}</div>
                        </div>`;
                    });
                    const content = `
                        <div>
                            <h3>${t.title}</h3>
                            <p><strong>Tip:</strong> ${getIssueTypeText(t.issue_type)}</p>
                            <p><strong>Durum:</strong> ${getStatusText(t.status)}</p>
                            <p><strong>Öncelik:</strong> ${getPriorityText(t.priority)}</p>
                            <p><strong>Açıklama:</strong> ${t.description}</p>
                            <div class="message-container">${mh || '<p>Henüz mesaj yok.</p>'}</div>
                            ${t.status !== 'closed' ? `
                            <div class="input-group">
                                <textarea id="replyMessage" placeholder="Mesajınızı yazın..." rows="3" style="padding:16px; border:2px solid var(--border); border-radius:12px;"></textarea>
                                <button class="btn btn-primary" onclick="sendTicketMessage()">Gönder</button>
                            </div>` : '<p class="message error">Bu talep kapatılmıştır, yanıt veremezsiniz.</p>'}
                        </div>`;
                    document.getElementById('modalTitle').textContent = `Talep #${ticketId} - ${t.title}`;
                    document.getElementById('modalContent').innerHTML = content;
                    document.getElementById('ticketModal').style.display = 'flex';
                    const mc = document.querySelector('.message-container');
                    if (mc) mc.scrollTop = mc.scrollHeight;
                }
            } catch (error) { console.error('Hata:', error); }
        }

        function closeTicketModal() {
            document.getElementById('ticketModal').style.display = 'none';
            currentTicketId = null;
        }

        async function sendTicketMessage() {
            if (!currentTicketId) return;
            const message = document.getElementById('replyMessage').value.trim();
            if (!message) { alert('Lütfen mesaj yazın'); return; }
            try {
                const response = await fetch(`/api/v1/tickets/${currentTicketId}/messages`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message })
                });
                const data = await response.json();
                if (data.success) {
                    document.getElementById('replyMessage').value = '';
                    viewTicketDetails(currentTicketId);
                } else {
                    alert('Mesaj gönderilemedi: ' + data.message);
                }
            } catch (error) {
                alert('Mesaj gönderme hatası');
            }
        }

        function getIssueTypeText(type) {
            const types = {
                'internet_banking': 'İnternet Bankacılığı', 'credit_card': 'Kredi Kartı',
                'mobile_app': 'Mobil Uygulama', 'account': 'Hesaplar', 'loan': 'Krediler',
                'other': 'Diğer', 'password_change': 'Şifre Değiştirme'
            };
            return types[type] || type;
        }

        function getStatusText(status) {
            const s = { 'open': 'Açık', 'closed': 'Kapalı', 'in_progress': 'İşlemde' };
            return s[status] || status;
        }

        function getPriorityText(priority) {
            const p = { 'critical': 'Kritik', 'high': 'Yüksek', 'medium': 'Orta', 'low': 'Düşük' };
            return p[priority] || priority;
        }

        async function loadStats() {
            try {
                const response = await fetch('/api/v1/my-tickets');
                const data = await response.json();
                if (data.success) {
                    const tickets = data.data.tickets || [];
                    const open = tickets.filter(t => t.status === 'open' || t.status === 'in_progress').length;
                    document.getElementById('totalTickets').textContent = tickets.length;
                    document.getElementById('openTickets').textContent = open;
                }
            } catch (error) { console.error(error); }
        }

        document.addEventListener('DOMContentLoaded', function() {
            loadTicketHistory();
            loadStats();
            updateBalanceDisplay();
            chatHistory.push({ type: 'ai', content: 'Merhaba! Size nasıl yardımcı olabilirim?', menu_type: 'main' });
        });
    </script>
</body>
</html>
'''


ADMIN_HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <title>FexBank - Yönetici Paneli</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root { --primary: #2563eb; --primary-dark: #1d4ed8; --secondary: #059669; --danger: #dc2626; --dark: #1e293b; --gray: #64748b; --border: #e2e8f0; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: #f1f5f9; min-height: 100vh; padding: 24px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 20px; padding: 32px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 2px solid var(--border); }
        .logo h1 { font-size: 2.4rem; font-weight: 800; background: linear-gradient(135deg, #2563eb, #1d4ed8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .user-info { text-align: right; color: var(--dark); font-size: 1.1rem; font-weight: 600; }
        .btn { padding: 12px 24px; border: none; border-radius: 12px; cursor: pointer; font-weight: 600; margin-left: 12px; font-size: 14px; }
        .btn-primary { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; }
        .btn-outline { background: transparent; color: var(--primary); border: 2px solid var(--primary); }
        .section { background: white; margin: 24px 0; padding: 32px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 1px solid var(--border); }
        .section h2 { color: var(--dark); margin-bottom: 20px; font-size: 1.5rem; font-weight: 700; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 32px; }
        .stat-card { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; padding: 28px; border-radius: 16px; text-align: center; }
        .stat-card.danger { background: linear-gradient(135deg, var(--danger), #b91c1c); }
        .stat-card.warning { background: linear-gradient(135deg, #d97706, #b45309); }
        .stat-number { font-size: 2.5rem; font-weight: 800; margin-bottom: 8px; }
        .table-container { overflow-x: auto; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; }
        th, td { padding: 16px 20px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; font-weight: 600; font-size: 14px; }
        tr:hover { background: #f8fafc; }
        .status-badge { padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; margin-right: 8px; }
        .status-open { background: #dcfce7; color: #166534; }
        .status-closed { background: #e0e7ff; color: #3730a3; }
        .status-in-progress { background: #fef3c7; color: #92400e; }
        .status-critical { background: #fecaca; color: #991b1b; }
        .status-high { background: #fed7aa; color: #9a3412; }
        .status-medium { background: #fef3c7; color: #92400e; }
        .status-low { background: #e0e7ff; color: #3730a3; }
        .tabs { display: flex; background: #f8fafc; border-radius: 15px; padding: 6px; margin-bottom: 28px; border: 1px solid var(--border); }
        .tab { flex: 1; padding: 14px; text-align: center; background: transparent; border: none; border-radius: 12px; cursor: pointer; font-weight: 600; color: var(--gray); font-size: 15px; }
        .tab.active { background: white; color: var(--primary); box-shadow: 0 4px 15px rgba(37,99,235,0.2); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .search-input { width: 100%; padding: 16px 20px; border: 2px solid var(--border); border-radius: 12px; font-size: 15px; margin-bottom: 20px; }
        .search-input:focus { outline: none; border-color: var(--primary); }
        .ticket-description { max-width: 300px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .action-btn { padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 12px; background: var(--primary); color: white; }
        .notification { position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 5px; color: white; z-index: 1000; display: none; }
        .notification.success { background: #28a745; }
        .notification.error { background: #dc3545; }
        .filter-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; border: 2px solid var(--border); background: white; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 12px; }
        .filter-btn.active { background: var(--primary); color: white; border-color: var(--primary); }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center; }
        .modal-content { background: white; border-radius: 16px; padding: 32px; max-width: 800px; width: 90%; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .close-modal { background: none; border: none; font-size: 24px; cursor: pointer; color: var(--gray); }
        .message-container { max-height: 400px; overflow-y: auto; border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 16px; background: #f8fafc; }
        .ticket-message { margin: 12px 0; padding: 12px 16px; border-radius: 12px; max-width: 80%; }
        .customer-message { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; margin-left: auto; border-bottom-right-radius: 6px; }
        .admin-message { background: white; color: var(--dark); margin-right: auto; border: 1px solid var(--border); border-bottom-left-radius: 6px; }
        .message-sender { font-size: 12px; font-weight: 600; margin-bottom: 4px; opacity: 0.8; }
        .message-content { font-size: 14px; }
        .message-time { font-size: 11px; text-align: right; margin-top: 4px; opacity: 0.6; }
        .btn-danger { background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; }
    </style>
</head>
<body>
    <div id="notification" class="notification"></div>
    <div class="container">
        <div class="header">
            <div class="logo"><h1>FexBank - Yönetici</h1></div>
            <div class="user-info">
                Hoş geldiniz, <strong>Yönetici</strong>!
                <button class="btn btn-outline" onclick="location.href='/logout'">Çıkış</button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number" id="totalUsers">0</div><div>Toplam Kullanıcı</div></div>
            <div class="stat-card"><div class="stat-number" id="totalTickets">0</div><div>Toplam Talep</div></div>
            <div class="stat-card danger"><div class="stat-number" id="criticalTickets">0</div><div>Kritik Talepler</div></div>
            <div class="stat-card warning"><div class="stat-number" id="openTickets">0</div><div>Açık Talepler</div></div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="showTab('open-tickets')">Talepler</button>
            <button class="tab" onclick="showTab('users')">Kullanıcılar</button>
        </div>

        <div id="open-tickets" class="tab-content active">
            <div class="section">
                <h2>Talepler</h2>
                <div class="filter-buttons">
                    <button class="filter-btn active" onclick="filterTickets('all')">Tümü</button>
                    <button class="filter-btn" onclick="filterTickets('open')">Açık</button>
                    <button class="filter-btn" onclick="filterTickets('in_progress')">İşlemde</button>
                    <button class="filter-btn" onclick="filterTickets('closed')">Kapalı</button>
                    <button class="filter-btn" onclick="filterTickets('critical')">Kritik</button>
                    <button class="filter-btn" onclick="filterTickets('high')">Yüksek</button>
                </div>
                <input type="text" id="openTicketSearch" class="search-input" placeholder="Talep ara" onkeyup="searchOpenTickets()">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th><th>Müşteri</th><th>Başlık</th><th>Tip</th>
                                <th>Açıklama</th><th>Öncelik</th><th>Durum</th><th>Oluşturma</th><th>İşlemler</th>
                            </tr>
                        </thead>
                        <tbody id="openTicketsTableBody"><tr><td colspan="9">Yükleniyor...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="users" class="tab-content">
            <div class="section">
                <h2>Tüm Kullanıcılar</h2>
                <input type="text" id="userSearch" class="search-input" placeholder="Kullanıcı ara" onkeyup="searchUsers()">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th><th>Ad Soyad</th><th>E-posta</th><th>Telefon</th>
                                <th>Kart</th><th>Kayıt Tarihi</th><th>Talep Sayısı</th>
                            </tr>
                        </thead>
                        <tbody id="usersTableBody"><tr><td colspan="7">Yükleniyor...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div id="ticketModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Talep Detayı</h2>
                <button class="close-modal" onclick="closeTicketModal()">&times;</button>
            </div>
            <div id="modalContent"></div>
        </div>
    </div>

    <script>
        let allTickets = [];
        let currentTicketId = null;

        function showNotification(message, type) {
            const n = document.getElementById('notification');
            n.textContent = message;
            n.className = `notification ${type}`;
            n.style.display = 'block';
            setTimeout(() => n.style.display = 'none', 3000);
        }

        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
            if (tabName === 'open-tickets') loadOpenTickets();
            else if (tabName === 'users') loadUsers();
        }

        async function loadAllData() {
            await loadStats();
            await loadOpenTickets();
            await loadUsers();
        }

        async function loadStats() {
            try {
                const response = await fetch('/api/v1/admin/stats');
                const data = await response.json();
                if (data.success) {
                    document.getElementById('totalUsers').textContent = data.data.total_users;
                    document.getElementById('totalTickets').textContent = data.data.total_tickets;
                    document.getElementById('criticalTickets').textContent = data.data.critical_tickets;
                    document.getElementById('openTickets').textContent = data.data.open_tickets;
                }
            } catch (e) { console.error(e); }
        }

        async function loadOpenTickets() {
            try {
                const response = await fetch('/api/v1/admin/tickets');
                const data = await response.json();
                if (data.success) {
                    allTickets = data.data.tickets || [];
                    renderTickets(allTickets);
                }
            } catch (e) {
                document.getElementById('openTicketsTableBody').innerHTML = '<tr><td colspan="9">Yükleme hatası</td></tr>';
            }
        }

        function renderTickets(tickets) {
            const html = tickets.map(t => {
                let sb = '', pb = '';
                if (t.status === 'open') sb = `<span class="status-badge status-open">Açık</span>`;
                else if (t.status === 'closed') sb = `<span class="status-badge status-closed">Kapalı</span>`;
                else if (t.status === 'in_progress') sb = `<span class="status-badge status-in-progress">İşlemde</span>`;
                if (t.priority === 'critical') pb = `<span class="status-badge status-critical">KRİTİK</span>`;
                else if (t.priority === 'high') pb = `<span class="status-badge status-high">YÜKSEK</span>`;
                else if (t.priority === 'medium') pb = `<span class="status-badge status-medium">ORTA</span>`;
                else pb = `<span class="status-badge status-low">DÜŞÜK</span>`;
                return `<tr>
                    <td>${t.id}</td>
                    <td>${t.customer_name || 'Bilinmiyor'}</td>
                    <td>${t.title}</td>
                    <td>${getIssueTypeText(t.issue_type)}</td>
                    <td class="ticket-description" title="${t.description}">${t.description.length > 50 ? t.description.substring(0, 50) + '...' : t.description}</td>
                    <td>${pb}</td>
                    <td>${sb}</td>
                    <td>${new Date(t.created_at).toLocaleString('tr-TR')}</td>
                    <td><button class="action-btn" onclick="viewTicketDetails(${t.id})">Yanıtla</button></td>
                </tr>`;
            }).join('');
            document.getElementById('openTicketsTableBody').innerHTML = html || '<tr><td colspan="9">Talep bulunamadı</td></tr>';
        }

        function filterTickets(filter) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            let filtered = allTickets;
            if (filter === 'open') filtered = allTickets.filter(t => t.status === 'open');
            else if (filter === 'in_progress') filtered = allTickets.filter(t => t.status === 'in_progress');
            else if (filter === 'closed') filtered = allTickets.filter(t => t.status === 'closed');
            else if (filter === 'critical') filtered = allTickets.filter(t => t.priority === 'critical');
            else if (filter === 'high') filtered = allTickets.filter(t => t.priority === 'high');
            renderTickets(filtered);
        }

        async function viewTicketDetails(ticketId) {
            currentTicketId = ticketId;
            try {
                const response = await fetch(`/api/v1/admin/tickets/${ticketId}/messages`);
                const data = await response.json();
                if (data.success) {
                    const t = data.data.ticket;
                    const messages = data.data.messages;
                    let mh = '';
                    messages.forEach(m => {
                        const cls = m.sender_type === 'customer' ? 'customer-message' : 'admin-message';
                        mh += `<div class="ticket-message ${cls}">
                            <div class="message-sender">${m.sender_name}</div>
                            <div class="message-content">${m.message}</div>
                            <div class="message-time">${new Date(m.created_at).toLocaleString('tr-TR')}</div>
                        </div>`;
                    });
                    const content = `
                        <div>
                            <h3>${t.title}</h3>
                            <p><strong>Müşteri:</strong> ${t.customer_name}</p>
                            <p><strong>Tip:</strong> ${getIssueTypeText(t.issue_type)}</p>
                            <p><strong>Durum:</strong> ${getStatusText(t.status)}</p>
                            <p><strong>Öncelik:</strong> ${getPriorityText(t.priority)}</p>
                            <p><strong>Açıklama:</strong> ${t.description}</p>
                            <div class="message-container">${mh || '<p>Henüz mesaj yok.</p>'}</div>
                            ${t.status !== 'closed' ? `
                            <div style="display:flex; gap:10px;">
                                <textarea id="replyMessage" placeholder="Müşteriye yanıt yazın..." rows="3" style="flex:1; padding:16px; border:2px solid var(--border); border-radius:12px;"></textarea>
                                <button class="btn btn-primary" onclick="sendAdminReply()">Gönder</button>
                            </div>
                            <div style="margin-top:12px;">
                                <button class="btn btn-danger" onclick="closeTicket(${ticketId})">🔒 Talebi Kapat</button>
                            </div>` : '<p style="color:#dc2626;">Bu talep kapatılmıştır.</p>'}
                        </div>`;
                    document.getElementById('modalTitle').textContent = `Talep #${ticketId} - ${t.title}`;
                    document.getElementById('modalContent').innerHTML = content;
                    document.getElementById('ticketModal').style.display = 'flex';
                    const mc = document.querySelector('.message-container');
                    if (mc) mc.scrollTop = mc.scrollHeight;
                }
            } catch (e) { console.error(e); }
        }

        function closeTicketModal() {
            document.getElementById('ticketModal').style.display = 'none';
            currentTicketId = null;
        }

        async function sendAdminReply() {
            const message = document.getElementById('replyMessage').value.trim();
            if (!currentTicketId || !message) { showNotification('Mesaj yazın', 'error'); return; }
            try {
                const response = await fetch(`/api/v1/admin/tickets/${currentTicketId}/messages`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message })
                });
                const data = await response.json();
                if (data.success) {
                    showNotification('Mesaj gönderildi', 'success');
                    document.getElementById('replyMessage').value = '';
                    viewTicketDetails(currentTicketId);
                } else {
                    showNotification('Hata: ' + data.message, 'error');
                }
            } catch (e) { showNotification('Mesaj gönderme hatası', 'error'); }
        }

        async function closeTicket(ticketId) {
            if (!confirm('Bu talebi kapatmak istediğinizden emin misiniz?')) return;
            try {
                const response = await fetch(`/api/v1/admin/tickets/${ticketId}/close`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ action: 'close' })
                });
                const data = await response.json();
                if (data.success) {
                    showNotification('Talep kapatıldı', 'success');
                    closeTicketModal();
                    loadOpenTickets();
                    loadStats();
                } else {
                    showNotification('Hata: ' + data.message, 'error');
                }
            } catch (e) {
                console.error('Kapatma hatası:', e);
                showNotification('Kapatma hatası: ' + e.message, 'error');
            }
        }

        async function loadUsers() {
            try {
                const response = await fetch('/api/v1/admin/users');
                const data = await response.json();
                if (data.success) {
                    const html = (data.data.users || []).map(u => `
                        <tr>
                            <td>${u.id}</td>
                            <td>${u.name}</td>
                            <td>${u.email}</td>
                            <td>${u.phone}</td>
                            <td>****${u.card_last_four || '####'}</td>
                            <td>${new Date(u.created_at).toLocaleString('tr-TR')}</td>
                            <td>${u.ticket_count || 0}</td>
                        </tr>`).join('');
                    document.getElementById('usersTableBody').innerHTML = html || '<tr><td colspan="7">Kullanıcı bulunamadı</td></tr>';
                }
            } catch (e) {
                document.getElementById('usersTableBody').innerHTML = '<tr><td colspan="7">Yükleme hatası</td></tr>';
            }
        }

        function searchOpenTickets() {
            const input = document.getElementById('openTicketSearch').value.toLowerCase();
            document.querySelectorAll('#openTicketsTableBody tr').forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(input) ? '' : 'none';
            });
        }

        function searchUsers() {
            const input = document.getElementById('userSearch').value.toLowerCase();
            document.querySelectorAll('#usersTableBody tr').forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(input) ? '' : 'none';
            });
        }

        function getIssueTypeText(type) {
            const t = { 'internet_banking': 'İnternet Bankacılığı', 'credit_card': 'Kredi Kartı', 'mobile_app': 'Mobil Uygulama', 'account': 'Hesaplar', 'loan': 'Krediler', 'other': 'Diğer', 'password_change': 'Şifre Değiştirme' };
            return t[type] || type;
        }
        function getStatusText(s) {
            const t = { 'open': 'Açık', 'closed': 'Kapalı', 'in_progress': 'İşlemde' };
            return t[s] || s;
        }
        function getPriorityText(p) {
            const t = { 'critical': 'Kritik', 'high': 'Yüksek', 'medium': 'Orta', 'low': 'Düşük' };
            return t[p] || p;
        }

        document.addEventListener('DOMContentLoaded', function() { loadAllData(); });
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(LOGIN_HTML, session=session)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, session=session)


@app.route('/admin')
@admin_required
def admin():
    return render_template_string(ADMIN_HTML, session=session)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/api/v1/auth/register', methods=['POST'])
@handle_errors
def register():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()
    card_number = data.get('card_number', '').strip().replace(' ', '')
    expiry_date = data.get('expiry_date', '').strip()
    cvv = data.get('cvv', '').strip()
    password = data.get('password', '')

    if not all([name, email, phone, card_number, expiry_date, cvv, password]):
        return api_response(False, None, "Tüm alanlar zorunludur", 400)
    if not validate_email(email):
        return api_response(False, None, "Geçersiz e-posta formatı", 400)
    if not validate_phone(phone):
        return api_response(False, None, "Geçersiz telefon formatı", 400)
    if not validate_card_number(card_number):
        return api_response(False, None, "Geçersiz kart numarası (16 hane olmalı)", 400)
    if not validate_expiry_date(expiry_date):
        return api_response(False, None, "Geçersiz son kullanma tarihi (AA/YY formatında olmalı)", 400)
    if not validate_cvv(cvv):
        return api_response(False, None, "Geçersiz CVV (3 hane olmalı)", 400)
    if len(password) < 8:
        return api_response(False, None, "Şifre en az 8 karakter içermelidir", 400)

    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor()
        cur.execute('SELECT id FROM customers WHERE email = %s', (email,))
        if cur.fetchone():
            return api_response(False, None, "Bu e-posta zaten kayıtlı", 409)

        cur.execute(
            'INSERT INTO customers (name, email, phone, card_number_encrypted, card_last_four, expiry_date_encrypted, password_hash) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id',
            (name, email, phone, encrypt_card(card_number), card_number[-4:], encrypt_card(expiry_date), hash_password(password))
        )
        user_id = cur.fetchone()[0]
        conn.commit()

        session.clear()
        session['customer_id'] = user_id
        session['customer_name'] = name
        session.permanent = True

        audit_log(user_id, 'REGISTER', f'Yeni kullanıcı kaydı: {email}', request.remote_addr)

        return api_response(True, {'user_id': user_id, 'name': name}, "Kayıt başarılı", 201)
    except Exception as e:
        conn.rollback()
        logger.error(f"Kayıt hatası: {e}")
        return api_response(False, None, "Kayıt sırasında hata oluştu", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/auth/login', methods=['POST'])
@handle_errors
def login():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    email = data.get('email', '').strip()
    card_number = data.get('card_number', '').strip().replace(' ', '')
    expiry_date = data.get('expiry_date', '').strip()
    cvv = data.get('cvv', '').strip()
    password = data.get('password', '')
    client_ip = request.remote_addr

    if check_login_attempts(client_ip, email):
        return api_response(False, None, "Çok fazla başarısız giriş denemesi. Lütfen daha sonra tekrar deneyin.", 429)

    if not all([email, card_number, expiry_date, cvv, password]):
        return api_response(False, None, "Tüm alanlar zorunludur", 400)

    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor()
        cur.execute(
            'SELECT id, name, password_hash, card_number_encrypted, expiry_date_encrypted FROM customers WHERE email = %s',
            (email,)
        )
        user = cur.fetchone()

        if not user:
            log_failed_login(client_ip, email)
            return api_response(False, None, "E-posta veya şifre hatalı", 401)

        user_id, name, password_hash, encrypted_card, encrypted_expiry = user

        if (not verify_password(password, password_hash) or
            card_number != decrypt_card(encrypted_card) or
            expiry_date != decrypt_card(encrypted_expiry)):
            log_failed_login(client_ip, email)
            return api_response(False, None, "Kimlik bilgileri hatalı", 401)

        session.clear()
        session['customer_id'] = user_id
        session['customer_name'] = name
        session.permanent = True

        audit_log(user_id, 'LOGIN', f'Başarılı giriş: {email}', client_ip)

        return api_response(True, {'user_id': user_id, 'name': name}, "Giriş başarılı", 200)
    except Exception as e:
        logger.error(f"Giriş hatası: {e}")
        return api_response(False, None, "Giriş sırasında hata oluştu", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/auth/admin-login', methods=['POST'])
@handle_errors
def admin_login():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    username = data.get('username', '').strip()
    password = data.get('password', '')

    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')

    if username != admin_username or password != admin_password:
        logger.warning(f"Başarısız yönetici girişi: {username} - IP: {request.remote_addr}")
        return api_response(False, None, "Geçersiz yönetici kullanıcı adı veya şifresi", 401)

    session.clear()
    session['admin_logged_in'] = True
    session['admin_username'] = username
    session.permanent = True

    logger.info(f"Yönetici girişi başarılı: {username} - IP: {request.remote_addr}")
    return api_response(True, {}, "Yönetici girişi başarılı", 200)


@app.route('/api/v1/chat', methods=['POST'])
@login_required
@handle_errors
def chat():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    question = data.get('question', '').strip()
    if not question:
        return api_response(False, None, "Soru boş olamaz", 400)

    customer_id = session.get('customer_id')
    response_data = generate_smart_response(question, session.get('customer_name', ''))

    conn = get_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute('INSERT INTO chat_history (customer_id, question, answer) VALUES (%s, %s, %s)',
                        (customer_id, question, response_data['answer']))
            conn.commit()
            cur.close()
        except Exception as e:
            logger.error(f"Sohbet geçmişi kaydetme hatası: {e}")
        finally:
            conn.close()

    return api_response(True, response_data, "Yanıt oluşturuldu", 200)


@app.route('/api/v1/transfer', methods=['POST'])
@login_required
@handle_errors
def transfer_money():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    recipient_card = data.get('recipient_card', '').strip().replace(' ', '')
    expiry_date = data.get('expiry_date', '').strip()
    cvv = data.get('cvv', '').strip()
    amount = data.get('amount', 0)
    transfer_type = data.get('transfer_type', '')

    if not all([recipient_card, expiry_date, cvv, amount, transfer_type]):
        return api_response(False, None, "Tüm alanlar zorunludur", 400)
    if not validate_card_number(recipient_card):
        return api_response(False, None, "Geçersiz alıcı kart numarası", 400)
    if not validate_expiry_date(expiry_date):
        return api_response(False, None, "Geçersiz son kullanma tarihi", 400)
    if not validate_cvv(cvv):
        return api_response(False, None, "Geçersiz CVV", 400)
    if amount <= 0:
        return api_response(False, None, "Geçersiz transfer tutarı", 400)
    if is_card_blocked(recipient_card):
        return api_response(False, None, "Bu kart bloke edilmiş ve transfer alamaz", 400)

    customer_id = session.get('customer_id')
    success, result = update_customer_balance(customer_id, -amount)
    if not success:
        return api_response(False, None, result, 400)

    if transfer_type == 'acil':
        message = f"{amount:,} RUB tutarındaki acil transfer {recipient_card[-4:]} numaralı hesaba 1 dakikadan kısa sürede gönderilecektir."
    else:
        message = f"{amount:,} RUB tutarındaki normal transfer {recipient_card[-4:]} numaralı hesaba 3-5 dakika içinde gönderilecektir."

    audit_log(customer_id, 'TRANSFER', f'{amount} RUB transfer -> {recipient_card[-4:]}', request.remote_addr)

    return api_response(True, {
        'new_balance': result,
        'transfer_amount': amount,
        'recipient_card': recipient_card[-4:],
        'transfer_type': transfer_type
    }, message, 200)


@app.route('/api/v1/change-password', methods=['POST'])
@login_required
@handle_errors
def change_password():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    new_password = data.get('new_password', '').strip()
    if not new_password:
        return api_response(False, None, "Yeni şifre boş olamaz", 400)
    if len(new_password) < 8:
        return api_response(False, None, "Şifre en az 8 karakter içermelidir", 400)

    customer_id = session.get('customer_id')
    success, message = update_customer_password(customer_id, new_password)
    if not success:
        return api_response(False, None, message, 400)

    audit_log(customer_id, 'PASSWORD_CHANGE', 'Şifre değiştirildi', request.remote_addr)
    return api_response(True, {}, "Şifre başarıyla değiştirildi", 200)


@app.route('/api/v1/update-card-limits', methods=['POST'])
@login_required
@handle_errors
def update_card_limits():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    dw = data.get('daily_withdrawal')
    ds = data.get('daily_shopping')
    doo = data.get('daily_online')
    mt = data.get('monthly_total')

    if not all([dw is not None, ds is not None, doo is not None, mt is not None]):
        return api_response(False, None, "Tüm limit alanları zorunludur", 400)
    if dw < 0 or ds < 0 or doo < 0 or mt < 0:
        return api_response(False, None, "Limit değerleri negatif olamaz", 400)

    customer_id = session.get('customer_id')
    new_limits = {'daily_withdrawal': dw, 'daily_shopping': ds, 'daily_online': doo, 'monthly_total': mt}
    success, message = update_customer_card_limits(customer_id, new_limits)
    if not success:
        return api_response(False, None, message, 400)

    audit_log(customer_id, 'LIMIT_CHANGE', str(new_limits), request.remote_addr)
    return api_response(True, {'new_limits': new_limits}, "Kart limitleri güncellendi. Değişiklikler 1-2 iş günü içinde yürürlüğe girer.", 200)


@app.route('/api/v1/block-card', methods=['POST'])
@login_required
@handle_errors
def block_card_route():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    card_number = data.get('card_number', '').strip().replace(' ', '')
    if not card_number:
        return api_response(False, None, "Kart numarası zorunludur", 400)
    if not validate_card_number(card_number):
        return api_response(False, None, "Geçersiz kart numarası", 400)

    success, message = block_card_func(card_number)
    if not success:
        return api_response(False, None, message, 400)

    audit_log(session.get('customer_id'), 'CARD_BLOCK', f'Kart bloke: {card_number[-4:]}', request.remote_addr)
    return api_response(True, {}, message, 200)


@app.route('/api/v1/order-card', methods=['POST'])
@login_required
@handle_errors
def order_card_route():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    address = data.get('address', '').strip()
    if not address:
        return api_response(False, None, "Adres zorunludur", 400)

    success, message = order_new_card(address)
    if not success:
        return api_response(False, None, message, 400)

    audit_log(session.get('customer_id'), 'CARD_ORDER', f'Adres: {address[:50]}', request.remote_addr)
    return api_response(True, {}, message, 200)


@app.route('/api/v1/block-access', methods=['POST'])
@login_required
@handle_errors
def block_access_route():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    username = data.get('username', '').strip()
    if not username:
        return api_response(False, None, "Kullanıcı adı zorunludur", 400)
    if username != session.get('customer_name'):
        return api_response(False, None, "Geçersiz kullanıcı adı", 400)

    success, message = block_user_access(username)
    if not success:
        return api_response(False, None, message, 400)

    audit_log(session.get('customer_id'), 'ACCESS_BLOCK', f'Kullanıcı erişimi engellendi: {username}', request.remote_addr)
    return api_response(True, {}, message, 200)


@app.route('/api/v1/tickets', methods=['POST'])
@login_required
@handle_errors
def create_ticket():
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    title = data.get('title', '').strip()
    issue_type = data.get('issue_type', '').strip()
    description = data.get('description', '').strip()

    if not all([title, issue_type, description]):
        return api_response(False, None, "Tüm alanlar zorunludur", 400)

    customer_id = session.get('customer_id')
    customer_name = session.get('customer_name', '')
    priority, priority_score = analyze_ticket_priority(title, description, issue_type)

    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO tickets (customer_id, customer_name, title, issue_type, description, priority, priority_score) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id',
            (customer_id, customer_name, title, issue_type, description, priority, priority_score)
        )
        ticket_id = cur.fetchone()[0]

        cur.execute(
            'INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message) VALUES (%s, %s, %s, %s)',
            (ticket_id, 'customer', customer_name, description)
        )

        conn.commit()
        audit_log(customer_id, 'TICKET_CREATE', f'Talep #{ticket_id} oluşturuldu', request.remote_addr)
        return api_response(True, {'ticket_id': ticket_id}, "Talep başarıyla oluşturuldu", 201)
    except Exception as e:
        conn.rollback()
        logger.error(f"Talep oluşturma hatası: {e}")
        return api_response(False, None, "Talep oluşturma hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/my-tickets', methods=['GET'])
@login_required
@handle_errors
def get_my_tickets():
    customer_id = session.get('customer_id')
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id, title, issue_type, description, status, priority, created_at FROM tickets WHERE customer_id = %s ORDER BY created_at DESC',
                    (customer_id,))
        tickets = cur.fetchall()
        return api_response(True, {'tickets': tickets}, "Talepler başarıyla alındı", 200)
    except Exception as e:
        logger.error(f"Talep alma hatası: {e}")
        return api_response(False, None, "Talep alma hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/tickets/<int:ticket_id>/messages', methods=['GET'])
@login_required
@handle_errors
def get_ticket_messages(ticket_id):
    customer_id = session.get('customer_id')
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM tickets WHERE id = %s AND customer_id = %s', (ticket_id, customer_id))
        ticket = cur.fetchone()
        if not ticket:
            return api_response(False, None, "Talep bulunamadı veya erişim yetkiniz yok", 404)

        cur.execute('SELECT * FROM ticket_messages WHERE ticket_id = %s ORDER BY created_at ASC', (ticket_id,))
        messages = cur.fetchall()
        return api_response(True, {'ticket': ticket, 'messages': messages}, "Mesajlar başarıyla alındı", 200)
    except Exception as e:
        logger.error(f"Mesaj alma hatası: {e}")
        return api_response(False, None, "Mesaj alma hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/tickets/<int:ticket_id>/messages', methods=['POST'])
@login_required
@handle_errors
def send_ticket_message(ticket_id):
    data = request.get_json()
    if not data:
        return api_response(False, None, "Geçersiz veri formatı", 400)

    message = data.get('message', '').strip()
    if not message:
        return api_response(False, None, "Mesaj boş olamaz", 400)

    customer_id = session.get('customer_id')
    customer_name = session.get('customer_name', '')

    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM tickets WHERE id = %s AND customer_id = %s AND status != %s',
                    (ticket_id, customer_id, 'closed'))
        ticket = cur.fetchone()
        if not ticket:
            return api_response(False, None, "Talep bulunamadı veya kapatılmış", 404)

        cur.execute('INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message) VALUES (%s, %s, %s, %s)',
                    (ticket_id, 'customer', customer_name, message))
        cur.execute('UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = %s', (ticket_id,))
        conn.commit()

        return api_response(True, {}, "Mesaj başarıyla gönderildi", 201)
    except Exception as e:
        conn.rollback()
        logger.error(f"Mesaj gönderme hatası: {e}")
        return api_response(False, None, "Mesaj gönderme hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/stats', methods=['GET'])
@admin_required
@handle_errors
def admin_stats():
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT COUNT(*) as count FROM customers')
        total_users = cur.fetchone()['count']
        cur.execute('SELECT COUNT(*) as count FROM tickets')
        total_tickets = cur.fetchone()['count']
        cur.execute('SELECT COUNT(*) as count FROM tickets WHERE priority = %s AND status IN (%s, %s)',
                    ('critical', 'open', 'in_progress'))
        critical_tickets = cur.fetchone()['count']
        cur.execute('SELECT COUNT(*) as count FROM tickets WHERE status IN (%s, %s)', ('open', 'in_progress'))
        open_tickets = cur.fetchone()['count']

        return api_response(True, {
            'total_users': total_users,
            'total_tickets': total_tickets,
            'critical_tickets': critical_tickets,
            'open_tickets': open_tickets
        }, "İstatistikler başarıyla alındı", 200)
    except Exception as e:
        logger.error(f"İstatistik hatası: {e}")
        return api_response(False, None, "İstatistik hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/tickets', methods=['GET'])
@admin_required
@handle_errors
def admin_tickets():
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('''
            SELECT t.*, c.name as customer_name
            FROM tickets t
            LEFT JOIN customers c ON t.customer_id = c.id
            ORDER BY t.priority_score DESC, t.created_at DESC
        ''')
        tickets = cur.fetchall()
        return api_response(True, {'tickets': tickets}, "Talepler başarıyla alındı", 200)
    except Exception as e:
        logger.error(f"Admin talep hatası: {e}")
        return api_response(False, None, "Talep alma hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/tickets/<int:ticket_id>/messages', methods=['GET'])
@admin_required
@handle_errors
def admin_get_ticket_messages(ticket_id):
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('''
            SELECT t.*, c.name as customer_name
            FROM tickets t
            LEFT JOIN customers c ON t.customer_id = c.id
            WHERE t.id = %s
        ''', (ticket_id,))
        ticket = cur.fetchone()
        if not ticket:
            return api_response(False, None, "Talep bulunamadı", 404)

        cur.execute('SELECT * FROM ticket_messages WHERE ticket_id = %s ORDER BY created_at ASC', (ticket_id,))
        messages = cur.fetchall()
        return api_response(True, {'ticket': ticket, 'messages': messages}, "Mesajlar başarıyla alındı", 200)
    except Exception as e:
        logger.error(f"Admin mesaj alma hatası: {e}")
        return api_response(False, None, "Mesaj alma hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/tickets/<int:ticket_id>/messages', methods=['POST'])
@admin_required
@handle_errors
def admin_send_ticket_message(ticket_id):
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    if not message:
        return api_response(False, None, "Mesaj boş olamaz", 400)

    admin_name = session.get('admin_username', 'Yönetici')

    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM tickets WHERE id = %s AND status != %s', (ticket_id, 'closed'))
        ticket = cur.fetchone()
        if not ticket:
            return api_response(False, None, "Talep bulunamadı veya kapatılmış", 404)

        cur.execute('INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message) VALUES (%s, %s, %s, %s)',
                    (ticket_id, 'admin', admin_name, message))
        cur.execute('UPDATE tickets SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s',
                    ('in_progress', ticket_id))
        conn.commit()
        return api_response(True, {}, "Mesaj başarıyla gönderildi", 201)
    except Exception as e:
        conn.rollback()
        logger.error(f"Admin mesaj gönderme hatası: {e}")
        return api_response(False, None, "Mesaj gönderme hatası", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/tickets/<int:ticket_id>/close', methods=['POST'])
@admin_required
@handle_errors
def admin_close_ticket(ticket_id):
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id, status FROM tickets WHERE id = %s', (ticket_id,))
        ticket = cur.fetchone()
        if not ticket:
            return api_response(False, None, "Talep bulunamadı", 404)

        cur.execute('UPDATE tickets SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s',
                    ('closed', ticket_id))
        cur.execute('INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message) VALUES (%s, %s, %s, %s)',
                    (ticket_id, 'admin', 'Sistem', 'Talep yönetici tarafından kapatıldı.'))
        conn.commit()
        logger.info(f"Talep #{ticket_id} kapatıldı")
        return api_response(True, {'ticket_id': ticket_id}, "Talep başarıyla kapatıldı", 200)
    except Exception as e:
        conn.rollback()
        logger.error(f"Talep kapatma hatası: {e}")
        return api_response(False, None, f"Hata: {str(e)}", 500)
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/admin/users', methods=['GET'])
@admin_required
@handle_errors
def admin_users():
    conn = get_db_connection()
    if not conn:
        return api_response(False, None, "Veritabanı hatası", 500)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('''
            SELECT c.id, c.name, c.email, c.phone, c.card_last_four, c.created_at,
                   COUNT(t.id) as ticket_count
            FROM customers c
            LEFT JOIN tickets t ON c.id = t.customer_id
            GROUP BY c.id, c.name, c.email, c.phone, c.card_last_four, c.created_at
            ORDER BY c.created_at DESC
        ''')
        users = cur.fetchall()
        return api_response(True, {'users': users}, "Kullanıcılar başarıyla alındı", 200)
    except Exception as e:
        logger.error(f"Kullanıcı alma hatası: {e}")
        return api_response(False, None, "Kullanıcı alma hatası", 500)
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    init_db()
    logger.info("FexBank sunucusu başlatılıyor: http://0.0.0.0:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
