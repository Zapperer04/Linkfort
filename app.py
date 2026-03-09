from flask import Flask, request, jsonify, redirect, render_template_string, current_app
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_bcrypt import Bcrypt
from config import Config
from models import db, URL, Click, User
from utils import generate_short_code, generate_random_code
from cache import init_redis, get_cached_url, set_cached_url, check_rate_limit
from threat_detection import init_threat_detection, calculate_threat_score
from urllib.parse import urlparse
import validators
import traceback
from datetime import datetime, timedelta
import re
import os

app = Flask(__name__)
app.config.from_object(Config)

# ✅ FIX: JWT Configuration must be set before JWTManager(app)
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-linkfort-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Enable CORS - ✅ FIX: Allow Authorization headers
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Initialize database
db.init_app(app)

# Initialize everything
with app.app_context():
    db.create_all()
    print("✅ Database tables created!")
    init_redis()
    init_threat_detection()

# ==================== HELPER FUNCTIONS ====================

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

# ==================== PAGE TEMPLATES ====================

WARNING_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>⚠️ Security Warning - LinkFort</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; padding: 20px;
        }
        .warning-box {
            background: white; border-radius: 16px; padding: 40px;
            max-width: 600px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .warning-icon { font-size: 64px; text-align: center; margin-bottom: 20px; }
        h1 { color: #e74c3c; text-align: center; margin-bottom: 10px; }
        .threat-score { text-align: center; font-size: 18px; color: #666; margin-bottom: 30px; }
        .url-display {
            background: #f8f9fa; padding: 15px; border-radius: 8px;
            word-break: break-all; margin: 20px 0; font-family: monospace;
            border-left: 4px solid #e74c3c;
        }
        .reasons {
            background: #fff3cd; border-left: 4px solid #ffc107;
            padding: 15px; margin: 20px 0; border-radius: 4px;
        }
        .reasons h3 { margin-top: 0; color: #856404; }
        .reasons ul { margin: 10px 0; padding-left: 20px; }
        .reasons li { color: #856404; margin: 5px 0; }
        .button-group { display: flex; gap: 10px; margin-top: 30px; }
        .btn {
            flex: 1; padding: 15px 30px; border: none; border-radius: 8px;
            font-size: 16px; font-weight: 600; cursor: pointer;
            text-decoration: none; text-align: center; transition: transform 0.2s;
        }
        .btn:hover { transform: translateY(-2px); }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-secondary { background: #95a5a6; color: white; }
        .footer { text-align: center; margin-top: 20px; color: #7f8c8d; font-size: 14px; }
    </style>
</head>
<body>
    <div class="warning-box">
        <div class="warning-icon">⚠️</div>
        <h1>Suspicious Link Detected</h1>
        <div class="threat-score">Threat Score: <strong style="color: #e74c3c;">{{ score }}/1.00</strong></div>
        <p style="text-align: center; color: #555;">This link has been flagged as potentially dangerous. Proceed with extreme caution.</p>
        <div class="url-display">{{ url }}</div>
        {% if reasons %}
        <div class="reasons">
            <h3>🚨 Why was this flagged?</h3>
            <ul>{% for reason in reasons %}<li>{{ reason }}</li>{% endfor %}</ul>
        </div>
        {% endif %}
        <div class="button-group">
            <a href="javascript:history.back()" class="btn btn-secondary">← Go Back (Safe)</a>
            <a href="{{ url }}" class="btn btn-danger">Proceed Anyway (Risky)</a>
        </div>
        <div class="footer">🛡️ Protected by <strong>LinkFort</strong> Threat Detection</div>
    </div>
</body>
</html>
"""

EXPIRED_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Link Expired - LinkFort</title></head>
<body style="font-family: Arial; text-align: center; padding: 100px;
     background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
     min-height: 100vh; margin: 0;">
    <div style="background: white; border-radius: 16px; padding: 40px;
          max-width: 500px; margin: 0 auto;
          box-shadow: 0 20px 60px rgba(0,0,0,0.3);">
        <div style="font-size: 64px; margin-bottom: 20px;">⏰</div>
        <h1 style="color: #e74c3c; margin-bottom: 10px;">Link Expired</h1>
        <p style="color: #555; font-size: 16px;">This short link has expired and is no longer available.</p>
        <p style="color: #7f8c8d; font-size: 14px; margin-top: 20px;">Expired on: {{ expired_at }}</p>
    </div>
</body>
</html>
"""

DISABLED_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Link Disabled - LinkFort</title></head>
<body style="font-family: Arial; text-align: center; padding: 100px;
     background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
     min-height: 100vh; margin: 0;">
    <div style="background: white; border-radius: 16px; padding: 40px;
          max-width: 500px; margin: 0 auto;
          box-shadow: 0 20px 60px rgba(0,0,0,0.3);">
        <div style="font-size: 64px; margin-bottom: 20px;">🚫</div>
        <h1 style="color: #636e72; margin-bottom: 10px;">Link Disabled</h1>
        <p style="color: #555; font-size: 16px;">This short link has been disabled by its owner and is no longer active.</p>
        <div style="margin-top: 30px;">
            <a href="/" style="background: #667eea; color: white; padding: 12px 28px;
               border-radius: 8px; text-decoration: none; font-weight: 600;">Create Your Own Link →</a>
        </div>
    </div>
</body>
</html>
"""

# ==================== JWT ERROR HANDLERS ====================

@jwt.unauthorized_loader
def unauthorized_callback(error):
    return jsonify({'error': 'Missing or invalid token', 'message': str(error)}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token', 'message': str(error)}), 422

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

# ==================== AUTH ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    if not data: return jsonify({'error': 'No data provided'}), 400

    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400
    if len(username) < 3: return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6: return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if '@' not in email: return jsonify({'error': 'Invalid email address'}), 400
    if User.query.filter_by(username=username).first(): return jsonify({'error': 'Username already taken'}), 400
    if User.query.filter_by(email=email).first(): return jsonify({'error': 'Email already registered'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=str(new_user.id))
    print(f"✅ New user registered: {username}")
    return jsonify({'message': 'Account created successfully!', 'access_token': access_token, 'user': new_user.to_dict()}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user"""
    data = request.get_json()
    if not data: return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not email or not password: return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid email or password'}), 401
    if not user.is_active: return jsonify({'error': 'Account is disabled'}), 401

    access_token = create_access_token(identity=str(user.id))
    print(f"✅ User logged in: {user.username}")
    return jsonify({'message': f'Welcome back, {user.username}!', 'access_token': access_token, 'user': user.to_dict()}), 200


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current logged in user"""
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user: return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': user.to_dict()}), 200


@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user"""
    return jsonify({'message': 'Logged out successfully'}), 200


# ==================== GENERAL ROUTES ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'LinkFort API is running'})


@app.route('/api/check-code/<code>', methods=['GET'])
def check_code_availability(code):
    """Check if a custom code is available"""
    if len(code) < 3: return jsonify({'available': False, 'reason': 'Too short'}), 200
    if len(code) > 20: return jsonify({'available': False, 'reason': 'Too long'}), 200
    if not re.match(r'^[a-zA-Z0-9_-]+$', code): return jsonify({'available': False, 'reason': 'Invalid chars'}), 200

    reserved = ['api', 'admin', 'dashboard', 'analytics', 'health', 'stats', 'app', 'www']
    if code.lower() in reserved: return jsonify({'available': False, 'reason': 'Reserved word'}), 200
    existing = URL.query.filter_by(short_code=code).first()
    if existing: return jsonify({'available': False, 'reason': 'Already taken'}), 200
    return jsonify({'available': True, 'reason': 'Available!'}), 200


@app.route('/api/shorten', methods=['POST'])
def shorten_url():
    """Shorten a URL with threat detection, custom code, and expiration"""
    client_ip = get_client_ip()
    allowed, remaining = check_rate_limit(client_ip, max_requests=10, window=60)
    if not allowed: return jsonify({'error': 'Rate limit exceeded.'}), 429

    current_user_id = None
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        try:
            token = auth_header.split(' ')[1]
            decoded = decode_token(token)
            current_user_id = int(decoded['sub'])
        except: pass

    data = request.get_json()
    if not data or 'url' not in data: return jsonify({'error': 'URL is required'}), 400

    original_url = data['url'].strip()
    custom_code = data.get('custom_code', '').strip()
    expiration_days = data.get('expiration_days', None)

    if not validators.url(original_url): return jsonify({'error': 'Invalid URL format'}), 400

    if custom_code:
        if len(custom_code) < 3 or len(custom_code) > 20: return jsonify({'error': 'Invalid custom code length'}), 400
        if not re.match(r'^[a-zA-Z0-9_-]+$', custom_code): return jsonify({'error': 'Invalid chars in custom code'}), 400
        reserved = ['api', 'admin', 'dashboard', 'analytics', 'health', 'stats', 'app', 'www']
        if custom_code.lower() in reserved: return jsonify({'error': 'Reserved word'}), 400
        if URL.query.filter_by(short_code=custom_code).first(): return jsonify({'error': 'Custom code taken'}), 400

    expires_at = None
    if expiration_days:
        try:
            days = int(expiration_days)
            if days < 1 or days > 365: return jsonify({'error': 'Exp must be 1-365 days'}), 400
            expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError: return jsonify({'error': 'Invalid expiration days'}), 400

    threat_score, verdict, details = calculate_threat_score(original_url)

    existing = URL.query.filter_by(original_url=original_url).first()
    if existing:
        existing.threat_score, existing.threat_verdict, existing.threat_details = threat_score, verdict, details
        existing.expires_at = expires_at
        if current_user_id: existing.user_id = current_user_id
        db.session.commit()
        if verdict == 'BLOCK': return jsonify({'error': 'URL blocked', 'threat_score': threat_score}), 403
        set_cached_url(existing.short_code, {'original_url': existing.original_url, 'id': existing.id, 'threat_verdict': existing.threat_verdict})
        return jsonify({'message': 'URL already shortened', 'data': existing.to_dict(), 'rate_limit_remaining': remaining}), 200

    new_url = URL(original_url=original_url, short_code='temp', threat_score=threat_score, threat_verdict=verdict, threat_details=details, expires_at=expires_at, user_id=current_user_id)
    db.session.add(new_url)
    db.session.flush()

    short_code = custom_code if custom_code else generate_short_code(new_url.id)
    while not custom_code and URL.query.filter_by(short_code=short_code).first(): short_code = generate_random_code()
    
    new_url.short_code = short_code
    db.session.commit()

    if verdict == 'BLOCK': return jsonify({'error': 'URL blocked', 'threat_score': threat_score}), 403
    set_cached_url(new_url.short_code, {'original_url': new_url.original_url, 'id': new_url.id, 'threat_verdict': new_url.threat_verdict})
    return jsonify({'message': 'URL shortened', 'data': new_url.to_dict(), 'rate_limit_remaining': remaining}), 201


@app.route('/<short_code>', methods=['GET'])
def redirect_url(short_code):
    """Redirect with threat protection, click tracking, expiration and active check"""
    cached = get_cached_url(short_code)
    if cached:
        print(f"✅ Cache HIT for {short_code}")
        url = URL.query.get(cached['id'])
        if not url: return jsonify({'error': 'Short URL not found'}), 404

        # ✅ NEW: Check if disabled
        if not url.is_active: return render_template_string(DISABLED_PAGE), 410

        if url.is_url_expired():
            return render_template_string(EXPIRED_PAGE, expired_at=url.expires_at.strftime('%B %d, %Y at %H:%M UTC'))

        if cached.get('threat_verdict') == 'WARN':
            return render_template_string(WARNING_PAGE, url=url.original_url, score=f"{url.threat_score:.2f}", reasons=url.threat_details.get('all_reasons', []))

        url.click_count += 1
        db.session.add(Click(url_id=url.id, ip_address=get_client_ip()))
        db.session.commit()
        return redirect(cached['original_url'], code=302)

    print(f"⚠️  Cache MISS for {short_code}")
    url = URL.query.filter_by(short_code=short_code).first()
    if not url: return jsonify({'error': 'Short URL not found'}), 404

    # ✅ NEW: Check if disabled
    if not url.is_active: return render_template_string(DISABLED_PAGE), 410

    if url.is_url_expired():
        return render_template_string(EXPIRED_PAGE, expired_at=url.expires_at.strftime('%B %d, %Y at %H:%M UTC'))

    if url.threat_verdict == 'WARN':
        return render_template_string(WARNING_PAGE, url=url.original_url, score=f"{url.threat_score:.2f}", reasons=url.threat_details.get('all_reasons', []))

    set_cached_url(short_code, {'original_url': url.original_url, 'id': url.id, 'threat_verdict': url.threat_verdict})
    url.click_count += 1
    db.session.add(Click(url_id=url.id, ip_address=get_client_ip()))
    db.session.commit()
    return redirect(url.original_url, code=302)


@app.route('/api/stats/<short_code>', methods=['GET'])
def get_stats(short_code):
    url = URL.query.filter_by(short_code=short_code).first()
    if not url: return jsonify({'error': 'Short URL not found'}), 404
    return jsonify({'data': url.to_dict()}), 200


@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get dashboard statistics for logged in user"""
    try:
        user_id = int(get_jwt_identity())
        now = datetime.utcnow()
        base_query = URL.query.filter_by(user_id=user_id)

        total_urls = base_query.count()
        total_clicks = db.session.query(db.func.sum(URL.click_count)).filter(URL.user_id == user_id).scalar() or 0
        threats_blocked = base_query.filter_by(threat_verdict='BLOCK').count()
        active_urls = base_query.filter(URL.threat_verdict.in_(['SAFE', 'WARN']), db.or_(URL.expires_at.is_(None), URL.expires_at > now)).count()
        expired_urls = base_query.filter(URL.expires_at.isnot(None), URL.expires_at <= now).count()

        recent_threats = base_query.filter_by(threat_verdict='BLOCK').order_by(URL.created_at.desc()).limit(20).all()
        threats_data = [{'id': url.id, 'url': url.original_url, 'score': url.threat_score, 'time': url.created_at.isoformat(), 'reasons': url.threat_details.get('all_reasons', []) if url.threat_details else []} for url in recent_threats]

        active_url_list = base_query.filter(URL.threat_verdict.in_(['SAFE', 'WARN']), db.or_(URL.expires_at.is_(None), URL.expires_at > now)).order_by(URL.created_at.desc()).limit(20).all()
        base_url = current_app.config.get('BASE_URL', 'http://localhost:5000')
        active_data = [{'id': url.id, 'original_url': url.original_url, 'short_url': f"{base_url}/{url.short_code}", 'short_code': url.short_code, 'verdict': url.threat_verdict, 'score': url.threat_score, 'clicks': url.click_count, 'created_at': url.created_at.isoformat(), 'expires_at': url.expires_at.isoformat() if url.expires_at else None} for url in active_url_list]

        expired_url_list = base_query.filter(URL.expires_at.isnot(None), URL.expires_at <= now).order_by(URL.expires_at.desc()).limit(20).all()
        expired_data = [{'id': url.id, 'original_url': url.original_url, 'short_url': f"{base_url}/{url.short_code}", 'short_code': url.short_code, 'verdict': url.threat_verdict, 'score': url.threat_score, 'clicks': url.click_count, 'created_at': url.created_at.isoformat(), 'expires_at': url.expires_at.isoformat() if url.expires_at else None} for url in expired_url_list]

        return jsonify({'stats': {'total_urls': total_urls, 'total_clicks': int(total_clicks), 'threats_blocked': threats_blocked, 'active_urls': active_urls, 'expired_urls': expired_urls}, 'recent_threats': threats_data, 'active_urls': active_data, 'expired_urls': expired_data}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    """Get analytics data - filtered by logged in user"""
    try:
        from sqlalchemy import func
        user_id = int(get_jwt_identity())
        threat_trends = []
        for i in range(6, -1, -1):
            date = datetime.now() - timedelta(days=i)
            safe = URL.query.filter(URL.user_id == user_id, URL.threat_verdict == 'SAFE', func.date(URL.created_at) == date.date()).count()
            warn = URL.query.filter(URL.user_id == user_id, URL.threat_verdict == 'WARN', func.date(URL.created_at) == date.date()).count()
            blocked = URL.query.filter(URL.user_id == user_id, URL.threat_verdict == 'BLOCK', func.date(URL.created_at) == date.date()).count()
            threat_trends.append({'date': date.strftime('%b %d'), 'safe': safe, 'warn': warn, 'blocked': blocked})

        score_ranges = [{'range': '0.0-0.2', 'count': 0}, {'range': '0.2-0.4', 'count': 0}, {'range': '0.4-0.6', 'count': 0}, {'range': '0.6-0.8', 'count': 0}, {'range': '0.8-1.0', 'count': 0}]
        user_urls = URL.query.filter_by(user_id=user_id).all()
        for url in user_urls:
            s = url.threat_score
            if s < 0.2: score_ranges[0]['count'] += 1
            elif s < 0.4: score_ranges[1]['count'] += 1
            elif s < 0.6: score_ranges[2]['count'] += 1
            elif s < 0.8: score_ranges[3]['count'] += 1
            else: score_ranges[4]['count'] += 1

        layer_perf = [{'name': 'Layer 1', 'value': 0}, {'name': 'Layer 2', 'value': 0}, {'name': 'Layer 3', 'value': 0}]
        for url in user_urls:
            if url.threat_details:
                layers = url.threat_details.get('layers', {})
                if layers.get('layer1', {}).get('score', 0) >= 0.5: layer_perf[0]['value'] += 1
                if layers.get('layer2', {}).get('score', 0) >= 0.5: layer_perf[1]['value'] += 1
                if layers.get('layer3', {}).get('score', 0) >= 0.5: layer_perf[2]['value'] += 1

        domain_stats = {}
        for url in [u for u in user_urls if u.threat_verdict == 'BLOCK']:
            try:
                domain = urlparse(url.original_url).netloc
                if domain not in domain_stats: domain_stats[domain] = {'domain': domain, 'count': 0, 'scores': [], 'reasons': []}
                domain_stats[domain]['count'] += 1
                domain_stats[domain]['scores'].append(url.threat_score)
                if url.threat_details and url.threat_details.get('all_reasons'): domain_stats[domain]['reasons'].append(url.threat_details['all_reasons'][0])
            except: continue

        top_blocked = []
        for domain, stats in sorted(domain_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
            top_blocked.append({'domain': domain, 'count': stats['count'], 'avgScore': sum(stats['scores'])/len(stats['scores']), 'topReason': stats['reasons'][0] if stats['reasons'] else 'Unknown'})

        click_stats = []
        now = datetime.now()
        for i in range(11, -1, -1):
            h_start = now - timedelta(hours=i)
            cnt = Click.query.join(URL).filter(URL.user_id == user_id, Click.clicked_at >= h_start, Click.clicked_at < (h_start + timedelta(hours=1))).count()
            click_stats.append({'hour': h_start.strftime('%H:%M'), 'clicks': cnt})

        return jsonify({'threatTrends': threat_trends, 'scoreDistribution': score_ranges, 'topBlockedDomains': top_blocked, 'layerPerformance': layer_perf, 'clickStats': click_stats}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ==================== URL MANAGEMENT ROUTES ====================

@app.route('/api/urls/<short_code>', methods=['GET'])
@jwt_required()
def get_url_detail(short_code):
    """Get full detail for a single URL (owner only)"""
    user_id = int(get_jwt_identity())
    url = URL.query.filter_by(short_code=short_code).first()
    if not url: return jsonify({'error': 'URL not found'}), 404
    if url.user_id != user_id: return jsonify({'error': 'Access denied'}), 403

    recent_clicks = Click.query.filter_by(url_id=url.id).order_by(Click.clicked_at.desc()).limit(20).all()
    clicks_data = [{'id': c.id, 'clicked_at': c.clicked_at.isoformat(), 'ip_address': c.ip_address} for c in recent_clicks]

    from sqlalchemy import func
    click_trend = []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        count = Click.query.filter(Click.url_id == url.id, func.date(Click.clicked_at) == day.date()).count()
        click_trend.append({'date': day.strftime('%b %d'), 'clicks': count})

    return jsonify({'data': url.to_dict(), 'recent_clicks': clicks_data, 'click_trend': click_trend}), 200


@app.route('/api/urls/<short_code>', methods=['PATCH'])
@jwt_required()
def edit_url(short_code):
    """Edit a URL's expiration date (owner only)"""
    user_id = int(get_jwt_identity())
    url = URL.query.filter_by(short_code=short_code).first()
    if not url: return jsonify({'error': 'URL not found'}), 404
    if url.user_id != user_id: return jsonify({'error': 'Access denied'}), 403

    data = request.get_json()
    if not data: return jsonify({'error': 'No data provided'}), 400

    if 'expiration_days' in data:
        exp = data['expiration_days']
        if exp is None: url.expires_at = None
        else:
            try:
                days = int(exp)
                if days < 1 or days > 365: return jsonify({'error': '1-365 days range required'}), 400
                url.expires_at = datetime.utcnow() + timedelta(days=days)
            except: return jsonify({'error': 'Invalid expiration value'}), 400

    db.session.commit()
    try:
        from cache import redis_client
        redis_client.delete(f"url:{short_code}")
    except: pass
    return jsonify({'message': 'URL updated successfully', 'data': url.to_dict()}), 200


@app.route('/api/urls/<short_code>/toggle', methods=['PATCH'])
@jwt_required()
def toggle_url(short_code):
    """Enable or disable a URL (owner only)"""
    user_id = int(get_jwt_identity())
    url = URL.query.filter_by(short_code=short_code).first()
    if not url: return jsonify({'error': 'URL not found'}), 404
    if url.user_id != user_id: return jsonify({'error': 'Access denied'}), 403

    data = request.get_json() or {}
    url.is_active = data.get('is_active', not url.is_active)
    db.session.commit()
    try:
        from cache import redis_client
        redis_client.delete(f"url:{short_code}")
    except: pass
    return jsonify({'message': f"URL {'enabled' if url.is_active else 'disabled'} successfully", 'data': url.to_dict()}), 200


@app.route('/api/urls/<short_code>', methods=['DELETE'])
@jwt_required()
def delete_url(short_code):
    """Permanently delete a URL (owner only)"""
    user_id = int(get_jwt_identity())
    url = URL.query.filter_by(short_code=short_code).first()
    if not url: return jsonify({'error': 'URL not found'}), 404
    if url.user_id != user_id: return jsonify({'error': 'Access denied'}), 403

    try:
        from cache import redis_client
        redis_client.delete(f"url:{short_code}")
    except: pass
    db.session.delete(url)
    db.session.commit()
    return jsonify({'message': 'URL deleted successfully', 'short_code': short_code}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)