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
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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

# ==================== WARNING PAGE TEMPLATE ====================

WARNING_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>⚠️ Security Warning - LinkFort</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .warning-box {
            background: white;
            border-radius: 16px;
            padding: 40px;
            max-width: 600px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .warning-icon { font-size: 64px; text-align: center; margin-bottom: 20px; }
        h1 { color: #e74c3c; text-align: center; margin-bottom: 10px; }
        .threat-score { text-align: center; font-size: 18px; color: #666; margin-bottom: 30px; }
        .url-display {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            word-break: break-all;
            margin: 20px 0;
            font-family: monospace;
            border-left: 4px solid #e74c3c;
        }
        .reasons {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .reasons h3 { margin-top: 0; color: #856404; }
        .reasons ul { margin: 10px 0; padding-left: 20px; }
        .reasons li { color: #856404; margin: 5px 0; }
        .button-group { display: flex; gap: 10px; margin-top: 30px; }
        .btn {
            flex: 1;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
            transition: transform 0.2s;
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
        <div class="threat-score">
            Threat Score: <strong style="color: #e74c3c;">{{ score }}/1.00</strong>
        </div>
        <p style="text-align: center; color: #555;">
            This link has been flagged as potentially dangerous. Proceed with extreme caution.
        </p>
        <div class="url-display">{{ url }}</div>
        {% if reasons %}
        <div class="reasons">
            <h3>🚨 Why was this flagged?</h3>
            <ul>
            {% for reason in reasons %}
                <li>{{ reason }}</li>
            {% endfor %}
            </ul>
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
        <p style="color: #555; font-size: 16px;">
            This short link has expired and is no longer available.
        </p>
        <p style="color: #7f8c8d; font-size: 14px; margin-top: 20px;">
            Expired on: {{ expired_at }}
        </p>
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

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password are required'}), 400

    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if '@' not in email:
        return jsonify({'error': 'Invalid email address'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(
        username=username,
        email=email,
        password_hash=password_hash
    )
    db.session.add(new_user)
    db.session.commit()

    # ✅ FIX: identity must be a string for JWT
    access_token = create_access_token(identity=str(new_user.id))

    print(f"✅ New user registered: {username}")

    return jsonify({
        'message': 'Account created successfully!',
        'access_token': access_token,
        'user': new_user.to_dict()
    }), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid email or password'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 401

    # ✅ FIX: identity must be a string for JWT
    access_token = create_access_token(identity=str(user.id))

    print(f"✅ User logged in: {user.username}")

    return jsonify({
        'message': f'Welcome back, {user.username}!',
        'access_token': access_token,
        'user': user.to_dict()
    }), 200


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current logged in user"""
    user_id = int(get_jwt_identity())  # ✅ FIX: Convert back to int
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

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
    if len(code) < 3:
        return jsonify({'available': False, 'reason': 'Too short (min 3 characters)'}), 200

    if len(code) > 20:
        return jsonify({'available': False, 'reason': 'Too long (max 20 characters)'}), 200

    if not re.match(r'^[a-zA-Z0-9_-]+$', code):
        return jsonify({'available': False, 'reason': 'Only letters, numbers, hyphens, underscores allowed'}), 200

    reserved = ['api', 'admin', 'dashboard', 'analytics', 'health', 'stats', 'app', 'www']
    if code.lower() in reserved:
        return jsonify({'available': False, 'reason': 'Reserved word'}), 200

    existing = URL.query.filter_by(short_code=code).first()
    if existing:
        return jsonify({'available': False, 'reason': 'Already taken'}), 200

    return jsonify({'available': True, 'reason': 'Available!'}), 200


@app.route('/api/shorten', methods=['POST'])
def shorten_url():
    """Shorten a URL with threat detection, custom code, and expiration"""

    client_ip = get_client_ip()
    allowed, remaining = check_rate_limit(client_ip, max_requests=10, window=60)

    if not allowed:
        return jsonify({'error': 'Rate limit exceeded. Please try again in a minute.'}), 429

    # ✅ FIX: Get user id from JWT if available
    current_user_id = None
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        try:
            token = auth_header.split(' ')[1]
            decoded = decode_token(token)
            current_user_id = int(decoded['sub'])  # Convert to int
        except Exception as e:
            print(f"  Token decode warning: {e}")
            pass

    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400

    original_url = data['url'].strip()
    custom_code = data.get('custom_code', '').strip()
    expiration_days = data.get('expiration_days', None)

    if not validators.url(original_url):
        return jsonify({'error': 'Invalid URL format'}), 400

    if custom_code:
        if len(custom_code) < 3:
            return jsonify({'error': 'Custom code must be at least 3 characters'}), 400
        if len(custom_code) > 20:
            return jsonify({'error': 'Custom code must be less than 20 characters'}), 400
        if not re.match(r'^[a-zA-Z0-9_-]+$', custom_code):
            return jsonify({'error': 'Custom code can only contain letters, numbers, hyphens, and underscores'}), 400
        reserved = ['api', 'admin', 'dashboard', 'analytics', 'health', 'stats', 'app', 'www']
        if custom_code.lower() in reserved:
            return jsonify({'error': f'"{custom_code}" is a reserved word'}), 400
        existing = URL.query.filter_by(short_code=custom_code).first()
        if existing:
            return jsonify({'error': f'Custom code "{custom_code}" is already taken'}), 400

    expires_at = None
    if expiration_days:
        try:
            days = int(expiration_days)
            if days < 1 or days > 365:
                return jsonify({'error': 'Expiration must be between 1 and 365 days'}), 400
            expires_at = datetime.utcnow() + timedelta(days=days)
        except ValueError:
            return jsonify({'error': 'Invalid expiration days'}), 400

    threat_score, verdict, details = calculate_threat_score(original_url)

    print(f"🔍 Scanned: {original_url}")
    print(f"   Score: {threat_score:.2f} | Verdict: {verdict}")
    if expires_at:
        print(f"   Expires: {expires_at.strftime('%Y-%m-%d %H:%M UTC')}")

    existing = URL.query.filter_by(original_url=original_url).first()
    if existing:
        existing.threat_score = threat_score
        existing.threat_verdict = verdict
        existing.threat_details = details
        existing.expires_at = expires_at
        if current_user_id:
            existing.user_id = current_user_id
        db.session.commit()

        if verdict == 'BLOCK':
            return jsonify({
                'error': 'URL blocked',
                'message': 'This URL has been identified as malicious.',
                'threat_score': threat_score,
                'threat_verdict': verdict,
                'reasons': details.get('all_reasons', [])
            }), 403

        set_cached_url(existing.short_code, {
            'original_url': existing.original_url,
            'id': existing.id,
            'threat_verdict': existing.threat_verdict
        })

        return jsonify({
            'message': 'URL already shortened',
            'data': existing.to_dict(),
            'rate_limit_remaining': remaining
        }), 200

    new_url = URL(
        original_url=original_url,
        short_code='temp',
        threat_score=threat_score,
        threat_verdict=verdict,
        threat_details=details,
        expires_at=expires_at,
        user_id=current_user_id
    )
    db.session.add(new_url)
    db.session.flush()

    if custom_code:
        short_code = custom_code
    else:
        short_code = generate_short_code(new_url.id)
        while URL.query.filter_by(short_code=short_code).first():
            short_code = generate_random_code()

    new_url.short_code = short_code
    db.session.commit()

    print(f"💾 Saved: ID={new_url.id}, Code={short_code}, Verdict={verdict}")

    if verdict == 'BLOCK':
        return jsonify({
            'error': 'URL blocked',
            'message': 'This URL has been identified as malicious.',
            'threat_score': threat_score,
            'threat_verdict': verdict,
            'reasons': details.get('all_reasons', [])
        }), 403

    set_cached_url(new_url.short_code, {
        'original_url': new_url.original_url,
        'id': new_url.id,
        'threat_verdict': new_url.threat_verdict
    })

    return jsonify({
        'message': 'URL shortened successfully',
        'data': new_url.to_dict(),
        'rate_limit_remaining': remaining,
        'custom_code_used': bool(custom_code)
    }), 201


@app.route('/<short_code>', methods=['GET'])
def redirect_url(short_code):
    """Redirect with threat protection, click tracking, and expiration check"""

    cached = get_cached_url(short_code)
    if cached:
        print(f"✅ Cache HIT for {short_code}")
        url = URL.query.get(cached['id'])

        if not url:
            return jsonify({'error': 'Short URL not found'}), 404

        if url.is_url_expired():
            return render_template_string(
                EXPIRED_PAGE,
                expired_at=url.expires_at.strftime('%B %d, %Y at %H:%M UTC')
            )

        if cached.get('threat_verdict') == 'WARN':
            return render_template_string(
                WARNING_PAGE,
                url=url.original_url,
                score=f"{url.threat_score:.2f}",
                reasons=url.threat_details.get('all_reasons', [])
            )

        url.click_count += 1
        click = Click(url_id=url.id, ip_address=get_client_ip())
        db.session.add(click)
        db.session.commit()

        return redirect(cached['original_url'], code=302)

    print(f"⚠️  Cache MISS for {short_code}")
    url = URL.query.filter_by(short_code=short_code).first()

    if not url:
        return jsonify({'error': 'Short URL not found'}), 404

    if url.is_url_expired():
        return render_template_string(
            EXPIRED_PAGE,
            expired_at=url.expires_at.strftime('%B %d, %Y at %H:%M UTC')
        )

    if url.threat_verdict == 'WARN':
        return render_template_string(
            WARNING_PAGE,
            url=url.original_url,
            score=f"{url.threat_score:.2f}",
            reasons=url.threat_details.get('all_reasons', [])
        )

    set_cached_url(short_code, {
        'original_url': url.original_url,
        'id': url.id,
        'threat_verdict': url.threat_verdict
    })

    url.click_count += 1
    click = Click(url_id=url.id, ip_address=get_client_ip())
    db.session.add(click)
    db.session.commit()

    return redirect(url.original_url, code=302)


@app.route('/api/stats/<short_code>', methods=['GET'])
def get_stats(short_code):
    url = URL.query.filter_by(short_code=short_code).first()
    if not url:
        return jsonify({'error': 'Short URL not found'}), 404
    return jsonify({'data': url.to_dict()}), 200


@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get dashboard statistics for logged in user"""
    try:
        # ✅ FIX: Convert identity back to int
        user_id = int(get_jwt_identity())
        now = datetime.utcnow()

        base_query = URL.query.filter_by(user_id=user_id)

        total_urls = base_query.count()
        total_clicks = db.session.query(
            db.func.sum(URL.click_count)
        ).filter(URL.user_id == user_id).scalar() or 0

        threats_blocked = base_query.filter_by(threat_verdict='BLOCK').count()

        active_urls = base_query.filter(
            URL.threat_verdict.in_(['SAFE', 'WARN']),
            db.or_(URL.expires_at.is_(None), URL.expires_at > now)
        ).count()

        expired_urls = base_query.filter(
            URL.expires_at.isnot(None),
            URL.expires_at <= now
        ).count()

        recent_threats = base_query.filter_by(threat_verdict='BLOCK')\
            .order_by(URL.created_at.desc()).limit(20).all()

        threats_data = []
        for url in recent_threats:
            reasons = []
            if url.threat_details:
                reasons = url.threat_details.get('all_reasons', [])
            threats_data.append({
                'id': url.id,
                'url': url.original_url,
                'score': url.threat_score,
                'time': url.created_at.isoformat(),
                'reasons': reasons
            })

        active_url_list = base_query.filter(
            URL.threat_verdict.in_(['SAFE', 'WARN']),
            db.or_(URL.expires_at.is_(None), URL.expires_at > now)
        ).order_by(URL.created_at.desc()).limit(20).all()

        base_url = current_app.config.get('BASE_URL', 'http://localhost:5000')

        active_data = [{
            'id': url.id,
            'original_url': url.original_url,
            'short_url': f"{base_url}/{url.short_code}",
            'short_code': url.short_code,
            'verdict': url.threat_verdict,
            'score': url.threat_score,
            'clicks': url.click_count,
            'created_at': url.created_at.isoformat(),
            'expires_at': url.expires_at.isoformat() if url.expires_at else None
        } for url in active_url_list]

        expired_url_list = base_query.filter(
            URL.expires_at.isnot(None),
            URL.expires_at <= now
        ).order_by(URL.expires_at.desc()).limit(20).all()

        expired_data = [{
            'id': url.id,
            'original_url': url.original_url,
            'short_url': f"{base_url}/{url.short_code}",
            'short_code': url.short_code,
            'verdict': url.threat_verdict,
            'score': url.threat_score,
            'clicks': url.click_count,
            'created_at': url.created_at.isoformat(),
            'expires_at': url.expires_at.isoformat() if url.expires_at else None
        } for url in expired_url_list]

        return jsonify({
            'stats': {
                'total_urls': total_urls,
                'total_clicks': int(total_clicks),
                'threats_blocked': threats_blocked,
                'active_urls': active_urls,
                'expired_urls': expired_urls
            },
            'recent_threats': threats_data,
            'active_urls': active_data,
            'expired_urls': expired_data
        }), 200

    except Exception as e:
        print(f"❌ Error in dashboard stats: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    """Get analytics data - filtered by logged in user"""
    try:
        from sqlalchemy import func

        # ✅ FIX: Filter analytics by user
        user_id = int(get_jwt_identity())

        threat_trends = []
        for i in range(6, -1, -1):
            date = datetime.now() - timedelta(days=i)

            safe = URL.query.filter(
                URL.user_id == user_id,
                URL.threat_verdict == 'SAFE',
                func.date(URL.created_at) == date.date()
            ).count()

            warn = URL.query.filter(
                URL.user_id == user_id,
                URL.threat_verdict == 'WARN',
                func.date(URL.created_at) == date.date()
            ).count()

            blocked = URL.query.filter(
                URL.user_id == user_id,
                URL.threat_verdict == 'BLOCK',
                func.date(URL.created_at) == date.date()
            ).count()

            threat_trends.append({
                'date': date.strftime('%b %d'),
                'safe': safe,
                'warn': warn,
                'blocked': blocked
            })

        score_ranges = [
            {'range': '0.0-0.2', 'count': 0},
            {'range': '0.2-0.4', 'count': 0},
            {'range': '0.4-0.6', 'count': 0},
            {'range': '0.6-0.8', 'count': 0},
            {'range': '0.8-1.0', 'count': 0}
        ]

        user_urls = URL.query.filter_by(user_id=user_id).all()
        for url in user_urls:
            score = url.threat_score
            if score < 0.2:
                score_ranges[0]['count'] += 1
            elif score < 0.4:
                score_ranges[1]['count'] += 1
            elif score < 0.6:
                score_ranges[2]['count'] += 1
            elif score < 0.8:
                score_ranges[3]['count'] += 1
            else:
                score_ranges[4]['count'] += 1

        layer1_detections = 0
        layer2_detections = 0
        layer3_detections = 0

        for url in user_urls:
            if url.threat_details:
                layers = url.threat_details.get('layers', {})
                if layers.get('layer1', {}).get('score', 0) >= 0.5:
                    layer1_detections += 1
                if layers.get('layer2', {}).get('score', 0) >= 0.5:
                    layer2_detections += 1
                if layers.get('layer3', {}).get('score', 0) >= 0.5:
                    layer3_detections += 1

        layer_performance = [
            {'name': 'Layer 1', 'value': layer1_detections},
            {'name': 'Layer 2', 'value': layer2_detections},
            {'name': 'Layer 3', 'value': layer3_detections}
        ]

        blocked_urls = URL.query.filter_by(user_id=user_id, threat_verdict='BLOCK').all()
        domain_stats = {}

        for url in blocked_urls:
            try:
                domain = urlparse(url.original_url).netloc
                if domain not in domain_stats:
                    domain_stats[domain] = {
                        'domain': domain,
                        'count': 0,
                        'scores': [],
                        'reasons': []
                    }
                domain_stats[domain]['count'] += 1
                domain_stats[domain]['scores'].append(url.threat_score)
                if url.threat_details:
                    reasons = url.threat_details.get('all_reasons', [])
                    if reasons:
                        domain_stats[domain]['reasons'].append(reasons[0])
            except:
                continue

        top_blocked = []
        for domain, stats in sorted(
            domain_stats.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]:
            avg_score = sum(stats['scores']) / len(stats['scores']) if stats['scores'] else 0
            top_reason = max(
                set(stats['reasons']), key=stats['reasons'].count
            ) if stats['reasons'] else 'Unknown'

            top_blocked.append({
                'domain': domain,
                'count': stats['count'],
                'avgScore': avg_score,
                'topReason': top_reason[:50] + '...' if len(top_reason) > 50 else top_reason
            })

        click_stats = []
        now = datetime.now()
        for i in range(11, -1, -1):
            hour_start = now - timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)

            # ✅ Filter clicks by user's URLs only
            clicks = Click.query.join(URL).filter(
                URL.user_id == user_id,
                Click.clicked_at >= hour_start,
                Click.clicked_at < hour_end
            ).count()

            click_stats.append({
                'hour': hour_start.strftime('%H:%M'),
                'clicks': clicks
            })

        return jsonify({
            'threatTrends': threat_trends,
            'scoreDistribution': score_ranges,
            'topBlockedDomains': top_blocked,
            'layerPerformance': layer_performance,
            'clickStats': click_stats
        }), 200

    except Exception as e:
        print(f"Analytics error: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)