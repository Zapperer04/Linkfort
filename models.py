from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

def get_utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def format_iso(dt):
    if not dt: return None
    s = dt.isoformat()
    if not s.endswith('Z') and '+' not in s:
        return s + 'Z'
    return s

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=get_utc_now)
    is_active = db.Column(db.Boolean, default=True)
    
    urls = db.relationship('URL', backref='owner', lazy=True)
    
    def __init__(self, username=None, email=None, password_hash=None, **kwargs):
        if username is not None: self.username = username
        if email is not None: self.email = email
        if password_hash is not None: self.password_hash = password_hash
        for k, v in kwargs.items(): setattr(self, k, v)
        
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': format_iso(self.created_at),
            'total_urls': len(self.urls)
        }


class URL(db.Model):
    __tablename__ = 'urls'
    
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.Text, nullable=False)
    short_code = db.Column(db.String(20), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=get_utc_now)
    click_count = db.Column(db.Integer, default=0)
    
    # Auth: Owner
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Expiration
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    is_expired = db.Column(db.Boolean, default=False)

    # ✅ NEW: Active/disabled toggle
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Threat detection
    threat_score = db.Column(db.Float, default=0.0)
    threat_verdict = db.Column(db.String(20), default='SAFE')
    threat_details = db.Column(db.JSON, nullable=True)
    
    clicks = db.relationship('Click', backref='url', lazy=True, cascade='all, delete-orphan')
    
    def __init__(self, original_url=None, short_code=None, threat_score=0.0, threat_verdict='SAFE', threat_details=None, expires_at=None, user_id=None, **kwargs):
        if original_url is not None: self.original_url = original_url
        if short_code is not None: self.short_code = short_code
        if threat_score is not None: self.threat_score = threat_score
        if threat_verdict is not None: self.threat_verdict = threat_verdict
        if threat_details is not None: self.threat_details = threat_details
        if expires_at is not None: self.expires_at = expires_at
        if user_id is not None: self.user_id = user_id
        for k, v in kwargs.items(): setattr(self, k, v)
        
    def __repr__(self):
        return f'<URL {self.short_code} -> {self.original_url}>'
    
    def is_url_expired(self):
        if self.expires_at is None:
            return False
        return get_utc_now() > self.expires_at
    
    def to_dict(self):
        from flask import current_app
        # ✅ PRODUCTION: Use SHORT_URL_BASE from config (can be overridden via env var)
        # This ensures short URLs use the production domain regardless of request source
        base_url = current_app.config.get('SHORT_URL_BASE', 'http://localhost:5000')
        
        return {
            'id': self.id,
            'original_url': self.original_url,
            'short_code': self.short_code,
            'short_url': f'{base_url}/{self.short_code}',
            'created_at': format_iso(self.created_at),
            'click_count': self.click_count,
            'threat_score': self.threat_score,
            'threat_verdict': self.threat_verdict,
            'threat_details': self.threat_details,
            'expires_at': format_iso(self.expires_at),
            'is_expired': self.is_url_expired(),
            'is_active': self.is_active,
            'user_id': self.user_id
        }


class Click(db.Model):
    __tablename__ = 'clicks'
    
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    clicked_at = db.Column(db.DateTime, default=get_utc_now, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    
    def __init__(self, url_id=None, ip_address=None, **kwargs):
        if url_id is not None: self.url_id = url_id
        if ip_address is not None: self.ip_address = ip_address
        for k, v in kwargs.items(): setattr(self, k, v)
        
    def __repr__(self):
        return f'<Click {self.id} for URL {self.url_id}>'