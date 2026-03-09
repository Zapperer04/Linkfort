from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    urls = db.relationship('URL', backref='owner', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'total_urls': len(self.urls)
        }


class URL(db.Model):
    __tablename__ = 'urls'
    
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.Text, nullable=False)
    short_code = db.Column(db.String(20), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
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
    
    def __repr__(self):
        return f'<URL {self.short_code} -> {self.original_url}>'
    
    def is_url_expired(self):
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self):
        from flask import current_app
        base_url = current_app.config.get('BASE_URL', 'http://localhost:5000')
        return {
            'id': self.id,
            'original_url': self.original_url,
            'short_code': self.short_code,
            'short_url': f'{base_url}/{self.short_code}',
            'created_at': self.created_at.isoformat(),
            'click_count': self.click_count,
            'threat_score': self.threat_score,
            'threat_verdict': self.threat_verdict,
            'threat_details': self.threat_details,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_expired': self.is_url_expired(),
            'is_active': self.is_active,   # ✅ NEW: exposed in API response
            'user_id': self.user_id
        }


class Click(db.Model):
    __tablename__ = 'clicks'
    
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('urls.id'), nullable=False)
    clicked_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    
    def __repr__(self):
        return f'<Click {self.id} for URL {self.url_id}>'