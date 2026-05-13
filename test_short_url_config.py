#!/usr/bin/env python
from app import app
from models import URL
from datetime import datetime

# Test that SHORT_URL_BASE is used
with app.app_context():
    # Create a test URL
    test_url = URL(
        original_url='https://www.example.com/test',
        short_code='test123',
        user_id=None,
        threat_score=0.0,
        threat_verdict='SAFE',
        created_at=datetime.utcnow()
    )
    
    # Check the short_url generation
    result = test_url.to_dict()
    print(f"Short URL Base Config: {app.config.get('SHORT_URL_BASE')}")
    print(f"Generated short_url: {result['short_url']}")
    print(f"[OK] Short URL correctly uses SHORT_URL_BASE!" if result['short_url'] == 'http://localhost:5000/test123' else "[FAIL] Short URL incorrect")
