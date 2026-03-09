from app import app
from models import db, URL

with app.app_context():
    # Get all URLs
    all_urls = URL.query.all()
    
    print(f"\n📊 Total URLs in database: {len(all_urls)}")
    print("="*60)
    
    for url in all_urls:
        print(f"\nID: {url.id}")
        print(f"  URL: {url.original_url[:80]}...")
        print(f"  Verdict: {url.threat_verdict}")
        print(f"  Score: {url.threat_score}")
        print(f"  Short Code: {url.short_code}")
    
    # Count by verdict
    print("\n" + "="*60)
    safe_count = URL.query.filter_by(threat_verdict='SAFE').count()
    warn_count = URL.query.filter_by(threat_verdict='WARN').count()
    block_count = URL.query.filter_by(threat_verdict='BLOCK').count()
    
    print(f"\n✅ SAFE: {safe_count}")
    print(f"⚠️  WARN: {warn_count}")
    print(f"🛡️  BLOCK: {block_count}")