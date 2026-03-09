import redis
import os
from dotenv import load_dotenv
import json

load_dotenv()

# Initialize Redis connection
redis_client = None

def init_redis():
    """Initialize Redis connection"""
    global redis_client
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    try:
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
        print("✅ Redis connected!")
        return True
    except Exception as e:
        print(f"⚠️  Redis connection failed: {e}")
        print("⚠️  Running without cache (slower redirects)")
        redis_client = None
        return False

def get_cached_url(short_code):
    """Get original URL from cache"""
    if not redis_client:
        return None
    
    try:
        cached = redis_client.get(f"url:{short_code}")
        if cached:
            return json.loads(cached)
        return None
    except Exception as e:
        print(f"Cache read error: {e}")
        return None

def set_cached_url(short_code, url_data, ttl=86400):
    """Cache URL data (TTL = 24 hours by default)"""
    if not redis_client:
        return False
    
    try:
        redis_client.setex(
            f"url:{short_code}",
            ttl,
            json.dumps(url_data)
        )
        return True
    except Exception as e:
        print(f"Cache write error: {e}")
        return False

def invalidate_cache(short_code):
    """Remove URL from cache"""
    if not redis_client:
        return False
    
    try:
        redis_client.delete(f"url:{short_code}")
        return True
    except Exception as e:
        print(f"Cache invalidation error: {e}")
        return False

def check_rate_limit(identifier, max_requests=10, window=60):
    """
    Token bucket rate limiting
    """
    if not redis_client:
        return True, max_requests
    
    try:
        key = f"ratelimit:{identifier}"
        current = redis_client.get(key)
        
        if current is None:
            redis_client.setex(key, window, max_requests - 1)
            return True, max_requests - 1
        
        current = int(current)
        if current > 0:
            redis_client.decr(key)
            return True, current - 1
        else:
            return False, 0
            
    except Exception as e:
        print(f"Rate limit error: {e}")
        return True, max_requests