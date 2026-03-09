import string
import random

# Base62 characters: 0-9, a-z, A-Z
BASE62_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase

def encode_base62(num):
    """Convert a number to base62 string"""
    if num == 0:
        return BASE62_CHARS[0]
    
    base62 = []
    while num:
        num, rem = divmod(num, 62)
        base62.append(BASE62_CHARS[rem])
    
    return ''.join(reversed(base62))

def generate_short_code(url_id):
    """Generate a short code from URL ID"""
    # Use the database ID to generate a unique code
    return encode_base62(url_id)

def generate_random_code(length=6):
    """Generate a random short code (fallback for collisions)"""
    return ''.join(random.choices(BASE62_CHARS, k=length))