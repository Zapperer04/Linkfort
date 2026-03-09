"""
Train XGBoost phishing detection model
Uses HYBRID approach: Real-world threat data + Synthetic patterns
Data sources: OpenPhish + URLhaus + Top Sites + Synthetic
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import xgboost as xgb
import pickle
import re
from urllib.parse import urlparse
import math
import requests

def calculate_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log2(p) for p in prob if p > 0])
    return entropy

def extract_url_features(url):
    """Extract 15 numerical features from URL for ML"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        
        if domain.startswith('www.'):
            domain = domain[4:]
        if ':' in domain:
            domain = domain.split(':')[0]
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'num_digits': sum(c.isdigit() for c in url),
            'domain_entropy': calculate_entropy(domain),
            'digit_ratio': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
            'is_https': 1 if parsed.scheme == 'https' else 0,
            'num_query_params': len(query.split('&')) if query else 0,
            'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
            'subdomain_count': domain.count('.'),
            'has_at_symbol': 1 if '@' in url else 0,
        }
        
        return features
    except:
        return None

def download_openphish_urls(max_urls=2000):
    """Download real phishing URLs from OpenPhish"""
    print("  📡 Downloading OpenPhish phishing dataset...")
    
    try:
        response = requests.get(
            'https://openphish.com/feed.txt',
            timeout=30,
            headers={'User-Agent': 'LinkFort-ML-Training/1.0'}
        )
        
        if response.status_code == 200:
            urls = response.text.strip().split('\n')
            urls = [url.strip() for url in urls if url.strip()][:max_urls]
            
            print(f"  ✅ Downloaded {len(urls)} real phishing URLs from OpenPhish")
            return urls
        else:
            print(f"  ⚠️  OpenPhish download failed (HTTP {response.status_code})")
            return []
            
    except Exception as e:
        print(f"  ⚠️  OpenPhish download error: {e}")
        return []

def download_urlhaus_malware(max_urls=1000):
    """Download real malware URLs from URLhaus"""
    print("  📡 Downloading URLhaus malware dataset...")
    
    try:
        response = requests.get(
            'https://urlhaus.abuse.ch/downloads/csv_recent/',
            timeout=30,
            headers={'User-Agent': 'LinkFort-ML-Training/1.0'}
        )
        
        if response.status_code == 200:
            lines = response.text.split('\n')
            urls = []
            
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                
                try:
                    parts = line.split('","')
                    if len(parts) >= 3:
                        url = parts[2].strip('"')
                        urls.append(url)
                        
                        if len(urls) >= max_urls:
                            break
                except:
                    continue
            
            print(f"  ✅ Downloaded {len(urls)} malware URLs from URLhaus")
            return urls
        else:
            print(f"  ⚠️  URLhaus download failed (HTTP {response.status_code})")
            return []
            
    except Exception as e:
        print(f"  ⚠️  URLhaus download error: {e}")
        return []

def download_legitimate_urls(max_urls=3000):
    """Generate legitimate URLs from top domains"""
    print("  🔧 Generating legitimate URLs from top sites...")
    
    top_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'ebay.com',
        'netflix.com', 'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
        'medium.com', 'twitch.tv', 'spotify.com', 'paypal.com', 'zoom.us',
        'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com', 'shopify.com',
        'wordpress.com', 'tumblr.com', 'pinterest.com', 'yahoo.com', 'bing.com',
        'cloudflare.com', 'steam.com', 'imdb.com', 'cnn.com', 'bbc.com',
        'nytimes.com', 'forbes.com', 'weather.com', 'craigslist.org', 'indeed.com',
        'espn.com', 'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com',
        'office.com', 'live.com', 'outlook.com', 'skype.com', 'trello.com',
        'notion.so', 'figma.com', 'canva.com', 'discord.com', 'telegram.org'
    ]
    
    urls = []
    paths = ['', '/about', '/contact', '/products', '/services', '/blog', '/news', 
             '/help', '/support', '/login', '/signup', '/search', '/careers', '/pricing',
             '/features', '/download', '/docs', '/api', '/community', '/events']
    
    for domain in top_domains:
        urls.append(f'https://www.{domain}')
        urls.append(f'https://{domain}')
        
        for path in paths:
            urls.append(f'https://{domain}{path}')
            if len(urls) >= max_urls:
                break
        
        if len(urls) >= max_urls:
            break
    
    print(f"  ✅ Generated {len(urls[:max_urls])} legitimate URLs")
    return urls[:max_urls]

def generate_synthetic_phishing(count=1000):
    """Generate synthetic phishing URLs"""
    print(f"  🔧 Generating {count} synthetic phishing patterns...")
    
    phishing_urls = []
    
    # IP addresses
    for i in range(150):
        ip = f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}"
        phishing_urls.append(f"http://{ip}/login")
    
    # Suspicious TLDs
    tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
    keywords = ['login', 'verify', 'secure', 'account', 'bank']
    for i in range(200):
        keyword = np.random.choice(keywords)
        phishing_urls.append(f"http://{keyword}-{np.random.randint(1000,9999)}{np.random.choice(tlds)}/page")
    
    # Long URLs
    for i in range(150):
        parts = [np.random.choice(['secure', 'login', 'verify']) for _ in range(5)]
        phishing_urls.append(f"http://{'-'.join(parts)}.com/path")
    
    # Typosquatting
    brands = ['paypal', 'amazon', 'google', 'microsoft']
    for i in range(150):
        brand = np.random.choice(brands)
        typo = brand[:3] + str(np.random.randint(0,9)) + brand[3:]
        phishing_urls.append(f"http://{typo}.com/login")
    
    # @ symbol
    for i in range(100):
        phishing_urls.append(f"http://google.com@evil{np.random.randint(100,999)}.com/")
    
    # Excessive subdomains
    for i in range(150):
        subs = '.'.join([f"s{j}" for j in range(4)])
        phishing_urls.append(f"http://{subs}.malicious.com/verify")
    
    # Redirect URLs
    for i in range(100):
        phishing_urls.append(f"http://redirect.xyz/go?url=http://malicious{i}.com")
    
    return phishing_urls[:count]

def generate_synthetic_legitimate(count=1000):
    """Generate synthetic legitimate URLs"""
    print(f"  🔧 Generating {count} synthetic legitimate URLs...")
    
    domains = ['example.com', 'test.org', 'demo.net', 'sample.io']
    urls = []
    
    for i in range(count):
        domain = np.random.choice(domains)
        path = np.random.choice(['', '/page', '/about'])
        protocol = 'https' if np.random.random() > 0.2 else 'http'
        urls.append(f'{protocol}://www.{domain}{path}')
    
    return urls

def train_model():
    """Train the hybrid model with real-world data"""
    print("\n🤖 Training HYBRID ML Phishing Detection Model")
    print("   (Real-World Threat Data + Synthetic Patterns)\n")
    print("="*60)
    
    print("\n📥 Collecting training data from multiple sources...\n")
    
    # Real phishing data
    real_phishing = download_openphish_urls(2000)
    real_malware = download_urlhaus_malware(1000)
    synthetic_phishing = generate_synthetic_phishing(1000)
    
    # Legitimate data
    real_legitimate = download_legitimate_urls(3000)
    synthetic_legitimate = generate_synthetic_legitimate(1000)
    
    all_phishing = real_phishing + real_malware + synthetic_phishing
    all_legitimate = real_legitimate + synthetic_legitimate
    
    real_count = len(real_phishing) + len(real_malware) + len(real_legitimate)
    total_count = len(all_phishing) + len(all_legitimate)
    
    print(f"\n📊 Dataset composition:")
    print(f"   Malicious URLs: {len(all_phishing)}")
    print(f"     - Real phishing (OpenPhish): {len(real_phishing)}")
    print(f"     - Real malware (URLhaus): {len(real_malware)}")
    print(f"     - Synthetic patterns: {len(synthetic_phishing)}")
    print(f"   Legitimate URLs: {len(all_legitimate)}")
    print(f"     - Real (Top sites): {len(real_legitimate)}")
    print(f"     - Synthetic: {len(synthetic_legitimate)}")
    print(f"   Total: {total_count} URLs")
    print(f"   Real-world data: {real_count} URLs ({(real_count/total_count*100):.1f}%)")
    
    # Extract features
    print("\n🔍 Extracting features...")
    data = []
    labels = []
    
    for url in all_phishing:
        features = extract_url_features(url)
        if features:
            data.append(features)
            labels.append(1)
    
    for url in all_legitimate:
        features = extract_url_features(url)
        if features:
            data.append(features)
            labels.append(0)
    
    df = pd.DataFrame(data)
    X = df.values
    y = np.array(labels)
    
    print(f"✅ Extracted features for {len(X)} URLs")
    print(f"   Phishing: {sum(y)}, Legitimate: {len(y) - sum(y)}")
    
    # Train
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n📊 Training on {len(X_train)} samples...")
    
    model = xgb.XGBClassifier(
        max_depth=6,
        learning_rate=0.1,
        n_estimators=150,
        random_state=42
    )
    
    model.fit(X_train, y_train, verbose=False)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"✅ MODEL TRAINED WITH REAL-WORLD DATA!")
    print(f"{'='*60}")
    print(f"\n📊 Accuracy: {accuracy * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save
    with open('phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open('feature_names.pkl', 'wb') as f:
        pickle.dump(list(df.columns), f)
    
    print("\n✅ Model saved!")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    train_model()