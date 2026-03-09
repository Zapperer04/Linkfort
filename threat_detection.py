"""
LinkFort Threat Detection System
Multi-layered approach: Pattern Matching → ML Classification → External Verification
"""

import re
import math
from urllib.parse import urlparse
from typing import Tuple, Dict, List

# ============================================================================
# LAYER 1: FAST PATTERN MATCHING (~1ms)
# ============================================================================

class Layer1PatternMatcher:
    """
    Quick pattern-based threat detection
    No external calls, no ML - just pure rule-based checking
    """
    
    # Suspicious TLDs (free or commonly abused)
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.xyz', '.top', '.work', '.click', '.link',
        '.pw', '.cc', '.ws', '.biz', '.info',
        '.online', '.site', '.website', '.space'
    }
    
    # Phishing keywords
    PHISHING_KEYWORDS = {
        'login', 'signin', 'account', 'verify', 'secure',
        'update', 'confirm', 'password', 'banking', 'paypal',
        'suspended', 'locked', 'unusual', 'activity', 'billing',
        'payment', 'wallet', 'restore', 'validate', 'authenticate'
    }
    
    # Redirect parameters
    REDIRECT_PARAMS = {
        'redirect', 'url', 'goto', 'next', 'return',
        'continue', 'target', 'redir', 'destination'
    }
    
    def __init__(self):
        self.reasons = []
        self.score = 0.0
    
    def analyze(self, url: str) -> Tuple[float, List[str]]:
        """
        Analyze URL using fast pattern matching
        Returns: (score, reasons)
        """
        self.reasons = []
        self.score = 0.0
        
        try:
            parsed = urlparse(url)
            domain = self._extract_domain(url)
            path = parsed.path.lower()
            query = parsed.query.lower()
            full_url = url.lower()
            
            # Check 1: IP Address (major red flag)
            if self._has_ip_address(url):
                self.score += 0.8
                self.reasons.append('Uses IP address instead of domain name')
            
            # Check 2: Phishing Keywords (3+ keywords = suspicious)
            keyword_count = sum(1 for keyword in self.PHISHING_KEYWORDS if keyword in full_url)
            if keyword_count >= 3:
                self.score += 0.5
                self.reasons.append(f'Contains {keyword_count} phishing-related keywords')
            elif keyword_count == 2:
                self.score += 0.2
                self.reasons.append(f'Contains {keyword_count} suspicious keywords')
            
            # Check 3: Suspicious TLD
            if self._has_suspicious_tld(domain):
                self.score += 0.35
                self.reasons.append('Uses free/commonly-abused domain extension')
            
            # Check 4: Excessive Subdomains (spoofing technique)
            subdomain_count = domain.count('.') if domain else 0
            if subdomain_count > 3:
                self.score += 0.3
                self.reasons.append(f'Excessive subdomains ({subdomain_count} levels)')
            elif subdomain_count > 2:
                self.score += 0.15
            
            # Check 5: @ Symbol (URL obfuscation)
            if '@' in url:
                self.score += 0.9
                self.reasons.append('Contains @ symbol (credential phishing technique)')
            
            # Check 6: Redirect Parameters
            if any(param in query for param in self.REDIRECT_PARAMS):
                self.score += 0.25
                self.reasons.append('Contains redirect parameters')
            
            # Check 7: Excessive Length
            if len(url) > 150:
                self.score += 0.3
                self.reasons.append('Extremely long URL (obfuscation)')
            elif len(url) > 100:
                self.score += 0.15
                self.reasons.append('Very long URL')
            
            # Check 8: Not HTTPS
            if parsed.scheme != 'https':
                self.score += 0.15
                self.reasons.append('Not using HTTPS')
            
            # Check 9: Excessive Hyphens/Underscores
            hyphen_count = url.count('-') + url.count('_')
            if hyphen_count > 5:
                self.score += 0.2
                self.reasons.append(f'Excessive hyphens/underscores ({hyphen_count})')
            
            # Check 10: Too Many Dots
            if url.count('.') > 5:
                self.score += 0.2
                self.reasons.append('Too many dots in URL')
            
            # Cap at 1.0
            self.score = min(self.score, 1.0)
            
            return self.score, self.reasons
            
        except Exception as e:
            return 0.5, [f'Analysis error: {str(e)}']
    
    def _extract_domain(self, url: str) -> str:
        """Extract clean domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain
        except:
            return ''
    
    def _has_ip_address(self, url: str) -> bool:
        """Check if URL uses IP address instead of domain"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain uses suspicious TLD"""
        return any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS)


# ============================================================================
# LAYER 2: MACHINE LEARNING (~50ms)
# ============================================================================

class Layer2MLClassifier:
    """ML-based phishing detection using XGBoost"""
    
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.available = False
        self._load_model()
    
    def _load_model(self):
        """Load trained ML model"""
        try:
            import pickle
            import os
            
            if os.path.exists('phishing_model.pkl') and os.path.exists('feature_names.pkl'):
                with open('phishing_model.pkl', 'rb') as f:
                    self.model = pickle.load(f)
                
                with open('feature_names.pkl', 'rb') as f:
                    self.feature_names = pickle.load(f)
                
                self.available = True
                print("  ✅ Layer 2: ML Model loaded successfully")
            else:
                print("  ⚠️  Layer 2: ML model files not found (run train_ml_model.py)")
        except Exception as e:
            print(f"  ⚠️  Layer 2: Failed to load ML model: {e}")
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        import math
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log2(p) for p in prob if p > 0])
        return entropy
    
    def _extract_features(self, url):
        """Extract features matching training data"""
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
                'domain_entropy': self._calculate_entropy(domain),
                'digit_ratio': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
                'is_https': 1 if parsed.scheme == 'https' else 0,
                'num_query_params': len(query.split('&')) if query else 0,
                'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
                'subdomain_count': domain.count('.'),
                'has_at_symbol': 1 if '@' in url else 0,
            }
            
            # Return features in correct order
            return [features[name] for name in self.feature_names]
        except:
            return None
    
    def analyze(self, url: str) -> Tuple[float, List[str]]:
        """
        Analyze URL using ML model
        Returns: (score, reasons)
        """
        if not self.available:
            return 0.0, []
        
        try:
            import numpy as np
            
            # Extract features
            features = self._extract_features(url)
            if features is None:
                return 0.0, ['ML feature extraction failed']
            
            # Predict
            features_array = np.array(features).reshape(1, -1)
            probability = self.model.predict_proba(features_array)[0][1]  # Prob of phishing
            
            reasons = []
            if probability > 0.7:
                reasons.append(f'ML model: High phishing probability ({probability*100:.0f}%)')
            elif probability > 0.5:
                reasons.append(f'ML model: Moderate phishing risk ({probability*100:.0f}%)')
            elif probability > 0.3:
                reasons.append(f'ML model: Low phishing risk ({probability*100:.0f}%)')
            
            return probability, reasons
            
        except Exception as e:
            return 0.0, [f'ML analysis error: {str(e)}']

# ============================================================================
# LAYER 3: EXTERNAL VERIFICATION (~200ms)
# ============================================================================

class Layer3ExternalVerifier:
    """External API verification using VirusTotal, Google Safe Browsing, and WHOIS"""
    
    def __init__(self):
        import os
        from dotenv import load_dotenv
        
        load_dotenv()
        
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.google_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
        self.available = bool(self.virustotal_key or self.google_key)
        
        if self.available:
            print(f"  ✅ Layer 3: External verification available")
            if self.virustotal_key:
                print(f"    - VirusTotal API enabled")
            if self.google_key:
                print(f"    - Google Safe Browsing enabled")
        else:
            print(f"  ⚠️  Layer 3: No API keys configured")

    def _check_virustotal(self, url: str) -> Tuple[bool, int, int]:
        """
        Check URL against VirusTotal
        Returns: (is_malicious, positives, total_engines)
        """
        if not self.virustotal_key:
            return False, 0, 0
        
        try:
            import requests
            import base64
            
            # VirusTotal v3 API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                "x-apikey": self.virustotal_key
            }
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                positives = malicious + suspicious
                is_malicious = positives > 2  # If 3+ engines flag it
                
                return is_malicious, positives, total
            
            elif response.status_code == 404:
                # URL not in VT database - submit for analysis
                self._submit_to_virustotal(url)
                return False, 0, 0
            
            return False, 0, 0
            
        except Exception as e:
            return False, 0, 0

    def _submit_to_virustotal(self, url: str):
        """Submit URL to VirusTotal for scanning"""
        try:
            import requests
            
            headers = {
                "x-apikey": self.virustotal_key
            }
            
            data = {"url": url}
            
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=data,
                timeout=5
            )
        except:
            pass

    def _check_google_safe_browsing(self, url: str) -> Tuple[bool, List[str]]:
        """
        Check URL against Google Safe Browsing
        Returns: (is_threat, threat_types)
        """
        if not self.google_key:
            return False, []
        
        try:
            import requests
            
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_key}"
            
            payload = {
                "client": {
                    "clientId": "linkfort",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'matches' in data and len(data['matches']) > 0:
                    threat_types = [match['threatType'] for match in data['matches']]
                    return True, threat_types
            
            return False, []
            
        except Exception as e:
            return False, []

    def _check_domain_age(self, url: str) -> Tuple[bool, int]:
        """
        Check domain age using WHOIS
        Returns: (is_suspicious, age_in_days)
        """
        try:
            import whois
            from datetime import datetime
            
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if domain.startswith('www.'):
                domain = domain[4:]
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Skip if IP address
            if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
                return False, 0
            
            w = whois.whois(domain)
            
            if w.creation_date:
                # Handle list of dates (some domains return multiple)
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                
                age_days = (datetime.now() - creation_date).days
                
                # Domains less than 90 days old are suspicious
                is_suspicious = age_days < 90
                
                return is_suspicious, age_days
            
            return False, 0
            
        except Exception as e:
            return False, 0

    def analyze(self, url: str) -> Tuple[float, List[str]]:
        """
        Analyze URL using external APIs
        Returns: (score, reasons)
        """
        if not self.available:
            return 0.0, []
        
        score = 0.0
        reasons = []
        
        # Check VirusTotal
        if self.virustotal_key:
            is_malicious_vt, positives, total = self._check_virustotal(url)
            
            if is_malicious_vt and total > 0:
                score += 0.8
                reasons.append(f'VirusTotal: {positives}/{total} engines flagged as malicious')
            elif positives > 0 and total > 0:
                score += 0.3
                reasons.append(f'VirusTotal: {positives}/{total} engines suspicious')
        
        # Check Google Safe Browsing
        if self.google_key:
            is_threat_gsb, threat_types = self._check_google_safe_browsing(url)
            
            if is_threat_gsb:
                score += 0.9
                reasons.append(f'Google Safe Browsing: Flagged as {", ".join(threat_types)}')
        
        # Check Domain Age
        is_new_domain, age_days = self._check_domain_age(url)
        
        if is_new_domain and age_days > 0:
            score += 0.4
            reasons.append(f'Domain is only {age_days} days old (suspicious)')
        
        # Cap at 1.0
        score = min(score, 1.0)
        
        return score, reasons


# ============================================================================
# MAIN THREAT DETECTION ORCHESTRATOR
# ============================================================================

class ThreatDetector:
    """
    Orchestrates all 3 layers and calculates weighted final score
    Weights: Layer1=30%, Layer2=50%, Layer3=20%
    """
    
    def __init__(self):
        self.layer1 = Layer1PatternMatcher()
        self.layer2 = Layer2MLClassifier()
        self.layer3 = Layer3ExternalVerifier()
        
        print("🛡️  Threat Detection System initialized")
        print("  ✅ Layer 1: Pattern Matching (Active)")
        
        if self.layer2.available:
            print("  ✅ Layer 2: ML Classification (Active - XGBoost trained on real phishing data)")
        else:
            print("  ⏳ Layer 2: ML Classification (Not available)")
            
        if self.layer3.available:
            print("  ✅ Layer 3: External Verification (Active)")
        else:
            print("  ⏳ Layer 3: External Verification (No API keys configured)")
    
    def analyze(self, url: str) -> Tuple[float, str, Dict]:
        """
        Run URL through all available layers and return weighted score
        
        Returns:
            (final_score, verdict, details)
        """
        print(f"\n🔍 Analyzing URL: {url}")
        
        details = {
            'url': url,
            'layers': {},
            'final_score': 0.0,
            'verdict': 'SAFE',
            'all_reasons': []
        }
        
        # Layer 1: Pattern Matching (30% weight)
        print("  → Layer 1: Running pattern matching...")
        layer1_score, layer1_reasons = self.layer1.analyze(url)
        print(f"    Score: {layer1_score:.3f}, Reasons: {len(layer1_reasons)}")
        
        details['layers']['layer1'] = {
            'name': 'Pattern Matching',
            'score': layer1_score,
            'weight': 0.30,
            'reasons': layer1_reasons
        }
        details['all_reasons'].extend(layer1_reasons)
        
        # Layer 2: ML Classification (50% weight)
        print("  → Layer 2: Running ML classification...")
        layer2_score, layer2_reasons = self.layer2.analyze(url)
        print(f"    Score: {layer2_score:.3f}, Reasons: {len(layer2_reasons)}")
        
        details['layers']['layer2'] = {
            'name': 'ML Classification',
            'score': layer2_score,
            'weight': 0.50,
            'reasons': layer2_reasons,
            'status': 'active' if self.layer2.available else 'not_available'
        }
        if layer2_reasons:
            details['all_reasons'].extend(layer2_reasons)
        
        # Layer 3: External Verification (20% weight)
        print("  → Layer 3: Running external verification...")
        layer3_score, layer3_reasons = self.layer3.analyze(url)
        print(f"    Score: {layer3_score:.3f}, Reasons: {len(layer3_reasons)}")
        
        details['layers']['layer3'] = {
            'name': 'External Verification',
            'score': layer3_score,
            'weight': 0.20,
            'reasons': layer3_reasons,
            'status': 'active' if self.layer3.available else 'not_available'
        }
        if layer3_reasons:
            details['all_reasons'].extend(layer3_reasons)
        
        # Calculate weighted final score
        if self.layer2.available:
            final_score = (
                (layer1_score * 0.30) +
                (layer2_score * 0.50) +
                (layer3_score * 0.20)
            )
        else:
            final_score = layer1_score
        
        # Convert numpy types to Python native types
        final_score = float(final_score)
        layer1_score = float(layer1_score)
        layer2_score = float(layer2_score)
        layer3_score = float(layer3_score)
        
        details['final_score'] = round(final_score, 3)
        details['layers']['layer1']['score'] = float(layer1_score)
        details['layers']['layer2']['score'] = float(layer2_score)
        details['layers']['layer3']['score'] = float(layer3_score)
        
        # Determine verdict
        if final_score >= 0.7:
            verdict = 'BLOCK'
        elif final_score >= 0.3:
            verdict = 'WARN'
        else:
            verdict = 'SAFE'
        
        details['verdict'] = verdict
        
        print(f"  ✅ Final Score: {final_score:.3f} ({verdict})")
        print(f"  📊 Breakdown: L1={layer1_score:.2f}×30% + L2={layer2_score:.2f}×50% + L3={layer3_score:.2f}×20%")
        
        return final_score, verdict, details


# ============================================================================
# INITIALIZATION & PUBLIC API
# ============================================================================

# Global detector instance
detector = None

def init_threat_detection():
    """Initialize the threat detection system"""
    global detector
    detector = ThreatDetector()

def calculate_threat_score(url: str) -> Tuple[float, str, Dict]:
    """
    Public API: Calculate threat score for a URL
    
    Returns:
        (score, verdict, details)
        score: 0.0 (safe) to 1.0 (malicious)
        verdict: 'SAFE', 'WARN', or 'BLOCK'
        details: dict with full analysis breakdown
    """
    global detector
    
    if detector is None:
        init_threat_detection()
    
    return detector.analyze(url)