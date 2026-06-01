#!/usr/bin/env python3
import re
import sys
from urllib.parse import urlparse

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
WHITE = '\033[97m'
GRAY = '\033[90m'
RESET = '\033[0m'

class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'secure', 'update', 'confirm',
            'signin', 'authenticate', 'validate', 'unlock', 'alert',
            'security', 'warning', 'notification', 'suspended', 'limited'
        ]
        
        self.suspicious_domains = [
            'rnicrosoft.com', 'googgle.com', 'faceb00k.com', 'amaz0n.com',
            'paypal-safety.com', 'appleid.com', 'microsoft-verify.com'
        ]
        
        self.good_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'github.com', 'reddit.com',
            'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com'
        ]
    
    def check_url(self, url):
        results = []
        score = 0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
        except:
            return {'score': 100, 'findings': ['Invalid URL format'], 'safe': False}
        
        if parsed.scheme != 'https':
            results.append('No HTTPS (insecure connection)')
            score += 20
        
        for keyword in self.suspicious_keywords:
            if keyword in domain:
                results.append(f'Suspicious keyword in domain: {keyword}')
                score += 25
                break
        
        for keyword in self.suspicious_keywords:
            if keyword in path:
                results.append(f'Suspicious keyword in path: {keyword}')
                score += 15
                break
        
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            results.append('IP address used instead of domain name')
            score += 40
        
        for suspicious in self.suspicious_domains:
            if suspicious in domain:
                results.append(f'Known suspicious domain pattern: {suspicious}')
                score += 50
                break
        
        subdomain_count = domain.count('.')
        if subdomain_count > 2:
            results.append('Many subdomains (possible fake)')
            score += 15
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        for shortener in shorteners:
            if shortener in domain:
                results.append(f'URL shortener used: {shortener}')
                score += 30
                break
        
        if '@' in url:
            results.append('Contains @ symbol (phishing technique)')
            score += 50
        
        parts = domain.split('.')
        if len(parts) >= 3:
            for good in self.good_domains:
                if good in domain and not domain.endswith(good):
                    results.append(f'Misleading: contains {good} but is not {good}')
                    score += 60
                    break
        
        if score >= 60:
            safe = False
            verdict = 'DANGEROUS'
            verdict_color = RED
        elif score >= 30:
            safe = False
            verdict = 'SUSPICIOUS'
            verdict_color = YELLOW
        else:
            safe = True
            verdict = 'SAFE'
            verdict_color = GREEN
        
        return {
            'score': score,
            'findings': results,
            'safe': safe,
            'verdict': verdict,
            'verdict_color': verdict_color,
            'domain': domain
        }

def main():
    print(f"{WHITE}{'='*60}{RESET}")
    print(f"{GREEN}        PHISHING URL DETECTOR{RESET}")
    print(f"{WHITE}{'='*60}{RESET}")
    print()
    
    detector = PhishingDetector()
    
    while True:
        print(f"{YELLOW}Enter URL to check (or 'quit'):{RESET}")
        url = input(f"{WHITE}> {RESET}").strip()
        
        if url.lower() == 'quit':
            print(f"{GREEN}Goodbye!{RESET}")
            break
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        print()
        
        result = detector.check_url(url)
        
        print(f"{WHITE}{'='*60}{RESET}")
        print(f"URL: {result['domain']}")
        print(f"Verdict: {result['verdict_color']}{result['verdict']}{RESET}")
        print(f"Risk score: {result['score']}/100")
        
        if result['findings']:
            print()
            for finding in result['findings']:
                print(f"  {RED}!{RESET} {finding}")
        
        if not result['safe']:
            print()
            print(f"{RED}[WARNING] Do not enter personal information on this site{RESET}")
        
        print(f"{WHITE}{'='*60}{RESET}")
        print()

if __name__ == "__main__":
    main()