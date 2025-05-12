import re
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

class PhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.classifier = RandomForestClassifier(n_estimators=100)
        self.suspicious_patterns = [
            r'urgent.*action',
            r'verify.*account',
            r'click.*here',
            r'password.*expired',
            r'account.*suspended',
            r'security.*breach',
            r'confirm.*details',
            r'limited.*time',
            r'free.*gift',
            r'bank.*account'
        ]
        
    def extract_features(self, text):
        # Check for suspicious patterns
        pattern_matches = sum(1 for pattern in self.suspicious_patterns 
                            if re.search(pattern, text.lower()))
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediate', 'asap', 'now', 'today']
        urgency_count = sum(1 for word in urgency_words 
                           if word in text.lower())
        
        # Check for URL patterns
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        suspicious_urls = sum(1 for url in urls if self._is_suspicious_url(url))
        
        return {
            'pattern_matches': pattern_matches,
            'urgency_count': urgency_count,
            'suspicious_urls': suspicious_urls,
            'text_length': len(text)
        }
    
    def _is_suspicious_url(self, url):
        # Check for common phishing URL patterns
        suspicious_domains = ['login', 'verify', 'account', 'secure', 'bank']
        return any(domain in url.lower() for domain in suspicious_domains)
    
    def analyze_email(self, email_text):
        features = self.extract_features(email_text)
        
        # Calculate risk score (0-100)
        risk_score = (
            features['pattern_matches'] * 20 +
            features['urgency_count'] * 15 +
            features['suspicious_urls'] * 25
        )
        risk_score = min(100, risk_score)
        
        return {
            'risk_score': risk_score,
            'is_phishing': risk_score > 70,
            'features': features
        }
    
    def analyze_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                email_text = f.read()
            return self.analyze_email(email_text)
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Phishing Email Detector')
    parser.add_argument('--email', help='Path to email file to analyze')
    parser.add_argument('--directory', help='Path to directory containing emails to analyze')
    args = parser.parse_args()
    
    detector = PhishingDetector()
    
    if args.email:
        result = detector.analyze_file(args.email)
        if result:
            print(f"\nAnalysis for {args.email}:")
            print(f"Risk Score: {result['risk_score']}/100")
            print(f"Phishing Detected: {'Yes' if result['is_phishing'] else 'No'}")
            print("\nFeature Analysis:")
            for feature, value in result['features'].items():
                print(f"- {feature}: {value}")
    
    elif args.directory:
        directory = Path(args.directory)
        if not directory.exists():
            print(f"Directory {args.directory} does not exist")
            return
        
        for file_path in directory.glob('*.txt'):
            result = detector.analyze_file(file_path)
            if result:
                print(f"\nAnalysis for {file_path}:")
                print(f"Risk Score: {result['risk_score']}/100")
                print(f"Phishing Detected: {'Yes' if result['is_phishing'] else 'No'}")
    
    else:
        print("Please provide either --email or --directory argument")
        parser.print_help()

if __name__ == "__main__":
    main() 