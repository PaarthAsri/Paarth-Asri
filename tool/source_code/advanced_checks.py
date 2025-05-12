import re
import email
import tldextract
import idna
from email.header import decode_header
from urllib.parse import urlparse

FREE_EMAIL_DOMAINS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com', 'protonmail.com'
]
SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly'
]
DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.jar', '.js', '.vbs', '.wsf', '.docm', '.xlsm']
GENERIC_GREETINGS = [r'dear (customer|user|member|client|friend)', r'hello (there)?', r'hi (there)?']
SENSITIVE_KEYWORDS = [r'password', r'ssn', r'social security', r'bank account', r'credit card', r'login', r'pin']
CLICK_DOWNLOAD_KEYWORDS = [r'click here', r'download now', r'open attachment', r'access (your|the) account']
TOO_GOOD_TO_BE_TRUE = [r'won.*\$?\d+', r'free.*gift', r'congratulations.*winner', r'lottery', r'prize']

# Helper: Levenshtein distance for lookalike domains

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

# Header & Metadata Analysis
def analyze_headers(raw_email):
    findings = []
    msg = email.message_from_string(raw_email)
    from_addr = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    received_spf = msg.get('Received-SPF', '')
    dkim = msg.get('DKIM-Signature', '')
    dmarc = msg.get('Authentication-Results', '')
    
    # Decode From
    name, addr = email.utils.parseaddr(from_addr)
    domain = addr.split('@')[-1].lower() if '@' in addr else ''
    
    # Free/suspicious domain
    if domain in FREE_EMAIL_DOMAINS:
        findings.append(f"Sender uses free/suspicious domain: {domain}")
    # Mismatched name/domain
    if name and domain and name.lower() not in domain:
        findings.append(f"Sender name and domain mismatch: {name} <{domain}>")
    # Reply-To mismatch
    if reply_to and reply_to != from_addr:
        findings.append(f"Reply-To address differs from From address: {reply_to}")
    # SPF/DKIM/DMARC
    if not received_spf or 'fail' in received_spf.lower():
        findings.append("SPF missing or failed")
    if not dkim:
        findings.append("DKIM missing")
    if not dmarc or 'fail' in dmarc.lower():
        findings.append("DMARC missing or failed")
    return findings

# Content-Based Analysis
def analyze_content(text):
    findings = []
    # Urgency/Threats
    if re.search(r'urgent|immediate|action required|suspend|blocked|failure to act', text, re.I):
        findings.append("Urgency or threat language detected")
    # Too good to be true
    for pattern in TOO_GOOD_TO_BE_TRUE:
        if re.search(pattern, text, re.I):
            findings.append("Too good to be true offer detected")
    # Spelling/grammar (very basic)
    if len(re.findall(r'\b[a-z]{1,2}\b', text, re.I)) > 10:
        findings.append("Possible spelling/grammar errors detected")
    # Generic greetings
    for pattern in GENERIC_GREETINGS:
        if re.search(pattern, text, re.I):
            findings.append("Generic greeting detected")
    # Sensitive info request
    for pattern in SENSITIVE_KEYWORDS:
        if re.search(pattern, text, re.I):
            findings.append("Request for sensitive information detected")
    # Click/download
    for pattern in CLICK_DOWNLOAD_KEYWORDS:
        if re.search(pattern, text, re.I):
            findings.append("Call to click or download detected")
    return findings

# URL and Link Inspection
def analyze_urls(text):
    findings = []
    url_pattern = r'http[s]?://[^\s\)\"]+'
    urls = re.findall(url_pattern, text)
    for url in urls:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        # Shortener
        if any(short in url for short in SHORTENER_DOMAINS):
            findings.append(f"URL shortener used: {url}")
        # IP address
        if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
            findings.append(f"URL uses IP address: {url}")
        # Lookalike domain
        for legit in ['paypal', 'amazon', 'apple', 'microsoft', 'bank', 'google']:
            if ext.domain and levenshtein(ext.domain, legit) == 1:
                findings.append(f"Lookalike domain detected: {url}")
        # IDN
        if 'xn--' in ext.domain:
            findings.append(f"Internationalized domain (IDN) detected: {url}")
    return findings

# Attachment Analysis
def analyze_attachments(msg):
    findings = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if filename and any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                findings.append(f"Suspicious attachment: {filename}")
    return findings

# Main advanced analysis function
def advanced_analysis(raw_email, plain_text):
    findings = []
    # Header analysis
    findings.extend(analyze_headers(raw_email))
    # Content analysis
    findings.extend(analyze_content(plain_text))
    # URL analysis
    findings.extend(analyze_urls(plain_text))
    # Attachment analysis
    msg = email.message_from_string(raw_email)
    findings.extend(analyze_attachments(msg))
    return findings 