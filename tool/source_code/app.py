from flask import Flask, render_template, request, jsonify, send_file
from phishing_detector import PhishingDetector
import os
import re
from urllib.parse import urlparse
import tldextract
import logging
import email
from advanced_checks import advanced_analysis
from fpdf import FPDF
import io
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
detector = PhishingDetector()

def extract_urls(text):
    # Extract URLs from text
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    logger.debug(f"Extracted URLs: {urls}")
    return urls

def analyze_url(url):
    try:
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic URL analysis
        analysis = {
            'url': url,
            'domain': extracted.domain,
            'tld': extracted.tld,
            'subdomain': extracted.subdomain,
            'is_https': parsed.scheme == 'https',
            'path_length': len(parsed.path),
            'has_parameters': bool(parsed.query),
            'suspicious_patterns': []
        }
        
        # Check for suspicious patterns
        if len(parsed.path) > 50:
            analysis['suspicious_patterns'].append('Long URL path')
        if extracted.subdomain and len(extracted.subdomain) > 10:
            analysis['suspicious_patterns'].append('Suspicious subdomain')
        if not analysis['is_https']:
            analysis['suspicious_patterns'].append('Not using HTTPS')
            
        logger.debug(f"URL analysis result: {analysis}")
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing URL {url}: {str(e)}")
        return {'url': url, 'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    try:
        email_content = request.json.get('email_content', '')
        if not email_content:
            return jsonify({'error': 'No email content provided'}), 400
        logger.debug(f"Received email content: {email_content[:100]}...")
        
        # Analyze the email
        result = detector.analyze_email(email_content)
        logger.debug(f"Base analysis result: {result}")
        
        # Extract and analyze URLs
        urls = extract_urls(email_content)
        url_analysis = [analyze_url(url) for url in urls]
        logger.debug(f"URL analysis results: {url_analysis}")
        
        # Add URL analysis to the result
        result['url_analysis'] = url_analysis
        
        # Advanced checks
        advanced_findings = advanced_analysis(email_content, email_content)
        result['advanced_findings'] = advanced_findings
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in analyze_email: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/report', methods=['POST'])
def generate_report():
    try:
        data = request.json
        email_content = data.get('email_content', '')
        result = data.get('result', {})
        url_analysis = result.get('url_analysis', [])
        advanced_findings = result.get('advanced_findings', [])
        risk_score = result.get('risk_score', 'N/A')
        is_phishing = result.get('is_phishing', False)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Phishing Email Analysis Report', ln=True, align='C')
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Generated: {timestamp}', ln=True)
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Email Content:', ln=True)
        pdf.set_font('Arial', '', 11)
        pdf.multi_cell(0, 8, email_content)
        pdf.ln(3)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Risk Score:', ln=True)
        pdf.set_font('Arial', '', 11)
        pdf.cell(0, 10, f'{risk_score}/100', ln=True)
        pdf.cell(0, 10, f'Phishing Verdict: {"Phishing" if is_phishing else "Legitimate"}', ln=True)
        pdf.ln(3)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Advanced Findings:', ln=True)
        pdf.set_font('Arial', '', 11)
        if advanced_findings:
            for finding in advanced_findings:
                pdf.multi_cell(0, 8, f'- {finding}')
        else:
            pdf.cell(0, 10, 'None', ln=True)
        pdf.ln(3)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'URL Analysis:', ln=True)
        pdf.set_font('Arial', '', 11)
        if url_analysis:
            for url in url_analysis:
                pdf.multi_cell(0, 8, f"URL: {url.get('url', '')}")
                pdf.multi_cell(0, 8, f"  Domain: {url.get('domain', '')}.{url.get('tld', '')}")
                pdf.multi_cell(0, 8, f"  HTTPS: {url.get('is_https', False)}")
                if url.get('suspicious_patterns'):
                    for pattern in url['suspicious_patterns']:
                        pdf.multi_cell(0, 8, f"  Suspicious: {pattern}")
                pdf.ln(1)
        else:
            pdf.cell(0, 10, 'No URLs found.', ln=True)
        pdf_bytes = pdf.output(dest='S').encode('latin1')
        pdf_output = io.BytesIO(pdf_bytes)
        return send_file(pdf_output, as_attachment=True, download_name='phishing_report.pdf', mimetype='application/pdf')
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 