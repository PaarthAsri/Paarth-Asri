# Phishing Email Detection Tool

This directory contains the implementation of our advanced phishing email detection system.

## Directory Structure

```
📁 tool/
├── 📁 source_code/
│   ├── app.py              # Flask web application
│   ├── advanced_checks.py  # Advanced detection algorithms
│   ├── phishing_detector.py # Core detection logic
│   ├── templates/          # Web interface templates
│   ├── static/            # Static assets (CSS, JS, images)
│   └── test_emails/       # Sample emails for testing
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Setup

1. Ensure you have Python 3.8 or higher installed
2. Create a virtual environment (recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Web Interface

1. Start the web server:
   ```
   python source_code/app.py
   ```
2. Open your browser and navigate to `http://localhost:5000`

### Command Line Interface

1. Analyze a single email:
   ```
   python source_code/phishing_detector.py --email "path/to/email.txt"
   ```
2. Analyze multiple emails:
   ```
   python source_code/phishing_detector.py --directory "path/to/emails"
   ```

## Features

- Real-time email analysis
- Advanced header inspection
- Content-based detection
- URL validation
- Behavioral pattern analysis
- Detailed threat reports

## Testing

Sample emails are provided in the `test_emails` directory for testing purposes. 