import re
import socket
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from database import save_scan
from email_checker import verify_email_advanced
from url_checker import analyze_url_comprehensive

app = Flask(__name__)

def analyze_url(url):
    return analyze_url_comprehensive(url.strip())

def analyze_email(email):
    return verify_email_advanced(email.strip())


def build_url_report(url):
    normalized_url = url.strip()
    if not normalized_url.startswith(('http://', 'https://')):
        normalized_url = 'http://' + normalized_url

    parsed = urlparse(normalized_url)
    status, score, details = analyze_url(normalized_url)
    hostname = parsed.hostname or ''
    ip_address = 'Unavailable'
    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        pass

    abuse_match = re.search(r'AbuseIPDB: Confidence (\d+)% \((\d+) reports\)', details)
    redirect_match = re.search(r'Redirect: (\d+) hop\(s\) detected\. Final URL: (.+?)(?: \| |$)', details)
    age_match = re.search(r'WHOIS: Domain is approximately (\d+) days old', details)
    keyword_match = re.search(r'Heuristic: Suspicious keywords found: (.+?)(?: \| |$)', details)
    ssl_match = re.search(r'SSL: Certificate is valid\. Expires in approximately (\d+) days', details)
    no_redirects = 'Redirect: No redirects detected.' in details

    return {
        'url': normalized_url,
        'status': status,
        'score': score,
        'domain': hostname,
        'ip_address': ip_address,
        'protocol': parsed.scheme,
        'is_https': parsed.scheme == 'https',
        'abuse_available': abuse_match is not None,
        'abuse_confidence': int(abuse_match.group(1)) if abuse_match else None,
        'abuse_reports': int(abuse_match.group(2)) if abuse_match else None,
        'ssl_valid': ssl_match is not None,
        'ssl_expiry_days': int(ssl_match.group(1)) if ssl_match else None,
        'redirect_count': 0 if no_redirects else (int(redirect_match.group(1)) if redirect_match else None),
        'final_url': redirect_match.group(2) if redirect_match else normalized_url,
        'redirect_chain': [normalized_url, redirect_match.group(2)] if redirect_match else [],
        'domain_age_days': int(age_match.group(1)) if age_match else None,
        'suspicious_keywords': [item.strip() for item in keyword_match.group(1).split(',')] if keyword_match else [],
        'details': details,
    }

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/result')
def result():
    url = request.args.get('url', '').strip()
    if not url:
        return render_template('index.html')
    return render_template('result.html', **build_url_report(url))

@app.route('/api/check-url', methods=['POST'])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    if not isinstance(url, str):
        return jsonify({"error": "URL must be text."}), 400
    url = url.strip()
    status, score, details = analyze_url(url)
    save_scan('url', url, status, details)
    return jsonify({"status": status, "score": score, "details": details})

@app.route('/api/check-email', methods=['POST'])
def check_email():
    data = request.get_json(silent=True) or {}
    email = data.get('email', '')
    if not isinstance(email, str):
        return jsonify({"error": "Email must be text."}), 400
    email = email.strip()
    status, score, details = analyze_email(email)
    save_scan('email', email, status, details)
    return jsonify({"status": status, "score": score, "details": details})

if __name__ == '__main__':
    app.run(debug=True)