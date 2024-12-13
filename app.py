from flask import Flask, request, render_template, jsonify
import requests
import socket
from urllib.parse import urlparse
import re  # For XSS and SQL Injection detection simulations

app = Flask(__name__)


# Function to detect SQL Injection (Improved mechanism)
def detect_sql_injection(url):
    # List of SQL injection patterns
    suspicious_payloads = [
        "' OR 1=1 --", "' OR '1'='1", "\" OR \"1\"=\"1", ";--", "--", "UNION SELECT", "DROP TABLE", "SELECT * FROM"
    ]

    for payload in suspicious_payloads:
        if re.search(re.escape(payload), url, re.IGNORECASE):  # Case-insensitive matching
            return "Potential SQL Injection detected"

    return "No SQL Injection detected"


# Function to detect XSS (Improved mechanism)
def detect_xss(url):
    # Common XSS payloads (strengthened detection)
    patterns = ["<script", "alert", "<img", "onerror"]
    for pattern in patterns:
        if pattern in input.lower():
            return True  # XSS indication
    return False

    xss_payloads = [
        "<script>", "</script>", "onerror=", "alert(", "<img src=", "<iframe", "document.cookie", "eval("
    ]

    for payload in xss_payloads:
        if re.search(re.escape(payload), url.lower(), re.IGNORECASE):  # Case-insensitive matching
            return "Potential XSS vulnerability detected"

    return "No XSS detected"


# Function to detect CSRF (Basic mechanism simulation)
def detect_csrf(url):
    # CSRF requires a form with specific request methods, so manual verification is advised
    return "CSRF detection is beyond URL scanning. Use manual analysis."


# Function to detect Open Redirect (Improved detection)
def detect_open_redirect(url):
    # Common patterns that suggest open redirects
    open_redirect_patterns = ["//", "http://", "https://", "www."]

    # Check if the URL might redirect to an external site
    if any(pattern in url.lower() for pattern in open_redirect_patterns):
        return "Potential Open Redirect vulnerability detected"

    return "No Open Redirect detected"


# Function to get URL details (with error handling)
def get_url_details(url):
    try:
        hostname = urlparse(url).hostname
        ip_address = socket.gethostbyname(hostname)
        # Use IPInfo API to fetch headquarters (replace 'your_api_token' with an actual token)
        response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=24ef2ca606de65")

        if response.status_code == 200:
            data = response.json()
            headquarters = data.get("org", "Unknown Headquarters")
        else:
            headquarters = "Unknown Headquarters"

        return {"ip_address": ip_address, "headquarters": headquarters}

    except Exception as e:
        return {"ip_address": "Unknown", "headquarters": "Unknown", "error": str(e)}


@app.route('/')
def home():
    return render_template('index.html')  # Render your HTML file


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    vulnerability = request.form.get('vulnerability')

    if not url:
        return jsonify({"error": "URL is required"})

    try:
        # Get URL details
        url_details = get_url_details(url)

        # Detect vulnerabilities based on the user's choice
        scan_result = {}
        if vulnerability == 'sql_injection':
            scan_result['sql_injection'] = detect_sql_injection(url)
        elif vulnerability == 'xss':
            scan_result['xss'] = detect_xss(url)
        elif vulnerability == 'csrf':
            scan_result['csrf'] = detect_csrf(url)
        elif vulnerability == 'open_redirect':
            scan_result['open_redirect'] = detect_open_redirect(url)

        # Simulate a vulnerability summary
        vulnerability_summary = {
            "risk_level": "Medium" if any("Potential" in result for result in scan_result.values()) else "Low"
        }

        return render_template(
            'index.html',
            scan_result=scan_result,
            url_details=url_details,
            vulnerability_summary=vulnerability_summary
        )

    except Exception as e:
        return render_template('index.html', error=str(e))


if __name__ == '__main__':
    app.run(debug=True)
