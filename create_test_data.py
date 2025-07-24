#!/usr/bin/env python3
"""
create_test_data.py - Create sample URL files for testing
This creates basic test files to get started quickly
"""

import os
import random

# Sample benign URLs (from thesis requirements)
benign_urls = [
    # Universities
    "https://www.harvard.edu",
    "https://www.mit.edu",
    "https://www.stanford.edu",
    "https://www.ox.ac.uk",
    "https://www.cam.ac.uk",
    "https://www.mtu.ie",

    # News sites
    "https://www.bbc.com",
    "https://www.reuters.com",
    "https://www.apnews.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.theguardian.com",

    # Popular sites (would be from Cisco Umbrella Top 1M)
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.reddit.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.github.com",

    # More educational
    "https://www.coursera.org",
    "https://www.edx.org",
    "https://www.khanacademy.org",

    # Technology
    "https://www.stackoverflow.com",
    "https://www.medium.com",
    "https://www.techcrunch.com",
]

# Sample malicious URLs (EXAMPLES ONLY - DO NOT VISIT)
# In production, get these from PhishTank, OpenPhish, VirusTotal
malicious_urls = [
    # Example phishing URLs (NOT REAL - for testing only)
    "http://phishing-paypal-example.com/login",
    "http://fake-amazon-login.net/account",
    "http://scam-bank-site.org/verify",
    "http://malicious-download.com/trojan.exe",
    "http://phishing-microsoft.net/office365",
    "http://fake-apple-id.com/locked",
    "http://scam-netflix.org/payment",
    "http://phishing-ebay.net/item",
    "http://malware-host.com/backdoor",
    "http://fake-google-docs.net/share",

    # More examples
    "http://suspicious-redirect.com/click",
    "http://malware-dropper.net/install",
    "http://phishing-facebook.org/verify",
    "http://scam-irs-site.com/refund",
    "http://fake-ups-tracking.net/package",
]

def create_url_files():
    """Create test URL files"""

    # Create benign URLs file
    with open('benign_urls.txt', 'w') as f:
        f.write("# Benign URLs for testing\n")
        f.write("# Generated for URL Malware Detection Proxy testing\n\n")
        for url in benign_urls:
            f.write(f"{url}\n")

    print(f"Created benign_urls.txt with {len(benign_urls)} URLs")

    # Create malicious URLs file
    with open('malicious_urls.txt', 'w') as f:
        f.write("# Malicious URLs for testing (EXAMPLES ONLY - DO NOT VISIT)\n")
        f.write("# In production, use real threat intelligence feeds\n\n")
        for url in malicious_urls:
            f.write(f"{url}\n")

    print(f"Created malicious_urls.txt with {len(malicious_urls)} URLs")

    # Create mixed file for performance testing
    mixed_urls = benign_urls[:20] + malicious_urls[:5]  # 80% benign, 20% malicious
    random.shuffle(mixed_urls)

    with open('mixed_urls.txt', 'w') as f:
        f.write("# Mixed URLs for performance testing\n")
        f.write("# 80% benign, 20% malicious\n\n")
        for url in mixed_urls:
            f.write(f"{url}\n")

    print(f"Created mixed_urls.txt with {len(mixed_urls)} URLs")

    # Create requirements.txt for easy setup
    with open('requirements.txt', 'w') as f:
        f.write("requests>=2.25.0\n")
        f.write("pandas>=1.2.0\n")
        f.write("numpy>=1.20.0\n")
        f.write("psutil>=5.8.0\n")
        f.write("aiohttp>=3.7.0\n")

    print("\nCreated requirements.txt")

    # Create a simple run script
    with open('run_test.sh', 'w') as f:
        f.write("#!/bin/bash\n\n")
        f.write("# Simple test runner\n")
        f.write("# Usage: ./run_test.sh [proxy_host] [proxy_port]\n\n")
        f.write("PROXY_HOST=${1:-localhost}\n")
        f.write("PROXY_PORT=${2:-8080}\n\n")
        f.write("echo \"Testing proxy at $PROXY_HOST:$PROXY_PORT\"\n\n")
        f.write("python proxy_tester.py \\\n")
        f.write("    --proxy-host $PROXY_HOST \\\n")
        f.write("    --proxy-port $PROXY_PORT \\\n")
        f.write("    --malicious-urls malicious_urls.txt \\\n")
        f.write("    --benign-urls benign_urls.txt \\\n")
        f.write("    --test-type both \\\n")
        f.write("    --workers 10 \\\n")
        f.write("    --duration 60 \\\n")
        f.write("    --target-rps 50\n")

    os.chmod('run_test.sh', 0o755)
    print("Created run_test.sh (executable)")

    print("\n" + "="*50)
    print("Setup complete! To run tests:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Make sure your proxy is running")
    print("3. Run quick test: python quick_test_example.py")
    print("4. Or run full test: ./run_test.sh [proxy_host] [proxy_port]")
    print("="*50)

if __name__ == "__main__":
    create_url_files()
