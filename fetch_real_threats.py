#!/usr/bin/env python3
"""
Quick fix version - bypasses all proxy settings
"""

import os
# Clear ALL proxy settings before importing requests
for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy']:
    os.environ.pop(var, None)

import requests
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_threats():
    """Quick fetch of malicious URLs"""
    print("Fetching real malicious URLs (proxy bypassed)...")

    malicious_urls = []

    # Try OpenPhish
    try:
        print("Trying OpenPhish...")
        resp = requests.get("https://openphish.com/feed.txt", timeout=10)
        if resp.status_code == 200:
            urls = resp.text.strip().split('\n')[:50]
            malicious_urls.extend([u.strip() for u in urls if u.strip()])
            print(f"✓ Got {len(urls)} URLs from OpenPhish")
    except Exception as e:
        print(f"✗ OpenPhish failed: {e}")

    # Try URLhaus
    try:
        print("Trying URLhaus...")
        resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=10)
        if resp.status_code == 200:
            lines = resp.text.strip().split('\n')[9:59]  # Skip headers, get 50
            for line in lines:
                if line and not line.startswith('#'):
                    parts = line.split('","')
                    if len(parts) >= 3:
                        url = parts[2].strip('"')
                        if url.startswith('http'):
                            malicious_urls.append(url)
            print(f"✓ Got {len(malicious_urls)} total URLs")
    except Exception as e:
        print(f"✗ URLhaus failed: {e}")

    # Save malicious URLs
    with open('real_malicious_urls.txt', 'w') as f:
        f.write(f"# Real malicious URLs - Generated {datetime.now()}\n")
        f.write("# WARNING: These are REAL threats!\n\n")
        for url in set(malicious_urls):  # Remove duplicates
            f.write(f"{url}\n")

    # Create benign URLs
    benign_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.facebook.com",
        "https://www.youtube.com",
        "https://www.wikipedia.org",
        "https://www.github.com",
        "https://www.stackoverflow.com",
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.reuters.com",
        "https://www.harvard.edu",
        "https://www.mit.edu",
        "https://www.stanford.edu",
        "https://www.python.org",
        "https://www.docker.com",
        "https://www.kubernetes.io",
        "https://www.reddit.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.zoom.us",
        "https://www.slack.com",
    ]

    with open('real_benign_urls.txt', 'w') as f:
        f.write(f"# Benign URLs - Generated {datetime.now()}\n\n")
        for url in benign_urls:
            f.write(f"{url}\n")

    print(f"\n✓ Created real_malicious_urls.txt with {len(set(malicious_urls))} URLs")
    print(f"✓ Created real_benign_urls.txt with {len(benign_urls)} URLs")
    print("\nNow run: python proxy_tester.py --proxy-host localhost --proxy-port 65080 --malicious-urls real_malicious_urls.txt --benign-urls real_benign_urls.txt --test-type both")

if __name__ == "__main__":
    fetch_threats()
