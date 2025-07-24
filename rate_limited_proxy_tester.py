#!/usr/bin/env python3
"""
rate_limited_proxy_tester.py - Test proxy with API rate limits in mind
Designed for VirusTotal's 4 requests/minute limit
"""

import time
import requests
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Tuple
import random

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RateLimitedProxyTester:
    def __init__(self, proxy_host: str, proxy_port: int, requests_per_minute: int = 4):
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.requests_per_minute = requests_per_minute
        self.delay_between_requests = 60.0 / requests_per_minute + 1  # Add 1 second buffer
        self.results = {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'latencies': [],
            'timestamps': []
        }

    def load_limited_datasets(self, malicious_file: str, benign_file: str,
                             malicious_limit: int = 10, benign_limit: int = 10) -> Tuple[List[Dict], List[Dict]]:
        """Load limited number of URLs for testing"""
        malicious_urls = []
        benign_urls = []

        # Load malicious URLs
        logger.info(f"Loading up to {malicious_limit} malicious URLs...")
        try:
            with open(malicious_file, 'r') as f:
                all_malicious = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                # Take a random sample to get variety
                if len(all_malicious) > malicious_limit:
                    selected = random.sample(all_malicious, malicious_limit)
                else:
                    selected = all_malicious
                malicious_urls = [{'url': url, 'label': 'malicious'} for url in selected]
        except Exception as e:
            logger.error(f"Error loading malicious URLs: {e}")

        # Load benign URLs
        logger.info(f"Loading up to {benign_limit} benign URLs...")
        try:
            with open(benign_file, 'r') as f:
                all_benign = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if len(all_benign) > benign_limit:
                    selected = random.sample(all_benign, benign_limit)
                else:
                    selected = all_benign
                benign_urls = [{'url': url, 'label': 'benign'} for url in selected]
        except Exception as e:
            logger.error(f"Error loading benign URLs: {e}")

        logger.info(f"Loaded {len(malicious_urls)} malicious and {len(benign_urls)} benign URLs")
        return malicious_urls, benign_urls

    def test_url(self, url: str, expected_label: str) -> Dict:
        """Test a single URL through the proxy"""
        proxies = {
            'http': self.proxy_url,
            'https': self.proxy_url
        }

        start_time = time.time()
        result = {
            'url': url,
            'expected': expected_label,
            'actual': None,
            'latency': None,
            'status_code': None,
            'error': None
        }

        try:
            response = requests.get(
                url,
                proxies=proxies,
                timeout=30,
                allow_redirects=False,
                verify=False
            )
            end_time = time.time()

            result['latency'] = (end_time - start_time) * 1000
            result['status_code'] = response.status_code

            # Check if blocked
            blocked = False
            if response.status_code == 403:
                blocked = True
            elif response.text:
                body_lower = response.text.lower()
                if any(indicator in body_lower for indicator in
                       ['security warning', 'potentially malicious', 'virustotal:',
                        'safe browsing:', 'scamadviser:']):
                    blocked = True

            result['actual'] = 'malicious' if blocked else 'benign'

        except Exception as e:
            end_time = time.time()
            result['latency'] = (end_time - start_time) * 1000
            result['error'] = str(e)
            result['actual'] = 'error'

        # Update metrics
        self._update_metrics(result)
        return result

    def _update_metrics(self, result: Dict):
        """Update confusion matrix metrics"""
        if result['actual'] == 'error':
            return

        if result['expected'] == 'malicious' and result['actual'] == 'malicious':
            self.results['true_positives'] += 1
        elif result['expected'] == 'malicious' and result['actual'] == 'benign':
            self.results['false_negatives'] += 1
        elif result['expected'] == 'benign' and result['actual'] == 'benign':
            self.results['true_negatives'] += 1
        elif result['expected'] == 'benign' and result['actual'] == 'malicious':
            self.results['false_positives'] += 1

        if result['latency']:
            self.results['latencies'].append(result['latency'])
            self.results['timestamps'].append(time.time())

    def run_rate_limited_test(self, urls: List[Dict]) -> List[Dict]:
        """Run test with rate limiting"""
        total_urls = len(urls)
        estimated_time = total_urls * self.delay_between_requests / 60

        logger.info(f"Starting rate-limited test with {total_urls} URLs")
        logger.info(f"Rate limit: {self.requests_per_minute} requests/minute")
        logger.info(f"Delay between requests: {self.delay_between_requests:.1f} seconds")
        logger.info(f"Estimated time: {estimated_time:.1f} minutes")

        all_results = []
        start_time = time.time()

        for i, url_data in enumerate(urls):
            # Test URL
            logger.info(f"Testing {i+1}/{total_urls}: {url_data['url'][:50]}...")
            result = self.test_url(url_data['url'], url_data['label'])
            all_results.append(result)

            # Show progress
            if result['actual'] == 'malicious':
                logger.info(f"  → BLOCKED (Status: {result['status_code']})")
            elif result['actual'] == 'benign':
                logger.info(f"  → ALLOWED (Status: {result['status_code']})")
            else:
                logger.info(f"  → ERROR: {result['error']}")

            # Rate limiting delay (except for last URL)
            if i < total_urls - 1:
                logger.debug(f"Waiting {self.delay_between_requests:.1f}s for rate limit...")
                time.sleep(self.delay_between_requests)

        elapsed_time = time.time() - start_time
        logger.info(f"Test completed in {elapsed_time/60:.1f} minutes")

        return all_results

    def calculate_metrics(self) -> Dict:
        """Calculate evaluation metrics"""
        tp = self.results['true_positives']
        fp = self.results['false_positives']
        tn = self.results['true_negatives']
        fn = self.results['false_negatives']

        metrics = {}

        # Detection metrics
        metrics['fpr'] = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
        metrics['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0

        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / \
                                 (metrics['precision'] + metrics['recall'])
        else:
            metrics['f1_score'] = 0

        # Performance metrics
        if self.results['latencies']:
            import numpy as np
            metrics['avg_latency_ms'] = np.mean(self.results['latencies'])
            metrics['max_latency_ms'] = np.max(self.results['latencies'])

        metrics['confusion_matrix'] = {
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn
        }

        return metrics

    def print_results(self, metrics: Dict):
        """Print test results"""
        print("\n" + "="*50)
        print("RATE-LIMITED TEST RESULTS")
        print("="*50)
        print(f"Rate limit: {self.requests_per_minute} requests/minute")
        print(f"\nDetection Metrics:")
        print(f"  False Positive Rate: {metrics['fpr']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall: {metrics['recall']:.4f}")
        print(f"  F1-Score: {metrics['f1_score']:.4f}")

        if 'avg_latency_ms' in metrics:
            print(f"\nPerformance:")
            print(f"  Average Latency: {metrics['avg_latency_ms']:.0f} ms")
            print(f"  Max Latency: {metrics['max_latency_ms']:.0f} ms")

        cm = metrics['confusion_matrix']
        print(f"\nConfusion Matrix:")
        print(f"  True Positives: {cm['true_positives']} (malicious blocked)")
        print(f"  False Positives: {cm['false_positives']} (benign blocked)")
        print(f"  True Negatives: {cm['true_negatives']} (benign allowed)")
        print(f"  False Negatives: {cm['false_negatives']} (malicious allowed)")

        total_tested = sum(cm.values())
        print(f"\nTotal URLs tested: {total_tested}")
        print("="*50)


def main():
    parser = argparse.ArgumentParser(
        description='Test URL Malware Detection Proxy with Rate Limiting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  # Quick test with 10 URLs each (5 minutes)
  python rate_limited_proxy_tester.py --malicious-urls real_malicious_urls.txt --benign-urls real_benign_urls.txt

  # Larger test with 25 URLs each (25 minutes)
  python rate_limited_proxy_tester.py --malicious-urls real_malicious_urls.txt --benign-urls real_benign_urls.txt --malicious-limit 25 --benign-limit 25

  # Test with specific rate limit
  python rate_limited_proxy_tester.py --malicious-urls real_malicious_urls.txt --benign-urls real_benign_urls.txt --rate-limit 10
        """
    )

    parser.add_argument('--proxy-host', default='localhost', help='Proxy hostname')
    parser.add_argument('--proxy-port', type=int, default=65080, help='Proxy port')
    parser.add_argument('--malicious-urls', required=True, help='File with malicious URLs')
    parser.add_argument('--benign-urls', required=True, help='File with benign URLs')
    parser.add_argument('--malicious-limit', type=int, default=10, help='Max malicious URLs to test')
    parser.add_argument('--benign-limit', type=int, default=10, help='Max benign URLs to test')
    parser.add_argument('--rate-limit', type=int, default=4, help='Requests per minute (default: 4)')
    parser.add_argument('--save-report', action='store_true', help='Save JSON report')

    args = parser.parse_args()

    # Initialize tester
    tester = RateLimitedProxyTester(args.proxy_host, args.proxy_port, args.rate_limit)

    # Load limited datasets
    malicious_urls, benign_urls = tester.load_limited_datasets(
        args.malicious_urls,
        args.benign_urls,
        args.malicious_limit,
        args.benign_limit
    )

    # Combine and shuffle
    all_urls = malicious_urls + benign_urls
    random.shuffle(all_urls)

    # Run test
    results = tester.run_rate_limited_test(all_urls)

    # Calculate and display metrics
    metrics = tester.calculate_metrics()
    tester.print_results(metrics)

    # Save report if requested
    if args.save_report:
        report = {
            'test_timestamp': datetime.now().isoformat(),
            'proxy_url': tester.proxy_url,
            'rate_limit': args.rate_limit,
            'urls_tested': len(all_urls),
            'metrics': metrics,
            'individual_results': results
        }

        filename = f'rate_limited_test_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {filename}")


if __name__ == "__main__":
    main()
