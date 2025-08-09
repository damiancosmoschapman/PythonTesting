#!/usr/bin/env python3
"""
proxy_tester.py
"""

import pandas as pd
import numpy as np
from datetime import datetime
import time
import psutil
import json
import argparse
from typing import Dict, List, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor
import requests
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProxyTester:
    def __init__(self, proxy_host: str, proxy_port: int):
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.results = {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0,
            'latencies': [],
            'timestamps': []
        }
        self.start_time = None
        self.end_time = None

    def load_datasets(self, malicious_file: str, benign_file: str) -> Tuple[List[Dict], List[Dict]]:
        """Load URL datasets from CSV files"""
        malicious_urls = []
        benign_urls = []

        # Load malicious URLs
        try:
            with open(malicious_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        malicious_urls.append({'url': url, 'label': 'malicious'})
        except Exception as e:
            logger.error(f"Error loading malicious URLs: {e}")

        # Load benign URLs
        try:
            with open(benign_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        benign_urls.append({'url': url, 'label': 'benign'})
        except Exception as e:
            logger.error(f"Error loading benign URLs: {e}")

        logger.info(f"Loaded {len(malicious_urls)} malicious URLs and {len(benign_urls)} benign URLs")
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
            'error': None,
            'response_body': None
        }

        try:
            # Make request through proxy with no redirect following
            response = requests.get(
                url,
                proxies=proxies,
                timeout=30,
                allow_redirects=False,
                verify=False  # Ignore SSL warnings for MITM proxy
            )
            end_time = time.time()

            result['latency'] = (end_time - start_time) * 1000  # Convert to ms
            result['status_code'] = response.status_code
            result['response_body'] = response.text[:500] if response.text else ""

            # YOUR PROXY DETECTION LOGIC
            # Based on your code, the proxy returns:
            # - Status 403 with warning HTML page for malicious URLs
            # - Normal response for safe URLs

            blocked = False

            # Check for 403 status (your proxy uses this)
            if response.status_code == 403:
                blocked = True
                logger.debug(f"URL blocked with 403: {url}")

            # Check response body for warning page indicators
            if response.text:
                body_lower = response.text.lower()
                # Your proxy's warning page contains these specific strings
                warning_indicators = [
                    'security warning',
                    'potentially malicious',
                    'flagged as potentially malicious',
                    'potentially dangerous',
                    'virustotal:',
                    'safe browsing:',
                    'scamadviser:',
                    'go back to safety',
                    'proceed anyway (not recommended)'
                ]

                for indicator in warning_indicators:
                    if indicator in body_lower:
                        blocked = True
                        logger.debug(f"Found warning indicator '{indicator}' for URL: {url}")
                        break

            # Set the result
            result['actual'] = 'malicious' if blocked else 'benign'

            # Log details for debugging
            if blocked:
                logger.debug(f"Blocked URL: {url} (Status: {response.status_code})")
            else:
                logger.debug(f"Allowed URL: {url} (Status: {response.status_code})")

        except requests.exceptions.ProxyError as e:
            # Proxy might have blocked the connection entirely
            end_time = time.time()
            result['latency'] = (end_time - start_time) * 1000
            result['actual'] = 'malicious'
            result['error'] = 'proxy_blocked'
            logger.debug(f"ProxyError for URL {url}: {str(e)}")

        except Exception as e:
            end_time = time.time()
            result['latency'] = (end_time - start_time) * 1000
            result['error'] = str(e)
            result['actual'] = 'error'
            logger.debug(f"Error testing URL {url}: {str(e)}")

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

    def run_accuracy_test(self, urls: List[Dict], max_workers: int = 10) -> List[Dict]:
        """Run accuracy testing with concurrent requests"""
        logger.info(f"Starting accuracy test with {len(urls)} URLs using {max_workers} workers")

        all_results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for url_data in urls:
                future = executor.submit(self.test_url, url_data['url'], url_data['label'])
                futures.append(future)

            for i, future in enumerate(futures):
                result = future.result()
                all_results.append(result)
                if (i + 1) % 100 == 0:
                    logger.info(f"Processed {i + 1}/{len(urls)} URLs")

        return all_results

    def run_performance_test(self, urls: List[Dict], duration_seconds: int = 300,
                           target_rps: int = 100) -> Dict:
        """Run performance testing with specified load"""
        logger.info(f"Starting performance test: {target_rps} RPS for {duration_seconds} seconds")

        start_time = time.time()
        end_time = start_time + duration_seconds
        request_interval = 1.0 / target_rps

        performance_results = {
            'latencies': [],
            'timestamps': [],
            'errors': 0,
            'total_requests': 0
        }

        url_index = 0
        while time.time() < end_time:
            request_start = time.time()

            # Get next URL (cycle through list)
            url_data = urls[url_index % len(urls)]
            url_index += 1

            # Test URL
            result = self.test_url(url_data['url'], url_data['label'])

            performance_results['total_requests'] += 1
            if result['error']:
                performance_results['errors'] += 1
            if result['latency']:
                performance_results['latencies'].append(result['latency'])
                performance_results['timestamps'].append(time.time())

            # Maintain target RPS
            elapsed = time.time() - request_start
            if elapsed < request_interval:
                time.sleep(request_interval - elapsed)

        return performance_results

    def calculate_metrics(self) -> Dict:
        """Calculate all evaluation metrics"""
        tp = self.results['true_positives']
        fp = self.results['false_positives']
        tn = self.results['true_negatives']
        fn = self.results['false_negatives']

        # Avoid division by zero
        metrics = {}

        # False Positive Rate
        if (fp + tn) > 0:
            metrics['fpr'] = fp / (fp + tn)
        else:
            metrics['fpr'] = 0

        # Precision
        if (tp + fp) > 0:
            metrics['precision'] = tp / (tp + fp)
        else:
            metrics['precision'] = 0

        # Recall
        if (tp + fn) > 0:
            metrics['recall'] = tp / (tp + fn)
        else:
            metrics['recall'] = 0

        # F1-Score
        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / \
                                 (metrics['precision'] + metrics['recall'])
        else:
            metrics['f1_score'] = 0

        # Latency metrics
        if self.results['latencies']:
            metrics['avg_latency_ms'] = np.mean(self.results['latencies'])
            metrics['max_latency_ms'] = np.max(self.results['latencies'])
            metrics['p95_latency_ms'] = np.percentile(self.results['latencies'], 95)
            metrics['p99_latency_ms'] = np.percentile(self.results['latencies'], 99)

        # Throughput
        if self.results['timestamps']:
            duration = self.results['timestamps'][-1] - self.results['timestamps'][0]
            if duration > 0:
                metrics['throughput_rps'] = len(self.results['timestamps']) / duration

        # Confusion matrix
        metrics['confusion_matrix'] = {
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn
        }

        return metrics

    def save_detailed_results(self, results: List[Dict], filename: str = 'detailed_results.json'):
        """Save detailed test results for analysis"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Detailed results saved to {filename}")

    def generate_report(self, metrics: Dict, output_file: str = 'test_report.json'):
        """Generate comprehensive test report"""
        report = {
            'test_timestamp': datetime.now().isoformat(),
            'proxy_url': self.proxy_url,
            'detection_metrics': {
                'false_positive_rate': metrics.get('fpr', 0),
                'precision': metrics.get('precision', 0),
                'recall': metrics.get('recall', 0),
                'f1_score': metrics.get('f1_score', 0)
            },
            'performance_metrics': {
                'avg_latency_ms': metrics.get('avg_latency_ms', 0),
                'max_latency_ms': metrics.get('max_latency_ms', 0),
                'p95_latency_ms': metrics.get('p95_latency_ms', 0),
                'p99_latency_ms': metrics.get('p99_latency_ms', 0),
                'throughput_rps': metrics.get('throughput_rps', 0)
            },
            'confusion_matrix': metrics.get('confusion_matrix', {}),
            'test_summary': {
                'total_urls_tested': sum(metrics.get('confusion_matrix', {}).values()),
                'f1_score_threshold_met': metrics.get('f1_score', 0) > 0.9
            }
        }

        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Print summary
        print("\n" + "="*50)
        print("TEST RESULTS SUMMARY")
        print("="*50)
        print(f"False Positive Rate: {report['detection_metrics']['false_positive_rate']:.4f}")
        print(f"Precision: {report['detection_metrics']['precision']:.4f}")
        print(f"Recall: {report['detection_metrics']['recall']:.4f}")
        print(f"F1-Score: {report['detection_metrics']['f1_score']:.4f}")
        print(f"\nAverage Latency: {report['performance_metrics']['avg_latency_ms']:.2f} ms")
        print(f"Max Latency: {report['performance_metrics']['max_latency_ms']:.2f} ms")
        print(f"Throughput: {report['performance_metrics']['throughput_rps']:.2f} RPS")
        print(f"\nF1-Score > 0.9 Requirement: {'✓ PASSED' if report['test_summary']['f1_score_threshold_met'] else '✗ FAILED'}")

        # Print confusion matrix details
        cm = metrics.get('confusion_matrix', {})
        print(f"\nConfusion Matrix:")
        print(f"  True Positives: {cm.get('true_positives', 0)} (malicious correctly blocked)")
        print(f"  False Positives: {cm.get('false_positives', 0)} (benign incorrectly blocked)")
        print(f"  True Negatives: {cm.get('true_negatives', 0)} (benign correctly allowed)")
        print(f"  False Negatives: {cm.get('false_negatives', 0)} (malicious incorrectly allowed)")
        print("="*50)

        return report


def main():
    parser = argparse.ArgumentParser(description='Test URL Malware Detection Proxy')
    parser.add_argument('--proxy-host', required=True, help='Proxy hostname')
    parser.add_argument('--proxy-port', type=int, required=True, help='Proxy port')
    parser.add_argument('--malicious-urls', required=True, help='File containing malicious URLs')
    parser.add_argument('--benign-urls', required=True, help='File containing benign URLs')
    parser.add_argument('--test-type', choices=['accuracy', 'performance', 'both'],
                       default='both', help='Type of test to run')
    parser.add_argument('--workers', type=int, default=10, help='Number of concurrent workers')
    parser.add_argument('--duration', type=int, default=300, help='Performance test duration (seconds)')
    parser.add_argument('--target-rps', type=int, default=100, help='Target requests per second')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--save-details', action='store_true', help='Save detailed results')

    args = parser.parse_args()

    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize tester
    tester = ProxyTester(args.proxy_host, args.proxy_port)

    # Load datasets
    malicious_urls, benign_urls = tester.load_datasets(args.malicious_urls, args.benign_urls)
    all_urls = malicious_urls + benign_urls

    # Store all results for detailed analysis
    all_results = []

    # Run tests
    if args.test_type in ['accuracy', 'both']:
        logger.info("Running accuracy tests...")
        accuracy_results = tester.run_accuracy_test(all_urls, max_workers=args.workers)
        all_results.extend(accuracy_results)

    if args.test_type in ['performance', 'both']:
        logger.info("Running performance tests...")
        perf_results = tester.run_performance_test(all_urls,
                                                  duration_seconds=args.duration,
                                                  target_rps=args.target_rps)

    # Save detailed results if requested
    if args.save_details and all_results:
        tester.save_detailed_results(all_results)

    # Calculate metrics and generate report
    metrics = tester.calculate_metrics()
    report = tester.generate_report(metrics)

    return report


if __name__ == "__main__":
    main()
