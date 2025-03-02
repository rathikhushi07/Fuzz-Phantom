import requests
import json
import re
import concurrent.futures
import logging
import urllib3
from typing import List, Dict, Optional
import random
import string
from dataclasses import dataclass
from datetime import datetime
import hashlib
import jwt
from urllib.parse import urlparse, urljoin
import socket

# Suppress insecure request warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class EndpointPattern:
    pattern: str
    frequency: int
    authentication_required: bool
    methods_allowed: List[str]
    parameters: List[str]

class APIFuzzer:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
        self.discovered_endpoints: List[str] = []
        self.patterns: Dict[str, EndpointPattern] = {}
        self.session = requests.Session()
        self.logger = self._setup_logger()
        self.common_patterns = [
            r"/api/v\d+/",
            r"/rest/",
            r"/graphql",
            r"/swagger",
            r"/docs"
        ]
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('APIFuzzer')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(f'api_fuzzer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _generate_random_string(self, length: int = 10) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _make_request(self, url: str, method: str = 'GET', data: Optional[Dict] = None) -> requests.Response:
        headers = {
            'User-Agent': f'SecurityResearchFuzzer/{self._generate_random_string(5)}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                timeout=10,
                verify=False  # Note: Only for testing purposes
            )
            return response
        except Exception as e:
            self.logger.error(f"Request failed: {str(e)}")
            return None

    def analyze_endpoint_patterns(self, sample_endpoints: List[str]):
        """Analyze patterns in known endpoints to predict undocumented ones."""
        for endpoint in sample_endpoints:
            parts = endpoint.split('/')
            for i in range(len(parts) - 1):
                pattern = '/'.join(parts[:i+1])
                if pattern in self.patterns:
                    self.patterns[pattern].frequency += 1
                else:
                    self.patterns[pattern] = EndpointPattern(
                        pattern=pattern,
                        frequency=1,
                        authentication_required=False,
                        methods_allowed=[],
                        parameters=[]
                    )

    def discover_endpoints(self, wordlist_path: str = None):
        """Discover potential undocumented endpoints using pattern analysis and wordlists."""
        base_paths = self._generate_base_paths()
        
        if wordlist_path:
            with open(wordlist_path, 'r') as f:
                additional_paths = f.read().splitlines()
            base_paths.extend(additional_paths)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._probe_endpoint, path) for path in base_paths]
            concurrent.futures.wait(futures)

    def _probe_endpoint(self, path: str):
        """Probe individual endpoints for existence and vulnerabilities."""
        url = urljoin(self.base_url, path)
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            response = self._make_request(url, method)
            if response and response.status_code != 404:
                self.discovered_endpoints.append((url, method))
                self._analyze_response(response, url, method)

    def test_authentication(self, endpoint: str):
        """Test authentication mechanisms and potential bypasses."""
        # Test without authentication
        response = self._make_request(endpoint)
        auth_required = response.status_code in [401, 403]

        if auth_required:
            # Test common authentication bypasses
            bypasses = [
                {'Authorization': 'null'},
                {'Authorization': 'undefined'},
                {'X-Original-URL': endpoint},
                {'X-Rewrite-URL': endpoint}
            ]
            
            for bypass in bypasses:
                response = self._make_request(endpoint, headers=bypass)
                if response.status_code not in [401, 403]:
                    self.logger.warning(f"Possible auth bypass found for {endpoint} using {bypass}")

    def test_injection_vulnerabilities(self, endpoint: str):
        """Test for common injection vulnerabilities."""
        payloads = {
            'sql': ["' OR '1'='1", "'); DROP TABLE users;--"],
            'nosql': ['{"$gt": ""}', '{"$where": "1==1"}'],
            'command': ['; ls -la', '|| whoami'],
            'xss': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
        }

        for vuln_type, tests in payloads.items():
            for payload in tests:
                response = self._make_request(
                    endpoint,
                    method='POST',
                    data={'param': payload}
                )
                if response:
                    self._analyze_injection_response(response, vuln_type, endpoint)

    def analyze_data_transmission(self, endpoint: str):
        """Analyze security of data transmission."""
        url_parsed = urlparse(endpoint)
        
        # Test SSL/TLS configuration
        hostname = url_parsed.hostname
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher[0] in ['DES', 'RC4', 'MD5']:
                        self.logger.warning(f"Weak cipher detected: {cipher[0]}")
        except Exception as e:
            self.logger.error(f"SSL/TLS analysis failed: {str(e)}")

    def _analyze_response(self, response: requests.Response, url: str, method: str):
        """Analyze response for security issues and patterns."""
        # Check for sensitive information in headers
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in sensitive_headers:
            if header in response.headers:
                self.logger.warning(f"Sensitive header found: {header}: {response.headers[header]}")

        # Check for security headers
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options'
        ]
        for header in security_headers:
            if header not in response.headers:
                self.logger.warning(f"Missing security header: {header}")

        # Analyze response content
        try:
            if response.content:
                # Check for potential data leaks
                sensitive_patterns = [
                    r'\b[\w\.-]+@[\w\.-]+\.\w+\b',  # Email addresses
                    r'\b\d{3}-\d{2}-\d{4}\b',       # SSN
                    r'\b\d{16}\b',                  # Credit card numbers
                ]
                
                content = response.text
                for pattern in sensitive_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        self.logger.critical(f"Potential sensitive data leak found: {match.group()}")

        except Exception as e:
            self.logger.error(f"Response analysis failed: {str(e)}")

    def _analyze_injection_response(self, response: requests.Response, vuln_type: str, endpoint: str):
        """Analyze responses for signs of successful injection."""
        error_patterns = {
            'sql': [
                r'SQL syntax.*MySQL',
                r'Warning.*sqlite_.*',
                r'Microsoft SQL Server',
                r'PostgreSQL.*ERROR'
            ],
            'nosql': [
                r'MongoDB.*Error',
                r'BadValue.*MongoDB'
            ]
        }

        if vuln_type in error_patterns:
            for pattern in error_patterns[vuln_type]:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.logger.critical(f"Potential {vuln_type} injection vulnerability found in {endpoint}")

    def generate_report(self) -> Dict:
        """Generate a comprehensive security analysis report."""
        return {
            'scan_time': datetime.now().isoformat(),
            'base_url': self.base_url,
            'discovered_endpoints': self.discovered_endpoints,
            'security_issues': self._get_security_issues(),
            'recommendations': self._generate_recommendations()
        }

    def _get_security_issues(self) -> List[Dict]:
        """Extract security issues from logs."""
        issues = []
        with open(self.logger.handlers[0].baseFilename, 'r') as f:
            for line in f:
                if 'WARNING' in line or 'CRITICAL' in line:
                    issues.append({
                        'timestamp': line.split('-')[0].strip(),
                        'level': line.split('-')[1].strip(),
                        'message': '-'.join(line.split('-')[2:]).strip()
                    })
        return issues

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Add recommendations based on findings
        if any('Missing security header' in issue['message'] for issue in self._get_security_issues()):
            recommendations.append("Implement all recommended security headers")
            
        if any('auth bypass' in issue['message'].lower() for issue in self._get_security_issues()):
            recommendations.append("Review and strengthen authentication mechanisms")
            
        if any('injection' in issue['message'].lower() for issue in self._get_security_issues()):
            recommendations.append("Implement proper input validation and parameterized queries")
            
        return recommendations

# Example usage:
def main():
    fuzzer = APIFuzzer('https://api.example.com', api_key='your_api_key_here')
    
    # Analyze known endpoints
    sample_endpoints = ['/api/v1/users', '/api/v1/products', '/api/v2/orders']
    fuzzer.analyze_endpoint_patterns(sample_endpoints)
    
    # Discover new endpoints
    fuzzer.discover_endpoints()
    
    # Test discovered endpoints
    for endpoint, method in fuzzer.discovered_endpoints:
        fuzzer.test_authentication(endpoint)
        fuzzer.test_injection_vulnerabilities(endpoint)
        fuzzer.analyze_data_transmission(endpoint)
    
    # Generate report
    report = fuzzer.generate_report()
    
    # Save report
    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=4)

if __name__ == "__main__":
    main()