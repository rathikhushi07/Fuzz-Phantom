import requests
import concurrent.futures
import dns.resolver
import socket
import logging
import yaml
import random
import string
from typing import List, Dict, Set
from dataclasses import dataclass
import urllib3
from urllib.parse import urlparse
import sys
import time

# Disable insecure request warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class VHostPayload:
    host: str
    original_host: str
    payload_type: str
    description: str

class Logger:
    def __init__(self, log_file: str = "vhost_fuzzer.log"):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

class PayloadGenerator:
    def __init__(self):
        self.common_subdomains = [
            "dev", "staging", "test", "admin", "internal",
            "backend", "api", "dashboard", "secure", "private"
        ]
        
    def generate_host_mutations(self, original_host: str) -> List[VHostPayload]:
        mutations = []
        domain = original_host.split(".")[-2:]
        base = original_host.split(".")[0]
        
        # Subdomain injection
        for subdomain in self.common_subdomains:
            mutations.append(VHostPayload(
                f"{subdomain}.{original_host}",
                original_host,
                "subdomain_injection",
                "Testing subdomain prefix"
            ))
            
        # Host header manipulation
        mutations.extend([
            VHostPayload(f"{base}-internal.{'.'.join(domain)}", original_host, "internal_domain", "Testing internal domain access"),
            VHostPayload(f"localhost", original_host, "localhost_access", "Testing localhost access"),
            VHostPayload(f"127.0.0.1", original_host, "localhost_ip", "Testing direct IP access"),
            VHostPayload(original_host + ":80", original_host, "port_injection", "Testing explicit port injection"),
            VHostPayload(original_host + ":443", original_host, "port_injection", "Testing explicit port injection"),
            VHostPayload(f"{original_host}#", original_host, "special_chars", "Testing fragment injection"),
            VHostPayload(f"{original_host}%00", original_host, "null_byte", "Testing null byte injection"),
            VHostPayload(f"{original_host}/", original_host, "path_traversal", "Testing path traversal in host"),
        ])
        
        # Add random subdomain testing
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=8))
        mutations.append(VHostPayload(
            f"{random_subdomain}.{original_host}",
            original_host,
            "random_subdomain",
            "Testing random subdomain access"
        ))
        
        return mutations

class NetworkUtils:
    @staticmethod
    def resolve_dns(hostname: str) -> Set[str]:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(hostname, 'A')
            return {str(rdata) for rdata in answers}
        except Exception:
            return set()
            
    @staticmethod
    def check_port_open(host: str, port: int, timeout: int = 5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error):
            return False

class VHostFuzzer:
    def __init__(self, target_url: str, threads: int = 10, timeout: int = 10):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.base_host = self.parsed_url.netloc
        self.threads = threads
        self.timeout = timeout
        self.logger = Logger()
        self.payload_gen = PayloadGenerator()
        self.network_utils = NetworkUtils()
        self.session = requests.Session()
        self.findings = []
        
    def _make_request(self, payload: VHostPayload) -> Dict:
        try:
            headers = {
                'Host': payload.host,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*'
            }
            
            response = self.session.get(
                self.target_url,
                headers=headers,
                verify=False,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            return {
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.content),
                'headers': dict(response.headers)
            }
        except Exception as e:
            self.logger.logger.error(f"Error testing payload {payload.host}: {str(e)}")
            return None

    def _analyze_response(self, result: Dict) -> None:
        if not result:
            return
            
        interesting_conditions = [
            (result['status_code'] != 404, "Non-404 response received"),
            (result['response_length'] > 0, "Non-empty response body"),
            ('x-powered-by' in result['headers'], "Technology information disclosure"),
            ('server' in result['headers'], "Server header present"),
            (result['status_code'] == 200, "Direct access possible"),
            (result['status_code'] == 301, "Redirect found"),
        ]
        
        for condition, description in interesting_conditions:
            if condition:
                finding = {
                    'payload': result['payload'],
                    'status_code': result['status_code'],
                    'length': result['response_length'],
                    'description': description
                }
                self.findings.append(finding)
                self.logger.logger.warning(
                    f"Potential vulnerability found with payload: {result['payload'].host}\n"
                    f"Type: {result['payload'].payload_type}\n"
                    f"Description: {description}\n"
                    f"Status Code: {result['status_code']}\n"
                    f"Response Length: {result['response_length']}"
                )

    def _test_cross_tenant_access(self, payload: VHostPayload) -> None:
        """Test for cross-tenant access vulnerabilities"""
        try:
            # Attempt to access resources with different virtual host headers
            standard_response = self._make_request(VHostPayload(self.base_host, self.base_host, "baseline", "Baseline request"))
            test_response = self._make_request(payload)
            
            if standard_response and test_response:
                if (test_response['status_code'] == standard_response['status_code'] and 
                    test_response['response_length'] == standard_response['response_length']):
                    self.logger.logger.warning(
                        f"Potential cross-tenant access vulnerability detected with payload: {payload.host}"
                    )
        except Exception as e:
            self.logger.logger.error(f"Error in cross-tenant testing: {str(e)}")

    def run(self) -> List[Dict]:
        self.logger.logger.info(f"Starting VHost fuzzing against {self.target_url}")
        
        # Generate payloads
        payloads = self.payload_gen.generate_host_mutations(self.base_host)
        
        # First, perform DNS enumeration
        resolved_ips = self.network_utils.resolve_dns(self.base_host)
        self.logger.logger.info(f"Resolved IPs for {self.base_host}: {resolved_ips}")
        
        # Test port availability
        for ip in resolved_ips:
            for port in [80, 443, 8080, 8443]:
                if self.network_utils.check_port_open(ip, port):
                    self.logger.logger.info(f"Port {port} is open on {ip}")
        
        # Execute fuzzing with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_payload = {
                executor.submit(self._make_request, payload): payload 
                for payload in payloads
            }
            
            for future in concurrent.futures.as_completed(future_to_payload):
                result = future.result()
                if result:
                    self._analyze_response(result)
                    self._test_cross_tenant_access(future_to_payload[future])
        
        self.logger.logger.info(f"Fuzzing completed. Found {len(self.findings)} potential issues.")
        return self.findings

def main():
    # Example usage
    target_url = "https://skit.ac.in"  # Replace with actual target
    fuzzer = VHostFuzzer(target_url, threads=10, timeout=10)
    findings = fuzzer.run()
    
    # Export findings to YAML
    with open('vhost_fuzzing_results.yaml', 'w') as f:
        yaml.dump(findings, f, default_flow_style=False)

if __name__ == "__main__":
    main()