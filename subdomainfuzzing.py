import requests
import concurrent.futures
import dns.resolver
import re
import ssl
import socket
import json
import argparse
import warnings
from urllib.parse import urlparse


class SubdomainVulnerabilityScanner:

    def _init_(self, domain, threads=50):
        self.domain = domain
        self.threads = threads
        self.vulnerable_subdomains = []
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    def passive_recon(self):
        """
        Passive reconnaissance using multiple sources
        """
        passive_sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
            # Add more passive recon sources
        ]

        discovered_subdomains = set()

        for source in passive_sources:
            try:
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    # Parse different source formats
                    if 'crt.sh' in source:
                        certs = response.json()
                        for cert in certs:
                            subdomains = cert.get('name_value', '').split('\n')
                            discovered_subdomains.update(sub.strip()
                                                         for sub in subdomains
                                                         if self.domain in sub)
                    else:
                        # HackerTarget and other sources
                        subdomains = response.text.split('\n')
                        discovered_subdomains.update(
                            sub.split(',')[0] for sub in subdomains
                            if self.domain in sub)
            except Exception as e:
                print(f"[!] Passive recon error with {source}: {e}")

        return list(discovered_subdomains)

    def active_dns_enumeration(self, wordlist):
        """
        Active DNS enumeration with multiple record types
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        discovered_subdomains = set()

        def check_subdomain(subdomain):
            try:
                full_subdomain = f"{subdomain}.{self.domain}"
                # Check multiple record types
                record_types = ['A', 'CNAME', 'MX', 'TXT']
                for record_type in record_types:
                    try:
                        answers = resolver.resolve(full_subdomain, record_type)
                        if answers:
                            return full_subdomain
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        continue
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as executor:
            results = list(executor.map(check_subdomain, wordlist))

        return {sub for sub in results if sub}

    def vulnerability_scan(self, subdomains):
        """
        Scan discovered subdomains for potential vulnerabilities
        """

        def scan_subdomain(subdomain):
            vulnerabilities = []
            protocols = ['http', 'https']

            for protocol in protocols:
                url = f"{protocol}://{subdomain}"
                try:
                    response = requests.get(
                        url,
                        timeout=5,
                        verify=False,  # Disable SSL verification
                        allow_redirects=True)

                    # Basic vulnerability checks
                    checks = [
                        self._check_directory_listing(response),
                        self._check_sensitive_headers(response.headers),
                        self._check_technology_fingerprint(response)
                    ]

                    # Aggregate vulnerabilities
                    subdomain_vulns = [vuln for vuln in checks if vuln]

                    if subdomain_vulns:
                        return {
                            'subdomain': subdomain,
                            'protocol': protocol,
                            'status_code': response.status_code,
                            'vulnerabilities': subdomain_vulns
                        }

                except requests.RequestException:
                    pass

            return None

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as executor:
            results = list(executor.map(scan_subdomain, subdomains))

        # Filter out None results and store vulnerable subdomains
        self.vulnerable_subdomains = [
            result for result in results
            if result and result['vulnerabilities']
        ]

        return self.vulnerable_subdomains

    def _check_directory_listing(self, response):
        """
        Check for potential directory listing vulnerability
        """
        directory_listing_patterns = [
            r'Index of /', r'Directory listing', r'<title>Directory Listing',
            r'Volume Serial Number'
        ]

        for pattern in directory_listing_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    'type': 'Directory Listing',
                    'severity': 'Medium',
                    'description': 'Potential directory listing exposed'
                }
        return None

    def _check_sensitive_headers(self, headers):
        """
        Check for sensitive or misconfigured headers
        """
        sensitive_headers = {
            'Server': 'Detailed server information exposed',
            'X-Powered-By': 'Technology stack information revealed',
            'X-AspNet-Version': 'Potential .NET version disclosure'
        }

        vulnerabilities = []
        for header, description in sensitive_headers.items():
            if header.lower() in map(str.lower, headers.keys()):
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'header': header,
                    'description': description
                })

        return vulnerabilities if vulnerabilities else None

    def _check_technology_fingerprint(self, response):
        """
        Identify potential technology vulnerabilities
        """
        technologies = {
            'WordPress': r'wp-',
            'Joomla': r'joomla',
            'Drupal': r'drupal',
            'phpMyAdmin': r'phpmyadmin',
            'Jenkins': r'jenkins',
            'GitLab': r'gitlab'
        }

        for tech, pattern in technologies.items():
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    'type': 'Technology Fingerprint',
                    'technology': tech,
                    'severity': 'Informational',
                    'description': f'Detected {tech} technology'
                }

        return None

    def run(self, wordlist_path=None):
        """
        Run comprehensive subdomain and vulnerability scanning
        """
        print(f"[*] Starting reconnaissance for {self.domain}")

        # Load wordlist
        if wordlist_path:
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f]
        else:
            # Default wordlist generation
            wordlist = [
                'www', 'mail', 'admin', 'test', 'dev', 'api', 'blog',
                'support', f'testsparker', 'test-sparker'
            ]

        # Passive Reconnaissance
        passive_subdomains = self.passive_recon()
        print(
            f"[+] Passive Recon Discovered: {len(passive_subdomains)} subdomains"
        )

        # Active DNS Enumeration
        active_subdomains = self.active_dns_enumeration(wordlist)
        print(
            f"[+] Active DNS Discovered: {len(active_subdomains)} subdomains")

        # Combine and deduplicate subdomains
        all_subdomains = list(set(passive_subdomains +
                                  list(active_subdomains)))

        # Vulnerability Scanning
        vulnerable_subdomains = self.vulnerability_scan(all_subdomains)

        print("\n[+] Vulnerability Scan Results:")
        for vuln_sub in vulnerable_subdomains:
            print(json.dumps(vuln_sub, indent=2))

        return {
            'all_subdomains': all_subdomains,
            'vulnerable_subdomains': vulnerable_subdomains
        }


def main():
    parser = argparse.ArgumentParser(
        description='Subdomain Vulnerability Scanner')
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path')
    parser.add_argument('-t',
                        '--threads',
                        type=int,
                        default=50,
                        help='Number of threads')

    args = parser.parse_args()

    scanner = SubdomainVulnerabilityScanner(args.domain, threads=args.threads)
    results = scanner.run(wordlist_path=args.wordlist)

    # Save results
    with open(f"{args.domain}_vulnerability_report.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()