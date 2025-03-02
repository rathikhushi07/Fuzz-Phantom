import os
import requests
import socket
from tqdm import tqdm

# Colors for CLI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Fetch subdomains from Certificate Transparency Logs
def fetch_from_cert_logs(domain):
    print(f"{Colors.OKCYAN}Fetching subdomains from Certificate Transparency Logs for {domain}{Colors.ENDC}")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return list({entry['name_value'] for entry in data})
    except Exception as e:
        print(f"{Colors.WARNING}Error fetching from Certificate Logs: {e}{Colors.ENDC}")
    return []

# Discover common subdomains by appending popular prefixes
def generate_common_subdomains(domain):
    print(f"{Colors.OKCYAN}Generating common subdomains for {domain}{Colors.ENDC}")
    prefixes = ["api", "admin", "user", "auth", "test", "dev", "staging"]
    return [f"{prefix}.{domain}" for prefix in prefixes]

# Resolve subdomains to IP addresses
def resolve_subdomains(subdomains):
    resolved_subdomains = []
    for subdomain in subdomains:
        try:
            socket.gethostbyname(subdomain)
            resolved_subdomains.append(subdomain)
            print(f"{Colors.OKGREEN}Resolved: {subdomain}{Colors.ENDC}")
        except socket.gaierror:
            print(f"{Colors.WARNING}Could not resolve: {subdomain}{Colors.ENDC}")
    return resolved_subdomains

# Discover common API endpoints
def fetch_common_endpoints(subdomains):
    common_endpoints = [
        "/api/v1", "/api/v2", "/api", "/admin/api", "/user/api", "/auth", "/admin", "/auth/login"
    ]
    api_endpoints = []
    for subdomain in subdomains:
        for endpoint in common_endpoints:
            url = f"http://{subdomain}{endpoint}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"{Colors.OKGREEN}Found API Endpoint: {url}{Colors.ENDC}")
                    api_endpoints.append(url)
            except requests.exceptions.RequestException:
                continue
    return api_endpoints

# Main discovery function
def discover_api_endpoints(domain):
    print(f"{Colors.HEADER}Starting API Endpoint Discovery for {domain}{Colors.ENDC}")

    # Fetch subdomains
    subdomains = fetch_from_cert_logs(domain)
    subdomains += generate_common_subdomains(domain)
    subdomains = list(set(subdomains))

    print(f"\n{Colors.OKCYAN}Resolving Subdomains{Colors.ENDC}")
    resolved_subdomains = resolve_subdomains(subdomains)

    print(f"\n{Colors.OKCYAN}Searching for Common API Endpoints{Colors.ENDC}")
    api_endpoints = fetch_common_endpoints(resolved_subdomains)

    print(f"\n{Colors.OKGREEN}API Endpoints Found:{Colors.ENDC}")
    for endpoint in api_endpoints:
        print(endpoint)

if __name__ == "__main__":
    domain = input("Enter the target domain (e.g., example.com): ").strip()
    discover_api_endpoints(domain)
