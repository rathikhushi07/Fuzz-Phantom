import requests
import itertools
import socket
from xml.sax.saxutils import escape
from html import escape
from urllib.parse import urlparse, urlencode
from bs4 import BeautifulSoup
from datetime import datetime
import dns.resolver
import json
from rich.console import Console
from rich.progress import track
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import time
import re

console = Console()

# Logging utilities
def log_info(message):
    console.print(f"[cyan][INFO] {message}[/cyan]")

def log_success(message):
    console.print(f"[green][SUCCESS] {message}[/green]")

def log_warning(message):
    console.print(f"[yellow][WARNING] {message}[/yellow]")

def log_error(message):
    console.print(f"[red][ERROR] {message}[/red]")

# Utility to generate a wordlist
def generate_wordlist(target):
    log_info("Generating wordlist...")
    wordlist = ["admin", "login", "test", "backup", "config", "api", "dev", "staging", "internal"]
    domain_parts = urlparse(target).netloc.split(".")
    for part in domain_parts:
        if part not in wordlist:
            wordlist.append(part)
    return wordlist

# Utility to discover hidden content
def discover_hidden_content(target):
    log_info("Discovering hidden content...")
    discovered = []
    paths = [
        "/robots.txt", "/sitemap.xml", "/admin", "/login", "/config", "/backup", "/test", "/hidden",
        "/.env", "/.git/", "/.htaccess"
    ]
    for path in paths:
        url = f"{target}{path}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                log_success(f"Hidden content found: {url}")
                discovered.append({"path": path, "status_code": response.status_code, "content": response.text[:200]})
        except requests.RequestException:
            pass
    return discovered

# Security headers analysis
def analyze_headers(target):
    log_info("Analyzing security headers...")
    try:
        response = requests.get(target, timeout=5)
        headers = response.headers
        recommendations = []
        if "Strict-Transport-Security" not in headers:
            recommendations.append("Enable HSTS: Protects against protocol downgrade attacks and cookie hijacking.")
        if "Content-Security-Policy" not in headers:
            recommendations.append("Add Content Security Policy: Mitigates cross-site scripting (XSS) and data injection attacks.")
        if "X-Frame-Options" not in headers:
            recommendations.append("Set X-Frame-Options to SAMEORIGIN: Prevents clickjacking attacks.")
        return {"headers": dict(headers), "recommendations": recommendations}
    except requests.RequestException as e:
        log_error(f"Failed to analyze headers: {e}")
        return {}

def discover_advanced_subdomains(domain, target):
    """
    Discover subdomains using a custom wordlist, DNS resolution, and HTTP validation.
    """
    log_info("Starting advanced subdomain fuzzing...")
    
    # Common prefixes to combine with the domain
    base_wordlist = ["www", "api", "mail", "ftp", "dev", "staging", "test", "shop", "blog", "admin", "secure", "support"]
    
    # Generate custom wordlist from the target
    custom_wordlist = generate_custom_wordlist(target)
    
    # Combine base wordlist with custom keywords
    combined_wordlist = set(base_wordlist + custom_wordlist)
    
    # Generate permutations (e.g., `www-test` or `test-dev`)
    fuzzing_combinations = set(combined_wordlist)
    fuzzing_combinations.update(
        "-".join(combo)
        for combo in itertools.permutations(base_wordlist, 2)
    )
    
    found = []
    for subdomain in track(fuzzing_combinations, description="Fuzzing subdomains..."):
        subdomain_url = f"{subdomain}.{domain}"
        try:
            # DNS resolution
            ip_address = socket.gethostbyname(subdomain_url)
            
            # HTTP validation
            response = requests.get(f"http://{subdomain_url}", timeout=5)
            if response.status_code == 200:
                log_success(f"Subdomain found: {subdomain_url} [IP: {ip_address}]")
                found.append({
                    "subdomain": subdomain_url,
                    "ip_address": ip_address,
                    "response_code": response.status_code
                })
        except (socket.gaierror, requests.RequestException):
            pass
    
    return found

# Custom Wordlist Generator
def generate_custom_wordlist(target):
    """
    Generate a custom wordlist by analyzing the target's HTML content and metadata.
    """
    log_info("Generating custom wordlist from the target...")
    wordlist = set()
    
    try:
        response = requests.get(target, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract words from <title>, <meta>, and hyperlinks
            if soup.title:
                wordlist.update(re.findall(r"\b\w+\b", soup.title.string.lower()))
            for meta in soup.find_all("meta"):
                content = meta.get("content", "")
                wordlist.update(re.findall(r"\b\w+\b", content.lower()))
            for link in soup.find_all("a", href=True):
                href = link["href"]
                wordlist.update(re.findall(r"\b\w+\b", href.lower()))
        
        log_success(f"Custom wordlist generated with {len(wordlist)} entries.")
    except requests.RequestException as e:
        log_error(f"Failed to generate custom wordlist: {e}")
    
    return list(wordlist)

# URL parameter fuzzing
def fuzz_url_parameters(target):
    log_info("Fuzzing URL parameters...")
    parameters = ["id", "user", "page", "action", "query", "search", "token"]
    values = ["1", "admin", "<script>alert(1)</script>", "' OR '1'='1", "%00"]
    vulnerabilities = []

    for param in parameters:
        for value in values:
            query = urlencode({param: value})
            test_url = f"{target}?{query}"
            try:
                response = requests.get(test_url, timeout=5)
                if "SQL syntax" in response.text or "error" in response.text:
                    log_warning(f"Possible vulnerability found with parameter: {param}={value}")
                    vulnerabilities.append({"parameter": param, "value": value, "url": test_url})
            except requests.RequestException:
                pass
    return vulnerabilities

# VHOST fuzzing
def fuzz_vhost(domain):
    log_info("Fuzzing virtual hosts...")
    vhosts = ["admin", "dev", "test", "staging", "internal", "beta"]
    found = []
    for vhost in vhosts:
        headers = {"Host": f"{vhost}.{domain}"}
        try:
            response = requests.get(f"http://{domain}", headers=headers, timeout=5)
            if response.status_code == 200:
                log_success(f"VHOST found: {vhost}.{domain}")
                found.append({"vhost": vhost, "response_code": response.status_code})
        except requests.RequestException:
            pass
    return found

# SQL Injection vulnerability scanner (example)
def detect_sqli(target):
    log_info("Scanning for SQL injection vulnerabilities...")
    vulnerabilities = []
    test_payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "admin'--"]
    for payload in test_payloads:
        test_url = f"{target}?id=1{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "SQL syntax" in response.text or "database error" in response.text:
                log_warning(f"Possible SQL injection found: {test_url}")
                vulnerabilities.append({"url": test_url, "payload": payload, "description": "SQL injection detected."})
        except requests.RequestException:
            pass
    return vulnerabilities

# API endpoint discovery and testing
def discover_api_endpoints(target):
    log_info("Discovering API endpoints...")
    endpoints = []
    try:
        response = requests.get(target, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and "/api/" in href:
                full_url = urlparse(href).geturl()
                log_success(f"API endpoint found: {full_url}")
                endpoints.append(full_url)
    except requests.RequestException as e:
        log_error(f"Failed to discover API endpoints: {e}")
    return endpoints

def generate_pdf_report(results, target, total_time):
    log_info("Generating PDF report...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"security_scan_report_{timestamp}.pdf"

    # Create the PDF document
    doc = SimpleDocTemplate(report_name, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"Security Scan Report for {target}", styles['Title']))
    story.append(Spacer(1, 12))

    # Summary
    story.append(Paragraph("Scan Summary", styles['Heading2']))
    story.append(Paragraph(f"Total Time: {total_time:.2f} seconds", styles['BodyText']))
    story.append(Spacer(1, 12))

    # Add detailed sections for each result
    for key, value in results.items():
        if value:
            story.append(Paragraph(key, styles['Heading2']))
            for item in value:
                # Escape the content to avoid syntax errors
                escaped_content = escape(json.dumps(item, indent=2))
                story.append(Paragraph(escaped_content, styles['BodyText']))
            story.append(Spacer(1, 12))

    # Save the PDF
    doc.build(story)
    log_success(f"PDF report saved as {report_name}")
    return report_name
# Main function
if __name__ == "__main__":
    console.clear()
    log_info("Starting advanced security scan...")
    target = input("Enter the target URL (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    start_time = time.time()
    domain = urlparse(target).netloc

    # Perform the scan
    results = {
        "Subdomains Found": discover_advanced_subdomains(domain, target),  # Corrected function name
        "Hidden Content": discover_hidden_content(target),
        "Headers Analysis": analyze_headers(target),
        "SQL Injection Vulnerabilities": detect_sqli(target),
        "API Endpoints": discover_api_endpoints(target),
        "URL Parameter Vulnerabilities": fuzz_url_parameters(target),
        "VHOSTs Found": fuzz_vhost(domain)
    }

    total_time = time.time() - start_time
    pdf_report = generate_pdf_report(results, target, total_time)

    console.print(f"\n[bold green]Scan completed! Report saved as: {pdf_report}[/bold green]")
