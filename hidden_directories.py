[import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import os
from bs4 import BeautifulSoup

class HiddenFileDetector:
    def __init__(self, base_url, wordlist_path=None, threads=10, headers=None, timeout=5):
        self.base_url = self.ensure_url_scheme(base_url)
        self.base_url = self.base_url if self.base_url.endswith('/') else self.base_url + '/'
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.headers = headers if headers else {"User-Agent": "Mozilla/5.0"}
        self.timeout = timeout
        self.found_items = []
        self.error_log = []
        self.default_wordlist = [
            ".git/", ".env", ".htaccess", ".htpasswd", ".config/", "admin/", "backup/", "db/", "test/",
            "tmp/", "logs/", ".ssh/", ".hidden", ".idea/", "uploads/", "private/", "config.php"
        ]

    @staticmethod
    def ensure_url_scheme(url):
        """Ensure the URL has a valid scheme."""
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
        return url

    def read_wordlist(self):
        """Load wordlist from file or use default."""
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            with open(self.wordlist_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        return self.default_wordlist

    def send_request(self, path):
        """Send a GET request to a specific path."""
        url = urljoin(self.base_url, path)
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            reason = self.analyze_response(path, response)
            if reason:
                self.found_items.append((path, response.status_code, len(response.content), reason))
                print(f"[FOUND] {path} - {reason}")
            else:
                print(f"[NOT FOUND] {path} (Status: {response.status_code})")
        except requests.RequestException as e:
            self.error_log.append(f"[ERROR] {url}: {e}")
            print(f"[ERROR] Could not connect to {url}: {e}")

    def analyze_response(self, path, response):
        """Analyze the response and determine why the path is considered hidden."""
        reasons = []

        # Check naming patterns
        if path.startswith("."):
            reasons.append("Starts with a '.' indicating a hidden file/directory.")
        if "config" in path.lower() or "backup" in path.lower():
            reasons.append("Contains sensitive keywords like 'config' or 'backup'.")

        # Check HTTP status code
        if response.status_code == 403:
            reasons.append("Access restricted (403 Forbidden).")
        elif response.status_code == 200:
            reasons.append("Accessible but may contain sensitive content.")

        # Check response size
        if len(response.content) > 0:
            reasons.append(f"Non-empty response detected (Size: {len(response.content)} bytes).")

        # Check headers
        if "X-Robots-Tag" in response.headers and "noindex" in response.headers["X-Robots-Tag"]:
            reasons.append("Marked as 'noindex' in X-Robots-Tag header.")

        return " | ".join(reasons) if reasons else None

    def parse_html(self, content):
        """Parse HTML to find additional paths."""
        soup = BeautifulSoup(content, "html.parser")
        paths = set()
        for tag in soup.find_all(["a", "script", "link"]):
            href = tag.get("href") or tag.get("src")
            if href and not href.startswith("#"):
                paths.add(urljoin(self.base_url, href))
        return paths

    def recursive_scan(self, path):
        """Recursively scan discovered directories."""
        if not path.endswith("/"):
            return
        print(f"[RECURSIVE SCAN] {path}")
        for item in self.default_wordlist:
            self.send_request(urljoin(path, item))

    def run(self):
        """Run the hidden file/directory detector."""
        print(f"Starting scan on {self.base_url}...\n")
        wordlist = self.read_wordlist()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.send_request, wordlist)

        print("\nRecursive scanning...\n")
        for path, _, _, _ in self.found_items:
            if path.endswith("/"):  # Only scan directories
                self.recursive_scan(path)

        self.save_results()

    def save_results(self):
        """Save the results to a file."""
        with open("found_items_with_reasons.txt", "w") as f:
            for path, status, size, reason in self.found_items:
                f.write(f"{path} (Status: {status}, Size: {size} bytes) - {reason}\n")

        with open("error_log.txt", "w") as f:
            for error in self.error_log:
                f.write(f"{error}\n")

        print("\nResults saved to 'found_items_with_reasons.txt' and 'error_log.txt'.")

# Example Usage
def main():
    url = input("Enter the target URL (e.g., https://example.com/): ").strip()
    wordlist_path = input("Enter the path to a custom wordlist file (or press Enter to use default): ").strip()
    wordlist_path = wordlist_path if wordlist_path else None
    threads = int(input("Enter the number of threads to use (default 10): ") or 10)
    headers = {"User-Agent": "Mozilla/5.0"}

    finder = HiddenFileDetector(base_url=url, wordlist_path=wordlist_path, threads=threads, headers=headers)
    finder.run()

if __name__ == "__main__":
    main()
]