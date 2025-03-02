import requests
import json
from bs4 import BeautifulSoup
import shodan

# Class to query external vulnerability databases
class VHostVulnerabilityScanner:

    def __init__(self, shodan_api_key, vulners_api_key):
        # Initialize APIs and base URLs
        self.shodan_api_key = shodan_api_key
        self.vulners_api_key = vulners_api_key
        self.shodan_client = shodan.Shodan(shodan_api_key)
        self.vulners_url = "https://vulners.com/api/v3/search/lucene/"

    # Function to query CVE Details for vhost related vulnerabilities
    def query_cve_details(self, search_query="vhost"):
        url = f"https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&search={search_query}&order=1"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            vulnerabilities = []
            for item in soup.find_all("tr", class_="srrowns"):
                cve_id = item.find("a").text.strip()
                vuln_summary = item.find("td", class_="vd").text.strip()
                vulnerabilities.append({"cve": cve_id, "summary": vuln_summary})
            return vulnerabilities
        else:
            return []

    # Function to query Exploit-DB for vhost related vulnerabilities
    def query_exploit_db(self, search_query="vhost"):
        url = f"https://www.exploit-db.com/search?type=exploits&q={search_query}"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            vulnerabilities = []
            for item in soup.find_all("tr"):
                exploit_title = item.find("td", class_="col1")
                if exploit_title:
                    exploit_name = exploit_title.text.strip()
                    vulnerabilities.append({"exploit": exploit_name, "url": item.find("a")["href"]})
            return vulnerabilities
        else:
            return []

    # Function to query Vulners API for vhost related vulnerabilities
    def query_vulners(self, search_query="vhost"):
        headers = {
            'Authorization': f"Bearer {self.vulners_api_key}"
        }
        params = {
            "query": search_query,
            "size": 5
        }
        response = requests.get(self.vulners_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = []
            for item in data['data']['search']:
                vuln_id = item.get('id')
                title = item.get('title')
                vulnerabilities.append({"vuln_id": vuln_id, "title": title})
            return vulnerabilities
        else:
            return []

    # Function to query Shodan for exposed services with vhost misconfigurations
    def query_shodan(self, search_query="vhost"):
        try:
            results = self.shodan_client.search(search_query)
            vulnerabilities = []
            for result in results['matches']:
                ip = result['ip_str']
                port = result['port']
                vulnerabilities.append({"ip": ip, "port": port, "data": result['data']})
            return vulnerabilities
        except shodan.APIError as e:
            print(f"Error querying Shodan: {e}")
            return []

    # Main function to gather vulnerabilities from multiple sources
    def get_vhost_vulnerabilities(self):
        cve_vulnerabilities = self.query_cve_details()
        exploit_db_vulnerabilities = self.query_exploit_db()
        vulners_vulnerabilities = self.query_vulners()
        shodan_vulnerabilities = self.query_shodan()

        all_vulnerabilities = {
            "CVE Details": cve_vulnerabilities,
            "Exploit DB": exploit_db_vulnerabilities,
            "Vulners": vulners_vulnerabilities,
            "Shodan": shodan_vulnerabilities
        }
        return all_vulnerabilities


# Example usage
if __name__ == "__main__":
    shodan_api_key = "aa6ZZ2ugynaDZHKgvEJLk22TgKeiKiNQey"
    vulners_api_key = "ZGH27RRUE8L7E2TCW6ZGO1EP1G8OQKYOJSBU2VFCBMN8AZC5EI2STMVLU07PFTR8"
    vhost_scanner = VHostVulnerabilityScanner(shodan_api_key, vulners_api_key)
    
    vulnerabilities = vhost_scanner.get_vhost_vulnerabilities()
    for source, vuln_list in vulnerabilities.items():
        print(f"\nVulnerabilities from {source}:")
        for vuln in vuln_list:
            print(vuln)
