import random
import string
import os
from flask import Flask, jsonify, request
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
from urllib.parse import urlparse

# Wordlist Generator Class with False Positive Handling
class WordlistGenerator:
    def __init__(self, min_length=5, max_length=12, custom_words=None):
        self.min_length = min_length
        self.max_length = max_length
        self.custom_words = custom_words if custom_words else []
        self.character_set = string.ascii_lowercase + string.digits + string.punctuation
        self.common_words = set(["password", "123456", "qwerty", "letmein"])  # Example common words

    def is_complex(self, word):
        """
        Check if a word is complex enough (not too simple or common).
        """
        return len(word) > 5 and any(char.isdigit() for char in word) and any(char in string.punctuation for char in word)

    def generate_base_words(self):
        """
        Generate base words from a set of custom or random combinations.
        Filters out too simple or common words.
        """
        words = []
        # Include custom words
        if self.custom_words:
            words.extend(self.custom_words)
        # Generate random words
        for _ in range(100):  # Adjust the number of words
            word_length = random.randint(self.min_length, self.max_length)
            word = ''.join(random.choice(self.character_set) for _ in range(word_length))

            # Check for false positives (common or simple words)
            if word not in self.common_words and self.is_complex(word):
                words.append(word)
        return words

    def save_wordlist(self, file_name="wordlist.txt"):
        """
        Save generated wordlist to a file
        """
        words = self.generate_base_words()
        with open(file_name, 'w') as f:
            for word in words:
                f.write(f"{word}\n")
        return words

# VHost Configurator Class
class VHostConfigurator:
    def __init__(self, domain_name, document_root, config_dir=None):
        self.domain_name = domain_name
        self.document_root = document_root
        self.config_dir = config_dir or self.get_default_config_dir()

    def get_default_config_dir(self):
        """
        Get default config directory based on the operating system
        """
        user_dir = os.path.expanduser("~")  # Get the home directory
        default_dir = os.path.join(user_dir, "vhosts")
        return default_dir

    def generate_vhost_config(self):
        """
        Generates a virtual host configuration for Apache
        """
        vhost_config = f"""
<VirtualHost *:80>
    ServerAdmin webmaster@{self.domain_name}
    ServerName {self.domain_name}
    DocumentRoot {self.document_root}
    ErrorLog ${{APACHE_LOG_DIR}}/error.log
    CustomLog ${{APACHE_LOG_DIR}}/access.log combined
</VirtualHost>
"""
        return vhost_config

    def save_vhost_config(self):
        """
        Save vhost configuration to file if no conflicts
        """
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)  # Create the directory if it doesn't exist
        
        config_path = os.path.join(self.config_dir, f"{self.domain_name}.conf")
        with open(config_path, 'w') as f:
            f.write(self.generate_vhost_config())
        return config_path

# PDF Report Generator
class PDFReportGenerator:
    @staticmethod
    def generate_report(wordlist, vhost_config, target_url, output_file="report.pdf"):
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph("Security Report", styles['Title']))
        story.append(Spacer(1, 12))

        # Target URL Section
        story.append(Paragraph("Target URL", styles['Heading2']))
        story.append(Paragraph(target_url, styles['BodyText']))
        story.append(Spacer(1, 12))

        # Wordlist Section
        story.append(Paragraph("Generated Wordlist", styles['Heading2']))
        for word in wordlist:
            story.append(Paragraph(word, styles['BodyText']))
        story.append(Spacer(1, 12))

        # VHost Config Section
        story.append(Paragraph("Generated VHost Configuration", styles['Heading2']))
        story.append(Paragraph(f"<pre>{vhost_config}</pre>", styles['BodyText']))
        
        # Save PDF
        doc.build(story)
        print(f"PDF report saved as {output_file}")

# Flask Application Setup for API
app = Flask(__name__)

@app.route('/generate-wordlist', methods=['POST'])
def generate_wordlist():
    """
    API Endpoint to trigger wordlist generation based on user input
    """
    try:
        data = request.json
        min_length = data.get('min_length', 5)
        max_length = data.get('max_length', 12)
        custom_words = data.get('custom_words', [])

        wordlist_generator = WordlistGenerator(min_length, max_length, custom_words)
        wordlist = wordlist_generator.save_wordlist()

        return jsonify({"message": "Wordlist generated successfully!", "wordlist": wordlist}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/get-vhost-config', methods=['GET'])
def get_vhost_config():
    """
    API Endpoint to generate vhost config based on query params
    """
    try:
        domain_name = request.args.get('domain_name', 'localhost')
        document_root = request.args.get('document_root', '/var/www/html')

        vhost_configurator = VHostConfigurator(domain_name, document_root)
        vhost_config = vhost_configurator.generate_vhost_config()

        return jsonify({"vhost_config": vhost_config}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/process-target-url', methods=['POST'])
def process_target_url():
    """
    API Endpoint to process a target URL and generate associated report
    """
    try:
        data = request.json
        target_url = data.get('target_url')

        if not target_url:
            raise ValueError("Target URL must be provided.")

        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL format.")

        # Generate Wordlist
        min_length = data.get('min_length', 5)
        max_length = data.get('max_length', 12)
        custom_words = data.get('custom_words', [])
        wordlist_generator = WordlistGenerator(min_length, max_length, custom_words)
        wordlist = wordlist_generator.save_wordlist()

        # Generate VHost Config
        domain_name = parsed_url.netloc
        document_root = data.get('document_root', '/var/www/html')
        vhost_configurator = VHostConfigurator(domain_name, document_root)
        vhost_config = vhost_configurator.generate_vhost_config()

        # Create PDF Report
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_file = f"security_report_{timestamp}.pdf"
        PDFReportGenerator.generate_report(wordlist, vhost_config, target_url, report_file)

        return jsonify({"message": "Report generated successfully!", "report_file": report_file}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    # Start the Flask API server
    app.run(debug=True)
