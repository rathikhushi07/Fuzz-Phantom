import requests
import json
import itertools
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
import argparse

COMMON_DIRS = [
    "admin", "backup", "config", "hidden", "logs", "private", "secure", "uploads", "test"
]
COMMON_FILES = [
    "index.php", "config.php", ".env", "database.sql", "backup.zip", ".htaccess", "error.log"
]

def scrape_hints(target):
    """
    Scrape the target URL to extract words for directory/file hints.
    """
    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        words = [word for tag in soup.find_all() for word in tag.get_text().split()]
        return words
    except Exception as e:
        print(f"Error scraping target: {e}")
        return []

def generate_wordlist(base_words):
    """
    Generates an advanced wordlist by combining common words and scraped hints.
    """
    print("Generating wordlist...")
    combined_words = set(base_words + COMMON_DIRS + COMMON_FILES)
    return list(combined_words)

def ml_predict_hidden_paths(target, wordlist):
    """
    Predict hidden files and directories using an ML model.
    """
    print("Training ML model to predict likely hidden paths...")
    responses = []
    for word in wordlist:
        url = f"{target}/{word}"
        try:
            res = requests.head(url, timeout=5)
            responses.append((url, len(res.text), res.status_code))
        except:
            responses.append((url, 0, 404))

    # ML Model Training
    model = Pipeline([
        ("tfidf", TfidfVectorizer()),
        ("clf", RandomForestClassifier())
    ])
    data = [r[0] for r in responses]
    labels = [1 if r[2] in [200, 301] else 0 for r in responses]  # Successful paths
    model.fit(data, labels)

    predictions = model.predict(data)
    likely_paths = [responses[i][0] for i in range(len(predictions)) if predictions[i] == 1]
    print(f"Predicted hidden paths: {likely_paths}")
    return likely_paths

def directory_fuzzer(target, wordlist):
    """
    Perform advanced directory and file fuzzing.
    """
    print(f"Starting directory and file exploration on {target}...")
    discovered = []
    for word in wordlist:
        for ext in ["", ".php", ".html", ".log", ".zip"]:
            url = f"{target}/{word}{ext}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"Found: {url}")
                    discovered.append(url)
            except requests.RequestException:
                continue
    return discovered

def main():
    parser = argparse.ArgumentParser(description="Advanced Directory & File Exploration")
    parser.add_argument("--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--output", default="exploration_results.json", help="Path to save results")
    args = parser.parse_args()

    # Generate wordlist
    scraped_hints = scrape_hints(args.target)
    wordlist = generate_wordlist(scraped_hints)

    # Predict hidden paths with ML
    predicted_paths = ml_predict_hidden_paths(args.target, wordlist)

    # Fuzz directories and files
    results = directory_fuzzer(args.target, predicted_paths)

    # Save results
    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
