#!/usr/bin/env python3
# Phishing URL Detector
# Author: Rick Hayes
# License: MIT
# Version: 2.73
# README: Explains criteria. Analyzes URLs for phishing indicators.

import argparse
import logging
import json
from urllib.parse import urlparse

def setup_logging():
    """Configure logging to file."""
    logging.basicConfig(filename='phishing_url_detector.log', level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file: str) -> dict:
    """Load configuration from JSON file."""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Config loading failed: {e}")
        return {"max_length": 75, "suspicious_chars": "@%+-", "min_dots": 2}

def analyze_url(url: str, config: dict) -> int:
    """Analyze URL for phishing indicators, return suspicion score."""
    score = 0
    parsed = urlparse(url)

    if len(url) > config["max_length"]:
        score += 1
    if any(char in url for char in config["suspicious_chars"]):
        score += 1
    if parsed.netloc.count('.') < config["min_dots"]:
        score += 1
    if not parsed.scheme:
        score += 1

    return score

def main():
    """Main function to parse args and detect phishing URLs."""
    parser = argparse.ArgumentParser(description="Phishing URL Detector")
    parser.add_argument("--url", required=True, help="URL to analyze")
    parser.add_argument("--config", default="config.json", help="Config file path")
    args = parser.parse_args()

    setup_logging()
    config = load_config(args.config)

    logging.info(f"Analyzing URL: {args.url}")
    score = analyze_url(args.url, config)
    logging.info(f"Suspicion score: {score}")
    print(f"URL: {args.url}")
    print(f"Suspicion score: {score}")
    if score > 2:
        print("Warning: URL may be suspicious")

if __name__ == "__main__":
    main()
