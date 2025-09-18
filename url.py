import concurrent.futures
import logging
import urllib.request
import re
from urllib.parse import urlparse
import requests
import sys
import time
from colorama import Fore, Style
from pyfiglet import Figlet

# Cache to store analysis results
url_cache = {}

def print_tool_name():
    f = Figlet(font='cybermedium', width=80)
    colored_text = f"{Fore.CYAN}{f.renderText('URL Guardian')}{Style.RESET_ALL}"
    print(colored_text)
    print("                                      A tool for analyzing the safety of URLs")
    

def analyze_url(url):
    # Replace 'YOUR_API_KEY' with the actual API key
    api_key = 'at_BsoZQZAvHch9HjjNduxD313MiAITA'

    try:
        # Check if the analysis result is cached
        if url in url_cache:
            print(f"Using cached analysis for URL: {url}")
            return url_cache[url]

        # Fetch HTML content with User-Agent header
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                   'Referer': 'https://www.google.com/'}
        request = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(request) as response:
            if response.getcode() == 403:
                logging.warning(f"HTTP 403 Forbidden error for URL: {url}")
                return {'error': f"HTTP 403 Forbidden error for URL: {url}"}
            html_content = response.read()
            analysis_results = {}

            # Check for malicious patterns in HTML content
            suspicious_patterns = ['phishing', 'malware', 'attack','aixos', 'exploit', 'virus', 'trojan', 'spyware', 'ransomware', 'keylogger', 'adware', 'hijack', 'fraud', 'scam', 'identity theft', 'social engineering', 'cryptojacking', 'command injection', 'cross-site scripting', 'SQL injection', 'cross-site request forgery', 'clickjacking', 'drive-by download', 'zero-day', 'botnet', 'rootkit', 'backdoor', 'payload', 'phish', 'malicious', 'dangerous', 'untrusted', 'exploitable', 'insecure', 'threat', 'vulnerable', 'suspicious', 'exploited', 'compromised', 'attack vector', 'security breach', 'information leak', 'brute force', 'buffer overflow', 'denial of service', 'DNS spoofing', 'eavesdropping', 'firewall bypass', 'man-in-the-middle', 'zero-day exploit', 'security flaw', 'security hole', 'security risk', 'security vulnerability', 'data breach', 'privacy invasion', 'phishing site', 'malicious link', 'malicious file', 'infected', 'unauthorized access', 'unauthorized modification', 'sensitive information', 'security alert', 'security incident', 'cyber attack', 'threat actor', 'zero-day vulnerability']
            found_patterns = [pattern for pattern in suspicious_patterns if re.search(pattern, str(html_content, 'utf-8', 'ignore'), re.IGNORECASE)]
            analysis_results['suspicious_patterns'] = found_patterns

        # Check domain reputation using the provided API key
        domain_reputation = check_domain_reputation(api_key, url)
        analysis_results['domain_reputation'] = domain_reputation

        # Check for blacklisted IPs (using a hypothetical service)
        # Replace this with an actual IP blacklisting check API
        ip_blacklisted = check_ip_blacklisted(url)
        analysis_results['ip_blacklisted'] = ip_blacklisted

        # Determine if URL is safe based on analysis
        analysis_results['is_safe'] = not found_patterns and domain_reputation and domain_reputation.get('reputationScore', 0) > 80

        # If 'is_safe' cannot be determined, default to False
        if analysis_results['is_safe'] is None or domain_reputation is None:
            analysis_results['is_safe'] = False
            print("Setting is_safe to False (default)")

        # Cache the analysis result
        url_cache[url] = analysis_results
        return analysis_results

    except urllib.error.URLError as e:
        logging.error(f"Error analyzing URL {url}: {str(e)}")
        return {'error': f"Error analyzing URL {url}: {str(e)}"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e} while analyzing URL {url}")
        return {'error': f"Error analyzing URL {url}: {str(e)}"}
    except Exception as e:
        logging.error(f"An unexpected error occurred during analysis of URL {url}: {str(e)}")
        return {'error': f"An unexpected error occurred during analysis of URL {url}: {str(e)}"}

def check_domain_reputation(api_key, url):
    # Use the provided API key and endpoint for domain reputation check
    api_endpoint = f"https://domain-reputation.whoisxmlapi.com/api/v2"
    params = {
        'apiKey': api_key,
        'domainName': urlparse(url).netloc
    }

    try:
        response = requests.get(api_endpoint, params=params)
        if response.status_code == 200:
            reputation_data = response.json()
            return reputation_data
        else:
            logging.error(f"Error: {response.status_code} while checking domain reputation for {url}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e} while checking domain reputation for {url}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking domain reputation for {url}: {str(e)}")
        return None

def check_ip_blacklisted(url):
    # Simulate an IP blacklisting check
    # Replace this with an actual IP blacklisting check API
    return False  # Hypothetical result indicating not blacklisted

def analyze_single_url(url):
    try:
        return analyze_url(url)
    except Exception as e:
        logging.error(f"An unexpected error occurred during analysis of URL {url}: {str(e)}")
        return {'error': f"An unexpected error occurred during analysis of URL {url}: {str(e)}"}

def analyze_urls_multithreaded(urls):
    try:
        analysis_results = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(analyze_single_url, urls))

        for i, url in enumerate(urls):
            analysis_results[url] = results[i]

        return analysis_results
    except Exception as e:
        logging.error(f"An unexpected error occurred during multithreaded analysis: {str(e)}")
        return {'error': f"An unexpected error occurred during multithreaded analysis: {str(e)}"}

def analyze_url_with_retry(url, max_retries=3, retry_delay=2):
    for attempt in range(max_retries):
        result = analyze_url(url)
        if 'error' not in result:
            return result
        elif 'HTTP Error 403' in result['error']:
            logging.warning(f"Retrying after {retry_delay} seconds due to 403 error.")
            time.sleep(retry_delay)
        else:
            return result

    return {'error': f"Max retries reached. Unable to analyze URL {url}"}

def welcome_message():
    print_tool_name()
    welcome_message = """
==============================================================================================================================================
                                                   Welcome to URL Guardian
==============================================================================================================================================

URL Guardian is a powerful tool designed to analyze the safety of URLs, providing valuable insights into potential threats and security risks. Whether you're a security professional, a system administrator, or just cautious about the links you encounter, this tool can help you make informed decisions before clicking on URLs.

Key Features:
- Multithreaded analysis for efficient processing of multiple URLs.
- Checks domain reputation, blacklisted IPs, and suspicious patterns in HTML content.
- Color-coded output for quick identification of safe and potentially unsafe URLs.
- Logs analysis results and errors for review.

Instructions:
1. Run the script with one or more URLs as command-line arguments.
   Example: python url_guardian.py https://example.com https://malicious-site.org
2. Alternatively, enter URLs when prompted, separating multiple URLs with spaces.
3. The tool will provide color-coded results indicating the safety of each analyzed URL.

Note: Ensure you have the required dependencies installed. The tool will log analysis details in 'url_analysis.log.'

Thank you for choosing URL Guardian. Let's safeguard your online experience!
"""
    print(welcome_message)

def main():
    try:
        # Extract URLs from command-line arguments
        urls = sys.argv[1:]
        # Check if URLs are provided
        if not urls:
            print("Enter the URL(s) to analyze (separate multiple URLs with spaces):")
            # Prompt the user to enter URLs
            user_input = input()
            # Split the user input into individual URLs
            urls = user_input.split()

        # Continue with the analysis as before
        analysis_results = analyze_urls_multithreaded(urls)

        # Display analysis results
        for url, result in analysis_results.items():
            print(f"Analysis for URL: {url}")

            # Check if the 'is_safe' key is present in the result
            if 'is_safe' in result:
                if result['is_safe']:
                    print(f"{Fore.GREEN}{Style.BRIGHT}This URL is safe to click.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}{Style.BRIGHT}This URL is potentially unsafe.{Style.RESET_ALL}")
            else:
                print("Unable to determine the safety of the URL. Check the analysis result for details.")
                print("Analysis Result:", result)

            print("_"*80)
    except Exception as e:
        logging.error(f"An unexpected error occurred during the main execution: {str(e)}")

if __name__ == "__main__":
    try:
        # Configure logging to a file
        logging.basicConfig(filename='url_analysis.log', level=logging.INFO)

        main()
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
