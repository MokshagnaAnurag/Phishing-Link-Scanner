import re
import requests
from urllib.parse import urlparse
from colorama import Fore, Style


# Function to perform basic phishing checks on a given URL
def basic_phishing_check(url):
    # List of suspicious keywords typically used in phishing URLs
    suspicious_keywords = ["free", "login", "update", "verify", "secure", "account", "bank", "webscr", "confirm"]

    try:
        # Extract domain from the URL
        domain = urlparse(url).netloc

        # Check for suspicious characters like '@' or excessive subdomains
        if "@" in url or "-" in domain or len(domain.split(".")) > 3:
            print(Fore.RED + "[!] Suspicious character found: '@' or excessive subdomains." + Style.RESET_ALL)
            return True

        # Check if any suspicious keywords are found in the URL
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                print(Fore.RED + f"[!] Keyword '{keyword}' found in URL. Could be phishing!" + Style.RESET_ALL)
                return True

        # Check if the URL uses HTTPS for a secure connection
        if "https://" not in url[:8]:
            print(Fore.RED + "[!] URL does not use HTTPS. It might not be secure." + Style.RESET_ALL)
            return True

    except Exception as e:
        # Handle any errors that occur during the check
        print(Fore.YELLOW + f"[!] Error checking URL: {e}" + Style.RESET_ALL)
        return False

    return False


# Function to query VirusTotal for deeper analysis of the URL
def virustotal_check(url):
    API_KEY = "your_api_key_here"  # Replace with your actual VirusTotal API key
    VT_API_URL = "https://www.virustotal.com/vtapi/v2/url/report"  # VirusTotal URL for reporting

    params = {"apikey": API_KEY, "resource": url}

    try:
        # Send GET request to VirusTotal API
        response = requests.get(VT_API_URL, params=params)
        result = response.json()

        # Check if VirusTotal flagged the URL
        if result.get("positives", 0) > 0:
            print(Fore.RED + f"[!] VirusTotal flagged the URL with {result['positives']} detections!" + Style.RESET_ALL)
            return True
        else:
            print(Fore.GREEN + "[✓] VirusTotal shows no detections for the URL." + Style.RESET_ALL)
            return False
    except Exception as e:
        # Handle any errors that occur during the query
        print(Fore.YELLOW + f"[!] Could not query VirusTotal: {e}" + Style.RESET_ALL)
        return False


# Main block to run the phishing scanner
if __name__ == "__main__":
    print(Fore.CYAN + "=== Phishing Link Scanner ===" + Style.RESET_ALL)

    # Input URL from user
    url = input("Enter the URL to check: ").strip()

    # Perform basic phishing checks
    if basic_phishing_check(url):
        print(Fore.RED + "[!] URL might be a phishing link! Proceed with caution." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[✓] No immediate phishing indicators found in the URL." + Style.RESET_ALL)

    # Ask user if they want to perform a deeper analysis with VirusTotal
    vt_check = input("Do you want to query VirusTotal for deeper analysis? (yes/no): ").strip().lower()
    if vt_check in ["yes", "y"]:
        virustotal_check(url)
    else:
        print(Fore.YELLOW + "Skipping VirusTotal check." + Style.RESET_ALL)
