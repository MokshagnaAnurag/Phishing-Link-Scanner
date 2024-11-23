
import re
import requests
from urllib.parse import urlparse
from colorama import Fore, Style


def basic_phishing_check(url):

    suspicious_keywords = ["free", "login", "update", "verify", "secure", "account", "bank", "webscr", "confirm"]
    try:
        domain = urlparse(url).netloc
        if "@" in url or "-" in domain or len(domain.split(".")) > 3:
            print(Fore.RED + "[!] Suspicious character found: '@' or excessive subdomains." + Style.RESET_ALL)
            return True

        for keyword in suspicious_keywords:
            if keyword in url.lower():
                print(Fore.RED + f"[!] Keyword '{keyword}' found in URL. Could be phishing!" + Style.RESET_ALL)
                return True

        if "https://" not in url[:8]:
            print(Fore.RED + "[!] URL does not use HTTPS. It might not be secure." + Style.RESET_ALL)
            return True

    except Exception as e:
        print(Fore.YELLOW + f"[!] Error checking URL: {e}" + Style.RESET_ALL)
        return False

    return False


def virustotal_check(url):
    API_KEY = "your_api_key_here"
    VT_API_URL = "https://www.virustotal.com/vtapi/v2/url/report"

    params = {"apikey": API_KEY, "resource": url}
    try:
        response = requests.get(VT_API_URL, params=params)
        result = response.json()

        if result.get("positives", 0) > 0:
            print(Fore.RED + f"[!] VirusTotal flagged the URL with {result['positives']} detections!" + Style.RESET_ALL)
            return True
        else:
            print(Fore.GREEN + "[✓] VirusTotal shows no detections for the URL." + Style.RESET_ALL)
            return False
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not query VirusTotal: {e}" + Style.RESET_ALL)
        return False


if __name__ == "__main__":
    print(Fore.CYAN + "=== Phishing Link Scanner ===" + Style.RESET_ALL)

    url = input("Enter the URL to check: ").strip()

    if basic_phishing_check(url):
        print(Fore.RED + "[!] URL might be a phishing link! Proceed with caution." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "[✓] No immediate phishing indicators found in the URL." + Style.RESET_ALL)

    vt_check = input("Do you want to query VirusTotal for deeper analysis? (yes/no): ").strip().lower()
    if vt_check in ["yes", "y"]:
        virustotal_check(url)
    else:
        print(Fore.YELLOW + "Skipping VirusTotal check." + Style.RESET_ALL)
