import re
import argparse
import subprocess
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def parse_nmap_results(file_path):
    urls = []
    with open(file_path, 'r') as file:
        content = file.read()

    # Regex pour capturer les sections de rapports Nmap
    report_blocks = re.findall(r'Nmap scan report for (.+?)\nHost is up.*?\nPORT\s+STATE\s+SERVICE\n(.+?)(?=\nNmap|$)', content, re.S)

    for block in report_blocks:
        host_info, ports_info = block
        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_info)
        
        # Si l'IP n'est pas entre parenthèses, on suppose que l'info est un IP directement.
        if ip_match:
            ip = ip_match.group(1)
        else:
            ip = host_info

        ports = re.findall(r'(\d+)/tcp\s+open', ports_info)
        for port in ports:
            if port in ['80', '8080']:
                protocol = 'http'
            else:
                protocol = 'https'
            urls.append(f"{protocol}://{ip}:{port}")

    return urls

def run_nmap_scan(ip_range):
    output_file = 'webResult.txt'
    nmap_command = ['nmap', '-p', '80,443,8443,65443,8083,8081,8082,8080', ip_range, '--open', '-oN', output_file]
    subprocess.run(nmap_command, check=True)
    return output_file

def fetch_page_preview(url):
    try:
        response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else 'No title found'
        # Extract some text content for preview, limited to 200 characters
        content = soup.get_text(strip=True)
        content_preview = content[:200] if content else 'No content found'
        redirect_info = response.url if response.url != url else 'No redirection'
        return title, content_preview, redirect_info
    except requests.RequestException as e:
        return 'Error fetching page', str(e), 'No redirection'

def main():
    init(autoreset=True)  # Initialize colorama and auto-reset colors after each print
    parser = argparse.ArgumentParser(description="Parse Nmap results and generate URLs with previews.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-file', dest='file_path', help="Path to the Nmap results file.")
    group.add_argument('-ip', dest='ip_range', help="IP range to scan with Nmap (e.g., 10.10.10.2/24).")

    args = parser.parse_args()

    if args.file_path:
        urls = parse_nmap_results(args.file_path)
    elif args.ip_range:
        nmap_output_file = run_nmap_scan(args.ip_range)
        urls = parse_nmap_results(nmap_output_file)

    for url in urls:
        title, content_preview, redirect_info = fetch_page_preview(url)
        print(f"{Fore.MAGENTA}URL: {Fore.CYAN}{url}")
        print(f"{Fore.BLUE}Title: {Style.RESET_ALL}{title}")
        print(f"{Fore.GREEN}Content Preview: {Style.RESET_ALL}{content_preview}")
        print(f"{Fore.RED}Redirection: {Style.RESET_ALL}{redirect_info}\n")

if __name__ == "__main__":
    main()
