
import re
import argparse
import subprocess

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
            urls.append(f"http://{ip}:{port}")

    return urls

def run_nmap_scan(ip_range):
    output_file = 'webResult.txt'
    nmap_command = ['nmap', '-p', '80,443,8443,65443,8083,8081,8082,8080', ip_range, '--open', '-oN', output_file]
    subprocess.run(nmap_command, check=True)
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Parse Nmap results and generate URLs.")
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
        print(url)

if __name__ == "__main__":
    main()
