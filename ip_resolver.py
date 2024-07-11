import argparse
import socket
import subprocess

def resolve_hostnames(input_file, output_file, ip_file, fast):
    with open(input_file, 'r') as f:
        hostnames = f.readlines()
    
    with open(output_file, 'w') as f_out, open(ip_file, 'w') as f_ip:
        for hostname in hostnames:
            hostname = hostname.strip()
            try:
                ip_address = socket.gethostbyname(hostname)
                f_ip.write(f"{ip_address}\n")
                
                if fast:
                    # Run nmap to detect OS
                    nmap_cmd = f"nmap -O {ip_address}"
                    nmap_output = subprocess.check_output(nmap_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
                    
                    os_info = "OS detection failed"
                    for line in nmap_output.splitlines():
                        if "OS details" in line:
                            os_info = line
                            break
                    
                    f_out.write(f"{hostname}: {ip_address} ({os_info})\n")
                else:
                    f_out.write(f"{hostname}: {ip_address}\n")
                
            except socket.gaierror:
                f_out.write(f"{hostname}: Resolution error\n")
            except subprocess.CalledProcessError as e:
                f_out.write(f"{hostname}: {ip_address} (nmap error)\n")
                f_out.write(e.output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Resolve hostnames to IP addresses and optionally detect OS.")
    parser.add_argument("-f", "--file", required=True, help="Input file with hostnames")
    parser.add_argument("-o", "--output", required=True, help="Output file for hostname to IP mapping and OS detection")
    parser.add_argument("-ip", "--ipoutput", required=True, help="Output file for IP addresses only")
    parser.add_argument("--fast", action="store_true", help="Enable fast mode for OS detection using nmap")

    args = parser.parse_args()

    resolve_hostnames(args.file, args.output, args.ipoutput, args.fast)
