import re
import argparse
import subprocess
from collections import defaultdict
from colorama import init, Fore, Style
from datetime import datetime

# Initialisation de colorama
init(autoreset=True)

# Liste des shares à colorer en rouge (blacklist)
blacklist = ['ADMIN$', 'C$', 'SYSVOL', 'IPC$']

# Fonction pour colorer les shares
def color_share(share_name):
    if share_name in blacklist:
        return f"{Fore.YELLOW}{share_name}{Style.RESET_ALL}"
    else:
        return f"{Fore.MAGENTA}{share_name}{Style.RESET_ALL}"

# Fonction pour colorer les permissions
def color_permission(permission):
    if permission == 'READ':
        return f"{Fore.GREEN}{permission}{Style.RESET_ALL}"
    elif permission == 'FULL':
        return f"{Fore.RED}{permission}{Style.RESET_ALL}"
    elif permission == 'WRITE':
        return f"{Fore.CYAN}{permission}{Style.RESET_ALL}"
    else:
        return permission

# Fonction pour exécuter le scan
def run_scan(ip_range, username, password):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_file = f'scanResult_{timestamp}.txt'
    print(f"{Fore.CYAN}Démarrage du scan SMB sur la plage {ip_range} avec l'utilisateur {username}...{Style.RESET_ALL}")
    command = f'crackmapexec smb {ip_range} -u {username} -p {password} --shares > {output_file}'
    subprocess.run(command, shell=True, check=True)
    print(f"{Fore.CYAN}Scan terminé. Résultats stockés dans {output_file}{Style.RESET_ALL}")
    return output_file

# Fonction principale
def main():
    # Initialisation de l'analyseur d'arguments
    parser = argparse.ArgumentParser(description='Extract SMB shares with read permissions from scan result.')
    parser.add_argument('-file', type=str, help='Path to the input file containing scan results')
    parser.add_argument('-scan', action='store_true', help='Run scan and store the result in a uniquely named file')
    parser.add_argument('-ip', type=str, help='IP range to scan (e.g., 10.4.0.0/16)')
    parser.add_argument('-u', type=str, help='Username for the scan')
    parser.add_argument('-p', type=str, help='Password for the scan')
    parser.add_argument('--filter', action='store_true', help='Filter out shares in the blacklist')

    # Parsing des arguments
    args = parser.parse_args()

    # Vérification des options et exécution du scan si nécessaire
    if args.scan:
        if not args.ip or not args.u or not args.p:
            parser.error('-scan requires -ip, -u, and -p.')
        input_file = run_scan(args.ip, args.u, args.p)
    else:
        if not args.file:
            parser.error('Either -file or -scan with -ip, -u, and -p must be specified.')
        input_file = args.file

    # Lecture du fichier
    print(f"{Fore.CYAN}Lecture du fichier {input_file}...{Style.RESET_ALL}")
    with open(input_file, 'r') as file:
        data = file.readlines()

    # Expression régulière pour extraire les informations
    share_pattern = re.compile(r'SMB\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\S+)\s+((?:READ|FULL|WRITE)(?:,\s*(?:READ|FULL|WRITE))*)')

    # Dictionnaire pour stocker les résultats par IP
    results = defaultdict(list)

    # Extraction des informations
    print(f"{Fore.CYAN}Extraction des informations des shares...{Style.RESET_ALL}")
    for line in data:
        match = share_pattern.search(line)
        if match:
            ip, share, permissions = match.groups()
            if args.filter and share in blacklist:
                continue
            colored_share = color_share(share)
            colored_permissions = ', '.join(color_permission(p.strip()) for p in permissions.split(','))
            results[ip].append(f"    {colored_share} {colored_permissions}")

    # Affichage des résultats
    print(f"{Fore.CYAN}Affichage des résultats :{Style.RESET_ALL}")
    for ip, shares in results.items():
        print(f"{Fore.CYAN}[---------------------------- {Fore.BLUE}{ip}{Fore.CYAN} ------------------------------]{Style.RESET_ALL}")
        print(f"smb://{ip}")
        for share in shares:
            print(share)

# Appel de la fonction principale
if __name__ == '__main__':
    main()
