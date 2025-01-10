import argparse
import paramiko
from ftplib import FTP, error_perm
from termcolor import colored
import socket
import subprocess
import time
from termcolor import cprint


def print_separator():
    print(colored("-" * 50, "blue"))

def print_section_header(header):
    print_separator()
    print(colored(f"[*] {header}", "cyan"))
    print_separator()

def print_command_output(command, output, output_file=None):
    print(f"\n{colored('[+]', 'green')} {colored('Command:', 'green')} {colored(command, 'yellow')}")
    print(f"{colored('[+]', 'green')} {colored('Output:', 'green')}")
    print(output)

    if output_file:
        with open(output_file, 'a') as file:
            file.write(f"\n{colored('[+]', 'green')} {colored('Command:', 'green')} {colored(command, 'yellow')}\n")
            file.write(f"{colored('[+]', 'green')} {colored('Output:', 'green')}\n{output}\n\n")


def enumerate_ssh(target_host, username, password, output_file=None):
    port = 22
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(colored(f"[*] Connecting to {target_host} via SSH...", "cyan"))
        time.sleep(1)
        print(colored(f"[*] Trying login with credentials...", "cyan"))
        time.sleep(1.5)
        ssh.connect(target_host, port, username, password)
        print(colored("[+] SSH Connection established.", "green"))

        ssh_commands = [
            'uname -a',
            'pwd',
            'ls -la',
            'whoami',
            'cat /etc/issue',
            'ifconfig',
            'cat /etc/passwd',
            'netstat -anp',
        ]

        for command in ssh_commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode().strip()
            print_command_output(command, output)

            if output_file:
                with open(output_file, 'a') as file:
                    file.write(f"\n{colored('[+]', 'green')} {colored('Command:', 'green')} {colored(command, 'yellow')}\n")
                    file.write(f"{colored('[+]', 'green')} {colored('Output:', 'green')}\n{output}\n\n")

    except Exception as e:
        print(colored(f"[-] Failed to connect to {target_host} via SSH: {e}", "red"))

    finally:
        ssh.close()
        print(colored("[*] SSH Connection closed.", "cyan"))
        
        



def enumerate_ftp(target_host, username, password, output_file=None, anonymous=False):
    ftp_port = 21
    ftp = None  # Initialize ftp to None
    error_code = None  # Initialize error_code to None

    try:
        # Connect to FTP server
        print(colored(f"[*] Connecting to {target_host} via FTP...", "cyan"))
        time.sleep(2)
        ftp = FTP()

        if not anonymous:
            # Attempt anonymous login first
            try:
                ftp.connect(target_host, ftp_port)
                print(colored("[*] Trying anonymous login...", "cyan"))
                ftp.login()
                print(colored("[+] FTP Connection established (Anonymous login).", "green"))
            except error_perm as e:
                if "530" in str(e):
                    print(colored("[-] Anonymous access not allowed", "red"))
                    if username != "" and password != "":
                        print(colored('[*] Trying with credentials...', "cyan"))
                        ftp = FTP()
                        ftp.connect(target_host, ftp_port)
                        ftp.login(username, password)
                        print(colored("[+] FTP Connection established (Authenticated login).", "green"))
                else:
                    raise
        else:
            ftp.connect(target_host, ftp_port)
            print(colored("[*] Trying anonymous login...", "cyan"))
            ftp.login("", "")
            print(colored("[+] FTP Connection established (Anonymous login).", "green"))

        # FTP commands for enumeration
        ftp_commands = [
            'pwd',
            'mlsd',  # Use 'mlsd' to list directory contents with details
        ]

        # Iterate through commands after successful login
        for command in ftp_commands:
            print_separator()

            if command == 'pwd':
                active_directory = ftp.pwd()
                print(colored(f"[+] Active directory: {active_directory}", "green"))

            elif command == 'mlsd':
                directory_listing = ftp.mlsd()
                print(colored("[+] Directory Listing:", "green"))
                for item in directory_listing:
                    print(item)

                # Download files with '.txt' extension

            # Save FTP command output to file if specified
            if output_file:
                with open(output_file, 'a') as file:
                    file.write(f"\n{colored('[+]', 'green')} {colored('FTP Command:', 'green')} {colored(command, 'yellow')}\n")
                    if command == 'mlsd':
                        for item in directory_listing:
                            file.write(item[0] + "\n")
                    else:
                        file.write(ftp.sendcmd(command))
                    file.write("\n")

    except Exception as e:
        error_code = str(e)
        print(colored(f"[-] An error occurred during process!: {e}", "red"))

    finally:
        # Close the FTP connection
        if error_code and '111' not in error_code and '530' not in error_code:
            try:
                ftp.quit()
            except (OSError, socket.error) as e:
                print(colored(f"[-] An error occurred while closing the FTP connection: {e}", "red"))
        print("[*] FTP Connection closed.")



def enumerate_http(target_host, wordlist, output_file=None):
    print(colored(f"[*] Enumerating HTTP on {target_host} using Gobuster...", "cyan"))
    time.sleep(1)
    
    gobuster_command = f"gobuster dir -u http://{target_host} -w {wordlist} -o {output_file}"
    subprocess.run(gobuster_command, shell=True)


def ftp_anon_enum(target_host, output_file=None):
    enumerate_ftp(target_host, username="", password="", output_file=output_file, anonymous=True)

def ssh_brute_force(target_host, username, wordlist, output_file=None):
    print(colored(f"[*] Bruteforcing SSH on {target_host} with Hydra...", "cyan"))
    time.sleep(1)

    hydra_command = f"hydra -v -l {username} -P {wordlist} ssh://{target_host} -t 4"
    subprocess.run(hydra_command, shell=True)
    
    
def web_enum(target_host, output_file=None):
    print(colored(f"[*] Running Nikto scan on {target_host}...", "cyan"))
    time.sleep(1)
    nikto_command = f"nikto -h {target_host} -o {output_file} -Format txt"
    subprocess.run(nikto_command, shell=True)
    
    

def dns_enum(target_host, output_file=None):
    print(colored(f"[*] Enumerating DNS for {target_host}...", "cyan"))
    time.sleep(1)

    print(colored(f"[*] Enumerating DNS with nslookup on {target_host}...", "cyan"))
    nslookup_command = f"nslookup {target_host}"
    nslookup_output = subprocess.getoutput(nslookup_command)
    print_command_output(nslookup_command, nslookup_output, output_file)
    print(colored(f"[*] completed 25%...", "cyan", attrs=["bold"]))
    time.sleep(10)
    
    print(colored(f"[*] Enumerating DNS with dig on {target_host}...", "cyan"))
    dig_trace_command = f"dig  {target_host} "
    dig_trace_output = subprocess.getoutput(dig_trace_command)
    print_command_output(dig_trace_command, dig_trace_output, output_file)
    print(colored(f"[*] completed 50%...", "cyan", attrs=["bold"]))
    time.sleep(10)
    
    
    print(colored(f"[*] Enumerating DNS with whois on {target_host}...", "cyan"))
    whois_command = f"whois {target_host}"
    whois_output = subprocess.getoutput(whois_command)
    print_command_output(whois_command, whois_output, output_file)
    print(colored(f"[*] completed 75%...", "cyan", attrs=["bold"]))
    time.sleep(10)
    
    print(colored(f"[*] Enumerating DNS with dnsrecon on {target_host}...", "cyan"))
    dnsrecon_command = f"dnsrecon -d {target_host}"
    dnsrecon_output = subprocess.getoutput(dnsrecon_command)
    print_command_output(dnsrecon_command, dnsrecon_output, output_file)
    print(colored(f"[*] successfully completed 100% of 100%!", "cyan", attrs=["bold"]))



def smb_enum(target_host, username, password, output_file=None):
    smb_commands = [
        'enum4linux -a {target_host}',  # Enumerate information about the target SMB server
        'smbclient -L //{target_host}',  # List shares on the target SMB server
    ]

    for command in smb_commands:
        print_separator()
        try:
            command = command.format(target_host=target_host)
            output = subprocess.getoutput(command)
            print_command_output(command, output, output_file)
        except Exception as e:
            print(colored(f"[-] An error occurred during SMB enumeration: {e}", "red"))



def exploit_enum(target_host, output_file=None):
    print_section_header(f"Exploit Enumeration for {target_host}")
    searchsploit_command = f"searchsploit {target_host}"
    searchsploit_output = subprocess.getoutput(searchsploit_command)
    print_command_output(searchsploit_command, searchsploit_output, output_file)


def sql_enum(target_host, output_file=None):
    print_section_header(f"SQL Enumeration for {target_host}")

    # SQLMap command for enumeration
    sqlmap_command = f"sqlmap -u {target_host} --random-agent --forms --crawl=2 --dbs --risk=3 --batch --level=5 --time-sec=20"

    subprocess.run(sqlmap_command, shell=True)





def print_banner():

    
    
    custom_lines = [
        "                 )         *     ",
        "            ) ( /(       (  `    ",
        "         ( /( )\())   (  )\))(   ",
        "         )\()|(_)\    )\((_)()\\  ",
        "       ((_)\ _((_)_ ((_|_()((_) ",
    ]

    lines = [
        "      |__ " + colored("(_)", "yellow", attrs=["bold"]) + " \| | | | |  \/  |",
        "       |_ \ | .` | |_| | |\/| |",
        "      |___/ |_|\_|\___/|_|  |_|",
        "  ____________________________________",
        " /___/___/___/___/___/___/___/___/___/",

        
    ]


    for line in custom_lines:
        print(colored(line, "yellow", attrs=["bold"]))
    for line in lines:
        print(colored(line, 'white', attrs=["bold"]))
    print(colored("Copyright (c) 2023 By @Richard. All rights reserved.", "white", attrs=['bold']))
    print(colored("ALL USED TOOLS:", "white", attrs=['bold']))

    
    
    tools = [
        "Hydra (Brute-force tool)",
        "Nikto (Web server scanner)",
        "Gobuster (Directory and file brute-forcer)",
        "Dig (DNS information tool)",
        "Enum4Linux (SMB enumeration tool)",
        "SMBClient (SMB enumeration tool)",
        "Nslookup (DNS lookup tool)",
        "Dnsrecon (DNS enumeration tool)",
        "Whois (DNS lookup tool)",
        "FTP (File Transfer Protocol)",
        "SSH (Secure Shell)",
        "Searchsploit (Exploit Database search tool)",
        "sqlmap (SQL enumeration tool)",
    ]
    
    for tool in tools:
        print(f"    - {colored(tool, 'white', attrs=['bold'])}")
    
    print(colored("=" * 50 + "\n", "blue"))
    
    
    
def print_warning():
    print(colored("[WARNING] This tool is intended for authorized security testing only.", "red", attrs=['bold']))
    print(colored("Using it against systems without permission is illegal.", "red", attrs=['bold']))
    print(colored("Please ensure you have the right to perform any enumeration activities.", "red", attrs=['bold']))
    print_separator()





def main():
    print_banner()
    print_warning()
    

    parser = argparse.ArgumentParser(description="Enumeration Tool")
    parser.add_argument("-ssh_enum", "--ssh_enum", dest="target_host_ssh", help="Target host to enumerate SSH")
    parser.add_argument("-ftp_enum", "--ftp_enum", dest="target_host_ftp", help="Target host to enumerate FTP with credentials")
    parser.add_argument("-ftp_anon_enum", "--ftp_anon_enum", dest="target_host_ftp_anon", help="Target host to enumerate anonymous FTP")
    parser.add_argument("-http_enum", "--http_enum", dest="target_host_http", help="Target host to enumerate HTTP")
    parser.add_argument("-ssh_brute", "--ssh_brute", dest="target_host_brute", help="Target host to brute-force SSH")
    parser.add_argument("-web_enum", "--web_enum", dest="target_host_web", help="Target host to enumerate HTTP with Nikto")
    parser.add_argument("-dns_enum", "--dns_enum", dest="target_host_dns", help="Target host to enumerate DNS")
    parser.add_argument("-smb_enum", "--smb_enum", dest="target_host_smb", help="Target host to enumerate SMB")
    parser.add_argument("-exploit_enum", "--exploit_enum", dest="exploit_target", help="Target for exploit enumeration")
    parser.add_argument("-sql_enum", "--sql_enum", dest="target_host_sql", help="Target host to enumerate SQL")
    parser.add_argument("-u", "--user", dest="username", default="anonymous", help="FTP/SSH/SMB username")
    parser.add_argument("-p", "--passwd", dest="password", default="", help="FTP/SSH/SMB password")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="Path to the wordlist for SSH brute-force")
    parser.add_argument("-o", "--output", dest="output_file", help="Output file to save results")
    args = parser.parse_args()


    if args.target_host_ssh:
        enumerate_ssh(args.target_host_ssh, args.username, args.password, args.output_file)
    elif args.target_host_ftp:
        enumerate_ftp(args.target_host_ftp, args.username, args.password, args.output_file, anonymous=False)
    elif args.target_host_ftp_anon:
        ftp_anon_enum(args.target_host_ftp_anon, args.output_file)
    elif args.target_host_http and args.wordlist:
        enumerate_http(args.target_host_http, args.wordlist, args.output_file)
    elif args.target_host_brute and args.username and args.wordlist:
        ssh_brute_force(args.target_host_brute, args.username, args.wordlist, args.output_file)
    elif args.target_host_web:
        web_enum(args.target_host_web, args.output_file)
    elif args.target_host_dns:
        dns_enum(args.target_host_dns, args.output_file)
    elif args.target_host_smb:
        if args.username and args.password:
            smb_enum(args.target_host_smb, args.username, args.password, args.output_file)
        else:
            smb_enum(args.target_host_smb, "", "", args.output_file)
    elif args.exploit_target:
        exploit_enum(args.exploit_target, args.output_file)
    elif args.target_host_sql:
        sql_enum(args.target_host_sql, args.output_file)
    else:
        
        print(colored("[-] Please specify a valid enumeration option.", "red"))

if __name__ == "__main__":
    main()
