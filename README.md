######   tg:@RichardAlmeyda ######



# Enumeration Tool

## Introduction
This tool is designed for authorized security testing purposes only. Unauthorized use is illegal. Ensure you have the right to perform any enumeration activities.

## Installation
sudo git clone https://github.com/RichardAlmeyda/3num-tool.git

To install the required dependencies, use the following command:

#pip install -r requirements.txt


#sudo apt install gobuster hydra whatweb

This will install the necessary Python packages specified in the requirements.txt file and required tools




*Usage*

##python 3num.py -h

The tool supports multiple enumeration options. Here are some examples:

##Enumerate SSH:
python 3num.py -ssh_enum <target_host> -u <username> -p <password> -o <output_file

##Enumerate FTP with Credentials:
python 3num.py -ftp_enum <target_host> -u <username> -p <password> -o <output_file>

##Enumerate Anonymous FTP:
python 3num.py -ftp_anon_enum <target_host> -o <output_file>

##Enumerate HTTP with Gobuster:
python 3num.py -http_enum <target_host> -w <wordlist> -o <output_file>

##Bruteforce SSH with Hydra:
python 3num.py -ssh_brute <target_host> -u <username> -w <wordlist> -o <output_file>

##Enumerate HTTP with Nikto:
python 3num.py -web_enum <target_host> -o <output_file>

##Enumerate exploits with searchsplot
python 3num.py -exploit_enum <target> -o <output_file>

##Enumerate DNS:
python 3num.py -dns_enum <target_host> -o <output_file>

##Enumerate SMB:
python 3num.py -smb_enum <target_host> -u <username> -p <password> -o <output_file>


For more options, check the help menu:
python 3num.py -h


Notes
Adjust the options and parameters based on your testing requirements.
Always ensure you have the right permissions to perform the chosen enumeration activities.


This README provides a brief overview of the tool, installation instructions, and usage examples.




+----------------------------------------------SUPPORT--------------------------------------------------+


USDT TRC20 : TTttSQ274h6bEAbtS2mbLNQVg3K3HiSU6y

BTC : 1AbHQdVVLzAGQv153UnJmvKsmWdX6sEfjk
