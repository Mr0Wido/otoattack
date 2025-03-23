#!/usr/bin/env python3

import subprocess
import argparse
import threading

def run_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        stdout, stderr = process.communicate()
        if stderr:
            print(f"Hata: {stderr.decode()}")
        else:
            print(stdout.decode())
    except Exception as e:
        print(f"İşlem sırasında hata oluştu: {e}")

def parser_arguments():
    parser = argparse.ArgumentParser(description="CORS Scan.")
    parser.add_argument("-ul", "--url-list", help="Specify a URL list for CORS", required=True)
    parser.add_argument("-d", "--domain", help="Specify a domain to check for CORS", required=True)
    return parser.parse_args()

def scan_cors():
    args = parser_arguments()
    target_list = args.url_list
    domain = args.domain

    ## Basic Origin Reflection
    ## Trusted null Origin payload
    ## Whitelisted null origin value payload
    ## Trusted subdomain in Origin payload
    ## Abuse on not properly Domain validation
    ## Origin domain extension not validated vulnerability payload
    
    commands = [
        f"cat {target_list} | while read url; do target=$(curl -s -I -H \"Origin: https://evil.com\" -X GET $url); if echo \"$target\" | grep 'https://evil.com'; then echo \"[Potential CORS Found] $url\"; else echo \"Nothing on $url\"; fi; done | tee -a cors_results.txt",
        f"cat {target_list} | while read url; do target=$(curl -s -I -H \"Origin: null\" -X GET $url); if echo \"$target\" | grep 'Access-Control-Allow-Origin: null'; then echo \"[Potential CORS Found] $url\"; else echo \"Nothing on $url\"; fi; done | tee -a cors_results.txt",
        f"cat {target_list} | while read url; do target=$(curl -s -I -X GET \"$url\"); if echo \"$target\" | grep 'Access-Control-Allow-Origin: null'; then echo \"[Potential CORS Found] $url\"; else echo \"Nothing on $url\"; fi; done | tee -a cors_results.txt",
        f"cat {target_list} | while read url; do target=$(curl -s -I -H \"Origin: evil.$url\" -X GET \"$url\"); if echo \"$target\" | grep 'Access-Control-Allow-Origin: null'; then echo \"[Potential CORS Found] $url\"; else echo \"Nothing on $url\"; fi; done | tee -a cors_results.txt",
        f"cat {target_list} | while read url; do target=$(curl -s -I -H \"Origin: https://not{domain}\" -X GET \"$url\"); if echo \"$target\" | grep 'Access-Control-Allow-Origin: https://not{domain}'; then echo \"[Potential CORS Found] $url\"; else echo \"Nothing on $url\"; fi; done | tee -a cors_results.txt",
        f"cat {target_list} | while read url; do target=$(curl -s -I -H \"Origin: {domain}.evil.com\" -X GET \"$url\"); if echo \"$target\" | grep \"Origin: Access-Control-Allow-Origin: {domain}.evil.com\"; then echo \"[Potential CORS Found] $url\"; else echo \"Nothing on $url\"; fi; done | tee -a cors_results.txt"
    ]

    threads = []
    for command in commands:
        thread = threading.Thread(target=run_command, args=(command,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    
    with open("cors_results.txt", "r") as f:
        print(f.read())

if __name__ == "__main__":
    scan_cors()
