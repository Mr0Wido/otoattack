#!/usr/bin/env python3

import os
import subprocess
import colorama
import argparse


def parser_arguments():
    parser = argparse.ArgumentParser(description="CSRF Scan.")
    parser.add_argument("-ul", "--url-list", help="Specify a URL list for CSRF", required=True)
    args = parser.parse_args()
    return args

def scan_csrf():
    args = parser_arguments()
    target_list = args.url_list
    ## csrf
    try:
        csrf_fuzzed_urls = "csrf_fuzzed_urls.txt"
        csrf_temp_results = "csrf_temp_results.txt"
        httpx_csrf_command = f" httpx -l {target_list} -title -sc -location -mc 200 -td -cl -probe -nc -o {csrf_fuzzed_urls}"
        httpx_csrf_out = subprocess.Popen(httpx_csrf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = httpx_csrf_out.communicate()
    
        sed_command = f"cat {csrf_fuzzed_urls} | awk '{{print $1}}' | sed 's|https\\?://||' | tee  {csrf_temp_results}"
        sed_out = subprocess.Popen(sed_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = sed_out.communicate()

    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error cleaning csrf: {e.stderr}")

    try:
        csrf_command = f"for URL in $(<{csrf_temp_results}); do (xsrfprobe -u \"${{URL}}\" -q --random-agent --skip-poc | tee -a csrf_temp.txt ); done"
        csrf_out = subprocess.Popen(csrf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        stdout, stderr = csrf_out.communicate()
                
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running csrf: {e.stderr}")

    try:
        sed2_command = r"grep -E '(\[\+\]|\[\!\]|\[\-\]|CSRF|http|VULNERABLE)' csrf_temp.txt | sed 's/\x1b\[[0-9;]*m//g'  | sed '/^ \[!\] Testing/ i\\' > output.txt"
        subprocess.run(sed2_command, shell=True, check=True)

        with open("output.txt", "r") as f:
            output = f.read()
            print(output)
    
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error searching csrf: {e.stderr}")

    subprocess.run("rm -rf csrf_temp_results.txt csrf_fuzzed_urls.txt csrf_temp.txt output.txt", shell=True)     

if __name__ == "__main__":
    scan_csrf()