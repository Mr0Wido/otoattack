#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import re
from typing import Optional

def remove_ansi_escape_sequences(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def clean_domain(domain: str) -> str:
    """Remove http:// or https:// from domain."""
    if domain.startswith("https://"):
        return domain[8:]
    elif domain.startswith("http://"):
        return domain[7:]
    return domain

def run_command(command: str, description: str = "") -> Optional[str]:
    """Run a shell command safely with error handling."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error {description}: {e.stderr}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(
        description='AUTOSSRF - Automated SSRF Testing Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-d', '--domain',
        required=False,
        help='Domain to test (e.g., example.com)'
    )
    parser.add_argument(
        '-s', '--server',
        required=True,
        help='SSRF detection server (e.g., Burp collaborator)'
    )
    parser.add_argument(
        '-f', '--file',
        required=False,
        help='File containing custom URLs (instead of using gau)'
    )
    args = parser.parse_args()

    # Validate inputs
    if not args.domain and not args.file:
        print("Error: Please provide either a domain (-d) or a file (-f)", file=sys.stderr)
        sys.exit(1)

    if args.file and not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' does not exist", file=sys.stderr)
        sys.exit(2)

    # Process domain or file
    temp_files = []
    try:
        if args.domain:
            domain = clean_domain(args.domain)
            print(f"[*] Fetching URLs for domain: {domain}")
            gau_command = f'gau {domain}'
            gau_output = run_command(gau_command, "fetching URLs with gau")
            if gau_output:
                with open("raw_urls.txt", 'w') as f:
                    f.write(gau_output)
                temp_files.append("raw_urls.txt")
        else:
            print(f"[*] Using URLs from file: {args.file}")
            with open(args.file, 'r') as src, open("raw_urls.txt", 'w') as dst:
                dst.write(src.read())
            temp_files.append("raw_urls.txt")

        # Process server URL
        server = args.server if args.server.startswith(('http://', 'https://')) else f"http://{args.server}"
        print(f"[*] Using SSRF server: {server}")

        # Parameterize URLs
        print("[*] Processing URLs...")
        commands = [
            "uniq raw_urls.txt | grep '?' | sort | qsreplace '' >> temp-parameterised_urls.txt",
            "cat raw_urls.txt | grep '=' >> parameterised_urls.txt"
        ]
        
        for cmd in commands:
            if not run_command(cmd, "processing URLs"):
                sys.exit(3)
        
        temp_files.extend(["temp-parameterised_urls.txt", "parameterised_urls.txt"])

        # Generate final URLs
        with open("parameterised_urls.txt", 'r') as infile, open("final_urls.txt", 'w') as outfile:
            for url in infile:
                url = url.strip()
                if not url:
                    continue
                    
                target = f"{server}/{url}" if "burp" in server else server
                processed_url = run_command(f'echo "{url}" | qsreplace "{target}"')
                if processed_url and '=' in processed_url:
                    outfile.write(processed_url)
        
        temp_files.append("final_urls.txt")

        # SSRF Testing
        print("[*] Starting SSRF testing...")
        ssrf_output = run_command("ffuf -w final_urls.txt -u FUZZ", "SSRF testing with ffuf")
        
        if ssrf_output:
            clean_output = remove_ansi_escape_sequences(ssrf_output)
            for line in clean_output.splitlines():
                if line.strip():
                    print(f"[Potential Vuln] {line}")
        
    finally:
        # Cleanup
        print("[*] Cleaning up temporary files...")
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception as e:
                print(f"Warning: Could not remove {temp_file}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()