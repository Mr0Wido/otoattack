#!/usr/bin/env python3

import subprocess
import argparse
import threading
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
import time

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_error(message: str) -> None:
    """Print error messages to stderr with red color."""
    sys.stderr.write(f"{Colors.RED}[!] {message}{Colors.RESET}\n")

def print_success(message: str) -> None:
    """Print success messages with green color."""
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")

def print_info(message: str) -> None:
    """Print informational messages with cyan color."""
    print(f"{Colors.CYAN}[*] {message}{Colors.RESET}")

def run_command(command: str) -> Optional[str]:
    """Execute a shell command with error handling."""
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            executable="/bin/bash"
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            print_error(f"Command failed: {command}\n{stderr.decode().strip()}")
            return None
            
        return stdout.decode().strip()
    except Exception as e:
        print_error(f"Error executing command: {e}")
        return None

def extract_domains(target_list: str) -> List[str]:
    """Extract unique domains from the target list."""
    command = (
        f"cat {target_list} | awk '{{print $1}}' | "
        f"sed 's|https\\?://||' | sed 's|/.*||' | "
        f"sort -u | tee probed_domains.txt"
    )
    
    if not run_command(command):
        print_error("Failed to extract domains")
        return []
    
    try:
        with open('probed_domains.txt', 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except IOError as e:
        print_error(f"Failed to read domains file: {e}")
        return []

def generate_base_commands(target_list: str) -> List[str]:
    """Generate base CORS test commands."""
    return [
        # Test with evil.com origin
        f"cat {target_list} | while read url; do "
        f"target=$(curl -s -I -H \"Origin: https://evil.com\" -X GET \"$url\"); "
        f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: https://evil.com'; then "
        f"echo \"[CORS] $url - Origin: https://evil.com\"; "
        f"fi; done",
        
        # Test with null origin
        f"cat {target_list} | while read url; do "
        f"target=$(curl -s -I -H \"Origin: null\" -X GET \"$url\"); "
        f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: null'; then "
        f"echo \"[CORS] $url - Origin: null\"; "
        f"fi; done",
        
        # Test with pre-existing null in response
        f"cat {target_list} | while read url; do "
        f"target=$(curl -s -I -X GET \"$url\"); "
        f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: null'; then "
        f"echo \"[CORS] $url - Pre-existing null origin\"; "
        f"fi; done",
        
        # Test with subdomain origin
        f"cat {target_list} | while read url; do "
        f"domain=$(echo \"$url\" | sed 's|https\\?://||' | sed 's|/.*||'); "
        f"target=$(curl -s -I -H \"Origin: https://evil.$domain\" -X GET \"$url\"); "
        f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: https://evil.$domain'; then "
        f"echo \"[CORS] $url - Origin: evil.$domain\"; "
        f"fi; done"
    ]

def generate_domain_specific_commands(target_list: str, domains: List[str]) -> List[str]:
    """Generate domain-specific CORS test commands."""
    commands = []
    for domain in domains:
        commands.extend([
            # Test with domain prefix
            f"cat {target_list} | while read url; do "
            f"target=$(curl -s -I -H \"Origin: https://not{domain}\" -X GET \"$url\"); "
            f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: https://not{domain}'; then "
            f"echo \"[CORS] $url - Origin: not{domain}\"; "
            f"fi; done",
            
            # Test with domain suffix
            f"cat {target_list} | while read url; do "
            f"target=$(curl -s -I -H \"Origin: https://{domain}.evil.com\" -X GET \"$url\"); "
            f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: https://{domain}.evil.com'; then "
            f"echo \"[CORS] $url - Origin: {domain}.evil.com\"; "
            f"fi; done",
            
            # Test with HTTP version
            f"cat {target_list} | while read url; do "
            f"target=$(curl -s -I -H \"Origin: http://{domain}\" -X GET \"$url\"); "
            f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: http://{domain}'; then "
            f"echo \"[CORS] $url - Origin: http://{domain}\"; "
            f"fi; done",
            
            # Test with port
            f"cat {target_list} | while read url; do "
            f"target=$(curl -s -I -H \"Origin: https://{domain}:8080\" -X GET \"$url\"); "
            f"if echo \"$target\" | grep -q 'Access-Control-Allow-Origin: https://{domain}:8080'; then "
            f"echo \"[CORS] $url - Origin: {domain}:8080\"; "
            f"fi; done"
        ])
    return commands

def scan_cors():
    """Main CORS scanning function."""
    parser = argparse.ArgumentParser(description="Advanced CORS Scanner")
    parser.add_argument("-ul", "--url-list", help="File containing list of URLs to test", required=True)
    parser.add_argument("-o", "--output", help="Output file for results", default="cors_results.txt")
    parser.add_argument("-t", "--threads", help="Number of concurrent threads", type=int, default=10)
    args = parser.parse_args()

    if not os.path.isfile(args.url_list):
        print_error(f"File not found: {args.url_list}")
        sys.exit(1)

    print_info(f"Starting CORS scan with {args.url_list}")
    start_time = time.time()

    # Extract domains for more targeted testing
    domains = extract_domains(args.url_list)
    if not domains:
        print_error("No domains found to test")
        sys.exit(1)

    # Generate test commands
    commands = generate_base_commands(args.url_list)
    commands.extend(generate_domain_specific_commands(args.url_list, domains))

    # Clear previous results
    if os.path.exists(args.output):
        os.remove(args.output)

    # Execute commands with thread pool
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(run_command, cmd) for cmd in commands]
        
        for future in futures:
            result = future.result()
            if result:
                with open(args.output, 'a') as f:
                    f.write(result + "\n")

    # Print summary
    elapsed = time.time() - start_time
    print_info(f"Scan completed in {elapsed:.2f} seconds")
    
    try:
        with open(args.output, 'r') as f:
            results = f.read().strip()
            if results:
                print_success("CORS vulnerabilities found:")
                print(results)
            else:
                print_info("No CORS vulnerabilities found")
    except IOError as e:
        print_error(f"Failed to read results file: {e}")

if __name__ == "__main__":
    scan_cors()