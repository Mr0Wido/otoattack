#!/usr/bin/env python3

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
from urllib.parse import urlparse
from typing import List, Dict, Optional, Union
import time
import signal

# Constants
DEFAULT_ORIGIN = "https://evil.com"
DEFAULT_THREADS = 20
TIMEOUT = 10
VERSION = "1.1.0"

# Bypass strategies
BYPASS_STRATEGIES = [
    'null',
    'https://subdomain.evil.com',
    'http://localhost',
    'file://',
    lambda domain: f'https://{domain}.evil.com',
    lambda domain: f'https://evil.com.{domain}',
    lambda domain: f'https://{domain}.com',
    lambda domain: f'http://{domain}',
    lambda domain: f'http://{domain}.evil',
    lambda domain: f'https://{domain.split(".")[0]}.evil.com',
]

class Color:
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
    sys.stderr.write(f"{Color.RED}[!] {message}{Color.RESET}\n")

def print_success(message: str) -> None:
    """Print success messages with green color."""
    print(f"{Color.GREEN}[+] {message}{Color.RESET}")

def print_info(message: str) -> None:
    """Print informational messages with cyan color."""
    print(f"{Color.CYAN}[*] {message}{Color.RESET}")

def print_warning(message: str) -> None:
    """Print warning messages with yellow color."""
    print(f"{Color.YELLOW}[-] {message}{Color.RESET}")

def print_banner() -> None:
    """Display tool banner."""
    banner = f"""
{Color.BOLD}{Color.MAGENTA}
 ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║     ██║   ██║██████╔╝███████╗
██║     ██║   ██║██╔══██╗╚════██║
╚██████╗╚██████╔╝██║  ██║███████║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
{Color.RESET}
{Color.BLUE}Advanced CORS Scanner v{VERSION}{Color.RESET}
"""
    print(banner)

def is_vulnerable(response: requests.Response, origin: str) -> bool:
    """Determine if CORS headers indicate a vulnerability."""
    allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
    allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
    
    # Check for dangerous configurations
    if allow_origin == '*' and allow_credentials:
        return True
    
    if allow_origin == origin and allow_credentials:
        return True
    
    if allow_origin == '*' or allow_origin == origin:
        return True
    
    # Check for reflected origin with credentials
    if allow_origin == response.request.headers.get('Origin', '') and allow_credentials:
        return True
    
    return False

def generate_bypass_strategies(domain: str) -> List[str]:
    """Generate bypass strategies for the given domain."""
    strategies = []
    for strategy in BYPASS_STRATEGIES:
        if callable(strategy):
            strategies.append(strategy(domain))
        else:
            strategies.append(strategy)
    return strategies

def attempt_bypass(url: str) -> Dict[str, Union[bool, str]]:
    """Attempt various CORS bypass techniques."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    strategies = generate_bypass_strategies(domain)
    
    bypass_results = {}
    
    for origin in strategies:
        headers = {
            'Origin': origin,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.options(
                url,
                headers=headers,
                timeout=TIMEOUT,
                verify=False  # For testing purposes only
            )
            bypass_results[origin] = is_vulnerable(response, origin)
        except requests.RequestException:
            bypass_results[origin] = 'Failed'
    
    return bypass_results

def check_cors(
    url: str,
    origin: str = DEFAULT_ORIGIN,
    output_file: Optional[str] = None,
    output_format: str = 'text',
    filter_vulnerable: bool = False
) -> Optional[Dict]:
    """Check a single URL for CORS vulnerabilities."""
    try:
        headers = {
            'Origin': origin,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.options(
            url,
            headers=headers,
            timeout=TIMEOUT,
            verify=False  # For testing purposes only
        )
        
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', 'Not Present'),
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', 'Not Present'),
            'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', 'Not Present'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials', 'Not Present'),
            'Access-Control-Expose-Headers': response.headers.get('Access-Control-Expose-Headers', 'Not Present')
        }
        
        vulnerable = is_vulnerable(response, origin)
        bypass_results = attempt_bypass(url)
        bypass_success = any(result == True for result in bypass_results.values())
        
        result = {
            'url': url,
            'origin': origin,
            'status_code': response.status_code,
            'vulnerable': vulnerable or bypass_success,
            'headers': cors_headers,
            'bypass_attempts': bypass_results,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if filter_vulnerable and not result['vulnerable']:
            return None
        
        if output_format == 'json':
            output = json.dumps(result, indent=4)
        else:
            output = []
            output.append(f"{Color.BOLD}URL:{Color.RESET} {url}")
            output.append(f"{Color.BOLD}Status:{Color.RESET} {response.status_code}")
            
            if result['vulnerable']:
                output.append(f"{Color.RED}{Color.BOLD}VULNERABLE CORS CONFIGURATION DETECTED!{Color.RESET}")
            else:
                output.append(f"{Color.GREEN}No CORS vulnerability detected{Color.RESET}")
            
            output.append(f"\n{Color.BOLD}CORS Headers:{Color.RESET}")
            for header, value in cors_headers.items():
                if value != 'Not Present':
                    output.append(f"  {header}: {value}")
            
            if result['vulnerable']:
                output.append(f"\n{Color.BOLD}Bypass Attempts:{Color.RESET}")
                for origin, success in bypass_results.items():
                    if success == 'Failed':
                        output.append(f"  {origin}: {Color.YELLOW}Request failed{Color.RESET}")
                    elif success:
                        output.append(f"  {origin}: {Color.RED}SUCCESS{Color.RESET}")
                    else:
                        output.append(f"  {origin}: {Color.GREEN}Failed{Color.RESET}")
            
            output.append(f"\n{'-'*60}")
            output = "\n".join(output)
        
        print(output)
        
        if output_file:
            try:
                mode = 'a' if os.path.exists(output_file) else 'w'
                with open(output_file, mode) as f:
                    if output_format == 'json':
                        f.write(output + "\n")
                    else:
                        f.write(output.replace(Color.RED, '')
                                      .replace(Color.GREEN, '')
                                      .replace(Color.YELLOW, '')
                                      .replace(Color.BLUE, '')
                                      .replace(Color.MAGENTA, '')
                                      .replace(Color.CYAN, '')
                                      .replace(Color.WHITE, '')
                                      .replace(Color.RESET, '')
                                      .replace(Color.BOLD, '') + "\n")
            except IOError as e:
                print_error(f"Failed to write to output file: {e}")
        
        return result
    
    except requests.RequestException as e:
        if not filter_vulnerable:
            print_warning(f"Could not connect to {url}: {str(e)}")
        return None

def signal_handler(sig, frame):
    """Handle Ctrl+C interrupt."""
    print_info("\nScan interrupted by user. Exiting gracefully...")
    sys.exit(0)

def main():
    """Main function to handle command-line arguments and execution."""
    signal.signal(signal.SIGINT, signal_handler)
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced CORS Scanner - Detect and test for CORS misconfigurations",
        add_help=False
    )
    
    parser.add_argument(
        "-u", "--url",
        help="Single URL to test for CORS misconfigurations"
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing list of URLs to test (one per line)"
    )
    parser.add_argument(
        "-r", "--origin",
        default=DEFAULT_ORIGIN,
        help=f"Custom origin to use for testing (default: {DEFAULT_ORIGIN})"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        "-o", "--output",
        help="File to save scan results"
    )
    parser.add_argument(
        "--format",
        choices=['text', 'json'],
        default='text',
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--filter",
        action='store_true',
        help="Only show vulnerable results"
    )
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        help="Show verbose output"
    )
    parser.add_argument(
        "-h", "--help",
        action='store_true',
        help="Show this help message and exit"
    )
    
    args = parser.parse_args()
    
    if args.help:
        parser.print_help()
        sys.exit(0)
    
    if not args.url and not args.file:
        print_error("You must specify either a URL (-u) or a file of URLs (-f)")
        parser.print_help()
        sys.exit(1)
    
    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend(line.strip() for line in f if line.strip())
        except IOError as e:
            print_error(f"Failed to read URL file: {e}")
            sys.exit(1)
    
    print_info(f"Starting scan with {len(urls)} URLs using {args.threads} threads")
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                check_cors,
                url,
                args.origin,
                args.output,
                args.format,
                args.filter
            )
            for url in urls
        ]
        
        for future in as_completed(futures):
            future.result()  # We handle results in the function
    
    elapsed = time.time() - start_time
    print_info(f"Scan completed in {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()