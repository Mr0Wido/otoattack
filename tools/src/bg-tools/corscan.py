#!/usr/bin/env python3

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
from urllib.parse import urlparse

def print_error(message, show_error=True):
    if show_error:
        sys.stderr.write(f"Error: {message}\n")
     

def is_vulnerable(response, origin):
    allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
    allow_credentials = response.headers.get('Access-Control-Allow-Credentials', 'false')
    
    if allow_origin == '*' and allow_credentials.lower() == 'true':
        return True
    
    if allow_origin == origin and allow_credentials.lower() == 'true':
        return True
    
    if allow_origin == '*' or allow_origin == origin:
        return True
    
    return False


def attempt_bypass(url):
    # Extract the domain from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    bypass_strategies = [
        'null',  # Use 'null' as the Origin
        'https://subdomain.evil.com',  # Use a subdomain
        'http://localhost',  # Use localhost as Origin
        'file://',  # Use file scheme
        f'https://{domain}.evil.com',  # Add ".evil.com" to the domain
        f'https://evil.com.{domain}',  # Add "evil.com." before the domain
        f'https://{domain}.com',  # Append ".com" to the domain
        f'http://{domain}',  # Use HTTP version of the domain
        f'http://{domain}.evil',  # Add ".evil" to the domain
        f'https://{domain.split(".")[0]}.evil.com',  # Use subdomain only with ".evil.com"
    ]

    bypass_results = {}

    for origin in bypass_strategies:
        headers = {'Origin': origin}
        try:
            response = requests.options(url, headers=headers, timeout=10)
            if is_vulnerable(response, origin):
                bypass_results[origin] = True
            else:
                bypass_results[origin] = False
        except requests.RequestException:
            bypass_results[origin] = 'Failed'

    return bypass_results

def check_cors(url, origin, output_file=None, output_format='text', filter_vulnerable=False):
    try:
        headers = {'Origin': origin}

        response = requests.options(url, headers=headers, timeout=10)
        cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']

        result = {
            'url': url,
            'origin': origin,
            'status_code': response.status_code,
            'vulnerable': is_vulnerable(response, origin),
            'headers': {header: response.headers.get(header, 'Not Present') for header in cors_headers}
        }

        bypass_results = attempt_bypass(url)
        bypass_success = any(result == True for result in bypass_results.values())

        # Filter results if needed
        if filter_vulnerable and not (result['vulnerable'] or bypass_success):
            return

        # Filter bypass results if needed
        if filter_vulnerable:
            bypass_results = {origin: result for origin, result in bypass_results.items() if result == True}

        if output_format == 'json':
            result['bypass_attempts'] = bypass_results
            result_output = json.dumps(result, indent=4)
        else:
            result_output = []
            result_output.append(f"URL: {url}")
            result_output.append(f"Origin: {origin}")
            result_output.append(f"Status Code: {response.status_code}")

            if result['vulnerable']:
                result_output.append(f"Potential Vulnerability Detected!")
            else:
                result_output.append(f"No CORS Vulnerability Detected")

            for header, value in result['headers'].items():
                if value != 'Not Present':
                    result_output.append(f"{header}: {value}")

            if not result['headers']:
                result_output.append(f"CORS Headers Not Found")

            result_output.append(f"CORS Bypass Attempts:")
            for origin, result in bypass_results.items():
                if result == 'Failed':
                    result_output.append(f"{origin}: Request Failed")
                else:
                    result_output.append(f"{origin}: {'Successful' if result else 'Failed'}")

            result_output.append("-" * 50)
            result_output = "\n".join(result_output)

        print(result_output)

        if output_file:
            try:
                with open(output_file, 'a') as f:
                    f.write(result_output + "\n")
            except IOError as e:
                print_error(f"Failed to write to output file {output_file}: {e}")

    except requests.RequestException as e:
        print_error(f"Could not connect to {url}. The URL may be invalid or unreachable.", not filter_vulnerable)

def print_help():
    help_text = f"""
Usage:
      crsn [options]

Options:
  -u, --url       Target URL to check CORS headers
  -f, --file      File containing a list of URLs to check CORS headers
  -r, --origin    Custom origin to use for the CORS check (default: https://evil.com)
  -t, --threads   Number of threads to use for scanning (default: 20)
  -o, --output    File to save the output
  --format         Output format: text (default) or json
  --filter        Filter results to show only vulnerable entries
  -h, --help      Show this help message and exit

Description:
  Advanced CORS Header Checker Tool with Vulnerability Detection and Bypass Attempts.
    """
    print(help_text)

def main():

    parser = argparse.ArgumentParser(add_help=False)  # Disable default help
    parser.add_argument("-u", "--url", help="Target URL to check CORS headers")
    parser.add_argument("-f", "--file", help="File containing a list of URLs to check CORS headers")
    parser.add_argument("-r", "--origin", default="https://evil.com", help="Custom origin to use for the CORS check (default: https://evil.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads to use for scanning (default: 20)")
    parser.add_argument("-o", "--output", help="File to save the output")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="Output format: text (default) or json")
    parser.add_argument("--filter", action='store_true', help="Filter results to show only vulnerable entries")
    parser.add_argument("-h", "--help", action='store_true', help="Show help message and exit")

    args = parser.parse_args()

    if args.help:
        print_help()
        sys.exit(0)

    if not args.url and not args.file:
        print_error("Please provide a URL with -u or a file with -f or -h for help.")
        sys.exit(1)

    try:
        if args.url:
            check_cors(args.url, origin=args.origin, output_file=args.output, output_format=args.format, filter_vulnerable=args.filter)

        if args.file:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(check_cors, url, origin=args.origin, output_file=args.output, output_format=args.format, filter_vulnerable=args.filter) for url in urls]
                for future in as_completed(futures):
                    future.result()
    
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
