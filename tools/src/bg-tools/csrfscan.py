#!/usr/bin/env python3

import os
import subprocess
import argparse
import sys
from pathlib import Path
from typing import Optional, List
import colorama
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama
colorama.init()

class CSRFTester:
    def __init__(self):
        self.args = self.parse_arguments()
        self.temp_files = []
        
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="Advanced CSRF (Cross-Site Request Forgery) Tester",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            "-ul", "--url-list",
            required=True,
            help="File containing list of URLs to test"
        )
        parser.add_argument(
            "-t", "--threads",
            type=int,
            default=4,
            help="Number of concurrent threads for XSRFProbe"
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=30,
            help="Timeout for each request in seconds"
        )
        parser.add_argument(
            "--no-cleanup",
            action="store_true",
            help="Keep temporary files after scan"
        )
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Show detailed output"
        )
        return parser.parse_args()

    def run_command(self, command: str, description: str = "") -> bool:
        """Run a shell command with error handling."""
        try:
            if self.args.verbose:
                print(colorama.Fore.CYAN + f"[*] Running: {command}" + colorama.Style.RESET_ALL)
                
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(colorama.Fore.RED + 
                  f"[!] Error {description}: {e.stderr.strip()}" + 
                  colorama.Style.RESET_ALL,
                  file=sys.stderr)
            return False

    def prepare_urls(self) -> bool:
        """Prepare URLs for testing."""
        output_file = "csrf_fuzzed_urls.txt"
        self.temp_files.append(output_file)
        
        # Run httpx to filter live hosts
        cmd = (
            f"httpx -l {self.args.url_list} "
            f"-title -sc -location -mc 200 "
            f"-td -cl -probe -nc -o {output_file}"
        )
        
        if not self.run_command(cmd, "filtering live hosts with httpx"):
            return False
            
        # Extract just the URLs
        temp_results = "csrf_temp_results.txt"
        self.temp_files.append(temp_results)
        
        cmd = (
            f"cat {output_file} | "
            f"awk '{{print $1}}' | "
            f"sed 's|https\\?://||' | "
            f"tee {temp_results}"
        )
        return self.run_command(cmd, "extracting URLs")

    def test_csrf(self) -> bool:
        """Test URLs for CSRF vulnerabilities."""
        input_file = "csrf_temp_results.txt"
        output_file = "csrf_temp.txt"
        self.temp_files.append(output_file)
        
        cmd = (
            f"xsrfprobe -i {input_file} "
            f"-q --random-agent --skip-poc "
            f"--threads {self.args.threads} "
            f"--timeout {self.args.timeout} "
            f"| tee -a {output_file}"
        )
        return self.run_command(cmd, "testing for CSRF vulnerabilities")

    def process_results(self) -> Optional[str]:
        """Process and format the results."""
        output_file = "csrf_results.txt"
        self.temp_files.append(output_file)
        
        cmd = (
            r"grep -E '(\[\+\]|\[\!\]|\[\-\]|CSRF|http|VULNERABLE)' csrf_temp.txt | "
            r"sed 's/\x1b\[[0-9;]*m//g' | "
            r"sed '/^ \[!\] Testing/ i\\' > {output_file}"
        )
        
        if not self.run_command(cmd, "processing results"):
            return None
            
        try:
            with open(output_file, "r") as f:
                return f.read()
        except IOError as e:
            print(colorama.Fore.RED +
                  f"[!] Error reading results: {e}" +
                  colorama.Style.RESET_ALL)
            return None

    def cleanup(self):
        """Remove temporary files."""
        if self.args.no_cleanup:
            print(colorama.Fore.YELLOW +
                  "[*] Keeping temporary files as requested" +
                  colorama.Style.RESET_ALL)
            return
            
        for file in self.temp_files:
            try:
                if os.path.exists(file):
                    os.remove(file)
            except Exception as e:
                print(colorama.Fore.YELLOW +
                      f"[!] Warning: Could not remove {file}: {e}" +
                      colorama.Style.RESET_ALL)

    def scan(self):
        """Execute the CSRF testing workflow."""
        print(colorama.Fore.CYAN + 
              "[*] Starting CSRF scan" + 
              colorama.Style.RESET_ALL)
        
        if not self.prepare_urls():
            return
            
        if not self.test_csrf():
            return
            
        results = self.process_results()
        if results:
            print(colorama.Fore.GREEN + 
                  "[+] CSRF Test Results:" + 
                  colorama.Style.RESET_ALL)
            print(results)
        else:
            print(colorama.Fore.YELLOW + 
                  "[-] No CSRF vulnerabilities found" + 
                  colorama.Style.RESET_ALL)
        
        self.cleanup()

if __name__ == "__main__":
    try:
        tester = CSRFTester()
        tester.scan()
    except KeyboardInterrupt:
        print(colorama.Fore.RED + 
              "\n[!] Scan interrupted by user" + 
              colorama.Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        print(colorama.Fore.RED + 
              f"[!] Unexpected error: {e}" + 
              colorama.Style.RESET_ALL)
        sys.exit(1)