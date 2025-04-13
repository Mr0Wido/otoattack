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

class LFIScanner:
    def __init__(self):
        self.args = self.parse_arguments()
        self.temp_files = []
        
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="Advanced LFI (Local File Inclusion) Scanner",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            "-l", "--url-list",
            required=True,
            help="File containing list of URLs to test"
        )
        parser.add_argument(
            "-p", "--payloads",
            default="tools/src/lfipayloads.txt",
            help="File containing LFI payloads"
        )
        parser.add_argument(
            "-t", "--threads",
            type=int,
            default=20,
            help="Number of concurrent threads"
        )
        parser.add_argument(
            "--no-cleanup",
            action="store_true",
            help="Keep temporary files after scan"
        )
        return parser.parse_args()

    def run_command(self, command: str, description: str = "") -> bool:
        """Run a shell command with error handling."""
        try:
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
        """Prepare URLs for fuzzing."""
        output_file = "lfi_fuzzed_urls.txt"
        self.temp_files.append(output_file)
        
        cmd = f"params -u {self.args.url_list} -o {output_file}"
        return self.run_command(cmd, "preparing URLs")

    def scan_urls(self) -> bool:
        """Scan URLs with FFUF."""
        if not os.path.exists(self.args.payloads):
            print(colorama.Fore.RED +
                  f"[!] Payload file not found: {self.args.payloads}" +
                  colorama.Style.RESET_ALL)
            return False

        output_dir = "ffuf_lfi_results"
        self.temp_files.append(output_dir)
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(exist_ok=True)
        
        cmd = (
            f"for URL in $(<lfi_fuzzed_urls.txt); do "
            f"ffuf -u \"${{URL}}\" -w {self.args.payloads}:FUZZ "
            f"-mc 200 -ac -sa -t {self.args.threads} "
            f"-or -od {output_dir}; "
            f"done"
        )
        return self.run_command(cmd, "scanning URLs")

    def analyze_results(self) -> Optional[str]:
        """Analyze FFUF results for successful LFI."""
        results_file = "lfi_temp_results.txt"
        self.temp_files.append(results_file)
        
        cmd = f"grep -Ril 'root:x' ffuf_lfi_results/ | tee {results_file}"
        if not self.run_command(cmd, "analyzing results"):
            return None
        
        vuln_file = "vuln.txt"
        self.temp_files.append(vuln_file)
        
        cmd = (
            "grep -o 'ffuf_lfi_results/[^ ]*' lfi_temp_results.txt | "
            "xargs -I {} sh -c 'echo \"=============VULNERABLE============\" >> vuln.txt; "
            "cat {} >> vuln.txt; echo \"\" >> vuln.txt'"
        )
        if not self.run_command(cmd, "collecting vulnerable results"):
            return None
        
        try:
            with open(vuln_file, "r") as f:
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
                if os.path.isdir(file):
                    subprocess.run(f"rm -rf {file}", shell=True)
                elif os.path.exists(file):
                    os.remove(file)
            except Exception as e:
                print(colorama.Fore.YELLOW +
                      f"[!] Warning: Could not remove {file}: {e}" +
                      colorama.Style.RESET_ALL)

    def scan(self):
        """Execute the LFI scan workflow."""
        print(colorama.Fore.CYAN + 
              "[*] Starting LFI scan" + 
              colorama.Style.RESET_ALL)
        
        if not self.prepare_urls():
            return
            
        if not self.scan_urls():
            return
            
        results = self.analyze_results()
        if results:
            print(colorama.Fore.GREEN + 
                  "[+] Vulnerable URLs found:" + 
                  colorama.Style.RESET_ALL)
            print(results)
        else:
            print(colorama.Fore.YELLOW + 
                  "[-] No LFI vulnerabilities found" + 
                  colorama.Style.RESET_ALL)
        
        self.cleanup()

if __name__ == "__main__":
    try:
        scanner = LFIScanner()
        scanner.scan()
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