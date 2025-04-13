from tools.common_libs import *
from tools.html_output import html_output
from tools.config import load_config

def parser_arguments():
    parser = argparse.ArgumentParser(description="Vulnerability Detection Scanner")
    parser.add_argument("-ul", "--list", help="Path to the list of targets", type=str)
    parser.add_argument("-dl", "--domain_list", help="Path to the list of domains", type=str)
    parser.add_argument("-d", "--domain", help="Domain to scan", type=str)
    parser.add_argument("-scan", help="Scan for detecting vulnerabilities", action="store_true")
    args = parser.parse_args()

    if not args.list:
        print(colorama.Fore.RED + "Please provide a target list.")
        sys.exit(1)
    
    if not args.domain and not args.domain_list:
        print(colorama.Fore.RED + "Please provide a domain or domain list for subdomain takeover.")
        sys.exit(1)

    return args

def run_gf(target_list):
    tools = ["xss", "sqli", "lfi", "rce", "ssrf", "redirect", "idor", "ssti", "interestingEXT", "interestingparams"]
    output_kind = 'gf_scan'
    directory = "gf-results"

    if not os.path.exists(directory):
        os.mkdir(directory)

    for tool in tools:
        try:
            output_filename = os.path.join(directory, f"{tool}.txt")
            gf_command = f'gf {tool} {target_list} | anew {output_filename}'

            print(colorama.Fore.GREEN + f" [*] Running GF scan for {tool}...")
            subprocess.run(gf_command, shell=True, check=True, capture_output=True, text=True)

            html_output(directory, output_filename, f"GF Scan {tool}", output_kind)

        except subprocess.CalledProcessError as e:
            print(colorama.Fore.RED + f"Error running {tool}: {e.stderr}")

def run_detect_tools(target_list, domain, domain_list):   
    directory = "scan-results"
    config = load_config()
    xss_server = config.get("XSS_SERVER")
    ssrf_server = config.get("SSRF_SERVER")
    
    print(colorama.Fore.GREEN + "\n [*] Getting Servers...")
    print(magenta + f" [+] XSS Server: {xss_server}")
    print(magenta + f" [+] SSRF Server: {ssrf_server} \n")
    
    if not os.path.exists(directory):
        os.mkdir(directory)
        
    ## XSS
    try:
        print(colorama.Fore.GREEN + f" [*] Running XSS scan for XSS...")
        dalfox_temp_file = "dalfox_temp.txt"
        xss_results = os.path.join(directory, "xss-results.txt")
        dalfox_command = f"dalfox file gf-results/xss.txt -o {dalfox_temp_file} --no-color"
        dalfox_out = subprocess.Popen(dalfox_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = dalfox_out.communicate()

        with open(dalfox_temp_file, "r") as f:
            with open(xss_results, "w") as xss:
                for line in f:
                    xss.write(line)


        blind_daltox_temp_file = "blind_dalfox_temp.txt"
        dalfox_command_2= f"cat {target_list} | grep 'https://' | grep -v 'png|jpg|css|js|gif|txt' | grep '=' | qsreplace -a | dalfox pipe -b {xss_server} --no-color | tee -a {blind_daltox_temp_file}"
        dalfox_out_2 = subprocess.Popen(dalfox_command_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output_2 = dalfox_out_2.communicate()

        with open(blind_daltox_temp_file, "r") as f:
            with open(xss_results, "a") as xss:
                for line in f:
                    xss.write(line)
        

        xss_command_2 = f"cat {target_list} | grep '=' | qsreplace '\"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure \"$host\" | grep -qs \"<script>alert(1)</script>\" && echo \" [+] Vulnerable $host\" | tee -a {xss_results} ;done"
        xss_out_2 = subprocess.Popen(xss_command_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        stdout, stderr = xss_out_2.communicate()
    
        subprocess.run(f"rm -rf {dalfox_temp_file} ", shell=True, check=True)
        subprocess.run(f"rm -rf {blind_daltox_temp_file}", shell=True, check=True)
        html_output(directory, xss_results, "XSS Scan", "xss_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running XSS: {e.stderr}")

    ## SQLi
    try:
        sqlmap_results = os.path.join(directory, "sqlmap_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running SQLMap scan for SQLi...")
        sqlmap_command = f"sqlmap -m gf-results/sqli.txt --batch --disable-coloring | tee -a {sqlmap_results}"
        sqlmap_out = subprocess.Popen(sqlmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = sqlmap_out.communicate()

        html_output(directory, sqlmap_results, "SQLi Scan", "sqli_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running SQLi: {e.stderr}")

    ## SSRF
    try:
        ssrf_results = os.path.join(directory, "ssrf_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running SSRF scan for SSRF...")
        ssrf_command = f"ssrftest -f gf-results/ssrf.txt -s {ssrf_server}"
        ssrf_out = subprocess.Popen(ssrf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = ssrf_out.communicate()

        with open(ssrf_results, "w") as f:
            f.write(output[0])


        ssrf_command_2 = f"cat {target_list} | grep \"=\" | qsreplace \"{ssrf_server}\" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr  | tee -a {ssrf_results}"
        ssrf_out_2 = subprocess.Popen(ssrf_command_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output_2 = ssrf_out_2.communicate()

        html_output(directory, ssrf_results, "SSRF Scan", "ssrf_scan")
        subprocess.run("rm -rf tmp-ssrf.txt", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running SSRF: {e.stderr}")

    ## Open Redirect
    try:
        open_redirect_results = os.path.join(directory, "open_redirect_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running Open Redirect scan for Open Redirect...")
        open_redirect_command = f"cat gf-results/redirect.txt | redirectest -p tools/src/redirect_payloads.txt -k FUZZ | tee -a {open_redirect_results}"
        open_redirect_out = subprocess.Popen(open_redirect_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = open_redirect_out.communicate()

        open_redirect_command_2 = f"cat {target_list} |  grep -a -i =http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep \"http://evil.com\" && echo -e \"[+] Vulnerable $host \" | tee -a {open_redirect_results};done"
        open_redirect_out_2 = subprocess.Popen(open_redirect_command_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        stdout, stderr = open_redirect_out_2.communicate()

        html_output(directory, open_redirect_results, "Open Redirect Scan", "open_redirect_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running Open Redirect: {e.stderr}")

    ## LFI
    try:
        lfi_results = os.path.join(directory, "lfi_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running LFI scan for LFI...")
        lfi_command = f"lfiscan -l gf-results/lfi.txt"
        lfi_out = subprocess.Popen(lfi_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = lfi_out.communicate()

        with open(lfi_results, "w") as f:
            f.write(output[0])

        html_output(directory, lfi_results, "LFI Scan", "lfi_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running LFI: {e.stderr}")

    ## CSRF
    try:
        csrf_results = os.path.join(directory, "csrf_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running CSRF scan for CSRF...")
        csrf_command = f"csrfscan -ul {target_list} | tee -a {csrf_results}"
        csrf_out = subprocess.Popen(csrf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = csrf_out.communicate()

        html_output(directory, csrf_results, "CSRF Scan", "csrf_scan")
        if  os .path.exists("xsrfprobe-output"):
            subprocess.run("rm -rf xsrfprobe-output", shell=True, check=True)   
        else:
            pass
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running CSRF: {e.stderr}")

    ## CRLF
    try:
        crlf_results = os.path.join(directory, "crlf_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running CRLF scan for CRLF...")
        crlf_command = f"crlfuzz -l {target_list} -s -o {crlf_results}"
        crlf_out = subprocess.Popen(crlf_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = crlf_out.communicate()

        html_output(directory, crlf_results, "CRLF Scan", "crlf_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running CRLF: {e.stderr}")

    ## SSTI
    try:
        ssti_results = os.path.join(directory, "ssti_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running SSTI scan for SSTI...")
        ssti_command = f"sstiscan -ul {target_list}"
        ssti_out = subprocess.Popen(ssti_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = ssti_out.communicate()

        with open('ssti_found.txt', 'r') as f:
            ssti = f.read()
        with open(ssti_results, 'w') as f:
            f.write(ssti)

        subprocess.run("rm -rf ssti_found.txt", shell=True, check=True)
        html_output(directory, ssti_results, "SSTI Scan", "ssti_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running SSTI: {e.stderr}")

    ## Header Injection
    try:
        header_results = os.path.join(directory, "header_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running Header Injection scan for Header Injection...")
        headi_command = f"for URL in $(<{target_list}); do (headi -url \"${{URL}}\" | tee {header_results}); done"
        headi_out = subprocess.Popen(headi_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable="/bin/bash")
        stdout, stderr = headi_out.communicate()
                
        html_output(directory, header_results, "Header Injection Scan", "header_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running Header Injection: {e.stderr}")

    ## CORS
    try:
        cors_results = os.path.join(directory, "cors_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running CORS scan for CORS...")
        cors_command = f"corscan -f {target_list} -o {cors_results} --filter"
        cors_out = subprocess.Popen(cors_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = cors_out.communicate()

        cors_command_2 = f"cors -ul {target_list} | tee -a {cors_results}"
        cors_command_2_out = subprocess.Popen(cors_command_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = cors_command_2_out.communicate()

        html_output(directory, cors_results, "CORS Scan", "cors_scan")

    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running CORS: {e.stderr}")

    ## Web Cache Vulnerability
    try:
        cache_results = os.path.join(directory, "cache_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running Web Cache scan for Web Cache...")
        cache_command = f"wcvs -u file:{target_list} -nc | tee {cache_results}"
        cache_out = subprocess.Popen(cache_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = cache_out.communicate()

        html_output(directory, cache_results, "Web Cache Scan", "cache_scan")
        subprocess.run("rm -rf *_Log", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running Web Cache: {e.stderr}")

    ## HTTP Request Smuggling
    try:
        smuggle_results = os.path.join(directory, "smuggle_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running HTTP Request Smuggling scan for HTTP Request Smuggling...")
        smuggle_command = f"cat {target_list} | smuggler -q --no-color -l {smuggle_results}"
        smuggle_out = subprocess.Popen(smuggle_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = smuggle_out.communicate()

        html_output(directory, smuggle_results, "HTTP Request Smuggling Scan", "smuggle_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running HTTP Request Smuggling: {e.stderr}")

    ## Subdomain Takeover
    try:
        subdomain_results = os.path.join(directory, "subdomain_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running Subdomain Takeover scan for Subdomain Takeover...")
        
        if domain_list:
            takeover_command = f"subzy r --hide_fails --targets {domain_list} | tee {subdomain_results}"
            takeover_out = subprocess.Popen(takeover_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            output = takeover_out.communicate()

        elif domain: 
            subdomain_command = f"subfinder -d {domain} -silent | anew subdomain.txt && assetfinder -subs-only {domain} | anew subdomain.txt && findomain -t {domain} -q | anew subdomain.txt && cero {domain} | anew subdomain.txt"
            subdomain_out = subprocess.Popen(subdomain_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            output = subdomain_out.communicate()

            takeover_command = f"subzy r --hide_fails --targets subdomain.txt | tee {subdomain_results}"
            takeover_out = subprocess.Popen(takeover_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            output = takeover_out.communicate()
            subprocess.run("rm -rf subdomain.txt", shell=True, check=True)
    
        html_output(directory, subdomain_results, "Subdomain Takeover Scan", "subdomain_scan")
        
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running Subdomain Takeover: {e.stderr}")

    ## Nuclei Scan
    try:
        nuclei_results = os.path.join(directory, "nuclei_results.txt")
        print(colorama.Fore.GREEN + f" [*] Running Nuclei scan for Nuclei...")
        nuclei_command = f"nuclei -l {target_list} -s critical,high,medium,low,info  -no-color -o {nuclei_results}"
        nuclei_out = subprocess.Popen(nuclei_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        output = nuclei_out.communicate()

        html_output(directory, nuclei_results, "Nuclei Scan", "nuclei_scan")
    except subprocess.CalledProcessError as e:
        print(colorama.Fore.RED + f"Error running Nuclei: {e.stderr}")

if __name__ == "__main__":
    args = parser_arguments()
    target_list = args.list
    domain = args.domain
    domain_list = args.domain_list

    if args.scan:
        print(colorama.Fore.GREEN + " [*] Starting GF Scan.....")
        run_gf(target_list)
        print(colorama.Fore.GREEN + " [*] Starting Detecting Tools.....")
        run_detect_tools(target_list, domain, domain_list)