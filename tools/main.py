# main.py
import colorama
import subprocess
from tqdm.autonotebook import tqdm
import argparse
from bs4 import BeautifulSoup
import os
import sys
import json
colorama.init()

blue = colorama.Fore.BLUE
red = colorama.Fore.RED
green = colorama.Fore.GREEN
yellow = colorama.Fore.YELLOW
magenta = colorama.Fore.MAGENTA
cyan = colorama.Fore.CYAN
reset = colorama.Fore.RESET
from tools.attack import run_gf
from tools.attack import run_detect_tools
from tools.config import config_file

def parser_Arguments():
    parser = argparse.ArgumentParser(description='Vulnrability Scanner')
    parser.add_argument("-ul", "--list", help="Path to the list of targets", type=str)
    parser.add_argument("-dl", "--domain_list", help="Path to the list of domains", type=str)
    parser.add_argument("-d", "--domain", help="Domain to scan", type=str)
    parser.add_argument("-scan", help="Scan for the detecting vulns", action="store_true")
    parser.add_argument("-config", help="Path to the config file", action="store_true")
    args = parser.parse_args()

    if not args.config and not args.list:
        parser.error("--list  must be specified")
    return args

def banner():
    print(f"""{red}

 ██████╗ ████████╗ ██████╗  █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║   ██║   ██║   ██║   ██║███████║   ██║      ██║   ███████║██║     █████╔╝ 
██║   ██║   ██║   ██║   ██║██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
╚██████╔╝   ██║   ╚██████╔╝██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{reset}""")
    print(f"{green}Coded By Furkan Deniz - @MR0Wido \n \n{reset}")

def main():
    banner()
    args = parser_Arguments()
    if args.scan:
        run_gf(target_list=args.list)
        run_detect_tools(target_list=args.list, domain=args.domain, domain_list=args.domain_list)
    if args.config:
        config_file()
    

if __name__ == "__main__":
    main()


