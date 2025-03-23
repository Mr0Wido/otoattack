import colorama
import subprocess
from tqdm.autonotebook import tqdm
import argparse
from bs4 import BeautifulSoup
import os
import sys
import json
import os
from datetime import datetime
colorama.init()

from concurrent.futures import ThreadPoolExecutor, as_completed

blue = colorama.Fore.BLUE
red = colorama.Fore.RED
green = colorama.Fore.GREEN
yellow = colorama.Fore.YELLOW
magenta = colorama.Fore.MAGENTA
cyan = colorama.Fore.CYAN
reset = colorama.Fore.RESET