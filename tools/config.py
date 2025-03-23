from tools.common_libs import *

def parser_arguments():
    parser = argparse.ArgumentParser(description="Server File")
    parser.add_argument("-config", help="Path to the config file", action="store_true")
    args = parser.parse_args()
    return args

def get_server_config():
    xss_server = input("Please enter the XSS server URL: ")
    ssrf_server = input("Please enter the SSRF server URL: ")
    return xss_server, ssrf_server

def config_file():
    args = parser_arguments()
    if args.config:
        with open("config.txt", "w") as f:
            xss_server, ssrf_server = get_server_config()
            f.write(f"XSS_SERVER={xss_server}\n")
            f.write(f"SSRF_SERVER={ssrf_server}\n")
            print(f"Config file saved as config.txt")
    else:
        print("Please provide a config file.")
        sys.exit(1)

def load_config():
    config = {}
    with open ('config.txt', 'r') as f:
        for line in f:
            name, value = line.strip().split('=')
            config[name] = value
    return config

if __name__ == "__main__":
    config_file()