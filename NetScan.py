#for commond-line arguments and exiting
import sys
# for networking interface for ip operations
import socket
# for ip network calculations
import ipaddress
# for paralel thred executions
import concurrent.futures
# for detecting operation system
import platform
# for running os commonds
import subprocess
# for regular expressions
import re
# for possible future os optrations
import os

#======================================================================================

def print_app_name():
    print("""
ooooo      ooo               .    .oooooo..o                                 
`888b.     `8'             .o8   d8P'    `Y8                                 
 8 `88b.    8   .ooooo.  .o888oo Y88bo.       .ooooo.   .oooo.   ooo. .oo.   
 8   `88b.  8  d88' `88b   888    `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b  
 8     `88b.8  888ooo888   888        `"Y88b 888        .oP"888   888   888  
 8       `888  888    .o   888 . oo     .d8P 888   .o8 d8(  888   888   888  
o8o        `8  `Y8bod8P'   "888" 8""88888P'  `Y8bod8P' `Y888""8o o888o o888o 

Welcome to NetScan, a network scanner brought to you by
jeks
for business inquiries  conctact  by emain to : business@jeks.net
     """)

# ====================================================================================


# ====================================================================================
def get_local_ip_and_mask():
    """
    Detects the Ip addresses and subnet mask from the system.
    Work for both windows and unix-like systems
    """
    system = platform.system().lower # detect the os type
    if system == 'windows':
        output = subprocess.check_output("ipconfig", universal_newlines=True) # run ipconfig and output
        ip_match = re.search(r'IPv4 address[. ]": ([\d. ]+)', output)  #find the ip address 4
        mask_match = re.search(r'subnet mask[. ]": ([\d. ]+)', output)  #find the subnet mask
        if ip_match and mask_match:
            return ip_match.group(1), mask_match.group(1)
        else:
            #for linux/macOS, use ipconfig and parse output
            output = subprocess.check_output("ipconfig", shell=True, universal_newlines=True)
            ip_match = re.search(r'inet ([\d. ]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
            if ip_match:
                ip = ip_match.group(1)                # extract ip address
                mask = mask_match.group(2)            # extract netmask
                if mask.startswith("0x"):             # if netmask is in hex
                    mask.socket.inet_ntoa(int(mask,16).to_bytes(4, "big"))  ## convert hexa to dotted decimal
                return ip, mask
    #  Fallback: try to infer IP, assume /24 mask
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8, 80'))                ##dummy connect get local ip
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip, '255.255.255.0'                  ##defalut mask

# =====================================================================================


# =====================================================================================
def mask_to_cidr(mask):
    """
    Converted a dotted-decimal subnet mask (e.g, 255.255.255.0) to CIDR notation (e.g, 24).

    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))
# =====================================================================================


# =====================================================================================
def parse_network(arg=None):
    """
    Parses the network arguments and retern and ipaddress.ip_network objects.
    Handels no arguments (auto-detect), /24, /16, etc.
    """
    if not arg:
        ip, mask = get_local_ip_and_mask()
        cidr = mask_to_cidr(mask)
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)      #user provides CIDR
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)
    else:
        raise ValueError("Invalid network format")      ##invalid input//
# =====================================================================================
# =====================================================================================

def ping(ip):
    """
    Ping a single IP address.
    Returns the IP if online (responds to ping), otherwise None.
    """
    ip = str(ip)
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]      ##windows: 1ping 1s timeout
    else:
        cmd = ["ping", "-c", "1", "-w", "1", ip]         # Unix: 1 ping 1s timeout
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):
            return ip
    except subprocess.TimeoutExpired:                ## timeout host not online
        return None
    except Exception:                               ## other error, threat as offline
        return None
# =====================================================================================

# =====================================================================================
def scan_network(network):
    """
    Scans all hosts in the given network in parallel.
    Return a list of online hosts.
    """
    print(f"Scanning network: (network)")                           # inform user what is being scanned
    online = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:   # use 100 threads
           futures = {executor.submit(ping, ip): ip for ip in network.hosts()}    # submint ping jobs
           for future in concurrent.futures.as_completed(futures):
               try:
                   result = future.result()
                   if result:
                       online.append(result)
               except Exception:
                   continue
    except KeyboardInterrupt:
        print("\nScan interupted by user, Showing results so for........")
    return online
# =====================================================================================
def show_help():
    """
    print usages and helps Information.
    """
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "Options:\n"
        "  -h, --help     show this help message\n"
        "Examples:\n"
        " netscan                           # Scan current local networ\n"
        " netscan 192.168.1.0               # Scan 192.168.1.0/24\n"
        " netscan 192.168.1                 # Scan 192.168.1/24\n"
        " netscan 192.168.1.0/24            # Scan 192.168.1.0/24\n"
        
    )

# =====================================================================================
def main():
    """
    Main funcation: parses arguments, runs scan, prints results.
    """
    args = sys.argv[1:]
    if not args:
        try:
            network = parse_network()
        except Exception as o:
           print(f"Error: {0}")
           show_help()
           return
    elif args[0] in ['-h', '--help']:
        show_help()
        return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])
        except Exception as o:
             print(f"Error: {0}")
             show_help()
             return
    else:
        show_help()
        return

    try:
        online_hosts = scan_network(network)
        print("\nOnline hosts:")
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)
    except KeyboardInterrupt:
        print("\nscan interrupted by user_")



if __name__ == "__main__":
    main()