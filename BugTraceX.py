#!/usr/bin/env python3
import os
import sys
from colorama import Fore, init

# === Initialize Colorama ===
init(autoreset=True)
BOLD = "\033[1m"

# === Clear screen function ===
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

# === Banner Function ===
def banner():
    clear_screen()
    print(Fore.RED + BOLD + "  ┏━━┳┳┳━━┳━━┳━┳━━┳━┳━┳┓┏┓")
    print(Fore.YELLOW + BOLD + "  ┃┏┓┃┃┃┏━╋┓┏┫╋┃┏┓┃┏┫┳┻┓┏┛")
    print(Fore.GREEN + BOLD + "  ┃┏┓┃┃┃┗┓┃┃┃┃┓┫┣┫┃┗┫┻┳┛┗┓")
    print(Fore.CYAN + BOLD + "  ┗━━┻━┻━━┛┗┛┗┻┻┛┗┻━┻━┻┛┗┛")
    print()
    print(Fore.MAGENTA + BOLD + "  𝐃𝐄𝐕𝐄𝐋𝐎𝐏𝐄𝐑 : 𝐑𝐚𝐣_𝐌𝐚𝐤𝐞𝐫")
    print(Fore.MAGENTA + BOLD + "  𝐓𝐄𝐋𝐄𝐆𝐑𝐀𝐌 : @𝐁𝐮𝐠𝐓𝐫𝐚𝐜𝐞𝐗")
    print()

# === Menu Function ===
def menu():
    print(Fore.GREEN + BOLD + "  [01]  HOST SCANNER")
    print(Fore.CYAN + BOLD + "  [02]  SUBFINDER")
    print(Fore.MAGENTA + BOLD + "  [03]  HOST INFO")
    print(Fore.YELLOW + BOLD + "  [04]  SPLIT TXT FILE")
    print(Fore.LIGHTBLUE_EX + BOLD + "  [05]  SMART SUBFINDER")
    print(Fore.GREEN + BOLD + "  [06]  SMART CIDR SCAN")
    print(Fore.CYAN + BOLD + "  [07]  REVERSE IP LOOKUP")
    print(Fore.MAGENTA + BOLD + "  [08]  CIDR TO DOMAIN")
    print(Fore.YELLOW + BOLD + "  [09]  SUBDOMAIN DOMAIN MAPPER")
    print(Fore.LIGHTBLUE_EX + BOLD + "  [10]  REMOVE SUBDOMAINS")
    print(Fore.GREEN + BOLD + "  [11]  UPDATE TOOL")
    print(Fore.RED + BOLD + "  [00]  EXIT\n")
    
    # Add extra blank line before input
    print(Fore.YELLOW + BOLD + "  [--] Your Choice : ", end='')

# === Host Scanner (Optimized Lag-Free) ===

import os, socket, threading, requests, urllib3, re, time
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init

# === Init ===
init(autoreset=True)
BOLD = "\033[1m"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_response(r):
    try:
        code = r.status_code
        loc = r.headers.get('Location', '').lower()
        if code in [302, 307] and "jio.com/balanceexhaust" in loc:
            return False
        return 100 <= code <= 599
    except:
        return False

def scan(host, port, method, timeout, live_hosts, lock, counter, total, output_file, host_seen):
    try:
        ip = socket.gethostbyname(host)
    except:
        with lock:
            counter[1] += 1
            print(Fore.CYAN + f"📡 Scanned: {counter[1]}/{total} | Live: {counter[0]}".ljust(50), end="\r")
        return

    protocol = "https" if str(port) in ["443", "8443"] else "http"
    url = f"{protocol}://{host}:{port}"

    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close"
    }

    try:
        session = requests.Session()  # 💡 Thread-safe: use local session
        session.keep_alive = False
        r = session.request(method=method, url=url, headers=headers, timeout=timeout, allow_redirects=False, verify=False)
        code = r.status_code

        server = r.headers.get('Server', 'unknown')[:16]
        if server.lower() == "unknown":
            server = ""

        with lock:
            counter[1] += 1
            if is_valid_response(r):
                counter[0] += 1
                if host not in host_seen:
                    host_seen.add(host)
                    live_hosts.append(host)
                    with open(output_file, "a") as f:
                        f.write(f"{host}\n")

                print(
                    Fore.YELLOW + BOLD + f"{method:<6}",
                    Fore.GREEN  + BOLD + f"{code:<5}",
                    Fore.RED    + BOLD + f"{server:<16}",
                    Fore.CYAN   + BOLD + f"{port:<5}",
                    Fore.MAGENTA+ BOLD + f"{ip:<15}",
                    Fore.WHITE  + BOLD + f"{host}"
                )
            print(Fore.WHITE + f"📡 Scanned: {counter[1]}/{total} | Live: {counter[0]}".ljust(50), end="\r")
    except:
        with lock:
            counter[1] += 1
            print(Fore.WHITE + f"📡 Scanned: {counter[1]}/{total} | Live: {counter[0]}".ljust(50), end="\r")
        return

def host_scanner():
    start_time = time.time()

    fn = input(Fore.YELLOW + BOLD + "\n📄 Enter host file (e.g., 1.txt): ").strip()
    if not fn or not os.path.isfile(fn):
        print(Fore.RED + BOLD + "❌ Invalid or missing host file.")
        return

    port_input = input(Fore.YELLOW + BOLD + "🔌 Enter port(s) (default 80): ").strip() or "80"
    try:
        ports = [int(p.strip()) for p in port_input.split(',') if p.strip().isdigit()]
    except:
        print(Fore.RED + BOLD + "❌ Invalid port(s).")
        return

    threads = input(Fore.YELLOW + BOLD + "⚙️  Threads (default 50): ").strip()
    threads = int(threads) if threads.isdigit() else 50

    timeout_input = input(Fore.YELLOW + BOLD + "⏱️  Timeout in seconds (default 3): ").strip()
    try:
        timeout = float(timeout_input) if timeout_input else 3
    except ValueError:
        timeout = 3

    method = input(Fore.YELLOW + BOLD + "🌐 HTTP Method (default HEAD): ").strip().upper()
    method = method if re.match(r"^[A-Z]+$", method) else "HEAD"

    output_file = input(Fore.YELLOW + BOLD + "💾 Output file (default: result.txt): ").strip() or "result.txt"

    try:
        with open(fn) as f:
            raw_hosts = list(set(h.strip() for h in f if h.strip()))
    except:
        print(Fore.RED + BOLD + "❌ Error reading host file.")
        return

    if os.path.exists(output_file):
        os.remove(output_file)

    socket.setdefaulttimeout(timeout)

    targets = [(re.sub(r':[0-9]+$', '', re.sub(r'^https?://', '', host).strip('/')), port) for host in raw_hosts for port in ports]
    total = len(targets)
    live_hosts = []
    lock = threading.Lock()
    counter = [0, 0]
    host_seen = set()

    print(Fore.CYAN + BOLD + "\nMETHOD  CODE  SERVER            PORT  IP               HOST")
    print(Fore.CYAN + BOLD + "------  ----  ----------------  ----  ---------------  ------------------------------")

    def wrapped_scan(args):
        scan(*args, method, timeout, live_hosts, lock, counter, total, output_file, host_seen)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(wrapped_scan, targets)

    mins = int((time.time() - start_time) // 60)
    secs = int((time.time() - start_time) % 60)
    print(Fore.CYAN + BOLD + f"\n⏱️  Scan completed in {mins} min {secs} sec.")
    print(Fore.GREEN + BOLD + f"\n✔ Total Live: {len(live_hosts)} saved to {output_file}")
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

# === Option 2: Subfinder ===
def subfinder():
    print(Fore.CYAN + BOLD + "\n[1] Manual Domain Input")
    print(Fore.CYAN + BOLD + "[2] Load From .txt File")
    method = input(Fore.YELLOW + BOLD + "Choose method [1/2]: ").strip()

    if method == '1':  
        domain = input(Fore.YELLOW + BOLD + "🔤 Enter domain: ").strip()  
        output_file = input(Fore.YELLOW + BOLD + "📁 Enter Output File Name: ").strip()  

        if not domain:  
            print(Fore.RED + BOLD + "✘ No domain entered.")  
            return  
        if not output_file:  
            print(Fore.RED + BOLD + "✘ No output file specified.")  
            return  

        print(Fore.CYAN + BOLD + f"\n🔍 Scanning: {domain}")  
        try:  
            result = os.popen(f"subfinder -all -d {domain} -silent").read()  
            subdomains = sorted(set(result.strip().split('\n'))) if result.strip() else []  
            count = len(subdomains)  

            with open(output_file, 'w') as f:  
                for sub in subdomains:  
                    f.write(sub + '\n')  

            print(Fore.GREEN + BOLD + f"✅ Found {count} subdomains for {domain}")  
            print(Fore.GREEN + BOLD + f"\n📦 Total Domains Scanned: 1")  
            print(Fore.GREEN + BOLD + f"✅ Total Subdomains Found: {count}")  
            print(Fore.GREEN + BOLD + f"💾 All Subdomains Saved to: {output_file}")  

        except Exception as e:  
            print(Fore.RED + BOLD + f"❌ Error scanning {domain}: {e}")  

    elif method == '2':  
        output_file = input(Fore.YELLOW + BOLD + "\n📁 Enter Name For Output File: ").strip()  
        domain_file = input(Fore.YELLOW + BOLD + "📄 Enter Path To Domain List (.txt): ").strip()  

        if not os.path.isfile(domain_file):  
            print(Fore.RED + BOLD + "✘ File not found!")  
            return  

        with open(domain_file) as f:  
            domains = [line.strip() for line in f if line.strip()]  

        print(Fore.CYAN + BOLD + f"\n📊 Total Domains: {len(domains)}\n")  

        # Clear previous contents before appending new subdomains
        open(output_file, 'w').close()

        total_found = 0  
        total_scanned = 0  

        for domain in domains:  
            print(Fore.CYAN + BOLD + f"🔍 Scanning: {domain}")  
            try:  
                result = os.popen(f"subfinder -all -d {domain} -silent").read()  
                subdomains = sorted(set(result.strip().split('\n'))) if result.strip() else []  
                count = len(subdomains)  
                total_found += count  
                total_scanned += 1  

                with open(output_file, 'a') as f:  
                    for sub in subdomains:  
                        f.write(sub + '\n')  

                print(Fore.GREEN + BOLD + f"✅ Found {count} subdomains for {domain}\n")  

            except Exception as e:  
                print(Fore.RED + BOLD + f"❌ Error scanning {domain}: {e}\n")  

        print(Fore.GREEN + BOLD + f"✅ Total Domains Scanned: {total_scanned}")  
        print(Fore.GREEN + BOLD + f"✅ Total Subdomains Found: {total_found}")  
        print(Fore.GREEN + BOLD + f"💾 All Subdomains Saved To: {output_file}")  

    else:  
        print(Fore.RED + BOLD + "✘ Invalid option selected.")  

    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to the menu...")

# === Option 3: Host Info ===

def is_valid_response(r):
    try:
        code = r.status_code
        loc = r.headers.get('Location', '').lower()

        # Only skip Jio fake redirect
        if code in [302, 307] and "jio.com/balanceexhaust" in loc:
            return False

        return 100 <= code <= 599  # Accept everything else
    except:
        return False

def host_info():
    import socket
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    init(autoreset=True)
    BOLD = Style.BRIGHT

    print(Fore.YELLOW + BOLD + "\nEnter Domain or IP: ", end="")
    host = input().strip()
    if not host:
        print(Fore.RED + BOLD + "✘ Host is required!")
        return

    print(Fore.YELLOW + BOLD + "Enter Port: ", end="")
    port = input().strip()
    if not port.isdigit():
        print(Fore.RED + BOLD + "✘ Invalid port number!")
        return

    print(Fore.YELLOW + BOLD + "Enter HTTP Method [default: HEAD]: ", end="")
    method = input().strip().upper()
    if method not in ["GET", "HEAD"]:
        method = "HEAD"

    url = f"http://{host}:{port}"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        "Connection": "close"
    }

    try:
        # === IP Resolution ===
        ip_list = []
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                if ip not in ip_list:
                    ip_list.append(ip)
        except:
            ip_list = ["N/A"]

        # === Reverse DNS ===
        try:
            socket.inet_aton(host)
            is_ip = True
        except socket.error:
            is_ip = False

        reverse_host = "N/A"
        if is_ip:
            try:
                reverse_host = socket.gethostbyaddr(host)[0]
            except:
                reverse_host = "No PTR record"

        # === Request ===
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=6, allow_redirects=False)
        else:
            r = requests.head(url, headers=headers, timeout=6, allow_redirects=False)

        if not is_valid_response(r):
            print(Fore.RED + BOLD + f"↪ ❌ Skipped Fake Response at {url}")
            return

        status = r.status_code
        location = r.headers.get("Location", "")
        content_len = int(r.headers.get("Content-Length", len(r.content)))
        content_type = r.headers.get("Content-Type", "").lower()

        # === Title Extraction === (only if GET was used)
        if method == "GET":
            try:
                soup = BeautifulSoup(r.text, 'html.parser')
                title = soup.title.string.strip() if soup.title else "N/A"
            except:
                title = "N/A"
        else:
            title = "N/A"

        # === Output ===
        print(Fore.GREEN + BOLD + "\n🌐 IP Addresses:")
        for ip in ip_list:
            print(Fore.CYAN + BOLD + f"├─ {ip}")
        if is_ip:
            print(Fore.LIGHTMAGENTA_EX + BOLD + f"└─ Reverse DNS: {reverse_host}")

        # === CDN Detection ===
        server_header = r.headers.get("Server", "").lower()
        cdn = "Cloudflare" if "cloudflare" in server_header or "cf-ray" in r.headers else "Unknown"
        print(Fore.MAGENTA + BOLD + "\n📦 CDN Detected:")
        print(Fore.CYAN + BOLD + f"└─ {cdn}")

        # === Request Info ===
        print(Fore.YELLOW + BOLD + "\n🔍 Request Info:")
        print(Fore.CYAN + BOLD + f"├─ Method: {method}")
        print(Fore.CYAN + BOLD + f"├─ Status: {status}")
        if location:
            print(Fore.CYAN + BOLD + f"├─ Location: {location}")
        print(Fore.CYAN + BOLD + f"└─ Title: {title}")

        # === Response Headers ===
        print(Fore.LIGHTGREEN_EX + BOLD + "\n📬 Response Headers:")
        headers_to_show = [
            "Date", "Content-Type", "Content-Length", "Connection", "Server",
            "Content-Encoding", "Transfer-Encoding", "X-Frame-Options", "Vary", "CF-RAY"
        ]
        for i, h in enumerate(headers_to_show):
            label = "└─" if i == len(headers_to_show) - 1 else "├─"
            print(Fore.CYAN + BOLD + f"{label} {h}: {r.headers.get(h, 'N/A')}")

    except requests.exceptions.Timeout:
        print(Fore.RED + BOLD + "✘ Connection timed out!")
    except requests.exceptions.ConnectionError:
        print(Fore.RED + BOLD + "✘ Connection error! Host may be unreachable.")
    except Exception as e:
        print(Fore.RED + BOLD + f"✘ Unexpected error: {e}")

    input(Fore.CYAN + BOLD + "\n↩ Press Enter to return to menu...")

# === Option 4: Split TXT File ===
def split_txt_file():
    filename = input(Fore.YELLOW + BOLD + "Enter Filename To Split: ").strip()
    try:
        with open(filename, "r") as f:
            lines = f.read().splitlines()
    except:
        print(Fore.RED + BOLD + "❌ File not found.")
        return
    total_lines = len(lines)
    if total_lines == 0:
        print(Fore.RED + BOLD + "❌ File is empty.")
        return
    try:
        parts = int(input(Fore.YELLOW + BOLD + "How Many Parts To Split Into: ").strip())
        if parts <= 0 or parts > total_lines:
            raise ValueError
    except:
        print(Fore.RED + BOLD + "❌ Invalid number of parts.")
        return
    lines_per_part = total_lines // parts
    remainder = total_lines % parts
    index = 0
    for i in range(parts):
        extra = 1 if i < remainder else 0
        chunk = lines[index : index + lines_per_part + extra]
        with open(f"{filename}_part{i+1}.txt", "w") as f:
            f.write("\n".join(chunk))
        index += lines_per_part + extra
    print(Fore.GREEN + BOLD + f"✔ File split into {parts} parts.")
    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to menu...")

# === Option 5: SMART SUBFINDER ===
def smart_subfinder():
    print(Fore.CYAN + BOLD + "[1] Load From .txt File")
    method = input(Fore.YELLOW + BOLD + "Choose method [1/2]: ").strip()
    if method != '1':
        print(Fore.RED + BOLD + "✘ Only method [1] is supported currently.")
        return

    out_file = input(Fore.YELLOW + BOLD + "📁 Enter name for output file (e.g., subdomains.txt): ").strip()
    file = input(Fore.YELLOW + BOLD + "📄 Enter path to domain list (.txt): ").strip()

    if not os.path.isfile(file):
        print(Fore.RED + BOLD + "✘ File not found!")
        return

    try:
        with open(file) as f:
            raw = [line.strip() for line in f if line.strip()]
        roots = list(set([tldextract.extract(x).top_domain_under_public_suffix for x in raw if tldextract.extract(x).top_domain_under_public_suffix]))
        print(Fore.CYAN + BOLD + f"\n📊 Total Domains Loaded: {len(roots)}\n")

        total_found = 0
        unique_subs = set()

        # 🔁 Loop through each domain
        for domain in roots:
            print(Fore.YELLOW + BOLD + f"🔍 Scanning: {domain}")
            cmd = f"subfinder -all -d {domain} -silent"
            output = os.popen(cmd).read().splitlines()
            found = len(output)
            total_found += found
            unique_subs.update(output)

            # ✅ Save immediately after each domain scan
            with open(out_file, "a") as out:
                for sub in output:
                    out.write(sub + "\n")

            print(Fore.GREEN + BOLD + f"✅ {found} subdomains found for {domain}\n")

        print(Fore.CYAN + BOLD + f"📦 Total Unique Subdomains Found: {len(unique_subs)}")
        print(Fore.CYAN + BOLD + f"📁 Results saved to: {out_file}")

    except Exception as e:
        print(Fore.RED + BOLD + f"✘ Error: {e}")

    input(Fore.CYAN + BOLD + "\n⏎ Press Enter to return to the menu...")

# === Option 6: SMART CIDR SCAN ===

def smart_cidr_scan():
    import requests
    import threading
    import time
    import sys
    import random
    from colorama import Fore, Style, init
    from ipaddress import ip_network

    init(autoreset=True)
    BOLD = Style.BRIGHT

    class Colors:
        LIVE = Fore.GREEN + BOLD
        IP = Fore.CYAN + BOLD
        PORT = Fore.GREEN + BOLD
        SEPARATOR = Fore.GREEN + BOLD
        STATUS = {
            '2xx': Fore.YELLOW + BOLD,
            '3xx': Fore.CYAN + BOLD,
            '4xx': Fore.RED + BOLD,
            '5xx': Fore.RED + BOLD
        }
        SERVER = {
            'nginx': Fore.MAGENTA + Style.BRIGHT,
            'apache': Fore.MAGENTA + Style.BRIGHT,
            'microsoft': Fore.MAGENTA + Style.BRIGHT,
            'iis': Fore.MAGENTA + Style.BRIGHT,
            'awselb': Fore.MAGENTA + Style.BRIGHT,
            'cloudflare': Fore.MAGENTA + Style.BRIGHT,
            'default': Fore.MAGENTA + Style.BRIGHT
        }
        BANNER = Fore.CYAN + BOLD
        INPUT = Fore.YELLOW + BOLD
        ERROR = Fore.RED + BOLD
        STATUS_TEXT = Fore.MAGENTA + BOLD
        COUNT = Fore.GREEN + BOLD
        SUMMARY = Fore.CYAN + BOLD
        FILENAME = Fore.YELLOW + BOLD

    def is_valid_response(r):
        try:
            code = r.status_code
            loc = r.headers.get('Location', '').lower()
            if code in [302, 307] and "jio.com/balanceexhaust" in loc:
                return False
            return 100 <= code <= 599
        except:
            return False

    print(Colors.BANNER + "\n[6] SMART CIDR SCANNER\n")

    try:
        cidr_input = input(Colors.INPUT + "[+] Enter CIDR: ").strip()
        ports_input = input(Colors.INPUT + "[+] Enter Ports: ").strip()
        thread_input = input(Colors.INPUT + "[+] Enter Number OF Threads: ").strip()
        out_file = input(Colors.INPUT + "[+] Enter Output Filename: ").strip()
        method_input = input(Colors.INPUT + "[+] Enter Method [HEAD]: ").strip().upper()

        if not cidr_input or not ports_input or not thread_input:
            return
        if not out_file:
            out_file = "cidr_live_hosts.txt"
        if method_input not in ["GET", "HEAD"]:
            method_input = "HEAD"

        try:
            net = ip_network(cidr_input, strict=False)
            all_ips = list(net.hosts())
            random.shuffle(all_ips)
        except Exception as e:
            print(Colors.ERROR + f"\n✘ Invalid CIDR: {e}")
            input(Colors.INPUT + "\nPress Enter to return to menu...")
            return

        try:
            ports = [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]
            threads = int(thread_input)
        except:
            print(Colors.ERROR + "\n✘ Invalid port(s) or thread count.")
            input(Colors.INPUT + "\nPress Enter to return to menu...")
            return

        open(out_file, "w").close()
        scanned = 0
        live_count = 0
        total = len(all_ips) * len(ports)
        lock = threading.Lock()

        def update_status():
            sys.stdout.write(
                "\r" + Colors.STATUS_TEXT + f"📡 Scanned: {scanned}/{total} " +
                Colors.COUNT + f"| Live: {live_count}     "
            )
            sys.stdout.flush()

        def scan(ip, port):
            nonlocal scanned, live_count
            try:
                url = f"http://{ip}:{port}"
                headers = {'User-Agent': 'Mozilla/5.0'}
                req_func = requests.get if method_input == "GET" else requests.head
                r = req_func(url, headers=headers, timeout=3, allow_redirects=False)

                if not is_valid_response(r):
                    return

                status = r.status_code
                server = r.headers.get('Server', 'Unknown').split('/')[0]
                server_lower = server.lower()

                with lock:
                    line = f"{ip}:{port} | Status: {status} | Server: {server}"
                    sys.stdout.write("\r" + " " * 100 + "\r")

                    server_color = Colors.SERVER['default']
                    for key in Colors.SERVER:
                        if key in server_lower:
                            server_color = Colors.SERVER[key]
                            break

                    if 200 <= status < 300:
                        status_group = '2xx'
                    elif 300 <= status < 400:
                        status_group = '3xx'
                    elif 400 <= status < 500:
                        status_group = '4xx'
                    else:
                        status_group = '5xx'

                    print(f"{Colors.IP}{ip:15}{Style.RESET_ALL} "
                          f"{Colors.PORT}{port:<5}{Style.RESET_ALL} "
                          f"{Colors.STATUS[status_group]}{status:<5}{Style.RESET_ALL} "
                          f"{server_color}{server}{Style.RESET_ALL}")

                    with open(out_file, "a") as f:
                        f.write(line + "\n")
                    live_count += 1
            except:
                pass
            finally:
                with lock:
                    scanned += 1
                    update_status()

        print("\nIP               PORT  CODE  SERVER")
        print("-------------------------------------------")

        threads_list = []
        for ip in all_ips:
            for port in ports:
                while threading.active_count() >= threads + 1:
                    time.sleep(0.01)
                t = threading.Thread(target=scan, args=(str(ip), port))
                t.start()
                threads_list.append(t)

        for t in threads_list:
            t.join()

        print(Colors.SUMMARY + f"\n\n📦 Total Live Hosts Found: {Colors.COUNT}{live_count}")
        print(Colors.SUMMARY + f"📁 Results saved to: {Colors.FILENAME}{out_file}")
        input(Colors.INPUT + "\n⏎ Press Enter to return to menu...")

    except KeyboardInterrupt:
        print(Colors.ERROR + "\n\n✘ Scan interrupted by user.")
        input(Colors.INPUT + "\n⏎ Press Enter to return to menu...")  

# === Option 7: REVERSE IP LOOKUP ===
def reverse_ip_lookup():
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style
    import socket
    import time

    BOLD = Style.BRIGHT  # Define BOLD constant

    banner()
    print(Fore.CYAN + BOLD + "\n[7] REVERSE IP LOOKUP\n" + Style.RESET_ALL)

    # Get target input
    target = input(Fore.YELLOW + BOLD + "[+] Enter IP OR Domain: " + Style.RESET_ALL).strip()
    if not target:
        input(Fore.RED + BOLD + "[!] No target entered. Press Enter to return..." + Style.RESET_ALL)
        return

    # Resolve domain to IP if needed
    resolved_ip = target
    try:
        if not target.replace('.', '').isdigit():
            resolved_ip = socket.gethostbyname(target)
            print(Fore.GREEN + BOLD + f"[✓] Resolved IP: {resolved_ip}" + Style.RESET_ALL)
    except socket.gaierror:
        print(Fore.RED + BOLD + "[!] Could not resolve domain to IP" + Style.RESET_ALL)
        input(Fore.YELLOW + BOLD + "\n[+] Press Enter to return to menu..." + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + BOLD + "[*] Fetching data from viewdns.info...\n" + Style.RESET_ALL)
    
    try:
        url = "https://domains.yougetsignal.com/domains.php"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Origin": "https://www.yougetsignal.com",
            "Referer": "https://www.yougetsignal.com/",
            "X-Requested-With": "XMLHttpRequest"
        }
        
        data = {"remoteAddress": resolved_ip, "key": "", "_": str(int(time.time() * 1000))}
        response = requests.post(url, data=data, headers=headers, timeout=15)
        response.raise_for_status()
        result = response.json()

        if result.get("status") != "Success":
            print(Fore.RED + BOLD + f"[!] Failed to fetch data: {result.get('message', 'Unknown error')}" + Style.RESET_ALL)
            input(Fore.YELLOW + BOLD + "\n[+] Press Enter to return to menu..." + Style.RESET_ALL)
            return

        domains = result.get("domainArray", [])
        
        if not domains:
            print(Fore.RED + BOLD + "[!] No domains found on this IP address." + Style.RESET_ALL)
        else:
            print()  # Empty line before domains
            for domain in domains:
                print(Fore.CYAN + " - " + domain[0] + Style.RESET_ALL)
            
            print(Fore.GREEN + BOLD + f"\n[✓] Total domains found: {len(domains)}" + Style.RESET_ALL)

            save = input(Fore.YELLOW + BOLD + "\n[+] Save results to a file? (y/n): " + Style.RESET_ALL).strip().lower()
            if save == 'y':
                output_file = input(Fore.YELLOW + BOLD + "[+] Enter Filename (with .txt): " + Style.RESET_ALL).strip()
                if output_file:
                    try:
                        with open(output_file, "w") as f:
                            for domain in domains:
                                f.write(domain[0] + "\n")
                        print(Fore.GREEN + BOLD + f"[✓] Saved to {output_file}" + Style.RESET_ALL)
                    except IOError as e:
                        print(Fore.RED + BOLD + f"[!] Error saving file: {e}" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + BOLD + f"[!] Error: {e}" + Style.RESET_ALL)

    input(Fore.YELLOW + BOLD + "\n[+] Press Enter to return to menu..." + Style.RESET_ALL)

# === Option 8: CIDR TO DOMAIN ===
def cidr_to_domain():
    import socket, ipaddress, threading, time, random, os
    from queue import Queue
    from colorama import Fore, Style, init

    init(autoreset=True)
    BOLD = Style.BRIGHT
    GREEN = Fore.GREEN + BOLD
    CYAN = Fore.CYAN + BOLD
    YELLOW = Fore.YELLOW + BOLD
    MAGENTA = Fore.MAGENTA + BOLD
    RED = Fore.RED + BOLD
    WHITE = Fore.WHITE + BOLD

    colors = [
        Fore.LIGHTRED_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTYELLOW_EX,
        Fore.LIGHTBLUE_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTWHITE_EX
    ]

    print(f"{MAGENTA}$ CIDR TO DOMAIN")
    cidr_input = input(f"{CYAN}[+] Enter CIDR range (e.g. 65.0.0.0/12): {WHITE}").strip()
    output_file = input(f"{CYAN}[+] Enter output filename [results.txt]: {WHITE}").strip()
    if not output_file:
        output_file = "results.txt"

    try:
        user_threads = int(input(f"{CYAN}[+] Enter number of threads [default 200]: {WHITE}").strip())
        if user_threads <= 0:
            raise ValueError
    except:
        print(f"{YELLOW}[!] Invalid input, using default: 200 threads")
        user_threads = 200

    scanned = 0
    found = 0
    lock = threading.Lock()
    all_domains = set()
    root_domains = set()

    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            for line in f:
                root_domains.add(line.strip())

    def extract_root_domain(domain):
        parts = domain.strip().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def reverse_dns_worker():
        nonlocal scanned, found
        while True:
            ip = q.get()
            if ip is None:
                break
            try:
                domain = socket.gethostbyaddr(ip)[0]
                root = extract_root_domain(domain)
                with lock:
                    if root not in root_domains:
                        root_domains.add(root)
                        all_domains.add(domain)
                        found += 1
                        color = random.choice(colors)
                        print(f"{color}[-] {ip} → {domain}")
                        with open(output_file, "a") as f:
                            f.write(root + "\n")
            except:
                pass
            finally:
                with lock:
                    scanned += 1
                q.task_done()

    def progress(total_ips):
        while scanned < total_ips:
            print(f"{WHITE}[SCAN] {scanned}/{total_ips} scanned | {GREEN}{found} found", end='\r')
            time.sleep(0.5)

    try:
        network = ipaddress.ip_network(cidr_input, strict=False)
    except Exception as e:
        print(f"{RED}[!] Invalid CIDR: {e}")
        return

    ip_list = list(network.hosts())
    random.shuffle(ip_list)
    total_ips = len(ip_list)
    print(f"{YELLOW}[*] Scanning {total_ips} IPs from {cidr_input} (in random order)...\n")

    q = Queue()
    for ip in ip_list:
        q.put(str(ip))

    threading.Thread(target=progress, args=(total_ips,), daemon=True).start()

    threads = []
    for _ in range(user_threads):
        t = threading.Thread(target=reverse_dns_worker, daemon=True)
        t.start()
        threads.append(t)

    q.join()

    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()

    print(f"\n{MAGENTA}[✔] Scan complete. {GREEN}{found} live domains found.")
    print(f"{CYAN}[✓] Root domains saved to {output_file}")

# === Option 9: SUBDOMAIN DOMAIN MAPPER ===
def subdomain_mapper():
    import os
    import time
    from collections import defaultdict
    from colorama import Fore, Style, init
    init(autoreset=True)
    BOLD = Style.BRIGHT

    YELLOW = Fore.YELLOW + BOLD
    GREEN = Fore.GREEN + BOLD
    CYAN = Fore.CYAN + BOLD
    MAGENTA = Fore.MAGENTA + BOLD
    RED = Fore.RED + BOLD
    BLUE = Fore.BLUE + BOLD
    WHITE = Fore.WHITE + BOLD

    COLORS = [MAGENTA, CYAN, GREEN, YELLOW, RED, BLUE, WHITE]

    os.system("clear")
    print(YELLOW + BOLD + "📁 SUBDOMAIN DOMAIN MAPPER")
    print("-" * 60)

    file_path = input(CYAN + "\n📄 Enter path to subdomain .txt file: ").strip()

    if not os.path.isfile(file_path):
        print(RED + "\n❌ File not found!")
        input("\nPress Enter to return to menu...")
        return

    print(GREEN + "\n🔍 Scanning subdomains...\n")
    start_time = time.time()

    domain_map = defaultdict(set)

    try:
        with open(file_path, "r") as f:
            for line in f:
                sub = line.strip().lower()
                if not sub or "." not in sub:
                    continue
                parts = sub.split(".")
                if len(parts) >= 2:
                    root_domain = ".".join(parts[-2:])
                    domain_map[root_domain].add(sub)
    except Exception as e:
        print(RED + f"\n❌ Error reading file: {e}")
        input("\nPress Enter to return to menu...")
        return

    if not domain_map:
        print(RED + "\n❌ No valid subdomains found.")
        input("\nPress Enter to return to menu...")
        return

    total = len(domain_map)
    print(YELLOW + f"\n📊 Total Root Domains with Subdomains: {total}")
    print("-" * 60)

    color_index = 0
    line_count = 0

    for root, subs in domain_map.items():
        color = COLORS[color_index]
        print(color + f"🌐 {root} → {len(subs)} subdomain(s) found")
        line_count += 1
        if line_count % 2 == 0:
            color_index = (color_index + 1) % len(COLORS)

    elapsed = round(time.time() - start_time, 2)
    print(GREEN + f"\n✅ Scan completed in {elapsed} seconds")
    input(CYAN + "\n🔙 Press Enter to return to menu...")

# === Option 10: REMOVE SUBDOMAINS ===
def remove_subdomains():
    import os, time
    from colorama import Fore, Style, init
    init(autoreset=True)
    BOLD = Style.BRIGHT

    os.system("clear")
    print(Fore.YELLOW + BOLD + "[•] SUBDOMAIN REMOVER STARTED...\n")

    domains = input(Fore.CYAN + BOLD + "[?] Enter domains to remove (comma separated, e.g., jio.com,google.com): ")
    domain_list = [d.strip().lower() for d in domains.split(",") if d.strip()]

    txt_file = input(Fore.CYAN + BOLD + "[?] Enter .txt filename containing subdomains: ").strip()
    if not os.path.isfile(txt_file):
        print(Fore.RED + BOLD + f"[!] File '{txt_file}' not found.")
        input(Fore.YELLOW + "\n[•] Press Enter to return to menu...")
        return

    print(Fore.MAGENTA + BOLD + "\n[✔] Removing subdomains for:", ', '.join(domain_list))
    print(Fore.BLUE + BOLD + f"[+] Processing: {txt_file}")

    start = time.time()
    total = 0
    removed = 0

    try:
        temp_file = txt_file + ".tmp"

        with open(txt_file, "r") as infile, open(temp_file, "w") as outfile:
            for line in infile:
                total += 1
                line = line.strip().lower()
                if not line:
                    continue
                if not any(line.endswith("." + d) or line == d for d in domain_list):
                    outfile.write(line + "\n")
                else:
                    removed += 1

        os.replace(temp_file, txt_file)

        end = time.time()
        print(Fore.GREEN + BOLD + f"\n[✓] Total Lines     : {total}")
        print(Fore.RED + BOLD   + f"[✓] Removed Lines   : {removed}")
        print(Fore.GREEN + BOLD + f"[✓] Saved Remaining : {total - removed}")
        print(Fore.YELLOW + BOLD + f"[⏱] Time Taken      : {round(end - start, 2)} seconds")
        print(Fore.CYAN + BOLD + f"[💾] File Overwritten: {txt_file}")
    except Exception as e:
        print(Fore.RED + BOLD + f"\n[!] Error: {e}")

    input(Fore.YELLOW + "\n[•] Press Enter to return to menu...")

# === Option 11: UPDATE TOOL ===
def update_tool():
    import os
    import time
    import requests
    from colorama import Fore, Style, init

    init(autoreset=True)
    BOLD = Style.BRIGHT
    YELLOW = Fore.YELLOW + BOLD
    GREEN = Fore.GREEN + BOLD
    RED = Fore.RED + BOLD
    CYAN = Fore.CYAN + BOLD

    # === Detect local version ===
    try:
        with open("version.txt", "r") as vf:
            local_version = vf.read().strip()
    except:
        local_version = "0.0"

    version_url = "https://raw.githubusercontent.com/bughunter11/BugTraceX/main/version.txt"
    script_url = "https://raw.githubusercontent.com/bughunter11/BugTraceX/main/BugTraceX.py"
    output_file = "BugTraceX.py"
    tmp_file = "BugTraceX_new.py"

    print(YELLOW + "\n[*] Checking for updates...")

    try:
        r = requests.get(version_url)
        r.raise_for_status()
        remote_version = r.text.strip()
    except Exception as e:
        print(RED + f"[!] Could not fetch remote version: {e}")
        time.sleep(2)
        return

    if remote_version == local_version:
        print(GREEN + f"[✓] Already up-to-date (v{local_version}).")
        time.sleep(3)
        return
    else:
        print(YELLOW + f"[!] Update available: v{local_version} → v{remote_version}")
        choice = input(CYAN + "[?] Do you want to update? (y/n): ").strip().lower()
        if choice != "y":
            print(RED + "[×] Update cancelled by user.\n")
            time.sleep(2)
            return

    print(YELLOW + "\n[*] Downloading latest version from GitHub...")

    try:
        response = requests.get(script_url)
        if response.status_code == 200:
            with open(tmp_file, "wb") as f:
                f.write(response.content)
            os.replace(tmp_file, output_file)
            with open("version.txt", "w") as vf:
                vf.write(remote_version)
            print(GREEN + "\n[✓] Tool updated successfully!")
            print(GREEN + "[→] Please restart Termux and run the script again.\n")
            time.sleep(4)
        else:
            print(RED + f"[✗] Update failed. GitHub responded with status code: {response.status_code}")
            time.sleep(2)
    except Exception as e:
        print(RED + f"[!] Update error: {str(e)}")
        time.sleep(2)

# === Exit ===
def exit_script():
    print(Fore.YELLOW + "\n┌" + "─" * 52 + "┐")
    print(Fore.MAGENTA + BOLD + "│       THANKS FOR USING RAJ TOOLKIT!       │")
    print(Fore.CYAN    + BOLD + "│   • Keep Hacking Ethically!               │")
    print(Fore.CYAN    + BOLD + "│   • Knowledge is Power!                   │")
    print(Fore.GREEN   + BOLD + "│   • Made with ♥ by RAJ_MAKER              │")
    print(Fore.YELLOW + "└" + "─" * 52 + "┘")
    sys.exit()

# === Main Runner ===
def main():
    while True:
        banner()
        menu()
        choice = input().strip()

        if choice == '1':
            host_scanner()
        elif choice == '2':
            subfinder()
        elif choice == '3':
            host_info()
        elif choice == '4':
            split_txt_file()
        elif choice == '5':
            smart_subfinder()
        elif choice == '6':
            smart_cidr_scan()
        elif choice == '7':
            reverse_ip_lookup()
        elif choice == '8':
            cidr_to_domain()
        elif choice == '9':
            subdomain_mapper()
        elif choice == '10':
            remove_subdomains()
        elif choice == '11':
            update_tool()
        elif choice == '0':
            exit_script()
        else:
            print(Fore.RED + BOLD + "  Invalid option!")

# === Execute Only When Run Directly ===
if __name__ == "__main__":
    main()