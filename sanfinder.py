from typing_extensions import final
import termcolor
import socket
import sys
import ssl
import queue
import tldextract


try:
    san_type = sys.argv[2]
    domains_file = sys.argv[1]
except:
    print("Error in command.")
    print("Try: python3 sanfinder.py <file_path> <san_type>[same/all]")
    sys.exit(1)


def tldExt(name):
    return tldextract.extract(name).registered_domain

try:
    with open(domains_file, 'r') as d:
        domains = d.read().strip().split()
except FileNotFoundError:
    print("File Not Exist..")
    sys.exit(1)

finalset = set(domains)
additional_parent_domains = set()
for domain in finalset:
    additional_parent_domains.add(tldExt(domain))

finalset = finalset.union(additional_parent_domains)

if san_type in ["same", "all"]:
    print(termcolor.colored('_' * 60, color='white', attrs=['bold']))
    print(termcolor.colored("\nFinding subdomains using Subject Alternative Names(SANs)...\n", color='yellow', attrs=['bold']))
    nothing_found_flag = True
    context = ssl.create_default_context()
    context.check_hostname = False

    socket.setdefaulttimeout(5)

    q = queue.Queue()
    printed = set()
    completed = set()
    for domain in finalset:
        q.put(domain)
    
    while not q.empty():
        try:
            hostname = q.get()
            if san_type == "same":
                if hostname not in printed and hostname not in finalset and any(hostname.endswith(d) for d in additional_parent_domains):
                    print(termcolor.colored(hostname, color='green', attrs=['bold']))
                    nothing_found_flag = False
                    printed.add(hostname)
            elif san_type == "all":
                if hostname not in printed and hostname not in finalset:
                    print(termcolor.colored(hostname, color='green', attrs=['bold']))
                    nothing_found_flag = False
                    printed.add(hostname)

            if hostname not in completed:
                completed.add(hostname)
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname, ) as ssock:
                        for (k, v) in ssock.getpeercert()['subjectAltName']:
                            if v not in q.queue and v.startswith("*.") and v.lstrip('*.') not in finalset:
                                q.put(v.lstrip('*.'))
                            elif v not in q.queue and v not in finalset:
                                q.put(v.lstrip('*.'))
        except (socket.gaierror, socket.timeout, ssl.SSLCertVerificationError, ConnectionRefusedError,
                ssl.SSLError, OSError):
            pass
        except KeyboardInterrupt:
            print(termcolor.colored("\nKeyboard Interrupt. Exiting...\n", color='red', attrs=['bold']))
            sys.exit(1)

    if nothing_found_flag:
        print(termcolor.colored("No SANs found.", color='green', attrs=['bold']))
else:
    print("Only `all` or `same` is supported option for type")
    print("eg. python3 sanfinder.py <file_path> <san_type>")
    sys.exit(1)