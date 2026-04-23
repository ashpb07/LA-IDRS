import os

def unblock_ip(ip):
    print(f"[+] Unblocking IP: {ip}")
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")