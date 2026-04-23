import os

blocked_ips = set()

def block_ip(ip):
    if ip in blocked_ips:
        return

    print(f"[🔥] Blocking IP: {ip}")

    # Block using iptables
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

    blocked_ips.add(ip)