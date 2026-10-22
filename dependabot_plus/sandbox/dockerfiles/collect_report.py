"""In-container report builder: parse monitor logs into the JSON the runner reads.

Runs inside the sandbox image (python3 only, stdlib). Kept as a standalone
file so it can be unit tested. Timestamps (tcpdump -tt) split events into
"install" (before the install command exited) and "post_install" (after).
"""
import json
import os
import re
import sys

_TS = re.compile(r"^(\d+(?:\.\d+)?)\s")
_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"


def _read(log_dir, name):
    try:
        with open(os.path.join(log_dir, name), errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def parse_dns(text, install_end):
    """Return (queries, post_install_queries, {ip: [hostnames]})."""
    queries, post, answers = [], [], {}
    last_ts = 0.0
    for line in text.splitlines():
        m = _TS.match(line)
        if m:
            last_ts = float(m.group(1))
        q = re.search(r"(\w+\?)\s+(\S+)", line)
        if q:
            entry = f"{q.group(1)} {q.group(2).rstrip('.')}"
            if entry not in queries:
                queries.append(entry)
            if last_ts > install_end and entry not in post:
                post.append(entry)
        for a in re.finditer(r"([A-Za-z0-9_.-]+?)\.? A (" + _IPV4 + ")", line):
            hosts = answers.setdefault(a.group(2), [])
            if a.group(1) not in hosts:
                hosts.append(a.group(1))
    return queries, post, answers


def parse_tcp(text, install_end):
    """Return (outbound destinations 'ip.port', post-install destinations)."""
    dests, post = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or " In " in line:
            continue
        m = re.search(r"> (\d+\.\d+\.\d+\.\d+\.\d+):", line)
        if not m:
            continue
        ts = _TS.match(line)
        dest = m.group(1)
        if dest not in dests:
            dests.append(dest)
        if ts and float(ts.group(1)) > install_end and dest not in post:
            post.append(dest)
    return dests, post


def parse_http(content):
    http_requests = []
    for m in re.finditer(r"(GET|POST|PUT|DELETE|PATCH) (\S+) HTTP", content):
        method, path = m.group(1), m.group(2)
        host_m = re.search(r"Host:\s*(\S+)", content[m.start():m.start() + 500])
        entry = {"method": method, "path": path, "host": host_m.group(1) if host_m else "unknown"}
        if method in ("POST", "PUT"):
            body_start = content.find("\r\n\r\n", m.start())
            if body_start > 0:
                body = content[body_start + 4:body_start + 504].strip()
                if body:
                    entry["body_preview"] = body[:500]
        http_requests.append(entry)
    return http_requests


def _lines(text):
    return [line.strip() for line in text.splitlines() if line.strip()]


def build_report(log_dir, install_exit, install_end):
    dns, dns_post, answers = parse_dns(_read(log_dir, "dns.log"), install_end)
    tcp, tcp_post = parse_tcp(_read(log_dir, "network.log"), install_end)
    return {
        "install_exit_code": install_exit,
        "install_end": install_end,
        "install_log": _read(log_dir, "install.log")[-10000:],
        "file_accesses": _lines(_read(log_dir, "canary.log")),
        "file_writes": _lines(_read(log_dir, "writes.log")),
        "dns_queries": dns,
        "dns_queries_post_install": dns_post,
        "dns_answers": answers,
        "tcp_connections": tcp,
        "tcp_connections_post_install": tcp_post,
        "http_requests": parse_http(_read(log_dir, "payload.log")),
        "sudo_attempts": _lines(_read(log_dir, "sudo.log")),
    }


if __name__ == "__main__":
    report = build_report(
        os.environ.get("LOG_DIR", "/var/log"),
        int(sys.argv[1]) if len(sys.argv) > 1 else 0,
        float(sys.argv[2]) if len(sys.argv) > 2 else 0.0,
    )
    print(json.dumps(report))
