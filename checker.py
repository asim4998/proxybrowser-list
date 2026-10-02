#!/usr/bin/env python3
"""ProxyBrowser proxy-list checker.

Fetches free proxies from ProxyScrape (v4 JSON API) and Geonode,
tests each with a real TCP handshake (SOCKS5 / SOCKS4 / HTTP CONNECT),
and writes proxies.json: country-ranked, speed-tested, top 60 per country.

Stdlib only -- runs on any machine and in GitHub Actions.
Writes proxies.json to the current working directory (repo root).
"""
import json
import socket
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

TIMEOUT = 4            # seconds per proxy test
MAX_PER_COUNTRY = 60   # cap kept entries per country
WORKERS = 250          # concurrent TCP tests
PROBE_IP = "93.184.216.34"   # example.com -- used for CONNECT target (no DNS needed)
PROBE_PORT = 80
UA = {"User-Agent": "ProxyBrowser-checker/1.0"}


def fetch_json(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


# ---------------------------------------------------------------- sources

def proxyscrape():
    """ProxyScrape v4 free API, JSON format (has ip_data.countryCode)."""
    out = []
    for proto in ("socks5", "socks4", "http"):
        skip = 0
        while True:
            url = ("https://api.proxyscrape.com/v4/free-proxy-list/get?"
                   "request=display_proxies&proxy_format=protocolipport&format=json"
                   "&protocol=%s&limit=2000&skip=%d" % (proto, skip))
            d = fetch_json(url)
            for p in d.get("proxies", []):
                cc = ((p.get("ip_data") or {}).get("countryCode") or "").upper()
                if len(cc) != 2:
                    continue
                try:
                    port = int(p["port"])
                except (KeyError, TypeError, ValueError):
                    continue
                out.append({"ip": p["ip"], "port": port, "proto": p.get("protocol", proto),
                            "country": cc, "source": "proxyscrape"})
            total = d.get("total_records") or 0
            shown = d.get("shown_records") or 0
            if not d.get("nextpage") or skip + shown >= total:
                break
            skip += shown
    return out


def geonode():
    """Geonode free proxy API (country + protocols fields)."""
    out = []
    page, limit = 1, 500
    while True:
        d = fetch_json("https://proxylist.geonode.com/api/proxy-list"
                       "?limit=%d&page=%d&sort_by=lastChecked&sort_type=desc" % (limit, page))
        for p in d.get("data", []):
            protos = p.get("protocols") or []
            proto = protos[0] if protos else "http"
            if proto == "https":
                proto = "http"
            if proto not in ("http", "socks4", "socks5"):
                continue
            cc = (p.get("country") or "").upper()
            if len(cc) != 2:
                continue
            try:
                port = int(p["port"])
            except (KeyError, TypeError, ValueError):
                continue
            out.append({"ip": p["ip"], "port": port, "proto": proto,
                        "country": cc, "source": "geonode"})
        total = d.get("total") or 0
        if page * limit >= total:
            break
        page += 1
    return out


# ---------------------------------------------------------------- TCP tests

def recvn(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def test_socks5(ip, port):
    """Full SOCKS5 handshake + CONNECT to probe target."""
    try:
        return _test_socks5(ip, port)
    except OSError:
        return None


def _test_socks5(ip, port):
    s = socket.create_connection((ip, port), timeout=TIMEOUT)
    try:
        s.settimeout(TIMEOUT)
        t = time.time()
        s.sendall(b"\x05\x01\x00")                       # greeting, no-auth
        if recvn(s, 2) != b"\x05\x00":
            return None                                  # auth required or not SOCKS5
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(PROBE_IP)
                  + struct.pack(">H", PROBE_PORT))       # CONNECT probe:80
        r = recvn(s, 4)
        if len(r) < 4 or r[0] != 5 or r[1] != 0:
            return None
        atyp = r[3]
        if atyp == 1:
            recvn(s, 6)
        elif atyp == 3:
            ln = recvn(s, 1)
            recvn(s, (ln[0] if ln else 0) + 2)
        elif atyp == 4:
            recvn(s, 18)
        return int((time.time() - t) * 1000)
    finally:
        s.close()


def test_socks4(ip, port):
    """SOCKS4 CONNECT request to probe target."""
    try:
        return _test_socks4(ip, port)
    except OSError:
        return None


def _test_socks4(ip, port):
    s = socket.create_connection((ip, port), timeout=TIMEOUT)
    try:
        s.settimeout(TIMEOUT)
        t = time.time()
        s.sendall(b"\x04\x01" + struct.pack(">H", PROBE_PORT)
                  + socket.inet_aton(PROBE_IP) + b"\x00")
        r = recvn(s, 8)
        if len(r) < 8 or r[1] != 0x5A:                   # 0x5A = granted
            return None
        return int((time.time() - t) * 1000)
    finally:
        s.close()


def test_http(ip, port):
    """HTTP CONNECT to probe target; success on 2xx."""
    try:
        return _test_http(ip, port)
    except OSError:
        return None


def _test_http(ip, port):
    s = socket.create_connection((ip, port), timeout=TIMEOUT)
    try:
        s.settimeout(TIMEOUT)
        t = time.time()
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n"
                   "Proxy-Connection: keep-alive\r\n\r\n"
                   % (PROBE_IP, PROBE_PORT, PROBE_IP)).encode())
        data = b""
        while b"\r\n" not in data and len(data) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        parts = line.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if 200 <= code < 300:
            return int((time.time() - t) * 1000)
        return None
    finally:
        s.close()


TESTERS = {"socks5": test_socks5, "socks4": test_socks4, "http": test_http}


# ---------------------------------------------------------------- main

def main():
    seen = set()
    cand = []
    for src in (proxyscrape, geonode):
        try:
            items = src()
        except Exception as e:
            print("source failed: %s: %s" % (src.__name__, e), flush=True)
            items = []
        print("%s: %d raw" % (src.__name__, len(items)), flush=True)
        for p in items:
            key = (p["ip"], p["port"], p["proto"])
            if key in seen:
                continue
            seen.add(key)
            cand.append(p)
    print("candidates after dedupe: %d" % len(cand), flush=True)

    def check(p):
        try:
            ms = TESTERS[p["proto"]](p["ip"], p["port"])
        except Exception:
            ms = None
        return p, ms

    alive = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for p, ms in ex.map(check, cand):
            if ms is None:
                continue
            alive.setdefault(p["country"], []).append(
                {"ip": p["ip"], "port": p["port"], "proto": p["proto"], "ms": ms})

    countries = {cc: sorted(v, key=lambda x: x["ms"])[:MAX_PER_COUNTRY]
                 for cc, v in alive.items()}
    out = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "countries": countries,
        "counts": {cc: len(v) for cc, v in countries.items()},
        "sources": ["proxyscrape", "geonode"],
    }
    with open("proxies.json", "w") as f:
        json.dump(out, f)
    total = sum(out["counts"].values())
    top = sorted(out["counts"].items(), key=lambda kv: kv[1], reverse=True)[:5]
    print("alive: %d across %d countries" % (total, len(countries)), flush=True)
    print("top5: %s" % top, flush=True)
    print("generated_at: %s" % out["generated_at"], flush=True)


if __name__ == "__main__":
    main()
