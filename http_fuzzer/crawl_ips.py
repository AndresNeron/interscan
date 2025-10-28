#!/usr/bin/env python3
"""
crawl_ips.py

Cluster-ready HTTP crawler and passive vulnerability scanner.
- Input: file with one target per line ("1.2.3.4" or "1.2.3.4:8080")
- Output: JSON report including endpoints, parameters, and potential issues.

⚠️ Legal note:
    Use only on systems you are authorized to test.

Dependencies:
    pip install aiohttp beautifulsoup4

Example:
    python3 crawl_ips.py -t ips.txt -o results.json -c 100 -d 2
"""

import sys
import json
import asyncio
import argparse
import urllib.parse
from pathlib import Path
from typing import List, Set, Dict, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp
from bs4 import BeautifulSoup

# -----------------------
# Configuration constants
# -----------------------

DEFAULT_COMMON_PATHS = [
    "/", "/index.html", "/index.php", "/admin", "/login", "/robots.txt",
    "/favicon.ico", "/sitemap.xml", "/.env", "/config.php", "/setup.php",
    "/phpinfo.php", "/wp-login.php", "/wp-admin/", "/api/", "/status",
]

BASE_PROBE = "interscan_test_12345"

PAYLOADS = [
    BASE_PROBE,                            # baseline
    urllib.parse.quote(BASE_PROBE),        # URL encoded
    urllib.parse.quote_plus(BASE_PROBE),   # form encoded
    BASE_PROBE.replace("_", "%5f"),        # partially encoded
]

# Optional payload profiles for analysis
payload_profiles = {
    "encoding": ["interscan_test_12345", "%69%6e%74%65%72%73%63%61%6e"],
    "path_traversal": ["../test", "..%2f..%2fetc/passwd"],
}


# -----------------------
# Helper functions
# -----------------------

def normalize_target_line(line: str) -> Tuple[str, int]:
    line = line.strip()
    if not line:
        raise ValueError("Empty target line")
    if ":" in line:
        host, port = line.split(":", 1)
        return host, int(port)
    return line, 80


def make_base_url(host: str, port: int) -> str:
    if port == 80:
        return f"http://{host}/"
    return f"http://{host}:{port}/"


async def fetch(session: aiohttp.ClientSession, url: str, timeout: int = 15):
    try:
        async with session.get(url, timeout=timeout) as resp:
            text = await resp.text(errors="replace")
            return resp.status, text, dict(resp.headers)
    except Exception:
        return None, None, None


def extract_links_and_params(base_url: str, html: str) -> Tuple[Set[str], Dict[str, Set[str]]]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    params_map = {}

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        absolute = urljoin(base_url, href)
        links.add(absolute)
        qs = urlparse(absolute).query
        if qs:
            for k in parse_qs(qs).keys():
                path = urlparse(absolute).path or "/"
                params_map.setdefault(path, set()).add(k)

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        absolute = urljoin(base_url, action)
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                path = urlparse(absolute).path or "/"
                params_map.setdefault(path, set()).add(name)

    return links, params_map


# -----------------------
# Core Crawler
# -----------------------

class Crawler:
    def __init__(self, targets: List[Tuple[str, int]], out_file: Path,
                 concurrency: int = 50, depth: int = 2, timeout: int = 15,
                 extra_paths: List[str] = None):
        self.targets = targets
        self.out_file = out_file
        self.concurrency = concurrency
        self.depth = depth
        self.timeout = timeout
        self.extra_paths = extra_paths or []
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = {}

    async def _get(self, session, url: str):
        async with self.semaphore:
            return await fetch(session, url, timeout=self.timeout)

    async def probe_param(self, session, base_url: str, path: str, param: str) -> Dict:
        parsed = urlparse(base_url)
        scheme_netloc = f"{parsed.scheme}://{parsed.netloc}"
        target_url = urljoin(scheme_netloc, path)

        reflections = []
        for payload in PAYLOADS:
            q = {param: payload}
            sep = "&" if "?" in target_url else "?"
            url = f"{target_url}{sep}{urlencode(q)}"
            status, text, headers = await self._get(session, url)
            reflected = payload in (text or "")
            reflections.append({
                "payload": payload,
                "status": status,
                "len": len(text) if text else 0,
                "reflected": reflected,
                "url": url,
            })
        return {"path": path, "param": param, "tests": reflections}

    async def crawl_target(self, session, host: str, port: int):
        base_url = make_base_url(host, port)
        info = {"host": host, "port": port, "base_url": base_url,
                "discovered": {}, "vulnerabilities": []}
        visited = set()
        to_visit = {base_url}
        depth = 0

        while to_visit and depth < self.depth:
            next_round = set()
            tasks = []
            for url in to_visit:
                if url in visited:
                    continue
                visited.add(url)
                tasks.append(self._get(session, url))

            responses = await asyncio.gather(*tasks)
            for url, (status, text, _) in zip(list(visited)[-len(responses):], responses):
                if status is None:
                    continue
                links, params_map = extract_links_and_params(url, text or "")
                info["discovered"][url] = {
                    "status": status,
                    "links": list(links),
                    "params": {p: list(s) for p, s in params_map.items()},
                }
                for link in links:
                    p = urlparse(link)
                    if (p.scheme in ("http", "https")) and (p.hostname == host):
                        next_round.add(f"{p.scheme}://{p.netloc}{p.path or '/'}")
            to_visit = next_round
            depth += 1

        # Probe default and extra paths
        for p in DEFAULT_COMMON_PATHS + self.extra_paths:
            url = urljoin(base_url, p)
            status, text, _ = await self._get(session, url)
            if status == 200 and ("index" not in p):
                if "test" in (text or "").lower():
                    info["vulnerabilities"].append({
                        "type": "info_leak",
                        "url": url,
                        "detail": "Contains keyword 'test' in response.",
                    })

        # Probe discovered parameters
        probe_tasks = []
        for page_url, data in info["discovered"].items():
            for path, params in data["params"].items():
                for param in params:
                    probe_tasks.append(self.probe_param(session, page_url, path, param))

        probe_results = await asyncio.gather(*probe_tasks)
        for probe in probe_results:
            for test in probe["tests"]:
                if test["reflected"]:
                    info["vulnerabilities"].append({
                        "type": "reflection",
                        "url": test["url"],
                        "param": probe["param"],
                        "payload": test["payload"],
                    })

        self.results[f"{host}:{port}"] = info

    async def run(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout + 5)
        headers = {"User-Agent": "interscan-vulnscan/1.0 (+https://example.invalid)"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            tasks = [self.crawl_target(session, host, port) for host, port in self.targets]
            await asyncio.gather(*tasks)

    def save(self):
        with open(self.out_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)


# -----------------------
# CLI entry
# -----------------------

def parse_args():
    p = argparse.ArgumentParser(description="Distributed HTTP crawler and passive vulnerability scanner.")
    p.add_argument("--targets", "-t", required=True, help="File with one IP or ip:port per line")
    p.add_argument("--out", "-o", default="crawl_results.json", help="Output JSON file")
    p.add_argument("--concurrency", "-c", type=int, default=50, help="Max concurrent requests")
    p.add_argument("--depth", "-d", type=int, default=2, help="Crawl depth")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout (seconds)")
    p.add_argument("--extra-paths", "-p", nargs="*", help="Extra paths to test")
    return p.parse_args()


def load_targets(path: Path) -> List[Tuple[str, int]]:
    lines = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    targets = []
    for line in lines:
        try:
            host, port = normalize_target_line(line)
            targets.append((host, port))
        except Exception as e:
            print(f"Skipping invalid target line: {line} ({e})", file=sys.stderr)
    return targets


def main():
    args = parse_args()
    tfile = Path(args.targets)
    if not tfile.exists():
        print(f"Targets file not found: {tfile}", file=sys.stderr)
        sys.exit(2)

    targets = load_targets(tfile)
    if not targets:
        print("No valid targets loaded.", file=sys.stderr)
        sys.exit(2)

    crawler = Crawler(
        targets=targets,
        out_file=Path(args.out),
        concurrency=args.concurrency,
        depth=args.depth,
        timeout=args.timeout,
        extra_paths=args.extra_paths or [],
    )

    asyncio.run(crawler.run())
    crawler.save()
    print(f"✅ Results saved to {args.out}")


if __name__ == "__main__":
    main()
