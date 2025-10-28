#!/usr/bin/env python3
"""
crawl_vulns.py

Cluster-ready HTTP crawler and passive vulnerability scanner with fuzzing.
- Input: file with one target per line ("1.2.3.4" or "1.2.3.4:8080")
- Output: JSON report including discovered endpoints, parameters, vulnerabilities, and fuzzing details.
- Verbose option will log progress to the console.

⚠️ Legal note:
    Use only on systems you are authorized to test.

Dependencies:
    pip install aiohttp beautifulsoup4

Example:
    python3 crawl_vulns.py -t ips.txt -o results.json -c 100 -d 2 --verbose
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
    "xss": ["../test", "..%2f..%2fetc/passwd"],
    "php": ["../test", "..%2f..%2fetc/passwd"],
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
# Core Crawler with Fuzzing
# -----------------------

class Crawler:
    def __init__(self, targets: List[Tuple[str, int]], out_file: Path,
                 concurrency: int = 50, depth: int = 2, timeout: int = 15,
                 extra_paths: List[str] = None, verbose: bool = False):
        self.targets = targets
        self.out_file = out_file
        self.concurrency = concurrency
        self.depth = depth
        self.timeout = timeout
        self.extra_paths = extra_paths or []
        self.verbose = verbose
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = {}

    async def _get(self, session, url: str):
        if self.verbose:
            print(f"Fetching: {url}")
        async with self.semaphore:
            return await fetch(session, url, timeout=self.timeout)

    async def probe_param(self, session, base_url: str, path: str, param: str) -> Dict:
        parsed = urlparse(base_url)
        scheme_netloc = f"{parsed.scheme}://{parsed.netloc}"
        target_url = urljoin(scheme_netloc, path)

        fuzz_results = []
        for payload in PAYLOADS:
            q = {param: payload}
            sep = "&" if "?" in target_url else "?"
            url = f"{target_url}{sep}{urlencode(q)}"
            status, text, headers = await self._get(session, url)
            reflected = payload in (text or "")
            fuzz_results.append({
                "payload": payload,
                "status": status,
                "len": len(text) if text else 0,
                "reflected": reflected,
                "url": url,
            })

        # Always include a vulnerabilities key, even if empty
        vulnerabilities = [
            {
                "type": "reflection",
                "url": result["url"],
                "param": param,
                "payload": result["payload"]
            }
            for result in fuzz_results if result["reflected"]
        ]
        
        # Ensure 'vulnerabilities' is always present
        return {"path": path, "param": param, "fuzz_results": fuzz_results, "vulnerabilities": vulnerabilities}


    async def crawl_target(self, session, host: str, port: int):
        base_url = make_base_url(host, port)
        info = {"host": host, "port": port, "base_url": base_url,
                "discovered": {}, "fuzzing": [], "vulnerabilities": []}  # Added "vulnerabilities" here
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
                    info["fuzzing"].append({
                        "type": "info_leak",
                        "url": url,
                        "detail": "Contains keyword 'test' in response.",
                    })

        # Probe discovered parameters for fuzzing
        probe_tasks = []
        for page_url, data in info["discovered"].items():
            for path, params in data["params"].items():
                for param in params:
                    probe_tasks.append(self.probe_param(session, page_url, path, param))

        probe_results = await asyncio.gather(*probe_tasks)
        for probe in probe_results:
            # Ensure we add 'vulnerabilities' to prevent KeyError
            info["fuzzing"].extend(probe["fuzz_results"])
            info["vulnerabilities"].extend(probe["vulnerabilities"])

        self.results[f"{host}:{port}"] = info


    async def run(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout + 5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = []
            for host, port in self.targets:
                tasks.append(self.crawl_target(session, host, port))

            await asyncio.gather(*tasks)

    def save(self):
        with open(self.out_file, "w") as f:
            json.dump(self.results, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crawl and fuzz HTTP targets to discover vulnerabilities.")
    parser.add_argument("-t", "--targets", required=True, help="File containing list of target IPs or domains")
    parser.add_argument("-o", "--output", required=True, help="Output file for results (JSON format)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Max concurrent requests")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Max depth of crawl")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--extra", nargs="*", default=[], help="Additional common paths to probe")

    args = parser.parse_args()

    targets = []
    with open(args.targets, "r") as f:
        for line in f:
            host, port = normalize_target_line(line)
            targets.append((host, port))

    crawler = Crawler(
        targets=targets,
        out_file=Path(args.output),
        concurrency=args.concurrency,
        depth=args.depth,
        extra_paths=args.extra,
        verbose=args.verbose
    )

    loop = asyncio.get_event_loop()
    loop.run_until_complete(crawler.run())
    crawler.save()
    print(f"Scan complete. Results saved to {args.output}.")
