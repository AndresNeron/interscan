#!/usr/bin/env python3
"""
crawl_ips.py

Crawl endpoints and parameters for a list of IPv4 addresses (port 80 or custom port).
- Input: file with one target per line (formats accepted: "1.2.3.4" or "1.2.3.4:8080")
- Output: JSON report with discovered paths, links, and parameters.

Dependencies:
    pip install aiohttp beautifulsoup4

Usage:
    python3 crawl_ips.py --targets ips.txt --out results.json --concurrency 50 --depth 2

Notes:
    - Be responsible: only scan systems you have permission to test.
    - This script uses a benign probe value for parameters ("interscan_test").
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

DEFAULT_COMMON_PATHS = [
    "/", "/index.html", "/index.php", "/admin", "/login", "/robots.txt",
    "/favicon.ico", "/sitemap.xml", "/.env", "/config.php", "/setup.php",
    "/phpinfo.php", "/wp-login.php", "/wp-admin/", "/api/", "/status",
]

BASE_PROBE = "interscan_test_12345"

PAYLOADS = [
    BASE_PROBE,  # baseline
    urllib.parse.quote(BASE_PROBE),         # URL-encoded
    urllib.parse.quote_plus(BASE_PROBE),    # application/x-www-form-urlencoded
    BASE_PROBE.replace("_", "%5f"),         # partial double-encoding example
]

payload_profiles = {
    "encoding": ["interscan_test_12345", "%69%6e%74%65%72%73%63%61%6e"],
    "xss_reflection": ["<script>", "'';!--=\"<XSS>=&{()}"],
    "path_traversal": ["../", "..%2f", "..%252f"],
}

# ----- Helpers -----
def normalize_target_line(line: str) -> Tuple[str, int]:
    """
    Parse a line like "1.2.3.4" or "1.2.3.4:8080" and return (ip, port)
    """
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
    """
    Fetch a URL and return (status, text, headers) or (None, None, None) on failure.
    """
    try:
        async with session.get(url, timeout=timeout) as resp:
            text = await resp.text(errors="replace")
            return resp.status, text, dict(resp.headers)
    except Exception as e:
        return None, None, None


def extract_links_and_params(base_url: str, html: str) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """
    Parse HTML and return:
      - set of discovered href paths (resolved absolute URLs)
      - dict mapping path -> set of parameter names seen in links/forms
    """
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    params_map = {}

    # <a href>
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        absolute = urljoin(base_url, href)
        links.add(absolute)
        qs = urlparse(absolute).query
        if qs:
            for k in parse_qs(qs).keys():
                path = urlparse(absolute).path or "/"
                params_map.setdefault(path, set()).add(k)

    # Forms (method, action, inputs)
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        absolute = urljoin(base_url, action)
        links.add(absolute)
        # inputs, selects, textareas
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                path = urlparse(absolute).path or "/"
                params_map.setdefault(path, set()).add(name)

    # Also look for script src and link hrefs (css) to discover paths
    for tag in soup.find_all(["script", "link", "img"], src=True):
        absolute = urljoin(base_url, tag["src"])
        links.add(absolute)

    for tag in soup.find_all("link", href=True):
        absolute = urljoin(base_url, tag["href"])
        links.add(absolute)

    return links, params_map


# ----- Main crawling logic -----


class Crawler:
    def __init__(self, targets: List[Tuple[str, int]], out_file: Path, concurrency: int = 50, depth: int = 2, timeout: int = 15, extra_paths: List[str] = None):
        self.targets = targets
        self.out_file = out_file
        self.concurrency = concurrency
        self.depth = depth
        self.timeout = timeout
        self.extra_paths = extra_paths or []
        self.semaphore = asyncio.Semaphore(concurrency)
        self.session: aiohttp.ClientSession = None
        self.results = {}

    async def _get(self, url: str):
        async with self.semaphore:
            return await fetch(self.session, url, timeout=self.timeout)

    async def probe_param(self, base_url: str, path: str, param: str) -> Dict:
        """
        Send a benign probe to a parameter and capture basic response metadata.
        """
        parsed = urlparse(base_url)
        scheme_netloc = f"{parsed.scheme}://{parsed.netloc}"
        target_url = urljoin(scheme_netloc, path)
        # We'll probe as GET param: ?param=BASE_PROBE
        q = {param: BASE_PROBE}
        sep = "&" if "?" in target_url else "?"
        url = f"{target_url}{sep}{urlencode(q)}"
        status, text, headers = await self._get(url)
        return {"url": url, "status": status, "len": len(text) if text else 0, "headers": headers}

    async def crawl_target(self, host: str, port: int):
        base_url = make_base_url(host, port)
        info = {"host": host, "port": port, "base_url": base_url, "discovered": {}, "probes": []}
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
                tasks.append(self._get(url))
            # run tasks
            responses = await asyncio.gather(*tasks)
            # match urls to responses in order
            for url, (status, text, headers) in zip(list(visited)[-len(responses):], responses):
                if status is None:
                    # failed
                    info["discovered"].setdefault(url, {"status": None, "links": [], "params": {}})
                    continue
                # parse links and params
                links, params_map = extract_links_and_params(url, text or "")
                info["discovered"].setdefault(url, {"status": status, "links": [], "params": {}})
                # store links (absolute) and discovered params
                info["discovered"][url]["links"] = list(links)
                # convert sets to lists
                info["discovered"][url]["params"] = {p: list(s) for p, s in params_map.items()}
                # schedule new internal links (same host) to next_round
                for link in links:
                    p = urlparse(link)
                    # same host & http
                    if (p.scheme in ("http", "https")) and (p.hostname == host):
                        # build normalized URL
                        normalized = f"{p.scheme}://{p.netloc}{p.path or '/'}"
                        next_round.add(normalized)
            to_visit = next_round
            depth += 1

        # probe common paths
        for p in DEFAULT_COMMON_PATHS + self.extra_paths:
            url = urljoin(base_url, p)
            status, text, headers = await self._get(url)
            info.setdefault("common_paths", []).append({"path": p, "url": url, "status": status, "len": len(text) if text else 0})

        # probe discovered parameters (benign)
        probe_tasks = []
        for page_url, data in info["discovered"].items():
            for path, params in data["params"].items():
                for param in params:
                    probe_tasks.append(self.probe_param(page_url, path, param))
        # limit concurrent probes to semaphore implicitly
        probe_results = []
        if probe_tasks:
            probe_results = await asyncio.gather(*probe_tasks)
        info["probes"] = probe_results

        self.results[f"{host}:{port}"] = info

    async def run(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout + 5)
        headers = {"User-Agent": "interscan-crawler/1.0 (+https://example.invalid)"}
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as sess:
            self.session = sess
            tasks = [self.crawl_target(host, port) for host, port in self.targets]
            # run with concurrency control at per-request level (semaphore)
            await asyncio.gather(*tasks)

    def save(self):
        with open(self.out_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)


# ----- CLI -----


def parse_args():
    p = argparse.ArgumentParser(description="Crawl HTTP endpoints and parameters for a list of IPs.")
    p.add_argument("--targets", "-t", required=True, help="File with one IP or ip:port per line")
    p.add_argument("--out", "-o", default="crawl_results.json", help="Output JSON file")
    p.add_argument("--concurrency", "-c", type=int, default=50, help="Max concurrent requests")
    p.add_argument("--depth", "-d", type=int, default=2, help="Crawl depth (levels of discovered internal links)")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout (seconds)")
    p.add_argument("--extra-paths", "-p", nargs="*", help="Extra common paths to probe")
    return p.parse_args()


def load_targets(path: Path) -> List[Tuple[str, int]]:
    lines = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    targets = []
    for L in lines:
        try:
            host, port = normalize_target_line(L)
            targets.append((host, port))
        except Exception as e:
            print(f"Skipping invalid target line: {L} ({e})", file=sys.stderr)
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

    out = Path(args.out)
    crawler = Crawler(targets=targets, out_file=out, concurrency=args.concurrency, depth=args.depth, timeout=args.timeout, extra_paths=args.extra_paths or [])
    asyncio.run(crawler.run())
    crawler.save()
    print(f"Saved results to {out}")

if __name__ == "__main__":
    main()
