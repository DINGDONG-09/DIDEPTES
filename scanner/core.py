# Komponen inti: Orchestrator + Crawler & HTTP client

import time
import requests
import re, urllib.parse as up
from bs4 import BeautifulSoup

from .checks.headers import HeaderCheck
from .checks.cookies_cors import CookieCORSCheck
from .checks.xss import XSSCheck
from .checks.sqli import SQLiCheck


class Crawler:
    HREF_RE = re.compile(r'href=["\'](.*?)["\']', re.I)

    def __init__(self, base, http, max_depth=1):
        # simpan base, http client, dan depth
        self.base = base.rstrip("/")
        self.http = http
        self.max_depth = max_depth
        self.visited = set()
        self.params = {}  # url -> [param1, param2, ...]
        self.base_host = up.urlparse(self.base).hostname

    def in_scope(self, url):
        # batasi hanya host yang sama
        return up.urlparse(url).hostname == self.base_host

    def crawl(self):
        # BFS sederhana dari base URL
        from collections import deque
        q = deque([(self.base, 0)])
        pages = []
        while q:
            url, d = q.popleft()
            if url in self.visited or d > self.max_depth or not self.in_scope(url):
                continue
            self.visited.add(url)
            try:
                r = self.http.get(url)
                pages.append((url, r))
                # simpan parameter GET jika ada
                qs = up.parse_qs(up.urlparse(url).query)
                if qs:
                    self.params[url] = list(qs.keys())
                # temukan link baru
                for href in self.HREF_RE.findall(r.text or ""):
                    q.append((up.urljoin(url, href), d + 1))
            except Exception:
                continue
        return pages


class HttpClient:
    """HTTP client sederhana + rate limit & timeout."""
    def __init__(self, rate=2.0, timeout=10):
        self.sess = requests.Session()
        self.rate = rate
        self.timeout = timeout
        self._last = 0

    def get(self, url, **kw):
        # rate limiting primitif
        now = time.time()
        delay = max(0, (1 / self.rate) - (now - self._last))
        if delay:
            time.sleep(delay)
        self._last = time.time()
        return self.sess.get(url, timeout=self.timeout, allow_redirects=True, **kw)


class Orchestrator:
    """Orkestrasi: crawl -> passive checks -> active checks."""
    def __init__(self, base_url, max_depth=1, rate=2.0, scope="same-domain"):
        self.base_url = base_url.rstrip("/")
        self.http = HttpClient(rate=rate)
        # ✅ inisialisasi crawler (yang sebelumnya hilang)
        self.crawler = Crawler(self.base_url, self.http, max_depth)

    def run(self):
        findings = []

        # 1) Crawl dulu agar dapat lebih dari 1 halaman + peta parameter
        pages = self.crawler.crawl()

        # 2) Passive checks di setiap halaman yang ditemukan
        for url, resp in pages:
            findings += HeaderCheck.inspect(url, resp)
            findings += CookieCORSCheck.inspect(url, resp)

        # 3) Active checks (butuh params_map dari crawler)
        params_map = self.crawler.params
        if params_map:
            findings += XSSCheck.run(self.http, params_map)
            findings += SQLiCheck.run(self.http, params_map)

        return findings
