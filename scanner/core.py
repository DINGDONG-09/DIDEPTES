# Komponen inti: Orchestrator + Crawler & HTTP client

import time
import requests
import re, urllib.parse as up
from bs4 import BeautifulSoup

from .checks.headers import HeaderCheck
from .checks.cookies_cors import CookieCORSCheck
from .checks.xss import XSSCheck
from .checks.sqli import SQLiCheck
from .checks.csrf import CSRFCheck
from .checks.misconfig import MisconfigCheck
from .loading import SimpleLoader


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
        
        # 1) Crawl first to get pages and parameter map - WITH LOADING
        crawler_loader = SimpleLoader("🕷️  Crawling website")
        crawler_loader.start()
        
        pages = self.crawler.crawl()  # returns [(url, response), ...]
        
        crawler_loader.stop(f"Found {len(pages)} pages")
        
        # 2) Extract URLs from pages for active checks
        crawled_urls = [url for url, resp in pages]
        
        # 3) Passive checks on each discovered page - WITH LOADING
        # Header checks
        header_loader = SimpleLoader("🔒 Checking security headers")
        header_loader.start()
        
        header_findings = []
        for url, resp in pages:
            header_findings += HeaderCheck.inspect(url, resp)
        findings += header_findings
        
        header_loader.stop(f"Header check completed - Found {len(header_findings)} issues")
        
        # Cookie & CORS checks
        cookie_loader = SimpleLoader("🍪 Analyzing cookies & CORS")
        cookie_loader.start()
        
        cookie_findings = []
        for url, resp in pages:
            cookie_findings += CookieCORSCheck.inspect(url, resp)
        findings += cookie_findings
        
        cookie_loader.stop(f"Cookie & CORS check completed - Found {len(cookie_findings)} issues")

        # 4) Active checks (use params from crawler) - WITH LOADING
        params_map = self.crawler.params
        if params_map:
            # SQL Injection checks
            sqli_loader = SimpleLoader("💉 Testing for SQL injection")
            sqli_loader.start()
            
            sqli_findings = SQLiCheck.run(self.http, params_map)
            findings += sqli_findings
            
            sqli_loader.stop(f"SQL injection test completed - Found {len(sqli_findings)} vulnerabilities")
            
            # XSS checks
            xss_loader = SimpleLoader("🎭 Testing for Cross-Site Scripting")
            xss_loader.start()
            
            xss_findings = XSSCheck.run(self.http, params_map)
            findings += xss_findings
            
            xss_loader.stop(f"XSS test completed - Found {len(xss_findings)} vulnerabilities")
        else:
            print("ℹ️  No parameters found for injection testing")
        
        # 5) CSRF and Misconfig checks need URL list - WITH LOADING
        misc_loader = SimpleLoader("🔧 Checking CSRF & misconfigurations")
        misc_loader.start()
        
        csrf_findings = CSRFCheck.run(self.http, crawled_urls)
        misconfig_findings = MisconfigCheck.run(self.http, crawled_urls)
        findings += csrf_findings
        findings += misconfig_findings
        
        total_misc = len(csrf_findings) + len(misconfig_findings)
        misc_loader.stop(f"CSRF & misconfiguration check completed - Found {total_misc} issues")

        return findings
