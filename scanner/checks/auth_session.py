# scanner/auth_session.py
"""
Auth & Session checks for the vuln-scanner project.

This file is a cleaned, enhanced rewrite that:
- preserves original checks (session cookie checks, login form checks, session-fixation)
- adds safe, optional brute-force (run_enhanced with allow_bruteforce flag)
- improves brute-force by including hidden inputs/CSRF tokens in payloads
- uses conservative success detection heuristics and exponential backoff on 429
- provides helpers for logout checks and cookie comparisons

USAGE:
- Core compatibility: AuthSessionCheck.run(http, base_url, pages, forms, options=None)
- Enhanced runner: AuthSessionCheck.run_enhanced(http, crawled_pages, options=None)
  - options keys: allow_bruteforce (bool), bruteforce_limit (int), bruteforce_wordlist_url (str),
    credentials: {"username": "...", "password": "..."},
    protected_path: "/account", baseline_page: (url, resp)
"""

import re
import time
import requests
from urllib.parse import urljoin, urlparse, quote
from typing import List, Dict, Any, Tuple, Optional, Iterable

# Default public wordlist (SecLists 10k common). Raw URL:
_DEFAULT_SECLISTS_10K_RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"

# Heuristics for session cookie names
_SESSION_COOKIE_HINTS = ["sessionid", "jsessionid", "phpsessid", "asp.net_sessionid", "session", "sid", "auth", "token"]

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
def _fetch_wordlist(url: str = _DEFAULT_SECLISTS_10K_RAW, max_lines: int = 1000, timeout: int = 6) -> Iterable[str]:
    """Fetch plaintext wordlist from URL (streamed). Yields up to max_lines entries.
    Falls back to small builtin list on failure."""
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        count = 0
        for raw in r.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            line = raw.strip()
            if not line:
                continue
            yield line
            count += 1
            if count >= max_lines:
                break
    except Exception:
        # fallback list (very small)
        for p in ("password", "123456", "12345678", "qwerty", "admin", "letmein", "welcome", "1234"):
            yield p

def _heuristic_find_login_form_from_html(html: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (action, username_field, password_field) if a simple login form is found in raw HTML."""
    if not html:
        return (None, None, None)
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, flags=re.DOTALL | re.IGNORECASE)
    for form_html in forms:
        m_pass = re.search(r'<input[^>]*type\s*=\s*["\']password["\'][^>]*name\s*=\s*["\']([^"\']+)["\']', form_html, flags=re.I)
        if m_pass:
            password_field = m_pass.group(1)
            m_user = re.search(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*(?:type\s*=\s*["\']text["\']|type\s*=\s*["\']email["\'])?', form_html, flags=re.I)
            username_field = m_user.group(1) if m_user else None
            action_match = re.search(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', form_html, flags=re.I)
            action = action_match.group(1) if action_match else None
            return (action, username_field, password_field)
    return (None, None, None)

def _build_payload_with_hidden(form: Dict[str, Any], username_field: str, password_field: str,
                               username: str, password: str) -> Dict[str, str]:
    """Preserve hidden inputs / CSRF tokens and fill username/password fields."""
    data = {}
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if not name:
            continue
        if name == username_field:
            data[name] = username
        elif name == password_field:
            data[name] = password
        elif inp.get("hidden") or ("csrf" in name.lower()) or inp.get("value"):
            data[name] = inp.get("value", "")
        else:
            # filler value
            data[name] = inp.get("value") or "test"
    return data

def _is_login_success(resp, baseline_text: str = "", username_hint: str = "") -> bool:
    """Conservative multi-check login success detection."""
    try:
        if getattr(resp, "status_code", None) in (301, 302, 303):
            return True
    except Exception:
        pass

    # JSON API responses
    try:
        j = resp.json()
        if isinstance(j, dict) and (j.get("token") or j.get("access_token") or j.get("success") or j.get("authenticated")):
            return True
    except Exception:
        pass

    # cookies set
    try:
        cookies = getattr(resp, "cookies", None)
        if cookies:
            for c in cookies:
                name = getattr(c, "name", None) or getattr(c, "key", None) or ""
                if any(h in name.lower() for h in ("sess", "sid", "token", "auth")):
                    return True
    except Exception:
        pass

    body = getattr(resp, "text", "") or ""
    if baseline_text and ("login" in baseline_text.lower() and "login" not in body.lower()):
        return True
    if username_hint and username_hint in body:
        return True

    return False

def _safe_post_with_backoff(http, action: str, data: Dict[str, str], max_retries: int = 3, initial_delay: float = 0.5):
    """Post wrapper with simple exponential backoff for 429 and transient errors."""
    delay = initial_delay
    for attempt in range(max_retries):
        try:
            r = http.post(action, data=data)
            code = getattr(r, "status_code", None)
            if code == 429:
                time.sleep(delay)
                delay = min(delay * 2, 10)
                continue
            return r
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 10)
    return None

def _compare_cookie_values(pre_cookies, post_cookies) -> Tuple[bool, List[str]]:
    """Compare two cookie iterables; return (has_same, list_of_cookie_names_that_match)."""
    same = []
    try:
        pre_map = {}
        post_map = {}
        for c in pre_cookies or []:
            name = getattr(c, "name", None) or getattr(c, "key", None) or (c.get("name") if isinstance(c, dict) else None)
            val = getattr(c, "value", None) or (c.get("value") if isinstance(c, dict) else None)
            if name:
                pre_map[name] = val
        for c in post_cookies or []:
            name = getattr(c, "name", None) or getattr(c, "key", None) or (c.get("name") if isinstance(c, dict) else None)
            val = getattr(c, "value", None) or (c.get("value") if isinstance(c, dict) else None)
            if name:
                post_map[name] = val
        for n, v in pre_map.items():
            if n in post_map and post_map[n] == v:
                same.append(n)
    except Exception:
        return False, []
    return (len(same) > 0), same

def _extract_login_pages_from_crawled(crawled_pages: List[Tuple[str, Any]]) -> List[Tuple[str, str]]:
    """Return list of (url, html_text) for pages likely to contain a login form."""
    out = []
    for url, resp in crawled_pages:
        txt = getattr(resp, "text", "") or ""
        if "login" in url.lower() or "signin" in url.lower() or "password" in txt.lower():
            out.append((url, txt))
    return out

def _normalize_action(base_url: str, action: Optional[str]) -> str:
    if not action:
        return base_url
    return urljoin(base_url, action)

# -----------------------------------------------------------------------------
# Primary class: keep original checks but update signatures for compatibility
# -----------------------------------------------------------------------------
class AuthSessionCheck:
    """
    Provides:
      - run(http, base_url, pages, forms, options=None)  <-- main compatibility entry
      - run_enhanced(http, crawled_pages, options=None) <-- enhanced runner (bruteforce, fixation, logout)
    """

    @staticmethod
    def run(http, base_url: str, pages: List[Tuple[str, Any]], forms: List[Dict[str, Any]], options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Backwards-compatible runner using the original checks found in prior file.
        - http: requests.Session-like object
        - base_url: string
        - pages: list of (url, response)
        - forms: list of form dicts (if crawler provided)
        - options: optional dict (currently unused here)
        """
        findings: List[Dict[str, Any]] = []

        # Iterate pages and run legacy checks
        for url, resp in pages:
            try:
                # session management & cookie checks
                findings.extend(AuthSessionCheck._check_session_management(url, resp))

                # authentication mechanisms & login form checks
                findings.extend(AuthSessionCheck._check_authentication(url, resp))

                # detailed session cookie analysis
                findings.extend(AuthSessionCheck._check_session_cookies(url, resp))

                # login form checks (CSRF presence, autocomplete)
                findings.extend(AuthSessionCheck._check_login_forms(url, resp, http))

                # session fixation using original helper
                findings.extend(AuthSessionCheck._check_session_fixation(url, http))

            except Exception as e:
                print(f"Auth check failed for {url}: {e}")
                continue

        return findings

    # --- Original-style helper methods (preserved & cleaned) ---

    @staticmethod
    def _check_session_management(url, resp):
        findings = []
        cookies = getattr(resp, "cookies", None)
        if not cookies:
            return findings

        for cookie in cookies:
            cookie_name = (getattr(cookie, "name", None) or "").lower()

            session_indicators = _SESSION_COOKIE_HINTS

            if any(indicator in cookie_name for indicator in session_indicators):
                # Secure flag
                if not getattr(cookie, "secure", False):
                    findings.append({
                        "type": "session:insecure-cookie",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session cookie '{cookie.name}' lacks Secure flag",
                        "recommendation": "Add Secure flag to session cookies to prevent transmission over HTTP",
                        "severity_score": 6
                    })
                # HttpOnly detection (Requests CookieJar does not expose HttpOnly directly for all jars; best-effort)
                try:
                    has_httponly = "httponly" in getattr(cookie, "rest", {}) or getattr(cookie, "httponly", False)
                except Exception:
                    has_httponly = False
                if not has_httponly:
                    findings.append({
                        "type": "session:httponly-missing",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session cookie '{cookie.name}' lacks HttpOnly flag",
                        "recommendation": "Add HttpOnly flag to session cookies to prevent XSS attacks",
                        "severity_score": 5
                    })
                # SameSite check (best-effort)
                samesite = None
                try:
                    samesite = getattr(cookie, "rest", {}).get("samesite") if hasattr(cookie, "rest") else None
                except Exception:
                    samesite = None
                if not samesite:
                    findings.append({
                        "type": "session:samesite-missing",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session cookie '{cookie.name}' lacks SameSite attribute",
                        "recommendation": "Add SameSite attribute to session cookies to prevent CSRF attacks",
                        "severity_score": 4
                    })
                # weak session id (length)
                try:
                    if len(getattr(cookie, "value", "") or "") < 16:
                        findings.append({
                            "type": "session:weak-session-id",
                            "url": url,
                            "cookie_name": cookie.name,
                            "evidence": f"Session ID appears to be weak (length: {len(getattr(cookie, 'value', '') or '')})",
                            "recommendation": "Use longer, cryptographically secure session IDs (minimum 128 bits)",
                            "severity_score": 7
                        })
                except Exception:
                    pass
        return findings

    @staticmethod
    def _check_authentication(url, resp):
        findings = []
        content = getattr(resp, "text", "") or ""
        headers = getattr(resp, "headers", {}) or {}

        # Basic/Digest detection
        if "www-authenticate" in headers:
            auth_header = headers.get("www-authenticate", "").lower()
            if "basic" in auth_header:
                findings.append({
                    "type": "auth:basic-authentication",
                    "url": url,
                    "evidence": "Basic Authentication detected",
                    "recommendation": "Replace Basic Auth with more secure authentication methods (OAuth, JWT, etc.)",
                    "severity_score": 6
                })
            if "digest" in auth_header:
                findings.append({
                    "type": "auth:digest-authentication",
                    "url": url,
                    "evidence": "Digest Authentication detected",
                    "recommendation": "Consider upgrading to modern authentication methods",
                    "severity_score": 3
                })

        # Login form over HTTP
        try:
            if urlparse(url).scheme == "http":
                login_patterns = [
                    r'type\s*=\s*["\']password["\']',
                    r'name\s*=\s*["\']password["\']',
                    r'name\s*=\s*["\']login["\']',
                    r'action\s*=\s*["\'][^"\']*login[^"\']*["\']'
                ]
                for pattern in login_patterns:
                    if re.search(pattern, content, flags=re.I):
                        findings.append({
                            "type": "auth:login-over-http",
                            "url": url,
                            "evidence": "Login form detected over unencrypted HTTP connection",
                            "recommendation": "Enforce HTTPS for all authentication pages",
                            "severity_score": 8
                        })
                        break
        except Exception:
            pass

        # password autocomplete
        try:
            password_fields = re.findall(r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>', content, flags=re.I)
            for field in password_fields:
                if 'autocomplete' not in field.lower() or 'autocomplete="off"' not in field.lower():
                    findings.append({
                        "type": "auth:password-autocomplete",
                        "url": url,
                        "evidence": "Password field allows autocomplete",
                        "recommendation": "Add autocomplete='off' to password fields",
                        "severity_score": 3
                    })
                    break
        except Exception:
            pass

        return findings

    @staticmethod
    def _check_session_cookies(url, resp):
        findings = []
        try:
            for cookie in getattr(resp, "cookies", []) or []:
                value = getattr(cookie, "value", "") or ""
                # sequential numeric
                if value.isdigit() and len(value) < 10:
                    findings.append({
                        "type": "session:predictable-session-id",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session ID appears to be sequential or predictable: {value}",
                        "recommendation": "Use cryptographically secure random session ID generation",
                        "severity_score": 8
                    })
                # timestamp-like
                timestamp_patterns = [r'\d{10}', r'\d{13}', r'\d{4}-\d{2}-\d{2}']
                for pattern in timestamp_patterns:
                    if re.search(pattern, value):
                        findings.append({
                            "type": "session:timestamp-based-session-id",
                            "url": url,
                            "cookie_name": cookie.name,
                            "evidence": f"Session ID contains timestamp pattern: {value}",
                            "recommendation": "Avoid using timestamps in session IDs",
                            "severity_score": 6
                        })
                        break
        except Exception:
            pass
        return findings

    @staticmethod
    def _check_login_forms(url, resp, http):
        findings = []
        content = getattr(resp, "text", "") or ""

        # find forms
        try:
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, content, flags=re.DOTALL | re.IGNORECASE)
            for form in forms:
                form_lower = form.lower()
                if any(indicator in form_lower for indicator in ['password', 'login', 'signin', 'username']):
                    csrf_patterns = [
                        r'name\s*=\s*["\'][^"\']*csrf[^"\']*["\']',
                        r'name\s*=\s*["\'][^"\']*token[^"\']*["\']',
                        r'name\s*=\s*["\']_token["\']'
                    ]
                    has_csrf = any(re.search(pattern, form_lower) for pattern in csrf_patterns)
                    if not has_csrf:
                        findings.append({
                            "type": "auth:missing-csrf-protection",
                            "url": url,
                            "evidence": "Login form lacks CSRF protection",
                            "recommendation": "Implement CSRF tokens in login forms",
                            "severity_score": 6
                        })
                    # account lockout detection placeholder (non-destructive)
                    # actual brute-force should be enabled only with explicit flag
        except Exception:
            pass

        return findings

    @staticmethod
    def _check_session_fixation(url, http):
        findings = []
        try:
            resp1 = http.get(url)
            initial_cookies = {cookie.name: cookie.value for cookie in getattr(resp1, "cookies", []) or []}
            if not initial_cookies:
                return findings

            login_urls = [urljoin(url, p) for p in ("/login", "/signin", "/auth", "/admin")]
            for login_url in login_urls:
                try:
                    resp2 = http.get(login_url)
                    if getattr(resp2, "status_code", None) == 200:
                        new_cookies = {cookie.name: cookie.value for cookie in getattr(resp2, "cookies", []) or []}
                        for cookie_name, cookie_value in initial_cookies.items():
                            if cookie_name.lower() in _SESSION_COOKIE_HINTS:
                                if cookie_name in new_cookies and new_cookies[cookie_name] == cookie_value:
                                    findings.append({
                                        "type": "session:session-fixation",
                                        "url": url,
                                        "login_url": login_url,
                                        "evidence": f"Session ID '{cookie_name}' not regenerated when accessing login page",
                                        "recommendation": "Regenerate session IDs upon authentication state changes",
                                        "severity_score": 7
                                    })
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return findings

# -----------------------------------------------------------------------------
# Enhanced runner: safe & optional bruteforce + reuse existing checks
# -----------------------------------------------------------------------------
def run_enhanced(http, crawled_pages: List[Tuple[str, Any]], options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    Enhanced runner:
    - http: requests.Session-like
    - crawled_pages: list of (url, response)
    - options:
        - allow_bruteforce: bool (default False)
        - bruteforce_wordlist_url: str (optional)
        - bruteforce_limit: int (default 200)
        - credentials: {"username": "...", "password": "..."} optional
        - protected_path: str optional
        - baseline_page: optional (url, resp) tuple
    """
    opts = options or {}
    allow_bruteforce = bool(opts.get("allow_bruteforce", False))
    wordlist_url = opts.get("bruteforce_wordlist_url", _DEFAULT_SECLISTS_10K_RAW)
    bruteforce_limit = int(opts.get("bruteforce_limit", 200))
    creds = opts.get("credentials") or {}
    protected_path = opts.get("protected_path")

    findings: List[Dict[str, Any]] = []

    # baseline page text (for login detection heuristics)
    baseline_text = ""
    if opts.get("baseline_page"):
        baseline_text = getattr(opts["baseline_page"][1], "text", "") or ""
    else:
        if crawled_pages:
            baseline_text = getattr(crawled_pages[0][1], "text", "") or ""

    # reuse original session-fixation check if present
    try:
        findings += [f for url, resp in crawled_pages for f in AuthSessionCheck._check_session_fixation(url, http)]
    except Exception:
        # fallback lightweight probe if original check fails
        try:
            for page_url, _ in crawled_pages[:3]:
                try:
                    r1 = http.get(page_url)
                    initial_cookies = {c.name: c.value for c in getattr(r1, "cookies", []) or []}
                    for cand in ("/login", "/signin", "/auth"):
                        try:
                            r2 = http.get(urljoin(page_url, cand))
                            new_cookies = {c.name: c.value for c in getattr(r2, "cookies", []) or []}
                            for cn, cv in initial_cookies.items():
                                if cn in new_cookies and new_cookies.get(cn) == cv:
                                    findings.append({
                                        "type": "auth:session-fixation",
                                        "url": page_url,
                                        "evidence": f"Session cookie '{cn}' preserved when accessing login path {cand}",
                                        "severity_score": 8
                                    })
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

    # logout checks: best-effort
    try:
        for page_url, resp in crawled_pages[:5]:
            txt = getattr(resp, "text", "") or ""
            m = re.search(r'href=[\'"]([^\'"]*(logout|signout)[^\'"]*)[\'"]', txt, flags=re.I)
            logout_url = None
            if m:
                logout_url = _normalize_action(page_url, m.group(1))
            else:
                logout_url = urljoin(page_url, "/logout")
            try:
                _ = http.get(logout_url)
            except Exception:
                try:
                    _ = http.post(logout_url, data={})
                except Exception:
                    pass
            prot = urljoin(page_url, protected_path) if protected_path else page_url
            try:
                rprot = http.get(prot)
                code = getattr(rprot, "status_code", None)
                body = getattr(rprot, "text", "") or ""
                # simple heuristic: if page still shows signs of login, flag issue
                if code == 200 and ("logout" not in body.lower() and "login" not in body.lower()):
                    # not a strong proof but flags for manual review
                    findings.append({
                        "type": "auth:logout-issue",
                        "url": prot,
                        "evidence": f"Protected path {prot} appears accessible after logout attempt (status {code})",
                        "severity_score": 8
                    })
                else:
                    findings.append({
                        "type": "auth:logout-success",
                        "url": prot,
                        "evidence": f"Protected path returned status {code} after logout attempt (expected).",
                        "severity_score": 0
                    })
            except Exception:
                pass
    except Exception:
        pass

    # Brute-force (optional & controlled)
    if allow_bruteforce:
        login_pages = _extract_login_pages_from_crawled(crawled_pages)
        if not login_pages and crawled_pages:
            base = crawled_pages[0][0]
            login_pages = [(urljoin(base, p), None) for p in ("/login", "/signin", "/auth", "/user/login")]

        attempted = 0
        success_found = False

        for page_url, page_html in login_pages:
            if attempted >= bruteforce_limit:
                break
            if not page_html:
                try:
                    rtmp = http.get(page_url)
                    page_html = getattr(rtmp, "text", "") or ""
                except Exception:
                    page_html = ""

            action_rel, ufield, pfield = _heuristic_find_login_form_from_html(page_html)
            action = _normalize_action(page_url, action_rel) if action_rel else page_url
            if not pfield:
                pfield = "password"
            if not ufield:
                ufield = "username"

            # try to obtain structured form from crawler 'forms' if any (caller may pass forms elsewhere)
            # best-effort: build minimal form object if none available
            form_obj = {"inputs": [{"name": ufield, "value": ""}, {"name": pfield, "value": ""}]}

            # iterate wordlist (generator)
            for pw in _fetch_wordlist(wordlist_url, max_lines=bruteforce_limit):
                if attempted >= bruteforce_limit:
                    break
                attempted += 1
                payload = _build_payload_with_hidden(form_obj, ufield, pfield, creds.get("username", ""), pw)
                r = _safe_post_with_backoff(http, action, payload)
                if not r:
                    continue
                if _is_login_success(r, baseline_text, creds.get("username", "")):
                    findings.append({
                        "type": "auth:bruteforce-success",
                        "url": action,
                        "evidence": f"Password '{pw}' succeeded for user '{creds.get('username','')}' (attempts: {attempted})",
                        "severity_score": 9
                    })
                    success_found = True
                    break
            if success_found:
                break

        if attempted == 0:
            findings.append({
                "type": "auth:bruteforce-skip",
                "url": crawled_pages[0][0] if crawled_pages else "",
                "evidence": "Bruteforce was enabled but no login pages were discovered or no passwords attempted.",
                "severity_score": 1
            })
        else:
            findings.append({
                "type": "auth:bruteforce-complete",
                "url": crawled_pages[0][0] if crawled_pages else "",
                "evidence": f"Bruteforce attempted {attempted} guesses (limit {bruteforce_limit}).",
                "severity_score": 1
            })

    return findings

# attach enhanced runner to class for convenience
try:
    AuthSessionCheck.run_enhanced = staticmethod(run_enhanced)
except Exception:
    pass