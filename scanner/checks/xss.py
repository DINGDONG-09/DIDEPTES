import re
import urllib.parse

def xss_payloads(base_payloads=None):
    """
    Generate XSS payloads:
    - classic reflected payloads
    - encoded variants
    - event-handler payloads
    - script-based
    """
    if base_payloads is None:
        base_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]

    out = list(base_payloads)

    
    encoded = [
        urllib.parse.quote(p) for p in base_payloads
    ]
    out.extend(encoded)

    
    event_payloads = [
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]
    out.extend(event_payloads)

    
    seen = set()
    res = []
    for p in out:
        if p not in seen:
            seen.add(p)
            res.append(p)
    return res


class XSSCheck:
    """Cross-Site Scripting (XSS) vulnerability checker."""

    XSS_PAYLOADS = xss_payloads()

    REFLECTION_PATTERNS = [
        re.compile(r"<script>alert\(1\)</script>", re.I),
        re.compile(r"onerror=alert\(1\)", re.I),
        re.compile(r"onload=alert\(1\)", re.I),
        re.compile(r"alert\(1\)", re.I),
    ]

    @classmethod
    def run(cls, http, params_map):
        """Test GET parameters for reflected XSS vulnerabilities."""
        findings = []

        for url, param_names in params_map.items():
            for param in param_names:
                findings.extend(cls._test_parameter(http, url, param))

        return findings

    @classmethod
    def run_forms(cls, http, forms, crawl_pages=None):
        """
        Test POST forms for XSS vulnerabilities.
        - crawl_pages: optional list of (url, resp) pairs to detect stored XSS
        """
        findings = []

        for form in forms:
            if form["method"].upper() == "POST":
                findings.extend(cls._test_form(http, form, crawl_pages))

        return findings

    @classmethod
    def _test_parameter(cls, http, url, param_name):
        """Test GET parameter for reflected XSS."""
        findings = []

        for payload in cls.XSS_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)

                query_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)

                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                response = http.get(test_url)

                if cls._is_vulnerable_reflected(response, payload):
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": cls._extract_evidence(response.text, payload),
                        "description": f"Reflected XSS vulnerability found in parameter '{param_name}'. "
                                     f"The application reflects user input without proper sanitization.",
                        "recommendation": "Sanitize user input, use proper output encoding (HTML entity encoding), "
                                       "and consider Content Security Policy (CSP)."
                    })
                    break

            except Exception:
                continue

        return findings

    @classmethod
    def _test_form(cls, http, form, crawl_pages=None):
        """Test POST form for XSS (reflected or stored)."""
        findings = []

        for input_field in form["inputs"]:
            if input_field["hidden"]:
                continue

            param_name = input_field["name"]

            for payload in cls.XSS_PAYLOADS:
                try:
                    data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param_name:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]

                    response = http.post(form["action"], data=data)

                    
                    if cls._is_vulnerable_reflected(response, payload):
                        findings.append({
                            "type": "XSS (Reflected - POST)",
                            "severity": "HIGH",
                            "url": form["action"],
                            "form_page": form["page"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": cls._extract_evidence(response.text, payload),
                            "description": f"Reflected XSS vulnerability in form parameter '{param_name}'.",
                            "recommendation": "Sanitize user input, escape output, enforce CSP."
                        })
                        break

                   
                    if crawl_pages:
                        for crawl_url, crawl_resp in crawl_pages:
                            if cls._is_vulnerable_reflected(crawl_resp, payload):
                                findings.append({
                                    "type": "XSS (Stored)",
                                    "severity": "CRITICAL",
                                    "url": crawl_url,
                                    "form_page": form["page"],
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": cls._extract_evidence(crawl_resp.text, payload),
                                    "description": f"Stored XSS vulnerability detected via parameter '{param_name}'. "
                                                 f"Payload persisted into {crawl_url}.",
                                    "recommendation": "Sanitize stored data before rendering, use encoding and CSP."
                                })
                                break

                except Exception:
                    continue

        return findings

    @classmethod
    def _is_vulnerable_reflected(cls, response, payload):
        """Check if response reflects the payload unsanitized."""
        if not response or not response.text:
            return False

        if payload in response.text:
            return True

        for pattern in cls.REFLECTION_PATTERNS:
            if pattern.search(response.text):
                return True

        return False

    @classmethod
    def _extract_evidence(cls, response_text, payload):
        """Extract relevant evidence from response."""
        if not response_text:
            return "No response text"

        idx = response_text.find(payload)
        if idx != -1:
            start = max(0, idx - 50)
            end = min(len(response_text), idx + len(payload) + 50)
            return response_text[start:end]

        for pattern in cls.REFLECTION_PATTERNS:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end]

        return "Potential XSS reflection detected"
