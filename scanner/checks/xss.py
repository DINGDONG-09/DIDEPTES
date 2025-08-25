import urllib.parse as up
import re
import random
import string

def _token():
    return "XSS" + "".join(random.choices(string.ascii_letters + string.digits, k=10))

PAYLOADS = [
    '\"><svg onload=alert(1)>',
    '\"><img src=x onerror=alert(1)>',
    '\"><script>alert(1)</script>',
]

def _update_query(url, extra):
    pr = up.urlparse(url)
    qs = dict(up.parse_qsl(pr.query))
    qs.update(extra)
    return up.urlunparse((
        pr.scheme, pr.netloc, pr.path, pr.params,
        up.urlencode(qs, doseq=True), pr.fragment
    ))

class XSSCheck:
    @staticmethod
    def run(http, params_map):
        findings = []
        for url, params in params_map.items():
            for p in params:
                tok = _token()
                for base in PAYLOADS:
                    payload = base.replace("1", tok)
                    try:
                        r = http.get(_update_query(url, {p: payload}))
                        body = r.text or ""
                        if tok in body and re.search(
                            rf"(<script[^>]*>[^<]*{tok}[^<]*</script>|on\w+\s*=\s*[^>]*{tok})",
                            body, re.I
                        ):
                            findings.append({
                                "type": "xss:reflected",
                                "url": url,
                                "param": p,
                                "payload": payload,
                                "evidence": f"Token {tok} muncul di konteks executable.",
                                "severity_score": 5
                            })
                            break
                    except Exception:
                        continue
        return findings
