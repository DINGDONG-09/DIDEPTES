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


# =========================
# Tambahan: XSS via POST forms
# =========================

def _looks_like_csrf(name: str) -> bool:
    n = name.lower()
    return ("csrf" in n) or ("xsrf" in n) or ("authenticity_token" in n)

def run_forms(http, forms):
    """
    Uji Reflected XSS lewat FORM POST.
    - Hidden / token (mis. CSRF) dipertahankan nilainya agar validasi form tidak gagal.
    - Semua field non-hidden diisi payload bertoken untuk mendeteksi pantulan berbahaya.
    """
    findings = []
    for f in forms:
        if f.get("method") != "POST":
            continue

        # Baseline data: hidden/CSRF pakai value asli, non-hidden placeholder
        base_data = {}
        for inp in f.get("inputs", []):
            name = inp["name"]
            if inp["hidden"] or _looks_like_csrf(name):
                base_data[name] = inp["value"]
            else:
                base_data[name] = "test"

        # Payload bertoken
        tok = _token()
        payloads = [p.replace("1", tok) for p in PAYLOADS]

        for payload in payloads:
            data = dict(base_data)
            # Isi semua non-hidden dengan payload bertoken
            for inp in f["inputs"]:
                name = inp["name"]
                if not (inp["hidden"] or _looks_like_csrf(name)):
                    data[name] = payload

            try:
                r = http.post(f["action"], data=data)
                body = r.text or ""
                # Token harus muncul di konteks executable (script/handler)
                if tok in body and re.search(
                    rf"(<script[^>]*>[^<]*{tok}[^<]*</script>|on\w+\s*=\s*[^>]*{tok})",
                    body, re.I
                ):
                    findings.append({
                        "type": "xss:reflected",
                        "url": f["action"],
                        "param": ",".join([i["name"] for i in f["inputs"] if not i["hidden"]]),
                        "payload": "POST form payload (tokenized)",
                        "evidence": f"Token {tok} muncul dalam konteks executable pada response.",
                        "severity_score": 5
                    })
                    break  # satu temuan per form cukup
            except Exception:
                continue

    return findings
try:
    XSSCheck.run_forms
except AttributeError:
    XSSCheck.run_forms = staticmethod(run_forms)