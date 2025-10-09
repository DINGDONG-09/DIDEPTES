 
from http.cookies import SimpleCookie

def _sev(ok: bool, missing=False):
    
    if missing:
        return 0
    return 2 if ok else -1

def _parse_set_cookie_all(headers):
    
    values = []
    for k, v in headers.items():
        if k.lower() == 'set-cookie':
            
            parts = v.split(", ")
            
            buf = []
            for p in parts:
                if "=" in p and (";" not in p.split("=", 1)[0]):
                    if buf:
                        values.append(", ".join(buf))
                        buf = []
                buf.append(p)
            if buf:
                values.append(", ".join(buf))
    return values

class CookieCORSCheck:
    @staticmethod
    def inspect(url, resp):
        findings = []
        h = {k.lower(): v for k, v in resp.headers.items()}

       
        
        
        set_cookies = _parse_set_cookie_all(resp.headers) or []
        if not set_cookies:
            findings.append({
                "type": "cookie:flags",
                "url": url,
                "present": False,
                "severity_score": 0,
                "evidence": "No Set-Cookie in response",
                "recommendation": "Pastikan cookie sensitif di-set melalui Set-Cookie dengan HttpOnly, Secure, dan SameSite."
            })
        else:
            for sc in set_cookies:
                c = SimpleCookie()
                try:
                    c.load(sc)
                except Exception:
                    
                    findings.append({
                        "type": "cookie:parse-warning",
                        "url": url,
                        "present": True,
                        "severity_score": -1,
                        "evidence": sc,
                        "recommendation": "Periksa format Set-Cookie; pastikan sesuai RFC."
                    })
                    continue

                
                for name, morsel in c.items():
                    attrs = sc.lower()
                    has_http_only = "httponly" in attrs
                    has_secure = "secure" in attrs
                    
                    ss = None
                    for token in attrs.split(";"):
                        token = token.strip()
                        if token.startswith("samesite="):
                            ss = token.split("=", 1)[1].strip()
                            break

                   
                    ok = has_http_only and has_secure and (ss in ("lax", "strict", "none"))
                    sev = _sev(ok)
                    
                    missing_flags = []
                    if not has_http_only: missing_flags.append("HttpOnly")
                    if not has_secure: missing_flags.append("Secure")
                    if ss is None: missing_flags.append("SameSite")
                    findings.append({
                        "type": "cookie:flags",
                        "url": url,
                        "cookie": name,
                        "present": True,
                        "severity_score": sev if not missing_flags else -1,
                        "evidence": sc,
                        "recommendation": (
                            "Tambahkan flag: " + ", ".join(missing_flags) if missing_flags else
                            "Konfigurasi cookie sudah baik (HttpOnly, Secure, SameSite). Untuk cross-site login modern, gunakan SameSite=Lax/Strict kecuali perlu None+Secure."
                        )
                    })

        
        aco = h.get("access-control-allow-origin")
        acc = h.get("access-control-allow-credentials")
        vary = h.get("vary")

        if aco is None:
            findings.append({
                "type": "cors:policy",
                "url": url,
                "present": False,
                "severity_score": 0,
                "evidence": "No Access-Control-Allow-Origin",
                "recommendation": "Jika API tidak perlu diakses lintas-origin, biarkan CORS nonaktif. Jika perlu, atur origin whitelist spesifik, bukan wildcard."
            })
        else:
            wildcard = aco.strip() == "*"
            cred_true = (acc or "").lower() == "true"
            
            misconfig = wildcard and cred_true
            
            sev = -1 if misconfig else 2
            rec = "Hindari 'Access-Control-Allow-Origin: *' saat 'Access-Control-Allow-Credentials: true'. Gunakan origin yang spesifik." \
                  if misconfig else \
                  "Kebijakan CORS tampak aman untuk use-case umum. Gunakan origin eksplisit bila memungkinkan."
            findings.append({
                "type": "cors:policy",
                "url": url,
                "present": True,
                "severity_score": sev,
                "evidence": f"ACA-Origin={aco}; ACA-Credentials={acc or '-'}; Vary={vary or '-'}",
                "recommendation": rec
            })

        return findings

