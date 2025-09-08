import time, urllib.parse as up, requests
ERROR_SIGNS = ["SQL syntax","SQLSTATE[","Unclosed quotation mark","near '","unterminated","pg_query","PDOException","ORA-"]

def _with_param(url, key, val):
    pr = up.urlparse(url); qs = dict(up.parse_qsl(pr.query)); qs[key] = val
    return up.urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, up.urlencode(qs, doseq=True), pr.fragment))

class SQLiCheck:
    @staticmethod
    def run(http, params_map):
        findings = []
        for url, params in params_map.items():
            for p in params:
                # -------- Error-based (GET) --------
                try:
                    r = http.get(_with_param(url, p, "1'"))
                    body = r.text or ""
                    if any(sig.lower() in body.lower() for sig in ERROR_SIGNS):
                        findings.append({
                            "type":"sqli:error-based-get","url":url,"param":p,
                            "payload":"1'","evidence":"Pesan error SQL terdeteksi.","severity_score":6
                        })
                except requests.RequestException:
                    pass

                # -------- Time-based (GET) --------
                try:
                    t0=time.time(); http.get(_with_param(url,p,"1")); base=time.time()-t0
                    t1=time.time(); http.get(_with_param(url,p,"1 AND SLEEP(3)")); slow=time.time()-t1
                    if slow-base>2.5:
                        t2=time.time(); http.get(_with_param(url,p,"1 AND SLEEP(3)")); slow2=time.time()-t2
                        if slow2-base>2.5:
                            findings.append({
                                "type":"sqli:time-based","url":url,"param":p,
                                "payload":"1 AND SLEEP(3)","evidence":f"Latency naik signifikan (~{round(slow,2)}s).","severity_score":7
                            })
                except requests.RequestException:
                    pass

                # -------- Error-based (POST sederhana ke URL yg sama) --------
                try:
                    post_data = {p: "1'"}
                    r = http.post(url, data=post_data)
                    body = r.text or ""
                    if any(sig.lower() in body.lower() for sig in ERROR_SIGNS):
                        findings.append({
                            "type":"sqli:error-based-post","url":url,"param":p,
                            "payload":"1'","evidence":"POST SQLi detected","severity_score":6
                        })
                except (requests.RequestException, AttributeError):
                    pass
        return findings


# =========================
# Tambahan: SQLi via POST forms (baru)
# =========================

def _looks_like_csrf(name: str) -> bool:
    n = name.lower()
    return ("csrf" in n) or ("xsrf" in n) or ("authenticity_token" in n)

def run_forms(http, forms):
    """
    Uji SQLi di FORM POST:
    - Hidden/CSRF token dipertahankan agar submit tidak gagal.
    - Pilih satu field non-hidden sebagai target injeksi.
    - Lakukan error-based & time-based test.
    """
    findings = []
    for f in forms:
        if f.get("method") != "POST":
            continue

        # Siapkan payload baseline: hidden/CSRF -> value asli, non-hidden -> "1"
        base = {}
        non_hidden = []
        for inp in f.get("inputs", []):
            name = inp["name"]
            if inp["hidden"] or _looks_like_csrf(name):
                base[name] = inp["value"]
            else:
                base[name] = "1"
                non_hidden.append(name)

        if not non_hidden:
            continue
        target = non_hidden[0]  # ambil satu field untuk injeksi sederhana

        # -------- Error-based (POST FORM) --------
        eb = dict(base)
        eb[target] = "1'"
        try:
            r = http.post(f["action"], data=eb)
            body = r.text or ""
            if any(sig.lower() in body.lower() for sig in ERROR_SIGNS):
                findings.append({
                    "type": "sqli:error-based-post-form",
                    "url": f["action"],
                    "param": target,
                    "payload": "1'",
                    "evidence": "Pesan error SQL terdeteksi pada response.",
                    "severity_score": 6
                })
        except requests.RequestException:
            pass

        # -------- Time-based (POST FORM) --------
        try:
            # baseline
            t0 = time.time(); http.post(f["action"], data=base); t_base = time.time() - t0

            tb = dict(base); tb[target] = "1 AND SLEEP(3)"
            t1 = time.time(); http.post(f["action"], data=tb); t_slow = time.time() - t1

            if t_slow - t_base > 2.5:
                # konfirmasi kedua
                t2 = time.time(); http.post(f["action"], data=tb); t_slow2 = time.time() - t2
                if t_slow2 - t_base > 2.5:
                    findings.append({
                        "type": "sqli:time-based-post-form",
                        "url": f["action"],
                        "param": target,
                        "payload": "1 AND SLEEP(3)",
                        "evidence": f"Latency naik signifikan (~{round(t_slow,2)}s).",
                        "severity_score": 7
                    })
        except requests.RequestException:
            pass

        

    return findings

# --- compatibility shim: expose module-level run_forms as a staticmethod on SQLiCheck
try:
    SQLiCheck.run_forms
except AttributeError:
    SQLiCheck.run_forms = staticmethod(run_forms)