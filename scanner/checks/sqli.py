 
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
                # Error-based
                try:
                    r = http.get(_with_param(url, p, "1'"))
                    body = r.text or ""
                    if any(sig.lower() in body.lower() for sig in ERROR_SIGNS):
                        findings.append({"type":"sqli:error-based","url":url,"param":p,"payload":"1'","evidence":"Pesan error SQL terdeteksi.","severity_score":6})
                except requests.RequestException:
                    pass
                # Time-based
                try:
                    t0=time.time(); http.get(_with_param(url,p,"1")); base=time.time()-t0
                    t1=time.time(); http.get(_with_param(url,p,"1 AND SLEEP(3)")); slow=time.time()-t1
                    if slow-base>2.5:
                        t2=time.time(); http.get(_with_param(url,p,"1 AND SLEEP(3)")); slow2=time.time()-t2
                        if slow2-base>2.5:
                            findings.append({"type":"sqli:time-based","url":url,"param":p,"payload":"1 AND SLEEP(3)","evidence":f"Latency naik signifikan (~{round(slow,2)}s).","severity_score":7})
                except requests.RequestException:
                    pass
        return findings
