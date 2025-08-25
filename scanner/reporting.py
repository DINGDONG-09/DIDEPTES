 # Menulis hasil scan ke JSON/HTML sederhana.

import json, html
from datetime import datetime

class Reporter:
    @staticmethod
    def to_json(findings, path):
        data = {"generated_at": datetime.utcnow().isoformat() + "Z", "findings": findings}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def to_html(findings, path):
        rows = []
        for f in findings:
            rows.append(
                "<tr>"
                f"<td>{html.escape(f.get('type',''))}</td>"
                f"<td>{html.escape(f.get('url',''))}</td>"
                f"<td>{html.escape(str(f.get('severity_score',0)))}</td>"
                f"<td>{html.escape(f.get('evidence',''))}</td>"
                "</tr>"
            )
        doc = f"""<html><head><meta charset="utf-8"><title>Mini-OWASP Report</title></head>
<body>
<h1>Mini-OWASP Report</h1>
<p>Generated at: {html.escape(datetime.utcnow().isoformat()+'Z')}</p>
<table border="1" cellspacing="0" cellpadding="6">
<tr><th>Type</th><th>URL</th><th>Severity</th><th>Evidence</th></tr>
{''.join(rows)}
</table>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)

