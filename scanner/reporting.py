

import json, html, os
from datetime import datetime

class Reporter:
    @staticmethod
    def to_json(findings, path):
        
        formatted_time = Reporter._format_timestamp()
        data = {"generated_at": formatted_time, "findings": findings}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def to_html(findings, path):
        
        css_content = Reporter._load_css()
        
        
        grouped_findings = Reporter._group_by_severity(findings)
        
        
        sections_html = Reporter._generate_sections(grouped_findings)
        
        
        formatted_time = Reporter._format_timestamp()
        
        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Mini-OWASP Report</title>
    <style>
        {css_content}
    </style>
</head>
<body>
    <div class="header-section">
        <h1>🛡️ Mini-OWASP Report</h1>
        <p>🚀 SCAN COMPLETED • {html.escape(formatted_time)} • {len(findings)} THREATS DETECTED</p>
        {Reporter._generate_summary_stats(grouped_findings)}
    </div>
    
    {sections_html}
</body>
</html>"""
    
        with open(path, "w", encoding="utf-8") as f:
            f.write(doc)

    @staticmethod
    def _group_by_severity(findings):
        """Group findings by severity level"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for finding in findings:
            score = finding.get('severity_score', 0)
            if score >= 9:
                grouped['critical'].append(finding)
            elif score >= 7:
                grouped['high'].append(finding)
            elif score >= 4:
                grouped['medium'].append(finding)
            elif score >= 1:
                grouped['low'].append(finding)
            else:
                grouped['info'].append(finding)
        
        return grouped
    
    @staticmethod
    def _generate_summary_stats(grouped_findings):
        """Generate summary statistics cards"""
        total = sum(len(findings) for findings in grouped_findings.values())
        
        if total == 0:
            return '<div class="summary-stats"><div class="stat-card secure">🔒 SYSTEM SECURE - NO THREATS DETECTED 🔒</div></div>'
        
        stats_html = '<div class="summary-stats">'
        
        severity_info = {
            'critical': {'icon': '🚨', 'label': 'CRITICAL'},
            'high': {'icon': '⚠️', 'label': 'HIGH'},
            'medium': {'icon': '🔶', 'label': 'MEDIUM'},
            'low': {'icon': '🔵', 'label': 'LOW'},
            'info': {'icon': 'ℹ️', 'label': 'INFO'}
        }
        
        for severity, info in severity_info.items():
            count = len(grouped_findings[severity])
            stats_html += f'''
            <div class="stat-card {severity}">
                <div class="stat-icon">{info['icon']}</div>
                <div class="stat-number">{count}</div>
                <div class="stat-label">{info['label']}</div>
            </div>
            '''
        
        stats_html += f'''
        <div class="stat-card total">
            <div class="stat-icon">📊</div>
            <div class="stat-number">{total}</div>
            <div class="stat-label">TOTAL</div>
        </div>
        </div>'''
        
        return stats_html
    
    @staticmethod
    def _generate_sections(grouped_findings):
        """Generate HTML sections for each severity level"""
        sections_html = ""
        
        severity_config = {
            'critical': {'title': '🚨 CRITICAL THREATS', 'color': '#ff0040'},
            'high': {'title': '⚠️ HIGH PRIORITY THREATS', 'color': '#ff6600'},
            'medium': {'title': '🔶 MEDIUM PRIORITY THREATS', 'color': '#ffcc00'},
            'low': {'title': '🔵 LOW PRIORITY THREATS', 'color': '#00ff88'},
            'info': {'title': 'ℹ️ INFORMATIONAL', 'color': '#00bfff'}
        }
        
        for severity, config in severity_config.items():
            findings = grouped_findings[severity]
            if not findings:
                continue
            
            sections_html += f'''
            <div class="severity-section {severity}-section">
                <div class="section-header">
                    <h2 class="section-title">{config['title']}</h2>
                    <div class="section-count">{len(findings)} Issues</div>
                </div>
                <table class="threats-table">
                    <thead>
                        <tr>
                            <th>🔍 Threat Type</th>
                            <th>🌐 Target URL</th>
                            <th>⚠️ Severity</th>
                            <th>📋 Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {Reporter._generate_table_rows(findings, severity)}
                    </tbody>
                </table>
            </div>
            '''
        
        if not any(grouped_findings.values()):
            sections_html = '''
            <div class="no-threats-section">
                <div class="secure-icon">🛡️</div>
                <h2>ALL SYSTEMS SECURE</h2>
                <p>No security threats detected during the scan.</p>
            </div>
            '''
        
        return sections_html
    
    @staticmethod
    def _generate_table_rows(findings, severity):
        """Generate table rows for findings"""
        rows = []
        for i, finding in enumerate(findings):
            severity_score = finding.get('severity_score', 0)
            rows.append(
                f"<tr style='--row-index: {i};' class='threat-row {severity}-row'>"
                f"<td class='threat-type'>{html.escape(finding.get('type',''))}</td>"
                f"<td class='threat-url'>{html.escape(finding.get('url',''))}</td>"
                f"<td class='threat-severity' data-severity='{severity_score}'>{html.escape(str(severity_score))}</td>"
                f"<td class='threat-evidence'>{html.escape(finding.get('evidence',''))}</td>"
                "</tr>"
            )
        return ''.join(rows)
    
    @staticmethod
    def _load_css():
        """Load CSS from external file"""
        try:
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            css_path = os.path.join(current_dir, 'report-style.css')
            
            with open(css_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[WARN] Gagal memuat CSS: {e}")
    
    @staticmethod
    def _format_timestamp():
        """Format timestamp as DD-MM-YYYY HH:MM"""
        now = datetime.now()
        return now.strftime("%d-%m-%Y %H:%M")