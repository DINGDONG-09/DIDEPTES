import re

class MisconfigCheck:
    @staticmethod
    def run(http, crawled_urls):
        findings = []
        
        
        sensitive_paths = [
            '/.env', '/.git/config', '/config.php', '/wp-config.php',
            '/admin', '/phpmyadmin', '/.htaccess', '/robots.txt',
            '/sitemap.xml', '/composer.json', '/package.json',
            '/.DS_Store', '/thumbs.db', '/backup.sql', '/database.sql'
        ]
        
        base_url = crawled_urls[0] if crawled_urls else ""
        if not base_url:
            return findings
            
        
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        
        for path in sensitive_paths:
            try:
                test_url = base + path
                r = http.get(test_url)
                
                if r.status_code == 200:
                    
                    content = r.text.lower()
                    
                    
                    if len(content) > 100 and not any(x in content for x in ['not found', '404', 'error']):
                        severity = MisconfigCheck._get_severity(path)
                        findings.append({
                            "type": "misconfig:sensitive-file",
                            "url": test_url,
                            "path": path,
                            "severity_score": severity,
                            "evidence": f"File sensitif dapat diakses: {path}",
                            "recommendation": f"Blokir akses ke {path} atau pindahkan ke lokasi yang aman"
                        })
                        
                elif r.status_code == 403:
                    
                    if path.endswith('/'):
                        findings.append({
                            "type": "misconfig:directory-listing",
                            "url": test_url,
                            "path": path,
                            "severity_score": 3,
                            "evidence": f"Directory terdeteksi tapi diblokir: {path}",
                            "recommendation": "Pastikan directory listing dinonaktifkan"
                        })
                        
            except Exception:
                pass
        
        
        for url in crawled_urls:
            try:
                r = http.get(url)
                
                
                if r.status_code == 200:
                    content = r.text.lower()
                    debug_patterns = [
                        'debug', 'stack trace', 'fatal error', 'warning:',
                        'notice:', 'strict standards:', 'deprecated:',
                        'mysql_connect', 'sql error', 'exception'
                    ]
                    
                    for pattern in debug_patterns:
                        if pattern in content:
                            findings.append({
                                "type": "misconfig:debug-info",
                                "url": url,
                                "pattern": pattern,
                                "severity_score": 4,
                                "evidence": f"Informasi debug terdeteksi: {pattern}",
                                "recommendation": "Nonaktifkan debug mode di production"
                            })
                            break
                            
                
                server = r.headers.get('Server', '')
                if server:
                   
                    if re.search(r'\d+\.\d+', server):
                        findings.append({
                            "type": "misconfig:version-disclosure",
                            "url": url,
                            "header": "Server",
                            "value": server,
                            "severity_score": 2,
                            "evidence": f"Server version disclosed: {server}",
                            "recommendation": "Sembunyikan versi server di header response"
                        })
                        
            except Exception:
                pass
                
        return findings
    
    @staticmethod
    def _get_severity(path):
        high_risk = ['.env', '/config.php', '/wp-config.php', '/.git/config']
        medium_risk = ['/admin', '/phpmyadmin', '/backup.sql', '/database.sql']
        
        if any(p in path for p in high_risk):
            return 8
        elif any(p in path for p in medium_risk):
            return 6
        else:
            return 3