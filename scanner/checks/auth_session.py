import re
import time
import requests
from urllib.parse import urljoin, urlparse

class AuthSessionCheck:
    @staticmethod
    def run(http, crawled_urls):
        """Run authentication and session security checks"""
        findings = []
        
        for url in crawled_urls:
            try:
                # Get initial response
                resp = http.get(url)
                
                # Check session management
                findings.extend(AuthSessionCheck._check_session_management(url, resp))
                
                # Check authentication mechanisms
                findings.extend(AuthSessionCheck._check_authentication(url, resp))
                
                # Check session cookies
                findings.extend(AuthSessionCheck._check_session_cookies(url, resp))
                
                # Check login forms
                findings.extend(AuthSessionCheck._check_login_forms(url, resp, http))
                
                # Check session fixation
                findings.extend(AuthSessionCheck._check_session_fixation(url, http))
                
            except Exception as e:
                print(f"Auth check failed for {url}: {e}")
                continue

        print(f"Authentication analysis completed. Found {len(findings)} issues")
        return findings
    
    @staticmethod
    def _check_session_management(url, resp):
        """Check session management security"""
        findings = []
        cookies = resp.cookies
        
        if not cookies:
            return findings
        
        for cookie in cookies:
            cookie_name = cookie.name.lower()
            
            # Check for common session cookie names
            session_indicators = ['sessionid', 'jsessionid', 'phpsessid', 'asp.net_sessionid', 'session', 'sid']
            
            if any(indicator in cookie_name for indicator in session_indicators):
                # Check if session cookie lacks Secure flag
                if not cookie.secure:
                    findings.append({
                        "type": "session:insecure-cookie",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session cookie '{cookie.name}' lacks Secure flag",
                        "recommendation": "Add Secure flag to session cookies to prevent transmission over HTTP",
                        "severity_score": 6
                    })
                
                # Check if session cookie lacks HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    findings.append({
                        "type": "session:httponly-missing",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session cookie '{cookie.name}' lacks HttpOnly flag",
                        "recommendation": "Add HttpOnly flag to session cookies to prevent XSS attacks",
                        "severity_score": 5
                    })
                
                # Check if session cookie lacks SameSite attribute
                if not cookie.has_nonstandard_attr('SameSite'):
                    findings.append({
                        "type": "session:samesite-missing",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session cookie '{cookie.name}' lacks SameSite attribute",
                        "recommendation": "Add SameSite attribute to session cookies to prevent CSRF attacks",
                        "severity_score": 4
                    })
                
                # Check for weak session ID
                if len(cookie.value) < 16:
                    findings.append({
                        "type": "session:weak-session-id",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session ID appears to be weak (length: {len(cookie.value)})",
                        "recommendation": "Use longer, cryptographically secure session IDs (minimum 128 bits)",
                        "severity_score": 7
                    })
        
        return findings
    
    @staticmethod
    def _check_authentication(url, resp):
        """Check authentication mechanisms"""
        findings = []
        content = resp.text.lower() if resp.text else ""
        headers = resp.headers
        
        # Check for basic authentication
        if 'www-authenticate' in headers:
            auth_header = headers['www-authenticate'].lower()
            
            if 'basic' in auth_header:
                findings.append({
                    "type": "auth:basic-authentication",
                    "url": url,
                    "evidence": "Basic Authentication detected",
                    "recommendation": "Replace Basic Auth with more secure authentication methods (OAuth, JWT, etc.)",
                    "severity_score": 6
                })
            
            if 'digest' in auth_header:
                findings.append({
                    "type": "auth:digest-authentication",
                    "url": url,
                    "evidence": "Digest Authentication detected",
                    "recommendation": "Consider upgrading to modern authentication methods",
                    "severity_score": 3
                })
        
        # Check for login forms without HTTPS
        if urlparse(url).scheme == 'http':
            login_patterns = [
                r'type\s*=\s*["\']password["\']',
                r'name\s*=\s*["\']password["\']',
                r'name\s*=\s*["\']login["\']',
                r'action\s*=\s*["\'][^"\']*login[^"\']*["\']'
            ]
            
            for pattern in login_patterns:
                if re.search(pattern, content):
                    findings.append({
                        "type": "auth:login-over-http",
                        "url": url,
                        "evidence": "Login form detected over unencrypted HTTP connection",
                        "recommendation": "Enforce HTTPS for all authentication pages",
                        "severity_score": 8
                    })
                    break
        
        # Check for password fields without autocomplete=off
        password_fields = re.findall(r'<input[^>]*type\s*=\s*["\']password["\'][^>]*>', content)
        for field in password_fields:
            if 'autocomplete' not in field.lower() or 'autocomplete="off"' not in field.lower():
                findings.append({
                    "type": "auth:password-autocomplete",
                    "url": url,
                    "evidence": "Password field allows autocomplete",
                    "recommendation": "Add autocomplete='off' to password fields",
                    "severity_score": 3
                })
                break
        
        return findings
    
    @staticmethod
    def _check_session_cookies(url, resp):
        """Detailed session cookie analysis"""
        findings = []
        
        # Check for session cookies with predictable values
        for cookie in resp.cookies:
            value = cookie.value
            
            # Check for sequential session IDs
            if value.isdigit() and len(value) < 10:
                findings.append({
                    "type": "session:predictable-session-id",
                    "url": url,
                    "cookie_name": cookie.name,
                    "evidence": f"Session ID appears to be sequential or predictable: {value}",
                    "recommendation": "Use cryptographically secure random session ID generation",
                    "severity_score": 8
                })
            
            # Check for timestamp-based session IDs
            timestamp_patterns = [
                r'\d{10}',  # Unix timestamp
                r'\d{13}',  # Millisecond timestamp
                r'\d{4}-\d{2}-\d{2}',  # Date format
            ]
            
            for pattern in timestamp_patterns:
                if re.search(pattern, value):
                    findings.append({
                        "type": "session:timestamp-based-session-id",
                        "url": url,
                        "cookie_name": cookie.name,
                        "evidence": f"Session ID contains timestamp pattern: {value}",
                        "recommendation": "Avoid using timestamps in session IDs",
                        "severity_score": 6
                    })
                    break
        
        return findings
    
    @staticmethod
    def _check_login_forms(url, resp, http):
        """Check login forms for security issues"""
        findings = []
        content = resp.text if resp.text else ""
        
        # Find login forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form in forms:
            form_lower = form.lower()
            
            # Check if it's a login form
            if any(indicator in form_lower for indicator in ['password', 'login', 'signin', 'username']):
                
                # Check for missing CSRF protection
                csrf_patterns = [
                    r'name\s*=\s*["\'][^"\']*csrf[^"\']*["\']',
                    r'name\s*=\s*["\'][^"\']*token[^"\']*["\']',
                    r'name\s*=\s*["\']_token["\']'
                ]
                
                has_csrf = any(re.search(pattern, form_lower) for pattern in csrf_patterns)
                
                if not has_csrf:
                    findings.append({
                        "type": "auth:missing-csrf-protection",
                        "url": url,
                        "evidence": "Login form lacks CSRF protection",
                        "recommendation": "Implement CSRF tokens in login forms",
                        "severity_score": 6
                    })
                
                # Check for account lockout mechanism test
                try:
                    # Attempt to detect if there's rate limiting
                    # This is a basic check - in production, be more careful about testing
                    pass  # Placeholder - actual brute force testing would be too aggressive
                    
                except Exception:
                    pass
        
        return findings
    
    @staticmethod
    def _check_session_fixation(url, http):
        """Check for session fixation vulnerabilities"""
        findings = []
        
        try:
            # Get initial session
            resp1 = http.get(url)
            initial_cookies = {cookie.name: cookie.value for cookie in resp1.cookies}
            
            if not initial_cookies:
                return findings
            
            # Try to access login page if it exists
            login_urls = [
                urljoin(url, '/login'),
                urljoin(url, '/signin'),
                urljoin(url, '/auth'),
                urljoin(url, '/admin')
            ]
            
            for login_url in login_urls:
                try:
                    resp2 = http.get(login_url)
                    if resp2.status_code == 200:
                        new_cookies = {cookie.name: cookie.value for cookie in resp2.cookies}
                        
                        # Check if session ID remained the same
                        for cookie_name, cookie_value in initial_cookies.items():
                            if cookie_name.lower() in ['sessionid', 'jsessionid', 'phpsessid', 'session']:
                                if cookie_name in new_cookies and new_cookies[cookie_name] == cookie_value:
                                    findings.append({
                                        "type": "session:session-fixation",
                                        "url": url,
                                        "login_url": login_url,
                                        "evidence": f"Session ID '{cookie_name}' not regenerated when accessing login page",
                                        "recommendation": "Regenerate session IDs upon authentication state changes",
                                        "severity_score": 7
                                    })
                        break
                        
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"Session fixation check failed for {url}: {e}")
        
        return findings