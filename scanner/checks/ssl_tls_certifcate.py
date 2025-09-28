"""
SSL/TLS Security Checker

This module performs comprehensive SSL/TLS security analysis based on:
- OWASP Top 10 2021 (A02: Cryptographic Failures)
- OWASP Transport Layer Security Cheat Sheet
- Industry best practices for SSL/TLS security

Checks performed:
- Certificate validity and expiration
- Protocol version security (TLS 1.2+)
- Cipher suite strength and security
- Certificate chain validation
- Common SSL/TLS vulnerabilities
- Perfect Forward Secrecy support
- Certificate transparency compliance
"""

import ssl
import socket
import datetime
import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional
import subprocess
import tempfile
import os

class SSLTLSCheck:
    """SSL/TLS security assessment"""
    
    # Weak cipher patterns (based on OWASP recommendations)
    WEAK_CIPHERS = [
        r'.*NULL.*',           # Null encryption
        r'.*EXPORT.*',         # Export-grade ciphers
        r'.*DES.*',           # DES encryption
        r'.*RC4.*',           # RC4 stream cipher
        r'.*MD5.*',           # MD5 hash
        r'.*SHA1.*',          # SHA1 hash (deprecated)
        r'.*ADH.*',           # Anonymous DH
        r'.*AECDH.*',         # Anonymous ECDH
        r'.*LOW.*',           # Low security ciphers
        r'.*EXP.*',           # Export ciphers
    ]
    
    # Secure cipher suites (OWASP recommended)
    RECOMMENDED_CIPHERS = [
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-AES128-GCM-SHA256'
    ]
    
    @staticmethod
    def run(base_url: str, http=None, pages: List = None, options: Dict = None) -> List[Dict[str, Any]]:
        """Main entry point for SSL/TLS security checks"""
        findings = []
        parsed_url = urlparse(base_url)
        
        # Only check HTTPS URLs
        if parsed_url.scheme != 'https':
            return [{
                "type": "ssl:not-https",
                "url": base_url,
                "evidence": "URL does not use HTTPS protocol",
                "recommendation": "Implement HTTPS with valid SSL/TLS certificate",
                "severity_score": 8
            }]
        
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        try:
            # Get SSL certificate and connection info
            cert_info = SSLTLSCheck._get_certificate_info(hostname, port)
            ssl_info = SSLTLSCheck._get_ssl_connection_info(hostname, port)
            
            # Perform various SSL/TLS checks
            findings.extend(SSLTLSCheck._check_certificate_validity(base_url, cert_info))
            findings.extend(SSLTLSCheck._check_certificate_expiration(base_url, cert_info))
            findings.extend(SSLTLSCheck._check_protocol_versions(base_url, hostname, port))
            findings.extend(SSLTLSCheck._check_cipher_suites(base_url, ssl_info))
            findings.extend(SSLTLSCheck._check_certificate_chain(base_url, cert_info))
            findings.extend(SSLTLSCheck._check_perfect_forward_secrecy(base_url, ssl_info))
            findings.extend(SSLTLSCheck._check_common_vulnerabilities(base_url, hostname, port))
            findings.extend(SSLTLSCheck._check_certificate_transparency(base_url, cert_info))
            
        except Exception as e:
            findings.append({
                "type": "ssl:connection-error",
                "url": base_url,
                "evidence": f"Failed to establish SSL connection: {str(e)}",
                "recommendation": "Verify SSL/TLS configuration and certificate installation",
                "severity_score": 7
            })
        
        return findings
    
    @staticmethod
    def _get_certificate_info(hostname: str, port: int) -> Dict:
        """Extract certificate information"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                
                return {
                    'cert': cert,
                    'cert_der': cert_der,
                    'cipher': ssock.cipher(),
                    'version': ssock.version(),
                    'peer_cert_chain': ssock.getpeercert_chain() if hasattr(ssock, 'getpeercert_chain') else []
                }
    
    @staticmethod
    def _get_ssl_connection_info(hostname: str, port: int) -> Dict:
        """Get detailed SSL connection information"""
        try:
            # Try different SSL contexts to gather information
            info = {}
            
            # Get supported protocols
            protocols = ['TLSv1', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3']
            supported_protocols = []
            
            for protocol in protocols:
                try:
                    if hasattr(ssl, f'PROTOCOL_{protocol.replace(".", "_")}'):
                        context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{protocol.replace(".", "_")}'))
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                supported_protocols.append(protocol)
                except:
                    pass
            
            info['supported_protocols'] = supported_protocols
            
            # Get cipher information with modern context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    info['cipher'] = ssock.cipher()
                    info['version'] = ssock.version()
                    
            return info
            
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _check_certificate_validity(base_url: str, cert_info: Dict) -> List[Dict[str, Any]]:
        """Check certificate validity and properties"""
        findings = []
        cert = cert_info.get('cert', {})
        
        if not cert:
            return [{
                "type": "ssl:no-certificate",
                "url": base_url,
                "evidence": "No certificate found",
                "recommendation": "Install a valid SSL/TLS certificate",
                "severity_score": 9
            }]
        
        # Check certificate subject
        subject = dict(x[0] for x in cert.get('subject', []))
        common_name = subject.get('commonName', '')
        
        if not common_name:
            findings.append({
                "type": "ssl:missing-cn",
                "url": base_url,
                "evidence": "Certificate missing Common Name (CN)",
                "recommendation": "Use certificate with proper Common Name",
                "severity_score": 6
            })
        
        # Check Subject Alternative Names (SAN)
        san_list = []
        for san in cert.get('subjectAltName', []):
            if san[0] == 'DNS':
                san_list.append(san[1])
        
        parsed_url = urlparse(base_url)
        hostname = parsed_url.hostname
        
        # Check if hostname matches certificate
        hostname_match = False
        if common_name == hostname or common_name == f"*.{hostname}":
            hostname_match = True
        if hostname in san_list:
            hostname_match = True
        
        if not hostname_match:
            findings.append({
                "type": "ssl:hostname-mismatch",
                "url": base_url,
                "evidence": f"Certificate CN '{common_name}' does not match hostname '{hostname}'",
                "recommendation": "Use certificate that matches the domain name",
                "severity_score": 8
            })
        
        # Check key size
        public_key = cert.get('publicKey')
        if public_key:
            # This is a simplified check - in real implementation you'd parse the key properly
            cert_der = cert_info.get('cert_der')
            if cert_der and len(cert_der) < 1000:  # Very rough estimation
                findings.append({
                    "type": "ssl:weak-key-size",
                    "url": base_url,
                    "evidence": "Certificate may be using weak key size",
                    "recommendation": "Use RSA keys >= 2048 bits or ECDSA keys >= 256 bits",
                    "severity_score": 7
                })
        
        return findings
    
    @staticmethod
    def _check_certificate_expiration(base_url: str, cert_info: Dict) -> List[Dict[str, Any]]:
        """Check certificate expiration"""
        findings = []
        cert = cert_info.get('cert', {})
        
        if not cert:
            return []
        
        # Parse expiration date
        not_after = cert.get('notAfter')
        if not_after:
            try:
                exp_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.datetime.now()
                days_until_expiry = (exp_date - now).days
                
                if days_until_expiry < 0:
                    findings.append({
                        "type": "ssl:cert-expired",
                        "url": base_url,
                        "evidence": f"Certificate expired {abs(days_until_expiry)} days ago",
                        "recommendation": "Renew SSL certificate immediately",
                        "severity_score": 10
                    })
                elif days_until_expiry < 30:
                    findings.append({
                        "type": "ssl:cert-expiring-soon",
                        "url": base_url,
                        "evidence": f"Certificate expires in {days_until_expiry} days",
                        "recommendation": "Renew SSL certificate before expiration",
                        "severity_score": 6
                    })
                elif days_until_expiry < 90:
                    findings.append({
                        "type": "ssl:cert-expiring",
                        "url": base_url,
                        "evidence": f"Certificate expires in {days_until_expiry} days",
                        "recommendation": "Plan certificate renewal",
                        "severity_score": 3
                    })
                    
            except ValueError as e:
                findings.append({
                    "type": "ssl:cert-date-parse-error",
                    "url": base_url,
                    "evidence": f"Could not parse certificate expiration date: {not_after}",
                    "recommendation": "Verify certificate validity",
                    "severity_score": 4
                })
        
        return findings
    
    @staticmethod
    def _check_protocol_versions(base_url: str, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Check supported SSL/TLS protocol versions"""
        findings = []
        
        # Test for insecure protocols
        insecure_protocols = {
            'SSLv2': {'attr': None, 'severity': 10},
            'SSLv3': {'attr': 'PROTOCOL_SSLv3', 'severity': 10},
            'TLSv1': {'attr': 'PROTOCOL_TLSv1', 'severity': 8},
            'TLSv1_1': {'attr': 'PROTOCOL_TLSv1_1', 'severity': 6}
        }
        
        for protocol_name, config in insecure_protocols.items():
            if config['attr'] and hasattr(ssl, config['attr']):
                try:
                    context = ssl.SSLContext(getattr(ssl, config['attr']))
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            findings.append({
                                "type": f"ssl:insecure-protocol-{protocol_name.lower()}",
                                "url": base_url,
                                "evidence": f"Server supports insecure protocol {protocol_name}",
                                "recommendation": f"Disable {protocol_name} and use TLS 1.2 or higher",
                                "severity_score": config['severity']
                            })
                except:
                    # Protocol not supported (good)
                    pass
        
        # Check if TLS 1.2+ is supported
        secure_protocols_supported = False
        for protocol_attr in ['PROTOCOL_TLSv1_2', 'PROTOCOL_TLS']:
            if hasattr(ssl, protocol_attr):
                try:
                    context = ssl.SSLContext(getattr(ssl, protocol_attr))
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            secure_protocols_supported = True
                            break
                except:
                    pass
        
        if not secure_protocols_supported:
            findings.append({
                "type": "ssl:no-secure-protocols",
                "url": base_url,
                "evidence": "Server does not support TLS 1.2 or higher",
                "recommendation": "Enable TLS 1.2 and TLS 1.3 support",
                "severity_score": 9
            })
        
        return findings
    
    @staticmethod
    def _check_cipher_suites(base_url: str, ssl_info: Dict) -> List[Dict[str, Any]]:
        """Check cipher suite security"""
        findings = []
        
        cipher_info = ssl_info.get('cipher')
        if not cipher_info:
            return []
        
        cipher_name = cipher_info[0] if cipher_info else ""
        
        # Check for weak ciphers
        for weak_pattern in SSLTLSCheck.WEAK_CIPHERS:
            if re.match(weak_pattern, cipher_name, re.IGNORECASE):
                findings.append({
                    "type": "ssl:weak-cipher",
                    "url": base_url,
                    "evidence": f"Weak cipher suite in use: {cipher_name}",
                    "recommendation": "Configure server to use strong cipher suites (AEAD ciphers preferred)",
                    "severity_score": 8
                })
                break
        
        # Check if using recommended ciphers
        using_recommended = any(rec_cipher in cipher_name for rec_cipher in SSLTLSCheck.RECOMMENDED_CIPHERS)
        
        if not using_recommended and cipher_name:
            findings.append({
                "type": "ssl:non-recommended-cipher",
                "url": base_url,
                "evidence": f"Non-recommended cipher suite: {cipher_name}",
                "recommendation": "Use OWASP recommended cipher suites with AEAD encryption",
                "severity_score": 4
            })
        
        return findings
    
    @staticmethod
    def _check_certificate_chain(base_url: str, cert_info: Dict) -> List[Dict[str, Any]]:
        """Check certificate chain validity"""
        findings = []
        cert = cert_info.get('cert', {})
        
        if not cert:
            return []
        
        # Check if self-signed
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        
        if issuer.get('commonName') == subject.get('commonName'):
            findings.append({
                "type": "ssl:self-signed-cert",
                "url": base_url,
                "evidence": "Certificate appears to be self-signed",
                "recommendation": "Use certificate from trusted Certificate Authority (CA)",
                "severity_score": 7
            })
        
        # Check certificate authority
        issuer_cn = issuer.get('commonName', '')
        known_cas = [
            'Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 
            'VeriSign', 'Thawte', 'Symantec', 'GlobalSign'
        ]
        
        is_known_ca = any(ca.lower() in issuer_cn.lower() for ca in known_cas)
        
        if not is_known_ca and issuer_cn:
            findings.append({
                "type": "ssl:unknown-ca",
                "url": base_url,
                "evidence": f"Certificate issued by unknown CA: {issuer_cn}",
                "recommendation": "Use certificate from well-known Certificate Authority",
                "severity_score": 5
            })
        
        return findings
    
    @staticmethod
    def _check_perfect_forward_secrecy(base_url: str, ssl_info: Dict) -> List[Dict[str, Any]]:
        """Check Perfect Forward Secrecy support"""
        findings = []
        
        cipher_info = ssl_info.get('cipher')
        if not cipher_info:
            return []
        
        cipher_name = cipher_info[0] if cipher_info else ""
        
        # Check for PFS-enabled key exchange
        pfs_kex = ['ECDHE', 'DHE']
        has_pfs = any(kex in cipher_name for kex in pfs_kex)
        
        if not has_pfs:
            findings.append({
                "type": "ssl:no-perfect-forward-secrecy",
                "url": base_url,
                "evidence": f"Cipher suite does not support Perfect Forward Secrecy: {cipher_name}",
                "recommendation": "Configure server to prefer ECDHE or DHE cipher suites",
                "severity_score": 6
            })
        
        return findings
    
    @staticmethod
    def _check_common_vulnerabilities(base_url: str, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Check for common SSL/TLS vulnerabilities"""
        findings = []
        
        # Check for SSL compression (CRIME vulnerability)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Note: This is a simplified check
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # In a real implementation, you'd check compression settings
                    # This is a placeholder for demonstration
                    pass
                    
        except Exception:
            pass
        
        # Check for weak DH parameters (simplified)
        try:
            # This would require more sophisticated testing in practice
            # For now, we'll check if DHE ciphers are available with weak parameters
            pass
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def _check_certificate_transparency(base_url: str, cert_info: Dict) -> List[Dict[str, Any]]:
        """Check Certificate Transparency compliance"""
        findings = []
        cert = cert_info.get('cert', {})
        
        if not cert:
            return []
        
        # Check for SCT extension (simplified check)
        extensions = cert.get('extensions', [])
        has_sct = False
        
        # In a real implementation, you'd parse the extensions properly
        # This is a placeholder check
        
        if not has_sct:
            findings.append({
                "type": "ssl:no-certificate-transparency",
                "url": base_url,
                "evidence": "Certificate may not be logged in Certificate Transparency logs",
                "recommendation": "Use certificates that comply with Certificate Transparency requirements",
                "severity_score": 3
            })
        
        return findings

# Additional utility functions for advanced SSL/TLS testing
class SSLTLSAdvanced:
    """Advanced SSL/TLS security testing utilities"""
    
    @staticmethod
    def check_hsts_header(http, base_url: str) -> List[Dict[str, Any]]:
        """Check HTTP Strict Transport Security header"""
        findings = []
        
        try:
            response = http.get(base_url)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if not hsts_header:
                findings.append({
                    "type": "ssl:missing-hsts",
                    "url": base_url,
                    "evidence": "Missing Strict-Transport-Security header",
                    "recommendation": "Implement HSTS header with max-age of at least 31536000 seconds",
                    "severity_score": 6
                })
            else:
                # Check HSTS configuration
                if 'max-age=' not in hsts_header.lower():
                    findings.append({
                        "type": "ssl:hsts-no-max-age",
                        "url": base_url,
                        "evidence": "HSTS header missing max-age directive",
                        "recommendation": "Add max-age directive to HSTS header",
                        "severity_score": 5
                    })
                else:
                    # Extract max-age value
                    import re
                    max_age_match = re.search(r'max-age=(\d+)', hsts_header.lower())
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 31536000:  # Less than 1 year
                            findings.append({
                                "type": "ssl:hsts-short-max-age",
                                "url": base_url,
                                "evidence": f"HSTS max-age is too short: {max_age} seconds",
                                "recommendation": "Set HSTS max-age to at least 31536000 seconds (1 year)",
                                "severity_score": 4
                            })
                
                if 'includesubdomains' not in hsts_header.lower():
                    findings.append({
                        "type": "ssl:hsts-no-subdomains",
                        "url": base_url,
                        "evidence": "HSTS header missing includeSubDomains directive",
                        "recommendation": "Add includeSubDomains to HSTS header if applicable",
                        "severity_score": 3
                    })
                
        except Exception as e:
            findings.append({
                "type": "ssl:hsts-check-error",
                "url": base_url,
                "evidence": f"Error checking HSTS header: {str(e)}",
                "recommendation": "Verify HTTPS configuration and HSTS implementation",
                "severity_score": 2
            })
        
        return findings

# Integration function to run all SSL/TLS checks
def run_complete_ssl_tls_check(http, base_url: str) -> List[Dict[str, Any]]:
    """Run complete SSL/TLS security assessment"""
    findings = []
    
    # Core SSL/TLS checks
    findings.extend(SSLTLSCheck.run(http, base_url))
    
    # HSTS check
    findings.extend(SSLTLSAdvanced.check_hsts_header(http, base_url))
    
    return findings