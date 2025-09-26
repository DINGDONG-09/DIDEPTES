import re
import urllib.parse

class LFICheck:
    """Local File Inclusion vulnerability checker."""
    
    # Common LFI payloads to test
    LFI_PAYLOADS = [
        # Basic traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
        
        # URL encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        
        # Double URL encoded
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        
        # Null byte (for older systems)
        "../../../etc/passwd%00",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00",
        
        # Filter bypass
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
        
        # Absolute paths
        "/etc/passwd",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "/proc/version",
        "/proc/self/environ",
        
        # PHP wrappers (if applicable)
        "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
        "file:///etc/passwd",
    ]
    
    # Patterns that indicate successful LFI
    SUCCESS_PATTERNS = [
        # Linux/Unix indicators
        re.compile(r"root:.*?:0:0:", re.I),  # /etc/passwd
        re.compile(r"daemon:.*?:/usr/sbin/nologin", re.I),  # /etc/passwd
        re.compile(r"Linux version \d+\.\d+", re.I),  # /proc/version
        re.compile(r"PATH=/.*?:/bin", re.I),  # /proc/self/environ
        
        # Windows indicators
        re.compile(r"# Copyright.*Microsoft Corp", re.I),  # hosts file
        re.compile(r"\d+\.\d+\.\d+\.\d+\s+\w+", re.I),  # IP entries in hosts
        re.compile(r"127\.0\.0\.1\s+localhost", re.I),  # localhost entry
        
        # Generic file system indicators
        re.compile(r"(\.\./){3,}", re.I),  # Multiple directory traversals in response
        re.compile(r"include.*?failed.*?open", re.I),  # PHP include errors
    ]

    @classmethod
    def run(cls, http, params_map):
        """Test GET parameters for LFI vulnerabilities."""
        findings = []
        
        for url, param_names in params_map.items():
            for param in param_names:
                findings.extend(cls._test_parameter(http, url, param))
                
        return findings

    @classmethod
    def run_forms(cls, http, forms):
        """Test POST forms for LFI vulnerabilities."""
        findings = []
        
        for form in forms:
            if form["method"].upper() == "POST":
                findings.extend(cls._test_form(http, form))
                
        return findings

    @classmethod
    def _test_parameter(cls, http, url, param_name):
        """Test a specific GET parameter for LFI."""
        findings = []
        
        for payload in cls.LFI_PAYLOADS:
            try:
                # Parse original URL
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)
                
                # Set the payload for the specific parameter
                query_params[param_name] = [payload]
                
                # Reconstruct URL with payload
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                response = http.get(test_url)
                
                # Check for LFI indicators in response
                if cls._is_vulnerable(response):
                    findings.append({
                        "type": "Local File Inclusion (GET)",
                        "severity": "HIGH",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": cls._extract_evidence(response.text),
                        "description": f"Local File Inclusion vulnerability found in parameter '{param_name}'. "
                                     f"The application includes files based on user input without proper validation.",
                        "recommendation": "Implement proper input validation, use whitelists for allowed files, "
                                       "and avoid direct file inclusion based on user input."
                    })
                    # Stop testing this parameter after first successful payload
                    break
                    
            except Exception:
                continue
                
        return findings

    @classmethod
    def _test_form(cls, http, form):
        """Test a POST form for LFI vulnerabilities."""
        findings = []
        
        # Test each non-hidden input field
        for input_field in form["inputs"]:
            if input_field["hidden"]:
                continue
                
            param_name = input_field["name"]
            
            for payload in cls.LFI_PAYLOADS:
                try:
                    # Prepare form data
                    data = {}
                    for inp in form["inputs"]:
                        if inp["name"] == param_name:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]
                    
                    response = http.post(form["action"], data=data)
                    
                    # Check for LFI indicators in response
                    if cls._is_vulnerable(response):
                        findings.append({
                            "type": "Local File Inclusion (POST)",
                            "severity": "HIGH",
                            "url": form["action"],
                            "form_page": form["page"],
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": cls._extract_evidence(response.text),
                            "description": f"Local File Inclusion vulnerability found in form parameter '{param_name}'. "
                                         f"The application includes files based on user input without proper validation.",
                            "recommendation": "Implement proper input validation, use whitelists for allowed files, "
                                           "and avoid direct file inclusion based on user input."
                        })
                        # Stop testing this parameter after first successful payload
                        break
                        
                except Exception:
                    continue
                    
        return findings

    @classmethod
    def _is_vulnerable(cls, response):
        """Check if response indicates LFI vulnerability."""
        if not response or not response.text:
            return False
            
        # Check for success patterns
        for pattern in cls.SUCCESS_PATTERNS:
            if pattern.search(response.text):
                return True
                
        # Check for file inclusion errors that might indicate vulnerability
        error_indicators = [
            "failed to open stream",
            "No such file or directory",
            "Permission denied",
            "include_once",
            "require_once",
            "Warning: include",
            "Fatal error: require",
        ]
        
        response_lower = response.text.lower()
        for indicator in error_indicators:
            if indicator.lower() in response_lower:
                return True
                
        return False

    @classmethod
    def _extract_evidence(cls, response_text):
        """Extract relevant evidence from response."""
        if not response_text:
            return "No response text"
            
        # Look for the most obvious evidence first
        for pattern in cls.SUCCESS_PATTERNS:
            match = pattern.search(response_text)
            if match:
                # Return some context around the match
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end].strip()
        
        # If no pattern match, look for error messages
        lines = response_text.split('\n')
        for line in lines:
            if any(indicator in line.lower() for indicator in [
                "include", "require", "failed to open", "no such file"
            ]):
                return line.strip()[:200]  # Limit evidence length
                
        return "Potential LFI vulnerability detected"