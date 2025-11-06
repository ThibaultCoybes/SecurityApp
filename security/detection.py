# security/detection.py
import re
from typing import Optional

SQLI_RE = re.compile(r"('|--|\b(OR|AND)\b\s+['\"]?\w+|;|/\*|\*/|\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)", re.IGNORECASE)

TOOL_SIGNATURES = {
    'sqlmap': ['sqlmap'],
    'nikto': ['nikto'],
    'nmap': ['nmap'],
    'curl': ['curl/'],
    'wget': ['wget/'],
    'python-requests': ['python-requests', 'python-urllib'],
    'postman': ['postman'],
    'insomnia': ['insomnia'],
    'masscan': ['masscan'],
    'acunetix': ['acunetix'],
    'nessus': ['nessus'],
    'headless': ['headlesschrome', 'headless'],
}

def detect_sql_injection(s: str) -> bool:
    if not s:
        return False
    return bool(SQLI_RE.search(s))


def detect_tool(user_agent: str, payload_sample: str = "") -> Optional[str]:
    ua = (user_agent or "").lower()
    
    for name, tokens in TOOL_SIGNATURES.items():
        if any(t in ua for t in tokens):
            return name
    
    ps = (payload_sample or "").lower()
    if 'union select' in ps or ' or 1=1' in ps:
        return 'sql_injection_payload'
    return None

