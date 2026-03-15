import re
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import IOC_PATTERNS

def extract_iocs(text):
    """Extract all IOCs from raw text and return structured results."""
    results = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
        # Filter out common false positives
        if ioc_type == "ipv4":
            matches = [ip for ip in matches if not ip.startswith("127.")
                       and not ip.startswith("0.") and not ip == "255.255.255.255"]
        if matches:
            results[ioc_type] = matches
    return results

def score_severity(ioc_type, context=""):
    """Assign severity based on IOC type and context."""
    high_keywords = ["malware", "ransomware", "c2", "botnet", "exploit", "shell"]
    medium_keywords = ["scan", "probe", "brute", "password", "credential"]

    context_lower = context.lower()
    if any(k in context_lower for k in high_keywords):
        return "high"
    if any(k in context_lower for k in medium_keywords):
        return "medium"
    if ioc_type in ["md5", "sha256"]:
        return "high"
    return "low"
