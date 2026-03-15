import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import MITRE_TAGS

def tag_with_mitre(text):
    """Map raw text to MITRE ATT&CK techniques."""
    text_lower = text.lower()
    tags = []

    keyword_map = {
        "port_scan": ["nmap", "port scan", "service discovery", "masscan"],
        "brute_force": ["brute force", "password spray", "hydra", "credential stuffing"],
        "phishing": ["phishing", "spear phish", "email lure", "credential harvest"],
        "credential_dump": ["mimikatz", "lsass", "credential dump", "hash dump"],
        "c2": ["command and control", "c2", "beacon", "cobalt strike", "callback"],
        "exfil": ["exfiltration", "data theft", "exfil", "upload", "dns tunnel"]
    }

    for technique_key, keywords in keyword_map.items():
        if any(kw in text_lower for kw in keywords):
            tags.append(MITRE_TAGS[technique_key])

    return tags if tags else ["T1190 - Exploit Public-Facing Application (default)"]
