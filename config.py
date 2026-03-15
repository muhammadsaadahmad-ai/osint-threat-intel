import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
DATABASE_URL = "sqlite:///database/osint.db"

PASTE_KEYWORDS = [
    "password", "credentials", "api_key", "token",
    "secret", "admin", "hack", "breach", "leaked"
]

IOC_PATTERNS = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "url": r"https?://[^\s\">]+"
}

MITRE_TAGS = {
    "port_scan": "T1046 - Network Service Discovery",
    "brute_force": "T1110 - Brute Force",
    "phishing": "T1566 - Phishing",
    "credential_dump": "T1003 - OS Credential Dumping",
    "c2": "T1071 - Application Layer Protocol",
    "exfil": "T1041 - Exfiltration Over C2 Channel"
}
