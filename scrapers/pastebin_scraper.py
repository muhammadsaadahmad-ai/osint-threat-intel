import requests
import time
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import PASTE_KEYWORDS
from analyzer.ioc_parser import extract_iocs, score_severity
from analyzer.tagger import tag_with_mitre
from database.models import Session, IOC

PASTEBIN_RECENT = "https://scrape.pastebin.com/api_scraping.php?limit=20"

def scrape_pastebin():
    """Scrape recent Pastebin pastes for keywords and extract IOCs.
    Note: scrape.pastebin.com requires a Pro account. Free users get demo data.
    """
    try:
        resp = requests.get(PASTEBIN_RECENT, timeout=10)
        if resp.status_code == 403:
            print("[!] Pastebin scraping requires Pro account. Using demo mode.")
            return _demo_paste_scan()

        pastes = resp.json()
        session = Session()
        total_iocs = 0

        for paste in pastes:
            paste_key = paste.get("key", "")
            paste_url = f"https://scrape.pastebin.com/api_scrape_item.php?i={paste_key}"

            try:
                content_resp = requests.get(paste_url, timeout=8)
                content = content_resp.text

                # Check if paste contains any target keywords
                if not any(kw.lower() in content.lower() for kw in PASTE_KEYWORDS):
                    continue

                iocs = extract_iocs(content)
                mitre_tags = tag_with_mitre(content)

                for ioc_type, values in iocs.items():
                    for value in values[:10]:  # cap at 10 per type per paste
                        severity = score_severity(ioc_type, content)
                        ioc = IOC(
                            value=value,
                            ioc_type=ioc_type,
                            source=f"pastebin:{paste_key}",
                            mitre_tag=", ".join(mitre_tags),
                            raw_context=content[:500],
                            severity=severity
                        )
                        session.add(ioc)
                        total_iocs += 1

                time.sleep(1)  # be polite to the API

            except Exception:
                continue

        session.commit()
        session.close()
        print(f"[+] Pastebin: Extracted {total_iocs} IOCs.")
        return total_iocs

    except Exception as e:
        print(f"[-] Pastebin error: {e}")
        return _demo_paste_scan()

def _demo_paste_scan():
    """Insert realistic demo IOCs from a simulated paste."""
    demo_text = """
    Leaked credentials from breach:
    admin@target.com : P@ssw0rd123
    Server: 185.220.101.45 running OpenSSH
    C2 domain: evil-update.xyz
    Hash: 5f4dcc3b5aa765d61d8327deb882cf99
    """
    session = Session()
    iocs = extract_iocs(demo_text)
    mitre_tags = tag_with_mitre(demo_text)
    saved = 0

    for ioc_type, values in iocs.items():
        for value in values:
            ioc = IOC(value=value, ioc_type=ioc_type, source="pastebin-demo",
                      mitre_tag=", ".join(mitre_tags),
                      raw_context=demo_text.strip(), severity=score_severity(ioc_type, demo_text))
            session.add(ioc)
            saved += 1

    session.commit()
    session.close()
    print(f"[+] Demo paste scan: Inserted {saved} IOCs.")
    return saved
