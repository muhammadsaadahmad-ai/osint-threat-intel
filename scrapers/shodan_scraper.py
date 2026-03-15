import shodan
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import SHODAN_API_KEY
from analyzer.ioc_parser import extract_iocs, score_severity
from analyzer.tagger import tag_with_mitre
from database.models import Session, IOC

def search_shodan(query, max_results=20):
    """Search Shodan for a query and store results as IOCs."""
    if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_key_here":
        print("[!] No Shodan API key set. Using demo mode with sample data.")
        return _demo_results(query)

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(query, limit=max_results)
        session = Session()
        saved = 0

        for result in results["matches"]:
            ip = result.get("ip_str", "")
            banner = result.get("data", "")
            port = result.get("port", 0)
            org = result.get("org", "Unknown")
            country = result.get("location", {}).get("country_name", "Unknown")

            context = f"IP: {ip} | Port: {port} | Org: {org} | Country: {country}\n{banner[:300]}"
            mitre_tags = tag_with_mitre(banner)
            severity = score_severity("ipv4", banner)

            ioc = IOC(
                value=ip,
                ioc_type="ipv4",
                source="shodan",
                mitre_tag=", ".join(mitre_tags),
                raw_context=context,
                severity=severity
            )
            session.add(ioc)
            saved += 1

        session.commit()
        session.close()
        print(f"[+] Shodan: Saved {saved} IOCs for query '{query}'")
        return saved

    except shodan.APIError as e:
        print(f"[-] Shodan API error: {e}")
        return 0

def _demo_results(query):
    """Demo mode — inserts sample data so you can test without an API key."""
    session = Session()
    sample_data = [
        ("192.168.1.100", "high", "T1046 - Network Service Discovery"),
        ("10.0.0.55", "medium", "T1190 - Exploit Public-Facing Application"),
        ("172.16.0.23", "low", "T1071 - Application Layer Protocol"),
    ]
    for ip, sev, tag in sample_data:
        ioc = IOC(value=ip, ioc_type="ipv4", source="shodan-demo",
                  mitre_tag=tag, raw_context=f"Demo data for query: {query}", severity=sev)
        session.add(ioc)
    session.commit()
    session.close()
    print(f"[+] Demo mode: Inserted 3 sample IOCs.")
    return 3

