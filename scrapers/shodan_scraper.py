import shodan
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import SHODAN_API_KEY
from analyzer.ioc_parser import extract_iocs, score_severity
from analyzer.tagger import tag_with_mitre
from database.models import Session, IOC

# Publicly known malicious / interesting IPs for research purposes
# Sources: public threat intel feeds (AbuseIPDB, Feodo Tracker, etc.)
RESEARCH_IPS = [
    "185.220.101.45",  # Known Tor exit node / scanner
    "89.248.167.131",  # Shodan crawler itself (ironic)
    "198.20.69.74",    # Shodan scanner
    "198.20.69.98",    # Shodan scanner
    "80.82.77.33",     # Known mass scanner (Shodan)
    "71.6.135.131",    # Shodan/Censys scanner
    "192.241.236.155", # DigitalOcean — common attacker infra
    "45.33.32.156",    # nmap.org scanme host (safe test target)
    "93.184.216.34",   # example.com (safe)
    "8.8.8.8",         # Google DNS
]

def search_shodan(query, max_results=20):
    """
    Free Shodan accounts don't support search queries.
    We use host lookups instead — same intelligence, different method.
    'query' param is kept for CLI compatibility but we use RESEARCH_IPS.
    """
    if not SHODAN_API_KEY or SHODAN_API_KEY == "":
        print("[!] No Shodan API key. Using demo mode.")
        return _demo_results(query)

    try:
        api = shodan.Shodan(SHODAN_API_KEY)

        # Verify key works first
        info = api.info()
        print(f"[+] Shodan account: {info.get('plan','unknown')} plan | "
              f"Query credits: {info.get('query_credits',0)} | "
              f"Scan credits: {info.get('scan_credits',0)}")

        session = Session()
        saved = 0

        print(f"[*] Looking up {len(RESEARCH_IPS)} known research IPs...")

        for ip in RESEARCH_IPS:
            try:
                host = api.host(ip)

                org     = host.get("org", "Unknown")
                country = host.get("country_name", "Unknown")
                ports   = [str(s["port"]) for s in host.get("data", [])]
                banners = " ".join([s.get("data","") for s in host.get("data",[])])[:500]
                vulns_raw = host.get("vulns", {})
                vulns = list(vulns_raw.keys()) if isinstance(vulns_raw, dict) else []

                context = (f"IP: {ip} | Org: {org} | Country: {country} | "
                           f"Open ports: {','.join(ports[:10])} | "
                           f"CVEs: {','.join(vulns[:5]) if vulns else 'none'}\n{banners}")

                mitre_tags = tag_with_mitre(banners)
                severity   = "high" if vulns else score_severity("ipv4", banners)

                # Save the IP itself
                ioc = IOC(
                    value      = ip,
                    ioc_type   = "ipv4",
                    source     = "shodan-host",
                    mitre_tag  = ", ".join(mitre_tags),
                    raw_context= context,
                    severity   = severity
                )
                session.add(ioc)
                saved += 1

                # Save any CVEs as separate high-severity IOCs
                for cve in vulns[:3]:
                    cve_ioc = IOC(
                        value      = cve,
                        ioc_type   = "cve",
                        source     = f"shodan-host:{ip}",
                        mitre_tag  = "T1190 - Exploit Public-Facing Application",
                        raw_context= f"CVE found on {ip} ({org}, {country})",
                        severity   = "high"
                    )
                    session.add(cve_ioc)
                    saved += 1

                print(f"  [+] {ip:<20} | {country:<15} | ports: {','.join(ports[:5])} "
                      f"| CVEs: {len(vulns)}")

            except shodan.APIError as e:
                print(f"  [-] {ip} — {e}")
                continue

        session.commit()
        session.close()
        print(f"\n[+] Shodan: Saved {saved} IOCs from host lookups.")
        return saved

    except shodan.APIError as e:
        print(f"[-] Shodan API error: {e}")
        return _demo_results(query)


def _demo_results(query):
    session = Session()
    sample_data = [
        ("192.168.1.100", "high",   "T1046 - Network Service Discovery"),
        ("10.0.0.55",     "medium", "T1190 - Exploit Public-Facing Application"),
        ("172.16.0.23",   "low",    "T1071 - Application Layer Protocol"),
    ]
    for ip, sev, tag in sample_data:
        ioc = IOC(value=ip, ioc_type="ipv4", source="shodan-demo",
                  mitre_tag=tag,
                  raw_context=f"Demo data for query: {query}",
                  severity=sev)
        session.add(ioc)
    session.commit()
    session.close()
    print("[+] Demo mode: Inserted 3 sample IOCs.")
    return 3

