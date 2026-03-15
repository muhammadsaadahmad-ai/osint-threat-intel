from rich.console import Console
from rich.panel import Panel
import threading, time

console = Console()

def main():
    console.print(Panel.fit(
        "[bold cyan]OSINT Threat Intelligence Platform[/bold cyan]\n"
        "[dim]Army Intelligence Cyber Portfolio — Phase 1[/dim]",
        border_style="cyan"
    ))

    # Initialize database
    from database.models import init_db
    init_db()

    console.print("\n[bold yellow]Select operation:[/bold yellow]")
    console.print("  [1] Run Shodan scraper")
    console.print("  [2] Run Pastebin scraper")
    console.print("  [3] Run all scrapers")
    console.print("  [4] Launch dashboard")
    console.print("  [5] Full pipeline (scrape + dashboard)\n")

    choice = input("Enter choice [1-5]: ").strip()

    if choice in ["1", "3", "5"]:
        query = input("Shodan query (e.g. 'apache country:PK' or press Enter for default): ").strip()
        if not query:
            query = "port:22 country:PK"
        from scrapers.shodan_scraper import search_shodan
        search_shodan(query)

    if choice in ["2", "3", "5"]:
        from scrapers.pastebin_scraper import scrape_pastebin
        scrape_pastebin()

    if choice in ["4", "5"]:
        console.print("\n[green][+] Dashboard running at http://127.0.0.1:5000[/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        from dashboard.app import run_dashboard
        run_dashboard()

if __name__ == "__main__":
    main()
