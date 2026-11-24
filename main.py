"""
ChargeGuard – Main Entry Point
Run:  python main.py
Opens the dashboard at http://localhost:8000
"""
import sys
import webbrowser
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


def setup():
    """One-time setup: generate firmware images and seed the database."""
    from rich.console import Console
    from rich.panel   import Panel
    console = Console()

    console.print(Panel.fit(
        "[bold blue]ChargeGuard[/bold blue] [green]v1.0.0[/green]\n"
        "EV Charger Security Verification System",
        border_style="blue",
        safe_box=True,
    ))

    console.print("\n[bold]>> Phase 0 - Initialising database...[/bold]")
    from db.database import init_db
    init_db()
    console.print("  [green]OK[/green] SQLite database ready")

    console.print("\n[bold]>> Phase 1 - Generating firmware images...[/bold]")
    from firmware.generator import generate_all
    fw_rows, cve_rows, id_rows = generate_all()
    console.print(f"  [green]OK[/green] {len(fw_rows)} firmware images created")

    console.print("\n[bold]>> Phase 2 - Seeding firmware registry & CVE database...[/bold]")
    from db.database import seed_firmware, seed_cves, seed_identity
    seed_firmware(fw_rows)
    seed_cves(cve_rows)
    seed_identity(id_rows)
    console.print(f"  [green]OK[/green] {len(fw_rows)} firmware entries seeded")
    console.print(f"  [green]OK[/green] {len(cve_rows)} CVE entries seeded")
    console.print(f"  [green]OK[/green] {len(id_rows)} identity entries enrolled")

    console.print("\n[bold]>> Phase 3 - Verifying compliance policy...[/bold]")
    from policy.mapper import get_all_controls
    controls = get_all_controls()
    total_controls = sum(len(v) for v in controls.values())
    console.print(f"  [green]OK[/green] {total_controls} compliance controls mapped "
                  f"(UNECE R155/R156, ETSI EN 303 645, ISA/IEC 62443-4-2)")

    return console


def main():
    console = setup()

    console.print("\n[bold]>> Phase 4 - Starting dashboard server...[/bold]")
    console.print("  [green]OK[/green] Dashboard -> http://localhost:8000")
    console.print(
        "\n[dim]  Press Ctrl+C to stop the server.[/dim]\n"
    )

    # Open browser after short delay
    import threading, time
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://localhost:8000")
    threading.Thread(target=open_browser, daemon=True).start()

    # Start FastAPI
    import uvicorn
    uvicorn.run(
        "dashboard.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
