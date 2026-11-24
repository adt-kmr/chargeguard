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
        "[bold blue]ChargeGuard[/bold blue] [green]v1.1.0[/green]\n"
        "EV Charger Security Verification System",
        border_style="blue",
        safe_box=True,
    ))

    console.print("\n[bold]>> Phase 1 - Provisioning node (firmware, audit, enrolment)...[/bold]")
    from firmware.provision import provision
    summary = provision()
    console.print(f"  [green]OK[/green] {summary.firmware} vendor-signed firmware images registered")
    console.print(f"  [green]OK[/green] Firmware audited once: {summary.cves} known CVEs cached by image hash")
    console.print(f"  [green]OK[/green] {summary.identities} charger identity and "
                  f"{summary.attestation_keys} TPM attestation key enrolled")
    console.print(f"  [green]OK[/green] {summary.measurements} golden measured-boot values (PCR0) recorded")

    console.print("\n[bold]>> Phase 2 - Verifying compliance policy...[/bold]")
    from policy.mapper import get_all_controls
    controls = get_all_controls()
    total_controls = sum(len(v) for v in controls.values())
    console.print(f"  [green]OK[/green] {total_controls} compliance controls mapped "
                  f"(UNECE R155/R156, ETSI EN 303 645, ISA/IEC 62443-4-2, NIST SP 800-193)")

    return console


def main():
    console = setup()

    console.print("\n[bold]>> Phase 3 - Starting gateway and dashboard...[/bold]")
    from config import OCPP_HOST, OCPP_PORT, OCPP_PATH, FLOW_SENSOR_PORT
    from advisor import Advisor
    console.print(f"  [green]OK[/green] OCPP 1.6 gateway -> ws://{OCPP_HOST}:{OCPP_PORT}{OCPP_PATH}/<charger-id>")
    console.print(f"  [green]OK[/green] Flow collector -> udp/{FLOW_SENSOR_PORT}")
    console.print(f"  [green]OK[/green] Advisor engine -> {Advisor().engine_name}")
    import os as _os
    console.print(f"  [green]OK[/green] Dashboard -> http://localhost:{_os.environ.get('CHARGEGUARD_PORT', '8000')}")
    console.print(
        "\n[dim]  Press Ctrl+C to stop the server.[/dim]\n"
    )

    # Open browser after short delay (set CHARGEGUARD_NO_BROWSER=1 to skip, e.g. on a headless Pi)
    import os, threading, time
    port = int(os.environ.get("CHARGEGUARD_PORT", "8000"))
    if not os.environ.get("CHARGEGUARD_NO_BROWSER"):
        def open_browser():
            time.sleep(1.5)
            webbrowser.open(f"http://localhost:{port}")
        threading.Thread(target=open_browser, daemon=True).start()

    # Start FastAPI
    import uvicorn
    uvicorn.run(
        "dashboard.main:app",
        host="127.0.0.1",
        port=port,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
