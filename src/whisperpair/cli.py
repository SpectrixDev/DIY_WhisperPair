"""
WhisperPair CLI - Interactive security research tool for Fast Pair vulnerability testing
CVE-2025-36911 - For authorized testing only
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns
from rich import box

console = Console()


BANNER = """
[bold red]╦ ╦╦ ╦╦╔═╗╔═╗╔═╗╦═╗╔═╗╔═╗╦╦═╗[/bold red]
[bold red]║║║╠═╣║╚═╗╠═╝║╣ ╠╦╝╠═╝╠═╣║╠╦╝[/bold red]
[bold red]╚╩╝╩ ╩╩╚═╝╩  ╚═╝╩╚═╩  ╩ ╩╩╩╚═[/bold red]

[bold cyan]Google Fast Pair Security Research Tool[/bold cyan]
[dim]CVE-2025-36911 Reference Implementation, by SpectrixDev[/dim]
"""

LEGAL_WARNING = """
[bold yellow]⚠ LEGAL WARNING: RESEARCH ONLY[/bold yellow]

[bold]UNAUTHORIZED ACCESS IS ILLEGAL.[/bold]
Ensure you have permission or ownership before testing.
"""


def print_banner():
    """Display the application banner."""
    console.print(Panel(BANNER, border_style="red", padding=(0, 2)))


def print_legal_warning():
    """Display legal warning panel."""
    console.print(Panel(LEGAL_WARNING, border_style="yellow", padding=(0, 2)))


def clear_screen():
    """Clear terminal screen."""
    console.clear()


def _handle_bluetooth_error(e: Exception) -> None:
    """Handle Bluetooth-related errors with helpful messages."""
    error_str = str(e).lower()

    if "no bluetooth" in error_str or "not available" in error_str:
        console.print("\n[bold red]ERROR: No Bluetooth adapter found![/bold red]")
        console.print("\n[yellow]Possible causes:[/yellow]")
        console.print("  1. No Bluetooth hardware present")
        console.print("  2. Bluetooth adapter is disabled")
        console.print("  3. BlueZ service not running (Linux)")
        console.print("\n[cyan]Troubleshooting steps:[/cyan]")
        console.print("  [dim]Linux:[/dim]")
        console.print("    • Check adapter: [green]hciconfig[/green] or [green]bluetoothctl show[/green]")
        console.print("    • Enable adapter: [green]sudo hciconfig hci0 up[/green]")
        console.print("    • Start BlueZ: [green]sudo systemctl start bluetooth[/green]")
        console.print("    • Check USB adapter: [green]lsusb | grep -i bluetooth[/green]")
        console.print("  [dim]macOS:[/dim]")
        console.print("    • System Preferences → Bluetooth → Turn On")
        console.print("  [dim]Windows:[/dim]")
        console.print("    • Settings → Bluetooth & devices → Turn on")
    else:
        console.print(f"\n[red]Bluetooth error: {e}[/red]")


def show_main_menu() -> str:
    """Display the main menu and return user choice."""
    console.print()
    console.print(Rule("[bold cyan]Main Menu[/bold cyan]", style="cyan"))
    console.print()

    menu_items = [
        ("1", "Scan", "Discover Fast Pair devices nearby", "green"),
        ("2", "Verify", "Test device vulnerability (requires authorization)", "yellow"),
        ("3", "Info", "Get detailed device information", "cyan"),
        ("4", "About", "Learn about CVE-2025-36911 & how verification works", "magenta"),
        ("0", "Exit", "Quit the application", "dim"),
    ]

    for key, name, desc, color in menu_items:
        if key == "0":
            console.print()
        console.print(f"  [{color}][bold]{key}[/bold][/{color}]  [{color}]{name}[/{color}]  [dim]{desc}[/dim]")

    console.print()
    choice = Prompt.ask(
        "[bold]Select option[/bold]",
        choices=["0", "1", "2", "3", "4"],
        default="1"
    )
    return choice


def show_scan_menu() -> dict:
    """Show scan options and return configuration."""
    console.print()
    console.print(Rule("[bold green]Scan Configuration[/bold green]", style="green"))
    console.print()

    console.print("[dim]Scan modes:[/dim]")
    console.print("  [bold]1[/bold]  Fast Pair devices only [dim](recommended)[/dim]")
    console.print("  [bold]2[/bold]  Potentially vulnerable devices [dim](not in pairing mode)[/dim]")
    console.print("  [bold]3[/bold]  All BLE devices")
    console.print("  [bold]0[/bold]  Back to main menu")
    console.print()

    mode = Prompt.ask("[bold]Select scan mode[/bold]", choices=["0", "1", "2", "3"], default="1")

    if mode == "0":
        return {"cancel": True}

    timeout = IntPrompt.ask("[bold]Scan timeout (seconds)[/bold]", default=10)

    return {
        "cancel": False,
        "mode": mode,
        "timeout": float(timeout),
        "vulnerable_only": mode == "2",
        "scan_all": mode == "3",
    }


async def run_scan(config: dict):
    """Execute the scan with given configuration."""
    from bleak.exc import BleakError
    from .scanner import FastPairScanner, find_vulnerable_devices

    devices = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning for devices ({config['timeout']}s)...",
            total=None,
        )

        try:
            if config["vulnerable_only"]:
                devices = await find_vulnerable_devices(timeout=config["timeout"], verbose=False)
            else:
                scanner = FastPairScanner(timeout=config["timeout"])
                if config["scan_all"]:
                    devices = await scanner.scan_all_ble()
                else:
                    devices = await scanner.scan()
        except BleakError as e:
            progress.stop()
            _handle_bluetooth_error(e)
            return

    if not devices:
        console.print("[yellow]No Fast Pair devices found.[/yellow]")
        return

    table = Table(title="Discovered Devices", box=box.ROUNDED)
    table.add_column("#", style="dim", width=3)
    table.add_column("Address", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Model ID", style="magenta")
    table.add_column("RSSI", justify="right")
    table.add_column("Mode", style="yellow")
    table.add_column("Risk", style="red")

    for idx, device in enumerate(devices, 1):
        model_id = f"0x{device.model_id:06X}" if device.model_id else "N/A"
        mode = "[green]PAIRING[/green]" if device.is_in_pairing_mode else "[dim]Idle[/dim]"
        risk = "[red]HIGH[/red]" if not device.is_in_pairing_mode else "[dim]Low[/dim]"

        # Use Text() to prevent Rich from interpreting MAC address colons as emoji codes (e.g. :AB: -> 🆎)
        addr_text = Text(device.address)
        
        table.add_row(
            str(idx),
            addr_text,
            device.name or device.model_name,
            model_id,
            f"{device.rssi} dBm",
            mode,
            risk,
        )

    console.print()
    console.print(table)
    console.print(f"\n[bold]Found {len(devices)} device(s)[/bold]")

    idle_count = sum(1 for d in devices if not d.is_in_pairing_mode)
    if idle_count:
        console.print(
            f"[yellow]⚠ {idle_count} device(s) advertising while NOT in pairing mode[/yellow]"
        )
        console.print("[dim]These may be vulnerable to CVE-2025-36911[/dim]")

    # Clipboard copy option
    console.print()
    copy_choice = Prompt.ask(
        "[bold]Enter device # to copy address (or 0 to continue)[/bold]", 
        choices=[str(i) for i in range(len(devices) + 1)],
        default="0",
        show_choices=False
    )
    
    if copy_choice != "0":
        selected_device = devices[int(copy_choice) - 1]
        try:
            import pyperclip
            pyperclip.copy(selected_device.address)
            console.print(f"[green]Copied {selected_device.address} to clipboard![/green]")
        except ImportError:
            console.print("[red]pyperclip not installed. Install it to use clipboard features.[/red]")
        except Exception as e:
            console.print(f"[red]Clipboard copy failed: {e}[/red]")
            console.print("[dim]On Linux, you may need 'xclip' or 'xsel' installed.[/dim]")


def show_verify_menu() -> dict:
    """Show verification options and handle authorization."""
    console.print()
    console.print(Rule("[bold yellow]Vulnerability Verification[/bold yellow]", style="yellow"))
    console.print()

    print_legal_warning()

    console.print()
    address = Prompt.ask("[bold]Enter target device address[/bold] [dim](e.g., AA:BB:CC:DD:EE:FF)[/dim]")

    if not address or len(address) < 17:
        console.print("[red]Invalid address format.[/red]")
        return {"cancel": True}

    console.print()
    use_key = Confirm.ask("[bold]Do you have an AES key?[/bold]", default=False)
    aes_key = None
    if use_key:
        key_input = Prompt.ask("[bold]Enter AES key (hex)[/bold]")
        try:
            aes_key = bytes.fromhex(key_input.replace(":", "").replace(" ", ""))
            if len(aes_key) != 16:
                console.print("[red]Key must be 16 bytes. Using test key.[/red]")
                aes_key = None
        except ValueError:
            console.print("[red]Invalid hex. Using test key.[/red]")
            aes_key = None

    return {
        "cancel": False,
        "address": address.upper(),
        "aes_key": aes_key,
    }


async def run_verify(config: dict):
    """Execute vulnerability verification."""
    from .client import FastPairClient
    from .protocol import parse_bluetooth_address

    address = config["address"]
    aes_key = config["aes_key"]

    if not aes_key:
        console.print("[cyan]No AES key provided - using response-detection mode.[/cyan]")
        console.print("[dim]The CVE doesn't require the key: any response = vulnerable.[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Connecting to target...", total=None)

        try:
            client = FastPairClient(address, connection_timeout=10.0)
            await client.connect()
            progress.update(task, description="[cyan]Connected. Sending verification request...")

            result = await client.verify_pairing_behavior(aes_key=aes_key)
            await client.disconnect()

        except Exception as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return

    console.print()
    if result.success:
        provider_info = f"[bold]Provider Address:[/bold] {result.provider_address}" if result.provider_address else "[dim]Provider address: (could not decrypt - key not provided)[/dim]"
        console.print(Panel(
            f"""
[bold red]⚠  VULNERABLE[/bold red]

Device responded to Key-based Pairing Request while NOT in pairing mode.

[bold]Target:[/bold] {address}
{provider_info}
[bold]Raw Response:[/bold] {result.raw_response.hex() if result.raw_response else 'N/A'}

[yellow]This device is vulnerable to CVE-2025-36911.[/yellow]
[dim]An attacker could complete standard Bluetooth pairing to hijack this device.[/dim]
""",
            title="[bold red]Verification Result[/bold red]",
            border_style="red",
        ))
    else:
        console.print(Panel(
            f"""
[bold green]✓  NOT VULNERABLE[/bold green]

Device did not respond to Key-based Pairing Request.

[bold]Target:[/bold] {address}
[bold]Details:[/bold] {result.error}

[dim]The device correctly ignored the pairing request (patched or not reachable).[/dim]
""",
            title="[bold green]Verification Result[/bold green]",
            border_style="green",
        ))


def show_info_menu() -> dict:
    """Show device info options."""
    console.print()
    console.print(Rule("[bold cyan]Device Information[/bold cyan]", style="cyan"))
    console.print()

    address = Prompt.ask(
        "[bold]Enter device address[/bold] [dim](e.g., AA:BB:CC:DD:EE:FF)[/dim]"
    )

    if not address or len(address) < 17:
        console.print("[red]Invalid address format.[/red]")
        return {"cancel": True}

    return {"cancel": False, "address": address.upper()}


async def run_info(config: dict):
    """Get device information."""
    from .client import FastPairClient
    from .constants import (
        MODEL_ID_CHAR_UUID,
        KEY_BASED_PAIRING_CHAR_UUID,
        ACCOUNT_KEY_CHAR_UUID,
        PASSKEY_CHAR_UUID,
        KNOWN_MODEL_IDS,
    )

    address = config["address"]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]Connecting to {address}...", total=None)

        try:
            client = FastPairClient(address, connection_timeout=10.0)
            await client.connect()

            table = Table(title=f"Device: {address}", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            model_id = await client.read_model_id()
            if model_id:
                model_name = KNOWN_MODEL_IDS.get(model_id, "Unknown")
                table.add_row("Model ID", f"0x{model_id:06X}")
                table.add_row("Model Name", model_name)
            else:
                table.add_row("Model ID", "[dim]Could not read[/dim]")

            char_table = Table(title="Fast Pair Characteristics", box=box.SIMPLE)
            char_table.add_column("Characteristic", style="cyan")
            char_table.add_column("UUID", style="dim")
            char_table.add_column("Present", justify="center")

            chars_to_check = [
                ("Model ID", MODEL_ID_CHAR_UUID),
                ("Key-based Pairing", KEY_BASED_PAIRING_CHAR_UUID),
                ("Passkey", PASSKEY_CHAR_UUID),
                ("Account Key", ACCOUNT_KEY_CHAR_UUID),
            ]

            for name, uuid in chars_to_check:
                try:
                    char = client._client.services.get_characteristic(uuid)
                    present = "[green]✓[/green]" if char else "[red]✗[/red]"
                except Exception:
                    present = "[yellow]?[/yellow]"
                char_table.add_row(name, uuid[:20] + "...", present)

            await client.disconnect()

            console.print()
            console.print(table)
            console.print()
            console.print(char_table)

        except Exception as e:
            console.print(f"[red]Failed to connect: {e}[/red]")


def show_about():
    """Display vulnerability info and verification walkthrough."""
    console.print()
    console.print(Rule("[bold magenta]About CVE-2025-36911[/bold magenta]", style="magenta"))
    console.print()

    console.print(Panel(
        """[bold]The Vulnerability[/bold]

Google Fast Pair requires devices to [bold]only accept pairing requests 
when in pairing mode[/bold]. Many devices fail this check:

[green]EXPECTED:[/green] "Am I in pairing mode?" → NO → Reject request
[red]ACTUAL:[/red]   Accepts request regardless of mode state

[bold]Impact:[/bold] Attacker within ~10-14m can:
  • Play audio through victim's headphones
  • Access microphone for surveillance  
  • Track location via Google Find Hub

[bold]Affected devices:[/bold] Pixel Buds Pro 2, Sony WF/WH-1000XM series,
JBL Tune/Live series, Anker Soundcore, and many more.

[green]Patches are available[/green] - update your device firmware!""",
        title="[bold]What is WhisperPair?[/bold]",
        border_style="magenta",
        padding=(1, 2),
    ))

    console.print()

    console.print(Panel(
        """[bold]Phase 1: Discovery[/bold] [dim](Passive)[/dim]
   Scan for devices advertising Fast Pair Service (UUID: 0xFE2C)
   Devices advertising while NOT in pairing mode are potential targets

[bold]Phase 2: Connection[/bold] [dim](Standard BLE)[/dim]
   Establish GATT connection - any Bluetooth adapter works

[bold]Phase 3: Verification[/bold] [dim](Active - Requires Authorization)[/dim]
   Write Key-based Pairing Request to: FE2C1234-8366-4814-8EB0-01DE32100BEA
   
   [bold red]THE BUG:[/bold red] Device should reject if not in pairing mode
   
   [bold cyan]KEY INSIGHT:[/bold cyan] The AES key is NOT required for detection!
   Vulnerable devices respond to ANY request when they shouldn't.
   Getting a response at all = VULNERABLE (response content doesn't matter)
   
   The real attack then completes with standard Bluetooth pairing.

[bold]Phase 4: Result[/bold]
   • Any response received → [red]VULNERABLE[/red]
   • No response / timeout → [green]PATCHED or not reachable[/green]

[yellow]⚠ This tool stops at verification. No pairing. No audio playback.[/yellow]""",
        title="[bold]How Verification Works[/bold]",
        border_style="blue",
        padding=(1, 2),
    ))

    console.print()

    console.print(Panel(
        """[bold]Research:[/bold] KU Leuven DistriNet
[bold]Published:[/bold] January 2026
[bold]Website:[/bold] https://whisperpair.eu
[bold]Severity:[/bold] Critical ($15,000 Google bounty)
[bold]Project Maintainer:[/bold] SpectrixDev

[dim]Responsibly disclosed to Google in August 2025 (150-day window)[/dim]""",
        title="[bold]Credits[/bold]",
        border_style="dim",
        padding=(0, 2),
    ))

    console.print()
    Prompt.ask("[dim]Press Enter to return to main menu[/dim]")


def interactive_loop():
    """Main interactive loop."""
    while True:
        clear_screen()
        print_banner()

        choice = show_main_menu()

        if choice == "0":
            console.print("\n[dim]Goodbye.[/dim]")
            break

        elif choice == "1":
            config = show_scan_menu()
            if not config.get("cancel"):
                asyncio.run(run_scan(config))
                console.print()
                Prompt.ask("[dim]Press Enter to continue[/dim]")

        elif choice == "2":
            config = show_verify_menu()
            if not config.get("cancel"):
                asyncio.run(run_verify(config))
                console.print()
                Prompt.ask("[dim]Press Enter to continue[/dim]")

        elif choice == "3":
            config = show_info_menu()
            if not config.get("cancel"):
                asyncio.run(run_info(config))
                console.print()
                Prompt.ask("[dim]Press Enter to continue[/dim]")

        elif choice == "4":
            show_about()


# =============================================================================
# CLI Entry Points (Click-based for direct command access)
# =============================================================================

@click.group(invoke_without_command=True)
@click.version_option(version="0.1.0")
@click.pass_context
def main(ctx):
    """WhisperPair - Fast Pair Security Research Tool

    Run without arguments for interactive mode, or use subcommands directly.
    """
    if ctx.invoked_subcommand is None:
        interactive_loop()


@main.command()
@click.option("--timeout", "-t", default=10.0, help="Scan timeout in seconds")
@click.option("--all", "-a", "scan_all", is_flag=True, help="Scan all BLE devices")
@click.option("--vulnerable", "-v", is_flag=True, help="Only show potentially vulnerable devices")
def scan(timeout: float, scan_all: bool, vulnerable: bool):
    """Scan for Fast Pair devices"""
    print_banner()
    config = {
        "timeout": timeout,
        "vulnerable_only": vulnerable,
        "scan_all": scan_all,
    }
    asyncio.run(run_scan(config))


@main.command(name="verify")
@click.argument("address")
@click.option("--key", "-k", help="AES key (hex) or Account Key file")
@click.option("--timeout", "-t", default=10.0, help="Connection timeout")
@click.option("--authorized", is_flag=True, help="Confirm you own the device and accept responsibility")
@click.option("--no-confirm", is_flag=True, help="Skip interactive confirmation")
def verify(address: str, key: Optional[str], timeout: float, authorized: bool, no_confirm: bool):
    """Verify Fast Pair vulnerability on a device"""
    print_banner()

    aes_key = None
    if key:
        try:
            aes_key = bytes.fromhex(key.replace(":", "").replace(" ", ""))
            if len(aes_key) != 16:
                raise ValueError("Key must be 16 bytes")
        except ValueError as e:
            console.print(f"[red]Invalid key: {e}[/red]")
            sys.exit(1)

    config = {
        "address": address.upper(),
        "aes_key": aes_key,
    }
    asyncio.run(run_verify(config))


@main.command()
@click.argument("address")
@click.option("--timeout", "-t", default=10.0, help="Connection timeout")
def info(address: str, timeout: float):
    """Get detailed information about a Fast Pair device"""
    print_banner()
    config = {"address": address.upper()}
    asyncio.run(run_info(config))


@main.command()
def about():
    """Learn about CVE-2025-36911 and how verification works"""
    print_banner()
    show_about()


if __name__ == "__main__":
    main()
