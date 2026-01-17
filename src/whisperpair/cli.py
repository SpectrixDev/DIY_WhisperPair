"""
WhisperPair CLI - Command-line interface for Fast Pair security research
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
from rich import print as rprint

console = Console()


BANNER = """
[bold red]╦ ╦╦ ╦╦╔═╗╔═╗╔═╗╦═╗╔═╗╔═╗╦╦═╗[/bold red]
[bold red]║║║╠═╣║╚═╗╠═╝║╣ ╠╦╝╠═╝╠═╣║╠╦╝[/bold red]
[bold red]╚╩╝╩ ╩╩╚═╝╩  ╚═╝╩╚═╩  ╩ ╩╩╩╚═[/bold red]

[dim]Google Fast Pair Security Research Tool[/dim]
[dim]CVE-2025-36911 - For authorized testing only[/dim]
"""


def print_banner():
    console.print(Panel(BANNER, border_style="red"))


def _handle_bluetooth_error(e: Exception) -> None:
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


@click.group()
@click.version_option(version="0.1.0")
def main():
    """WhisperPair - Fast Pair Security Research Tool"""
    pass


@main.command()
@click.option("--timeout", "-t", default=10.0, help="Scan timeout in seconds")
@click.option("--all", "-a", "scan_all", is_flag=True, help="Scan all BLE devices")
@click.option("--vulnerable", "-v", is_flag=True, help="Only show potentially vulnerable devices")
def scan(timeout: float, scan_all: bool, vulnerable: bool):
    """Scan for Fast Pair devices"""
    print_banner()

    async def do_scan():
        from bleak.exc import BleakError
        from .scanner import FastPairScanner, find_vulnerable_devices

        devices = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning for Fast Pair devices ({timeout}s)...",
                total=None,
            )

            try:
                if vulnerable:
                    devices = await find_vulnerable_devices(timeout=timeout, verbose=False)
                else:
                    scanner = FastPairScanner(timeout=timeout)
                    if scan_all:
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

        table = Table(title="Fast Pair Devices Found")
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Model ID", style="magenta")
        table.add_column("RSSI", justify="right")
        table.add_column("Mode", style="yellow")
        table.add_column("Vulnerable?", style="red")

        for device in devices:
            model_id = f"0x{device.model_id:06X}" if device.model_id else "N/A"
            mode = "[green]PAIRING[/green]" if device.is_in_pairing_mode else "[dim]Idle[/dim]"
            vuln = "[red]LIKELY[/red]" if not device.is_in_pairing_mode else "[dim]N/A[/dim]"

            table.add_row(
                device.address,
                device.name or device.model_name,
                model_id,
                f"{device.rssi} dBm",
                mode,
                vuln,
            )

        console.print(table)
        console.print(f"\n[bold]Found {len(devices)} device(s)[/bold]")

        if not vulnerable:
            idle_count = sum(1 for d in devices if not d.is_in_pairing_mode)
            if idle_count:
                console.print(
                    f"[yellow]⚠ {idle_count} device(s) advertising while NOT in pairing mode "
                    f"(potential WhisperPair targets)[/yellow]"
                )

    asyncio.run(do_scan())


@main.command(name="verify")
@click.argument("address")
@click.option("--key", "-k", help="AES key (hex) or Account Key file")
@click.option("--timeout", "-t", default=10.0, help="Connection timeout")
@click.option("--seeker-address", "-s", help="Seeker's Bluetooth address (optional)")
@click.option("--authorized", is_flag=True, help="Confirm you own the device and accept responsibility")
@click.option("--no-confirm", is_flag=True, help="Skip interactive confirmation")
def verify(address: str, key: Optional[str], timeout: float, seeker_address: Optional[str], authorized: bool, no_confirm: bool):
    print_banner()

    console.print(f"[bold]Target:[/bold] {address}")

    if not authorized:
        console.print("[red]Refusing to run without explicit consent flag.[/red]")
        console.print("Use --authorized to confirm you own the device and accept responsibility.")
        sys.exit(2)

    if not no_confirm:
        response = console.input("Type 'I AM AUTHORIZED' to continue: ")
        if response.strip() != "I AM AUTHORIZED":
            console.print("[red]Authorization confirmation failed.[/red]")
            sys.exit(2)

    if not key:
        console.print(
            "[yellow]⚠ No AES key provided. Using test key (will likely fail).[/yellow]"
        )
        console.print(
            "[dim]To get real keys, you need the device's Anti-Spoofing public key "
            "(from Google's database) or an existing Account Key.[/dim]"
        )
        aes_key = bytes(16)
    else:
        try:
            aes_key = bytes.fromhex(key.replace(":", "").replace(" ", ""))
            if len(aes_key) != 16:
                raise ValueError("Key must be 16 bytes")
        except ValueError as e:
            console.print(f"[red]Invalid key: {e}[/red]")
            sys.exit(1)

    async def do_verify():
        from .client import FastPairClient, VerificationResult
        from .protocol import parse_bluetooth_address

        seeker_addr_bytes = None
        if seeker_address:
            try:
                seeker_addr_bytes = parse_bluetooth_address(seeker_address)
            except ValueError as e:
                console.print(f"[red]Invalid seeker address: {e}[/red]")
                return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Connecting to target...", total=None)

            try:
                client = FastPairClient(address, connection_timeout=timeout)
                await client.connect()
                progress.update(task, description="[cyan]Connected. Sending verification request...")

                result = await client.verify_pairing_behavior(
                    aes_key=aes_key,
                    seeker_address=seeker_addr_bytes,
                )

                await client.disconnect()

            except Exception as e:
                console.print(f"[red]Connection failed: {e}[/red]")
                return

        if result.success:
            console.print("\n[bold green]✓ VERIFICATION COMPLETE[/bold green]")
            console.print(f"[green]Provider BR/EDR Address: {result.provider_address}[/green]")
            console.print(
                "\n[yellow]Device appears VULNERABLE to CVE-2025-36911[/yellow]"
            )
            console.print(
                "[dim]Next step: Initiate Bluetooth Classic pairing with the Provider address[/dim]"
            )
        else:
            console.print(f"\n[red]✗ Verification failed: {result.error}[/red]")
            console.print(
                "[dim]This could mean: device is patched, wrong key, or not a Fast Pair device[/dim]"
            )

    asyncio.run(do_verify())


@main.command()
@click.argument("address")
@click.option("--timeout", "-t", default=10.0, help="Connection timeout")
def info(address: str, timeout: float):
    """Get detailed information about a Fast Pair device"""
    print_banner()

    async def do_info():
        from .client import FastPairClient
        from .constants import (
            MODEL_ID_CHAR_UUID,
            KEY_BASED_PAIRING_CHAR_UUID,
            ACCOUNT_KEY_CHAR_UUID,
            PASSKEY_CHAR_UUID,
            KNOWN_MODEL_IDS,
        )

        console.print(f"[bold]Connecting to {address}...[/bold]")

        try:
            client = FastPairClient(address, connection_timeout=timeout)
            await client.connect()

            table = Table(title=f"Device Information: {address}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            model_id = await client.read_model_id()
            if model_id:
                model_name = KNOWN_MODEL_IDS.get(model_id, "Unknown")
                table.add_row("Model ID", f"0x{model_id:06X}")
                table.add_row("Model Name", model_name)
            else:
                table.add_row("Model ID", "[dim]Could not read[/dim]")

            char_table = Table(title="Fast Pair Characteristics")
            char_table.add_column("Characteristic", style="cyan")
            char_table.add_column("UUID", style="dim")
            char_table.add_column("Present", style="yellow")

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
                    props = ", ".join(char.properties) if char else ""
                except Exception:
                    present = "[yellow]?[/yellow]"
                    props = ""
                char_table.add_row(name, uuid[:20] + "...", present)

            await client.disconnect()

            console.print(table)
            console.print()
            console.print(char_table)

        except Exception as e:
            console.print(f"[red]Failed to connect: {e}[/red]")

    asyncio.run(do_info())


@main.command()
def demo():
    print_banner()

    console.print(Panel(
        """
[bold cyan]WhisperPair Verification Walkthrough[/bold cyan]

This demo explains the verification flow without targeting devices.

[bold]1. Discovery Phase[/bold]
   Scan for BLE devices advertising Fast Pair Service (0xFE2C)
   Devices advertising while NOT in pairing mode are potential concerns

[bold]2. Connection Phase[/bold]
   Connect to target's GATT server
   No special hardware required - standard Bluetooth adapter works

[bold]3. Verification Phase (CVE-2025-36911)[/bold]
   Write Key-based Pairing Request to characteristic:
   UUID: FE2C1234-8366-4814-8EB0-01DE32100BEA
   
   [red]VULNERABILITY:[/red] Device should check if in pairing mode, but doesn't
   Vulnerable device responds and initiates Bluetooth pairing

[bold]4. Pairing Completion (Prevented)[/bold]
   This tool stops here. In a real attack, the attacker would
   complete Bluetooth Classic pairing and establish audio connection.

[bold yellow]Affected Devices Include:[/bold yellow]
   • Google Pixel Buds Pro 2
   • Sony WF-1000XM4, WH-1000XM5
   • JBL Tune Buds, Live Pro 2
   • Anker Soundcore Liberty 4
   • Many more...

[dim]Reference: https://whisperpair.eu[/dim]
""",
        title="Verification Flow",
        border_style="red",
    ))

    console.print("\n[bold]Commands:[/bold]")
    console.print("  [cyan]whisperpair scan[/cyan]          - Find Fast Pair devices")
    console.print("  [cyan]whisperpair scan -v[/cyan]       - Find potentially vulnerable devices")
    console.print("  [cyan]whisperpair info ADDR[/cyan]     - Get device information")
    console.print("  [cyan]whisperpair verify ADDR[/cyan]   - Verify Fast Pair behavior")



if __name__ == "__main__":
    main()
