"""
WhisperPair TUI - CVE-2025-36911 Verification Tool
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, Center, ScrollableContainer
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    LoadingIndicator,
    Static,
    TabbedContent,
    TabPane,
)


class ConfirmationModal(ModalScreen[bool]):
    
    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self.title_text = title
        self.message_text = message
    
    def compose(self) -> ComposeResult:
        yield Container(
            Static(self.title_text, id="confirm-title"),
            Static(self.message_text, id="confirm-message"),
            Horizontal(
                Button("Confirm", id="confirm-yes", variant="warning"),
                Button("Cancel", id="confirm-no", variant="primary"),
                id="confirm-buttons",
            ),
            id="confirm-dialog",
        )
    
    @on(Button.Pressed, "#confirm-yes")
    def confirm_yes(self) -> None:
        self.dismiss(True)
    
    @on(Button.Pressed, "#confirm-no")
    def confirm_no(self) -> None:
        self.dismiss(False)


class MainScreen(Screen):
    
    BINDINGS = [
        Binding("s", "scan", "Scan"),
        Binding("q", "quit", "Quit"),
    ]
    
    def __init__(self) -> None:
        super().__init__()
        self.devices: list = []
        self.is_scanning = False
        self.selected_device = None
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            with TabbedContent():
                with TabPane("Scan", id="tab-scan"):
                    yield Vertical(
                        Static("[bold red]DEVICE SCANNER[/]", classes="panel-title"),
                        Static("Scan for Fast Pair devices. Devices NOT in pairing mode may be vulnerable.", classes="label-dim"),
                        Horizontal(
                            Button("Start Scan", id="btn-scan", variant="primary"),
                            Button("Scan Vulnerable Only", id="btn-scan-vuln", variant="warning"),
                            Button("Clear", id="btn-clear", variant="default"),
                            classes="button-row",
                        ),
                        Container(
                            Static("Ready to scan. Press 'Start Scan' to begin.", id="scan-status"),
                            LoadingIndicator(id="scan-loader"),
                            id="scan-status-container",
                        ),
                        DataTable(id="device-table"),
                        Horizontal(
                            Button("Device Info", id="btn-info", variant="primary", disabled=True),
                            Button("Verify Selected", id="btn-verify", variant="warning", disabled=True),
                            classes="button-row",
                        ),
                        id="scan-panel",
                    )
                with TabPane("Verify", id="tab-verify"):
                    yield Vertical(
                        Static("[bold red]VULNERABILITY VERIFICATION[/]", classes="panel-title"),
                        Static("Verify if a specific device is vulnerable to CVE-2025-36911", classes="label-dim"),
                        Container(
                            Static("Target Device Address:"),
                            Input(placeholder="AA:BB:CC:DD:EE:FF", id="verify-address"),
                            id="verify-input-container",
                        ),
                        Horizontal(
                            Button("Verify Device", id="btn-verify-addr", variant="warning"),
                            classes="button-row",
                        ),
                        Container(Static("", id="verify-result"), id="verify-result-container"),
                        id="verify-panel",
                    )
                with TabPane("Learn", id="tab-learn"):
                    yield ScrollableContainer(
                        Static(EDUCATION_CONTENT, id="education-content"),
                        id="education-panel",
                    )
                with TabPane("About", id="tab-about"):
                    yield ScrollableContainer(
                        Static(ABOUT_CONTENT, id="about-content"),
                        id="about-panel",
                    )
        yield Footer()
    
    def on_mount(self) -> None:
        table = self.query_one("#device-table", DataTable)
        table.add_columns("Address", "Name", "Model ID", "RSSI", "Mode", "Status")
        table.cursor_type = "row"
        self.query_one("#scan-loader").display = False
    
    @on(Button.Pressed, "#btn-scan")
    def start_scan(self) -> None:
        self._do_scan(vulnerable_only=False)
    
    @on(Button.Pressed, "#btn-scan-vuln")
    def start_scan_vulnerable(self) -> None:
        self._do_scan(vulnerable_only=True)
    
    @work(exclusive=True)
    async def _do_scan(self, vulnerable_only: bool = False) -> None:
        if self.is_scanning:
            return
        
        self.is_scanning = True
        status = self.query_one("#scan-status", Static)
        loader = self.query_one("#scan-loader")
        table = self.query_one("#device-table", DataTable)
        
        loader.display = True
        status.update("[bold blue]Scanning for devices (10s)...[/]")
        self.query_one("#btn-scan", Button).disabled = True
        self.query_one("#btn-scan-vuln", Button).disabled = True
        
        try:
            from .scanner import FastPairScanner, find_vulnerable_devices
            
            if vulnerable_only:
                devices = await find_vulnerable_devices(timeout=10.0)
            else:
                scanner = FastPairScanner(timeout=10.0)
                devices = await scanner.scan()
            
            self.devices = devices
            table.clear()
            
            for device in devices:
                model_id = f"0x{device.model_id:06X}" if device.model_id else "N/A"
                mode = "PAIRING" if device.is_in_pairing_mode else "Idle"
                vuln_status = "N/A" if device.is_in_pairing_mode else "LIKELY VULNERABLE"
                
                table.add_row(
                    device.address,
                    device.name or device.model_name,
                    model_id,
                    f"{device.rssi} dBm",
                    mode,
                    vuln_status,
                )
            
            if devices:
                status.update(f"[bold green]Found {len(devices)} device(s)[/]")
            else:
                status.update("[yellow]No Fast Pair devices found[/]")
                
        except ImportError:
            status.update("[bold red]Error: bleak not installed. Run: pip install bleak[/]")
        except Exception as e:
            error_msg = str(e).lower()
            if "bluetooth" in error_msg or "adapter" in error_msg:
                status.update("[bold red]No Bluetooth adapter found or disabled[/]")
            else:
                status.update(f"[bold red]Error: {e}[/]")
        finally:
            self.is_scanning = False
            loader.display = False
            self.query_one("#btn-scan", Button).disabled = False
            self.query_one("#btn-scan-vuln", Button).disabled = False
    
    @on(Button.Pressed, "#btn-clear")
    def clear_results(self) -> None:
        table = self.query_one("#device-table", DataTable)
        table.clear()
        self.devices = []
        self.query_one("#scan-status", Static).update("Ready to scan.")
        self.query_one("#btn-info", Button).disabled = True
        self.query_one("#btn-verify", Button).disabled = True
    
    @on(DataTable.RowSelected)
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is not None:
            self.query_one("#btn-info", Button).disabled = False
            self.query_one("#btn-verify", Button).disabled = False
            self.selected_device = event.row_key
    
    @on(Button.Pressed, "#btn-info")
    async def show_device_info(self) -> None:
        if self.selected_device is None or not self.devices:
            return
        
        table = self.query_one("#device-table", DataTable)
        row_idx = table.get_row_index(self.selected_device)
        if row_idx < len(self.devices):
            device = self.devices[row_idx]
            await self.app.push_screen(DeviceInfoScreen(device))
    
    @on(Button.Pressed, "#btn-verify")
    async def verify_selected_device(self) -> None:
        if self.selected_device is None or not self.devices:
            return
        
        table = self.query_one("#device-table", DataTable)
        row_idx = table.get_row_index(self.selected_device)
        if row_idx < len(self.devices):
            device = self.devices[row_idx]
            confirmed = await self.app.push_screen_wait(
                ConfirmationModal(
                    "Confirm Verification",
                    f"Verify {device.name} ({device.address})?\n\nOnly proceed if you OWN this device.",
                )
            )
            if confirmed:
                await self.app.push_screen(VerificationScreen(device.address))
    
    @on(Button.Pressed, "#btn-verify-addr")
    async def verify_address(self) -> None:
        address = self.query_one("#verify-address", Input).value.strip()
        if not address:
            self.query_one("#verify-result", Static).update("[bold red]Enter a valid Bluetooth address[/]")
            return
        
        confirmed = await self.app.push_screen_wait(
            ConfirmationModal(
                "Confirm Verification",
                f"Verify {address}?\n\nOnly proceed if you OWN this device.",
            )
        )
        if confirmed:
            await self.app.push_screen(VerificationScreen(address))
    
    def action_scan(self) -> None:
        self.query_one("#btn-scan", Button).press()
    
    def action_quit(self) -> None:
        self.app.exit()


class DeviceInfoScreen(Screen):
    
    BINDINGS = [Binding("escape", "back", "Back")]
    
    def __init__(self, device) -> None:
        super().__init__()
        self.device = device
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Static("[bold red]DEVICE INFORMATION[/]", classes="panel-title"),
            Vertical(
                Static(f"[bold]Name:[/] {self.device.name or 'Unknown'}"),
                Static(f"[bold]Address:[/] {self.device.address}"),
                Static(f"[bold]Model ID:[/] 0x{self.device.model_id:06X}" if self.device.model_id else "[bold]Model ID:[/] N/A"),
                Static(f"[bold]Model Name:[/] {self.device.model_name}"),
                Static(f"[bold]RSSI:[/] {self.device.rssi} dBm"),
                Static(f"[bold]Pairing Mode:[/] {'Yes' if self.device.is_in_pairing_mode else 'No'}"),
                Static(""),
                self._get_vuln_status(),
                id="device-details",
            ),
            Horizontal(
                Button("Verify Device", id="btn-verify-device", variant="warning"),
                Button("Back", id="btn-back", variant="primary"),
                classes="button-row",
            ),
            id="info-container",
        )
        yield Footer()
    
    def _get_vuln_status(self) -> Static:
        if self.device.is_in_pairing_mode:
            return Static("[yellow]Device in pairing mode - vulnerability check N/A[/]", classes="status-box")
        else:
            return Static(
                "[bold red]POTENTIALLY VULNERABLE[/]\n"
                "Device advertising while NOT in pairing mode.\n"
                "Primary indicator of CVE-2025-36911.",
                classes="status-box status-vulnerable",
            )
    
    @on(Button.Pressed, "#btn-back")
    def action_back(self) -> None:
        self.app.pop_screen()
    
    @on(Button.Pressed, "#btn-verify-device")
    async def action_verify(self) -> None:
        confirmed = await self.app.push_screen_wait(
            ConfirmationModal("Confirm", f"Verify {self.device.address}?")
        )
        if confirmed:
            await self.app.push_screen(VerificationScreen(self.device.address))


class VerificationScreen(Screen):
    
    BINDINGS = [Binding("escape", "back", "Back")]
    
    def __init__(self, address: str) -> None:
        super().__init__()
        self.address = address
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Center(
            Container(
                Static("[bold red]VULNERABILITY VERIFICATION[/]", id="verify-title"),
                Static(f"Target: {self.address}", id="verify-target"),
                LoadingIndicator(id="verify-loader"),
                Static("Connecting...", id="verify-status"),
                Container(id="verify-result-box"),
                Horizontal(
                    Button("Back", id="btn-back-dash", variant="primary"),
                    id="verify-actions",
                ),
                id="verify-panel",
            ),
            id="verify-container",
        )
        yield Footer()
    
    def on_mount(self) -> None:
        self.run_verification()
    
    @work(exclusive=True)
    async def run_verification(self) -> None:
        status = self.query_one("#verify-status", Static)
        loader = self.query_one("#verify-loader")
        result_box = self.query_one("#verify-result-box")
        
        try:
            from .client import FastPairClient
            
            status.update("Connecting to device...")
            client = FastPairClient(self.address, connection_timeout=15.0)
            await client.connect()
            
            status.update("Connected. Sending verification request...")
            result = await client.verify_pairing_behavior(aes_key=bytes(16))
            await client.disconnect()
            
            loader.display = False
            
            if result.success:
                status.update("[bold red]VERIFICATION COMPLETE[/]")
                result_box.mount(Static(
                    f"[bold red]VULNERABLE[/]\n\n"
                    f"Device accepted Key-based Pairing Request while NOT in pairing mode.\n"
                    f"Provider Address: {result.provider_address}\n\n"
                    f"[bold]Recommendation:[/] Update firmware immediately.",
                    classes="status-box status-vulnerable",
                ))
            else:
                status.update("[bold green]VERIFICATION COMPLETE[/]")
                result_box.mount(Static(
                    f"[bold green]PATCHED / NOT VULNERABLE[/]\n\n"
                    f"Result: {result.error}\n\n"
                    f"Device correctly rejected the request.",
                    classes="status-box status-patched",
                ))
                
        except ImportError:
            loader.display = False
            status.update("[bold red]Error[/]")
            result_box.mount(Static("[red]Missing: bleak. Run: pip install bleak[/]", classes="status-box"))
        except Exception as e:
            loader.display = False
            status.update("[bold red]Error[/]")
            result_box.mount(Static(f"[red]{e}[/]", classes="status-box"))
    
    @on(Button.Pressed, "#btn-back-dash")
    def action_back(self) -> None:
        self.app.pop_screen()


EDUCATION_CONTENT = """
[bold red]WhisperPair Vulnerability (CVE-2025-36911)[/]

[bold]What is it?[/]
A flaw in Google Fast Pair implementations affecting millions of Bluetooth
audio accessories from Google, Sony, JBL, Anker, and others.

[bold]The Flaw[/]
Devices should ONLY accept pairing requests when in pairing mode.
Vulnerable devices accept requests regardless of mode.

[bold]Attack Impact[/]
Within ~10-14 metres, an attacker can:
  - Hijack audio (play through victim's headphones)
  - Eavesdrop (access microphone)
  - Track location (via Google Find Hub)

[bold]Affected Devices (Pre-Patch)[/]
  - Google Pixel Buds Pro 2
  - Sony WF-1000XM4, WH-1000XM5, LinkBuds S
  - JBL Tune Buds, Live Pro 2
  - Anker Soundcore Liberty 4

[bold]Mitigation[/]
  1. Update firmware immediately
  2. Disable Bluetooth when not needed
  3. Factory reset before selling

[bold]References[/]
  - https://whisperpair.eu
  - CVE-2025-36911
"""

ABOUT_CONTENT = """
[bold red]WhisperPair Verification Tool[/]

[bold]Version:[/] 0.1.0
[bold]CVE:[/] CVE-2025-36911
[bold]Disclosure:[/] Completed (January 2026)

[bold]Purpose[/]
  - Verify if devices are patched
  - Understand the vulnerability
  - Develop detection strategies
  - Security education

[bold]Legal Notice[/]
This tool is for AUTHORIZED USE ONLY.
Using it on devices you don't own is illegal under:
  - UK Computer Misuse Act 1990
  - US CFAA
  - Similar laws in other jurisdictions

[bold]Original Research[/]
KU Leuven (DistriNet)
Paper: "WhisperPair: Hijacking Bluetooth Accessories Using Google Fast Pair"
Google Severity: Critical | Bounty: $15,000

[bold]Disclaimer[/]
This tool does NOT contain exploit code or audio playback.
It only verifies if a device is vulnerable.
"""


class WhisperPairApp(App):
    
    TITLE = "WhisperPair"
    SUB_TITLE = "CVE-2025-36911 Security Research Tool"
    CSS_PATH = "tui.tcss"
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
    ]
    
    def on_mount(self) -> None:
        self.push_screen(MainScreen())


def main():
    console = Console()
    
    console.print(Panel(
        "[bold red]WhisperPair[/] - CVE-2025-36911 Verification Tool\n\n"
        "[yellow]WARNING:[/] This tool performs active Bluetooth operations.\n"
        "Only use on devices you OWN or are AUTHORIZED to test.\n"
        "Unauthorized use is illegal under UK Computer Misuse Act 1990.",
        title="Legal Notice",
        border_style="red",
    ))
    
    response = console.input("\n[bold]Do you accept responsibility? (y/n):[/] ")
    
    if response.lower().strip() not in ("y", "yes"):
        console.print("[red]Exiting.[/]")
        sys.exit(0)
    
    app = WhisperPairApp()
    app.run()


if __name__ == "__main__":
    main()
