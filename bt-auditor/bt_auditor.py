#!/usr/bin/env python3
"""
bt-auditor: Bluetooth Scanning and Security Auditing Tool

A command-line tool for discovering, fingerprinting, and auditing
Bluetooth and BLE devices on macOS and Linux.
"""

import argparse
import json
import csv
import sys
import platform
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class DeviceType(Enum):
    """Known Bluetooth device types based on fingerprinting."""
    UNKNOWN = "Unknown"
    PHONE = "Phone"
    LAPTOP = "Laptop"
    HEADPHONES = "Headphones"
    SPEAKER = "Speaker"
    WATCH = "Watch"
    FITNESS_TRACKER = "Fitness Tracker"
    KEYBOARD = "Keyboard"
    MOUSE = "Mouse"
    BEACON = "Beacon"
    IOT_DEVICE = "IoT Device"
    CAR = "Car System"
    MEDICAL = "Medical Device"


class SecurityFlag(Enum):
    """Security concern flags."""
    HIDDEN_DEVICE = "Hidden Device (No name advertised)"
    UNKNOWN_VENDOR = "Unknown Manufacturer"
    LEGACY_PAIRING = "Legacy Pairing Supported"
    TEST_MODE = "Test/Debug Mode Detected"
    KNOWN_VULNERABLE = "Known Vulnerable Device"
    WEAK_ENCRYPTION = "Weak Encryption"
    OPEN_PAIRING = "Open Pairing Mode"


@dataclass
class BluetoothDevice:
    """Represents a discovered Bluetooth device."""
    mac_address: str
    name: Optional[str] = None
    rssi: Optional[int] = None
    device_class: Optional[int] = None
    services: List[str] = field(default_factory=list)
    manufacturer_data: Dict[int, bytes] = field(default_factory=dict)
    device_type: str = DeviceType.UNKNOWN.value
    flags: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        # Convert manufacturer_data bytes to hex strings
        result['manufacturer_data'] = {
            k: v.hex() if isinstance(v, bytes) else v 
            for k, v in self.manufacturer_data.items()
        }
        return result


# Known service UUIDs for fingerprinting
KNOWN_SERVICES = {
    # Apple
    "0000fe0f-0000-1000-8000-00805f9b34fb": "Apple Continuity",
    "0000fd6f-0000-1000-8000-00805f9b34fb": "Apple Find My",
    # Google
    "0000fe0c-0000-1000-8000-00805f9b34fb": "Google Eddystone",
    "0000fe95-0000-1000-8000-00805f9b34fb": "Google Beacon",
    # Microsoft
    "0000ffe0-0000-1000-8000-00805f9b34fb": "Microsoft HID",
    # Common profiles
    "0000110a-0000-1000-8000-00805f9b34fb": "A/V Remote Control",
    "0000110b-0000-1000-8000-00805f9b34fb": "A/V Remote Control Target",
    "0000110c-0000-1000-8000-00805f9b34fb": "A/V Remote Control Controller",
    "0000110e-0000-1000-8000-00805f9b34fb": "Audio Source",
    "00001112-0000-1000-8000-00805f9b34fb": "Headset Audio Gateway",
    "0000111f-0000-1000-8000-00805f9b34fb": "Hands-Free Audio Gateway",
    "00001124-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "00001132-0000-1000-8000-00805f9b34fb": "Personal Area Network",
}

# Known manufacturer IDs
MANUFACTURER_IDS = {
    0x0006: "Microsoft",
    0x004C: "Apple",
    0x0075: "Samsung",
    0x00E0: "Intel",
    0x01F5: "Fitbit",
    0x02E0: "Garmin",
    0x038B: "Xiaomi",
    0x0059: "Nordic Semiconductor",
    0x00D6: "Dialog Semiconductor",
    0x0113: "Motorola",
    0x0001: "Nokia",
    0x0024: "Sony",
    0x008F: "Broadcom",
    0x00CF: "Qualcomm",
}

# Known vulnerable device signatures (example entries)
VULNERABLE_SIGNATURES = {
    # Add known vulnerable device patterns here
    # Format: (manufacturer_id_prefix, name_pattern)
}


class BluetoothScanner:
    """Base class for Bluetooth scanning."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.devices: Dict[str, BluetoothDevice] = {}
    
    def log(self, message: str):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"[DEBUG] {message}")
    
    def fingerprint_device(self, device: BluetoothDevice) -> BluetoothDevice:
        """Analyze device characteristics to determine type and flags."""
        # Fingerprint device type
        device.device_type = self._identify_device_type(device)
        
        # Check for security flags
        device.flags = self._check_security_flags(device)
        
        return device
    
    def _identify_device_type(self, device: BluetoothDevice) -> str:
        """Identify device type based on services and manufacturer data."""
        services_lower = [s.lower() for s in device.services]
        
        # Check manufacturer data
        for manuf_id, data in device.manufacturer_data.items():
            if manuf_id == 0x004C:  # Apple
                if device.name and any(x in device.name.lower() for x in ['airpods', 'beats']):
                    return DeviceType.HEADPHONES.value
                elif "watch" in (device.name or "").lower():
                    return DeviceType.WATCH.value
            
            elif manuf_id == 0x01F5:  # Fitbit
                return DeviceType.FITNESS_TRACKER.value
            
            elif manuf_id == 0x02E0:  # Garmin
                return DeviceType.FITNESS_TRACKER.value
        
        # Check services
        audio_services = [
            "0000110a", "0000110b", "0000110c", "0000110e",
            "00001112", "0000111f"
        ]
        hid_services = ["00001124"]
        
        if any(s in services_lower for s in audio_services):
            if device.name and any(x in device.name.lower() for x in ['headset', 'earbud', 'speaker']):
                return DeviceType.SPEAKER.value
            return DeviceType.HEADPHONES.value
        
        if any(s in services_lower for s in hid_services):
            if device.name and 'keyboard' in device.name.lower():
                return DeviceType.KEYBOARD.value
            elif device.name and 'mouse' in device.name.lower():
                return DeviceType.MOUSE.value
            return DeviceType.HID.value if hasattr(DeviceType, 'HID') else DeviceType.UNKNOWN.value
        
        # Check for beacons
        beacon_services = [
            "0000fe0c", "0000fe95", "0000fe0f"  # Eddystone, Google, Apple
        ]
        if any(s in services_lower for s in beacon_services):
            return DeviceType.BEACON.value
        
        # Default heuristics based on name
        if device.name:
            name_lower = device.name.lower()
            if any(x in name_lower for x in ['iphone', 'android', 'phone', 'mobile']):
                return DeviceType.PHONE.value
            elif any(x in name_lower for x in ['macbook', 'laptop', 'notebook', 'windows']):
                return DeviceType.LAPTOP.value
            elif any(x in name_lower for x in ['watch', 'wearable']):
                return DeviceType.WATCH.value
            elif any(x in name_lower for x in ['car', 'auto', 'vehicle']):
                return DeviceType.CAR.value
            elif any(x in name_lower for x in ['medical', 'health', 'sensor']):
                return DeviceType.MEDICAL.value
        
        return DeviceType.UNKNOWN.value
    
    def _check_security_flags(self, device: BluetoothDevice) -> List[str]:
        """Check for potential security concerns."""
        flags = []
        
        # Hidden device (no name)
        if not device.name or device.name.strip() == "":
            flags.append(SecurityFlag.HIDDEN_DEVICE.value)
        
        # Unknown vendor
        has_known_vendor = False
        for manuf_id in device.manufacturer_data.keys():
            if manuf_id in MANUFACTURER_IDS:
                has_known_vendor = True
                break
        
        if not has_known_vendor and device.manufacturer_data:
            flags.append(SecurityFlag.UNKNOWN_VENDOR.value)
        
        # Check for test mode indicators in services
        test_mode_services = [
            "0000fff0", "0000fff1", "0000fff2",  # Common test services
            "deadbeef", "cafebabe"  # Example test patterns
        ]
        services_lower = [s.lower() for s in device.services]
        if any(s in services_lower for s in test_mode_services):
            flags.append(SecurityFlag.TEST_MODE.value)
        
        # Check against known vulnerable signatures
        for manuf_id, data in device.manufacturer_data.items():
            for sig_manuf, sig_pattern in VULNERABLE_SIGNATURES:
                if manuf_id == sig_manuf:
                    if device.name and sig_pattern.lower() in device.name.lower():
                        flags.append(SecurityFlag.KNOWN_VULNERABLE.value)
                        break
        
        return flags
    
    def add_or_update_device(self, device: BluetoothDevice) -> None:
        """Add new device or update existing one."""
        mac = device.mac_address.upper()
        
        if mac in self.devices:
            # Update existing device
            existing = self.devices[mac]
            if device.rssi is not None:
                existing.rssi = device.rssi
            if device.name and not existing.name:
                existing.name = device.name
            if device.services:
                existing.services = list(set(existing.services + device.services))
            if device.manufacturer_data:
                existing.manufacturer_data.update(device.manufacturer_data)
            existing.last_seen = datetime.now().isoformat()
            
            # Re-fingerprint with updated info
            self.fingerprint_device(existing)
        else:
            # Add new device
            self.fingerprint_device(device)
            self.devices[mac] = device
    
    def get_devices(self) -> List[BluetoothDevice]:
        """Get list of all discovered devices."""
        return list(self.devices.values())
    
    def clear_devices(self) -> None:
        """Clear all discovered devices."""
        self.devices.clear()


class BleakScanner(BluetoothScanner):
    """BLE scanner using bleak library (cross-platform)."""
    
    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.scanner = None
    
    async def scan_async(self, duration: int = 10) -> List[BluetoothDevice]:
        """Scan for BLE devices asynchronously."""
        try:
            from bleak import BleakScanner
        except ImportError:
            print("Error: bleak library not installed. Run: pip install bleak")
            sys.exit(1)
        
        self.log(f"Starting BLE scan for {duration} seconds...")
        
        def detection_callback(device, advertisement_data):
            """Handle device discovery."""
            mac = device.address
            name = device.name
            
            bt_device = BluetoothDevice(
                mac_address=mac,
                name=name if name else None,
                rssi=device.rssi,
                services=[str(s) for s in advertisement_data.service_uuids],
                manufacturer_data=dict(advertisement_data.manufacturer_data),
            )
            
            self.add_or_update_device(bt_device)
            self.log(f"Found: {mac} - {name or 'Unknown'} (RSSI: {device.rssi})")
        
        scanner = BleakScanner(detection_callback=detection_callback)
        await scanner.start()
        
        # Wait for specified duration
        import asyncio
        await asyncio.sleep(duration)
        
        await scanner.stop()
        self.log(f"Scan complete. Found {len(self.devices)} devices.")
        
        return self.get_devices()
    
    def scan(self, duration: int = 10) -> List[BluetoothDevice]:
        """Synchronous wrapper for async scan."""
        import asyncio
        return asyncio.run(self.scan_async(duration))


class CoreBluetoothScanner(BluetoothScanner):
    """BLE scanner using macOS CoreBluetooth framework."""
    
    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self.central_manager = None
        self.discovered_peripherals = {}
    
    def scan(self, duration: int = 10) -> List[BluetoothDevice]:
        """Scan for BLE devices using CoreBluetooth."""
        try:
            from CoreBluetooth import (
                CBCentralManager, CBUUID, NSObject
            )
            from objc import selector, YES
            from Cocoa import NSDate, NSRunLoop, NSDefaultRunLoopMode
        except ImportError:
            print("Error: pyobjc-framework-CoreBluetooth not installed.")
            print("Run: pip install pyobjc-framework-CoreBluetooth")
            sys.exit(1)
        
        self.log(f"Starting CoreBluetooth scan for {duration} seconds...")
        
        class ScannerDelegate(NSObject):
            """Delegate for handling BLE discoveries."""
            
            def centralManagerDidUpdateState_(self, manager):
                self.log(f"Central manager state updated: {manager.state()}")
            
            def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
                self, manager, peripheral, data, rssi
            ):
                """Handle discovered peripheral."""
                mac = peripheral.identifier().UUIDString()
                name = peripheral.name()
                
                # Extract services
                services = []
                service_uuids = data.get('kCBAdvDataServiceUUIDs', [])
                for svc in service_uuids:
                    services.append(str(svc.UUIDString()))
                
                # Extract manufacturer data
                manuf_data = {}
                raw_manuf = data.get('kCBAdvDataManufacturerData', None)
                if raw_manuf:
                    # Convert NSData to bytes
                    manuf_bytes = bytes(raw_manuf.bytes().tobytes())
                    manuf_data[0x0000] = manuf_bytes  # Placeholder ID
                
                bt_device = BluetoothDevice(
                    mac_address=mac,
                    name=name if name else None,
                    rssi=int(rssi) if rssi else None,
                    services=services,
                    manufacturer_data=manuf_data,
                )
                
                self.add_or_update_device(bt_device)
                self.log(f"Found: {mac} - {name or 'Unknown'} (RSSI: {rssi})")
        
        delegate = ScannerDelegate.alloc().init()
        manager = CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)
        
        # Wait for central manager to be ready
        import time
        start_time = time.time()
        while time.time() - start_time < 2:
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.1)
            )
        
        # Start scanning
        manager.scanForPeripheralsWithServices_options_(None, None)
        
        # Run for specified duration
        end_time = time.time() + duration
        while time.time() < end_time:
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.1)
            )
        
        # Stop scanning
        manager.stopScan()
        
        self.log(f"Scan complete. Found {len(self.devices)} devices.")
        return self.get_devices()


def export_to_json(devices: List[BluetoothDevice], filepath: str) -> None:
    """Export device list to JSON file."""
    data = {
        "scan_timestamp": datetime.now().isoformat(),
        "device_count": len(devices),
        "devices": [d.to_dict() for d in devices]
    }
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Results exported to: {filepath}")


def export_to_csv(devices: List[BluetoothDevice], filepath: str) -> None:
    """Export device list to CSV file."""
    if not devices:
        print("No devices to export.")
        return
    
    fieldnames = [
        'mac_address', 'name', 'rssi', 'device_class',
        'device_type', 'flags', 'services', 'manufacturer_data',
        'first_seen', 'last_seen'
    ]
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for device in devices:
            row = device.to_dict()
            row['services'] = '; '.join(row['services'])
            row['manufacturer_data'] = str(row['manufacturer_data'])
            row['flags'] = '; '.join(row['flags'])
            writer.writerow(row)
    
    print(f"Results exported to: {filepath}")


def format_device_table(devices: List[BluetoothDevice]) -> str:
    """Format devices as a pretty table."""
    if not devices:
        return "No devices found."
    
    # Calculate column widths
    headers = ["MAC Address", "Name", "RSSI", "Type", "Flags"]
    rows = []
    
    for device in devices:
        rows.append([
            device.mac_address,
            device.name or "<hidden>",
            str(device.rssi) if device.rssi else "N/A",
            device.device_type,
            ", ".join(device.flags) if device.flags else "-",
        ])
    
    # Calculate max widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    
    # Build table
    lines = []
    separator = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    
    # Header
    header_line = "|" + "|".join(f" {h:<{widths[i]}} " for i, h in enumerate(headers)) + "|"
    lines.append(separator)
    lines.append(header_line)
    lines.append(separator)
    
    # Rows
    for row in rows:
        row_line = "|" + "|".join(f" {cell:<{widths[i]}} " for i, cell in enumerate(row)) + "|"
        lines.append(row_line)
    
    lines.append(separator)
    
    return "\n".join(lines)


def run_scan(args) -> None:
    """Execute a scan operation."""
    print(f"\n{'='*60}")
    print("BT-AUDITOR - Bluetooth Scanner")
    print(f"{'='*60}\n")
    
    # Determine scanner to use
    system = platform.system()
    
    if args.classic_only:
        print("Note: Classic Bluetooth scanning requires platform-specific libraries.")
        print("Currently only BLE scanning is fully supported.")
        print()
    
    if system == "Darwin":
        print(f"Platform: macOS - Using CoreBluetooth")
        scanner = CoreBluetoothScanner(verbose=args.verbose)
    else:
        print(f"Platform: {system} - Using Bleak")
        scanner = BleakScanner(verbose=args.verbose)
    
    # Perform scan
    duration = args.duration if args.duration else 10
    print(f"Scanning for {duration} seconds... Press Ctrl+C to stop early.\n")
    
    try:
        devices = scanner.scan(duration=duration)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        devices = scanner.get_devices()
    
    # Display results
    print(f"\n{'='*60}")
    print(f"Scan Complete - {len(devices)} devices found")
    print(f"{'='*60}\n")
    
    print(format_device_table(devices))
    
    # Show detailed info if verbose
    if args.verbose:
        print("\n\nDetailed Device Information:")
        print("-" * 60)
        for device in devices:
            print(f"\nMAC: {device.mac_address}")
            print(f"  Name: {device.name or '<hidden>'}")
            print(f"  RSSI: {device.rssi}")
            print(f"  Type: {device.device_type}")
            print(f"  Services: {', '.join(device.services) or 'None'}")
            if device.manufacturer_data:
                print(f"  Manufacturer Data:")
                for mid, data in device.manufacturer_data.items():
                    if isinstance(data, bytes):
                        print(f"    ID {hex(mid)}: {data.hex()}")
                    else:
                        print(f"    ID {hex(mid)}: {data}")
            if device.flags:
                print(f"  ⚠️  Flags: {', '.join(device.flags)}")
    
    # Export if requested
    if args.output:
        if args.output.endswith('.json'):
            export_to_json(devices, args.output)
        elif args.output.endswith('.csv'):
            export_to_csv(devices, args.output)
        else:
            print(f"Warning: Unknown file extension for '{args.output}'")
            print("Defaulting to JSON format.")
            export_to_json(devices, args.output if args.output.endswith('.json') else args.output + '.json')


def run_audit(args) -> None:
    """Run security audit on discovered devices."""
    print(f"\n{'='*60}")
    print("BT-AUDITOR - Security Audit Mode")
    print(f"{'='*60}\n")
    
    # First perform a scan
    args.classic_only = getattr(args, 'classic_only', False)
    args.verbose = True  # Always verbose in audit mode
    run_scan(args)
    
    # Analyze findings
    system = platform.system()
    if system == "Darwin":
        scanner = CoreBluetoothScanner(verbose=True)
    else:
        scanner = BleakScanner(verbose=True)
    
    devices = scanner.get_devices()
    
    print(f"\n{'='*60}")
    print("SECURITY AUDIT REPORT")
    print(f"{'='*60}\n")
    
    flagged_devices = [d for d in devices if d.flags]
    
    if not flagged_devices:
        print("✓ No security concerns detected in discovered devices.")
    else:
        print(f"⚠️  {len(flagged_devices)} device(s) with potential security concerns:\n")
        
        for device in flagged_devices:
            print(f"MAC: {device.mac_address}")
            print(f"  Name: {device.name or '<hidden>'}")
            print(f"  Type: {device.device_type}")
            print(f"  ⚠️  Concerns:")
            for flag in device.flags:
                print(f"    - {flag}")
            print()
    
    # Summary statistics
    print("\nSummary:")
    print(f"  Total devices: {len(devices)}")
    print(f"  Flagged devices: {len(flagged_devices)}")
    
    device_types = {}
    for d in devices:
        device_types[d.device_type] = device_types.get(d.device_type, 0) + 1
    
    print(f"  Device types: {', '.join(f'{k}({v})' for k, v in device_types.items())}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='bt-auditor',
        description='Bluetooth Scanning and Security Auditing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan                    Basic BLE scan
  %(prog)s scan --duration 30      Scan for 30 seconds
  %(prog)s scan --ble-only         Scan BLE devices only
  %(prog)s scan --output out.json  Export results to JSON
  %(prog)s audit                   Run full security audit
  %(prog)s scan --verbose          Show detailed information
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan for Bluetooth devices')
    scan_parser.add_argument(
        '-d', '--duration',
        type=int,
        default=10,
        help='Scan duration in seconds (default: 10)'
    )
    scan_parser.add_argument(
        '--ble-only',
        action='store_true',
        help='Scan BLE devices only'
    )
    scan_parser.add_argument(
        '--classic-only',
        action='store_true',
        help='Scan Classic Bluetooth only (limited support)'
    )
    scan_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file (JSON or CSV format)'
    )
    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    scan_parser.set_defaults(func=run_scan)
    
    # Audit command
    audit_parser = subparsers.add_parser('audit', help='Run security audit')
    audit_parser.add_argument(
        '-d', '--duration',
        type=int,
        default=15,
        help='Scan duration in seconds (default: 15)'
    )
    audit_parser.add_argument(
        '--ble-only',
        action='store_true',
        help='Scan BLE devices only'
    )
    audit_parser.add_argument(
        '--classic-only',
        action='store_true',
        help='Scan Classic Bluetooth only'
    )
    audit_parser.set_defaults(func=run_audit)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)


if __name__ == '__main__':
    main()
