# bt-auditor

A command-line Bluetooth scanning and security auditing tool for macOS (with optional Linux support via BlueZ). It passively and actively discovers nearby Bluetooth and BLE devices, fingerprints them, logs findings, and flags potentially suspicious behavior.

## Features

- **Device Discovery**: Scan for both Classic Bluetooth and BLE devices
- **Device Information**: Display MAC address, name, RSSI, device class, services, and manufacturer data
- **Fingerprinting**: Identify device types based on advertised services and manufacturer data
- **Security Auditing**: Flag suspicious behavior like hidden devices, weak pairing modes, or known vulnerable devices
- **Logging**: Export findings to JSON or CSV formats
- **Cross-Platform**: Works on macOS (CoreBluetooth) and Linux (BlueZ)

## Installation

```bash
pip install -r requirements.txt
```

### Dependencies

- **macOS**: No additional dependencies (uses CoreBluetooth via `pyobjc-framework-CoreBluetooth`)
- **Linux**: BlueZ stack and `bluepy` or `bleak` library

## Usage

### Basic Scan

```bash
python bt_auditor.py scan
```

### Scan with Duration

```bash
python bt_auditor.py scan --duration 30
```

### Scan BLE Only

```bash
python bt_auditor.py scan --ble-only
```

### Scan Classic Only

```bash
python bt_auditor.py scan --classic-only
```

### Audit Mode

```bash
python bt_auditor.py audit
```

### Export Results

```bash
python bt_auditor.py scan --output results.json
python bt_auditor.py scan --output results.csv
```

### Verbose Mode

```bash
python bt_auditor.py scan --verbose
```

## Output Fields

| Field | Description |
|-------|-------------|
| MAC Address | Unique Bluetooth hardware address |
| Name | Device name (if advertised) |
| RSSI | Received Signal Strength Indicator |
| Device Class | Bluetooth class of device |
| Services | List of advertised service UUIDs |
| Manufacturer Data | Vendor-specific data |
| Device Type | Fingerprinted device category |
| Flags | Security-related observations |

## Security Flags

The tool flags devices with these potential security concerns:

- **Hidden Device**: No name advertised
- **Unknown Vendor**: Unrecognized manufacturer
- **Legacy Pairing**: Supports legacy pairing modes
- **Test Mode**: Device in test/debug mode
- **Known Vulnerable**: Matches known vulnerable device signatures

## License

MIT License
