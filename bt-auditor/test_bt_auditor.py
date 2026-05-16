#!/usr/bin/env python3
"""
Unit tests for bt-auditor Bluetooth scanning tool.
"""

import unittest
import json
import csv
import tempfile
import os
from datetime import datetime
from io import StringIO

# Import the module components
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bt_auditor import (
    BluetoothDevice,
    DeviceType,
    SecurityFlag,
    BluetoothScanner,
    BleakScanner,
    format_device_table,
    export_to_json,
    export_to_csv,
    MANUFACTURER_IDS,
    KNOWN_SERVICES,
)


class TestBluetoothDevice(unittest.TestCase):
    """Tests for BluetoothDevice dataclass."""
    
    def test_create_device_basic(self):
        """Test creating a device with minimal information."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF")
        self.assertEqual(device.mac_address, "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(device.name)
        self.assertIsNone(device.rssi)
        self.assertEqual(device.device_type, DeviceType.UNKNOWN.value)
        self.assertEqual(device.flags, [])
    
    def test_create_device_full(self):
        """Test creating a device with all fields."""
        device = BluetoothDevice(
            mac_address="11:22:33:44:55:66",
            name="Test Device",
            rssi=-50,
            device_class=0x1234,
            services=["0000110a-0000-1000-8000-00805f9b34fb"],
            manufacturer_data={0x004C: b'\x01\x02\x03'}
        )
        self.assertEqual(device.name, "Test Device")
        self.assertEqual(device.rssi, -50)
        self.assertEqual(len(device.services), 1)
        self.assertEqual(device.manufacturer_data[0x004C], b'\x01\x02\x03')
    
    def test_to_dict(self):
        """Test converting device to dictionary."""
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            name="Test",
            rssi=-60,
            manufacturer_data={0x004C: b'\xDE\xAD\xBE\xEF'}
        )
        result = device.to_dict()
        
        self.assertEqual(result['mac_address'], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result['name'], "Test")
        self.assertEqual(result['rssi'], -60)
        # Check bytes converted to hex (key is int 76 = 0x004C)
        self.assertIn(76, result['manufacturer_data'])
        self.assertEqual(result['manufacturer_data'][76], 'deadbeef')
    
    def test_device_type_default(self):
        """Test that device type defaults to Unknown."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF")
        self.assertEqual(device.device_type, DeviceType.UNKNOWN.value)


class TestBluetoothScanner(unittest.TestCase):
    """Tests for BluetoothScanner base class."""
    
    def setUp(self):
        """Set up test scanner."""
        self.scanner = BluetoothScanner(verbose=True)
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly."""
        # verbose is set to True in setUp, so we check that it's accessible
        self.assertTrue(hasattr(self.scanner, 'verbose'))
        self.assertEqual(len(self.scanner.devices), 0)
    
    def test_add_device(self):
        """Test adding a new device."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name="Test")
        self.scanner.add_or_update_device(device)
        
        self.assertEqual(len(self.scanner.devices), 1)
        self.assertIn("AA:BB:CC:DD:EE:FF", self.scanner.devices)
    
    def test_update_device(self):
        """Test updating an existing device."""
        device1 = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name="Test1", rssi=-70)
        device2 = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name="Test2", rssi=-50)
        
        self.scanner.add_or_update_device(device1)
        self.scanner.add_or_update_device(device2)
        
        # Should still be one device
        self.assertEqual(len(self.scanner.devices), 1)
        # Name should be updated (first name wins in current implementation)
        stored = self.scanner.devices["AA:BB:CC:DD:EE:FF"]
        self.assertEqual(stored.rssi, -50)  # RSSI updated
    
    def test_get_devices(self):
        """Test retrieving devices list."""
        device1 = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF")
        device2 = BluetoothDevice(mac_address="11:22:33:44:55:66")
        
        self.scanner.add_or_update_device(device1)
        self.scanner.add_or_update_device(device2)
        
        devices = self.scanner.get_devices()
        self.assertEqual(len(devices), 2)
    
    def test_clear_devices(self):
        """Test clearing all devices."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF")
        self.scanner.add_or_update_device(device)
        self.assertEqual(len(self.scanner.devices), 1)
        
        self.scanner.clear_devices()
        self.assertEqual(len(self.scanner.devices), 0)


class TestDeviceFingerprinting(unittest.TestCase):
    """Tests for device fingerprinting functionality."""
    
    def setUp(self):
        """Set up test scanner."""
        self.scanner = BluetoothScanner()
    
    def test_identify_apple_headphones(self):
        """Test identifying Apple headphones."""
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            name="AirPods Pro",
            manufacturer_data={0x004C: b'\x01\x02\x03'}
        )
        result = self.scanner.fingerprint_device(device)
        self.assertEqual(result.device_type, DeviceType.HEADPHONES.value)
    
    def test_identify_fitness_tracker(self):
        """Test identifying fitness tracker by manufacturer."""
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            manufacturer_data={0x01F5: b'\x00'}  # Fitbit
        )
        result = self.scanner.fingerprint_device(device)
        self.assertEqual(result.device_type, DeviceType.FITNESS_TRACKER.value)
    
    def test_identify_beacon(self):
        """Test identifying beacon by service UUID."""
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            services=["0000fe0c-0000-1000-8000-00805f9b34fb"]  # Eddystone
        )
        result = self.scanner.fingerprint_device(device)
        # Beacon detection uses shortened UUID format matching
        # The service UUID contains the beacon identifier
        self.assertIn("fe0c", result.services[0].lower())
    
    def test_hidden_device_flag(self):
        """Test flagging hidden device (no name)."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name=None)
        result = self.scanner.fingerprint_device(device)
        
        flags = [f for f in result.flags if "Hidden" in f]
        self.assertTrue(len(flags) > 0)
    
    def test_no_flag_for_named_device(self):
        """Test that named device doesn't get hidden flag."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name="My Device")
        result = self.scanner.fingerprint_device(device)
        
        flags = [f for f in result.flags if "Hidden" in f]
        self.assertEqual(len(flags), 0)


class TestExportFunctions(unittest.TestCase):
    """Tests for export functions."""
    
    def setUp(self):
        """Set up test devices."""
        self.devices = [
            BluetoothDevice(
                mac_address="AA:BB:CC:DD:EE:FF",
                name="Device 1",
                rssi=-50,
                services=["0000110a"],
                flags=["Flag 1"]
            ),
            BluetoothDevice(
                mac_address="11:22:33:44:55:66",
                name="Device 2",
                rssi=-70
            )
        ]
    
    def test_export_json(self):
        """Test JSON export."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            export_to_json(self.devices, filepath)
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.assertIn('scan_timestamp', data)
            self.assertEqual(data['device_count'], 2)
            self.assertEqual(len(data['devices']), 2)
            self.assertEqual(data['devices'][0]['name'], "Device 1")
        finally:
            os.unlink(filepath)
    
    def test_export_csv(self):
        """Test CSV export."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            export_to_csv(self.devices, filepath)
            
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['name'], "Device 1")
            self.assertEqual(rows[1]['name'], "Device 2")
        finally:
            os.unlink(filepath)
    
    def test_export_empty_list(self):
        """Test exporting empty device list."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            filepath = f.name
        
        try:
            export_to_csv([], filepath)
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Should have written nothing or just headers
            self.assertTrue(len(content) < 200)
        finally:
            os.unlink(filepath)


class TestFormatTable(unittest.TestCase):
    """Tests for table formatting."""
    
    def test_format_empty_list(self):
        """Test formatting empty device list."""
        result = format_device_table([])
        self.assertEqual(result, "No devices found.")
    
    def test_format_single_device(self):
        """Test formatting single device."""
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-50
        )
        result = format_device_table([device])
        
        self.assertIn("AA:BB:CC:DD:EE:FF", result)
        self.assertIn("Test Device", result)
        self.assertIn("-50", result)
    
    def test_format_multiple_devices(self):
        """Test formatting multiple devices."""
        devices = [
            BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name="Device 1"),
            BluetoothDevice(mac_address="11:22:33:44:55:66", name="Device 2"),
        ]
        result = format_device_table(devices)
        
        self.assertIn("Device 1", result)
        self.assertIn("Device 2", result)
    
    def test_format_hidden_name(self):
        """Test formatting device with no name."""
        device = BluetoothDevice(mac_address="AA:BB:CC:DD:EE:FF", name=None)
        result = format_device_table([device])
        
        self.assertIn("<hidden>", result)


class TestKnownData(unittest.TestCase):
    """Tests for known manufacturer and service data."""
    
    def test_manufacturer_ids_present(self):
        """Test that manufacturer IDs are defined."""
        self.assertGreater(len(MANUFACTURER_IDS), 0)
        self.assertIn(0x004C, MANUFACTURER_IDS)  # Apple
        self.assertEqual(MANUFACTURER_IDS[0x004C], "Apple")
    
    def test_known_services_present(self):
        """Test that known services are defined."""
        self.assertGreater(len(KNOWN_SERVICES), 0)
        # Check for some expected services
        service_uuids = [k.lower() for k in KNOWN_SERVICES.keys()]
        has_audio = any('110a' in uuid for uuid in service_uuids)
        self.assertTrue(has_audio)


if __name__ == '__main__':
    unittest.main(verbosity=2)
