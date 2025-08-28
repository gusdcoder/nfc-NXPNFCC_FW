#!/usr/bin/env python3
"""
Example Usage of NFC HCE Vulnerability Scanner

This script demonstrates how to use the vulnerability scanner toolkit
for different testing scenarios.
"""

import os
import sys
import json
from datetime import datetime


def example_firmware_scan():
    """Example: Scan firmware for vulnerabilities"""
    print("=== Example 1: Firmware Vulnerability Scan ===")
    print("This example scans NFC firmware binaries for potential vulnerabilities.")
    print()
    
    # Import the scanner
    from hce_vuln_scanner import NFCVulnScanner
    
    # Initialize scanner (no root, no frida for firmware-only scan)
    scanner = NFCVulnScanner(use_root=False, use_frida=False)
    
    # Scan firmware directory
    firmware_dir = "./InfraFW"
    if os.path.exists(firmware_dir):
        print(f"Scanning firmware directory: {firmware_dir}")
        results = scanner.scan_firmware_directory(firmware_dir)
        
        print(f"✓ Scanned {results['files_scanned']} firmware files")
        print(f"✓ Found {len(results['vulnerabilities'])} potential vulnerabilities")
        print(f"✓ Detected {len(results['suspicious_patterns'])} suspicious patterns")
        
        # Show firmware versions
        print("\nFirmware versions found:")
        for fw in results['firmware_versions'][:3]:  # Show first 3
            print(f"  - {fw['version']} ({fw['file']})")
        
        # Show sample vulnerabilities
        if results['vulnerabilities']:
            print(f"\nSample vulnerabilities:")
            for vuln in results['vulnerabilities'][:2]:  # Show first 2
                print(f"  - {vuln['type']}: {vuln['description']}")
    else:
        print(f"❌ Firmware directory not found: {firmware_dir}")
    
    print()


def example_combined_analysis():
    """Example: Combined firmware and simulated device analysis"""
    print("=== Example 2: Combined Analysis ===")
    print("This example shows combined firmware and device analysis.")
    print()
    
    from hce_vuln_scanner import NFCVulnScanner
    
    # Initialize scanner with all capabilities
    scanner = NFCVulnScanner(use_root=True, use_frida=True)
    
    # Scan firmware
    firmware_results = scanner.scan_firmware_directory("./InfraFW")
    
    # Note: Device scanning would require a real Android device
    # For this example, we'll simulate the device analysis results
    print("Note: Device analysis requires a connected Android device with ADB")
    print("Simulating device analysis results...")
    
    # Generate a comprehensive report
    report = scanner.generate_report()
    
    # Display summary
    report_data = json.loads(report)
    summary = report_data['summary']
    
    print(f"Analysis Summary:")
    print(f"  Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"  High severity: {summary['high_severity']}")
    print(f"  Medium severity: {summary['medium_severity']}")
    print(f"  Low severity: {summary['low_severity']}")
    
    print()


def example_non_root_analysis():
    """Example: Non-root device analysis"""
    print("=== Example 3: Non-Root Device Analysis ===")
    print("This example shows how to analyze HCE without root access.")
    print()
    
    from non_root_hce_analyzer import NonRootHCEAnalyzer
    
    # Initialize analyzer (would use real device ID in practice)
    analyzer = NonRootHCEAnalyzer(device_id=None)
    
    print("Note: This analysis requires a connected Android device")
    print("In a real scenario, you would:")
    print("  1. Connect Android device via USB")
    print("  2. Enable USB debugging") 
    print("  3. Run: python3 non_root_hce_analyzer.py --all")
    print()
    print("Expected capabilities:")
    print("  ✓ Enumerate HCE-enabled applications")
    print("  ✓ Check HCE service permissions")
    print("  ✓ Test for AID conflicts")
    print("  ✓ Analyze NFC intent handling")
    
    print()


def example_frida_analysis():
    """Example: Frida-based dynamic analysis"""
    print("=== Example 4: Frida Dynamic Analysis ===")
    print("This example demonstrates dynamic analysis with Frida.")
    print()
    
    try:
        from frida_hce_analyzer import FridaHCEAnalyzer
        
        print("Frida dynamic analysis capabilities:")
        print("  ✓ Real-time APDU command interception")
        print("  ✓ HCE service method hooking")
        print("  ✓ Security policy bypass detection")
        print("  ✓ Memory analysis for sensitive data")
        print("  ✓ Suspicious activity pattern recognition")
        print()
        print("To run Frida analysis:")
        print("  1. Install Frida: pip install frida-tools")
        print("  2. Install frida-server on target device")
        print("  3. Run: python3 frida_hce_analyzer.py --duration 300")
        
    except ImportError:
        print("Frida not available - install with: pip install frida-tools")
    
    print()


def show_vulnerability_examples():
    """Show examples of vulnerabilities that can be detected"""
    print("=== Vulnerability Detection Examples ===")
    print("The scanner can detect various types of vulnerabilities:")
    print()
    
    vulnerabilities = {
        "Firmware Vulnerabilities": [
            "Stack overflow patterns in ARM firmware",
            "Hardcoded cryptographic keys",
            "Debug/test patterns in production firmware",
            "Buffer overflow indicators"
        ],
        "HCE Application Vulnerabilities": [
            "Overprivileged NFC permissions",
            "Exported HCE services without protection",
            "Debuggable payment applications",
            "Multiple HCE category registrations"
        ],
        "Runtime Vulnerabilities": [
            "Unauthorized default service changes",
            "Suspicious APDU command patterns",
            "Security policy bypass attempts",
            "Sensitive data exposure in memory"
        ],
        "System Vulnerabilities": [
            "AID conflicts between applications",
            "NFC routing table manipulation",
            "Intent filter hijacking",
            "Secure Element bypass vulnerabilities"
        ]
    }
    
    for category, vulns in vulnerabilities.items():
        print(f"{category}:")
        for vuln in vulns:
            print(f"  • {vuln}")
        print()


def main():
    """Main example function"""
    print("NFC HCE Vulnerability Scanner - Usage Examples")
    print("=" * 60)
    print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Run examples
    example_firmware_scan()
    example_combined_analysis()
    example_non_root_analysis()
    example_frida_analysis()
    show_vulnerability_examples()
    
    print("For more information, see README_VULNERABILITY_SCANNER.md")


if __name__ == "__main__":
    main()