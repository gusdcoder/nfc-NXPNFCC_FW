#!/usr/bin/env python3
"""
Test Suite for NFC HCE Vulnerability Scanner

This script validates the functionality of all scanner components.
"""

import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path


def test_main_scanner():
    """Test the main vulnerability scanner"""
    print("[+] Testing main vulnerability scanner...")
    
    # Test firmware scanning
    cmd = [
        sys.executable, 'hce_vuln_scanner.py',
        '--scan-firmware', './InfraFW',
        '--output', '/tmp/test_main_scanner.json'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("  ✓ Main scanner executed successfully")
            
            # Validate output file
            if os.path.exists('/tmp/test_main_scanner.json'):
                with open('/tmp/test_main_scanner.json', 'r') as f:
                    report = json.load(f)
                
                if 'scan_info' in report and 'summary' in report:
                    print("  ✓ Valid report generated")
                    print(f"    - Found {report['summary']['total_vulnerabilities']} vulnerabilities")
                    print(f"    - Scanned {report['firmware_analysis']['files_scanned']} firmware files")
                    return True
                else:
                    print("  ✗ Invalid report format")
            else:
                print("  ✗ Report file not created")
        else:
            print(f"  ✗ Scanner failed with exit code {result.returncode}")
            print(f"    Error: {result.stderr}")
    except Exception as e:
        print(f"  ✗ Exception during test: {e}")
    
    return False


def test_non_root_analyzer():
    """Test the non-root HCE analyzer"""
    print("[+] Testing non-root HCE analyzer...")
    
    # Test help output (basic functionality)
    cmd = [sys.executable, 'non_root_hce_analyzer.py', '--help']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'Non-root NFC HCE vulnerability analyzer' in result.stdout:
            print("  ✓ Non-root analyzer help works")
            return True
        else:
            print("  ✗ Non-root analyzer help failed")
    except Exception as e:
        print(f"  ✗ Exception during test: {e}")
    
    return False


def test_frida_analyzer():
    """Test the Frida HCE analyzer"""
    print("[+] Testing Frida HCE analyzer...")
    
    # Test help output (basic functionality)
    cmd = [sys.executable, 'frida_hce_analyzer.py', '--help']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'Frida-based NFC HCE dynamic analyzer' in result.stdout:
            print("  ✓ Frida analyzer help works")
            
            # Check if Frida is available
            if 'Frida not installed' in result.stderr:
                print("  ⚠ Frida not installed (optional dependency)")
            else:
                print("  ✓ Frida is available")
            
            return True
        else:
            print("  ✗ Frida analyzer help failed")
    except Exception as e:
        print(f"  ✗ Exception during test: {e}")
    
    return False


def test_firmware_analysis():
    """Test firmware analysis functionality"""
    print("[+] Testing firmware analysis...")
    
    # Check if firmware directory exists
    if not os.path.exists('./InfraFW'):
        print("  ✗ InfraFW directory not found")
        return False
    
    # Count firmware files
    firmware_files = []
    for root, dirs, files in os.walk('./InfraFW'):
        for file in files:
            if file.endswith('.c') and 'phDnldNfc_UpdateSeq' in file:
                firmware_files.append(os.path.join(root, file))
    
    if len(firmware_files) > 0:
        print(f"  ✓ Found {len(firmware_files)} firmware files")
        
        # Test analyzing a single file
        try:
            from hce_vuln_scanner import NFCVulnScanner
            scanner = NFCVulnScanner()
            result = scanner._analyze_firmware_file(firmware_files[0])
            
            if 'vulnerabilities' in result and 'version' in result:
                print("  ✓ Firmware analysis logic works")
                return True
            else:
                print("  ✗ Firmware analysis returned invalid result")
        except Exception as e:
            print(f"  ✗ Firmware analysis failed: {e}")
    else:
        print("  ✗ No firmware files found")
    
    return False


def test_report_generation():
    """Test report generation"""
    print("[+] Testing report generation...")
    
    try:
        from hce_vuln_scanner import NFCVulnScanner
        
        # Create scanner and populate with test data
        scanner = NFCVulnScanner()
        scanner.scan_results = {
            'timestamp': '2025-01-28T10:00:00Z',
            'root_mode': False,
            'frida_enabled': False,
            'firmware_analysis': {
                'vulnerabilities': [
                    {
                        'type': 'TEST_VULN',
                        'severity': 'HIGH',
                        'description': 'Test vulnerability'
                    }
                ]
            }
        }
        
        # Generate report
        report = scanner.generate_report()
        
        if report:
            report_data = json.loads(report)
            if 'scan_info' in report_data and 'summary' in report_data:
                print("  ✓ Report generation works")
                return True
            else:
                print("  ✗ Generated report has invalid format")
        else:
            print("  ✗ Report generation returned empty result")
    except Exception as e:
        print(f"  ✗ Report generation failed: {e}")
    
    return False


def run_all_tests():
    """Run all test cases"""
    print("="*60)
    print("NFC HCE Vulnerability Scanner Test Suite")
    print("="*60)
    
    tests = [
        test_main_scanner,
        test_non_root_analyzer,
        test_frida_analyzer,
        test_firmware_analysis,
        test_report_generation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            print()
        except Exception as e:
            print(f"  ✗ Test failed with exception: {e}")
            print()
    
    print("="*60)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return True
    else:
        print("❌ Some tests failed")
        return False


def main():
    """Main test function"""
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    success = run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()