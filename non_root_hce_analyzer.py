#!/usr/bin/env python3
"""
NFC HCE Non-Root Vulnerability Tests

This module provides vulnerability testing capabilities for NFC HCE implementations
that work without root access on Android devices.

Features:
- APK-based HCE vulnerability testing
- Intent-based NFC analysis
- Non-privileged HCE app enumeration
- Static analysis of installed HCE applications

Author: NFC Security Research Team
License: See LA_OPT_NXP_Software_License.pdf
"""

import os
import sys
import subprocess
import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path


class NonRootHCEAnalyzer:
    """Non-root HCE vulnerability analyzer"""
    
    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id
        self.adb_cmd = ['adb'] + (['-s', device_id] if device_id else [])
        
    def analyze_hce_apps(self) -> Dict[str, Any]:
        """Analyze HCE applications without root access"""
        print("[+] Analyzing HCE applications (non-root mode)")
        
        results = {
            'hce_apps': [],
            'vulnerabilities': [],
            'payment_apps': [],
            'suspicious_activities': []
        }
        
        # Get all installed packages
        packages = self._get_installed_packages()
        
        # Filter HCE-related packages
        hce_packages = self._filter_hce_packages(packages)
        results['hce_apps'] = hce_packages
        
        # Analyze each HCE package
        for package in hce_packages:
            app_analysis = self._analyze_hce_package(package)
            if app_analysis.get('vulnerabilities'):
                results['vulnerabilities'].extend(app_analysis['vulnerabilities'])
            if app_analysis.get('is_payment_app'):
                results['payment_apps'].append(package)
            if app_analysis.get('suspicious_activities'):
                results['suspicious_activities'].extend(app_analysis['suspicious_activities'])
        
        return results
    
    def _get_installed_packages(self) -> List[str]:
        """Get list of installed packages"""
        try:
            cmd = self.adb_cmd + ['shell', 'pm', 'list', 'packages']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                packages = []
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('package:'):
                        package = line.replace('package:', '').strip()
                        packages.append(package)
                return packages
            return []
        except Exception as e:
            print(f"[-] Failed to get packages: {e}")
            return []
    
    def _filter_hce_packages(self, packages: List[str]) -> List[str]:
        """Filter packages that likely support HCE"""
        hce_keywords = [
            'pay', 'wallet', 'card', 'nfc', 'emv', 'contactless',
            'tap', 'mobile', 'banking', 'finance', 'payment'
        ]
        
        hce_packages = []
        for package in packages:
            package_lower = package.lower()
            if any(keyword in package_lower for keyword in hce_keywords):
                # Verify it actually has NFC/HCE capabilities
                if self._verify_hce_capabilities(package):
                    hce_packages.append(package)
        
        return hce_packages
    
    def _verify_hce_capabilities(self, package: str) -> bool:
        """Verify if package has HCE capabilities"""
        try:
            # Get package info
            cmd = self.adb_cmd + ['shell', 'dumpsys', 'package', package]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                hce_indicators = [
                    'android.nfc.cardemulation.action.host_apdu_service',
                    'android.nfc.cardemulation.host_apdu_service',
                    'android.permission.nfc',
                    'hostapduservice',
                    'cardemulation'
                ]
                
                return any(indicator in output for indicator in hce_indicators)
            
            return False
        except Exception:
            return False
    
    def _analyze_hce_package(self, package: str) -> Dict[str, Any]:
        """Analyze individual HCE package for vulnerabilities"""
        analysis = {
            'package': package,
            'vulnerabilities': [],
            'suspicious_activities': [],
            'is_payment_app': False,
            'permissions': [],
            'services': []
        }
        
        try:
            # Get detailed package information
            cmd = self.adb_cmd + ['shell', 'dumpsys', 'package', package]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract permissions
                analysis['permissions'] = self._extract_permissions(output)
                
                # Extract services
                analysis['services'] = self._extract_services(output)
                
                # Check if it's a payment app
                analysis['is_payment_app'] = self._is_payment_app(output)
                
                # Check for vulnerabilities
                vulns = self._check_package_vulnerabilities(package, output)
                analysis['vulnerabilities'].extend(vulns)
                
                # Check for suspicious activities
                suspicious = self._check_suspicious_activities(package, output)
                analysis['suspicious_activities'].extend(suspicious)
        
        except Exception as e:
            print(f"[-] Failed to analyze package {package}: {e}")
        
        return analysis
    
    def _extract_permissions(self, package_info: str) -> List[str]:
        """Extract permissions from package info"""
        permissions = []
        lines = package_info.split('\n')
        in_permissions = False
        
        for line in lines:
            if 'requested permissions:' in line.lower():
                in_permissions = True
                continue
            elif in_permissions and line.strip() and not line.startswith(' '):
                break
            elif in_permissions and line.strip().startswith('android.permission'):
                perm = line.strip()
                permissions.append(perm)
        
        return permissions
    
    def _extract_services(self, package_info: str) -> List[str]:
        """Extract services from package info"""
        services = []
        lines = package_info.split('\n')
        
        for line in lines:
            if 'service' in line.lower() and ('apdu' in line.lower() or 'nfc' in line.lower()):
                service_match = re.search(r'Service{[^}]+}', line)
                if service_match:
                    services.append(service_match.group())
        
        return services
    
    def _is_payment_app(self, package_info: str) -> bool:
        """Check if package is a payment application"""
        payment_indicators = [
            'android.nfc.cardemulation.category.payment',
            'payment',
            'wallet',
            'credit',
            'debit',
            'bank'
        ]
        
        package_lower = package_info.lower()
        return any(indicator in package_lower for indicator in payment_indicators)
    
    def _check_package_vulnerabilities(self, package: str, package_info: str) -> List[Dict[str, Any]]:
        """Check for vulnerabilities in HCE package"""
        vulnerabilities = []
        
        # Check for overprivileged permissions
        dangerous_perms = [
            'android.permission.NFC_TRANSACTION_EVENT',
            'android.permission.NFC_PREFERRED_PAYMENT_INFO',
            'android.permission.WRITE_SECURE_SETTINGS',
            'android.permission.BIND_NFC_SERVICE'
        ]
        
        package_lower = package_info.lower()
        found_dangerous = []
        for perm in dangerous_perms:
            if perm.lower() in package_lower:
                found_dangerous.append(perm)
        
        if found_dangerous:
            vulnerabilities.append({
                'type': 'OVERPRIVILEGED_PERMISSIONS',
                'severity': 'MEDIUM',
                'description': f"Package {package} has dangerous NFC permissions",
                'permissions': found_dangerous
            })
        
        # Check for exported HCE services without proper protection
        if 'exported=true' in package_info and 'hostapduservice' in package_lower:
            vulnerabilities.append({
                'type': 'EXPORTED_HCE_SERVICE',
                'severity': 'HIGH',
                'description': f"Package {package} exports HCE service without protection",
                'package': package
            })
        
        # Check for debuggable flag
        if 'debuggable=true' in package_info:
            vulnerabilities.append({
                'type': 'DEBUGGABLE_APP',
                'severity': 'MEDIUM',
                'description': f"HCE app {package} is debuggable",
                'package': package
            })
        
        return vulnerabilities
    
    def _check_suspicious_activities(self, package: str, package_info: str) -> List[Dict[str, Any]]:
        """Check for suspicious activities in HCE package"""
        suspicious = []
        
        # Check for multiple payment categories
        payment_categories = [
            'android.nfc.cardemulation.category.payment',
            'android.nfc.cardemulation.category.other'
        ]
        
        found_categories = []
        for category in payment_categories:
            if category in package_info:
                found_categories.append(category)
        
        if len(found_categories) > 1:
            suspicious.append({
                'type': 'MULTIPLE_CATEGORIES',
                'description': f"Package {package} registered for multiple HCE categories",
                'categories': found_categories
            })
        
        # Check for unusual AID prefixes
        aid_pattern = r'[A-F0-9]{10,32}'
        aids = re.findall(aid_pattern, package_info.upper())
        
        for aid in aids:
            # Check for potentially suspicious AIDs
            if aid.startswith('F0') or aid.startswith('FF'):
                suspicious.append({
                    'type': 'SUSPICIOUS_AID',
                    'description': f"Package {package} uses potentially suspicious AID: {aid}",
                    'aid': aid
                })
        
        return suspicious
    
    def check_nfc_intent_handling(self) -> Dict[str, Any]:
        """Check NFC intent handling vulnerabilities (non-root)"""
        print("[+] Checking NFC intent handling")
        
        results = {
            'intent_handlers': [],
            'vulnerabilities': []
        }
        
        try:
            # Get apps that handle NFC intents
            cmd = self.adb_cmd + ['shell', 'dumpsys', 'package', 'q', 'android.nfc.action.NDEF_DISCOVERED']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                handlers = self._parse_intent_handlers(result.stdout)
                results['intent_handlers'] = handlers
                
                # Check for vulnerabilities in intent handling
                for handler in handlers:
                    vulns = self._check_intent_handler_vulnerabilities(handler)
                    results['vulnerabilities'].extend(vulns)
        
        except Exception as e:
            print(f"[-] Failed to check NFC intent handling: {e}")
        
        return results
    
    def _parse_intent_handlers(self, dumpsys_output: str) -> List[Dict[str, Any]]:
        """Parse intent handlers from dumpsys output"""
        handlers = []
        lines = dumpsys_output.split('\n')
        
        current_handler = None
        for line in lines:
            if 'Activity Resolver Table:' in line:
                continue
            elif line.strip().startswith('Non-Data Actions:'):
                continue
            elif re.match(r'\s+[a-f0-9]+\s+', line):
                # This looks like a handler entry
                parts = line.strip().split()
                if len(parts) >= 2:
                    handler_info = ' '.join(parts[1:])
                    if '/' in handler_info:
                        handlers.append({
                            'handler': handler_info,
                            'priority': parts[0] if parts[0].isdigit() else 'unknown'
                        })
        
        return handlers
    
    def _check_intent_handler_vulnerabilities(self, handler: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check vulnerabilities in NFC intent handlers"""
        vulnerabilities = []
        
        handler_str = handler.get('handler', '')
        
        # Check for overly broad intent filters
        if '*' in handler_str or '.*' in handler_str:
            vulnerabilities.append({
                'type': 'BROAD_INTENT_FILTER',
                'severity': 'MEDIUM',
                'description': f"Handler {handler_str} uses overly broad intent filter",
                'handler': handler_str
            })
        
        # Check for exported activities handling NFC intents
        if 'exported=true' in handler_str:
            vulnerabilities.append({
                'type': 'EXPORTED_NFC_HANDLER',
                'severity': 'HIGH',
                'description': f"NFC intent handler {handler_str} is exported",
                'handler': handler_str
            })
        
        return vulnerabilities
    
    def test_hce_aid_conflicts(self) -> Dict[str, Any]:
        """Test for HCE AID conflicts (non-root)"""
        print("[+] Testing for HCE AID conflicts")
        
        results = {
            'aids': {},
            'conflicts': [],
            'vulnerabilities': []
        }
        
        try:
            # Get HCE routing information
            cmd = self.adb_cmd + ['shell', 'dumpsys', 'nfc']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                aids = self._extract_aids_from_dumpsys(result.stdout)
                results['aids'] = aids
                
                # Check for AID conflicts
                conflicts = self._find_aid_conflicts(aids)
                results['conflicts'] = conflicts
                
                # Generate vulnerability reports for conflicts
                for conflict in conflicts:
                    results['vulnerabilities'].append({
                        'type': 'AID_CONFLICT',
                        'severity': 'HIGH',
                        'description': f"AID conflict detected: {conflict['aid']}",
                        'apps': conflict['apps']
                    })
        
        except Exception as e:
            print(f"[-] Failed to test AID conflicts: {e}")
        
        return results
    
    def _extract_aids_from_dumpsys(self, nfc_dumpsys: str) -> Dict[str, List[str]]:
        """Extract AIDs and their associated apps from NFC dumpsys"""
        aids = {}
        lines = nfc_dumpsys.split('\n')
        
        current_app = None
        for line in lines:
            # Look for app names
            app_match = re.search(r'ComponentInfo{([^}]+)}', line)
            if app_match:
                current_app = app_match.group(1)
            
            # Look for AIDs
            aid_match = re.search(r'([A-F0-9]{10,32})', line.upper())
            if aid_match and current_app:
                aid = aid_match.group(1)
                if aid not in aids:
                    aids[aid] = []
                if current_app not in aids[aid]:
                    aids[aid].append(current_app)
        
        return aids
    
    def _find_aid_conflicts(self, aids: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Find AID conflicts where multiple apps claim the same AID"""
        conflicts = []
        
        for aid, apps in aids.items():
            if len(apps) > 1:
                conflicts.append({
                    'aid': aid,
                    'apps': apps,
                    'conflict_type': 'MULTIPLE_REGISTRATION'
                })
        
        return conflicts
    
    def generate_non_root_report(self) -> Dict[str, Any]:
        """Generate comprehensive non-root analysis report"""
        print("[+] Generating non-root analysis report")
        
        report = {
            'scan_type': 'non_root_analysis',
            'timestamp': os.popen('date').read().strip(),
            'device_id': self.device_id,
            'analyses': {}
        }
        
        try:
            # Analyze HCE apps
            report['analyses']['hce_apps'] = self.analyze_hce_apps()
            
            # Check NFC intent handling
            report['analyses']['intent_handling'] = self.check_nfc_intent_handling()
            
            # Test AID conflicts
            report['analyses']['aid_conflicts'] = self.test_hce_aid_conflicts()
            
            # Summary
            total_vulns = 0
            for analysis in report['analyses'].values():
                total_vulns += len(analysis.get('vulnerabilities', []))
            
            report['summary'] = {
                'total_vulnerabilities': total_vulns,
                'hce_apps_found': len(report['analyses']['hce_apps'].get('hce_apps', [])),
                'payment_apps_found': len(report['analyses']['hce_apps'].get('payment_apps', [])),
                'aid_conflicts': len(report['analyses']['aid_conflicts'].get('conflicts', []))
            }
        
        except Exception as e:
            report['error'] = str(e)
        
        return report


def main():
    """Main function for non-root HCE analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Non-root NFC HCE vulnerability analyzer")
    parser.add_argument('--device-id', help='Android device ID for ADB')
    parser.add_argument('--output', '-o', help='Output file for report (JSON format)')
    parser.add_argument('--analyze-apps', action='store_true', help='Analyze HCE applications')
    parser.add_argument('--check-intents', action='store_true', help='Check NFC intent handling')
    parser.add_argument('--test-aids', action='store_true', help='Test for AID conflicts')
    parser.add_argument('--all', action='store_true', help='Run all analyses')
    
    args = parser.parse_args()
    
    if not any([args.analyze_apps, args.check_intents, args.test_aids, args.all]):
        parser.print_help()
        sys.exit(1)
    
    analyzer = NonRootHCEAnalyzer(args.device_id)
    
    if args.all:
        report = analyzer.generate_non_root_report()
    else:
        report = {'analyses': {}}
        
        if args.analyze_apps:
            report['analyses']['hce_apps'] = analyzer.analyze_hce_apps()
        
        if args.check_intents:
            report['analyses']['intent_handling'] = analyzer.check_nfc_intent_handling()
        
        if args.test_aids:
            report['analyses']['aid_conflicts'] = analyzer.test_hce_aid_conflicts()
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()