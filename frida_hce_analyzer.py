#!/usr/bin/env python3
"""
Frida-based NFC HCE Dynamic Analysis Module

This module provides advanced dynamic analysis capabilities for NFC HCE implementations
using the Frida dynamic instrumentation framework.

Features:
- Real-time APDU command monitoring
- HCE service method hooking
- NFC transaction analysis
- Security policy bypass detection
- Memory analysis for sensitive data

Author: NFC Security Research Team
License: See LA_OPT_NXP_Software_License.pdf
"""

import sys
import json
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import subprocess
import re

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print("[-] Frida not installed. Install with: pip install frida-tools")


class FridaHCEAnalyzer:
    """Frida-based HCE dynamic analyzer"""
    
    def __init__(self, device_id: Optional[str] = None, spawn_mode: bool = False):
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida is required for dynamic analysis")
        
        self.device_id = device_id
        self.spawn_mode = spawn_mode
        self.session = None
        self.script = None
        self.analysis_results = {
            'start_time': datetime.now().isoformat(),
            'intercepted_calls': [],
            'apdu_commands': [],
            'security_violations': [],
            'memory_leaks': [],
            'suspicious_activities': []
        }
        self.hooks_installed = False
        self.monitoring = False
        
        # Connect to device
        try:
            if device_id:
                self.device = frida.get_usb_device(device_id)
            else:
                self.device = frida.get_usb_device()
            print(f"[+] Connected to device: {self.device}")
        except Exception as e:
            print(f"[-] Failed to connect to device: {e}")
            raise
    
    def attach_to_nfc_service(self) -> bool:
        """Attach to the NFC system service"""
        try:
            # Try to attach to NFC service
            self.session = self.device.attach("com.android.nfc")
            print("[+] Attached to NFC service")
            return True
        except frida.ProcessNotFoundError:
            print("[-] NFC service not found. Trying alternative processes...")
            
            # Try alternative NFC-related processes
            alternative_processes = [
                "system_server",  # NFC might be part of system server
                "android.nfc",
                "nfc",
                "com.nxp.nfc"
            ]
            
            for process in alternative_processes:
                try:
                    self.session = self.device.attach(process)
                    print(f"[+] Attached to {process}")
                    return True
                except frida.ProcessNotFoundError:
                    continue
            
            print("[-] Failed to attach to any NFC-related process")
            return False
        except Exception as e:
            print(f"[-] Failed to attach to NFC service: {e}")
            return False
    
    def install_hce_hooks(self) -> bool:
        """Install comprehensive HCE monitoring hooks"""
        if not self.session:
            print("[-] No active session to install hooks")
            return False
        
        script_code = self._generate_comprehensive_frida_script()
        
        try:
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            
            print("[+] HCE monitoring hooks installed successfully")
            self.hooks_installed = True
            return True
        except Exception as e:
            print(f"[-] Failed to install hooks: {e}")
            return False
    
    def _generate_comprehensive_frida_script(self) -> str:
        """Generate comprehensive Frida script for HCE analysis"""
        return """
// Comprehensive NFC HCE Dynamic Analysis Script
console.log("[+] Starting NFC HCE Dynamic Analysis");

// Global variables for tracking
var apduCounter = 0;
var securityViolations = [];
var suspiciousActivities = [];

Java.perform(function() {
    console.log("[+] Java runtime available, installing hooks...");
    
    // ===========================================
    // NFC Adapter Hooks
    // ===========================================
    try {
        var NfcAdapter = Java.use("android.nfc.NfcAdapter");
        console.log("[+] Hooking NfcAdapter methods");
        
        // Hook getDefaultAdapter
        NfcAdapter.getDefaultAdapter.overload('android.content.Context').implementation = function(context) {
            console.log("[*] NfcAdapter.getDefaultAdapter() called");
            send({
                type: 'nfc_call',
                method: 'getDefaultAdapter',
                context: context.toString(),
                timestamp: Date.now()
            });
            return this.getDefaultAdapter(context);
        };
        
        // Hook enableForegroundDispatch
        NfcAdapter.enableForegroundDispatch.implementation = function(activity, intent, filters, techLists) {
            console.log("[*] NfcAdapter.enableForegroundDispatch() called");
            console.log("    Activity: " + activity);
            
            send({
                type: 'nfc_call',
                method: 'enableForegroundDispatch',
                activity: activity.toString(),
                timestamp: Date.now()
            });
            
            return this.enableForegroundDispatch(activity, intent, filters, techLists);
        };
        
        // Hook disableForegroundDispatch
        NfcAdapter.disableForegroundDispatch.implementation = function(activity) {
            console.log("[*] NfcAdapter.disableForegroundDispatch() called");
            send({
                type: 'nfc_call',
                method: 'disableForegroundDispatch',
                activity: activity.toString(),
                timestamp: Date.now()
            });
            
            return this.disableForegroundDispatch(activity);
        };
        
    } catch (e) {
        console.log("[-] Failed to hook NfcAdapter: " + e);
    }
    
    // ===========================================
    // Card Emulation Hooks
    // ===========================================
    try {
        var CardEmulation = Java.use("android.nfc.cardemulation.CardEmulation");
        console.log("[+] Hooking CardEmulation methods");
        
        // Hook getInstance
        CardEmulation.getInstance.implementation = function(adapter) {
            console.log("[*] CardEmulation.getInstance() called");
            send({
                type: 'hce_call',
                method: 'getInstance',
                timestamp: Date.now()
            });
            return this.getInstance(adapter);
        };
        
        // Hook getDefaultServiceForCategory
        CardEmulation.getDefaultServiceForCategory.implementation = function(category) {
            console.log("[*] CardEmulation.getDefaultServiceForCategory() called");
            console.log("    Category: " + category);
            
            var result = this.getDefaultServiceForCategory(category);
            
            send({
                type: 'hce_call',
                method: 'getDefaultServiceForCategory',
                category: category,
                result: result ? result.toString() : null,
                timestamp: Date.now()
            });
            
            return result;
        };
        
        // Hook setDefaultServiceForCategory - CRITICAL SECURITY METHOD
        CardEmulation.setDefaultServiceForCategory.implementation = function(service, category) {
            console.log("[!] SECURITY: CardEmulation.setDefaultServiceForCategory() called");
            console.log("    Service: " + service);
            console.log("    Category: " + category);
            
            // This is a security-sensitive operation
            send({
                type: 'security_violation',
                method: 'setDefaultServiceForCategory',
                service: service.toString(),
                category: category,
                severity: 'HIGH',
                description: 'Default payment service being changed',
                timestamp: Date.now()
            });
            
            securityViolations.push({
                type: 'DEFAULT_SERVICE_CHANGE',
                service: service.toString(),
                category: category,
                timestamp: Date.now()
            });
            
            return this.setDefaultServiceForCategory(service, category);
        };
        
        // Hook getAidsForService
        CardEmulation.getAidsForService.implementation = function(service, category) {
            console.log("[*] CardEmulation.getAidsForService() called");
            
            var result = this.getAidsForService(service, category);
            var aids = [];
            
            if (result) {
                var iterator = result.iterator();
                while (iterator.hasNext()) {
                    aids.push(iterator.next().toString());
                }
            }
            
            send({
                type: 'hce_call',
                method: 'getAidsForService',
                service: service.toString(),
                category: category,
                aids: aids,
                timestamp: Date.now()
            });
            
            return result;
        };
        
    } catch (e) {
        console.log("[-] Failed to hook CardEmulation: " + e);
    }
    
    // ===========================================
    // Host APDU Service Hooks
    // ===========================================
    try {
        var HostApduService = Java.use("android.nfc.cardemulation.HostApduService");
        console.log("[+] Hooking HostApduService methods");
        
        // Hook processCommandApdu - MOST CRITICAL METHOD
        HostApduService.processCommandApdu.implementation = function(commandApdu, extras) {
            apduCounter++;
            console.log("[*] HostApduService.processCommandApdu() called (#" + apduCounter + ")");
            
            var apduHex = "";
            if (commandApdu) {
                for (var i = 0; i < commandApdu.length; i++) {
                    apduHex += ("0" + (commandApdu[i] & 0xFF).toString(16)).slice(-2).toUpperCase();
                }
                console.log("    Command APDU: " + apduHex);
                
                // Parse APDU structure
                if (commandApdu.length >= 4) {
                    var cla = commandApdu[0] & 0xFF;
                    var ins = commandApdu[1] & 0xFF;
                    var p1 = commandApdu[2] & 0xFF;
                    var p2 = commandApdu[3] & 0xFF;
                    
                    console.log("    CLA: 0x" + cla.toString(16).toUpperCase());
                    console.log("    INS: 0x" + ins.toString(16).toUpperCase());
                    console.log("    P1: 0x" + p1.toString(16).toUpperCase());
                    console.log("    P2: 0x" + p2.toString(16).toUpperCase());
                    
                    // Check for suspicious commands
                    var suspicious = false;
                    var suspiciousReason = "";
                    
                    // Check for SELECT commands to unusual AIDs
                    if (ins === 0xA4) {
                        suspicious = true;
                        suspiciousReason = "SELECT command detected";
                    }
                    
                    // Check for READ BINARY commands
                    if (ins === 0xB0) {
                        suspicious = true;
                        suspiciousReason = "READ BINARY command detected";
                    }
                    
                    // Check for proprietary class bytes
                    if (cla >= 0x80) {
                        suspicious = true;
                        suspiciousReason = "Proprietary class byte detected";
                    }
                    
                    // Check for long APDUs (potential buffer overflow)
                    if (commandApdu.length > 255) {
                        suspicious = true;
                        suspiciousReason = "Unusually long APDU command";
                    }
                    
                    if (suspicious) {
                        console.log("[!] SUSPICIOUS: " + suspiciousReason);
                        
                        suspiciousActivities.push({
                            type: 'SUSPICIOUS_APDU',
                            apduHex: apduHex,
                            reason: suspiciousReason,
                            cla: cla,
                            ins: ins,
                            timestamp: Date.now()
                        });
                        
                        send({
                            type: 'suspicious_activity',
                            activity_type: 'SUSPICIOUS_APDU',
                            apdu: apduHex,
                            reason: suspiciousReason,
                            severity: 'MEDIUM',
                            timestamp: Date.now()
                        });
                    }
                    
                    // Send APDU data
                    send({
                        type: 'apdu_command',
                        apdu: apduHex,
                        cla: cla,
                        ins: ins,
                        p1: p1,
                        p2: p2,
                        length: commandApdu.length,
                        suspicious: suspicious,
                        reason: suspiciousReason,
                        timestamp: Date.now()
                    });
                }
            }
            
            // Call original method
            var result = this.processCommandApdu(commandApdu, extras);
            
            // Log response
            if (result) {
                var responseHex = "";
                for (var i = 0; i < result.length; i++) {
                    responseHex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2).toUpperCase();
                }
                console.log("    Response APDU: " + responseHex);
                
                // Check response status
                if (result.length >= 2) {
                    var sw1 = result[result.length - 2] & 0xFF;
                    var sw2 = result[result.length - 1] & 0xFF;
                    var statusWord = (sw1 << 8) | sw2;
                    
                    console.log("    Status Word: 0x" + statusWord.toString(16).toUpperCase());
                    
                    // Check for error conditions
                    if (statusWord !== 0x9000) {
                        console.log("    Status: ERROR (not 9000)");
                        
                        if (statusWord === 0x6300) {
                            console.log("[!] WARNING: Authentication failed");
                        } else if (statusWord === 0x6982) {
                            console.log("[!] WARNING: Security status not satisfied");
                        } else if (statusWord === 0x6A82) {
                            console.log("[!] WARNING: File not found");
                        }
                    }
                    
                    send({
                        type: 'apdu_response',
                        response: responseHex,
                        status_word: statusWord,
                        length: result.length,
                        timestamp: Date.now()
                    });
                }
            }
            
            return result;
        };
        
        // Hook onDeactivated
        HostApduService.onDeactivated.implementation = function(reason) {
            console.log("[*] HostApduService.onDeactivated() called");
            console.log("    Reason: " + reason);
            
            send({
                type: 'hce_call',
                method: 'onDeactivated',
                reason: reason,
                timestamp: Date.now()
            });
            
            return this.onDeactivated(reason);
        };
        
    } catch (e) {
        console.log("[-] Failed to hook HostApduService: " + e);
    }
    
    // ===========================================
    // NFC-F Service Hooks (for Felica emulation)
    // ===========================================
    try {
        var HostNfcFService = Java.use("android.nfc.cardemulation.HostNfcFService");
        console.log("[+] Hooking HostNfcFService methods");
        
        HostNfcFService.processNfcFPacket.implementation = function(commandPacket, extras) {
            console.log("[*] HostNfcFService.processNfcFPacket() called");
            
            var packetHex = "";
            if (commandPacket) {
                for (var i = 0; i < commandPacket.length; i++) {
                    packetHex += ("0" + (commandPacket[i] & 0xFF).toString(16)).slice(-2).toUpperCase();
                }
                console.log("    NFC-F Packet: " + packetHex);
            }
            
            send({
                type: 'nfcf_packet',
                packet: packetHex,
                length: commandPacket ? commandPacket.length : 0,
                timestamp: Date.now()
            });
            
            return this.processNfcFPacket(commandPacket, extras);
        };
        
    } catch (e) {
        console.log("[-] HostNfcFService not available or failed to hook: " + e);
    }
    
    // ===========================================
    // Security and Memory Analysis
    // ===========================================
    
    // Hook String operations to detect sensitive data
    try {
        var String = Java.use("java.lang.String");
        var originalGetBytes = String.getBytes.overload();
        
        String.getBytes.overload().implementation = function() {
            var str = this.toString();
            
            // Check for sensitive data patterns
            if (str.length > 8 && /^[0-9]{13,19}$/.test(str)) {
                // Looks like a credit card number
                console.log("[!] SENSITIVE: Potential credit card number in memory");
                send({
                    type: 'memory_leak',
                    data_type: 'CREDIT_CARD',
                    pattern: 'PAN_PATTERN',
                    severity: 'CRITICAL',
                    timestamp: Date.now()
                });
            }
            
            if (/^[A-F0-9]{32}$/.test(str.toUpperCase())) {
                // Looks like a 128-bit key
                console.log("[!] SENSITIVE: Potential cryptographic key in memory");
                send({
                    type: 'memory_leak',
                    data_type: 'CRYPTO_KEY',
                    pattern: 'HEX_128BIT',
                    severity: 'HIGH',
                    timestamp: Date.now()
                });
            }
            
            return originalGetBytes.call(this);
        };
        
    } catch (e) {
        console.log("[-] Failed to hook String operations: " + e);
    }
    
    // ===========================================
    // Initialization Complete
    // ===========================================
    
    console.log("[+] All NFC HCE hooks installed successfully");
    console.log("[+] Monitoring started - waiting for NFC transactions...");
    
    send({
        type: 'init_complete',
        hooks_installed: [
            'NfcAdapter',
            'CardEmulation', 
            'HostApduService',
            'HostNfcFService',
            'String (memory analysis)'
        ],
        timestamp: Date.now()
    });
});

// Helper function to convert byte array to hex string
function bytesToHex(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2).toUpperCase();
    }
    return hex;
}
"""
    
    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]):
        """Handle messages from Frida script"""
        try:
            if message['type'] == 'send':
                payload = message['payload']
                msg_type = payload.get('type', 'unknown')
                
                # Route message based on type
                if msg_type == 'init_complete':
                    print("[+] Frida hooks initialization complete")
                    self.monitoring = True
                    
                elif msg_type == 'nfc_call':
                    self._handle_nfc_call(payload)
                    
                elif msg_type == 'hce_call':
                    self._handle_hce_call(payload)
                    
                elif msg_type == 'apdu_command':
                    self._handle_apdu_command(payload)
                    
                elif msg_type == 'apdu_response':
                    self._handle_apdu_response(payload)
                    
                elif msg_type == 'security_violation':
                    self._handle_security_violation(payload)
                    
                elif msg_type == 'suspicious_activity':
                    self._handle_suspicious_activity(payload)
                    
                elif msg_type == 'memory_leak':
                    self._handle_memory_leak(payload)
                    
                elif msg_type == 'nfcf_packet':
                    self._handle_nfcf_packet(payload)
                
            elif message['type'] == 'error':
                print(f"[-] Frida error: {message['description']}")
                
        except Exception as e:
            print(f"[-] Error handling message: {e}")
    
    def _handle_nfc_call(self, payload: Dict[str, Any]):
        """Handle NFC adapter calls"""
        method = payload.get('method', 'unknown')
        timestamp = payload.get('timestamp', time.time())
        
        self.analysis_results['intercepted_calls'].append({
            'type': 'nfc_adapter',
            'method': method,
            'timestamp': timestamp,
            'details': payload
        })
        
        print(f"[NFC] {method}() called at {datetime.fromtimestamp(timestamp/1000)}")
    
    def _handle_hce_call(self, payload: Dict[str, Any]):
        """Handle HCE-specific calls"""
        method = payload.get('method', 'unknown')
        timestamp = payload.get('timestamp', time.time())
        
        self.analysis_results['intercepted_calls'].append({
            'type': 'hce',
            'method': method,
            'timestamp': timestamp,
            'details': payload
        })
        
        if method == 'getDefaultServiceForCategory':
            category = payload.get('category', 'unknown')
            result = payload.get('result', 'none')
            print(f"[HCE] Default service for {category}: {result}")
        else:
            print(f"[HCE] {method}() called at {datetime.fromtimestamp(timestamp/1000)}")
    
    def _handle_apdu_command(self, payload: Dict[str, Any]):
        """Handle APDU command interceptions"""
        apdu = payload.get('apdu', '')
        cla = payload.get('cla', 0)
        ins = payload.get('ins', 0)
        suspicious = payload.get('suspicious', False)
        timestamp = payload.get('timestamp', time.time())
        
        self.analysis_results['apdu_commands'].append(payload)
        
        status_indicator = "[!]" if suspicious else "[APDU]"
        print(f"{status_indicator} Command: {apdu} (CLA=0x{cla:02X}, INS=0x{ins:02X})")
        
        if suspicious:
            reason = payload.get('reason', 'Unknown')
            print(f"         Reason: {reason}")
    
    def _handle_apdu_response(self, payload: Dict[str, Any]):
        """Handle APDU response interceptions"""
        response = payload.get('response', '')
        status_word = payload.get('status_word', 0)
        
        if status_word == 0x9000:
            print(f"[APDU] Response: {response} (SUCCESS)")
        else:
            print(f"[APDU] Response: {response} (ERROR: 0x{status_word:04X})")
    
    def _handle_security_violation(self, payload: Dict[str, Any]):
        """Handle security violations"""
        method = payload.get('method', 'unknown')
        severity = payload.get('severity', 'UNKNOWN')
        description = payload.get('description', '')
        
        self.analysis_results['security_violations'].append(payload)
        
        print(f"[SECURITY-{severity}] {method}: {description}")
    
    def _handle_suspicious_activity(self, payload: Dict[str, Any]):
        """Handle suspicious activities"""
        activity_type = payload.get('activity_type', 'unknown')
        severity = payload.get('severity', 'UNKNOWN')
        reason = payload.get('reason', '')
        
        self.analysis_results['suspicious_activities'].append(payload)
        
        print(f"[SUSPICIOUS-{severity}] {activity_type}: {reason}")
    
    def _handle_memory_leak(self, payload: Dict[str, Any]):
        """Handle memory leak detections"""
        data_type = payload.get('data_type', 'unknown')
        severity = payload.get('severity', 'UNKNOWN')
        pattern = payload.get('pattern', '')
        
        self.analysis_results['memory_leaks'].append(payload)
        
        print(f"[MEMORY-{severity}] Sensitive data detected: {data_type} ({pattern})")
    
    def _handle_nfcf_packet(self, payload: Dict[str, Any]):
        """Handle NFC-F packet interceptions"""
        packet = payload.get('packet', '')
        length = payload.get('length', 0)
        
        print(f"[NFC-F] Packet: {packet} ({length} bytes)")
    
    def start_monitoring(self, duration: Optional[int] = None) -> Dict[str, Any]:
        """Start dynamic monitoring"""
        if not self.hooks_installed:
            print("[-] Hooks not installed. Call install_hce_hooks() first")
            return {}
        
        print(f"[+] Starting dynamic monitoring...")
        if duration:
            print(f"[+] Monitoring duration: {duration} seconds")
        else:
            print("[+] Monitoring indefinitely (Ctrl+C to stop)")
        
        start_time = time.time()
        
        try:
            if duration:
                time.sleep(duration)
            else:
                # Monitor indefinitely
                while True:
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped by user")
        except Exception as e:
            print(f"\n[-] Monitoring error: {e}")
        
        end_time = time.time()
        monitoring_duration = end_time - start_time
        
        # Finalize results
        self.analysis_results['end_time'] = datetime.now().isoformat()
        self.analysis_results['duration_seconds'] = monitoring_duration
        
        print(f"[+] Monitoring completed. Duration: {monitoring_duration:.2f} seconds")
        return self.analysis_results
    
    def generate_frida_report(self) -> Dict[str, Any]:
        """Generate comprehensive Frida analysis report"""
        if not self.analysis_results:
            return {'error': 'No analysis results available'}
        
        # Calculate statistics
        total_apdus = len(self.analysis_results['apdu_commands'])
        suspicious_apdus = len([a for a in self.analysis_results['apdu_commands'] if a.get('suspicious')])
        total_violations = len(self.analysis_results['security_violations'])
        total_suspicious = len(self.analysis_results['suspicious_activities'])
        total_leaks = len(self.analysis_results['memory_leaks'])
        
        # Analyze APDU patterns
        apdu_analysis = self._analyze_apdu_patterns()
        
        # Generate risk assessment
        risk_level = self._assess_risk_level()
        
        report = {
            'analysis_summary': {
                'total_apdu_commands': total_apdus,
                'suspicious_apdus': suspicious_apdus,
                'security_violations': total_violations,
                'suspicious_activities': total_suspicious,
                'memory_leaks': total_leaks,
                'risk_level': risk_level
            },
            'apdu_analysis': apdu_analysis,
            'raw_results': self.analysis_results,
            'recommendations': self._generate_frida_recommendations()
        }
        
        return report
    
    def _analyze_apdu_patterns(self) -> Dict[str, Any]:
        """Analyze APDU command patterns"""
        apdus = self.analysis_results['apdu_commands']
        
        if not apdus:
            return {'message': 'No APDU commands captured'}
        
        # Count commands by instruction
        ins_counts = {}
        cla_counts = {}
        
        for apdu in apdus:
            ins = apdu.get('ins', 0)
            cla = apdu.get('cla', 0)
            
            ins_hex = f"0x{ins:02X}"
            cla_hex = f"0x{cla:02X}"
            
            ins_counts[ins_hex] = ins_counts.get(ins_hex, 0) + 1
            cla_counts[cla_hex] = cla_counts.get(cla_hex, 0) + 1
        
        # Find most common commands
        top_instructions = sorted(ins_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_classes = sorted(cla_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_commands': len(apdus),
            'unique_instructions': len(ins_counts),
            'unique_classes': len(cla_counts),
            'top_instructions': top_instructions,
            'top_classes': top_classes
        }
    
    def _assess_risk_level(self) -> str:
        """Assess overall security risk level"""
        violations = len(self.analysis_results['security_violations'])
        suspicious = len(self.analysis_results['suspicious_activities'])
        leaks = len(self.analysis_results['memory_leaks'])
        
        high_risk_indicators = violations + leaks
        medium_risk_indicators = suspicious
        
        if high_risk_indicators > 0:
            return 'HIGH'
        elif medium_risk_indicators > 3:
            return 'MEDIUM'
        elif medium_risk_indicators > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_frida_recommendations(self) -> List[str]:
        """Generate recommendations based on Frida analysis"""
        recommendations = []
        
        violations = self.analysis_results['security_violations']
        suspicious = self.analysis_results['suspicious_activities']
        leaks = self.analysis_results['memory_leaks']
        apdus = self.analysis_results['apdu_commands']
        
        if violations:
            recommendations.append(
                "Critical security violations detected. Review default payment app changes "
                "and unauthorized HCE service modifications."
            )
        
        if leaks:
            recommendations.append(
                "Sensitive data detected in memory. Implement proper data sanitization "
                "and use secure memory allocation for sensitive operations."
            )
        
        if any(a.get('suspicious') for a in apdus):
            recommendations.append(
                "Suspicious APDU commands detected. Implement proper input validation "
                "and command filtering in HCE applications."
            )
        
        if len(apdus) > 100:
            recommendations.append(
                "High volume of APDU commands detected. Consider implementing rate limiting "
                "and transaction monitoring."
            )
        
        recommendations.append("Regularly monitor HCE applications for security violations.")
        recommendations.append("Use code obfuscation and anti-debugging techniques in HCE apps.")
        
        return recommendations
    
    def cleanup(self):
        """Clean up Frida session"""
        if self.script:
            try:
                self.script.unload()
                print("[+] Frida script unloaded")
            except Exception as e:
                print(f"[-] Error unloading script: {e}")
        
        if self.session:
            try:
                self.session.detach()
                print("[+] Frida session detached")
            except Exception as e:
                print(f"[-] Error detaching session: {e}")


def main():
    """Main function for Frida HCE analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Frida-based NFC HCE dynamic analyzer")
    parser.add_argument('--device-id', help='USB device ID')
    parser.add_argument('--duration', '-d', type=int, help='Monitoring duration in seconds')
    parser.add_argument('--output', '-o', help='Output file for analysis report (JSON)')
    parser.add_argument('--target-app', help='Target application package name')
    parser.add_argument('--spawn', action='store_true', help='Spawn target application')
    
    args = parser.parse_args()
    
    if not FRIDA_AVAILABLE:
        print("[-] Frida is not available. Please install it with: pip install frida-tools")
        sys.exit(1)
    
    try:
        # Initialize analyzer
        analyzer = FridaHCEAnalyzer(args.device_id, args.spawn)
        
        # Attach to NFC service or target app
        if args.target_app:
            print(f"[+] Targeting application: {args.target_app}")
            # Would implement app-specific attachment here
        
        if not analyzer.attach_to_nfc_service():
            print("[-] Failed to attach to NFC service")
            sys.exit(1)
        
        # Install hooks
        if not analyzer.install_hce_hooks():
            print("[-] Failed to install monitoring hooks")
            sys.exit(1)
        
        # Start monitoring
        results = analyzer.start_monitoring(args.duration)
        
        # Generate report
        report = analyzer.generate_frida_report()
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Analysis report saved to {args.output}")
        else:
            print("\n" + "="*60)
            print("FRIDA ANALYSIS REPORT")
            print("="*60)
            print(json.dumps(report, indent=2))
        
    except KeyboardInterrupt:
        print("\n[+] Analysis interrupted by user")
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        try:
            analyzer.cleanup()
        except:
            pass


if __name__ == "__main__":
    main()