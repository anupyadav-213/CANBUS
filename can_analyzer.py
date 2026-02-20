"""
can_analyzer.py - Main CAN Bus Security Analyzer
Comprehensive analysis system with reporting
"""

import json
import time
import uuid
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

from can_message import CANMessage, CANStatistics, AnalysisReport, SecurityAlert
from detection_engines import SecurityAnalysisEngine
from can_simulator import VehicleCANSimulator, TrafficScenarioGenerator


class CANBusSecurityAnalyzer:
    """
    Complete CAN Bus Security Analysis System
    """
    
    def __init__(self, name: str = "CAN Bus Analyzer"):
        self.name = name
        self.engine = SecurityAnalysisEngine()
        self.messages = []
        self.stats = {}  # {can_id: CANStatistics}
        self.start_time = None
        self.end_time = None
        self.report = None
    
    def analyze(self, messages: List[CANMessage]) -> Dict:
        """Analyze CAN messages"""
        self.start_time = time.time()
        self.messages = messages
        self.engine.reset()
        self.stats.clear()
        
        # Process each message
        for message in messages:
            # Analyze with detection engines
            self.engine.analyze(message)
            
            # Update statistics
            self._update_stats(message)
        
        self.end_time = time.time()
        
        # Generate report
        return self._generate_report()
    
    def _update_stats(self, message: CANMessage):
        """Update message statistics"""
        can_id = message.can_id
        
        if can_id not in self.stats:
            self.stats[can_id] = CANStatistics(can_id=can_id)
        
        stat = self.stats[can_id]
        stat.message_count += 1
        stat.data_patterns.add(hash(message.data))
        stat.bytes_sent += len(message.data)
        
        if stat.first_seen is None:
            stat.first_seen = message.timestamp
        
        stat.last_seen = message.timestamp
        
        stat.min_dlc = min(stat.min_dlc, message.dlc)
        stat.max_dlc = max(stat.max_dlc, message.dlc)
        
        if stat.first_seen and stat.last_seen:
            duration = stat.last_seen - stat.first_seen
            if duration > 0:
                stat.message_rate = stat.message_count / duration
    
    def _generate_report(self) -> Dict:
        """Generate analysis report"""
        duration = self.end_time - self.start_time
        summary = self.engine.get_summary()
        
        # Compile stats
        msg_stats = {}
        for can_id, stat in self.stats.items():
            msg_stats[f"0x{can_id:03X}"] = stat.to_dict()
        
        # Create report
        report_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'analyzer': self.name,
                'version': '2.0'
            },
            'analysis': {
                'total_messages': len(self.messages),
                'duration_seconds': round(duration, 3),
                'avg_rate': round(len(self.messages) / duration if duration > 0 else 0, 2),
                'unique_ids': len(self.stats)
            },
            'security': summary,
            'message_stats': msg_stats,
            'alerts': [alert.to_dict() for alert in self.engine.alerts],
            'timeline': self._generate_timeline()
        }
        
        self.report = report_data
        return report_data
    
    def _generate_timeline(self) -> List[Dict]:
        """Generate event timeline"""
        if not self.messages:
            return []
        
        timeline = []
        base_time = self.messages[0].timestamp
        
        for alert in sorted(self.engine.alerts, key=lambda a: a.timestamp):
            timeline.append({
                'offset_seconds': round(alert.timestamp - base_time, 3),
                'event_type': alert.alert_type,
                'severity': alert.severity,
                'can_id': f'0x{alert.can_id:03X}',
                'confidence': round(alert.confidence, 2)
            })
        
        return timeline
    
    def save_report(self, filepath: str):
        """Save report to JSON"""
        if not self.report:
            raise ValueError("No analysis completed yet")
        
        with open(filepath, 'w') as f:
            json.dump(self.report, f, indent=2)
        
        print(f"✓ Report saved: {filepath}")
    
    def print_summary(self):
        """Print analysis summary"""
        if not self.report:
            print("No analysis completed")
            return
        
        print("\n" + "="*70)
        print("CAN BUS SECURITY ANALYSIS REPORT")
        print("="*70)
        
        meta = self.report['metadata']
        analysis = self.report['analysis']
        security = self.report['security']
        
        print(f"\nTimestamp: {meta['timestamp']}")
        print(f"Analyzer: {meta['analyzer']} v{meta['version']}")
        
        print(f"\nAnalysis Scope:")
        print(f"  Messages: {analysis['total_messages']}")
        print(f"  Duration: {analysis['duration_seconds']}s")
        print(f"  Rate: {analysis['avg_rate']} msg/sec")
        print(f"  Unique IDs: {analysis['unique_ids']}")
        
        print(f"\nSecurity Summary:")
        print(f"  Total Alerts: {security['total_alerts']}")
        
        if security['alert_types']:
            print(f"\n  Alert Types:")
            for atype, count in security['alert_types'].items():
                print(f"    • {atype}: {count}")
        
        if security['severities']:
            print(f"\n  Severities:")
            for severity, count in security['severities'].items():
                print(f"    • {severity}: {count}")
        
        print(f"\nTop Affected CAN IDs:")
        for can_id, count in sorted(
            security['affected_can_ids'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]:
            print(f"  {can_id}: {count} alerts")
        
        if self.report['alerts']:
            print(f"\nRecent Alerts (Last 5):")
            for alert in self.report['alerts'][-5:]:
                print(f"\n  [{alert['severity']}] {alert['alert_type']}")
                print(f"    CAN ID: {alert['can_id']}")
                print(f"    Confidence: {alert['confidence']:.0%}")
                print(f"    {alert['description']}")
        
        print("\n" + "="*70 + "\n")


class RealtimeMonitor:
    """Real-time CAN bus monitoring"""
    
    def __init__(self):
        self.analyzer = CANBusSecurityAnalyzer("Realtime Monitor")
        self.buffer = []
    
    def process_message(self, message: CANMessage) -> List[SecurityAlert]:
        """Process single message"""
        self.buffer.append(message)
        alerts = self.analyzer.engine.analyze(message)
        
        for alert in alerts:
            self._display_alert(alert)
        
        return alerts
    
    def _display_alert(self, alert: SecurityAlert):
        """Display alert"""
        print(f"⚠️  {alert.alert_type.upper()}")
        print(f"    Severity: {alert.severity}")
        print(f"    CAN ID: 0x{alert.can_id:03X}")
        print(f"    Confidence: {alert.confidence:.0%}")
        print(f"    {alert.description}\n")


def run_demo():
    """Run complete demonstration"""
    print("\n" + "="*70)
    print("CAN BUS SECURITY ANALYZER - DEMONSTRATION")
    print("="*70 + "\n")
    
    # Generate traffic
    print("[*] Generating test traffic...")
    generator = TrafficScenarioGenerator()
    messages = generator.generate_mixed_scenario()
    print(f"[*] Generated {len(messages)} messages")
    
    # Analyze
    print("[*] Running security analysis...")
    analyzer = CANBusSecurityAnalyzer()
    results = analyzer.analyze(messages)
    
    # Display results
    analyzer.print_summary()
    
    # Save report
    report_path = "/mnt/user-data/outputs/can_security_report.json"
    try:
        analyzer.save_report(report_path)
    except Exception as e:
        print(f"Could not save report: {e}")
    
    return results


if __name__ == "__main__":
    run_demo()
