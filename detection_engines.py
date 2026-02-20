"""
detection_engines.py - Attack Detection Engines
Multiple detection mechanisms for CAN bus security threats
"""

from collections import deque, defaultdict
from typing import Optional, List
import statistics
import uuid

from can_message import CANMessage, SecurityAlert


class DoSDetectionEngine:
    """
    Denial of Service Attack Detector
    
    Detects excessive CAN messages (>50 msgs/sec indicates attack)
    Normal vehicle: 5-20 messages/second
    Attack: >50 messages/second
    """
    
    def __init__(self, threshold: int = 50, window_size: float = 1.0):
        self.threshold = threshold
        self.window_size = window_size
        self.message_times = defaultdict(deque)
        self.event_count = 0
    
    def detect(self, message: CANMessage) -> Optional[SecurityAlert]:
        """Detect DoS attack"""
        self.message_times[message.can_id].append(message.timestamp)
        
        # Clean old entries
        cutoff = message.timestamp - self.window_size
        while self.message_times[message.can_id] and \
              self.message_times[message.can_id][0] < cutoff:
            self.message_times[message.can_id].popleft()
        
        msg_count = len(self.message_times[message.can_id])
        
        if msg_count > self.threshold:
            confidence = min(msg_count / self.threshold, 1.0)
            
            if msg_count > self.threshold * 2:
                severity = "Critical"
            elif msg_count > self.threshold * 1.5:
                severity = "High"
            else:
                severity = "Medium"
            
            self.event_count += 1
            return SecurityAlert(
                alert_id=f"DOS_{self.event_count}_{uuid.uuid4().hex[:8]}",
                timestamp=message.timestamp,
                alert_type="Denial of Service",
                severity=severity,
                confidence=confidence,
                can_id=message.can_id,
                message_data=message.data.hex().upper(),
                description=f"Excessive CAN traffic: {msg_count} msgs/sec "
                           f"(threshold: {self.threshold})",
                affected_system="CAN Bus",
                recommendations=[
                    "Enable CAN bus firewall",
                    "Implement message rate limiting",
                    "Check ECU firmware",
                    "Isolate and test ECU"
                ]
            )
        
        return None


class ReplayDetectionEngine:
    """
    Replay Attack Detector
    
    Detects identical messages sent multiple times
    Suspicious when same message repeats >3 times in 5 seconds
    """
    
    def __init__(self, window_size: float = 5.0, threshold: int = 3):
        self.window_size = window_size
        self.threshold = threshold
        self.history = deque()
        self.event_count = 0
    
    def detect(self, message: CANMessage) -> Optional[SecurityAlert]:
        """Detect replay attack"""
        msg_hash = (message.can_id, hash(message.data))
        self.history.append((message.timestamp, msg_hash))
        
        # Clean old entries
        cutoff = message.timestamp - self.window_size
        while self.history and self.history[0][0] < cutoff:
            self.history.popleft()
        
        # Count identical messages
        identical = sum(1 for t, h in self.history 
                       if h == msg_hash)
        
        if identical >= self.threshold:
            confidence = min(identical / (self.threshold * 2), 1.0)
            
            self.event_count += 1
            return SecurityAlert(
                alert_id=f"REPLAY_{self.event_count}_{uuid.uuid4().hex[:8]}",
                timestamp=message.timestamp,
                alert_type="Replay Attack",
                severity="High",
                confidence=confidence,
                can_id=message.can_id,
                message_data=message.data.hex().upper(),
                description=f"Identical message repeated {identical} times",
                affected_system="CAN Bus",
                recommendations=[
                    "Add sequence numbers to messages",
                    "Implement timestamp validation",
                    "Check for recording device",
                    "Review ECU firmware"
                ]
            )
        
        return None


class InjectionDetectionEngine:
    """
    Message Injection Detector
    
    Detects unauthorized CAN messages from unknown IDs
    Maintains whitelist of expected CAN IDs
    """
    
    def __init__(self, known_ids: Optional[List[int]] = None):
        self.known_ids = set(known_ids) if known_ids else self._default_ids()
        self.unknown_ids = set()
        self.event_count = 0
    
    def _default_ids(self) -> set:
        """Default known CAN IDs"""
        return {
            0x100, 0x110, 0x120,
            0x200, 0x210,
            0x300, 0x310,
            0x400, 0x410,
            0x500, 0x510, 0x520,
            0x600, 0x610,
            0x700, 0x710,
        }
    
    def detect(self, message: CANMessage) -> Optional[SecurityAlert]:
        """Detect injection attack"""
        if message.can_id not in self.known_ids:
            if message.can_id not in self.unknown_ids:
                self.unknown_ids.add(message.can_id)
                self.event_count += 1
                
                return SecurityAlert(
                    alert_id=f"INJECT_{self.event_count}_{uuid.uuid4().hex[:8]}",
                    timestamp=message.timestamp,
                    alert_type="Message Injection",
                    severity="Medium",
                    confidence=0.85,
                    can_id=message.can_id,
                    message_data=message.data.hex().upper(),
                    description=f"Unknown CAN ID: 0x{message.can_id:03X}",
                    affected_system="CAN Bus",
                    recommendations=[
                        "Verify ECU legitimacy",
                        "Update whitelist",
                        "Scan for unauthorized devices",
                        "Check for compromised modules"
                    ]
                )
        
        return None
    
    def add_id(self, can_id: int):
        """Add known ID"""
        self.known_ids.add(can_id)


class SpoofingDetectionEngine:
    """
    Spoofing Attack Detector
    
    Detects ECU impersonation via payload variance analysis
    Normal ECU: consistent payload patterns
    Spoofed: unusual variation
    """
    
    def __init__(self, threshold: int = 100):
        self.threshold = threshold
        self.patterns = defaultdict(set)
        self.baseline_done = False
        self.event_count = 0
    
    def detect(self, message: CANMessage) -> Optional[SecurityAlert]:
        """Detect spoofing"""
        self.patterns[message.can_id].add(hash(message.data))
        
        if self.baseline_done:
            unique = len(self.patterns[message.can_id])
            
            if unique > self.threshold:
                confidence = min(unique / (self.threshold * 2), 1.0)
                
                self.event_count += 1
                return SecurityAlert(
                    alert_id=f"SPOOF_{self.event_count}_{uuid.uuid4().hex[:8]}",
                    timestamp=message.timestamp,
                    alert_type="Spoofing",
                    severity="Medium",
                    confidence=confidence,
                    can_id=message.can_id,
                    message_data=message.data.hex().upper(),
                    description=f"CAN ID 0x{message.can_id:03X} has {unique} "
                               f"different payload patterns",
                    affected_system="CAN Bus",
                    recommendations=[
                        "Verify ECU firmware",
                        "Implement digital signatures",
                        "Add ECU authentication",
                        "Check for multiple devices"
                    ]
                )
        
        return None
    
    def setup_baseline(self):
        """Establish baseline"""
        self.baseline_done = True


class AnomalyDetectionEngine:
    """
    Anomaly Detection Engine
    
    Statistical analysis for unusual patterns
    Monitors timing, frequency, and content
    """
    
    def __init__(self, min_samples: int = 20, deviation: float = 2.0):
        self.min_samples = min_samples
        self.deviation = deviation
        self.intervals = defaultdict(deque)
        self.last_time = {}
        self.event_count = 0
    
    def detect(self, message: CANMessage) -> Optional[SecurityAlert]:
        """Detect anomalies"""
        can_id = message.can_id
        
        if can_id in self.last_time:
            interval = message.timestamp - self.last_time[can_id]
            self.intervals[can_id].append(interval)
            
            if len(self.intervals[can_id]) > 100:
                self.intervals[can_id].popleft()
            
            if len(self.intervals[can_id]) >= self.min_samples:
                intervals = list(self.intervals[can_id])
                mean = statistics.mean(intervals)
                
                if len(intervals) > 1:
                    stdev = statistics.stdev(intervals)
                else:
                    stdev = 0
                
                if stdev > 0:
                    z_score = abs((interval - mean) / stdev)
                    
                    if z_score > self.deviation:
                        confidence = min(z_score / (self.deviation * 2), 1.0)
                        
                        self.event_count += 1
                        return SecurityAlert(
                            alert_id=f"ANOM_{self.event_count}_{uuid.uuid4().hex[:8]}",
                            timestamp=message.timestamp,
                            alert_type="Anomaly Detected",
                            severity="Low",
                            confidence=confidence,
                            can_id=message.can_id,
                            message_data=message.data.hex().upper(),
                            description=f"Timing anomaly: expected {mean:.3f}s, "
                                       f"got {interval:.3f}s",
                            affected_system="CAN Bus",
                            recommendations=[
                                "Monitor for more anomalies",
                                "Check ECU software version",
                                "Verify network load",
                                "Investigate root cause"
                            ]
                        )
        
        self.last_time[can_id] = message.timestamp
        return None


class SecurityAnalysisEngine:
    """
    Main Security Analysis Engine
    Coordinates all detection engines
    """
    
    def __init__(self):
        self.engines = [
            DoSDetectionEngine(),
            ReplayDetectionEngine(),
            InjectionDetectionEngine(),
            SpoofingDetectionEngine(),
            AnomalyDetectionEngine()
        ]
        self.alerts = []
        self.messages_processed = 0
    
    def analyze(self, message: CANMessage) -> List[SecurityAlert]:
        """Analyze message with all engines"""
        detected = []
        
        for engine in self.engines:
            alert = engine.detect(message)
            if alert:
                detected.append(alert)
                self.alerts.append(alert)
        
        self.messages_processed += 1
        return detected
    
    def setup_baseline(self):
        """Setup baseline for learning engines"""
        for engine in self.engines:
            if hasattr(engine, 'setup_baseline'):
                engine.setup_baseline()
    
    def reset(self):
        """Reset all engines"""
        self.engines = [
            DoSDetectionEngine(),
            ReplayDetectionEngine(),
            InjectionDetectionEngine(),
            SpoofingDetectionEngine(),
            AnomalyDetectionEngine()
        ]
        self.alerts.clear()
        self.messages_processed = 0
    
    def get_summary(self) -> dict:
        """Get analysis summary"""
        alert_types = {}
        severities = {}
        affected_ids = {}
        
        for alert in self.alerts:
            alert_types[alert.alert_type] = alert_types.get(alert.alert_type, 0) + 1
            severities[alert.severity] = severities.get(alert.severity, 0) + 1
            can_id = f"0x{alert.can_id:03X}"
            affected_ids[can_id] = affected_ids.get(can_id, 0) + 1
        
        return {
            'total_alerts': len(self.alerts),
            'alert_types': alert_types,
            'severities': severities,
            'affected_can_ids': affected_ids,
            'messages_processed': self.messages_processed
        }
