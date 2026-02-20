"""
can_message.py - CAN Message Data Models
Comprehensive data structures for CAN bus communication and analysis
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Set
import json
import hashlib


class FrameType(Enum):
    """CAN Frame Types"""
    STANDARD = "Standard (11-bit ID)"
    EXTENDED = "Extended (29-bit ID)"
    REMOTE = "Remote Request"
    ERROR = "Error Frame"


class MessageStatus(Enum):
    """Message Analysis Status"""
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    UNKNOWN = "Unknown"


@dataclass
class CANMessage:
    """
    Represents a single CAN bus message
    
    Standard CAN (11-bit):
        - ID range: 0x000 - 0x7FF
        - Max payload: 8 bytes
    
    Extended CAN (29-bit):
        - ID range: 0x00000000 - 0x1FFFFFFF
        - Max payload: 8 bytes
    
    CAN-FD (Flexible Data-rate):
        - Max payload: 64 bytes
        - Higher data rates
    """
    
    timestamp: float                          # Unix timestamp
    can_id: int                               # CAN identifier
    dlc: int                                  # Data Length Code (0-8 or 0-64 for FD)
    data: bytes                               # Payload
    is_extended: bool = False                 # 29-bit ID flag
    is_rtr: bool = False                      # Remote Transmission Request
    is_fd: bool = False                       # CAN-FD frame
    is_error: bool = False                    # Error frame
    source_ecu: Optional[str] = None          # Source ECU
    destination_ecu: Optional[str] = None     # Destination ECU
    sequence_number: Optional[int] = None     # Sequence number
    
    def __post_init__(self):
        """Validate message on creation"""
        # Validate CAN ID range
        max_id = 0x1FFFFFFF if self.is_extended else 0x7FF
        if not 0 <= self.can_id <= max_id:
            raise ValueError(f"Invalid CAN ID: 0x{self.can_id:X}")
        
        # Validate DLC
        max_dlc = 64 if self.is_fd else 8
        if not 0 <= self.dlc <= max_dlc:
            raise ValueError(f"Invalid DLC: {self.dlc}")
        
        # Validate data length matches DLC
        if len(self.data) != self.dlc:
            raise ValueError(f"Data length {len(self.data)} doesn't match DLC {self.dlc}")
    
    def __hash__(self):
        """Hash for pattern tracking"""
        return hash((self.can_id, bytes(self.data)))
    
    def get_checksum(self) -> str:
        """Calculate SHA256 checksum of message"""
        msg_bytes = bytes([self.can_id >> 8, self.can_id & 0xFF]) + self.data
        return hashlib.sha256(msg_bytes).hexdigest()
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'timestamp': round(self.timestamp, 6),
            'can_id': f'0x{self.can_id:03X}',
            'dlc': self.dlc,
            'data': self.data.hex().upper(),
            'is_extended': self.is_extended,
            'is_rtr': self.is_rtr,
            'is_fd': self.is_fd,
            'source_ecu': self.source_ecu,
            'destination_ecu': self.destination_ecu,
            'sequence_number': self.sequence_number
        }
    
    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: dict) -> 'CANMessage':
        """Create from dictionary"""
        return cls(
            timestamp=data['timestamp'],
            can_id=int(data['can_id'], 16) if isinstance(data['can_id'], str) else data['can_id'],
            dlc=data['dlc'],
            data=bytes.fromhex(data['data']) if isinstance(data['data'], str) else data['data'],
            is_extended=data.get('is_extended', False),
            is_rtr=data.get('is_rtr', False),
            is_fd=data.get('is_fd', False),
            is_error=data.get('is_error', False),
            source_ecu=data.get('source_ecu'),
            destination_ecu=data.get('destination_ecu'),
            sequence_number=data.get('sequence_number')
        )
    
    def get_byte(self, index: int) -> int:
        """Get specific byte"""
        if not 0 <= index < len(self.data):
            raise IndexError(f"Byte index {index} out of range")
        return self.data[index]
    
    def get_bits(self, start_bit: int, length: int) -> int:
        """Extract bits from message"""
        byte_index = start_bit // 8
        bit_offset = start_bit % 8
        value = 0
        for i in range(length):
            bit_pos = bit_offset + i
            byte_idx = byte_index + (bit_pos // 8)
            bit_idx = bit_pos % 8
            if byte_idx < len(self.data):
                bit = (self.data[byte_idx] >> bit_idx) & 1
                value |= (bit << i)
        return value
    
    def set_byte(self, index: int, value: int):
        """Set specific byte (creates new CANMessage)"""
        if not 0 <= index < len(self.data):
            raise IndexError(f"Byte index {index} out of range")
        data_list = list(self.data)
        data_list[index] = value & 0xFF
        self.data = bytes(data_list)


@dataclass
class CANStatistics:
    """Statistics for a CAN ID"""
    can_id: int
    message_count: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    data_patterns: Set[int] = field(default_factory=set)  # Hash values
    min_dlc: int = 8
    max_dlc: int = 0
    avg_dlc: float = 0.0
    message_rate: float = 0.0  # messages per second
    bytes_sent: int = 0
    
    def to_dict(self) -> dict:
        return {
            'can_id': f'0x{self.can_id:03X}',
            'message_count': self.message_count,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'unique_patterns': len(self.data_patterns),
            'min_dlc': self.min_dlc,
            'max_dlc': self.max_dlc,
            'avg_dlc': round(self.avg_dlc, 2),
            'message_rate': round(self.message_rate, 2),
            'bytes_sent': self.bytes_sent
        }


@dataclass
class SecurityAlert:
    """Security alert/event"""
    alert_id: str
    timestamp: float
    alert_type: str  # DoS, Injection, Replay, Spoofing, Anomaly
    severity: str  # Critical, High, Medium, Low
    confidence: float  # 0.0-1.0
    can_id: int
    message_data: str  # Hex string
    description: str
    affected_system: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'alert_id': self.alert_id,
            'timestamp': round(self.timestamp, 6),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'confidence': round(self.confidence, 3),
            'can_id': f'0x{self.can_id:03X}',
            'message_data': self.message_data,
            'description': self.description,
            'affected_system': self.affected_system,
            'recommendations': self.recommendations
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class AnalysisReport:
    """Complete analysis report"""
    report_id: str
    timestamp: float
    analysis_duration: float
    total_messages: int = 0
    total_alerts: int = 0
    message_stats: Dict[str, dict] = field(default_factory=dict)
    alerts: List[SecurityAlert] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            'report_id': self.report_id,
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'analysis_duration_seconds': round(self.analysis_duration, 2),
            'total_messages': self.total_messages,
            'total_alerts': self.total_alerts,
            'message_statistics': self.message_stats,
            'alerts': [alert.to_dict() for alert in self.alerts],
            'summary': self.summary
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    def save(self, filepath: str):
        """Save report to file"""
        with open(filepath, 'w') as f:
            f.write(self.to_json())
        return filepath
    
    @classmethod
    def load(cls, filepath: str) -> 'AnalysisReport':
        """Load report from file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls(
            report_id=data['report_id'],
            timestamp=datetime.fromisoformat(data['timestamp']).timestamp(),
            analysis_duration=data['analysis_duration_seconds']
        )


# ECU Database
COMMON_ECU_IDS = {
    0x100: {'name': 'Engine Status', 'ecu': 'ECM'},
    0x110: {'name': 'Engine Temperature', 'ecu': 'ECM'},
    0x120: {'name': 'Engine RPM', 'ecu': 'ECM'},
    0x200: {'name': 'Brake Status', 'ecu': 'ABS'},
    0x210: {'name': 'Brake Pressure', 'ecu': 'ABS'},
    0x300: {'name': 'Transmission State', 'ecu': 'TCM'},
    0x310: {'name': 'Gear Selection', 'ecu': 'TCM'},
    0x400: {'name': 'Steering Angle', 'ecu': 'EPS'},
    0x410: {'name': 'Steering Torque', 'ecu': 'EPS'},
    0x500: {'name': 'Vehicle Speed', 'ecu': 'BCM'},
    0x510: {'name': 'Door Status', 'ecu': 'BCM'},
    0x520: {'name': 'Window Status', 'ecu': 'BCM'},
    0x600: {'name': 'HVAC Status', 'ecu': 'Climate'},
    0x610: {'name': 'Temperature', 'ecu': 'Climate'},
    0x700: {'name': 'Infotainment', 'ecu': 'IVI'},
    0x710: {'name': 'Navigation', 'ecu': 'IVI'},
}

def get_ecu_info(can_id: int) -> dict:
    """Get ECU info for CAN ID"""
    if can_id in COMMON_ECU_IDS:
        return COMMON_ECU_IDS[can_id]
    return {'name': 'Unknown', 'ecu': 'Unknown'}
