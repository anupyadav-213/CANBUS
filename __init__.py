"""
CAN Bus Security Analyzer Package
"""

from can_message import CANMessage, CANStatistics, SecurityAlert, AnalysisReport
from detection_engines import SecurityAnalysisEngine
from can_simulator import VehicleCANSimulator, TrafficScenarioGenerator
from can_analyzer import CANBusSecurityAnalyzer, RealtimeMonitor

__version__ = "2.0"
__author__ = "Your Name"
__all__ = [
    'CANMessage',
    'CANStatistics',
    'SecurityAlert',
    'AnalysisReport',
    'SecurityAnalysisEngine',
    'VehicleCANSimulator',
    'TrafficScenarioGenerator',
    'CANBusSecurityAnalyzer',
    'RealtimeMonitor'
]
