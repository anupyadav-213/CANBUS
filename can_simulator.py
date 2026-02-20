"""
can_simulator.py - CAN Bus Traffic Simulator
Generates realistic and attack CAN bus traffic for testing
"""

import random
import time
from typing import List
from can_message import CANMessage


class VehicleCANSimulator:
    """
    Realistic CAN Bus Traffic Simulator
    Simulates actual vehicle ECU communications
    """
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.timestamp = time.time()
        self.frame_count = 0
    
    def generate_normal_message(self) -> CANMessage:
        """Generate normal vehicle CAN message"""
        self.timestamp += 0.001  # 1ms increment
        self.frame_count += 1
        
        # Select ECU
        ecu_patterns = {
            'engine': (0x100, self._gen_engine_data),
            'brake': (0x200, self._gen_brake_data),
            'transmission': (0x300, self._gen_trans_data),
            'steering': (0x400, self._gen_steering_data),
            'body': (0x500, self._gen_body_data),
            'climate': (0x600, self._gen_climate_data),
            'infotainment': (0x700, self._gen_info_data),
        }
        
        ecu, generator = random.choice(list(ecu_patterns.values()))
        data = generator()
        
        return CANMessage(
            timestamp=self.timestamp,
            can_id=ecu,
            dlc=len(data),
            data=data,
            source_ecu=self._get_ecu_name(ecu)
        )
    
    @staticmethod
    def _gen_engine_data() -> bytes:
        """Engine status message"""
        rpm = random.randint(500, 7000)
        temp = random.randint(70, 120)
        return bytes([
            (rpm >> 8) & 0xFF, rpm & 0xFF,
            temp, random.randint(0, 100),
            0x00, 0x00, 0x00, 0x00
        ])
    
    @staticmethod
    def _gen_brake_data() -> bytes:
        """Brake system message"""
        return bytes([
            random.randint(0, 100),
            random.randint(0, 255),
            0x00, 0x00
        ])
    
    @staticmethod
    def _gen_trans_data() -> bytes:
        """Transmission message"""
        return bytes([
            random.randint(0, 6),
            random.randint(0, 255),
            0x00, 0x00
        ])
    
    @staticmethod
    def _gen_steering_data() -> bytes:
        """Steering message"""
        angle = random.randint(-180, 180)
        return bytes([
            (angle >> 8) & 0xFF, angle & 0xFF,
            random.randint(0, 255), 0x00, 0x00, 0x00
        ])
    
    @staticmethod
    def _gen_body_data() -> bytes:
        """Body control message"""
        return bytes([random.randint(0, 255), 0x00])
    
    @staticmethod
    def _gen_climate_data() -> bytes:
        """Climate control message"""
        return bytes([
            random.randint(16, 30),
            random.randint(0, 4),
            random.randint(0, 3),
            0x00
        ])
    
    @staticmethod
    def _gen_info_data() -> bytes:
        """Infotainment message"""
        return bytes([random.randint(0, 255) for _ in range(8)])
    
    @staticmethod
    def _get_ecu_name(can_id: int) -> str:
        """Get ECU name"""
        names = {
            0x100: "ECM", 0x200: "ABS", 0x300: "TCM",
            0x400: "EPS", 0x500: "BCM", 0x600: "Climate",
            0x700: "IVI"
        }
        return names.get(can_id, f"ECU_0x{can_id:03X}")
    
    def generate_dos_attack(self) -> CANMessage:
        """Generate DoS attack message"""
        self.timestamp += 0.001
        return CANMessage(
            timestamp=self.timestamp,
            can_id=0x100,
            dlc=8,
            data=bytes([0xFF] * 8),
            source_ecu="Attacker"
        )
    
    def generate_injection_attack(self) -> CANMessage:
        """Generate message injection"""
        self.timestamp += 0.001
        return CANMessage(
            timestamp=self.timestamp,
            can_id=0x750,
            dlc=8,
            data=bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00]),
            source_ecu="Injected"
        )
    
    def generate_replay_attack(self) -> CANMessage:
        """Generate replay attack"""
        self.timestamp += 0.001
        return CANMessage(
            timestamp=self.timestamp,
            can_id=0x200,
            dlc=4,
            data=bytes([0xAA, 0xBB, 0xCC, 0xDD]),
            source_ecu="Replayed"
        )
    
    def generate_spoofing_attack(self) -> CANMessage:
        """Generate spoofing attack"""
        self.timestamp += 0.001
        return CANMessage(
            timestamp=self.timestamp,
            can_id=0x300,
            dlc=4,
            data=bytes([random.randint(0, 255) for _ in range(4)]),
            source_ecu="Spoofed"
        )
    
    def generate_anomaly_message(self) -> CANMessage:
        """Generate timing anomaly"""
        self.timestamp += 0.1  # Unusual timing
        return CANMessage(
            timestamp=self.timestamp,
            can_id=0x400,
            dlc=6,
            data=bytes([random.randint(0, 255) for _ in range(6)]),
            source_ecu="ECM"
        )


class TrafficScenarioGenerator:
    """
    Generates realistic attack scenarios
    """
    
    def __init__(self):
        self.simulator = VehicleCANSimulator()
    
    def generate_normal_scenario(self, duration: float = 10.0) -> List[CANMessage]:
        """Generate normal traffic"""
        messages = []
        start = time.time()
        while time.time() - start < duration:
            messages.append(self.simulator.generate_normal_message())
        return messages
    
    def generate_dos_scenario(self, duration: float = 10.0) -> List[CANMessage]:
        """Generate DoS attack scenario"""
        messages = []
        start = time.time()
        attack_start = start + duration * 0.3
        
        while time.time() - start < duration:
            if time.time() < attack_start:
                messages.append(self.simulator.generate_normal_message())
            else:
                for _ in range(5):
                    messages.append(self.simulator.generate_dos_attack())
        
        return messages
    
    def generate_injection_scenario(self, duration: float = 10.0) -> List[CANMessage]:
        """Generate injection attack scenario"""
        messages = []
        start = time.time()
        attack_start = start + duration * 0.3
        
        while time.time() - start < duration:
            if time.time() < attack_start:
                messages.append(self.simulator.generate_normal_message())
            else:
                messages.append(self.simulator.generate_injection_attack())
        
        return messages
    
    def generate_replay_scenario(self, duration: float = 10.0) -> List[CANMessage]:
        """Generate replay attack scenario"""
        messages = []
        start = time.time()
        attack_start = start + duration * 0.3
        
        while time.time() - start < duration:
            if time.time() < attack_start:
                messages.append(self.simulator.generate_normal_message())
            else:
                messages.append(self.simulator.generate_replay_attack())
        
        return messages
    
    def generate_mixed_scenario(self) -> List[CANMessage]:
        """Generate mixed normal + attack traffic"""
        messages = []
        
        # 70% normal
        for _ in range(700):
            messages.append(self.simulator.generate_normal_message())
        
        # 30% attacks
        attack_types = [
            self.simulator.generate_dos_attack,
            self.simulator.generate_injection_attack,
            self.simulator.generate_replay_attack,
            self.simulator.generate_spoofing_attack,
            self.simulator.generate_anomaly_message,
        ]
        
        for _ in range(300):
            attack = random.choice(attack_types)
            messages.append(attack())
        
        # Sort by timestamp
        messages.sort(key=lambda m: m.timestamp)
        
        return messages
