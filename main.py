#!/usr/bin/env python3
"""
CAN Bus Security Analyzer
Main entry point for the application

Usage:
    python main.py --demo              Run demonstration
    python main.py --analyze FILE      Analyze CAN messages
    python main.py --scenario TYPE     Run specific scenario
    python main.py --report FILE       Generate report
"""

import sys
import argparse
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from can_analyzer import CANBusSecurityAnalyzer, run_demo
from can_simulator import TrafficScenarioGenerator
from can_message import CANMessage


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='CAN Bus Security Analyzer - Detect automotive network attacks'
    )
    
    parser.add_argument('--demo', action='store_true',
                       help='Run demonstration')
    
    parser.add_argument('--scenario', type=str,
                       choices=['normal', 'dos', 'injection', 'replay', 'mixed'],
                       help='Run specific scenario')
    
    parser.add_argument('--analyze', type=str,
                       help='Analyze messages from JSON file')
    
    parser.add_argument('--report', type=str,
                       help='Save report to file')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Demo mode
    if args.demo:
        print("[*] Running demonstration...")
        run_demo()
        return
    
    # Scenario mode
    if args.scenario:
        print(f"[*] Running {args.scenario} scenario...")
        generator = TrafficScenarioGenerator()
        
        scenario_map = {
            'normal': generator.generate_normal_scenario,
            'dos': generator.generate_dos_scenario,
            'injection': generator.generate_injection_scenario,
            'replay': generator.generate_replay_scenario,
            'mixed': generator.generate_mixed_scenario,
        }
        
        messages = scenario_map[args.scenario]()
        
        analyzer = CANBusSecurityAnalyzer()
        analyzer.analyze(messages)
        analyzer.print_summary()
        
        if args.report:
            analyzer.save_report(args.report)
        
        return
    
    # Analyze mode
    if args.analyze:
        print(f"[*] Analyzing {args.analyze}...")
        
        with open(args.analyze, 'r') as f:
            data = json.load(f)
        
        messages = [CANMessage.from_dict(m) for m in data.get('messages', [])]
        print(f"[*] Loaded {len(messages)} messages")
        
        analyzer = CANBusSecurityAnalyzer()
        analyzer.analyze(messages)
        analyzer.print_summary()
        
        if args.report:
            analyzer.save_report(args.report)
        
        return
    
    # Default: show help
    parser.print_help()


if __name__ == '__main__':
    main()
