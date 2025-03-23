#!/usr/bin/env python3
"""
Malicious Command Detector - Main Application
A security tool for detecting malicious patterns in curl and bash commands.
"""

import os
import sys
import argparse
import configparser
from engine import analyze_command

def display_risk_score(score):
    """Displays risk score with color and visual representation in terminal."""
    score = round(score, 1)
    
    if score >= 8:
        color = "\033[91m"  # Red
        level = "HIGH RISK"
    elif score >= 4:
        color = "\033[93m"  # Yellow
        level = "CAUTION"
    else:
        color = "\033[92m"  # Green
        level = "SAFE"
    
    reset = "\033[0m"  # Reset color
    filled = int(score)
    bar = "█" * filled + "░" * (10 - filled)
    
    print(f"\nRisk Assessment:")
    print(f"{color}[{bar}] {score}/10 - {level}{reset}")

def display_banner():
    """Displays application banner."""
    banner = """
 ╔═══════════════════════════════════════════════════╗
 ║  Malicious Command Detector v1.0                  ║
 ║  With VirusTotal Integration                      ║
 ╚═══════════════════════════════════════════════════╝
    """
    print(banner)

def load_config():
    """Loads configuration from config.ini file or environment variables."""
    api_key = None
    
    # Try to load from config file
    if os.path.exists('config.ini'):
        config = configparser.ConfigParser()
        config.read('config.ini')
        if 'VirusTotal' in config and 'api_key' in config['VirusTotal']:
            api_key = config['VirusTotal']['api_key']
    
    # If not found, try environment variable
    if not api_key:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    
    return api_key

def interactive_mode(api_key):
    """Run the detector in interactive mode to analyze commands entered by the user."""
    print("Interactive Mode - Enter commands to analyze (type 'exit' to quit)")
    print("=" * 60)
    
    if api_key:
        print(f"VirusTotal API Key: {'*' * 8}{api_key[-4:]}")
        print("URL analysis with VirusTotal is enabled.")
    else:
        print("No VirusTotal API key configured. URL analysis is disabled.")
    
    print("=" * 60)
    
    while True:
        try:
            command = input("\nEnter command to analyze: ")
            if command.lower() in ['exit', 'quit', 'q']:
                break
                
            if not command.strip():
                continue
                
            result, score, patterns = analyze_command(command, api_key)
            
            print(f"\nCommand: {command}")
            print(f"Result: {result}")
            display_risk_score(score)
            
            if patterns:
                print("\nDetected patterns:")
                for pattern in patterns:
                    print(f"- {pattern}")
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
    
    print("\nThank you for using Malicious Command Detector!")

def analyze_single_command(command, api_key):
    """Analyze a single command passed as argument."""
    result, score, patterns = analyze_command(command, api_key)
    
    print(f"Command: {command}")
    print(f"Result: {result}")
    display_risk_score(score)
    
    if patterns:
        print("\nDetected patterns:")
        for pattern in patterns:
            print(f"- {pattern}")

def main():
    """Main function to parse arguments and execute the program."""
    parser = argparse.ArgumentParser(description="Malicious Command Detector with VirusTotal Integration")
    parser.add_argument("-c", "--command", help="Single command to analyze")
    parser.add_argument("--api-key", help="VirusTotal API key (overrides config file and environment variable)")
    args = parser.parse_args()
    
    display_banner()
    
    # Get API key from arguments, config, or environment
    api_key = args.api_key or load_config()
    
    if args.command:
        # Single command mode
        analyze_single_command(args.command, api_key)
    else:
        # Interactive mode
        interactive_mode(api_key)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)
