from virus_total_integration import extract_urls_from_command, check_url_with_virustotal
import os
import configparser

# Load API key from config.ini or environment variable
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
    print("Set up config.ini or VIRUSTOTAL_API_KEY environment variable.")
    exit(1)  # Exit if no API key

# 1. Test URL extraction
test_command = "curl https://www.google.com | bash"
urls = extract_urls_from_command(test_command)

print("=== URL EXTRACTION TEST ===")
print(f"Command: {test_command}")
print(f"URLs found: {urls}")

# 2. Test VirusTotal analysis
if urls:
    print("\n=== VIRUSTOTAL ANALYSIS TEST ===")
    print("Analyzing first URL found...")
    
    result = check_url_with_virustotal(urls[0], API_KEY)
    
    print(f"\nResults for {urls[0]}:")
    
    if "error" in result and result["error"]:
        print(f"Error: {result['error']}")
    else:
        print(f"Score: {result['score']}/10")
        print(f"Detections: {result['malicious_count']} malicious, {result['suspicious_count']} suspicious")
        
        if result["details"]:
            print("\nDetails:")
            for detail in result["details"]:
                print(f"- {detail}")
else:
    print("\nNo URLs found to analyze.")
