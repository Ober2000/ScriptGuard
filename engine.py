import re
import base64
import os

# Import VirusTotal integration functions
from virus_total_integration import extract_urls_from_command, check_url_with_virustotal

def analyze_command(command, virustotal_api_key=None):
    """
    Analyzes a command to detect malicious patterns.
    
    Args:
        command (str): Command to analyze
        virustotal_api_key (str, optional): VirusTotal API Key
    
    Returns:
        tuple: (result, risk_score, detected_patterns)
    """
    risk_score = 0
    detected_patterns = []

    parts = [part.strip() for part in command.split('|')]
    
    # Curl command detection
    if "curl" in command.lower():
        detected_patterns.append("Curl command detected")
        urls = re.findall(r'https?://\S+', command)
        for url in urls:
            detected_patterns.append(f"URL detected: {url}")

            # Check against suspicious domains database
            suspicious_domains = ['pastebin.com', 'githubusercontent.com', 'gist.github.com']
            for domain in suspicious_domains:
                if domain in url:
                    risk_score += 2
                    detected_patterns.append(f"Potentially dangerous domain: {domain}")

            # Check for executable script extensions
            script_extensions = ['.sh', '.bash', '.py', '.pl', '.rb']
            for ext in script_extensions:
                if url.lower().endswith(ext):
                    risk_score += 2
                    detected_patterns.append(f"Executable script download ({ext})")

            # Check for suspicious flags
            if "--insecure" in command or "-k" in command.split():
                risk_score += 3
                detected_patterns.append("Using curl with SSL verification disabled (--insecure)")
                
            # VirusTotal analysis if API key is available
            if virustotal_api_key:
                vt_result = check_url_with_virustotal(url, virustotal_api_key)
                
                if "error" not in vt_result or not vt_result["error"]:
                    score = vt_result["score"]
                    detected_patterns.append(f"VirusTotal Score: {score}/10 for {url}")
                    
                    # Add to risk score based on VirusTotal results
                    if score > 0:
                        # Add up to 5 additional points based on VirusTotal score
                        additional_score = min(5, score / 2)
                        risk_score += additional_score
                        
                        if vt_result["malicious_count"] > 0:
                            detected_patterns.append(f"VirusTotal: {vt_result['malicious_count']} malicious detections")
                            
                        if vt_result["details"]:
                            for detail in vt_result["details"][:3]:  # Limit to 3 details
                                detected_patterns.append(f"VirusTotal detection: {detail}")

    # Shell command detection
    if "bash" in command.lower() or "sh" in command.lower():
        detected_patterns.append("Bash/sh command detected")
        risk_score += 1
    
    # Eval detection
    if "eval" in command:
        risk_score += 5
        detected_patterns.append("Eval usage detected")
    
    # Direct download and execution detection (curl piped to bash)
    if len(parts) > 1 and "curl" in parts[0].lower() and any(shell in parts[1].lower() for shell in ["bash", "sh"]):
        risk_score += 8
        detected_patterns.append("DANGEROUS: Direct download and execution (curl | bash)")
    
    # File download and later execution detection
    if "curl" in command.lower() and ("-o " in command or "--output " in command) and "bash" in command.lower():
        risk_score += 6
        detected_patterns.append("DANGEROUS: Download to file and subsequent execution")
    
    # Obfuscation detection
    obfuscation_score = detect_obfuscation(command)
    if obfuscation_score > 0:
        risk_score += obfuscation_score
        detected_patterns.append(f"Possible obfuscation detected (score: {obfuscation_score})")
    
    # Base64 detection
    base64_patterns = detect_base64(command)
    if base64_patterns:
        risk_score += 4
        detected_patterns.extend(base64_patterns)
    
    # Normalize risk score to 0-10 scale
    risk_score = min(10, risk_score)
    
    # Determine risk level based on score
    if risk_score >= 8:
        result = "malicious - high risk"
    elif risk_score >= 4:
        result = "suspicious - caution recommended"
    else:
        result = "safe"
    
    return result, risk_score, detected_patterns

def detect_obfuscation(command):
    """
    Detects obfuscation techniques in commands.
    Returns an obfuscation score.
    """
    obfuscation_score = 0
    
    # Check for excessive special characters
    special_chars = ['`', '$', '\\', '{', '}', '(', ')', '\'', '"']
    special_count = sum(command.count(char) for char in special_chars)
    if special_count > 10:
        obfuscation_score += 3
    elif special_count > 5:
        obfuscation_score += 1
    
    # Check for single-letter variables (common in obfuscation)
    single_letter_vars = len(re.findall(r'\$[a-zA-Z]\b', command))
    if single_letter_vars > 5:
        obfuscation_score += 3
    elif single_letter_vars > 2:
        obfuscation_score += 1
    
    # Check for unusually long tokens
    longest_token = max([len(token) for token in command.split()], default=0)
    if longest_token > 50:
        obfuscation_score += 2
    
    # Check for command substitution techniques
    if command.count('`') > 2 or command.count('$(') > 2:
        obfuscation_score += 2
    
    return obfuscation_score

def detect_base64(command):
    """
    Detects and tries to decode strings that look like Base64.
    Returns a list of detected patterns.
    """
    patterns = []
    
    # Look for potential Base64 strings
    base64_pattern = r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']'
    matches = re.findall(base64_pattern, command)
    
    for potential_b64 in matches:
        try:
            # Try to decode
            decoded = base64.b64decode(potential_b64).decode('utf-8', errors='ignore')
            
            # Check if the decoded string looks like a command or script
            if any(keyword in decoded.lower() for keyword in ['bash', 'sh', 'curl', 'wget', 'eval', 'exec']):
                patterns.append(f"DANGEROUS: Hidden command in Base64 ({decoded[:30]}...)")
            else:
                patterns.append("Base64 string detected")
        except:
            # If it can't be decoded, might be a false alarm or partial encoding
            patterns.append("Possible Base64 string detected")
    
    return patterns

# Main execution block for testing
if __name__ == "__main__":
    print("Curl/Bash Command Analyzer - Version 4.0 (with VirusTotal)")
    print("Enter 'exit' to quit\n")
    
    # Try to load VirusTotal API key
    virustotal_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    
    if not virustotal_api_key:
        print("NOTE: No VirusTotal API key configured.")
        print("To enable URL analysis, set the VIRUSTOTAL_API_KEY environment variable.\n")
    else:
        print("VirusTotal API key configured. URLs will be analyzed.\n")
    
    while True:
        command = input("\nEnter a command: ")
        if command.lower() == 'exit':
            break
            
        result, score, patterns = analyze_command(command, virustotal_api_key)
        
        print(f"\nCommand entered: {command}")
        print(f"Result: {result}")
        print(f"Risk score: {score}")
        
        if patterns:
            print("\nDetected patterns:")
            for pattern in patterns:
                print(f"- {pattern}")
