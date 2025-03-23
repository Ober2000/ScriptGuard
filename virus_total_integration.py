import requests
import time
import re
import urllib.parse
from urllib.parse import urlparse

def check_url_with_virustotal(url, api_key):
    """
    Submits a URL to VirusTotal for analysis and returns the results.
    
    Args:
        url (str): The URL to analyze
        api_key (str): VirusTotal API key
    
    Returns:
        dict: Analysis results including score and details
    """
    url = url.strip('\'"')
    
    # Validate URL format
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return {"error": "Invalid URL", "score": 0, "details": []}
    except:
        return {"error": "Malformed URL", "score": 0, "details": []}
    
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        # Step 1: Submit URL for analysis
        url_encoded = urllib.parse.quote_plus(url)
        url_id_response = requests.post(
            "https://www.virustotal.com/api/v3/urls", 
            headers=headers,
            data=f"url={url_encoded}"
        )
        
        if url_id_response.status_code != 200:
            return {
                "error": f"Error submitting URL to VirusTotal: {url_id_response.status_code}",
                "score": 0,
                "details": []
            }
        
        # Extract analysis ID from response
        try:
            analysis_id = url_id_response.json().get("data", {}).get("id", "")
            if not analysis_id:
                return {"error": "Could not get analysis ID", "score": 0, "details": []}
        except Exception as e:
            return {"error": f"Error processing VirusTotal response: {str(e)}", "score": 0, "details": []}
        
        # Step 2: Get analysis results
        max_attempts = 5
        for attempt in range(max_attempts):
            time.sleep(2)  # Respect API rate limits
            
            result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            result = requests.get(
                result_url,
                headers={"x-apikey": api_key}
            )
            
            if result.status_code == 200:
                data = result.json()
                status = data.get("data", {}).get("attributes", {}).get("status")
                
                if status == "completed":
                    stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                    results = data.get("data", {}).get("attributes", {}).get("results", {})
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 1
                    
                    vt_score = ((malicious * 2) + suspicious) * 10 / total if total > 0 else 0
                    
                    details = []
                    for engine, result in results.items():
                        if result.get("category") in ["malicious", "suspicious"]:
                            details.append(f"{engine}: {result.get('result', 'No details')}")
                    
                    return {
                        "score": round(vt_score, 2),
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_engines": total,
                        "details": details[:5]
                    }
                
                elif status == "queued":
                    continue  # Keep waiting
        
        return {"error": "Timeout waiting for results", "score": 0, "details": []}
        
    except Exception as e:
        return {"error": f"Request error: {str(e)}", "score": 0, "details": []}


def extract_urls_from_command(command):
    """
    Extracts all URLs present in a command.
    
    Args:
        command (str): The command to analyze
    
    Returns:
        list: List of found URLs
    """
    url_pattern = r'https?://[^\s\'";,><)]+|www\.[^\s\'";,><)]+\.[^\s\'";,><)]+'
    
    urls = re.findall(url_pattern, command)
    
    cleaned_urls = []
    for url in urls:
        if url.startswith('www.'):
            url = 'http://' + url
        
        url = url.rstrip('.,;:\'"])}')
        
        cleaned_urls.append(url)
    
    return cleaned_urls
