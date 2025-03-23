# Script Guard

A security tool that analyzes curl and bash commands to detect potentially malicious patterns, with VirusTotal integration for URL analysis.

## Features

- Real-time analysis of shell commands
- Detection of suspicious and malicious patterns
- Identification of obfuscation techniques
- Base64 detection and decoding
- VirusTotal integration for URL verification
- Risk scoring system (0-10)
- Interactive command-line interface

## Requirements

- Python 3.6+
- `requests` library
- VirusTotal API key (optional but recommended)

## Installation

1. Clone the repository:
   git clone https://github.com/your-username/script-guard.git
   cd script-guard
2. Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:
   pip install requests
4. Configure your VirusTotal API key:
   - Create a `config.ini` file:
     [VirusTotal]
     api_key = YOUR_API_KEY_HERE
   - Or set it as an environment variable:
     export VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE  # On Windows: set VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE

## How It Works

The tool analyzes commands using several detection methods:

1. **Pattern Matching**: Detects known dangerous patterns like `curl | bash`
2. **Domain Analysis**: Flags known suspicious domains
3. **Obfuscation Detection**: Identifies command obfuscation techniques
4. **Base64 Detection**: Finds and decodes Base64-encoded strings
5. **VirusTotal Integration**: Checks URLs against 70+ security vendors

Each detected element contributes to a risk score from 0-10:
- 0-3: Safe
- 4-7: Suspicious (caution recommended)
- 8-10: Malicious (high risk)

## Project Structure

- `engine.py`: Core analysis engine
- `virus_total_integration.py`: VirusTotal API integration
- `main.py`: Command-line interface
- `test_engine_vt.py`: Test suite for verifying functionality

## License

This project is licensed under the MIT License - see the LICENSE file for details.
