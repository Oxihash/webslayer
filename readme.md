# WebSlayer by Oxihash

WebSlayer is an automated web application testing and report generating tool.

## Installation

1. Clone the repository:
git clone https://github.com/oxihash/webslayer.git
cd webslayer
pip install -r requirements.txt

3. Install system dependencies:
- OWASP ZAP
- Gobuster
- Nikto
- Nmap
- Wafw00f

## Usage

Run the tool:
python webslayer.py

Follow the prompts to enter the target URL or IP address. The tool will automatically perform the scans and generate a report in the `webslayer_reports` directory.

## Features

- ZAP Scan
- Directory Busting (using Gobuster)
- Nikto Scan
- Nmap Vulnerability Scan
- WAF Detection (using Wafw00f)
- Concurrent scanning for faster results
- Progress bar for scan status
- Comprehensive Markdown report generation

## License

This project is licensed under the MIT License.
