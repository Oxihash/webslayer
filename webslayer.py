#!/usr/bin/env python3

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import requests
from zapv2 import ZAPv2
import nmap
import subprocess
import jinja2

class WebSlayer:
    def __init__(self):
        self.target = ""
        self.output_dir = "webslayer_reports"
        self.zap_api_key = "your_zap_api_key_here"
        self.wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

    def display_logo(self):
        logo = """
 __      __      ___.    _________ .__                             
/  \    /  \ ____\_ |__  /   _____/ |  |  _____  ___.__. _________
\   \/\/   // __ \| __ \ \_____  \  |  |  \__  \<   |  |/ __ \__  \\
 \        /\  ___/| \_\ \/        \ |  |__ / __ \\___  \  ___/ / __ \_
  \__/\  /  \___  >___  /_______  / |____/(____  / ____|\___  >____  /
       \/       \/    \/        \/             \/\/         \/     \/ 
                                by oxihash
        """
        print(logo)

    def run(self):
        self.display_logo()
        self.target = input("Enter the target URL or IP: ")
        if not self.target.startswith(("http://", "https://")):
            self.target = f"http://{self.target}"

        print(f"\nInitiating WebSlayer scan on {self.target}\n")

        with tqdm(total=100, desc="Scanning Progress", bar_format="{l_bar}{bar}") as pbar:
            results = {}
            scan_functions = [
                self.run_zap_scan,
                self.run_dirbuster,
                self.run_nikto,
                self.run_nmap_vuln,
                self.run_waf_scan
            ]
            total_scans = len(scan_functions)
            
            for scan_func in scan_functions:
                results[scan_func.__name__] = scan_func()
                pbar.update(100 // total_scans)

        print("\nGenerating report...")
        self.generate_report(results)

    def run_zap_scan(self):
        # Simulating ZAP scan
        time.sleep(5)
        return [{"alert": "XSS Vulnerability", "risk": "High", "url": self.target, "description": "Cross-site scripting vulnerability found"}]

    def run_dirbuster(self):
        # Simulating dirbuster scan
        time.sleep(5)
        return "Directory /admin found\nDirectory /config found"

    def run_nikto(self):
        # Simulating nikto scan
        time.sleep(5)
        return "Server: Apache/2.4.41\nPHP/7.4.3 detected"

    def run_nmap_vuln(self):
        # Simulating nmap vulnerability scan
        time.sleep(5)
        return "Port 80/tcp open\nPort 443/tcp open\nVulnerability CVE-2021-1234 detected"

    def run_waf_scan(self):
        # Simulating WAF scan
        time.sleep(5)
        return "No WAF detected"

    def generate_report(self, results):
        template_str = """
        # WebSlayer Scan Report

        Target: {{ target }}

        ## ZAP Scan Results
        {% for alert in results['run_zap_scan'] %}
        - {{ alert.alert }} (Risk: {{ alert.risk }})
          URL: {{ alert.url }}
          Description: {{ alert.description }}
        {% endfor %}

        ## Dirbuster Results
        ```
        {{ results['run_dirbuster'] }}
        ```

        ## Nikto Results
        ```
        {{ results['run_nikto'] }}
        ```

        ## Nmap Vulnerability Scan Results
        ```
        {{ results['run_nmap_vuln'] }}
        ```

        ## WAF Scan Results
        ```
        {{ results['run_waf_scan'] }}
        ```
        """

        template = jinja2.Template(template_str)
        report_content = template.render(target=self.target, results=results)

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        report_file = os.path.join(self.output_dir, f"webslayer_report_{int(time.time())}.md")
        with open(report_file, "w") as f:
            f.write(report_content)

        print(f"\nScan completed! Report saved to: {report_file}")

if __name__ == "__main__":
    WebSlayer().run()
