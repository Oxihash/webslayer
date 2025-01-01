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

    def run(self):
        self.target = input("Enter the target URL or IP: ")
        if not self.target.startswith(("http://", "https://")):
            self.target = f"http://{self.target}"

        print(f"\nInitiating WebSlayer scan on {self.target}\n")

        with tqdm(total=100, desc="Scanning Progress", bar_format="{l_bar}{bar}") as pbar:
            results = {}
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(self.run_zap_scan): "ZAP Scan",
                    executor.submit(self.run_dirbuster): "Dirbuster",
                    executor.submit(self.run_nikto): "Nikto",
                    executor.submit(self.run_nmap_vuln): "Nmap Vuln Scan",
                    executor.submit(self.run_waf_scan): "WAF Scan"
                }

                for future in futures:
                    results[futures[future]] = future.result()
                    pbar.update(20)

        self.generate_report(results)

    def run_zap_scan(self):
        zap = ZAPv2(apikey=self.zap_api_key)
        zap.urlopen(self.target)
        scan_id = zap.ascan.scan(self.target)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(5)
        return zap.core.alerts()

    def run_dirbuster(self):
        output_file = "dirbuster_output.txt"
        cmd = f"gobuster dir -u {self.target} -w {self.wordlist} -o {output_file}"
        subprocess.run(cmd, shell=True, check=True)
        with open(output_file, "r") as f:
            return f.read()

    def run_nikto(self):
        output_file = "nikto_output.txt"
        cmd = f"nikto -h {self.target} -output {output_file}"
        subprocess.run(cmd, shell=True, check=True)
        with open(output_file, "r") as f:
            return f.read()

    def run_nmap_vuln(self):
        nm = nmap.PortScanner()
        nm.scan(self.target, arguments="-sV --script vuln")
        return nm.csv()

    def run_waf_scan(self):
        output_file = "wafw00f_output.txt"
        cmd = f"wafw00f {self.target} -o {output_file}"
        subprocess.run(cmd, shell=True, check=True)
        with open(output_file, "r") as f:
            return f.read()

    def generate_report(self, results):
        template_str = """
        # WebSlayer Scan Report

        Target: {{ target }}

        ## ZAP Scan Results
        {% for alert in results['ZAP Scan'] %}
        - {{ alert.alert }} (Risk: {{ alert.risk }})
          URL: {{ alert.url }}
          Description: {{ alert.description }}
        {% endfor %}

        ## Dirbuster Results
        ```
        {{ results['Dirbuster'] }}
        ```

        ## Nikto Results
        ```
        {{ results['Nikto'] }}
        ```

        ## Nmap Vulnerability Scan Results
        ```
        {{ results['Nmap Vuln Scan'] }}
        ```

        ## WAF Scan Results
        ```
        {{ results['WAF Scan'] }}
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
