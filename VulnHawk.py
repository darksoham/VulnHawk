# WordPress Vulnerability Scanner - Full GUI Version with All Features

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import requests
from bs4 import BeautifulSoup
import nmap
import socket
import dns.resolver
import tldextract
import os
import json
import csv
import pdfkit
import time
import whois
import subprocess

# Global stop flag
stop_scan = False

# Utils

def log(text_widget, message):
    text_widget.insert(tk.END, message + "\n")
    text_widget.see(tk.END)

def export_report(domain, data):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    folder = f"reports/{domain}"
    os.makedirs(folder, exist_ok=True)

    # JSON
    with open(f"{folder}/report_{timestamp}.json", "w") as f:
        json.dump(data, f, indent=2)

    # CSV
    with open(f"{folder}/report_{timestamp}.csv", "w", newline='') as f:
        writer = csv.writer(f)
        for key, value in data.items():
            writer.writerow([key, value])

    # PDF
    html_content = "<h1>Scan Report</h1>"
    for k, v in data.items():
        html_content += f"<b>{k}</b>: {v}<br>"
    with open(f"{folder}/report_{timestamp}.html", "w") as f:
        f.write(html_content)
    pdfkit.from_file(f"{folder}/report_{timestamp}.html", f"{folder}/report_{timestamp}.pdf")

# Scanner Modules

def check_wp_version(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        return gen['content'] if gen else "Unknown"
    except:
        return "Error fetching version"

def check_security_headers(url):
    try:
        r = requests.get(url)
        return {
            'X-Frame-Options': r.headers.get('X-Frame-Options', 'Missing'),
            'Strict-Transport-Security': r.headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': r.headers.get('Content-Security-Policy', 'Missing')
        }
    except:
        return {'Error': 'Failed to fetch headers'}

def file_enumeration(url):
    files = ['wp-config.php', '.git/', 'readme.html']
    found = []
    for f in files:
        try:
            if stop_scan: return found
            full_url = url + '/' + f
            r = requests.get(full_url)
            if r.status_code == 200:
                found.append(f)
        except:
            continue
    return found

def js_scrape(url):
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        return [s['src'] for s in soup.find_all('script') if s.get('src')]
    except:
        return []

def dns_info(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.address for ip in result]
    except:
        return []

def check_spf_dkim_dmarc(domain):
    results = {}
    try:
        txt = dns.resolver.resolve(domain, 'TXT')
        for r in txt:
            record = r.to_text()
            if 'spf' in record:
                results['SPF'] = record
            if 'dkim' in record:
                results['DKIM'] = record
            if 'dmarc' in record:
                results['DMARC'] = record
    except:
        pass
    return results

def run_full_scan(domain, output):
    global stop_scan
    stop_scan = False
    url = "http://" + domain if not domain.startswith("http") else domain
    log(output, f"Starting scan on {domain}...")

    report = {}
    report['Domain'] = domain
    report['IP Address'] = dns_info(domain)

    log(output, "[+] Checking WordPress version...")
    report['WP Version'] = check_wp_version(url)

    log(output, "[+] Checking security headers...")
    report['Security Headers'] = check_security_headers(url)

    log(output, "[+] Enumerating common files...")
    report['Sensitive Files'] = file_enumeration(url)

    log(output, "[+] Scraping JavaScript URLs...")
    report['JS Files'] = js_scrape(url)

    log(output, "[+] Checking email spoof protection...")
    report['Email Protections'] = check_spf_dkim_dmarc(domain)

    if stop_scan:
        log(output, "[!] Scan manually stopped.")
        return

    log(output, "[+] Exporting report...")
    export_report(domain, report)
    log(output, "[✓] Scan complete. Report saved.")

# GUI Setup

def start_scan(entry, output):
    domain = entry.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a domain")
        return
    threading.Thread(target=run_full_scan, args=(domain, output)).start()

def stop_scan_fn():
    global stop_scan
    stop_scan = True

root = tk.Tk()
root.title("WordPress Vulnerability Scanner")
root.geometry("900x600")

style = ttk.Style(root)
style.theme_use('clam')

# Input Frame
input_frame = ttk.Frame(root)
input_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

label = ttk.Label(input_frame, text="Enter Domain:")
label.pack(pady=5)

entry = ttk.Entry(input_frame, width=40)
entry.pack(pady=5)

start_btn = ttk.Button(input_frame, text="Start Scan", command=lambda: start_scan(entry, output_box))
start_btn.pack(pady=10)

stop_btn = ttk.Button(input_frame, text="Stop Scan", command=stop_scan_fn)
stop_btn.pack(pady=5)

# Output Frame
output_frame = ttk.Frame(root)
output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

output_box = ScrolledText(output_frame, wrap=tk.WORD, width=80, height=35)
output_box.pack(fill=tk.BOTH, expand=True)

root.mainloop()
