# 🛡️ VulnHawk

**VulnHawk** is an advanced website vulnerability scanner built for security researchers and penetration testers. It features a user-friendly GUI, powerful scanning modules, and anonymous scanning capabilities via the Tor network.

---

## ✨ Features

* ✅ Website & CMS Detection (WordPress, Joomla, Drupal, etc.)
* ✅ SSL/TLS Analysis
* ✅ Security Headers Check
* ✅ JavaScript File Scraping + CVE Scanning
* ✅ Login Panel Detection + Brute-force Testing
* ✅ Subdomain Takeover Detection
* ✅ Directory Brute-force and File Upload Vulnerability Testing
* ✅ Email Spoofing (SPF, DKIM, DMARC) Checks
* ✅ Open Redirect Testing
* ✅ Reverse IP Lookup
* ✅ Export Results: PDF, JSON, CSV
* ✅ Interactive HTML Report with Severity Tags
* ✅ Dark Mode GUI with Scan History & Tooltips
* ✅ Anonymous Scanning using Tor Proxy
* ✅ GeoIP Lookup and Whois Information
* ✅ Built-in Scan Progress Bar and Stop Button
* ✅ Scheduler Mode and Searchable Log Output

---

## 💻 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/VulnHawk.git
cd VulnHawk
```

Set up a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate
```

Install all required Python packages:

```bash
pip install -r requirements.txt
```

Install PDF generator for reports:

```bash
sudo apt install wkhtmltopdf
```

(Optional) Start Tor for anonymous scanning:

```bash
sudo service tor start
```

---

## 🚀 Usage

Start the tool:

```bash
python3 scnwp.py
```

Use the GUI to:

* Select scan targets
* View real-time output
* Stop scans mid-way
* Export reports after scanning

---

## 📸 Screenshots

> (You can add images here later)

---

## 📁 Output Formats

* `report.html`: Interactive HTML report
* `report.pdf`: Printable PDF report
* `report.json`: Machine-readable results
* `report.csv`: Spreadsheet-compatible data

---

## 🔐 Disclaimer

This tool is for **educational and authorized security testing only**. Do not scan websites without explicit permission. The developer is **not responsible** for any misuse.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss improvements.
