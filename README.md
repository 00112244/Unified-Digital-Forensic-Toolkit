
# Unified Digital Forensic Toolkit  

A comprehensive **Digital Forensics Toolkit** that combines five forensic analysis modules into one project.  
This toolkit is designed for **cybersecurity students, SOC analysts, and digital forensics learners** to perform initial investigations on different types of data.  

---

## Features  

- **Email Analyzer** → Extracts and analyzes email headers for source tracing and spam/phishing detection.  
- **Image Analyzer** → Extracts metadata (Exif, camera info, GPS, timestamps) from images.  
- **File Analyzer** → Provides file type identification, hashing (MD5/SHA256), and integrity verification.  
- **URL Analyzer** → Checks URLs for malicious reputation using APIs like VirusTotal / AbuseIPDB.  
- **Network Analyzer** → Analyzes packet captures (PCAP files) for suspicious traffic or IOCs.  

---

---

## ⚙️ Installation  

```bash
# Clone the repository
git clone https://github.com/00112244/Unified-Digital-Forensic-Toolkit.git
cd forensic-toolkit

# Create virtual environment (optional)
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
````

---

## 🚀 Usage

Each module can be executed independently.

```bash
# Example: Run email analyzer
python main.py 
choose the option (Email Analyzer)

# Example: Run image analyzer
python main.py 
choose the option (Image Analyzer)
```

---

## 📦 Dependencies

List of common libraries (add more as needed):

* `python-whois` – for URL lookups
* `requests` – for API queries
* `Pillow` – for image metadata
* `scapy` – for network/packet analysis
* `hashlib` – for file hashing

*(All dependencies are listed in `requirements.txt`)*

---

## 🤝 Contributing

Contributions are welcome! 

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
