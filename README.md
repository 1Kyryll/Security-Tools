# Security Tools

A set of tools written in Python for Penetration Testing, searching vulnerabilities within your systems and auditing your credentials. The *Security+ course* inspired me to make this repo; some of these tools could be used in your everyday chores or ethical hacking labs and projects. Repo tools:

- **Port/Vulnerability Scanner** in `scanner/`
- **Password Audit Tool** in `audit/`
- **C2 Reverse Shell** in `c2/`

## Setting up the project

Clone the repo and move into the project folder:

```bash
git clone https://github.com/1Kyryll/Security-Tools.git
cd Security-Tools
```

Create a virtual environment:

```bash
python -m venv ./venv
```

Install `requirements.txt`:

```bash
pip install -r requirements.txt
```

Set up a `.env` file and add an `NVD_API_KEY` variable in it. You can get this key at https://nvd.nist.gov/developers/request-an-api-key.

## Port and Vulnerability Scanner

This tool scans an *IP address* for open ports and looks up vulnerabilities in the **NVD** database. File structure explained:

- `core/`
    - `port_scan.py` — connects to different ports using the built-in `socket` library. The `scan_ports` method concurrently connects to multiple ports with Python threads to speed up the whole scanning process.
    - `banner.py` — grabs banners for ports that do not speak first.
    - `fingerprint.py` — matches services and their versions for open ports.
- `utils/`
    - `network.py` — checks whether the IP address is private, provides a rate limiter and parses port range input.
- `output/`
    - `reporter.py` — sets up a `rich` library console and the open ports / vulnerabilities table.
- `vuln/`
    - `cve_db.py` — maps service names and versions to CPE strings and performs vulnerability lookups with the `nvd_client` library.
    - `checks.py` — performs vulnerability checks (HTTP headers, anonymous FTP, default paths).
- `main.py` — application entrypoint.

#### Example usage

See options and flags:

```bash
python scanner/main.py
```

Scan the first 1000 ports on localhost:

```bash
python scanner/main.py -t 127.0.0.1 -p 1-1000
```
