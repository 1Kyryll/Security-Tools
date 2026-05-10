# Security Tools

A set of tools written in Python for Penetration Testing, searching vulnerabilities within your systems and auditing your credentials. The *Security+ course* inspired me to make this repo; some of these tools could be used in your everyday chores or ethical hacking labs and projects. Repo tools:

- **Port/Vulnerability Scanner** in `Port-Scanner/`
- **Password Audit Tool** in `Password-Audit/`
- **C2 Reverse Shell** in `C2-Framework/`

## ⚠️ Disclaimer

The offensive security tools provided in this repository are intended **strictly for educational and research purposes**. They are designed to help students, security researchers, and authorized penetration testers learn about vulnerabilities, attack techniques, and defensive countermeasures in controlled, lawful environments such as personal labs, CTF challenges, and systems where the user has **explicit written authorization** to perform security testing.

### Acceptable Use
- Learning and studying offensive security concepts
- Use in isolated lab environments you own or control
- Authorized penetration testing engagements with documented permission
- Capture-the-Flag (CTF) competitions and intentionally vulnerable training platforms

### Prohibited Use
- Any use against systems, networks, or devices you do not own or for which you do not have explicit written permission
- Any unlawful, malicious, or unethical activity

Unauthorized use of these tools against systems you do not own or have permission to test may violate local, state, federal, or international laws, including (but not limited to) the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and similar legislation worldwide.

### Liability
The author(s) and contributor(s) of this repository assume **no liability** and are **not responsible** for any misuse, damage, or legal consequences arising from the use of these tools. By using, cloning, or downloading the contents of this repository, you agree that you are solely responsible for your actions and that you will use these tools in compliance with all applicable laws.

**If you do not agree to these terms, do not use this repository.**

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

## Password Audit Tool

This is a simple *password cracker* which detect the hashing algorithm, and tries to match the hash using wordlist user provides. Here is the file structure: 

- `core/` 
    - `cracker.py` - opens a wordlist file and tries to match hashes using multiple predefined rules
    - `detector.py` - detects hashing algorithm
    - `hashes.py` - helper that hashes a plaintext with hashlib 
- `breach/` 
    - `hibp.py` - checks whether a password has a breach using `pwnedpasswords` library
- `output/` 
    - `reporter.py` - CLI data representation
- `wordlist/`
    - `hashes.txt` - **SHA256** hashes for three simple passwords: test, 123, dubai2020
- `main.py` - application entrypoint 

#### Example usage 

See options and flags:

```bash
python audit/main.py
```

Crack passwords in `wordlist/hashes.txt` using `rockyou.txt`(before that you need to download that file):

```bash 
python audit/main.py -i ./audit/wordlist/hashes.txt -w <path>/rockyou.txt
```

## Mini C2 Framework

C2 - stands for **Command & Control.** C2 Frameworks allow to *Command and Control* compromised devices, establish a connection between Server, Client and Agent. Agent is basically a malicious application that runs on the victim's machine, while Client(Attacker) receives data and executes commands using C2 Server. Here is a breakdown of the file structure:

- `server/`
    - `app.py` - a Flask C2 Server.
    - `models.py` - data models.
    - `store.py` - an in-memory store of data models.
- `agent/`
    - `agent.py` - malicious app that runs on a victim's machine, executes commands on it and sends data to the Client.
- `operator/`
    - `cli.py` - attacker's CLI interface for executing commands and getting data from the compromised machine.

#### Example usage 

To fully grasp the concept of C2, you need to setup two VMs, victim(e.g. Ubuntu) and attacker(e.g. Kali). From these VMs clone this github repo. 

Run malicious application in the victim's VM:

```bash
python C2-Framework/agent/agent.py 
```

In the attacker's VMs run C2 Server and execute commands:

```bash
# Init Server
python -m C2-Framework/server.app 

# Execute commands remotely on the victim's VM
python C2-Framework/operator/cli.py agents
python C2-Framework/operator/cli.py task <agent-id-prefix> "whoami"
python C2-Framework/operator/cli.py task <agent-id-prefix> "ls /etc"
```
